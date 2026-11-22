// Package quicsession drives service lifecycle on an already registered QUIC
// carrier. It never dials, retries application requests, or authorizes handlers.
package quicsession

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/sessionstate"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
	"github.com/solodyagin/outgate-sdk/transport/quichttp"
)

// Options supplies verified local security readiness, never bootstrap metadata.
// SecurityReady defaults to false. Handler must contain the deployment's
// signature/authorization middleware. ReadinessCheck must match the registration
// flag; it runs outside locks with one slot retained even after cancellation.
type Options struct {
	SecurityReady    bool
	SecurityDeadline time.Time
	ReadinessCheck   func(context.Context) error
	TickInterval     time.Duration
	MaxCommands      int
}

// Service owns the control reader/writer, readiness callback and reverse HTTP/3
// server. Done means all of them and all actual handlers have exited. A callback
// ignoring cancellation can delay Done, but cannot spawn replacement callbacks.
type Service struct {
	mu      sync.Mutex
	state   *sessionstate.State
	carrier *quiccontrol.Carrier
	http    *quichttp.Service
	ack     v1.RegisterAck
	options Options

	ctx     context.Context
	cancel  context.CancelFunc
	wake    chan struct{}
	changed chan struct{}
	done    chan struct{}
	workers sync.WaitGroup
	probes  sync.WaitGroup

	probeCancel context.CancelFunc
	nextProbe   time.Time
	pending     []v1.DrainAck
	localDrain  bool

	closeIntent, stopping, graceful, reconnect bool
	err                                        error
}

// NewService consumes HTTP attachment and sole control-reader ownership. Only
// negotiated minor-1 quiescent-fence sessions are supported; no fallback occurs.
func NewService(c *quiccontrol.Carrier, handler http.Handler, o Options) (*Service, error) {
	if c == nil || handler == nil {
		return nil, v1.ErrProtocol
	}
	r, ack, development := c.Registration()
	if !v1.HasQUICQuiescentFence(ack) || r.ReadinessCheckConfigured != (o.ReadinessCheck != nil) {
		return nil, v1.ErrProtocol
	}
	if o.MaxCommands == 0 {
		o.MaxCommands = 64
	}
	if o.TickInterval == 0 {
		o.TickInterval = 100 * time.Millisecond
	}
	if o.TickInterval <= 0 || o.TickInterval > time.Second {
		return nil, v1.ErrProtocol
	}
	o.TickInterval = min(o.TickInterval, time.Duration(ack.Timeouts.StatusIntervalMS)*time.Millisecond/2)
	if o.ReadinessCheck != nil {
		o.TickInterval = min(o.TickInterval, time.Duration(min(ack.Readiness.IntervalMS, ack.Readiness.TimeoutMS))*time.Millisecond/2)
	}
	if o.TickInterval <= 0 {
		o.TickInterval = time.Millisecond
	}
	state, err := sessionstate.New(sessionstate.Config{Local: sessionstate.Service, Development: development, MaxControlBytes: v1.MaxControlBytes, RegisterTimeout: 10 * time.Second, MaxCommands: o.MaxCommands, NativeStreams: true})
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if err = state.Begin(now); err != nil {
		return nil, err
	}
	if _, err = state.Apply(sessionstate.Service, r, now); err != nil {
		return nil, err
	}
	if _, err = state.Apply(sessionstate.Gateway, ack, now); err != nil {
		return nil, err
	}
	if _, err = state.Security(o.SecurityReady, o.SecurityDeadline, now); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{state: state, carrier: c, ack: ack, options: o, ctx: ctx, cancel: cancel, wake: make(chan struct{}, 1), changed: make(chan struct{}, 1), done: make(chan struct{}), pending: make([]v1.DrainAck, 0, o.MaxCommands)}
	s.http, err = quichttp.NewService(c, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		s.mu.Lock()
		lease, effect, err := s.state.AdmitNative(time.Now())
		s.effectLocked(effect, err)
		s.mu.Unlock()
		if err != nil {
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		defer func() {
			s.mu.Lock()
			e, err := s.state.CompleteNative(lease, time.Now())
			s.effectLocked(e, err)
			s.mu.Unlock()
			s.signal()
		}()
		handler.ServeHTTP(w, req)
	}))
	if err != nil {
		cancel()
		return nil, err
	}
	s.workers.Add(4)
	go func() {
		defer s.workers.Done()
		err := s.http.Serve()
		s.mu.Lock()
		s.stopLocked(err, false, false)
		s.mu.Unlock()
	}()
	go s.read()
	go s.write()
	go s.tick()
	s.signal()
	return s, nil
}

func (s *Service) Done() <-chan struct{} { return s.done }
func (s *Service) Err() error            { s.mu.Lock(); defer s.mu.Unlock(); return s.err }
func (s *Service) Snapshot() sessionstate.Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.Snapshot()
}

// ReconnectRequested is only a hint after validated unregister_ack and complete
// cleanup. The owner may establish a fresh session; business requests never move.
func (s *Service) ReconnectRequested() bool {
	select {
	case <-s.done:
	default:
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reconnect && s.graceful && !s.closeIntent && s.err == nil
}

func (s *Service) SetSecurity(ready bool, deadline time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, err := s.state.Security(ready, deadline, time.Now())
	s.effectLocked(e, err)
	s.signal()
	return err
}

// Revoke preempts even a terminal rotation acknowledgement during cleanup.
func (s *Service) Revoke() {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.state.Revoke(time.Now())
	s.err, s.reconnect, s.graceful = sessionstate.ErrSecurity, false, false
	s.stopLocked(sessionstate.ErrSecurity, false, false)
}

// Drain requests final shutdown and waits for the original bounded handshake.
// An expired caller context closes the carrier; it never extends peer deadlines.
func (s *Service) Drain(ctx context.Context) error {
	s.mu.Lock()
	s.closeIntent, s.reconnect = true, false
	if !s.stopping {
		deadline, _ := ctx.Deadline()
		e, err := s.state.Close(deadline, time.Now())
		s.effectLocked(e, err)
		if !s.stopping && !s.state.Snapshot().Fenced && s.state.Snapshot().PendingDrains == 0 {
			s.localDrain = true
		}
		s.signal()
	}
	s.mu.Unlock()
	return s.wait(ctx)
}

// Close cancels immediately. A bounded wait can expire while an uncooperative
// handler/callback still owns resources; Done remains open until actual cleanup.
func (s *Service) Close(ctx context.Context) error {
	s.mu.Lock()
	s.closeIntent, s.reconnect = true, false
	s.stopLocked(nil, false, false)
	s.mu.Unlock()
	return s.wait(ctx)
}

func (s *Service) wait(ctx context.Context) error {
	select {
	case <-s.done:
		return s.Err()
	case <-ctx.Done():
		s.mu.Lock()
		s.stopLocked(ctx.Err(), false, false)
		s.mu.Unlock()
		return ctx.Err()
	}
}

func (s *Service) signal() {
	s.wakeWriter()
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

func (s *Service) wakeWriter() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Service) effectLocked(e sessionstate.Effect, err error) {
	if e.CloseTransport {
		s.stopLocked(err, err == nil, e.Reconnect)
	}
}

func (s *Service) stopLocked(err error, graceful, reconnect bool) {
	if s.stopping {
		return
	}
	s.stopping, s.err, s.graceful = true, err, graceful
	s.reconnect = reconnect && graceful && !s.closeIntent
	if s.state.Snapshot().TransportActive {
		_, _ = s.state.Disconnected(false, time.Now())
	}
	s.cancel()
	if s.probeCancel != nil {
		s.probeCancel()
	}
	go s.cleanup()
}

func (s *Service) cleanup() {
	s.mu.Lock()
	err := s.err
	s.mu.Unlock()
	switch {
	case errors.Is(err, sessionstate.ErrSecurity):
		_ = s.carrier.Revoke()
	case err != nil:
		_ = s.carrier.Abort()
	default:
		_ = s.carrier.Close()
	}
	_ = s.http.Close()
	s.workers.Wait()
	s.probes.Wait()
	s.mu.Lock()
	// Expiry remains authoritative even if cleanup outlasts a normal terminal ack.
	deadline := s.state.Snapshot().Deadline
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		_, _ = s.state.Revoke(time.Now())
		s.err, s.graceful, s.reconnect = sessionstate.ErrSecurity, false, false
	}
	if err := s.state.Cleaned(time.Now()); err != nil && s.err == nil {
		s.err = err
		s.reconnect = false
	}
	close(s.done)
	s.mu.Unlock()
}

func (s *Service) read() {
	defer s.workers.Done()
	for {
		message, err := s.carrier.Receive(s.ctx)
		s.mu.Lock()
		if s.stopping {
			s.mu.Unlock()
			return
		}
		if err != nil {
			s.stopLocked(err, false, false)
			s.mu.Unlock()
			return
		}
		e, err := s.state.Apply(sessionstate.Gateway, message, time.Now())
		if err == nil {
			var extensions = mapExtensions(message)
			if extensions != nil {
				lastID, decodeErr := v1.DecodeQUICQuiescentFence(extensions)
				if decodeErr != nil {
					err = decodeErr
				} else {
					err = s.http.Fence(lastID)
				}
			}
		}
		if err != nil {
			s.stopLocked(err, false, false)
		} else {
			if e.Reply != nil {
				// Join an unsent local intent. Once Apply has recorded it in the
				// writer, crossed drain commands retain both ledger obligations.
				s.localDrain = false
				if len(s.pending) == cap(s.pending) {
					s.stopLocked(sessionstate.ErrCapacity, false, false)
				} else {
					s.pending = append(s.pending, *e.Reply)
				}
			}
			if s.state.Snapshot().Phase == sessionstate.Draining && s.probeCancel != nil {
				s.probeCancel()
			}
			s.effectLocked(e, nil)
		}
		s.mu.Unlock()
		s.signal()
	}
}

func (s *Service) tick() {
	defer s.workers.Done()
	t := time.NewTimer(s.options.TickInterval)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.changed:
		case <-t.C:
		}
		s.mu.Lock()
		if s.stopping {
			s.mu.Unlock()
			return
		}
		now := time.Now()
		before := s.state.Snapshot()
		e, err := s.state.Advance(now)
		s.effectLocked(e, err)
		if s.probeCancel != nil && !before.ProbeDeadline.IsZero() && !now.Before(before.ProbeDeadline) {
			s.probeCancel()
		}
		if !s.stopping && s.options.ReadinessCheck != nil && !s.state.Snapshot().ProbeOutstanding && s.state.Snapshot().Phase != sessionstate.Draining && !now.Before(s.nextProbe) {
			s.startProbeLocked()
		}
		snapshot := s.state.Snapshot()
		delay := s.options.TickInterval
		for _, deadline := range []time.Time{snapshot.Deadline, snapshot.ProbeDeadline} {
			if !deadline.IsZero() {
				delay = min(delay, max(time.Nanosecond, time.Until(deadline)))
			}
		}
		s.mu.Unlock()
		s.wakeWriter()
		t.Reset(delay)
	}
}

func (s *Service) startProbeLocked() {
	e, err := s.state.StartProbe(time.Now())
	s.effectLocked(e, err)
	if err != nil {
		return
	}
	ctx, cancel := context.WithDeadline(s.ctx, s.state.Snapshot().ProbeDeadline)
	s.probeCancel = cancel
	s.probes.Add(1)
	go func() {
		defer s.probes.Done()
		success := false
		func() { defer func() { _ = recover() }(); success = s.options.ReadinessCheck(ctx) == nil }()
		cancel()
		s.mu.Lock()
		e, err := s.state.FinishProbe(success, time.Now())
		s.effectLocked(e, err)
		s.probeCancel = nil
		s.nextProbe = time.Now().Add(time.Duration(s.ack.Readiness.IntervalMS) * time.Millisecond)
		s.mu.Unlock()
		s.signal()
	}()
}

func (s *Service) write() {
	defer s.workers.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.wake:
		}
		for {
			s.mu.Lock()
			message := s.nextLocked()
			s.mu.Unlock()
			if message == nil {
				break
			}
			if err := s.carrier.Send(s.ctx, message); err != nil {
				s.mu.Lock()
				s.stopLocked(err, false, false)
				s.mu.Unlock()
				return
			}
		}
	}
}

func (s *Service) nextLocked() any {
	if s.stopping {
		return nil
	}
	e, err := s.state.Advance(time.Now())
	s.effectLocked(e, err)
	if s.stopping {
		return nil
	}
	snapshot := s.state.Snapshot()
	// Unregister is our final frame. In particular, do not start a periodic
	// status write that the terminal ack could interrupt with carrier shutdown.
	if snapshot.UnregisterPending {
		return nil
	}
	var message any
	switch {
	case s.localDrain:
		id, err := commandID()
		if err != nil {
			s.stopLocked(err, false, false)
			return nil
		}
		message = v1.Drain{Type: "drain", CommandID: id, DeadlineMS: remaining(snapshot.Deadline), Code: "shutdown"}
		s.localDrain = false
	case len(s.pending) != 0 && snapshot.NativeActive == 0 && s.http.Active() == 0:
		message = s.pending[0]
		copy(s.pending, s.pending[1:])
		s.pending = s.pending[:len(s.pending)-1]
	case snapshot.Phase == sessionstate.Draining && snapshot.Fenced && snapshot.NativeActive == 0 && s.http.Active() == 0 && !snapshot.ProbeOutstanding && snapshot.PendingDrains == 0 && !snapshot.UnregisterPending:
		id, err := commandID()
		if err != nil {
			s.stopLocked(err, false, false)
			return nil
		}
		message = v1.Unregister{Type: "unregister", CommandID: id, DeadlineMS: remaining(snapshot.Deadline), Code: "shutdown"}
	case snapshot.StatusDue:
		code := "initializing"
		if snapshot.LocalReady {
			code = "ready"
		} else if snapshot.Phase == sessionstate.Draining {
			code = "draining"
		}
		message = v1.InstanceStatus{Type: "instance_status", Sequence: v1.U64(snapshot.Sequence + 1), Ready: snapshot.LocalReady, Code: code, ObservedAt: time.Now().Unix()}
	default:
		return nil
	}
	e, err = s.state.Apply(sessionstate.Service, message, time.Now())
	if err != nil {
		s.stopLocked(err, false, false)
		return nil
	}
	s.effectLocked(e, nil)
	return message
}

func remaining(deadline time.Time) int {
	return max(1, min(30000, int(time.Until(deadline)/time.Millisecond)))
}
func commandID() (v1.U64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	n := binary.BigEndian.Uint64(b[:])
	if n == 0 {
		n = 1
	}
	return v1.U64(n), nil
}

func mapExtensions(message any) map[string]json.RawMessage {
	switch m := message.(type) {
	case v1.Drain:
		return m.Extensions
	case v1.DrainAck:
		return m.Extensions
	case v1.Reconnect:
		return m.Extensions
	default:
		return nil
	}
}
