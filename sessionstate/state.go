// Package sessionstate models one owner's WSS session lifecycle without I/O,
// callbacks or goroutines. Serialize every method at ordered frame boundaries.
package sessionstate

import (
	"encoding/json"
	"errors"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/wssstate"
)

type Role = wssstate.Role

const (
	Gateway = wssstate.Gateway
	Service = wssstate.Service
)

type Phase string

const (
	Created    Phase = "created"
	Connecting Phase = "connecting"
	Registered Phase = "registered"
	Ready      Phase = "ready"
	Draining   Phase = "draining"
	Closed     Phase = "closed"
)

var (
	ErrProtocol = v1.ErrProtocol
	ErrState    = errors.New("outgate: session operation unavailable in current state")
	ErrTimeout  = errors.New("outgate: session deadline exceeded")
	ErrSecurity = errors.New("outgate: session security deadline reached")
	ErrCapacity = wssstate.ErrCapacity
)

// Config supplies pre-negotiation limits. Session command history is prepaid at
// MaxCommands*128 bytes within negotiated BufferBytes, separate from WSS state.
// Transport queues and actual cleanup must have their own bounded allocation.
type Config struct {
	Local             Role
	Development       bool
	MaxControlBytes   int
	RegisterTimeout   time.Duration
	MaxCommands       int
	MaxPendingCancels int
}

const commandCharge = 128

type command struct {
	sender Role
	kind   string
	acked  bool
}

// Effect must be executed before the next frame. Stream carries the existing
// wssstate effects. Reply must go through Apply immediately before ordered write.
// StopAll cancels every old handler; CleanupRequired forbids a new transport
// until the caller confirms transport closure and cleanup through Cleaned.
// Reconnect never permits replay of application requests.
type Effect struct {
	Stream          wssstate.Effect
	Reply           *v1.DrainAck
	CloseTransport  bool
	StopAll         bool
	CleanupRequired bool
	Reconnect       bool
}

type Snapshot struct {
	Phase            Phase
	TransportActive  bool
	CleanupRequired  bool
	SessionID        string
	Sequence         uint64
	LastStatus       time.Time
	StatusDue        bool
	Deadline         time.Time
	Fenced           bool
	Commands         int
	ReservedBytes    uint64
	Streams          wssstate.Stats
	ProbeOutstanding bool
	ProbeDeadline    time.Time
}

type State struct {
	config               Config
	phase                Phase
	active, cleanup      bool
	authorized, excluded bool

	securityReady             bool
	securityDeadline          time.Time
	registerDeadline          time.Time
	drainDeadline             time.Time
	lastTime, lastStatus      time.Time
	sequence                  uint64
	reportedReady             bool
	fence, shutdown, rotating bool

	register              *v1.Register
	sessionID, previousID string
	barrier, expiry       time.Time
	timeouts              v1.RegisterAckTimeouts
	commands              map[uint64]command
	streamControlLimit    int
	admitted              bool
	streams               *wssstate.State

	probeConfigured     bool
	probeReady          bool
	probeRunning        bool
	probeTimedOut       bool
	probeDeadline       time.Time
	lastProbe           time.Time
	successes, failures int
	readiness           v1.RegisterAckReadiness
}

func New(c Config) (*State, error) {
	if c.Local != Gateway && c.Local != Service || c.MaxControlBytes < 1 || c.MaxControlBytes > v1.MaxControlBytes || c.RegisterTimeout <= 0 || c.RegisterTimeout > 10*time.Second || c.MaxCommands < 1 || c.MaxCommands > 2048 || c.MaxPendingCancels < 1 || c.MaxPendingCancels > 2048 {
		return nil, ErrProtocol
	}
	return &State{config: c, phase: Created}, nil
}

func (s *State) Snapshot() Snapshot {
	out := Snapshot{Phase: s.phase, TransportActive: s.active, CleanupRequired: s.cleanup, SessionID: s.sessionID, Sequence: s.sequence, LastStatus: s.lastStatus, Deadline: earlier(s.registerDeadline, s.drainDeadline), Fenced: s.fence, Commands: len(s.commands)}
	out.Deadline = earlier(out.Deadline, earlier(s.securityDeadline, s.expiry))
	out.ProbeOutstanding = s.probeRunning
	if s.probeRunning && !s.probeTimedOut {
		out.ProbeDeadline = s.probeDeadline
	}
	if s.streams != nil {
		out.Streams = s.streams.Stats()
		out.ReservedBytes = out.Streams.ReservedBytes + uint64(s.config.MaxCommands*commandCharge)
		out.StatusDue = s.config.Local == Service && (s.reportedReady != (s.eligible(s.lastTime) && s.phase != Draining) || s.lastStatus.IsZero() || !s.lastTime.Before(s.lastStatus.Add(time.Duration(s.timeouts.StatusIntervalMS)*time.Millisecond)))
	}
	return out
}

// Begin starts registration on an already secured new transport. Connection/TLS
// timeouts and retry backoff belong to the adapter. No second live transport is
// accepted; security authorization and all wire namespaces are reset.
func (s *State) Begin(now time.Time) error {
	if s.phase == Closed || s.active || s.cleanup || s.phase != Created && s.phase != Connecting {
		return ErrState
	}
	if err := s.clock(now); err != nil {
		s.phase = Closed
		return err
	}
	s.phase = Connecting
	s.active = true
	s.securityReady = false
	s.securityDeadline = time.Time{}
	s.registerDeadline = now.Add(s.config.RegisterTimeout)
	s.drainDeadline = time.Time{}
	s.lastStatus = time.Time{}
	s.sequence = 0
	s.reportedReady = false
	s.authorized = false
	s.excluded = false
	s.admitted = false
	s.fence = false
	s.shutdown = false
	s.rotating = false
	s.register = nil
	s.sessionID = ""
	s.barrier = time.Time{}
	s.expiry = time.Time{}
	s.commands = nil
	s.probeConfigured = false
	s.probeReady = false
	s.probeRunning = false
	s.probeTimedOut = false
	s.probeDeadline = time.Time{}
	s.lastProbe = time.Time{}
	s.successes = 0
	s.failures = 0
	s.streams = nil
	return nil
}

// AuthorizeRegistration is Gateway's explicit assertion that credential,
// permissions/conflicts and required durable control/outbox checks succeeded.
// This model does not perform or prove those checks.
func (s *State) AuthorizeRegistration(now time.Time) (Effect, error) {
	if e, err := s.Advance(now); err != nil {
		return e, err
	}
	if s.config.Local != Gateway || s.phase != Connecting || s.register == nil {
		return Effect{}, ErrState
	}
	s.authorized = true
	return Effect{}, nil
}

// Security sets verified local security readiness and an optional absolute
// deadline. It cannot extend an earlier deadline in this transport. Revocation
// should call Revoke; temporary recovery immediately removes new admission.
func (s *State) Security(ready bool, deadline, now time.Time) (Effect, error) {
	if e, err := s.Advance(now); err != nil {
		return e, err
	}
	if s.phase == Closed || !s.active {
		return Effect{}, ErrState
	}
	s.securityReady = ready
	s.securityDeadline = earlier(s.securityDeadline, deadline)
	return s.Advance(now)
}
func (s *State) Revoke(now time.Time) (Effect, error) {
	if err := s.clock(now); err != nil {
		return s.finish(false), err
	}
	return s.finish(false), ErrSecurity
}

// Advance drives registration, security, drain and stream cancel deadlines even
// without traffic. Status freshness uses receipt time, never ObservedAt.
func (s *State) Advance(now time.Time) (Effect, error) {
	if err := s.clock(now); err != nil {
		return s.finish(false), err
	}
	if s.phase == Closed {
		return Effect{}, ErrState
	}
	if !s.active {
		return Effect{}, nil
	}
	if reached(now, s.securityDeadline) || reached(now, s.expiry) {
		return s.finish(false), ErrSecurity
	}
	if reached(now, s.registerDeadline) {
		return s.finish(true), ErrTimeout
	}
	if reached(now, s.drainDeadline) {
		return s.finish(s.rotating && !s.shutdown), ErrTimeout
	}
	if s.probeRunning && !s.probeTimedOut && reached(now, s.probeDeadline) {
		s.probeTimedOut = true
		s.probeReady = false
		s.successes = 0
		s.failures = 0
	}
	if s.config.Local == Service && s.probeConfigured && !s.lastProbe.IsZero() && now.Sub(s.lastProbe) > time.Duration(s.readiness.StaleAfterMS)*time.Millisecond {
		s.probeReady = false
		s.successes = 0
		s.failures = 0
	}

	if s.streams != nil {
		if err := s.streams.CheckTimeout(now); err != nil {
			return s.finish(true), err
		}
	}
	s.refresh(now)
	return Effect{}, nil
}
func (s *State) refresh(now time.Time) {
	if s.phase != Registered && s.phase != Ready {
		return
	}
	fresh := !s.lastStatus.IsZero() && now.Sub(s.lastStatus) <= time.Duration(s.timeouts.StatusStaleMS)*time.Millisecond
	if s.eligible(now) && s.reportedReady && fresh {
		s.phase = Ready
		s.admitted = true
	} else {
		s.phase = Registered
	}
}

// Apply validates decoded values before delivery or immediately before ordered
// transmission. A write failure must call Disconnected; frames are never replayed.
// Local rejected frames do not mutate wire state. Invalid incoming frames close
// this transport; callers must execute the returned cleanup effect even on error.
func (s *State) Apply(from Role, message any, now time.Time) (Effect, error) {
	if e, err := s.Advance(now); err != nil {
		return e, err
	}
	if from != Gateway && from != Service || !s.active {
		return s.reject(from, ErrProtocol)
	}
	if m, ok := message.(v1.Chunk); ok {
		return s.streamFrame(from, m, now)
	}
	switch message.(type) {
	case v1.Register, v1.RegisterAck, v1.RegisterNack, v1.InstanceStatus,
		v1.Drain, v1.DrainAck, v1.Unregister, v1.UnregisterAck, v1.Reconnect,
		v1.RequestStart, v1.ResponseStart, v1.RequestEnd, v1.ResponseEnd,
		v1.WindowUpdate, v1.Cancel, v1.CancelAck, v1.WebSocketOpen, v1.WebSocketOpenAck, v1.WebSocketEnd:
	default:
		return s.reject(from, ErrProtocol)
	}
	valid := message.(interface{ Validate() error })
	if valid.Validate() != nil {
		return s.reject(from, ErrProtocol)
	}
	raw, err := json.Marshal(message)
	limit := s.config.MaxControlBytes
	if s.streams != nil {
		limit = s.streamControlLimit
	}
	if err != nil || len(raw) > limit {
		return s.reject(from, ErrProtocol)
	}
	switch m := message.(type) {
	case v1.Register:
		if s.phase != Connecting || from != Service || s.register != nil {
			return s.reject(from, ErrProtocol)
		}
		// Bounded deep copy: callers retain ownership of slices/maps and may mutate them.
		copy, err := v1.DecodeRegister(raw)
		if err != nil {
			return s.reject(from, err)
		}
		s.register = &copy
	case v1.RegisterAck:
		if s.phase != Connecting || from != Gateway || s.register == nil || s.config.Local == Gateway && !s.authorized || m.SessionID == s.previousID || m.ValidateForRegister(*s.register, v1.RegisterAckValidationOptions{Development: s.config.Development}) != nil || m.Limits.MaxControlBytes > s.config.MaxControlBytes {
			return s.reject(from, ErrProtocol)
		}
		if m.CredentialExpiresAt != nil && !now.Before(time.Unix(*m.CredentialExpiresAt, 0)) {
			return s.reject(from, ErrSecurity)
		}
		limits := m.Limits
		limits.BufferBytes -= s.config.MaxCommands * commandCharge
		if limits.BufferBytes <= 0 {
			return s.reject(from, ErrCapacity)
		}
		streams, err := wssstate.New(wssstate.Config{Local: s.config.Local, Limits: limits, CancelAckTimeout: time.Duration(m.Timeouts.CancelAckMS) * time.Millisecond, MaxPendingCancels: s.config.MaxPendingCancels})
		if err != nil {
			return s.reject(from, err)
		}
		s.commands = make(map[uint64]command, s.config.MaxCommands)
		s.streams = streams
		s.streamControlLimit = m.Limits.MaxControlBytes
		s.probeConfigured = s.register.ReadinessCheckConfigured
		s.readiness = m.Readiness
		s.timeouts = m.Timeouts
		s.sessionID = m.SessionID
		s.previousID = m.SessionID
		s.phase = Registered
		s.register = nil
		s.registerDeadline = time.Time{}
		s.barrier = time.Unix(m.ReadyNotBefore, 0)
		if m.CredentialExpiresAt != nil {
			s.expiry = time.Unix(*m.CredentialExpiresAt, 0)
		}
	case v1.RegisterNack:
		if s.phase != Connecting || from != Gateway || s.register == nil {
			return s.reject(from, ErrProtocol)
		}
		return s.finish(m.Retryable), nil
	case v1.InstanceStatus:
		if s.streams == nil || from != Service || uint64(m.Sequence) <= s.sequence || from == s.config.Local && m.Ready && (m.Code != "ready" || !s.eligible(now) || s.phase == Draining) {
			return s.reject(from, ErrProtocol)
		}
		s.sequence = uint64(m.Sequence)
		s.reportedReady = m.Ready && m.Code == "ready"
		s.lastStatus = now
		s.refresh(now)
	case v1.Drain:
		return s.command(from, uint64(m.CommandID), "drain", m.DeadlineMS, m.Code, now)
	case v1.Reconnect:
		if from != Gateway {
			return s.reject(from, ErrProtocol)
		}
		return s.command(from, uint64(m.CommandID), "reconnect", m.DeadlineMS, m.Code, now)
	case v1.Unregister:
		if from != Service || s.phase != Draining || !s.fence || !s.empty() || s.pendingDrains() || s.hasUnregister() {
			return s.reject(from, ErrProtocol)
		}
		return s.command(from, uint64(m.CommandID), "unregister", m.DeadlineMS, m.Code, now)
	case v1.DrainAck:
		return s.ack(from, uint64(m.CommandID), "drain", now)
	case v1.UnregisterAck:
		return s.ack(from, uint64(m.CommandID), "unregister", now)
	default:
		return s.streamFrame(from, message, now)
	}
	return Effect{}, nil
}

func (s *State) command(from Role, id uint64, kind string, ms int, code string, now time.Time) (Effect, error) {
	if s.streams == nil {
		return s.reject(from, ErrProtocol)
	}
	if _, exists := s.commands[id]; exists {
		return s.reject(from, ErrProtocol)
	}
	if len(s.commands) >= s.config.MaxCommands {
		return s.reject(from, ErrCapacity)
	}
	s.commands[id] = command{sender: from, kind: kind}
	s.phase = Draining
	limit := time.Duration(ms) * time.Millisecond
	if negotiated := time.Duration(s.timeouts.DrainMS) * time.Millisecond; limit > negotiated {
		limit = negotiated
	}
	s.drainDeadline = earlier(s.drainDeadline, now.Add(limit))
	if kind == "reconnect" || code == "credential_rotation" {
		s.rotating = true
	} else if kind == "drain" {
		s.shutdown = true
	}
	// Gateway never creates a new assignment after initiating/receiving drain.
	// At Service a Gateway-origin command follows all prior starts in its writer;
	// Service-origin drain waits for the returning Gateway drain_ack fence.
	if s.config.Local == Gateway || from == Gateway {
		s.fence = true
	}
	if kind == "drain" && from != s.config.Local {
		return Effect{Reply: &v1.DrainAck{Type: "drain_ack", CommandID: v1.U64(id)}}, nil
	}
	return Effect{}, nil
}
func (s *State) ack(from Role, id uint64, kind string, now time.Time) (Effect, error) {
	c, ok := s.commands[id]
	if !ok || c.kind != kind || c.sender == from || c.acked {
		return s.reject(from, ErrProtocol)
	}
	if kind == "unregister" && (from != Gateway || !s.empty() || s.config.Local == Gateway && !s.excluded) {
		return s.reject(from, ErrProtocol)
	}
	c.acked = true
	s.commands[id] = c
	if kind == "drain" {
		if from == Gateway {
			s.fence = true
		}
		return Effect{}, nil
	}
	return s.finish(s.rotating && !s.shutdown), nil
}

// ConfirmExcluded asserts Gateway's actual session exclusion and cleanup, after
// receiving unregister and before writing unregister_ack. Durable route ownership
// is outside this model and must not be deleted by cleanup.
func (s *State) ConfirmExcluded(now time.Time) (Effect, error) {
	if e, err := s.Advance(now); err != nil {
		return e, err
	}
	if s.config.Local != Gateway || s.phase != Draining || !s.empty() {
		return Effect{}, ErrState
	}
	pending := false
	for _, c := range s.commands {
		pending = pending || c.kind == "unregister" && !c.acked
	}
	if !pending {
		return Effect{}, ErrState
	}
	s.excluded = true
	return Effect{}, nil
}

func (s *State) streamFrame(from Role, m any, now time.Time) (Effect, error) {
	if s.streams == nil {
		return s.reject(from, ErrProtocol)
	}
	start := false
	switch m.(type) {
	case v1.RequestStart, v1.WebSocketOpen:
		start = true
	}
	if start {
		allowed := s.phase == Ready && !s.fence
		if s.config.Local == Service {
			allowed = s.admitted && !s.fence && s.securityReady && !now.Before(s.barrier)
		}
		if !allowed {
			return s.reject(from, ErrState)
		}
	}
	e, err := s.streams.Apply(from, m, now)
	if err != nil && err != wssstate.ErrBodyLength && from != s.config.Local {
		out, _ := s.reject(from, err)
		out.Stream = e
		return out, err
	}
	return Effect{Stream: e}, err
}

func (s *State) Consume(id uint64, direction string, n uint64, now time.Time) (Effect, error) {
	if e, err := s.Advance(now); err != nil {
		return e, err
	}
	if s.streams == nil {
		return Effect{}, ErrState
	}
	e, err := s.streams.Consume(id, direction, n)
	return Effect{Stream: e}, err
}

// Close requests final shutdown. Repeated calls only shorten its deadline;
// Close during rotation suppresses reconnect. Service must still send drain and
// wait for the Gateway fence; the adapter owns command IDs and ordered writes.
func (s *State) Close(deadline, now time.Time) (Effect, error) {
	if s.phase == Closed {
		return Effect{}, nil
	}
	s.shutdown = true
	if e, err := s.Advance(now); err != nil {
		return e, err
	}
	if !s.active || s.streams == nil {
		return s.finish(false), nil
	}
	s.phase = Draining
	if s.config.Local == Gateway {
		s.fence = true
	}
	bound := earlier(now.Add(30*time.Second), now.Add(time.Duration(s.timeouts.DrainMS)*time.Millisecond))
	s.drainDeadline = earlier(s.drainDeadline, earlier(bound, deadline))
	return s.Advance(now)
}

// Disconnected invalidates every stream and namespace, without application retry.
// A new transport requires Cleaned and Begin; transport backoff is external.
func (s *State) Disconnected(retry bool, now time.Time) (Effect, error) {
	if err := s.clock(now); err != nil {
		return s.finish(false), err
	}
	if !s.active {
		return Effect{}, ErrState
	}
	return s.finish(retry && !s.shutdown), nil
}

// Cleaned confirms the adapter has closed the old transport and released every
// handler/queue/stream resource, including the outstanding readiness invocation.
// It does not start another connection; an uncooperative callback blocks reconnect.
func (s *State) Cleaned(now time.Time) error {
	if s.active || !s.cleanup || s.probeRunning {
		return ErrState
	}
	if err := s.clock(now); err != nil {
		s.phase = Closed
		return err
	}
	s.cleanup = false
	return nil
}
func (s *State) finish(retry bool) Effect {
	active := s.active
	s.active = false
	s.cleanup = s.cleanup || active
	if retry && !s.shutdown {
		s.phase = Connecting
	} else {
		s.phase = Closed
	}
	s.register = nil
	s.streams = nil
	s.commands = nil
	s.securityReady = false
	s.registerDeadline = time.Time{}
	s.drainDeadline = time.Time{}
	return Effect{CloseTransport: active, StopAll: active, CleanupRequired: s.cleanup, Reconnect: s.phase == Connecting}
}
func (s *State) reject(from Role, err error) (Effect, error) {
	if from != s.config.Local {
		return s.finish(false), err
	}
	return Effect{}, err
}
func (s *State) empty() bool {
	return s.streams != nil && s.streams.Stats().Active == 0 && s.streams.Stats().PendingCancels == 0
}
func (s *State) hasUnregister() bool {
	for _, c := range s.commands {
		if c.kind == "unregister" {
			return true
		}
	}
	return false
}

func (s *State) pendingDrains() bool {
	for _, c := range s.commands {
		if c.kind == "drain" && !c.acked {
			return true
		}
	}
	return false
}
func (s *State) clock(now time.Time) error {
	if now.IsZero() || !s.lastTime.IsZero() && now.Before(s.lastTime) {
		return ErrProtocol
	}
	s.lastTime = now
	return nil
}
func earlier(a, b time.Time) time.Time {
	if a.IsZero() || !b.IsZero() && b.Before(a) {
		return b
	}
	return a
}
func reached(now, deadline time.Time) bool { return !deadline.IsZero() && !now.Before(deadline) }

func (s *State) eligible(now time.Time) bool {
	return s.securityReady && !now.Before(s.barrier) && (s.config.Local == Gateway || !s.probeConfigured || s.probeReady)
}

// StartProbe reserves the sole local readiness callback slot. The adapter calls
// the callback outside this model. A timed-out invocation retains its slot until
// FinishProbe, so an uncooperative callback cannot cause unbounded goroutines.
func (s *State) StartProbe(now time.Time) (Effect, error) {
	if e, err := s.Advance(now); err != nil {
		return e, err
	}
	if s.config.Local != Service || !s.probeConfigured || s.streams == nil || s.phase == Draining || s.probeRunning {
		return Effect{}, ErrState
	}
	s.probeRunning = true
	s.probeTimedOut = false
	s.probeDeadline = now.Add(time.Duration(s.readiness.TimeoutMS) * time.Millisecond)
	return Effect{}, nil
}

// FinishProbe applies negotiated consecutive success/failure thresholds. A late
// result releases its slot but cannot turn a timed-out sample into success.
func (s *State) FinishProbe(success bool, now time.Time) (Effect, error) {
	// Completion of a retired transport's invocation releases its slot only.
	if !s.active && s.probeRunning {
		if err := s.clock(now); err != nil {
			return s.finish(false), err
		}
		s.probeRunning = false
		s.probeDeadline = time.Time{}
		s.probeReady = false
		return Effect{}, nil
	}
	if e, err := s.Advance(now); err != nil {
		if !s.active {
			s.probeRunning = false
			s.probeDeadline = time.Time{}
			s.probeReady = false
		}
		return e, err
	}
	if !s.probeRunning {
		return Effect{}, ErrState
	}
	s.probeRunning = false
	s.probeDeadline = time.Time{}
	if !s.probeTimedOut {
		s.lastProbe = now
		if success {
			s.failures = 0
			if s.successes < s.readiness.SuccessThreshold {
				s.successes++
			}
			if s.successes >= s.readiness.SuccessThreshold {
				s.probeReady = true
			}
		} else {
			s.successes = 0
			if s.failures < s.readiness.FailureThreshold {
				s.failures++
			}
			if s.failures >= s.readiness.FailureThreshold {
				s.probeReady = false
			}
		}
	}
	s.refresh(now)
	return Effect{}, nil
}
