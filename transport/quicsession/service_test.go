package quicsession

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/solodyagin/outgate-sdk/internal/quictest"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/sessionstate"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
	"github.com/solodyagin/outgate-sdk/transport/quichttp"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func await[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("operation stalled")
		var zero T
		return zero
	}
}

func pair(t *testing.T, probe bool, change func(*v1.RegisterAck)) (*quiccontrol.Carrier, *quiccontrol.Carrier) {
	t.Helper()
	sc, gc := quictest.Pair(t, true, v1.QUICALPN)
	r, a := quictest.Fixtures(t, true)
	r.ProtocolMinor, a.ProtocolMinor = 1, 1
	r.Capabilities = append(r.Capabilities, v1.QUICQuiescentFenceCapability)
	r.RequiredCapabilities = append(r.RequiredCapabilities, v1.QUICQuiescentFenceCapability)
	a.Capabilities = append(a.Capabilities, v1.QUICQuiescentFenceCapability)
	a.RequiredCapabilities = append(a.RequiredCapabilities, v1.QUICQuiescentFenceCapability)
	r.ReadinessCheckConfigured = probe
	a.Readiness.Required = probe
	a.ReadyNotBefore = time.Now().Add(-time.Second).Unix()
	a.Timeouts.StatusIntervalMS, a.Timeouts.StatusStaleMS = 50, 200
	a.Readiness.IntervalMS, a.Readiness.TimeoutMS, a.Readiness.StaleAfterMS = 30, 20, 200
	a.Readiness.SuccessThreshold, a.Readiness.FailureThreshold = 1, 1
	if change != nil {
		change(&a)
	}
	must(t, a.ValidateForRegister(r, v1.RegisterAckValidationOptions{}))
	result := make(chan *quiccontrol.Carrier, 1)
	go func() {
		c, err := quiccontrol.Accept(t.Context(), gc, quiccontrol.Options{}, func(context.Context, tls.ConnectionState, []byte, v1.Register) (v1.RegisterAck, error) { return a, nil })
		if err != nil {
			result <- nil
		} else {
			result <- c
		}
	}()
	s, ack, err := quiccontrol.Open(t.Context(), sc, quiccontrol.Options{}, []byte("test-only-grant"), r)
	must(t, err)
	g := await(t, result)
	if g == nil {
		t.Fatal("accept failed")
	}
	// Neither an Open result nor a returned Registration copy can replace the
	// immutable actual limits/expiry/negotiation consumed by the driver.
	ack.Limits.MaxInflight = 0
	copyR, copyA, _ := s.Registration()
	copyR.Capabilities[0] = "mutated"
	copyA.RequiredCapabilities[0] = "mutated"
	*copyA.CredentialExpiresAt = 1
	_, actual, _ := s.Registration()
	if actual.Limits.MaxInflight == 0 || *actual.CredentialExpiresAt == 1 {
		t.Fatal("mutable bootstrap snapshot")
	}
	t.Cleanup(func() { _ = s.Close(); _ = g.Close() })
	return s, g
}

func start(t *testing.T, c *quiccontrol.Carrier, handler http.Handler, o Options) *Service {
	t.Helper()
	o.TickInterval = time.Millisecond
	s, err := NewService(c, handler, o)
	must(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.Close(ctx)
	})
	return s
}

func receive(t *testing.T, g *quiccontrol.Carrier, predicate func(any) bool) any {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	for {
		m, err := g.Receive(ctx)
		must(t, err)
		if predicate(m) {
			return m
		}
	}
}
func status(t *testing.T, g *quiccontrol.Carrier, ready bool) v1.InstanceStatus {
	t.Helper()
	return receive(t, g, func(m any) bool { v, ok := m.(v1.InstanceStatus); return ok && v.Ready == ready }).(v1.InstanceStatus)
}
func control(t *testing.T, g *quiccontrol.Carrier) any {
	t.Helper()
	return receive(t, g, func(m any) bool { _, ok := m.(v1.InstanceStatus); return !ok })
}
func terminal(t *testing.T, g *quiccontrol.Carrier, s *Service, wantReconnect bool) {
	t.Helper()
	u, ok := control(t, g).(v1.Unregister)
	if !ok {
		t.Fatal("unregister missing")
	}
	must(t, g.Send(t.Context(), v1.UnregisterAck{Type: "unregister_ack", CommandID: u.CommandID}))
	await(t, s.Done())
	must(t, s.Err())
	await(t, g.Done())
	var appErr *quic.ApplicationError
	if !errors.As(g.Err(), &appErr) || !appErr.Remote || appErr.ErrorCode != quiccontrol.CodeNormal {
		t.Fatal("terminal ack did not produce a normal peer close", g.Err())
	}
	if s.ReconnectRequested() != wantReconnect || s.Snapshot().CleanupRequired {
		t.Fatal("incorrect cleanup/reconnect")
	}
}
func request(t *testing.T, g *quichttp.Gateway) *http.Response {
	t.Helper()
	r, err := http.NewRequestWithContext(t.Context(), "GET", "https://public.example.test/api", nil)
	must(t, err)
	response, err := g.RoundTrip(r)
	must(t, err)
	_, err = io.Copy(io.Discard, response.Body)
	must(t, err)
	must(t, response.Body.Close())
	return response
}

func TestReadinessSecurityAndGatewayDrain(t *testing.T) {
	c, g := pair(t, false, nil)
	var calls atomic.Int32
	s := start(t, c, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(204) }), Options{})
	first := status(t, g, false)
	if first.Sequence != 1 {
		t.Fatal("missing initial status")
	}
	h, err := quichttp.NewGateway(g)
	must(t, err)
	if request(t, h).StatusCode != 503 || calls.Load() != 0 {
		t.Fatal("dispatch before verified readiness")
	}
	must(t, s.SetSecurity(true, time.Time{}))
	status(t, g, true)
	if request(t, h).StatusCode != 204 || calls.Load() != 1 {
		t.Fatal("ready handler missing")
	}
	must(t, g.Send(t.Context(), v1.Drain{Type: "drain", CommandID: 1, DeadlineMS: 2000, Code: "shutdown", Extensions: v1.QUICQuiescentFenceExtensions(h.Pause())}))
	ack, ok := control(t, g).(v1.DrainAck)
	if !ok || ack.CommandID != 1 {
		t.Fatal("missing drain acknowledgement")
	}
	terminal(t, g, s, false)
}

func TestServiceDrainAndCrossedCommands(t *testing.T) {
	c, g := pair(t, false, nil)
	s := start(t, c, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), Options{SecurityReady: true})
	status(t, g, true)
	result := make(chan error, 1)
	go func() { result <- s.Drain(t.Context()) }()
	drain, ok := control(t, g).(v1.Drain)
	if !ok {
		t.Fatal("missing service drain")
	}
	must(t, g.Send(t.Context(), v1.Drain{Type: "drain", CommandID: 1, DeadlineMS: 2000, Code: "shutdown", Extensions: v1.QUICQuiescentFenceExtensions(0)}))
	if ack, ok := control(t, g).(v1.DrainAck); !ok || ack.CommandID != 1 {
		t.Fatal("missing crossed ack")
	}
	// Both commands must be acknowledged before unregister.
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	for {
		m, err := g.Receive(ctx)
		if err != nil {
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal(err)
			}
			break
		}
		if _, ok := m.(v1.Unregister); ok {
			t.Fatal("crossed ledger bypass")
		}
	}
	cancel()
	must(t, g.Send(t.Context(), v1.DrainAck{Type: "drain_ack", CommandID: drain.CommandID, Extensions: v1.QUICQuiescentFenceExtensions(0)}))
	terminal(t, g, s, false)
	must(t, await(t, result))
}

func TestRotationHintAndFinalClose(t *testing.T) {
	for _, final := range []bool{false, true} {
		t.Run(map[bool]string{false: "rotation", true: "final"}[final], func(t *testing.T) {
			c, g := pair(t, false, nil)
			s := start(t, c, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), Options{SecurityReady: true})
			status(t, g, true)
			must(t, g.Send(t.Context(), v1.Reconnect{Type: "reconnect", CommandID: 1, DeadlineMS: 2000, Code: "credential_rotation", Extensions: v1.QUICQuiescentFenceExtensions(0)}))
			u, ok := control(t, g).(v1.Unregister)
			if !ok {
				t.Fatal("unregister missing")
			}
			if s.ReconnectRequested() {
				t.Fatal("reconnect before cleanup")
			}
			// Unregister must be the final S frame, so a delayed terminal ack
			// cannot race a periodic status write and close with protocol_error.
			quiet, cancelQuiet := context.WithTimeout(t.Context(), 80*time.Millisecond)
			if m, err := g.Receive(quiet); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("frame after unregister", m, err)
			}
			cancelQuiet()
			var drained chan error
			if final {
				drained = make(chan error, 1)
				go func() { drained <- s.Drain(t.Context()) }()
				for !s.closeRequested() {
					time.Sleep(time.Millisecond)
				}
			}
			must(t, g.Send(t.Context(), v1.UnregisterAck{Type: "unregister_ack", CommandID: u.CommandID}))
			await(t, s.Done())
			must(t, s.Err())
			if s.ReconnectRequested() == final {
				t.Fatal("incorrect final intent")
			}
			if final {
				must(t, await(t, drained))
			}
		})
	}
}
func (s *Service) closeRequested() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.closeIntent }

func TestProbeTimeoutRetainsSlotAndActualCleanup(t *testing.T) {
	c, g := pair(t, true, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	s := start(t, c, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unexpected handler") }), Options{SecurityReady: true, ReadinessCheck: func(ctx context.Context) error { calls.Add(1); close(entered); <-release; return nil }})
	await(t, entered)
	status(t, g, false)
	time.Sleep(90 * time.Millisecond)
	if calls.Load() != 1 || !s.Snapshot().ProbeOutstanding || s.Snapshot().LocalReady {
		t.Fatal("timeout did not retain sole slot")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if !errors.Is(s.Close(ctx), context.DeadlineExceeded) {
		t.Fatal("close did not wait for actual callback")
	}
	select {
	case <-s.Done():
		t.Fatal("false cleanup")
	default:
	}
	close(release)
	await(t, s.Done())
	if s.Snapshot().ProbeOutstanding || s.ReconnectRequested() {
		t.Fatal("old callback leaked readiness")
	}
}

func TestProbePanicAndThresholds(t *testing.T) {
	c, g := pair(t, true, func(a *v1.RegisterAck) { a.Readiness.SuccessThreshold = 2 })
	var calls atomic.Int32
	s := start(t, c, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), Options{SecurityReady: true, ReadinessCheck: func(context.Context) error {
		if calls.Add(1) == 1 {
			panic("private callback text")
		}
		return nil
	}})
	status(t, g, false)
	status(t, g, true)
	if calls.Load() < 3 || !s.Snapshot().LocalReady {
		t.Fatal("threshold bypass")
	}
	s.Revoke()
	await(t, s.Done())
	if !errors.Is(s.Err(), sessionstate.ErrSecurity) || s.ReconnectRequested() {
		t.Fatal("revocation did not preempt")
	}
}

func TestInvalidFenceAndExpiry(t *testing.T) {
	for _, expiry := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing_fence", true: "security_deadline"}[expiry], func(t *testing.T) {
			c, g := pair(t, false, nil)
			o := Options{SecurityReady: true}
			if expiry {
				o.SecurityDeadline = time.Now().Add(40 * time.Millisecond)
			}
			s := start(t, c, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), o)
			status(t, g, true)
			if !expiry {
				must(t, g.Send(t.Context(), v1.Drain{Type: "drain", CommandID: 1, DeadlineMS: 1000, Code: "shutdown"}))
			}
			await(t, s.Done())
			if s.Err() == nil || s.ReconnectRequested() {
				t.Fatal("accepted invalid/expired session")
			}
		})
	}
}

func TestUncooperativeHandlerBlocksTerminalCleanup(t *testing.T) {
	c, g := pair(t, false, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	s := start(t, c, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { close(entered); <-release }), Options{SecurityReady: true})
	status(t, g, true)
	h, err := quichttp.NewGateway(g)
	must(t, err)
	requestDone := make(chan error, 1)
	requestCtx, cancelRequest := context.WithCancel(t.Context())
	defer cancelRequest()
	go func() {
		r, _ := http.NewRequestWithContext(requestCtx, "GET", "https://public.example.test/api", nil)
		response, err := h.RoundTrip(r)
		if response != nil {
			_ = response.Body.Close()
		}
		requestDone <- err
	}()
	await(t, entered)
	cancelRequest()
	_ = await(t, requestDone)
	must(t, g.Send(t.Context(), v1.Drain{Type: "drain", CommandID: 1, DeadlineMS: 30, Code: "shutdown", Extensions: v1.QUICQuiescentFenceExtensions(h.Pause())}))
	// No fake ack/unregister while the actual handler is still running. Deadline
	// closes the carrier, yet Done waits for its resource ownership to end.
	await(t, c.Done())
	select {
	case <-s.Done():
		t.Fatal("handler still owns resources")
	default:
	}
	close(release)
	await(t, s.Done())
	if s.Err() == nil || s.Snapshot().NativeActive != 0 {
		t.Fatal("incorrect deadline cleanup")
	}
}

func TestDrainWaitsForReadinessInvocation(t *testing.T) {
	c, g := pair(t, true, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	s := start(t, c, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), Options{SecurityReady: true, ReadinessCheck: func(context.Context) error { close(entered); <-release; return nil }})
	await(t, entered)
	must(t, g.Send(t.Context(), v1.Drain{Type: "drain", CommandID: 1, DeadlineMS: 2000, Code: "shutdown", Extensions: v1.QUICQuiescentFenceExtensions(0)}))
	if _, ok := control(t, g).(v1.DrainAck); !ok {
		t.Fatal("missing drain ack")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	for {
		m, err := g.Receive(ctx)
		if err != nil {
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal(err)
			}
			break
		}
		if _, ok := m.(v1.Unregister); ok {
			t.Fatal("callback ownership bypass")
		}
	}
	cancel()
	close(release)
	terminal(t, g, s, false)
}

func TestLateProbeCannotRestoreReady(t *testing.T) {
	c, g := pair(t, true, nil)
	entered, release, second := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	s := start(t, c, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), Options{SecurityReady: true, ReadinessCheck: func(ctx context.Context) error {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
			return nil
		}
		close(second)
		<-ctx.Done()
		return ctx.Err()
	}})
	await(t, entered)
	time.Sleep(40 * time.Millisecond)
	close(release)
	await(t, second)
	if s.Snapshot().LocalReady {
		t.Fatal("late successful result restored readiness")
	}
	status(t, g, false)
}

func TestInvalidCommandLedger(t *testing.T) {
	for _, scenario := range []string{"duplicate", "wrong_ack", "increasing_fence"} {
		t.Run(scenario, func(t *testing.T) {
			c, g := pair(t, false, nil)
			s := start(t, c, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), Options{SecurityReady: true})
			status(t, g, true)
			if scenario == "wrong_ack" {
				must(t, g.Send(t.Context(), v1.UnregisterAck{Type: "unregister_ack", CommandID: 999}))
			} else {
				must(t, g.Send(t.Context(), v1.Drain{Type: "drain", CommandID: 1, DeadlineMS: 2000, Code: "shutdown", Extensions: v1.QUICQuiescentFenceExtensions(0)}))
				control(t, g)
				id, fence := v1.U64(1), uint64(0)
				if scenario == "increasing_fence" {
					id, fence = 2, 1
				}
				must(t, g.Send(t.Context(), v1.Drain{Type: "drain", CommandID: id, DeadlineMS: 2000, Code: "shutdown", Extensions: v1.QUICQuiescentFenceExtensions(fence)}))
			}
			await(t, s.Done())
			if s.Err() == nil || s.ReconnectRequested() {
				t.Fatal("invalid ledger accepted")
			}
		})
	}
}

func TestConstructorRejectsMismatchedConfiguration(t *testing.T) {
	c, g := pair(t, false, nil)
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	for _, o := range []Options{{ReadinessCheck: func(context.Context) error { return nil }}, {MaxCommands: -1}, {TickInterval: -time.Second}} {
		if _, err := NewService(c, handler, o); err == nil {
			t.Fatal("invalid options accepted")
		}
	}
	if _, err := NewService(g, handler, Options{}); err == nil {
		t.Fatal("gateway role accepted")
	}
	s := start(t, c, handler, Options{SecurityReady: true})
	status(t, g, true)
	if _, err := NewService(c, handler, Options{}); err == nil {
		t.Fatal("duplicate owner accepted")
	}
	must(t, s.Close(t.Context()))
}

func TestSecurityDeadlineDoesNotWaitForPeriodicTick(t *testing.T) {
	c, g := pair(t, false, func(a *v1.RegisterAck) { a.Timeouts.StatusIntervalMS, a.Timeouts.StatusStaleMS = 5000, 15000 })
	s, err := NewService(c, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), Options{SecurityReady: true, SecurityDeadline: time.Now().Add(40 * time.Millisecond), TickInterval: time.Second})
	must(t, err)
	t.Cleanup(func() { _ = s.Close(t.Context()) })
	status(t, g, true)
	select {
	case <-s.Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("security expiry waited for periodic tick")
	}
	if !errors.Is(s.Err(), sessionstate.ErrSecurity) {
		t.Fatal(s.Err())
	}
}

func TestServiceRenewSecurityReplacesOnlyFreshnessLease(t *testing.T) {
	c, g := pair(t, false, nil)
	s := start(t, c, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), Options{SecurityReady: true})
	status(t, g, true)
	must(t, s.RenewSecurity(true, time.Now().Add(150*time.Millisecond)))
	for range 4 {
		select {
		case <-s.Done():
			t.Fatal("fresh lease expired", s.Err())
		case <-time.After(40 * time.Millisecond):
		}
		must(t, s.RenewSecurity(true, time.Now().Add(150*time.Millisecond)))
	}
	if !s.Snapshot().TransportActive {
		t.Fatal("refresh did not keep transport active")
	}
	s.Revoke()
	if err := s.RenewSecurity(true, time.Now().Add(time.Second)); err == nil {
		t.Fatal("renewal revived revoked service")
	}
	await(t, s.Done())
}
