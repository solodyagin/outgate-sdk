package client

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/solodyagin/outgate-sdk/internal/quictest"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/sessionstate"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
	"github.com/solodyagin/outgate-sdk/transport/quichttp"
	"github.com/solodyagin/outgate-sdk/transport/quicsession"
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
func eventually(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatal("condition stalled")
		}
		time.Sleep(time.Millisecond)
	}
}

func pair(t *testing.T, id byte) (*quiccontrol.Carrier, *quiccontrol.Carrier) {
	return pairProfile(t, id, false, false, "")
}

func pairProfile(t *testing.T, id byte, probe, development bool, suffix string) (*quiccontrol.Carrier, *quiccontrol.Carrier) {
	t.Helper()
	sc, gc := quictest.Pair(t, true, v1.QUICALPN)
	b, err := os.ReadFile("../tests/fixtures/protocol/v1/control-messages.json")
	must(t, err)
	var corpus struct{ Positive []json.RawMessage }
	must(t, json.Unmarshal(b, &corpus))
	var r v1.Register
	var a v1.RegisterAck
	for _, b := range corpus.Positive {
		var tag struct{ Type string }
		must(t, json.Unmarshal(b, &tag))
		switch tag.Type {
		case "register":
			r, err = v1.DecodeRegister(b)
			must(t, err)
		case "register_ack":
			a, err = v1.DecodeRegisterAck(b)
			must(t, err)
		}
	}
	r.ProtocolMinor, a.ProtocolMinor = 1, 1
	r.Capabilities = append(r.Capabilities, v1.QUICQuiescentFenceCapability)
	r.RequiredCapabilities = append(r.RequiredCapabilities, v1.QUICQuiescentFenceCapability)
	a.Capabilities = append(a.Capabilities, v1.QUICQuiescentFenceCapability)
	a.RequiredCapabilities = append(a.RequiredCapabilities, v1.QUICQuiescentFenceCapability)
	r.InstanceID += suffix
	r.ReadinessCheckConfigured = probe
	a.Readiness.Required = probe
	a.Readiness.IntervalMS, a.Readiness.TimeoutMS, a.Readiness.StaleAfterMS = 20, 100, 1000
	a.Readiness.SuccessThreshold = 1
	a.ReadyNotBefore = time.Now().Add(-time.Second).Unix()
	expiry := time.Now().Add(time.Hour).Unix()
	a.CredentialExpiresAt = &expiry
	var sid [16]byte
	sid[0] = id
	a.SessionID = base64.RawURLEncoding.EncodeToString(sid[:])
	accepted := make(chan *quiccontrol.Carrier, 1)
	go func() {
		g, err := quiccontrol.Accept(t.Context(), gc, quiccontrol.Options{Development: development}, func(context.Context, tls.ConnectionState, []byte, v1.Register) (v1.RegisterAck, error) { return a, nil })
		if err != nil {
			accepted <- nil
		} else {
			accepted <- g
		}
	}()
	s, _, err := quiccontrol.Open(t.Context(), sc, quiccontrol.Options{Development: development}, []byte("test-only-grant"), r)
	must(t, err)
	g := await(t, accepted)
	if g == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = s.Close(); _ = g.Close() })
	return s, g
}
func config(connect Connect) Config {
	return Config{Connect: connect, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }), BackoffMin: time.Millisecond, BackoffMax: 2 * time.Millisecond}
}
func run(t *testing.T, c *Client, ctx context.Context) <-chan error {
	t.Helper()
	result := make(chan error, 1)
	go func() { result <- c.Run(ctx) }()
	return result
}
func receive(t *testing.T, g *quiccontrol.Carrier, kind string) any {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	for {
		m, err := g.Receive(ctx)
		must(t, err)
		switch kind {
		case "status":
			if v, ok := m.(v1.InstanceStatus); ok && v.Ready {
				return v
			}
		case "drain":
			if _, ok := m.(v1.Drain); ok {
				return m
			}
		case "unregister":
			if _, ok := m.(v1.Unregister); ok {
				return m
			}
		}
	}
}
func acknowledgeDrain(t *testing.T, g *quiccontrol.Carrier) {
	t.Helper()
	m := receive(t, g, "drain").(v1.Drain)
	must(t, g.Send(t.Context(), v1.DrainAck{Type: "drain_ack", CommandID: m.CommandID, Extensions: v1.QUICQuiescentFenceExtensions(0)}))
	u := receive(t, g, "unregister").(v1.Unregister)
	must(t, g.Send(t.Context(), v1.UnregisterAck{Type: "unregister_ack", CommandID: u.CommandID}))
}

func TestNewCloseBeforeRunAndSafeErrors(t *testing.T) {
	var calls atomic.Int32
	c, err := New(config(func(context.Context) (*quiccontrol.Carrier, quicsession.Options, error) {
		calls.Add(1)
		return nil, quicsession.Options{}, errors.New("secret")
	}))
	must(t, err)
	if c.Status().State != sessionstate.Created || calls.Load() != 0 {
		t.Fatal("New performed I/O")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel()
	if !errors.Is(c.WaitReady(ctx), context.DeadlineExceeded) {
		t.Fatal("WaitReady started Run")
	}
	must(t, c.Close(t.Context()))
	must(t, c.Close(t.Context()))
	if !errors.Is(c.Run(t.Context()), ErrClientClosed) || !errors.Is(c.WaitReady(t.Context()), ErrClientClosed) || calls.Load() != 0 {
		t.Fatal("closed client started")
	}
	e := &Error{Code: TransportFailure, cause: errors.New("secret")}
	if e.Error() != "outgate: transport_failure" {
		t.Fatal("unsafe error")
	}
}

func TestRunReadyAndConcurrentClose(t *testing.T) {
	s, g := pair(t, 1)
	c, err := New(config(func(context.Context) (*quiccontrol.Carrier, quicsession.Options, error) {
		return s, quicsession.Options{SecurityReady: true}, nil
	}))
	must(t, err)
	running := run(t, c, t.Context())
	must(t, c.WaitReady(t.Context()))
	receive(t, g, "status")
	if !errors.Is(c.Run(t.Context()), ErrAlreadyStarted) {
		t.Fatal("second Run accepted")
	}
	status := c.Status()
	if !status.Connected || status.ReadySince.IsZero() || status.ConnectedSince.IsZero() || status.Transport != "quic" {
		t.Fatal(status)
	}
	closed := make(chan error, 8)
	for range 8 {
		go func() { closed <- c.Close(t.Context()) }()
	}
	acknowledgeDrain(t, g)
	for range 8 {
		must(t, await(t, closed))
	}
	must(t, await(t, running))
	await(t, c.Done())
	if c.Status().State != sessionstate.Closed {
		t.Fatal(c.Status())
	}
}

func TestRunCancellationDrains(t *testing.T) {
	s, g := pair(t, 1)
	c, err := New(config(func(context.Context) (*quiccontrol.Carrier, quicsession.Options, error) {
		return s, quicsession.Options{SecurityReady: true}, nil
	}))
	must(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	running := run(t, c, ctx)
	must(t, c.WaitReady(t.Context()))
	cancel()
	acknowledgeDrain(t, g)
	must(t, await(t, running))
}

func TestShorterCloseDeadlineForcesOneCleanup(t *testing.T) {
	s, g := pair(t, 1)
	var calls atomic.Int32
	c, err := New(config(func(context.Context) (*quiccontrol.Carrier, quicsession.Options, error) {
		calls.Add(1)
		return s, quicsession.Options{SecurityReady: true}, nil
	}))
	must(t, err)
	running := run(t, c, t.Context())
	must(t, c.WaitReady(t.Context()))
	long := make(chan error, 1)
	go func() { long <- c.Close(t.Context()) }()
	receive(t, g, "drain")
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if !errors.Is(c.Close(ctx), context.DeadlineExceeded) {
		t.Fatal("short deadline ignored")
	}
	if err := await(t, running); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	_ = await(t, long)
	if calls.Load() != 1 {
		t.Fatal("Close reconnected")
	}
}

func TestBlockedConnectorRetainsSlot(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	cfg := config(func(ctx context.Context) (*quiccontrol.Carrier, quicsession.Options, error) {
		calls.Add(1)
		close(entered)
		<-release
		return nil, quicsession.Options{}, ctx.Err()
	})
	cfg.ConnectTimeout = 10 * time.Millisecond
	c, err := New(cfg)
	must(t, err)
	running := run(t, c, t.Context())
	await(t, entered)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if !errors.Is(c.Close(ctx), context.DeadlineExceeded) {
		t.Fatal("connector ownership forgotten")
	}
	select {
	case <-c.Done():
		t.Fatal("false cleanup")
	default:
	}
	if calls.Load() != 1 {
		t.Fatal("overlapping attempts")
	}
	close(release)
	if err := await(t, running); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("late connector cleanup hid shutdown timeout", err)
	}
	await(t, c.Done())
}

func TestRotationReconnectAndSessionIDReuse(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "reused"}[reuse], func(t *testing.T) {
			s1, g1 := pair(t, 1)
			id := byte(2)
			if reuse {
				id = 1
			}
			s2, g2 := pair(t, id)
			var calls atomic.Int32
			c, err := New(config(func(context.Context) (*quiccontrol.Carrier, quicsession.Options, error) {
				n := calls.Add(1)
				if n == 1 {
					return s1, quicsession.Options{SecurityReady: true}, nil
				}
				if n == 2 {
					return s2, quicsession.Options{SecurityReady: true}, nil
				}
				return nil, quicsession.Options{}, errors.New("unexpected attempt")
			}))
			must(t, err)
			running := run(t, c, t.Context())
			must(t, c.WaitReady(t.Context()))
			receive(t, g1, "status")
			must(t, g1.Send(t.Context(), v1.Reconnect{Type: "reconnect", CommandID: 1, DeadlineMS: 2000, Code: "credential_rotation", Extensions: v1.QUICQuiescentFenceExtensions(0)}))
			u := receive(t, g1, "unregister").(v1.Unregister)
			if calls.Load() != 1 {
				t.Fatal("new connection before terminal ack")
			}
			must(t, g1.Send(t.Context(), v1.UnregisterAck{Type: "unregister_ack", CommandID: u.CommandID}))
			if reuse {
				err := await(t, running)
				var e *Error
				if !errors.As(err, &e) || e.Code != ProtocolFailure {
					t.Fatal(err)
				}
				return
			}
			receive(t, g2, "status")
			must(t, c.WaitReady(t.Context()))
			if calls.Load() != 2 {
				t.Fatal("missing reconnect")
			}
			closed := make(chan error, 1)
			go func() { closed <- c.Close(t.Context()) }()
			acknowledgeDrain(t, g2)
			must(t, await(t, closed))
			must(t, await(t, running))
		})
	}
}

func TestTransientConnectRetryAndFatalFailure(t *testing.T) {
	var calls atomic.Int32
	c, err := New(config(func(context.Context) (*quiccontrol.Carrier, quicsession.Options, error) {
		if calls.Add(1) < 3 {
			return nil, quicsession.Options{}, context.DeadlineExceeded
		}
		return nil, quicsession.Options{}, errors.New("private credential detail")
	}))
	must(t, err)
	err = c.Run(t.Context())
	if calls.Load() != 3 || err.Error() != "outgate: transport_failure" || c.Status().LastErrorCode != TransportFailure {
		t.Fatal(err, c.Status(), calls.Load())
	}
}

func TestConnectorPanicIsTerminal(t *testing.T) {
	c, err := New(config(func(context.Context) (*quiccontrol.Carrier, quicsession.Options, error) { panic("private panic") }))
	must(t, err)
	err = c.Run(t.Context())
	if err == nil || err.Error() != "outgate: transport_failure" {
		t.Fatal(err)
	}
}

func TestReconnectWaitsForActualOldCallback(t *testing.T) {
	s1, g1 := pairProfile(t, 1, true, false, "")
	s2, g2 := pairProfile(t, 2, true, false, "")
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	c, err := New(config(func(context.Context) (*quiccontrol.Carrier, quicsession.Options, error) {
		n := calls.Add(1)
		if n == 1 {
			return s1, quicsession.Options{SecurityReady: true, ReadinessCheck: func(context.Context) error { close(entered); <-release; return nil }}, nil
		}
		if n == 2 {
			return s2, quicsession.Options{SecurityReady: true, ReadinessCheck: func(context.Context) error { return nil }}, nil
		}
		return nil, quicsession.Options{}, errors.New("unexpected connect")
	}))
	must(t, err)
	running := run(t, c, t.Context())
	await(t, entered)
	must(t, g1.Close())
	time.Sleep(30 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatal("new transport overlapped old callback")
	}
	close(release)
	eventually(t, func() bool { return calls.Load() == 2 || c.Status().State == sessionstate.Closed })
	if c.Status().State == sessionstate.Closed {
		err := await(t, running)
		t.Fatalf("reconnect ended: %v (cause %T: %v)", err, errors.Unwrap(err), errors.Unwrap(err))
	}
	receive(t, g2, "status")
	must(t, c.WaitReady(t.Context()))
	closed := make(chan error, 1)
	go func() { closed <- c.Close(t.Context()) }()
	acknowledgeDrain(t, g2)
	must(t, await(t, closed))
	must(t, await(t, running))
}

func TestDevelopmentDowngradeAndChangedIdentityFailClosed(t *testing.T) {
	s, _ := pairProfile(t, 1, false, true, "")
	c, err := New(config(func(context.Context) (*quiccontrol.Carrier, quicsession.Options, error) {
		return s, quicsession.Options{SecurityReady: true}, nil
	}))
	must(t, err)
	var e *Error
	if err = c.Run(t.Context()); !errors.As(err, &e) || e.Code != SecurityFailure {
		t.Fatal("development downgrade accepted", err)
	}
	s1, g1 := pair(t, 1)
	s2, _ := pairProfile(t, 2, false, false, "-changed")
	var calls atomic.Int32
	c, err = New(config(func(context.Context) (*quiccontrol.Carrier, quicsession.Options, error) {
		if calls.Add(1) == 1 {
			return s1, quicsession.Options{SecurityReady: true}, nil
		}
		return s2, quicsession.Options{SecurityReady: true}, nil
	}))
	must(t, err)
	running := run(t, c, t.Context())
	must(t, c.WaitReady(t.Context()))
	must(t, g1.Close())
	err = await(t, running)
	if !errors.As(err, &e) || e.Code != SecurityFailure || calls.Load() != 2 {
		t.Fatal("identity changed on reconnect", err)
	}
}

func TestSecurityRecoveryAndRevoke(t *testing.T) {
	s, g := pair(t, 1)
	c, err := New(config(func(context.Context) (*quiccontrol.Carrier, quicsession.Options, error) {
		return s, quicsession.Options{SecurityReady: true}, nil
	}))
	must(t, err)
	if !errors.Is(c.SetSecurity(true, time.Time{}), ErrClientNotReady) {
		t.Fatal("gate created session")
	}
	running := run(t, c, t.Context())
	must(t, c.WaitReady(t.Context()))
	receive(t, g, "status")
	must(t, c.SetSecurity(false, time.Time{}))
	if c.Status().State != sessionstate.Registered || !c.Status().ReadySince.IsZero() {
		t.Fatal("security recovery stayed ready")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if !errors.Is(c.WaitReady(ctx), context.DeadlineExceeded) {
		t.Fatal("WaitReady bypassed security")
	}
	must(t, c.SetSecurity(true, time.Time{}))
	must(t, c.WaitReady(t.Context()))
	c.Revoke()
	err = await(t, running)
	var e *Error
	if !errors.As(err, &e) || e.Code != SecurityFailure || c.Status().LastErrorCode != SecurityFailure {
		t.Fatal(err, c.Status())
	}
}

func TestRunCancelPreservesAcceptedHandlerUntilDrain(t *testing.T) {
	s, g := pair(t, 1)
	entered, release, canceled := make(chan struct{}), make(chan struct{}), make(chan struct{})
	cfg := config(func(context.Context) (*quiccontrol.Carrier, quicsession.Options, error) {
		return s, quicsession.Options{SecurityReady: true}, nil
	})
	cfg.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-release:
			w.WriteHeader(204)
		case <-r.Context().Done():
			close(canceled)
		}
	})
	c, err := New(cfg)
	must(t, err)
	runCtx, cancelRun := context.WithCancel(t.Context())
	running := run(t, c, runCtx)
	must(t, c.WaitReady(t.Context()))
	h, err := quichttp.NewGateway(g)
	must(t, err)
	requestDone := make(chan error, 1)
	go func() {
		req, _ := http.NewRequestWithContext(t.Context(), "GET", "https://public.example.test/api", nil)
		response, err := h.RoundTrip(req)
		if response != nil {
			_ = response.Body.Close()
		}
		requestDone <- err
	}()
	await(t, entered)
	cancelRun()
	drain := receive(t, g, "drain").(v1.Drain)
	select {
	case <-canceled:
		t.Fatal("Run cancellation canceled accepted handler before drain")
	default:
	}
	close(release)
	must(t, await(t, requestDone))
	must(t, g.Send(t.Context(), v1.DrainAck{Type: "drain_ack", CommandID: drain.CommandID, Extensions: v1.QUICQuiescentFenceExtensions(h.Pause())}))
	u := receive(t, g, "unregister").(v1.Unregister)
	must(t, g.Send(t.Context(), v1.UnregisterAck{Type: "unregister_ack", CommandID: u.CommandID}))
	must(t, await(t, running))
}

func TestCanceledRunAndRevokeDuringConnect(t *testing.T) {
	var calls atomic.Int32
	cfg := config(func(context.Context) (*quiccontrol.Carrier, quicsession.Options, error) {
		calls.Add(1)
		return nil, quicsession.Options{}, nil
	})
	c, err := New(cfg)
	must(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	must(t, c.Run(ctx))
	if calls.Load() != 0 {
		t.Fatal("canceled Run connected")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	cfg.Connect = func(context.Context) (*quiccontrol.Carrier, quicsession.Options, error) {
		close(entered)
		<-release
		return nil, quicsession.Options{}, nil
	}
	c, err = New(cfg)
	must(t, err)
	running := run(t, c, t.Context())
	await(t, entered)
	c.Revoke()
	select {
	case <-c.Done():
		t.Fatal("revocation forgot outstanding connector")
	default:
	}
	close(release)
	err = await(t, running)
	var e *Error
	if !errors.As(err, &e) || e.Code != SecurityFailure || !errors.As(c.WaitReady(t.Context()), &e) {
		t.Fatal(err)
	}
}
