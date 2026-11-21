package sessionstate

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

var epoch = time.Unix(1700000000, 0)

func config(local Role) Config {
	return Config{Local: local, MaxControlBytes: 65536, RegisterTimeout: 10 * time.Second, MaxCommands: 32, MaxPendingCancels: 32}
}
func fixtures(t testing.TB) (v1.Register, v1.RegisterAck) {
	t.Helper()
	b, err := os.ReadFile("../tests/fixtures/protocol/v1/control-messages.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct{ Positive []json.RawMessage }
	if err = json.Unmarshal(b, &corpus); err != nil {
		t.Fatal(err)
	}
	r, err := v1.DecodeRegister(corpus.Positive[0])
	if err != nil {
		t.Fatal(err)
	}
	a, err := v1.DecodeRegisterAck(corpus.Positive[1])
	if err != nil {
		t.Fatal(err)
	}
	expiry := epoch.Add(time.Hour).Unix()
	a.CredentialExpiresAt = &expiry
	a.ReadyNotBefore = epoch.Unix()
	return r, a
}
func must(t testing.TB, e Effect, err error) Effect {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func apply(t testing.TB, s *State, from Role, m any, now time.Time) Effect {
	t.Helper()
	e, err := s.Apply(from, m, now)
	return must(t, e, err)
}
func register(t testing.TB, local Role) *State {
	t.Helper()
	s, err := New(config(local))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Begin(epoch); err != nil {
		t.Fatal(err)
	}
	r, a := fixtures(t)
	apply(t, s, Service, r, epoch)
	if local == Gateway {
		e, err := s.AuthorizeRegistration(epoch)
		must(t, e, err)
	}
	apply(t, s, Gateway, a, epoch)
	if s.Snapshot().Phase != Registered {
		t.Fatal(s.Snapshot())
	}
	return s
}
func ready(t testing.TB, local Role) *State {
	t.Helper()
	s := register(t, local)
	e, err := s.Security(true, time.Time{}, epoch)
	must(t, e, err)
	if local == Service {
		for i := 0; i < s.readiness.SuccessThreshold; i++ {
			probe(t, s, true, epoch)
		}
	}
	apply(t, s, Service, status(1, true), epoch)
	if s.Snapshot().Phase != Ready {
		t.Fatal(s.Snapshot())
	}
	return s
}
func probe(t testing.TB, s *State, result bool, now time.Time) {
	t.Helper()
	e, err := s.StartProbe(now)
	must(t, e, err)
	e, err = s.FinishProbe(result, now)
	must(t, e, err)
}
func status(seq uint64, ready bool) v1.InstanceStatus {
	code := "initializing"
	if ready {
		code = "ready"
	}
	return v1.InstanceStatus{Type: "instance_status", Sequence: v1.U64(seq), Ready: ready, Code: code, ObservedAt: 0}
}
func request(id uint64) v1.RequestStart {
	return v1.RequestStart{Type: "request_start", StreamID: v1.U64(id), Method: "GET", Host: "example.test", RawRequestURI: "/api/v2", Headers: []v1.Header{}}
}
func drain(id uint64, ms int, code string) v1.Drain {
	return v1.Drain{Type: "drain", CommandID: v1.U64(id), DeadlineMS: ms, Code: code}
}
func drainAck(id uint64) v1.DrainAck { return v1.DrainAck{Type: "drain_ack", CommandID: v1.U64(id)} }
func assertError(t testing.TB, s *State, from Role, m any, want error, now time.Time) Effect {
	t.Helper()
	e, err := s.Apply(from, m, now)
	if !errors.Is(err, want) {
		t.Fatalf("%T got %v want %v", m, err, want)
	}
	return e
}

func TestRegistrationAndSecurityBarrier(t *testing.T) {
	for _, local := range []Role{Gateway, Service} {
		s, err := New(config(local))
		if err != nil {
			t.Fatal(err)
		}
		if s.Snapshot().Phase != Created {
			t.Fatal(s.Snapshot())
		}
		if err = s.Begin(epoch); err != nil {
			t.Fatal(err)
		}
		r, a := fixtures(t)
		a.ReadyNotBefore = epoch.Add(60 * time.Second).Unix()
		apply(t, s, Service, r, epoch)
		if local == Gateway {
			assertError(t, s, Gateway, a, ErrProtocol, epoch)
			e, err := s.AuthorizeRegistration(epoch)
			must(t, e, err)
		}
		apply(t, s, Gateway, a, epoch)
		if e, err := s.Advance(epoch.Add(11 * time.Second)); err != nil {
			t.Fatal(e, err)
		} // recovery barrier is outside registration timeout
		now := epoch.Add(59 * time.Second)
		e, err := s.Security(true, time.Time{}, now)
		must(t, e, err)
		if local == Service {
			for i := 0; i < a.Readiness.SuccessThreshold; i++ {
				probe(t, s, true, now)
			}
		}
		// Gateway can receive ready while its independent barrier/security still blocks admission.
		if local == Gateway {
			apply(t, s, Service, status(1, true), now)
		} else {
			assertError(t, s, Service, status(1, true), ErrProtocol, now)
		}
		if s.Snapshot().Phase != Registered {
			t.Fatal(s.Snapshot())
		}
		now = epoch.Add(time.Minute)
		e, err = s.Advance(now)
		must(t, e, err)
		if local == Service {
			apply(t, s, Service, status(1, true), now)
		}
		if s.Snapshot().Phase != Ready {
			t.Fatal(s.Snapshot())
		}
	}
}
func TestStatusFreshnessAndSequence(t *testing.T) {
	s := ready(t, Gateway)
	stale := time.Duration(s.timeouts.StatusStaleMS) * time.Millisecond
	e, err := s.Advance(epoch.Add(stale))
	must(t, e, err)
	if s.phase != Ready {
		t.Fatal(s.phase)
	}
	e, err = s.Advance(epoch.Add(stale + time.Nanosecond))
	must(t, e, err)
	if s.phase != Registered {
		t.Fatal(s.phase)
	}
	apply(t, s, Service, status(2, true), epoch.Add(stale+time.Second))
	if s.phase != Ready {
		t.Fatal(s.phase)
	}
	e, err = s.Security(false, time.Time{}, epoch.Add(stale+time.Second))
	must(t, e, err)
	if s.phase != Registered {
		t.Fatal(s.phase)
	}
	e, err = s.Security(true, time.Time{}, epoch.Add(stale+time.Second))
	must(t, e, err)
	e = assertError(t, s, Service, status(2, true), ErrProtocol, epoch.Add(stale+time.Second))
	if !e.CloseTransport || !e.StopAll || s.phase != Closed {
		t.Fatal(e, s.Snapshot())
	}
}
func TestProbeThresholdsAndTimeoutSlot(t *testing.T) {
	s := register(t, Service)
	e, err := s.Security(true, time.Time{}, epoch)
	must(t, e, err)
	assertError(t, s, Service, status(1, true), ErrProtocol, epoch)
	for i := 0; i < s.readiness.SuccessThreshold; i++ {
		probe(t, s, true, epoch)
	}
	apply(t, s, Service, status(1, true), epoch)
	for i := 1; i < s.readiness.FailureThreshold; i++ {
		probe(t, s, false, epoch)
		if s.phase != Ready {
			t.Fatal("failure threshold ignored")
		}
	}
	probe(t, s, false, epoch)
	if s.phase != Registered || !s.Snapshot().StatusDue {
		t.Fatal(s.Snapshot())
	}
	for i := 0; i < s.readiness.SuccessThreshold; i++ {
		probe(t, s, true, epoch)
	}
	e, err = s.StartProbe(epoch)
	must(t, e, err)
	now := epoch.Add(time.Duration(s.readiness.TimeoutMS) * time.Millisecond)
	e, err = s.Advance(now)
	must(t, e, err)
	if s.phase != Registered {
		t.Fatal(s.phase)
	}
	if _, err = s.StartProbe(now); err != ErrState {
		t.Fatal("second callback admitted", err)
	}
	e, err = s.FinishProbe(true, now)
	must(t, e, err)
	if s.probeReady {
		t.Fatal("late success restored readiness")
	}
	probe(t, s, true, now)
	if s.readiness.SuccessThreshold > 1 && s.probeReady {
		t.Fatal("missing threshold")
	}
}
func TestServiceDrainFenceAndExistingStream(t *testing.T) {
	s := ready(t, Service)
	apply(t, s, Service, drain(1, 30000, "server_shutdown"), epoch)
	// A previously ordered Gateway start may arrive before its returning drain_ack.
	apply(t, s, Gateway, request(1), epoch)
	apply(t, s, Gateway, drainAck(1), epoch)
	assertError(t, s, Service, v1.Unregister{Type: "unregister", CommandID: 2, DeadlineMS: 30000, Code: "server_shutdown"}, ErrProtocol, epoch)
	apply(t, s, Gateway, v1.RequestEnd{Type: "request_end", StreamID: 1}, epoch)
	apply(t, s, Service, v1.ResponseStart{Type: "response_start", StreamID: 1, Status: 200, Headers: []v1.Header{}}, epoch)
	apply(t, s, Service, v1.ResponseEnd{Type: "response_end", StreamID: 1}, epoch)
	apply(t, s, Service, v1.Unregister{Type: "unregister", CommandID: 2, DeadlineMS: 30000, Code: "server_shutdown"}, epoch)
	e := apply(t, s, Gateway, v1.UnregisterAck{Type: "unregister_ack", CommandID: 2}, epoch)
	if !e.CloseTransport || e.Reconnect || s.phase != Closed {
		t.Fatal(e, s.Snapshot())
	}
}
func TestGatewayDrainAndCleanupAssertion(t *testing.T) {
	s := ready(t, Gateway)
	apply(t, s, Service, drain(1, 30000, "server_shutdown"), epoch)
	assertError(t, s, Gateway, request(1), ErrState, epoch)
	apply(t, s, Gateway, drainAck(1), epoch)
	apply(t, s, Service, v1.Unregister{Type: "unregister", CommandID: 2, DeadlineMS: 30000, Code: "server_shutdown"}, epoch)
	assertError(t, s, Gateway, v1.UnregisterAck{Type: "unregister_ack", CommandID: 2}, ErrProtocol, epoch)
	e, err := s.ConfirmExcluded(epoch)
	must(t, e, err)
	e = apply(t, s, Gateway, v1.UnregisterAck{Type: "unregister_ack", CommandID: 2}, epoch)
	if !e.CloseTransport || e.Reconnect {
		t.Fatal(e)
	}
}
func TestNewStartAfterFenceIsTerminal(t *testing.T) {
	for _, m := range []any{request(1), v1.WebSocketOpen{Type: "websocket_open", StreamID: 1, Method: "GET", Host: "example.test", RawRequestURI: "/ws", Headers: []v1.Header{}}} {
		s := ready(t, Service)
		apply(t, s, Service, drain(1, 30000, "server_shutdown"), epoch)
		apply(t, s, Gateway, drainAck(1), epoch)
		e := assertError(t, s, Gateway, m, ErrState, epoch)
		if !e.StopAll || s.phase != Closed {
			t.Fatal(e)
		}
	}
}
func TestRotationCloseAndEarliestDeadline(t *testing.T) {
	for _, local := range []Role{Gateway, Service} {
		s := ready(t, local)
		apply(t, s, Gateway, v1.Reconnect{Type: "reconnect", CommandID: 1, DeadlineMS: 20000, Code: "credential_rotation"}, epoch)
		e, err := s.Close(epoch.Add(5*time.Second), epoch)
		must(t, e, err)
		e, err = s.Close(epoch.Add(time.Minute), epoch)
		must(t, e, err)
		if !s.drainDeadline.Equal(epoch.Add(5 * time.Second)) {
			t.Fatal(s.drainDeadline)
		}
		e, err = s.Advance(epoch.Add(5 * time.Second))
		if err != ErrTimeout || e.Reconnect || !e.StopAll || s.phase != Closed {
			t.Fatal(e, err)
		}
	}
}
func TestReconnectRequiresCleanupAndNewNamespace(t *testing.T) {
	s := ready(t, Service)
	apply(t, s, Gateway, request(1), epoch)
	oldID := s.sessionID
	e, err := s.Disconnected(true, epoch)
	must(t, e, err)
	if !e.Reconnect || !e.StopAll || s.Snapshot().Streams.Active != 0 {
		t.Fatal(e, s.Snapshot())
	}
	if err = s.Begin(epoch); err != ErrState {
		t.Fatal("old cleanup skipped", err)
	}
	if err = s.Cleaned(epoch); err != nil {
		t.Fatal(err)
	}
	if err = s.Begin(epoch); err != nil {
		t.Fatal(err)
	}
	r, a := fixtures(t)
	apply(t, s, Service, r, epoch)
	a.SessionID = oldID
	// A Service cannot issue its own register acknowledgement.
	assertError(t, s, Service, a, ErrProtocol, epoch)
	a.SessionID = "AQEBAQEBAQEBAQEBAQEBAQ"
	apply(t, s, Gateway, a, epoch)
	if s.sequence != 0 || s.streams.Stats().Opened != 0 || s.securityReady {
		t.Fatal(s.Snapshot())
	}
}
func TestCommandHistoryAndLocalAtomicity(t *testing.T) {
	s := ready(t, Service)
	apply(t, s, Service, drain(7, 30000, "server_shutdown"), epoch)
	before := s.Snapshot()
	assertError(t, s, Service, drain(7, 1, "server_shutdown"), ErrProtocol, epoch)
	if !reflect.DeepEqual(before, s.Snapshot()) {
		t.Fatal("duplicate changed deadline/history")
	}
	assertError(t, s, Service, drainAck(7), ErrProtocol, epoch)
	apply(t, s, Gateway, drainAck(7), epoch)
	assertError(t, s, Service, drain(7, 1000, "server_shutdown"), ErrProtocol, epoch)
	s.config.MaxCommands = 1 // exercise history admission without allocating unbounded entries
	assertError(t, s, Service, drain(8, 1000, "server_shutdown"), ErrCapacity, epoch)
}
func TestRegistrationFailureAndFatalClock(t *testing.T) {
	s, err := New(config(Service))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Begin(epoch); err != nil {
		t.Fatal(err)
	}
	e, err := s.Advance(epoch.Add(10 * time.Second))
	if err != ErrTimeout || !e.Reconnect || !e.CleanupRequired {
		t.Fatal(e, err)
	}
	s = ready(t, Service)
	e, err = s.Advance(epoch.Add(-time.Second))
	if err != ErrProtocol || !e.StopAll || s.phase != Closed {
		t.Fatal(e, err)
	}
	s = ready(t, Gateway)
	e, err = s.Security(true, epoch.Add(time.Second), epoch)
	must(t, e, err)
	apply(t, s, Gateway, drain(1, 30000, "credential_rotation"), epoch)
	e, err = s.Advance(epoch.Add(time.Second))
	if err != ErrSecurity || e.Reconnect || !e.StopAll {
		t.Fatal(e, err)
	}
}

func TestRegistrationNackAndNoSecondRegister(t *testing.T) {
	for _, retry := range []bool{false, true} {
		s, err := New(config(Service))
		if err != nil {
			t.Fatal(err)
		}
		if err = s.Begin(epoch); err != nil {
			t.Fatal(err)
		}
		r, _ := fixtures(t)
		apply(t, s, Service, r, epoch)
		assertError(t, s, Service, r, ErrProtocol, epoch)
		code := "auth_failed"
		if retry {
			code = "duplicate_instance"
		}
		e := apply(t, s, Gateway, v1.RegisterNack{Type: "register_nack", Code: code, Detail: "refused", Retryable: retry}, epoch)
		if e.Reconnect != retry || !e.CloseTransport {
			t.Fatal(e)
		}
	}
	s := ready(t, Service)
	r, _ := fixtures(t)
	assertError(t, s, Service, r, ErrProtocol, epoch)
}
func TestRegisterCopyAndAckCapacity(t *testing.T) {
	s, err := New(config(Gateway))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Begin(epoch); err != nil {
		t.Fatal(err)
	}
	r, a := fixtures(t)
	apply(t, s, Service, r, epoch)
	r.Paths[0] = "/changed"
	r.Capabilities[0] = "changed"
	e, err := s.AuthorizeRegistration(epoch)
	must(t, e, err)
	a.Limits.BufferBytes = 100
	assertError(t, s, Gateway, a, ErrCapacity, epoch)
	_, a = fixtures(t)
	apply(t, s, Gateway, a, epoch)
	if s.Snapshot().ReservedBytes > uint64(a.Limits.BufferBytes) {
		t.Fatal(s.Snapshot())
	}
}
func TestControlAndWrongDirection(t *testing.T) {
	s := ready(t, Service)
	for _, m := range []any{v1.Reconnect{Type: "reconnect", CommandID: 1, DeadlineMS: 1, Code: "rotate"}, status(2, true)} {
		if _, ok := m.(v1.InstanceStatus); ok {
			assertError(t, s, Gateway, m, ErrProtocol, epoch)
			break
		}
		assertError(t, s, Service, m, ErrProtocol, epoch)
	}
	s = ready(t, Service)
	s.streamControlLimit = 64
	m := drain(1, 30000, "shutdown")
	m.Extensions = map[string]json.RawMessage{"opaque": json.RawMessage(`"large enough for the negotiated small limit"`)}
	before := s.Snapshot()
	assertError(t, s, Service, m, ErrProtocol, epoch)
	if !reflect.DeepEqual(before, s.Snapshot()) {
		t.Fatal("local control limit changed state")
	}
}
func TestDrainDeadlineCannotExtendAndRevokeWins(t *testing.T) {
	s := ready(t, Gateway)
	apply(t, s, Gateway, drain(1, 1000, "credential_rotation"), epoch)
	apply(t, s, Gateway, drain(2, 30000, "credential_rotation"), epoch.Add(500*time.Millisecond))
	if !s.drainDeadline.Equal(epoch.Add(time.Second)) {
		t.Fatal(s.drainDeadline)
	}
	e, err := s.Revoke(epoch.Add(500 * time.Millisecond))
	if err != ErrSecurity || e.Reconnect || !e.StopAll {
		t.Fatal(e, err)
	}
	s = ready(t, Gateway)
	apply(t, s, Gateway, v1.Reconnect{Type: "reconnect", CommandID: 1, DeadlineMS: 1, Code: "credential_rotation"}, epoch)
	e, err = s.Advance(epoch.Add(time.Millisecond))
	if err != ErrTimeout || !e.Reconnect || !e.CleanupRequired {
		t.Fatal(e, err)
	}
}
func TestCloseBeforeBeginAndConfig(t *testing.T) {
	s, err := New(config(Service))
	if err != nil {
		t.Fatal(err)
	}
	e, err := s.Close(time.Time{}, epoch)
	must(t, e, err)
	if s.phase != Closed || e.CloseTransport {
		t.Fatal(e, s.phase)
	}
	e, err = s.Close(time.Time{}, epoch)
	must(t, e, err)
	if err = s.Begin(epoch); err != ErrState {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.Local = 9 }, func(c *Config) { c.MaxCommands = 2049 }, func(c *Config) { c.MaxPendingCancels = 0 }, func(c *Config) { c.RegisterTimeout = 11 * time.Second }, func(c *Config) { c.MaxControlBytes = 0 }} {
		c := config(Service)
		mutate(&c)
		if _, err = New(c); err != ErrProtocol {
			t.Fatal(err)
		}
	}
}
func TestMixedStreamsSurviveDrainAndAwaitConsumption(t *testing.T) {
	for _, local := range []Role{Gateway, Service} {
		s := ready(t, local)
		apply(t, s, Gateway, request(1), epoch)
		apply(t, s, Gateway, v1.WebSocketOpen{Type: "websocket_open", StreamID: 2, Method: "GET", Host: "example.test", RawRequestURI: "/ws", Headers: []v1.Header{}, FromHandlerCredit: 8}, epoch)
		apply(t, s, Service, v1.WebSocketOpenAck{Type: "websocket_open_ack", StreamID: 2, ToHandlerCredit: 8}, epoch)
		apply(t, s, Gateway, drain(1, 30000, "server_shutdown"), epoch)
		apply(t, s, Service, drainAck(1), epoch)
		apply(t, s, Gateway, v1.RequestEnd{Type: "request_end", StreamID: 1}, epoch)
		apply(t, s, Service, v1.ResponseStart{Type: "response_start", StreamID: 1, Status: 200, Headers: []v1.Header{}}, epoch)
		apply(t, s, Service, v1.ResponseEnd{Type: "response_end", StreamID: 1}, epoch)
		apply(t, s, Gateway, v1.Chunk{StreamID: 2, Kind: v1.WebSocketToHandler, Payload: []byte("GET\r\n")}, epoch)
		apply(t, s, Service, v1.Chunk{StreamID: 2, Kind: v1.WebSocketFromHandler, Payload: []byte("101\r\n")}, epoch)
		apply(t, s, Gateway, v1.WebSocketEnd{Type: "websocket_end", StreamID: 2, Direction: "websocket_to_handler", BytesSent: 5}, epoch)
		apply(t, s, Service, v1.WebSocketEnd{Type: "websocket_end", StreamID: 2, Direction: "websocket_from_handler", BytesSent: 5}, epoch)
		if s.empty() {
			t.Fatal("buffered handshake forgotten")
		}
		dir := "websocket_to_handler"
		if local == Gateway {
			dir = "websocket_from_handler"
		}
		e, err := s.Consume(2, dir, 5, epoch)
		must(t, e, err)
		if !s.empty() {
			t.Fatal(s.Snapshot())
		}
	}
}

func FuzzSessionLifecycle(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 32 {
			data = data[:32]
		}
		for _, value := range data {
			g, s := ready(t, Gateway), ready(t, Service)
			now := epoch
			send := func(from Role, m any) { apply(t, g, from, m, now); apply(t, s, from, m, now) }
			send(Gateway, request(1))
			if value%2 == 0 {
				// Commit a prior Gateway start, delay its delivery until after
				// Service initiates drain, then deliver the ordered ack fence.
				apply(t, g, Gateway, request(2), now)
				send(Service, drain(1, 30000, "server_shutdown"))
				apply(t, s, Gateway, request(2), now)
				send(Gateway, v1.RequestEnd{Type: "request_end", StreamID: 2})
				send(Service, v1.ResponseStart{Type: "response_start", StreamID: 2, Status: 200, Headers: []v1.Header{}})
				send(Service, v1.ResponseEnd{Type: "response_end", StreamID: 2})
				send(Gateway, drainAck(1))
			} else {
				send(Gateway, drain(1, 30000, "credential_rotation"))
				send(Service, drainAck(1))
			}
			send(Gateway, v1.RequestEnd{Type: "request_end", StreamID: 1})
			send(Service, v1.ResponseStart{Type: "response_start", StreamID: 1, Status: 204, Headers: []v1.Header{}})
			send(Service, v1.ResponseEnd{Type: "response_end", StreamID: 1})
			if value%3 == 0 {
				send(Service, v1.Unregister{Type: "unregister", CommandID: 2, DeadlineMS: 30000, Code: "shutdown"})
				e, err := g.ConfirmExcluded(now)
				must(t, e, err)
				send(Gateway, v1.UnregisterAck{Type: "unregister_ack", CommandID: 2})
			} else {
				now = epoch.Add(30 * time.Second)
				for _, st := range []*State{g, s} {
					e, err := st.Advance(now)
					if err != ErrTimeout || !e.CloseTransport {
						t.Fatal(e, err)
					}
				}
			}
			for _, st := range []*State{g, s} {
				snap := st.Snapshot()
				if snap.TransportActive || snap.Streams.Active != 0 || snap.ReservedBytes != 0 || !snap.CleanupRequired {
					t.Fatal(snap)
				}
				if err := st.Cleaned(now); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
}

func TestCallbackSlotSurvivesDisconnect(t *testing.T) {
	s := ready(t, Service)
	e, err := s.StartProbe(epoch)
	must(t, e, err)
	e, err = s.Disconnected(true, epoch)
	must(t, e, err)
	if !s.Snapshot().ProbeOutstanding {
		t.Fatal("lost callback slot")
	}
	if err = s.Cleaned(epoch); err != ErrState {
		t.Fatal("cleanup ignored callback", err)
	}
	e, err = s.FinishProbe(true, epoch)
	must(t, e, err)
	if err = s.Cleaned(epoch); err != nil {
		t.Fatal(err)
	}
	if err = s.Begin(epoch); err != nil {
		t.Fatal(err)
	}
	if s.Snapshot().ProbeOutstanding || s.probeReady {
		t.Fatal(s.Snapshot())
	}
}
func TestReusedSessionID(t *testing.T) {
	s := ready(t, Gateway)
	old := s.sessionID
	e, err := s.Disconnected(true, epoch)
	must(t, e, err)
	if err = s.Cleaned(epoch); err != nil {
		t.Fatal(err)
	}
	if err = s.Begin(epoch); err != nil {
		t.Fatal(err)
	}
	r, a := fixtures(t)
	apply(t, s, Service, r, epoch)
	e, err = s.AuthorizeRegistration(epoch)
	must(t, e, err)
	a.SessionID = old
	assertError(t, s, Gateway, a, ErrProtocol, epoch)
	a.SessionID = "AQEBAQEBAQEBAQEBAQEBAQ"
	apply(t, s, Gateway, a, epoch)
}

func TestSimultaneousDrainRequiresBothAcks(t *testing.T) {
	s := ready(t, Service)
	apply(t, s, Service, drain(1, 30000, "server_shutdown"), epoch)
	e := apply(t, s, Gateway, drain(2, 30000, "server_shutdown"), epoch)
	if e.Reply == nil || e.Reply.CommandID != 2 {
		t.Fatal(e)
	}
	apply(t, s, Gateway, drainAck(1), epoch)
	u := v1.Unregister{Type: "unregister", CommandID: 3, DeadlineMS: 30000, Code: "server_shutdown"}
	assertError(t, s, Service, u, ErrProtocol, epoch)
	apply(t, s, Service, *e.Reply, epoch)
	apply(t, s, Service, u, epoch)
	u.CommandID = 4
	assertError(t, s, Service, u, ErrProtocol, epoch)
}
func TestStreamCancelDeadlineClosesSession(t *testing.T) {
	s := ready(t, Service)
	apply(t, s, Gateway, request(1), epoch)
	apply(t, s, Service, v1.Cancel{Type: "cancel", StreamID: 1, CancelID: 1, Scope: "all", Code: "shutdown"}, epoch)
	now := epoch.Add(time.Duration(s.timeouts.CancelAckMS) * time.Millisecond)
	e, err := s.Advance(now)
	if err == nil || !e.CloseTransport || !e.StopAll || !e.CleanupRequired {
		t.Fatal(e, err)
	}
}
func TestCredentialExpiryAndDevelopment(t *testing.T) {
	for _, dev := range []bool{false, true} {
		c := config(Gateway)
		c.Development = dev
		s, err := New(c)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.Begin(epoch); err != nil {
			t.Fatal(err)
		}
		r, a := fixtures(t)
		a.CredentialExpiresAt = nil
		apply(t, s, Service, r, epoch)
		e, err := s.AuthorizeRegistration(epoch)
		must(t, e, err)
		if dev {
			apply(t, s, Gateway, a, epoch)
		} else {
			assertError(t, s, Gateway, a, ErrProtocol, epoch)
		}
	}
	s := ready(t, Gateway)
	e, err := s.Advance(epoch.Add(time.Hour))
	if err != ErrSecurity || !e.StopAll || e.Reconnect {
		t.Fatal(e, err)
	}
}

func TestLocalProbeResultBecomesStale(t *testing.T) {
	s := ready(t, Service)
	now := epoch.Add(time.Duration(s.readiness.StaleAfterMS) * time.Millisecond)
	e, err := s.Advance(now)
	must(t, e, err)
	apply(t, s, Service, status(2, true), now)
	now = now.Add(time.Nanosecond)
	e, err = s.Advance(now)
	must(t, e, err)
	if s.phase != Registered || !s.Snapshot().StatusDue {
		t.Fatal(s.Snapshot())
	}
	assertError(t, s, Service, status(3, true), ErrProtocol, now)
	for i := 0; i < s.readiness.SuccessThreshold; i++ {
		probe(t, s, true, now)
	}
	apply(t, s, Service, status(3, true), now)
}

func TestProbeCompletionAtSecurityDeadlineReleasesSlot(t *testing.T) {
	s := ready(t, Service)
	e, err := s.Security(true, epoch.Add(time.Second), epoch)
	must(t, e, err)
	e, err = s.StartProbe(epoch)
	must(t, e, err)
	e, err = s.FinishProbe(true, epoch.Add(time.Second))
	if err != ErrSecurity || !e.CloseTransport || s.Snapshot().ProbeOutstanding {
		t.Fatal(e, err, s.Snapshot())
	}
	if err = s.Cleaned(epoch.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestUnsupportedMessageValuesAreRejected(t *testing.T) {
	s := ready(t, Service)
	var pointer *v1.InstanceStatus
	for _, m := range []any{nil, pointer, &v1.InstanceStatus{}, 42} {
		before := s.Snapshot()
		assertError(t, s, Service, m, ErrProtocol, epoch)
		if !reflect.DeepEqual(before, s.Snapshot()) {
			t.Fatal("unsupported local message mutated state")
		}
	}
}
