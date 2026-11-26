package client

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/sessionstate"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
	"github.com/solodyagin/outgate-sdk/transport/quichttp"
	"github.com/solodyagin/outgate-sdk/transport/quicsession"
)

func TestRenewalPlanningAndRetryBounds(t *testing.T) {
	accepted := time.Unix(1000, 0)
	for _, tc := range []struct{ life, lead time.Duration }{
		{time.Hour, 5 * time.Minute}, {25 * time.Minute, 5 * time.Minute},
		{time.Minute, 12 * time.Second}, {time.Second, 200 * time.Millisecond}, {0, 0},
	} {
		expiry := accepted.Add(tc.life)
		if got := renewalTime(accepted, expiry); !got.Equal(expiry.Add(-tc.lead)) {
			t.Fatalf("life %s: %s", tc.life, got)
		}
	}
	for _, cap := range []time.Duration{0, time.Second, 2 * time.Second, 30 * time.Second, time.Hour} {
		for i := 0; i < 50; i++ {
			d := renewalRetry(cap)
			if d < time.Second || d > max(time.Second, min(30*time.Second, cap)) {
				t.Fatal(d)
			}
		}
	}
}

// Exercise real transport/cleanup with an immediate first scheduled acquisition.
// The pure time calculation above checks the production schedule independently.
func earlyRenewal(t *testing.T, e *dialEnvironment) *Client {
	t.Helper()
	c, err := New(Config{QUIC: &e.config, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})})
	must(t, err)
	original := c.config.Connect
	first := true
	c.config.Connect = func(ctx context.Context) (*quiccontrol.Carrier, quicsession.Options, error) {
		carrier, options, err := original(ctx)
		if first && err == nil {
			c.renewal.refreshAt = time.Now()
			first = false
		}
		return carrier, options, err
	}
	return c
}

func TestProactiveRenewalPinsCandidateUntilOldTerminalAck(t *testing.T) {
	e := dialEnv(t)
	_, accepted := listen(t, e)
	var calls atomic.Int32
	candidateAllowed := make(chan struct{})
	var published atomic.Uint64
	published.Store(2)
	e.config.Credentials = func(ctx context.Context) (CredentialSnapshot, error) {
		s := e.snapshot
		if calls.Add(1) > 1 {
			select {
			case <-candidateAllowed:
			case <-ctx.Done():
				return CredentialSnapshot{}, ctx.Err()
			}
			s.Generation = published.Load()
			s.Credential = grant(byte(s.Generation))
		}
		return s, nil
	}
	c := earlyRenewal(t, e)
	running := run(t, c, t.Context())
	g1 := await(t, accepted)
	must(t, g1.err)
	must(t, c.WaitReady(t.Context()))
	close(candidateAllowed)
	d := receive(t, g1.carrier, "drain").(v1.Drain)
	// No second connection while the old carrier still owns its namespace.
	select {
	case <-accepted:
		t.Fatal("overlapping registration")
	default:
	}
	published.Store(3) // The provider changes again while the old session drains.
	must(t, g1.carrier.Send(t.Context(), v1.DrainAck{Type: "drain_ack", CommandID: d.CommandID, Extensions: v1.QUICQuiescentFenceExtensions(0)}))
	u := receive(t, g1.carrier, "unregister").(v1.Unregister)
	if calls.Load() != 2 {
		t.Fatal("candidate reacquired during drain")
	}
	select {
	case <-accepted:
		t.Fatal("registration before terminal ack")
	default:
	}
	must(t, g1.carrier.Send(t.Context(), v1.UnregisterAck{Type: "unregister_ack", CommandID: u.CommandID}))
	g2 := await(t, accepted)
	must(t, g2.err)
	receive(t, g2.carrier, "status")
	if *g2.register.CredentialGeneration != 2 || calls.Load() != 2 {
		t.Fatal("validated candidate was replaced")
	}
	must(t, c.WaitReady(t.Context()))
	closed := make(chan error, 1)
	go func() { closed <- c.Close(t.Context()) }()
	acknowledgeDrain(t, g2.carrier)
	must(t, await(t, closed))
	must(t, await(t, running))
}

func TestProactiveRenewalKeepsWorkingPairOnInvalidCandidate(t *testing.T) {
	for _, kind := range []string{"temporary", "invalid", "rollback", "same", "panic", "timeout"} {
		t.Run(kind, func(t *testing.T) {
			e := dialEnv(t)
			_, accepted := listen(t, e)
			var calls atomic.Int32
			failed := make(chan struct{})
			e.config.SourceTimeout = 30 * time.Millisecond
			e.config.Credentials = func(ctx context.Context) (CredentialSnapshot, error) {
				n := calls.Add(1)
				s := e.snapshot
				if n == 1 {
					return s, nil
				}
				if n == 2 {
					defer close(failed)
					switch kind {
					case "temporary":
						return CredentialSnapshot{}, errors.New("private source details")
					case "invalid":
						s.Generation = 2
						s.Credential = []byte("invalid secret")
					case "rollback":
						s.Generation = 0
					case "same":
					case "panic":
						panic("private source panic")
					case "timeout":
						<-ctx.Done()
						return CredentialSnapshot{}, ctx.Err()
					}
					return s, nil
				}
				s.Generation = 2
				s.Credential = grant(2)
				return s, nil
			}
			c := earlyRenewal(t, e)
			running := run(t, c, t.Context())
			g1 := await(t, accepted)
			must(t, g1.err)
			must(t, c.WaitReady(t.Context()))
			await(t, failed)
			if c.Status().State != sessionstate.Ready || !c.Status().Connected {
				t.Fatal("bad candidate stopped working pair")
			}
			select {
			case <-accepted:
				t.Fatal("invalid candidate dialed")
			default:
			}
			// The retry obtains a valid pair while the old carrier remains live.
			acknowledgeDrain(t, g1.carrier)
			g2 := await(t, accepted)
			must(t, g2.err)
			receive(t, g2.carrier, "status")
			if *g2.register.CredentialGeneration != 2 {
				t.Fatal("retry lost new generation")
			}
			closed := make(chan error, 1)
			go func() { closed <- c.Close(t.Context()) }()
			acknowledgeDrain(t, g2.carrier)
			must(t, await(t, closed))
			must(t, await(t, running))
		})
	}
}

func TestRenewalRevokeAndCloseRetainSourceSlotUntilReturn(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(map[bool]string{false: "close", true: "revoke"}[revoke], func(t *testing.T) {
			e := dialEnv(t)
			_, accepted := listen(t, e)
			entered, release, canceled := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			e.config.Credentials = func(ctx context.Context) (CredentialSnapshot, error) {
				s := e.snapshot
				if calls.Add(1) > 1 {
					close(entered)
					<-ctx.Done()
					close(canceled)
					<-release
					s.Generation = 2
					s.Credential = grant(2)
				}
				return s, nil
			}
			c := earlyRenewal(t, e)
			running := run(t, c, t.Context())
			g := await(t, accepted)
			must(t, g.err)
			await(t, entered)
			if revoke {
				c.Revoke()
			} else {
				ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
				defer cancel()
				if err := c.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal(err)
				}
			}
			await(t, canceled)
			select {
			case <-c.Done():
				t.Fatal("completed before actual source cleanup")
			default:
			}
			close(release)
			err := await(t, running)
			var safe *Error
			if !errors.As(err, &safe) || revoke && safe.Code != SecurityFailure || !revoke && safe.Code != ShutdownTimeout {
				t.Fatal(err)
			}
			if calls.Load() != 2 {
				t.Fatal("source calls overlapped")
			}
			select {
			case <-accepted:
				t.Fatal("late candidate created transport")
			default:
			}
		})
	}
}

func TestRenewalExpiryPreemptsUncooperativeSource(t *testing.T) {
	e := dialEnv(t)
	e.config.Session.SecurityDeadline = time.Now().Add(150 * time.Millisecond)
	_, accepted := listen(t, e)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	e.config.Credentials = func(ctx context.Context) (CredentialSnapshot, error) {
		if calls.Add(1) > 1 {
			close(entered)
			<-ctx.Done()
			<-release
		}
		return e.snapshot, nil
	}
	c := earlyRenewal(t, e)
	running := run(t, c, t.Context())
	g := await(t, accepted)
	must(t, g.err)
	await(t, entered)
	eventually(t, func() bool { return !c.Status().Connected })
	select {
	case <-c.Done():
		t.Fatal("source slot released before callback return")
	default:
	}
	close(release)
	err := await(t, running)
	if !errors.Is(err, &Error{Code: SecurityFailure}) {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatal("retry after expiry")
	}
}

func TestProactiveRenewalDrainsExistingRequestWithoutReplay(t *testing.T) {
	e := dialEnv(t)
	_, accepted := listen(t, e)
	renew, entered, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var sources, handlers atomic.Int32
	e.config.Credentials = func(ctx context.Context) (CredentialSnapshot, error) {
		s := e.snapshot
		if sources.Add(1) > 1 {
			select {
			case <-renew:
			case <-ctx.Done():
				return CredentialSnapshot{}, ctx.Err()
			}
			s.Generation = 2
			s.Credential = grant(2)
		}
		return s, nil
	}
	c := earlyRenewal(t, e)
	c.config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlers.Add(1)
		close(entered)
		select {
		case <-release:
			w.WriteHeader(204)
		case <-r.Context().Done():
			t.Error("rotation canceled accepted request before drain completed")
		}
	})
	running := run(t, c, t.Context())
	g1 := await(t, accepted)
	must(t, g1.err)
	receive(t, g1.carrier, "status")
	h, err := quichttp.NewGateway(g1.carrier)
	must(t, err)
	requestDone := make(chan error, 1)
	go func() {
		req, _ := http.NewRequestWithContext(t.Context(), "POST", "https://public.example.test/api", nil)
		response, err := h.RoundTrip(req)
		if response != nil {
			_ = response.Body.Close()
		}
		requestDone <- err
	}()
	await(t, entered)
	close(renew)
	d := receive(t, g1.carrier, "drain").(v1.Drain)
	if handlers.Load() != 1 {
		t.Fatal("request replayed")
	}
	select {
	case <-accepted:
		t.Fatal("new session before handler cleanup")
	default:
	}
	watermark := h.Pause()
	close(release)
	must(t, await(t, requestDone))
	must(t, g1.carrier.Send(t.Context(), v1.DrainAck{Type: "drain_ack", CommandID: d.CommandID, Extensions: v1.QUICQuiescentFenceExtensions(watermark)}))
	u := receive(t, g1.carrier, "unregister").(v1.Unregister)
	must(t, g1.carrier.Send(t.Context(), v1.UnregisterAck{Type: "unregister_ack", CommandID: u.CommandID}))
	g2 := await(t, accepted)
	must(t, g2.err)
	receive(t, g2.carrier, "status")
	if handlers.Load() != 1 || sources.Load() != 2 {
		t.Fatal("replayed request or reacquired candidate")
	}
	closed := make(chan error, 1)
	go func() { closed <- c.Close(t.Context()) }()
	acknowledgeDrain(t, g2.carrier)
	must(t, await(t, closed))
	must(t, await(t, running))
}

func TestProactiveRenewalFinalIntentSuppressesNewRegistration(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(map[bool]string{false: "close", true: "revoke"}[revoke], func(t *testing.T) {
			e := dialEnv(t)
			_, accepted := listen(t, e)
			var calls atomic.Int32
			e.config.Credentials = func(context.Context) (CredentialSnapshot, error) {
				s := e.snapshot
				s.Generation = uint64(calls.Add(1))
				s.Credential = grant(byte(s.Generation))
				return s, nil
			}
			c := earlyRenewal(t, e)
			running := run(t, c, t.Context())
			g := await(t, accepted)
			must(t, g.err)
			d := receive(t, g.carrier, "drain").(v1.Drain)
			must(t, g.carrier.Send(t.Context(), v1.DrainAck{Type: "drain_ack", CommandID: d.CommandID, Extensions: v1.QUICQuiescentFenceExtensions(0)}))
			u := receive(t, g.carrier, "unregister").(v1.Unregister)
			if revoke {
				c.Revoke()
				if err := await(t, running); !errors.Is(err, &Error{Code: SecurityFailure}) {
					t.Fatal(err)
				}
			} else {
				// Record final intent before allowing the pending terminal ack to arrive.
				c.requestClose(time.Now().Add(time.Second))
				must(t, g.carrier.Send(t.Context(), v1.UnregisterAck{Type: "unregister_ack", CommandID: u.CommandID}))
				must(t, await(t, running))
			}
			if calls.Load() != 2 {
				t.Fatal("unexpected source acquisition")
			}
			select {
			case <-accepted:
				t.Fatal("final intent lost to rotation")
			default:
			}
			if c.renewal.pending != nil {
				t.Fatal("pending credentials retained after shutdown")
			}
		})
	}
}

func TestProactiveRenewalContinuesAfterBoundedDrainTimeout(t *testing.T) {
	e := dialEnv(t)
	e.ack.Timeouts.DrainMS = 40
	_, accepted := listen(t, e)
	var calls atomic.Int32
	e.config.Credentials = func(context.Context) (CredentialSnapshot, error) {
		s := e.snapshot
		s.Generation = uint64(calls.Add(1))
		s.Credential = grant(byte(s.Generation))
		return s, nil
	}
	c := earlyRenewal(t, e)
	running := run(t, c, t.Context())
	g1 := await(t, accepted)
	must(t, g1.err)
	receive(t, g1.carrier, "drain") // Deliberately withhold drain_ack.
	g2 := await(t, accepted)
	must(t, g2.err)
	receive(t, g2.carrier, "status")
	if *g2.register.CredentialGeneration != 2 || calls.Load() != 2 {
		t.Fatal("lost prepared candidate after bounded cleanup")
	}
	c.Revoke()
	if err := await(t, running); !errors.Is(err, &Error{Code: SecurityFailure}) {
		t.Fatal(err)
	}
}

func TestFileCredentialsProactiveScheduleUsesConfirmedAckExpiry(t *testing.T) {
	dir, manifest, e := fileSourceFixture(t)
	expiry := time.Now().Add(5 * time.Second).Unix()
	e.ack.CredentialExpiresAt = &expiry // Much earlier than the one-hour leaf expiry.
	source, err := FileCredentials(dir, "manifest.json")
	must(t, err)
	acquisitions := make(chan time.Time, 8)
	e.config.Credentials = func(ctx context.Context) (CredentialSnapshot, error) { acquisitions <- time.Now(); return source(ctx) }
	_, accepted := listen(t, e)
	c, err := New(Config{QUIC: &e.config, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})})
	must(t, err)
	running := run(t, c, t.Context())
	first := await(t, acquisitions)
	g1 := await(t, accepted)
	must(t, g1.err)
	receive(t, g1.carrier, "status")
	must(t, os.WriteFile(filepath.Join(dir, "grant2"), grant(2), 0600))
	manifest["generation"], manifest["deployment_grant_file"] = "2", "grant2"
	writeManifest(t, dir, manifest)
	next := await(t, acquisitions)
	if next.Sub(first) < 2*time.Second || !next.Before(time.Unix(expiry, 0)) {
		t.Fatal("renewal ignored ack lifetime")
	}
	acknowledgeDrain(t, g1.carrier)
	g2 := await(t, accepted)
	must(t, g2.err)
	receive(t, g2.carrier, "status")
	if *g2.register.CredentialGeneration != 2 {
		t.Fatal("file generation not renewed")
	}
	c.Revoke()
	if err := await(t, running); !errors.Is(err, &Error{Code: SecurityFailure}) {
		t.Fatal(err)
	}
}

func TestPeerFinalDrainWinsOverLateRenewalCandidate(t *testing.T) {
	e := dialEnv(t)
	_, accepted := listen(t, e)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	e.config.Credentials = func(context.Context) (CredentialSnapshot, error) {
		s := e.snapshot
		if calls.Add(1) > 1 {
			close(entered)
			<-release
			s.Generation = 2
			s.Credential = grant(2)
		}
		return s, nil
	}
	c := earlyRenewal(t, e)
	running := run(t, c, t.Context())
	g := await(t, accepted)
	must(t, g.err)
	await(t, entered)
	must(t, g.carrier.Send(t.Context(), v1.Drain{Type: "drain", CommandID: 1, DeadlineMS: 2000, Code: "shutdown", Extensions: v1.QUICQuiescentFenceExtensions(0)}))
	u := receive(t, g.carrier, "unregister").(v1.Unregister)
	close(release)
	must(t, g.carrier.Send(t.Context(), v1.UnregisterAck{Type: "unregister_ack", CommandID: u.CommandID}))
	must(t, await(t, running))
	select {
	case <-accepted:
		t.Fatal("late renewal overrode peer final drain")
	default:
	}
}

func TestPeerFinalDrainWinsOverAlreadyStartedRotation(t *testing.T) {
	e := dialEnv(t)
	_, accepted := listen(t, e)
	var calls atomic.Int32
	e.config.Credentials = func(context.Context) (CredentialSnapshot, error) {
		s := e.snapshot
		s.Generation = uint64(calls.Add(1))
		s.Credential = grant(byte(s.Generation))
		return s, nil
	}
	c := earlyRenewal(t, e)
	running := run(t, c, t.Context())
	g := await(t, accepted)
	must(t, g.err)
	local := receive(t, g.carrier, "drain").(v1.Drain)
	peerID := v1.U64(uint64(local.CommandID) ^ 1)
	if peerID == 0 {
		peerID = 2
	}
	must(t, g.carrier.Send(t.Context(), v1.Drain{Type: "drain", CommandID: peerID, DeadlineMS: 2000, Code: "shutdown", Extensions: v1.QUICQuiescentFenceExtensions(0)}))
	must(t, g.carrier.Send(t.Context(), v1.DrainAck{Type: "drain_ack", CommandID: local.CommandID, Extensions: v1.QUICQuiescentFenceExtensions(0)}))
	u := receive(t, g.carrier, "unregister").(v1.Unregister)
	must(t, g.carrier.Send(t.Context(), v1.UnregisterAck{Type: "unregister_ack", CommandID: u.CommandID}))
	must(t, await(t, running))
	select {
	case <-accepted:
		t.Fatal("local rotation overrode crossed final drain")
	default:
	}
}

func TestRotationTimeoutWaitsForActualOldHandler(t *testing.T) {
	e := dialEnv(t)
	e.ack.Timeouts.DrainMS = 40
	_, accepted := listen(t, e)
	renew, entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var sources atomic.Int32
	e.config.Credentials = func(ctx context.Context) (CredentialSnapshot, error) {
		s := e.snapshot
		if sources.Add(1) > 1 {
			select {
			case <-renew:
			case <-ctx.Done():
				return CredentialSnapshot{}, ctx.Err()
			}
			s.Generation = 2
			s.Credential = grant(2)
		}
		return s, nil
	}
	c := earlyRenewal(t, e)
	c.config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		close(canceled)
		<-release
	})
	running := run(t, c, t.Context())
	g1 := await(t, accepted)
	must(t, g1.err)
	receive(t, g1.carrier, "status")
	h, err := quichttp.NewGateway(g1.carrier)
	must(t, err)
	requestDone := make(chan error, 1)
	go func() {
		req, _ := http.NewRequestWithContext(t.Context(), "POST", "https://public.example.test/api", nil)
		response, err := h.RoundTrip(req)
		if response != nil {
			_ = response.Body.Close()
		}
		requestDone <- err
	}()
	await(t, entered)
	close(renew)
	receive(t, g1.carrier, "drain")
	await(t, canceled)
	select {
	case <-accepted:
		t.Fatal("new session overlapped old handler after deadline")
	default:
	}
	close(release)
	await(t, requestDone) // Cancellation is expected; business delivery is not retried.
	g2 := await(t, accepted)
	must(t, g2.err)
	receive(t, g2.carrier, "status")
	if sources.Load() != 2 {
		t.Fatal("candidate reacquired")
	}
	c.Revoke()
	if err := await(t, running); !errors.Is(err, &Error{Code: SecurityFailure}) {
		t.Fatal(err)
	}
}
