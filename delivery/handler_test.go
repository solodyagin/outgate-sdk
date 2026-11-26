package delivery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/solodyagin/outgate-sdk/httpsig"
)

type replayFunc func(context.Context, httpsig.Reservation) error

func (f replayFunc) Reserve(ctx context.Context, entry httpsig.Reservation) error {
	return f(ctx, entry)
}

func inboundHTTP(t *testing.T, f fixture) *http.Request {
	t.Helper()
	meta := f.signed(t, f.request)
	r := httptest.NewRequest(meta.Method, meta.RawURI, strings.NewReader("streamed"))
	r.Host = meta.Authority
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, VerifiedChains: [][]*x509.Certificate{{}}}
	for _, field := range meta.Headers {
		r.Header.Add(field[0], field[1])
	}
	return r
}

func TestHandlerDispatchAfterReplayCommitWithVerifiedContext(t *testing.T) {
	f := setupAt(t, httpsig.Gateway, true, time.Now())
	f.request.RawURI = "/%61pi/%69tems?x=%2b&z="
	r := inboundHTTP(t, f)
	var calls []string
	store := &reservationStore{entries: make(map[httpsig.ReplayKey]bool)}
	config := HandlerConfig{
		Verifier: f.verifier, ReplayNamespace: "instance-1", StripPrefix: true,
		Prepare: func(_ context.Context, _ *tls.ConnectionState, meta httpsig.Request) (Key, Binding, error) {
			calls = append(calls, "prepare")
			if meta.RawURI != f.request.RawURI || meta.Authority != r.Host {
				t.Fatal("transport admission did not receive public metadata")
			}
			return f.key, f.binding, nil
		},
		Authorize: func(_ context.Context, _ httpsig.Request, verified Verified) (time.Time, error) {
			calls = append(calls, "authorize")
			identity, ok := verified.Identity()
			if !ok || identity.ExpiresAt.IsZero() {
				t.Fatal("missing verified user identity")
			}
			return f.now.Add(time.Minute), nil
		},
		ReplayStore: replayFunc(func(ctx context.Context, entry httpsig.Reservation) error {
			calls = append(calls, "reserve")
			if entry.Key.Namespace != "instance-1" || entry.Key.Caller != f.binding.Caller {
				t.Fatal("wrong replay key")
			}
			return store.Reserve(ctx, entry)
		}),
	}
	h, err := NewHandler(config, http.HandlerFunc(func(w http.ResponseWriter, got *http.Request) {
		calls = append(calls, "dispatch")
		verified, mount, ok := FromContext(got.Context())
		user, hasUser := verified.User()
		if !ok || !hasUser || user.ID != "alice" || verified.HopLimit() != 3 || mount.Prefix != "/api" || mount.OriginalRequestURI != f.request.RawURI {
			t.Fatal("incorrect trusted context")
		}
		if got.URL.Path != "/items" || got.URL.RawPath != "/%69tems" || got.RequestURI != "/%69tems?x=%2b&z=" || got.Header.Get("X-Forwarded-Prefix") != "/api" {
			t.Fatal("incorrect local request", got.URL, got.RequestURI)
		}
		if got.Body != r.Body || got.Header.Get("Signature") != "" || got.Header.Get("X-Outgate-User-Assertion") != "" {
			t.Fatal("handler body or private headers changed incorrectly")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []int{http.StatusNoContent, http.StatusUnauthorized} {
		response := httptest.NewRecorder()
		h.ServeHTTP(response, r)
		if response.Code != want {
			t.Fatalf("status %d, want %d", response.Code, want)
		}
	}
	if !reflect.DeepEqual(calls, []string{"prepare", "authorize", "reserve", "dispatch", "prepare", "authorize", "reserve"}) || r.RequestURI != f.request.RawURI || r.Header.Get("Signature") == "" {
		t.Fatal("incorrect admission order or mutation of incoming request", calls)
	}
}

func TestHandlerDenialAndReplayFailures(t *testing.T) {
	f := setupAt(t, httpsig.Gateway, false, time.Now())
	for _, tc := range []struct {
		name      string
		mutate    func(*http.Request)
		policy    error
		store     error
		status    int
		lastStage int
	}{
		{name: "unverified TLS", mutate: func(r *http.Request) { r.TLS.VerifiedChains = nil }, status: 401},
		{name: "oversized fields", mutate: func(r *http.Request) { r.Header.Set("X-Large", strings.Repeat("a", 32768)) }, status: 401},
		{name: "unsigned", mutate: func(r *http.Request) { r.Header.Del("Signature") }, status: 401, lastStage: 1},
		{name: "duplicate signature", mutate: func(r *http.Request) { r.Header.Add("Signature", r.Header.Get("Signature")) }, status: 401, lastStage: 1},
		{name: "revoked route", policy: ErrForbidden, status: 403, lastStage: 2},
		{name: "caller quota", store: httpsig.ErrReplayCallerQuota, status: 429, lastStage: 3},
		{name: "commit failure", store: errors.New("private failure"), status: 503, lastStage: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stage := 0
			config := HandlerConfig{
				Verifier: f.verifier, ReplayNamespace: "instance-1",
				Prepare: func(context.Context, *tls.ConnectionState, httpsig.Request) (Key, Binding, error) {
					stage = 1
					return f.key, f.binding, nil
				},
				Authorize: func(context.Context, httpsig.Request, Verified) (time.Time, error) {
					stage = 2
					return f.now.Add(time.Minute), tc.policy
				},
				ReplayStore: replayFunc(func(context.Context, httpsig.Reservation) error {
					stage = 3
					return tc.store
				}),
			}
			r := inboundHTTP(t, f)
			if tc.mutate != nil {
				tc.mutate(r)
			}
			h, err := NewHandler(config, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("rejected request reached handler") }))
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			h.ServeHTTP(response, r)
			if response.Code != tc.status || stage != tc.lastStage || strings.Contains(response.Body.String(), "private failure") || tc.status == 503 && response.Header().Get("Retry-After") != "1" {
				t.Fatalf("unexpected status, body or admission stage: %d %q %d", response.Code, response.Body.String(), stage)
			}
		})
	}
}

func TestHandlerDoesNotDispatchIfLeaseExpiresDuringCommit(t *testing.T) {
	f := setupAt(t, httpsig.Gateway, false, time.Now())
	current := f.now
	lease := current.Add(time.Second)
	config := HandlerConfig{
		Verifier: f.verifier, ReplayNamespace: "instance-1",
		Prepare: func(context.Context, *tls.ConnectionState, httpsig.Request) (Key, Binding, error) {
			return f.key, f.binding, nil
		},
		Authorize: func(context.Context, httpsig.Request, Verified) (time.Time, error) {
			return lease, nil
		},
		ReplayStore: replayFunc(func(context.Context, httpsig.Reservation) error {
			current = lease
			return nil
		}),
	}
	response := httptest.NewRecorder()
	config.serve(response, inboundHTTP(t, f), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expired request reached handler after commit")
	}), func() time.Time { return current })
	if response.Code != http.StatusServiceUnavailable {
		t.Fatal("unexpected status", response.Code)
	}
}
