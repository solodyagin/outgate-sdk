package client

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

func writeDiscovery(w http.ResponseWriter, revision uint64, path string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v1.DiscoveryResponse{ServiceID: "target-service", RouteRevision: v1.U64(revision), Mounts: map[string]v1.DiscoveryMount{"api": {Path: path, PathMode: "strip"}, "other": {Path: path, PathMode: "preserve"}}})
}
func verifyDiscoveryAuth(t *testing.T, r *http.Request) {
	t.Helper()
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || r.Header.Get("X-Outgate-Deployment-Grant-ID") != strings.Split(string(grant(1)), ".")[0] {
		t.Error("discovery missing accepted mTLS/grant identity")
	}
	if r.Header.Get("Signature") != "" || r.Header.Get("X-User-ID") != "" || r.Header.Get("Authorization") != "" {
		t.Error("discovery used business/user credentials")
	}
}

type unreadDiscoveryBody struct{ reads atomic.Int32 }

func (b *unreadDiscoveryBody) Read(p []byte) (int, error) { b.reads.Add(1); return 0, io.EOF }

func TestDiscoveryHelperRawURICacheAndStreaming409(t *testing.T) {
	e := dialEnv(t)
	var discoveries, business atomic.Int32
	var revision atomic.Uint64
	revision.Store(1)
	release := make(chan struct{})
	defer close(release)
	server := serviceHTTPServer(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/outgate/discovery/") {
			verifyDiscoveryAuth(t, r)
			discoveries.Add(1)
			rev := revision.Load()
			writeDiscovery(w, rev, "/api/v"+strconv.FormatUint(rev+1, 10))
			return
		}
		verifyHTTPCall(t, e, r)
		business.Add(1)
		w.WriteHeader(409)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	c, _ := readyServiceHTTP(t, e, ServiceHTTPConfig{ServerRoots: e.config.ServerRoots, SigningKey: serviceHTTPKey()})
	body := &unreadDiscoveryBody{}
	req, err := c.NewServiceRequest(t.Context(), server.URL, "POST", "target-service", "api", "/%E2%82%AC?a=2&a=1&x=%2b", body)
	must(t, err)
	if body.reads.Load() != 0 || business.Load() != 0 || req.URL.RequestURI() != "/api/v2/%E2%82%AC?a=2&a=1&x=%2b" || req.Header.Get("X-Outgate-Expected-Route-Revision") != "1" {
		t.Fatal("helper sent/read/rewrote business request")
	}
	_, err = c.NewServiceRequest(t.Context(), server.URL, "GET", "target-service", "api", "/", nil)
	must(t, err)
	if discoveries.Load() != 1 {
		t.Fatal("cache miss")
	}
	client, err := c.ServiceHTTPClient(server.URL)
	must(t, err)
	response, err := client.Do(req)
	must(t, err)
	defer response.Body.Close()
	revision.Store(2)
	next, err := c.NewServiceRequest(t.Context(), server.URL, "GET", "target-service", "api", "/?", nil)
	must(t, err)
	if next.URL.RequestURI() != "/api/v3/?" || next.Header.Get("X-Outgate-Expected-Route-Revision") != "2" || discoveries.Load() != 2 || business.Load() != 1 {
		t.Fatal("409 did not invalidate cache or replayed business")
	}
}

func TestDiscoveryCacheTTLQuotaAndCredentialScope(t *testing.T) {
	var cache discoveryCache
	now := time.Unix(1000, 0)
	key := discoveryKey{"https://example.test", "target-service", "api"}
	entry := discoveryEntry{generation: 1, expires: now.Add(30 * time.Second)}
	if !cache.store(key, entry, 0) {
		t.Fatal("store")
	}
	if _, ok, _ := cache.lookup(key, 1, now.Add(29*time.Second)); !ok {
		t.Fatal("premature expiry")
	}
	if _, ok, _ := cache.lookup(key, 1, now.Add(30*time.Second)); ok {
		t.Fatal("stale cache used")
	}
	cache.store(key, entry, 0)
	if _, ok, _ := cache.lookup(key, 2, now); ok {
		t.Fatal("cache crossed credential/session switch")
	}
	for i := 0; i < 256; i++ {
		cache.store(discoveryKey{key.origin, key.target, strconv.Itoa(i)}, entry, 0)
	}
	cache.lookup(discoveryKey{key.origin, key.target, "0"}, 1, now)
	cache.store(key, entry, 0)
	if len(cache.entries) != 256 {
		t.Fatal("unbounded cache")
	}
	if _, ok := cache.entries[discoveryKey{key.origin, key.target, "1"}]; ok {
		t.Fatal("oldest entry not evicted")
	}
	cache.invalidate(key)
	if len(cache.entries) != 0 || cache.store(key, entry, 0) {
		t.Fatal("in-flight invalidation not fenced")
	}
}

func TestDiscoveryNegativeCacheAndInvalidInput(t *testing.T) {
	e := dialEnv(t)
	var hits atomic.Int32
	server := serviceHTTPServer(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"service_id":"target-service","route_revision":"1","mounts":{}}`)
	}))
	c, _ := readyServiceHTTP(t, e, ServiceHTTPConfig{ServerRoots: e.config.ServerRoots, SigningKey: serviceHTTPKey()})
	for _, uri := range []string{"//escape", "/../escape", "/%2fescape", "/x#fragment", "https://other.example/"} {
		if _, err := c.NewServiceRequest(t.Context(), server.URL, "GET", "target-service", "api", uri, &unreadDiscoveryBody{}); !errors.Is(err, &Error{Code: InvalidRequest}) {
			t.Fatal(err)
		}
	}
	if hits.Load() != 0 {
		t.Fatal("invalid local URI reached discovery")
	}
	for i := 0; i < 2; i++ {
		if _, err := c.NewServiceRequest(t.Context(), server.URL, "GET", "target-service", "api", "/", nil); !errors.Is(err, &Error{Code: MountNotFound}) {
			t.Fatal(err)
		}
	}
	if hits.Load() != 1 {
		t.Fatal("authenticated missing mount not cached")
	}
}

func TestDiscoveryRejectsUnusableResponsesWithoutCaching(t *testing.T) {
	for _, mode := range []string{"redirect", "status", "media", "oversize", "malformed", "wrong_service", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			e := dialEnv(t)
			var hits atomic.Int32
			server := serviceHTTPServer(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				switch mode {
				case "redirect":
					w.Header().Set("Location", "/elsewhere")
					w.WriteHeader(302)
				case "status":
					w.WriteHeader(403)
				case "media":
					w.Header().Set("Content-Type", "text/plain")
					_, _ = io.WriteString(w, `{}`)
				case "oversize":
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, strings.Repeat("a", 65537))
				case "malformed":
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"service_id":"target-service","route_revision":"1","route_revision":"2","mounts":{}}`)
				case "wrong_service":
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"service_id":"other","route_revision":"1","mounts":{}}`)
				case "timeout":
					<-r.Context().Done()
				}
			}))
			timeout := 5 * time.Second
			if mode == "timeout" {
				timeout = 250 * time.Millisecond
			}
			c, _ := readyServiceHTTP(t, e, ServiceHTTPConfig{ServerRoots: e.config.ServerRoots, SigningKey: serviceHTTPKey(), DiscoveryTimeout: timeout})
			for i := 0; i < 2; i++ {
				if _, err := c.NewServiceRequest(t.Context(), server.URL, "GET", "target-service", "api", "/", nil); !errors.Is(err, &Error{Code: DiscoveryUnavailable}) {
					t.Fatal(err)
				}
			}
			if hits.Load() != 2 {
				t.Fatal("cached invalid response or followed redirect")
			}
		})
	}
}

func TestDiscoveryInflightLookupCannotRestoreInvalidatedRevision(t *testing.T) {
	e := dialEnv(t)
	var gets atomic.Int32
	var revision atomic.Uint64
	revision.Store(1)
	entered, release := make(chan struct{}), make(chan struct{})
	server := serviceHTTPServer(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/outgate/discovery/") {
			n := gets.Add(1)
			rev := revision.Load()
			if n == 2 {
				close(entered)
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
			}
			writeDiscovery(w, rev, "/api")
			return
		}
		revision.Store(2)
		w.WriteHeader(409)
	}))
	c, _ := readyServiceHTTP(t, e, ServiceHTTPConfig{ServerRoots: e.config.ServerRoots, SigningKey: serviceHTTPKey()})
	req, err := c.NewServiceRequest(t.Context(), server.URL, "GET", "target-service", "api", "/call", nil)
	must(t, err)
	lookup := make(chan error, 1)
	go func() {
		_, err := c.NewServiceRequest(t.Context(), server.URL, "GET", "target-service", "other", "/call", nil)
		lookup <- err
	}()
	await(t, entered)
	client, err := c.ServiceHTTPClient(server.URL)
	must(t, err)
	response, err := client.Do(req)
	must(t, err)
	_ = response.Body.Close()
	close(release)
	if err := await(t, lookup); !errors.Is(err, &Error{Code: DiscoveryUnavailable}) {
		t.Fatal("stale in-flight lookup returned", err)
	}
	fresh, err := c.NewServiceRequest(t.Context(), server.URL, "GET", "target-service", "other", "/call", nil)
	must(t, err)
	if fresh.Header.Get("X-Outgate-Expected-Route-Revision") != "2" || gets.Load() != 3 {
		t.Fatal("in-flight stale revision cached")
	}
}

func TestDiscoveryMountJoining(t *testing.T) {
	for _, test := range []struct{ prefix, local, want string }{
		{"/", "/?", "/?"}, {"/api", "/", "/api/"}, {"/отчёты", "/%e2%82%ac?b=2&a=%2b", "/%D0%BE%D1%82%D1%87%D1%91%D1%82%D1%8B/%e2%82%ac?b=2&a=%2b"},
	} {
		t.Run(test.prefix, func(t *testing.T) {
			e := dialEnv(t)
			server := serviceHTTPServer(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/outgate/discovery/") {
					writeDiscovery(w, 1, test.prefix)
					return
				}
				verifyHTTPCall(t, e, r)
				if r.RequestURI != test.want {
					t.Error("wire URI changed")
				}
				w.WriteHeader(204)
			}))
			c, _ := readyServiceHTTP(t, e, ServiceHTTPConfig{ServerRoots: e.config.ServerRoots, SigningKey: serviceHTTPKey()})
			req, err := c.NewServiceRequest(t.Context(), server.URL, "GET", "target-service", "api", test.local, nil)
			must(t, err)
			if req.URL.RequestURI() != test.want {
				t.Fatalf("got %s", req.URL.RequestURI())
			}
			client, err := c.ServiceHTTPClient(server.URL)
			must(t, err)
			response, err := client.Do(req)
			must(t, err)
			_ = response.Body.Close()
		})
	}
}

func TestDiscoveryCacheAndBuiltRequestCannotCrossReconnect(t *testing.T) {
	e := dialEnv(t)
	var gets, business atomic.Int32
	server := serviceHTTPServer(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/outgate/discovery/") {
			n := gets.Add(1)
			writeDiscovery(w, uint64(n), "/api")
			return
		}
		business.Add(1)
		w.WriteHeader(204)
	}))
	c, pair := readyServiceHTTP(t, e, ServiceHTTPConfig{ServerRoots: e.config.ServerRoots, SigningKey: serviceHTTPKey()})
	body := &unreadDiscoveryBody{}
	old, err := c.NewServiceRequest(t.Context(), server.URL, "POST", "target-service", "api", "/", body)
	must(t, err)
	must(t, pair.g.carrier.Send(t.Context(), v1.Reconnect{Type: "reconnect", CommandID: 1, DeadlineMS: 2000, Code: "credential_rotation", Extensions: v1.QUICQuiescentFenceExtensions(0)}))
	u := receive(t, pair.g.carrier, "unregister").(v1.Unregister)
	must(t, pair.g.carrier.Send(t.Context(), v1.UnregisterAck{Type: "unregister_ack", CommandID: u.CommandID}))
	next := await(t, pair.accepted)
	must(t, next.err)
	receive(t, next.carrier, "status")
	client, err := c.ServiceHTTPClient(server.URL)
	must(t, err)
	if _, err := client.Do(old); !errors.Is(err, &Error{Code: DiscoveryUnavailable}) {
		t.Fatal(err)
	}
	if business.Load() != 0 || body.reads.Load() != 0 {
		t.Fatal("old discovery request sent after switch")
	}
	fresh, err := c.NewServiceRequest(t.Context(), server.URL, "GET", "target-service", "api", "/", nil)
	must(t, err)
	if fresh.Header.Get("X-Outgate-Expected-Route-Revision") != "2" || gets.Load() != 2 {
		t.Fatal("cache crossed accepted session switch")
	}
}

func TestDiscoveryExplicitDevelopmentUsesServiceBearer(t *testing.T) {
	e := dialEnv(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer dev-token" || r.Header.Get("Signature") != "" || r.Header.Get("X-Outgate-Deployment-Grant-ID") != "" || len(r.TLS.PeerCertificates) != 0 {
			t.Error("incorrect development discovery auth")
		}
		writeDiscovery(w, 1, "/api")
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{e.server}, NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	t.Cleanup(server.Close)
	e.config.Development = true
	e.config.ClientRoots = nil
	e.config.TrustDomain = ""
	e.config.Credentials, _ = StaticCredentials(CredentialSnapshot{Credential: []byte("dev-token")})
	_, accepted := listen(t, e)
	c, err := New(Config{QUIC: &e.config, Development: true, ServiceHTTP: &ServiceHTTPConfig{ServerRoots: e.config.ServerRoots, SigningKey: serviceHTTPKey()}, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})})
	must(t, err)
	running := run(t, c, t.Context())
	g := await(t, accepted)
	must(t, g.err)
	receive(t, g.carrier, "status")
	t.Cleanup(func() { c.Revoke(); await(t, running) })
	request, err := c.NewServiceRequest(t.Context(), server.URL, "GET", "target-service", "api", "/hello", nil)
	must(t, err)
	if request.URL.RequestURI() != "/api/hello" {
		t.Fatal("development helper failed")
	}
}
