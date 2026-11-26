package client

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/solodyagin/outgate-sdk/delegation"
	"github.com/solodyagin/outgate-sdk/httpsig"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

var userKeyOnce sync.Once
var userIssuerKey *rsa.PrivateKey

func userKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	userKeyOnce.Do(func() {
		var err error
		userIssuerKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
	})
	return userIssuerKey
}
func userVerifier(t *testing.T) *delegation.Verifier {
	t.Helper()
	now := time.Now()
	key := userKey(t)
	v, err := delegation.New(delegation.Config{Issuer: "https://issuer.example", Claims: delegation.ClaimMap{UserID: "sub", Roles: "roles", SessionID: "sid", Attributes: map[string]string{"tenant_id": "tenant_id"}}, Keys: delegation.KeySnapshot{Keys: map[string]*rsa.PublicKey{"issuer-1": {N: new(big.Int).Set(key.N), E: key.E}}, LoadedAt: now.Add(-time.Second), ValidUntil: now.Add(4 * time.Minute)}})
	must(t, err)
	return v
}
func userToken(t *testing.T, caller, target string) string {
	t.Helper()
	now := time.Now()
	header := []byte(`{"alg":"RS256","kid":"issuer-1","typ":"outgate-delegation+jwt"}`)
	payload, _ := json.Marshal(map[string]any{"iss": "https://issuer.example", "aud": target, "sub": "alice", "act": map[string]any{"sub": caller}, "sid": "session-1", "jti": "assertion-1", "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(120 * time.Second).Unix(), "roles": []string{"reader", "роль", "😀"}, "tenant_id": "acme"})
	message := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	hash := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, userKey(t), crypto.SHA256, hash[:])
	must(t, err)
	return message + "." + base64.RawURLEncoding.EncodeToString(signature)
}
func delegationOptions(t *testing.T, e *dialEnvironment, check func(context.Context, delegation.Identity) (time.Time, error)) ServiceHTTPConfig {
	return ServiceHTTPConfig{ServerRoots: e.config.ServerRoots, SigningKey: serviceHTTPKey(), AttributeHeaders: map[string]string{"tenant_id": "X-User-Tenant-ID"}, Delegation: &DelegationConfig{Verifier: userVerifier(t), SecurityCheck: check}}
}
func TestUserContextOwnershipAndInvalidValues(t *testing.T) {
	user := UserContext{ID: "alice", Roles: []string{"reader"}, Attributes: map[string]string{"tenant_id": "acme"}}
	ctx := WithUserContext(t.Context(), user)
	user.Roles[0] = "admin"
	user.Attributes["tenant_id"] = "other"
	got, ok := UserContextFromContext(ctx)
	if !ok || got.Roles[0] != "reader" || got.Attributes["tenant_id"] != "acme" {
		t.Fatal("mutated context")
	}
	got.Roles[0] = "changed"
	again, _ := UserContextFromContext(ctx)
	if again.Roles[0] != "reader" {
		t.Fatal("aliased getter")
	}
	invalid := WithUserContext(t.Context(), UserContext{ID: "alice\nadmin"})
	if _, ok := UserContextFromContext(invalid); ok {
		t.Fatal("invalid local user trusted")
	}
}
func TestUserAssertionSignedMTLSRequestAndMappedClaims(t *testing.T) {
	e := dialEnv(t)
	verifier := userVerifier(t)
	var checked atomic.Int32
	token := userToken(t, e.config.Register.ServiceID, "target-service")
	server := serviceHTTPServer(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Outgate-User-Assertion") != token || r.Header.Get("X-User-ID") != "alice" || r.Header.Get("X-User-Tenant-ID") != "acme" {
			t.Error("user headers not derived from claims")
		}
		if strings.Contains(r.Header.Get("X-User-Roles"), "роль") {
			t.Error("raw non-ASCII header")
		}
		var roles []string
		if err := json.Unmarshal([]byte(r.Header.Get("X-User-Roles")), &roles); err != nil || !reflect.DeepEqual(roles, []string{"reader", "роль", "😀"}) {
			t.Error("role semantics changed")
		}
		profile, _ := httpsig.New(httpsig.Config{Leg: httpsig.Call, AttributeHeaders: []string{"x-user-tenant-id"}})
		var headers []v1.Header
		for name, values := range r.Header {
			for _, value := range values {
				headers = append(headers, v1.Header{strings.ToLower(name), value})
			}
		}
		key := serviceHTTPKey()
		if _, err := profile.Verify(httpsig.Request{Method: r.Method, Scheme: "https", Authority: r.Host, RawURI: r.RequestURI, Headers: headers}, key.ID, key.Secret, time.Now()); err != nil {
			t.Error("bad signed user profile", err)
		}
		if _, err := verifier.Verify(token, r.Header.Get("X-Outgate-Caller-Service"), r.Header.Get("X-Outgate-Target-Service"), time.Now()); err != nil {
			t.Error(err)
		}
		w.WriteHeader(204)
	}))
	options := delegationOptions(t, e, func(ctx context.Context, id delegation.Identity) (time.Time, error) {
		checked.Add(1)
		if id.SessionID != "session-1" || id.Actor != e.config.Register.ServiceID || id.Target != "target-service" {
			t.Error("unverified identity passed to callback")
		}
		return time.Now().Add(time.Minute), nil
	})
	c, _ := readyServiceHTTP(t, e, options)
	httpClient, err := c.ServiceHTTPClient(server.URL)
	must(t, err)
	// Assertion alone derives the context; local context, when supplied, must match.
	for _, withLocal := range []bool{false, true} {
		ctx := WithUserAssertion(WithTargetService(t.Context(), "target-service"), token)
		if withLocal {
			ctx = WithUserContext(ctx, UserContext{ID: "alice", Roles: []string{"reader", "роль", "😀"}, Attributes: map[string]string{"tenant_id": "acme"}})
		}
		req, err := http.NewRequestWithContext(ctx, "GET", server.URL+"/api?x=%2b", nil)
		must(t, err)
		response, err := httpClient.Do(req)
		must(t, err)
		_ = response.Body.Close()
		if len(req.Header) != 0 {
			t.Fatal("mutated request")
		}
	}
	if checked.Load() != 2 {
		t.Fatal("security check missing")
	}
}
func TestProductionUserFailureDoesNotReachNetwork(t *testing.T) {
	e := dialEnv(t)
	var hits, checks atomic.Int32
	server := serviceHTTPServer(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(204) }))
	c, _ := readyServiceHTTP(t, e, delegationOptions(t, e, func(context.Context, delegation.Identity) (time.Time, error) {
		checks.Add(1)
		return time.Now().Add(time.Second), nil
	}))
	httpClient, err := c.ServiceHTTPClient(server.URL)
	must(t, err)
	for _, mode := range []string{"local_only", "wrong_actor", "wrong_audience", "mismatched_user", "empty_token", "oversized", "invalid_user"} {
		t.Run(mode, func(t *testing.T) {
			ctx := WithTargetService(t.Context(), "target-service")
			token := userToken(t, e.config.Register.ServiceID, "target-service")
			switch mode {
			case "local_only":
				ctx = WithUserContext(ctx, UserContext{ID: "alice"})
				token = ""
			case "wrong_actor":
				token = userToken(t, "other-service", "target-service")
			case "wrong_audience":
				token = userToken(t, e.config.Register.ServiceID, "other-service")
			case "mismatched_user":
				ctx = WithUserContext(ctx, UserContext{ID: "attacker", Roles: []string{"admin"}})
			case "empty_token":
				token = ""
			case "oversized":
				token = strings.Repeat("a", delegation.MaxTokenBytes+1)
			case "invalid_user":
				ctx = WithUserContext(ctx, UserContext{ID: "alice\nadmin"})
			}
			if mode != "local_only" {
				ctx = WithUserAssertion(ctx, token)
			}
			req, err := http.NewRequestWithContext(ctx, "POST", server.URL+"/api", &unreadDiscoveryBody{})
			must(t, err)
			if _, err := httpClient.Do(req); err == nil {
				t.Fatal("invalid user call accepted")
			}
		})
	}
	if hits.Load() != 0 || checks.Load() != 0 {
		t.Fatal("invalid assertion reached callback or network")
	}
}
func TestUserSecurityLeaseExpiryAndSafeCallbackErrors(t *testing.T) {
	for _, mode := range []string{"lease", "error", "panic"} {
		t.Run(mode, func(t *testing.T) {
			e := dialEnv(t)
			var hits atomic.Int32
			canceled := make(chan struct{})
			server := serviceHTTPServer(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				_, _ = w.Write([]byte("first"))
				w.(http.Flusher).Flush()
				<-r.Context().Done()
				close(canceled)
			}))
			options := delegationOptions(t, e, func(context.Context, delegation.Identity) (time.Time, error) {
				if mode == "error" {
					return time.Time{}, errors.New("private security state")
				}
				if mode == "panic" {
					panic("private panic")
				}
				return time.Now().Add(250 * time.Millisecond), nil
			})
			c, _ := readyServiceHTTP(t, e, options)
			client, err := c.ServiceHTTPClient(server.URL)
			must(t, err)
			req := httpRequest(t, "GET", server.URL+"/stream", nil)
			req = req.WithContext(WithUserAssertion(req.Context(), userToken(t, e.config.Register.ServiceID, "target-service")))
			response, err := client.Do(req)
			if mode != "lease" {
				if err == nil || hits.Load() != 0 || strings.Contains(err.Error(), "private") {
					t.Fatal("callback failure leaked or dispatched")
				}
				return
			}
			must(t, err)
			await(t, canceled)
			_, err = io.ReadAll(response.Body)
			if err == nil {
				t.Fatal("user stream outlived lease")
			}
			_ = response.Body.Close()
		})
	}
}

func TestDefaultClientRejectsAssertionWithoutSecurityProvider(t *testing.T) {
	e := dialEnv(t)
	var hits atomic.Int32
	server := serviceHTTPServer(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(204) }))
	c, _ := readyServiceHTTP(t, e, ServiceHTTPConfig{ServerRoots: e.config.ServerRoots, SigningKey: serviceHTTPKey()})
	client, err := c.ServiceHTTPClient(server.URL)
	must(t, err)
	req := httpRequest(t, "GET", server.URL+"/", nil)
	req = req.WithContext(WithUserAssertion(req.Context(), userToken(t, e.config.Register.ServiceID, "target-service")))
	if _, err := client.Do(req); !errors.Is(err, &Error{Code: SecurityFailure}) {
		t.Fatal(err)
	}
	if hits.Load() != 0 {
		t.Fatal("default user delegation failed open")
	}
}

func TestUserSecurityCallbackRetainsSlotAndCloseWaitsActualReturn(t *testing.T) {
	e := dialEnv(t)
	var checks, hits atomic.Int32
	entered, release, canceled := make(chan struct{}), make(chan struct{}), make(chan struct{})
	server := serviceHTTPServer(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(204) }))
	c, pair := readyServiceHTTP(t, e, delegationOptions(t, e, func(ctx context.Context, _ delegation.Identity) (time.Time, error) {
		checks.Add(1)
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release
		return time.Now().Add(time.Second), nil
	}))
	client, err := c.ServiceHTTPClient(server.URL)
	must(t, err)
	req := httpRequest(t, "GET", server.URL+"/", nil)
	req = req.WithContext(WithUserAssertion(req.Context(), userToken(t, e.config.Register.ServiceID, "target-service")))
	completed := make(chan error, 1)
	go func() { _, err := client.Do(req); completed <- err }()
	await(t, entered)
	closeCtx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	closed := make(chan error, 1)
	go func() { closed <- c.Close(closeCtx) }()
	acknowledgeDrain(t, pair.g.carrier)
	if err := await(t, closed); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	await(t, canceled)
	select {
	case <-c.Done():
		t.Fatal("completed before actual user callback return")
	default:
	}
	close(release)
	if err := await(t, completed); err == nil {
		t.Fatal("late security decision accepted")
	}
	if checks.Load() != 1 || hits.Load() != 0 {
		t.Fatal("callback overlapped or late request dispatched")
	}
	if err := await(t, pair.running); !errors.Is(err, &Error{Code: ShutdownTimeout}) {
		t.Fatal(err)
	}
}

func TestUserCallbackCannotDispatchSupersededCredentialPair(t *testing.T) {
	e := dialEnv(t)
	var sources, hits atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	e.config.Credentials = func(context.Context) (CredentialSnapshot, error) {
		snapshot := e.snapshot
		snapshot.Generation = uint64(sources.Add(1))
		snapshot.Credential = grant(byte(snapshot.Generation))
		return snapshot, nil
	}
	server := serviceHTTPServer(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(204) }))
	c, pair := readyServiceHTTP(t, e, delegationOptions(t, e, func(context.Context, delegation.Identity) (time.Time, error) {
		close(entered)
		<-release
		return time.Now().Add(time.Second), nil
	}))
	client, err := c.ServiceHTTPClient(server.URL)
	must(t, err)
	req := httpRequest(t, "GET", server.URL+"/", nil)
	req = req.WithContext(WithUserAssertion(req.Context(), userToken(t, e.config.Register.ServiceID, "target-service")))
	result := make(chan error, 1)
	go func() { _, err := client.Do(req); result <- err }()
	await(t, entered)
	must(t, pair.g.carrier.Send(t.Context(), v1.Reconnect{Type: "reconnect", CommandID: 1, DeadlineMS: 2000, Code: "credential_rotation", Extensions: v1.QUICQuiescentFenceExtensions(0)}))
	u := receive(t, pair.g.carrier, "unregister").(v1.Unregister)
	must(t, pair.g.carrier.Send(t.Context(), v1.UnregisterAck{Type: "unregister_ack", CommandID: u.CommandID}))
	next := await(t, pair.accepted)
	must(t, next.err)
	receive(t, next.carrier, "status")
	close(release)
	if err := await(t, result); !errors.Is(err, ErrClientNotReady) {
		t.Fatal(err)
	}
	if hits.Load() != 0 {
		t.Fatal("old pair dispatched after rotation")
	}
}

func TestDevelopmentUserContextRequiresExplicitProfile(t *testing.T) {
	s := &serviceHTTPState{development: true, config: ServiceHTTPConfig{AttributeHeaders: map[string]string{"tenant_id": "x-user-tenant-id"}}}
	ctx := WithUserContext(t.Context(), UserContext{ID: "alice", Roles: []string{"роль", "😀"}, Attributes: map[string]string{"tenant_id": "acme"}})
	headers, err := s.userHeaders(nil, ctx, "target-service")
	must(t, err)
	fields := make(map[string]string)
	for _, header := range headers {
		fields[header[0]] = header[1]
	}
	if fields["x-user-id"] != "alice" || fields["x-user-tenant-id"] != "acme" || fields["x-outgate-user-assertion"] != "" {
		t.Fatal("invalid development context")
	}
	if _, err := s.userHeaders(nil, WithUserAssertion(ctx, "a.b.c"), "target-service"); !errors.Is(err, &Error{Code: InvalidRequest}) {
		t.Fatal("development accepted issuer assertion", err)
	}
	if _, err := s.userHeaders(nil, WithUserContext(t.Context(), UserContext{ID: "алиса"}), "target-service"); !errors.Is(err, &Error{Code: InvalidRequest}) {
		t.Fatal("unsupported plain-header encoding accepted", err)
	}
	s.development = false
	if _, err := s.userHeaders(nil, ctx, "target-service"); !errors.Is(err, &Error{Code: SecurityFailure}) {
		t.Fatal("local context granted production identity", err)
	}
}

func TestUserKeyRemovedDuringSecurityCheckPreventsDispatch(t *testing.T) {
	e := dialEnv(t)
	var hits atomic.Int32
	server := serviceHTTPServer(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(204) }))
	verifier := userVerifier(t)
	options := delegationOptions(t, e, func(context.Context, delegation.Identity) (time.Time, error) {
		now := time.Now()
		must(t, verifier.ReplaceKeys(delegation.KeySnapshot{Keys: map[string]*rsa.PublicKey{"replacement": &userKey(t).PublicKey}, LoadedAt: now, ValidUntil: now.Add(time.Minute)}))
		return now.Add(time.Minute), nil
	})
	options.Delegation.Verifier = verifier
	c, _ := readyServiceHTTP(t, e, options)
	httpClient, err := c.ServiceHTTPClient(server.URL)
	must(t, err)
	req := httpRequest(t, "GET", server.URL+"/", nil)
	req = req.WithContext(WithUserAssertion(req.Context(), userToken(t, e.config.Register.ServiceID, "target-service")))
	if _, err := httpClient.Do(req); !errors.Is(err, &Error{Code: SecurityFailure}) {
		t.Fatal("removed issuer key permitted dispatch", err)
	}
	if hits.Load() != 0 {
		t.Fatal("removed issuer key reached network")
	}
}
