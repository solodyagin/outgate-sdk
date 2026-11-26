package delivery

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/solodyagin/outgate-sdk/delegation"
	"github.com/solodyagin/outgate-sdk/httpsig"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

var keyOnce sync.Once
var issuerKey *rsa.PrivateKey

func issuer(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	keyOnce.Do(func() {
		var err error
		issuerKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
	})
	return issuerKey
}

type fixture struct {
	verifier *Verifier
	profile  *httpsig.Profile
	key      Key
	binding  Binding
	request  httpsig.Request
	now      time.Time
	config   Config
	claims   map[string]any
}

func setup(t testing.TB, leg string, user bool) fixture {
	t.Helper()
	now := time.Unix(1795723200, 0)
	jwt, err := delegation.New(delegation.Config{Issuer: "https://issuer.example", Claims: delegation.ClaimMap{UserID: "sub", Roles: "roles", SessionID: "sid", Attributes: map[string]string{"tenant_id": "tenant_id"}}, Keys: delegation.KeySnapshot{Keys: map[string]*rsa.PublicKey{"issuer-1": &issuer(t).PublicKey}, LoadedAt: now.Add(-time.Second), ValidUntil: now.Add(4 * time.Minute)}})
	if err != nil {
		t.Fatal(err)
	}
	config := Config{Leg: leg, JWT: jwt, AttributeHeaders: map[string]string{"tenant_id": "x-user-tenant-id"}}
	verifier, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := httpsig.New(httpsig.Config{Leg: leg, AttributeHeaders: []string{"x-user-tenant-id"}})
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{Caller: "caller-service", Target: "target-service", GrantID: "grant-1"}
	r := httpsig.Request{Method: "POST", Scheme: "https", Authority: "gateway.example:9443", RawURI: "/api/items?x=%2b&z=", Headers: []v1.Header{{"x-outgate-caller-service", binding.Caller}, {"x-outgate-target-service", binding.Target}, {"x-outgate-deployment-grant-id", binding.GrantID}, {"x-outgate-hop-limit", "3"}, {"x-outgate-context-headers", "[]"}}}
	if leg == httpsig.Gateway {
		binding.Instance, binding.Version, binding.Prefix = "instance-1", "1.2.3", "/api"
		r.Headers = append(r.Headers, v1.Header{"x-tunnel-instance", binding.Instance}, v1.Header{"x-tunnel-version", binding.Version}, v1.Header{"x-forwarded-prefix", binding.Prefix})
	}
	claims := map[string]any{"iss": "https://issuer.example", "aud": binding.Target, "sub": "alice", "act": map[string]string{"sub": binding.Caller}, "sid": "session-1", "jti": "assertion-1", "iat": now.Unix(), "exp": now.Add(120 * time.Second).Unix(), "roles": []string{"reader", "роль"}, "tenant_id": "acme"}
	if user {
		r = set(r, "x-outgate-context-headers", `["x-user-id","x-user-roles","x-user-tenant-id"]`)
		r.Headers = append(r.Headers, v1.Header{"x-user-id", "alice"}, v1.Header{"x-user-roles", `["reader","\u0440\u043e\u043b\u044c"]`}, v1.Header{"x-user-tenant-id", "acme"}, v1.Header{"x-outgate-user-assertion", token(t, claims)})
	}
	return fixture{verifier, profile, Key{ID: "hmac-1", Secret: []byte(strings.Repeat("s", 32))}, binding, r, now, config, claims}
}
func token(t testing.TB, claims map[string]any) string {
	t.Helper()
	header := []byte(`{"alg":"RS256","kid":"issuer-1","typ":"outgate-delegation+jwt"}`)
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	message := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(message))
	sig, err := rsa.SignPKCS1v15(rand.Reader, issuer(t), crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return message + "." + base64.RawURLEncoding.EncodeToString(sig)
}
func set(r httpsig.Request, name, value string) httpsig.Request {
	r.Headers = append([]v1.Header{}, r.Headers...)
	for i, h := range r.Headers {
		if strings.EqualFold(h[0], name) {
			r.Headers[i][1] = value
			return r
		}
	}
	r.Headers = append(r.Headers, v1.Header{name, value})
	return r
}
func (f fixture) signed(t testing.TB, r httpsig.Request) httpsig.Request {
	t.Helper()
	h, err := f.profile.Sign(r, f.key.ID, f.key.Secret, f.now)
	if err != nil {
		t.Fatal("fixture signature", err)
	}
	r.Headers = append(append([]v1.Header{}, r.Headers...), v1.Header{"signature-input", h.SignatureInput}, v1.Header{"signature", h.Signature})
	return r
}
func TestBothLegsVerifySemanticUserContextAndBackground(t *testing.T) {
	for _, leg := range []string{httpsig.Call, httpsig.Gateway} {
		for _, user := range []bool{false, true} {
			f := setup(t, leg, user)
			r := f.signed(t, f.request)
			before := append([]v1.Header{}, r.Headers...)
			v, err := f.verifier.Verify(r, f.key, f.binding, f.now)
			if err != nil {
				t.Fatal(leg, user, err)
			}
			if v.Binding() != f.binding || v.HopLimit() != 3 || v.Signature().Info().Leg != leg {
				t.Fatal("lost authenticated metadata")
			}
			got, has := v.User()
			id, hasID := v.Identity()
			if has != user || hasID != user {
				t.Fatal("invented/lost identity")
			}
			if user {
				if got.ID != "alice" || !reflect.DeepEqual(got.Roles, []string{"reader", "роль"}) || got.Attributes["tenant_id"] != "acme" || id.SessionID != "session-1" {
					t.Fatal("claims mismatch")
				}
				got.Roles[0] = "admin"
				got.Attributes["tenant_id"] = "other"
				again, _ := v.User()
				if again.Roles[0] != "reader" || again.Attributes["tenant_id"] != "acme" {
					t.Fatal("aliased user")
				}
			}
			if !reflect.DeepEqual(before, r.Headers) {
				t.Fatal("mutated signed bytes")
			}
		}
	}
}
func TestSignedSemanticMismatchRejected(t *testing.T) {
	for _, leg := range []string{httpsig.Call, httpsig.Gateway} {
		for _, mode := range []string{"id", "roles", "role_order", "attribute", "attribute_missing", "wrong_actor", "wrong_aud", "jwt_expiry", "unknown_key"} {
			t.Run(leg+"/"+mode, func(t *testing.T) {
				f := setup(t, leg, true)
				r := f.request
				switch mode {
				case "id":
					r = set(r, "x-user-id", "mallory")
				case "roles":
					r = set(r, "x-user-roles", `["admin"]`)
				case "role_order":
					r = set(r, "x-user-roles", `["\u0440\u043e\u043b\u044c","reader"]`)
				case "attribute":
					r = set(r, "x-user-tenant-id", "other")
				case "attribute_missing":
					delete(f.claims, "tenant_id")
				case "wrong_actor":
					f.claims["act"] = map[string]string{"sub": "other-service"}
				case "wrong_aud":
					f.claims["aud"] = "other-service"
				case "jwt_expiry":
					f.claims["iat"] = f.now.Add(-time.Minute).Unix()
					f.claims["exp"] = f.now.Unix()
				case "unknown_key":
					f.key.ID = "other-hmac-key"
				}
				if mode == "attribute_missing" || mode == "wrong_actor" || mode == "wrong_aud" || mode == "jwt_expiry" {
					r = set(r, "x-outgate-user-assertion", token(t, f.claims))
				}
				r = f.signed(t, r)
				key := f.key
				if mode == "unknown_key" {
					key.ID = "hmac-1"
				}
				if _, err := f.verifier.Verify(r, key, f.binding, f.now); !errors.Is(err, ErrDelivery) {
					t.Fatal("signed forgery accepted", err)
				}
			})
		}
	}
}
func TestAssertionAttributesMustHaveExactHeaderRepresentation(t *testing.T) {
	for _, mode := range []string{"missing_header", "unmapped_claim", "extra_header"} {
		t.Run(mode, func(t *testing.T) {
			f := setup(t, httpsig.Call, true)
			r := f.request
			if mode != "extra_header" {
				r = set(r, "x-outgate-context-headers", `["x-user-id","x-user-roles"]`)
				kept := make([]v1.Header, 0, len(r.Headers))
				for _, h := range r.Headers {
					if h[0] != "x-user-tenant-id" {
						kept = append(kept, h)
					}
				}
				r.Headers = kept
			} else {
				delete(f.claims, "tenant_id")
				r = set(r, "x-outgate-user-assertion", token(t, f.claims))
			}
			if mode == "unmapped_claim" {
				f.config.AttributeHeaders = nil
				var err error
				f.verifier, err = New(f.config)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.verifier.Verify(f.signed(t, r), f.key, f.binding, f.now); err == nil {
				t.Fatal("partial attribute representation accepted")
			}
		})
	}
}

func TestExpectedBindingAndOriginalPathRequired(t *testing.T) {
	for _, leg := range []string{httpsig.Call, httpsig.Gateway} {
		f := setup(t, leg, true)
		r := f.signed(t, f.request)
		for _, field := range []string{"caller", "target", "grant", "instance", "version", "prefix", "empty"} {
			expected := f.binding
			switch field {
			case "caller":
				expected.Caller = "other-service"
			case "target":
				expected.Target = "other-service"
			case "grant":
				expected.GrantID = "other-grant"
			case "instance":
				expected.Instance = "other-instance"
			case "version":
				expected.Version = "other-version"
			case "prefix":
				expected.Prefix = "/other"
			case "empty":
				expected = Binding{}
			}
			if _, err := f.verifier.Verify(r, f.key, expected, f.now); err == nil {
				t.Fatal("binding accepted", leg, field)
			}
		}
		mutated := r
		mutated.RawURI = "/items?x=%2b&z="
		if _, err := f.verifier.Verify(mutated, f.key, f.binding, f.now); err == nil {
			t.Fatal("stripped URI accepted")
		}
	}
	f := setup(t, httpsig.Gateway, false)
	for _, path := range []string{"/apix/items", "/items"} {
		r := f.request
		r.RawURI = path
		if _, err := f.verifier.Verify(f.signed(t, r), f.key, f.binding, f.now); err == nil {
			t.Fatal("signed route outside mount accepted")
		}
	}
	f.binding.Prefix = "/"
	r := set(f.request, "x-forwarded-prefix", "/")
	if _, err := f.verifier.Verify(f.signed(t, r), f.key, f.binding, f.now); err != nil {
		t.Fatal("root mount", err)
	}
}
func TestBackgroundOnlyAndOwnedMapping(t *testing.T) {
	f := setup(t, httpsig.Call, false)
	config := f.config
	config.JWT = nil
	background, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := background.Verify(f.signed(t, f.request), f.key, f.binding, f.now); err != nil {
		t.Fatal(err)
	}
	user := setup(t, httpsig.Call, true)
	if _, err := background.Verify(user.signed(t, user.request), user.key, user.binding, user.now); err == nil {
		t.Fatal("user without JWT verifier")
	}
	f = user
	f.config.AttributeHeaders["tenant_id"] = "x-user-changed"
	if _, err := f.verifier.Verify(f.signed(t, f.request), f.key, f.binding, f.now); err != nil {
		t.Fatal("configuration aliased", err)
	}
	for _, mapping := range []map[string]string{{"tenant_id": "authorization"}, {"tenant_id": "x-user-id"}, {"tenant_id": "x-user-a", "other": "X-User-A"}, {"bad name": "x-user-a"}} {
		if _, err := New(Config{Leg: httpsig.Call, AttributeHeaders: mapping}); err == nil {
			t.Fatal("unsafe mapping accepted")
		}
	}
}

type reservationStore struct {
	entries map[httpsig.ReplayKey]bool
	calls   int
}

func (s *reservationStore) Reserve(_ context.Context, r httpsig.Reservation) error {
	s.calls++
	if s.entries[r.Key] {
		return httpsig.ErrReplay
	}
	s.entries[r.Key] = true
	return nil
}
func TestVerificationLeavesReplayToAuthorizedAdmission(t *testing.T) {
	f := setup(t, httpsig.Gateway, true)
	r := f.signed(t, f.request)
	s := &reservationStore{entries: make(map[httpsig.ReplayKey]bool)}
	for i := 0; i < 2; i++ {
		v, err := f.verifier.Verify(r, f.key, f.binding, f.now)
		if err != nil {
			t.Fatal(err)
		}
		err = v.Signature().Reserve(t.Context(), s, "recipient-1", f.now)
		if i == 0 && err != nil || i == 1 && !errors.Is(err, httpsig.ErrReplay) {
			t.Fatal("replay admission", err)
		}
	}
	if s.calls != 2 || len(s.entries) != 1 {
		t.Fatal("lost reservation")
	}
	var zero Verified
	if err := zero.Signature().Reserve(t.Context(), s, "recipient-1", f.now); err == nil || s.calls != 2 {
		t.Fatal("zero proof reserved nonce")
	}
}
func FuzzDeliveryUserEquality(f *testing.F) {
	fixture := setup(f, httpsig.Call, true)
	f.Add("alice", `["reader","\u0440\u043e\u043b\u044c"]`, "acme")
	f.Add("alice", `["admin"]`, "acme")
	f.Fuzz(func(t *testing.T, id, roles, tenant string) {
		if len(id)+len(roles)+len(tenant) > 10000 {
			return
		}
		r := set(set(set(fixture.request, "x-user-id", id), "x-user-roles", roles), "x-user-tenant-id", tenant)
		h, err := fixture.profile.Sign(r, fixture.key.ID, fixture.key.Secret, fixture.now)
		if err != nil {
			return
		}
		r.Headers = append(r.Headers, v1.Header{"signature-input", h.SignatureInput}, v1.Header{"signature", h.Signature})
		v, err := fixture.verifier.Verify(r, fixture.key, fixture.binding, fixture.now)
		if err == nil {
			user, ok := v.User()
			var decoded []string
			if json.Unmarshal([]byte(roles), &decoded) != nil || !ok || id != user.ID || tenant != user.Attributes["tenant_id"] || !reflect.DeepEqual(decoded, user.Roles) {
				t.Fatal("semantic mismatch accepted")
			}
		}
	})
}
