package delegation

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

var once sync.Once
var issuerKey *rsa.PrivateKey

func key(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	once.Do(func() {
		var err error
		issuerKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
	})
	return issuerKey
}
func configuration(t testing.TB, now time.Time) Config {
	return Config{Issuer: "https://issuer.example", Claims: ClaimMap{UserID: "sub", Roles: "roles", SessionID: "sid", Attributes: map[string]string{"tenant_id": "tenant_id"}}, Keys: KeySnapshot{Keys: map[string]*rsa.PublicKey{"issuer-1": {N: new(big.Int).Set(key(t).N), E: key(t).E}}, LoadedAt: now.Add(-time.Second), ValidUntil: now.Add(4 * time.Minute)}}
}
func claims(now time.Time) map[string]any {
	return map[string]any{"iss": "https://issuer.example", "aud": "target-service", "sub": "alice", "act": map[string]any{"sub": "caller-service"}, "sid": "session-1", "jti": "assertion-1", "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(120 * time.Second).Unix(), "roles": []string{"reader", "роль"}, "tenant_id": "acme"}
}
func token(t testing.TB, fields map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "outgate-delegation+jwt", "kid": "issuer-1"})
	p, _ := json.Marshal(fields)
	return rawToken(t, h, p)
}
func rawToken(t testing.TB, header, payload []byte) string {
	t.Helper()
	message := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(message))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key(t), crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return message + "." + base64.RawURLEncoding.EncodeToString(sig)
}
func TestVerifyOwnedKeysClaimsAndFreshness(t *testing.T) {
	now := time.Unix(1795723200, 0)
	c := configuration(t, now)
	v, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	signed := token(t, claims(now))
	c.Keys.Keys["issuer-1"].N.SetInt64(3)
	delete(c.Keys.Keys, "issuer-1")
	c.Claims.Attributes["tenant_id"] = "forged"
	got, err := v.Verify(signed, "caller-service", "target-service", now)
	if err != nil {
		t.Fatal(err)
	}
	user, _ := got.User()
	if user.ID != "alice" || user.Roles[1] != "роль" || user.Attributes["tenant_id"] != "acme" || got.Identity().SessionID != "session-1" {
		t.Fatal("claim mapping")
	}
	user.Roles[0] = "admin"
	user.Attributes["tenant_id"] = "mutated"
	again, _ := got.User()
	if again.Roles[0] != "reader" || again.Attributes["tenant_id"] != "acme" {
		t.Fatal("aliased verified claims")
	}
	if _, err := v.Verify(signed, "wrong", "target-service", now); !errors.Is(err, ErrAssertion) {
		t.Fatal("actor mismatch")
	}
	if _, err := v.Verify(signed, "caller-service", "wrong", now); !errors.Is(err, ErrAssertion) {
		t.Fatal("audience mismatch")
	}
	expiredKeys := configuration(t, now)
	expiredKeys.Keys.LoadedAt = now.Add(-5 * time.Minute)
	expiredKeys.Keys.ValidUntil = now
	stale, _ := New(expiredKeys)
	if _, err := stale.Verify(signed, "caller-service", "target-service", now); err == nil {
		t.Fatal("stale key accepted")
	}
	if _, err := (Verified{}).User(); err == nil {
		t.Fatal("zero verified value trusted")
	}
}
func TestSignedInvalidClaimsAndJOSE(t *testing.T) {
	now := time.Unix(1795723200, 0)
	v, _ := New(configuration(t, now))
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"issuer", func(c map[string]any) { c["iss"] = "https://other.example" }},
		{"audiences", func(c map[string]any) { c["aud"] = []string{"target-service", "other"} }},
		{"actor", func(c map[string]any) {
			c["act"] = map[string]any{"sub": "other", "act": map[string]any{"sub": "caller-service"}}
		}},
		{"lifetime", func(c map[string]any) { c["exp"] = now.Add(301 * time.Second).Unix() }},
		{"expired", func(c map[string]any) {
			c["iat"] = now.Add(-120 * time.Second).Unix()
			c["nbf"] = c["iat"]
			c["exp"] = now.Unix()
		}},
		{"future", func(c map[string]any) { c["nbf"] = now.Add(time.Second).Unix() }},
		{"missing_sid", func(c map[string]any) { delete(c, "sid") }},
		{"null_jti", func(c map[string]any) { c["jti"] = nil }},
		{"roles_type", func(c map[string]any) { c["roles"] = "admin" }},
		{"roles_count", func(c map[string]any) { c["roles"] = make([]string, 33) }},
		{"control", func(c map[string]any) { c["roles"] = []string{"reader\nadmin"} }},
		{"attribute_type", func(c map[string]any) { c["tenant_id"] = map[string]any{"admin": true} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fields := claims(now)
			test.mutate(fields)
			if _, err := v.Verify(token(t, fields), "caller-service", "target-service", now); !errors.Is(err, ErrAssertion) {
				t.Fatal("accepted signed invalid claims")
			}
		})
	}
	payload, _ := json.Marshal(claims(now))
	for _, header := range []string{
		`{"alg":"HS256","typ":"outgate-delegation+jwt","kid":"issuer-1"}`,
		`{"alg":"none","typ":"outgate-delegation+jwt","kid":"issuer-1"}`,
		`{"alg":"RS256","typ":"JWT","kid":"issuer-1"}`,
		`{"alg":"RS256","typ":"outgate-delegation+jwt","kid":"unknown"}`,
		`{"alg":"RS256","alg":"RS256","typ":"outgate-delegation+jwt","kid":"issuer-1"}`,
		`{"alg":"RS256","typ":"outgate-delegation+jwt","kid":"issuer-1","crit":["new"]}`,
		`{"alg":"RS256","typ":"outgate-delegation+jwt","kid":"issuer-1","b64":false}`,
	} {
		if _, err := v.Verify(rawToken(t, []byte(header), payload), "caller-service", "target-service", now); err == nil {
			t.Fatal("accepted unsupported JOSE profile")
		}
	}
	duplicated := strings.TrimSuffix(string(payload), "}") + `,"exp":` + string(json.RawMessage("1795723300")) + `}`
	if _, err := v.Verify(rawToken(t, []byte(`{"alg":"RS256","typ":"outgate-delegation+jwt","kid":"issuer-1"}`), []byte(duplicated)), "caller-service", "target-service", now); err == nil {
		t.Fatal("accepted duplicate signed claim")
	}
	trustedHeader := []byte(`{"alg":"RS256","typ":"outgate-delegation+jwt","kid":"issuer-1","jku":"https://attacker.example/keys","x5u":"http://attacker.example/cert","jwk":{"kty":"oct","k":"attacker"}}`)
	if _, err := v.Verify(rawToken(t, trustedHeader, payload), "caller-service", "target-service", now); err != nil {
		t.Fatal("untrusted key hints selected a source")
	}
}
func TestSkewAudienceMappingAndSnapshotReplacement(t *testing.T) {
	now := time.Unix(1795723200, 0)
	config := configuration(t, now)
	config.ClockSkew = 30 * time.Second
	v, _ := New(config)
	fields := claims(now)
	fields["aud"] = []string{"target-service"}
	fields["iat"] = now.Add(30 * time.Second).Unix()
	fields["nbf"] = fields["iat"]
	fields["exp"] = now.Add(150 * time.Second).Unix()
	if _, err := v.Verify(token(t, fields), "caller-service", "target-service", now); err != nil {
		t.Fatal(err)
	}
	fields["iat"] = now.Add(31 * time.Second).Unix()
	if _, err := v.Verify(token(t, fields), "caller-service", "target-service", now); err == nil {
		t.Fatal("future skew expanded")
	}
	next := configuration(t, now).Keys
	next.LoadedAt = now
	next.ValidUntil = now.Add(5 * time.Minute)
	if err := v.ReplaceKeys(next); err != nil {
		t.Fatal(err)
	}
	old := configuration(t, now).Keys
	if v.ReplaceKeys(old) == nil {
		t.Fatal("snapshot time rolled back")
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.ClockSkew = 31 * time.Second }, func(c *Config) { c.Keys.ValidUntil = c.Keys.LoadedAt.Add(6 * time.Minute) }, func(c *Config) { c.Keys.Keys["issuer-1"].N.SetInt64(3) }, func(c *Config) { c.Claims.Roles = "" }} {
		config := configuration(t, now)
		mutate(&config)
		if _, err := New(config); !errors.Is(err, ErrConfig) {
			t.Fatal("invalid config accepted")
		}
	}
}
func FuzzAssertion(f *testing.F) {
	now := time.Unix(1795723200, 0)
	v, _ := New(configuration(f, now))
	f.Add(token(f, claims(now)))
	f.Add("a.b.c")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		verified, err := v.Verify(s, "caller-service", "target-service", now)
		if err != nil {
			return
		}
		user, err := verified.User()
		if err != nil || user.ID == "" || verified.Identity().Actor != "caller-service" {
			t.Fatal("invalid verified assertion")
		}
	})
}
