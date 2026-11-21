package httpsig

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

type vector struct {
	Name             string
	Production, User bool
	Label, Method    string
	RawURI           string `json:"raw_request_uri"`
	KeyHex           string `json:"key_hex"`
	Components       []struct{ Name, Value string }
	Input            string `json:"signature_input"`
	Base             string `json:"signature_base"`
	Signature        string
	Negative         struct{ Field, Value string } `json:"negative_replace"`
}

func vectors(t testing.TB) []vector {
	t.Helper()
	b, err := os.ReadFile("../tests/fixtures/protocol/v1/signatures.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct{ Vectors []vector }
	if err = json.Unmarshal(b, &corpus); err != nil {
		t.Fatal(err)
	}
	return corpus.Vectors
}
func setup(t testing.TB, v vector) (*Profile, Request, []byte, Params) {
	t.Helper()
	p, err := New(Config{Leg: v.Label, Development: !v.Production})
	if err != nil {
		t.Fatal(err)
	}
	r := Request{Method: v.Method, Scheme: "https", RawURI: v.RawURI}
	for _, c := range v.Components {
		if c.Name == "@authority" {
			r.Authority = c.Value
		} else if !strings.HasPrefix(c.Name, "@") {
			r.Headers = append(r.Headers, v1.Header{c.Name, c.Value})
		}
	}
	key, err := hex.DecodeString(v.KeyHex)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSignatureInput(v.Input)
	if err != nil {
		t.Fatal(err)
	}
	return p, r, key, parsed.Params
}
func signed(r Request, h Headers) Request {
	r.Headers = append(append([]v1.Header{}, r.Headers...), v1.Header{"Signature-Input", h.SignatureInput}, v1.Header{"Signature", h.Signature})
	return r
}
func set(r Request, name, value string) Request {
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
func drop(r Request, name string) Request {
	headers := []v1.Header{}
	for _, h := range r.Headers {
		if !strings.EqualFold(h[0], name) {
			headers = append(headers, h)
		}
	}
	r.Headers = headers
	return r
}
func TestGolden(t *testing.T) {
	for _, v := range vectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			p, r, key, params := setup(t, v)
			base, input, err := p.SignatureBase(r, params)
			if err != nil || base != v.Base || input != v.Input {
				t.Fatal("signature base/input mismatch", err)
			}
			headers, err := p.SignWithParams(r, params, key)
			if err != nil || headers.Signature != v.Signature || headers.SignatureInput != v.Input {
				t.Fatal("golden HMAC mismatch", err)
			}
			verified, err := p.Verify(signed(r, headers), params.KeyID, key, time.Unix(params.Created, 0))
			if err != nil {
				t.Fatal(err)
			}
			if verified.Info().Caller != "my-service" || verified.Info().Leg != v.Label {
				t.Fatal(verified.Info())
			}
			// Original normative tamper vector; URI bytes are never normalized or sorted.
			tampered := r
			_, q, has := strings.Cut(r.RawURI, "?")
			tampered.RawURI = v.Negative.Value
			if has {
				tampered.RawURI += "?" + q
			}
			if _, err = p.Verify(signed(tampered, headers), params.KeyID, key, time.Unix(params.Created, 0)); err != ErrAuth {
				t.Fatal("tampered path accepted")
			}
		})
	}
	b, err := os.ReadFile("../tests/fixtures/protocol/v1/signatures.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Combination struct {
			Lines []string
			Value string `json:"canonical_value"`
		} `json:"rfc_field_combination"`
	}
	if err = json.Unmarshal(b, &corpus); err != nil {
		t.Fatal(err)
	}
	value, err := CanonicalField(corpus.Combination.Lines)
	if err != nil || value != corpus.Combination.Value {
		t.Fatal(value, err)
	}
}

func TestRequestTampering(t *testing.T) {
	for _, v := range vectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			p, r, key, params := setup(t, v)
			r = signed(r, Headers{v.Input, v.Signature})
			now := time.Unix(params.Created, 0)
			for _, mutate := range []func(Request) Request{
				func(r Request) Request { r.Method = "get"; return r },
				func(r Request) Request { r.Authority = "other.example"; return r },
				func(r Request) Request { r.RawURI += "&extra=1"; return r },
				func(r Request) Request { return set(r, "x-outgate-caller-service", "another") },
				func(r Request) Request { return set(r, "x-outgate-target-service", "another") },
				func(r Request) Request { return set(r, "x-outgate-context-headers", `["x-user-id","x-user-roles"]`) },
				func(r Request) Request { return drop(r, "Signature") },
				func(r Request) Request { return drop(r, "Signature-Input") },
				func(r Request) Request { return set(r, "Signature", v.Signature+", other=:AAAA:") },
				func(r Request) Request { return set(r, "x-user-unsigned", "injected") },
				func(r Request) Request {
					r.Headers = append(append([]v1.Header{}, r.Headers...), v1.Header{"X-Outgate-Caller-Service", "my-service"})
					return r
				},
			} {
				changed := mutate(r)
				// A user vector's manifest is already the replacement above; avoid a no-op.
				if sameRequest(changed, r) {
					continue
				}
				if _, err := p.Verify(changed, params.KeyID, key, now); err != ErrAuth {
					t.Fatal("tamper accepted", err)
				}
			}
			if _, err := p.Verify(r, "wrong-key", key, now); err != ErrAuth {
				t.Fatal("key ID mismatch accepted")
			}
			other := append([]byte{}, key...)
			other[0] ^= 1
			if _, err := p.Verify(r, params.KeyID, other, now); err != ErrAuth {
				t.Fatal("wrong key")
			}
		})
	}
}
func sameRequest(a, b Request) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}

func TestTimeAndParams(t *testing.T) {
	v := vectors(t)[0]
	p, r, key, params := setup(t, v)
	r = signed(r, Headers{v.Input, v.Signature})
	for _, offset := range []time.Duration{-30*time.Second - time.Nanosecond, -30 * time.Second, 0, 90 * time.Second, 90*time.Second + time.Nanosecond} {
		_, err := p.Verify(r, params.KeyID, key, time.Unix(params.Created, 0).Add(offset))
		valid := offset >= -30*time.Second && offset <= 90*time.Second
		if (err == nil) != valid {
			t.Fatal(offset, err)
		}
	}
	for _, mutate := range []func(*Params){
		func(p *Params) { p.Created = -1 }, func(p *Params) { p.Created = maxTimestamp }, func(p *Params) { p.Expires++ }, func(p *Params) { p.Nonce += "=" }, func(p *Params) { p.Nonce = "AAAAAAAAAAAAAAAAAAAAAB" }, func(p *Params) { p.KeyID = "" }, func(p *Params) { p.KeyID = "bad\"key" }, func(p *Params) { p.KeyID = "bad\\key" }, func(p *Params) { p.KeyID = "bad\nkey" }, func(p *Params) { p.KeyID = strings.Repeat("a", 129) },
	} {
		bad := params
		mutate(&bad)
		if _, _, err := p.SignatureBase(drop(drop(r, "Signature"), "Signature-Input"), bad); err != ErrAuth {
			t.Fatal("invalid params")
		}
	}
}

// This fake tests the interface contract, not durable SQL or production replay.
type fakeStore struct {
	mu       sync.Mutex
	entries  map[ReplayKey]time.Time
	capacity int
	calls    int
	failure  error
}

func (s *fakeStore) Reserve(ctx context.Context, r Reservation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.failure != nil {
		return s.failure
	}
	if _, ok := s.entries[r.Key]; ok {
		return ErrReplay
	}
	if len(s.entries) >= s.capacity {
		return errors.New("private storage failure")
	}
	s.entries[r.Key] = r.RetainUntil
	return nil
}
func TestReplayAtomicReservation(t *testing.T) {
	v := vectors(t)[0]
	p, r, key, params := setup(t, v)
	now := time.Unix(params.Created, 0)
	verified, err := p.Verify(signed(r, Headers{v.Input, v.Signature}), params.KeyID, key, now)
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{entries: map[ReplayKey]time.Time{}, capacity: 1}
	var wg sync.WaitGroup
	success := make(chan bool, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := verified.Reserve(context.Background(), store, "gateway-1", now)
			if err != nil && err != ErrReplay {
				t.Error(err)
			}
			success <- err == nil
		}()
	}
	wg.Wait()
	close(success)
	n := 0
	for ok := range success {
		if ok {
			n++
		}
	}
	if n != 1 {
		t.Fatal("multiple reservations", n)
	}
	for k, until := range store.entries {
		if k.Leg != Call || k.Namespace != "gateway-1" || k.Caller != "my-service" || k.KeyID != params.KeyID || k.Nonce != params.Nonce || !until.Equal(time.Unix(params.Expires+30, 0)) {
			t.Fatal("wrong replay identity/retention")
		}
	}
	if err := verified.Reserve(context.Background(), store, "gateway-2", now); err != ErrReplayUnavailable {
		t.Fatal("capacity must fail closed", err)
	}
	before := store.calls
	if err := verified.Reserve(context.Background(), store, "gateway-1", time.Unix(params.Expires+31, 0)); err != ErrAuth || store.calls != before {
		t.Fatal("late reserve touched store")
	}
	if err := (Verified{}).Reserve(context.Background(), store, "gateway-1", now); err != ErrAuth {
		t.Fatal("unverified reserve")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verified.Reserve(ctx, store, "gateway-1", now); err != ErrReplayUnavailable || store.calls != before {
		t.Fatal("cancelled reserve")
	}
}

func TestStrictMetadataAndContext(t *testing.T) {
	v := vectors(t)[1]
	p, r, key, params := setup(t, v)
	invalid := []Request{
		set(r, "x-outgate-context-headers", `["x-user-roles","x-user-id"]`),
		set(r, "x-outgate-context-headers", `["x-user-id","x-user-id","x-user-roles"]`),
		set(r, "x-outgate-context-headers", `[ "x-user-id", "x-user-roles" ]`),
		set(r, "x-outgate-context-headers", `["X-User-ID","x-user-roles"]`),
		set(r, "x-outgate-context-headers", `["x-user-id"]`),
		set(r, "x-outgate-context-headers", `[null]`),
		set(r, "x-outgate-context-headers", `null`),
		set(r, "x-outgate-context-headers", `[]`),
		set(r, "x-user-roles", `[null]`), set(r, "x-user-roles", `[{}]`), set(r, "x-user-roles", `["\ud800"]`), set(r, "x-user-roles", `["\u0000"]`),
		set(r, "x-user-roles", `["`+strings.Repeat("a", 65)+`"]`),
		set(r, "x-user-roles", `["`+strings.Repeat("a\",\"", 32)+`a"]`),
		set(r, "x-user-id", strings.Repeat("a", 129)), set(r, "x-user-id", " user"), set(r, "x-user-id", "user "), set(r, "x-user-id", "a\tb"), set(r, "x-user-id", "é"),
		set(r, "x-outgate-expected-route-revision", "01"), set(r, "x-outgate-expected-route-revision", "0"), set(r, "x-outgate-expected-route-revision", "18446744073709551616"),
		set(r, "Host", "other.example"), set(r, "x-outgate-unknown", "injected"), set(r, "x-tunnel-instance", "injected"),
	}
	bad := r
	bad.Headers = append(append([]v1.Header{}, r.Headers...), v1.Header{"X-User-ID", "user-1"})
	invalid = append(invalid, bad)
	for _, changed := range invalid {
		if _, err := p.SignWithParams(changed, params, key); err != ErrAuth {
			t.Fatal("invalid metadata/context accepted")
		}
	}
	for _, uri := range []string{"https://other/path", "//other/path", "/a#fragment", "/a%2fb", "/%2e%2e", "/a//b", "/a?x=%", "/a?x= ", "/" + strings.Repeat("a", 8192)} {
		changed := r
		changed.RawURI = uri
		if _, err := p.SignWithParams(changed, params, key); err != ErrAuth {
			t.Fatal("ambiguous URI accepted")
		}
	}
	allowed := set(r, "x-user-roles", `["\u00e9","reader"]`)
	if _, err := p.SignWithParams(allowed, params, key); err != nil {
		t.Fatal("ASCII encoded Unicode role rejected", err)
	}
}

func TestAttributesAndProductionFields(t *testing.T) {
	v := vectors(t)[3]
	_, r, key, params := setup(t, v)
	names := []string{"x-user-tenant-id"}
	p, err := New(Config{Leg: Gateway, AttributeHeaders: names})
	if err != nil {
		t.Fatal(err)
	}
	names[0] = "mutated" // Profile must own its immutable allowlist.
	r = set(r, "x-outgate-context-headers", `["x-user-id","x-user-roles","x-user-tenant-id"]`)
	r = set(r, "x-user-tenant-id", "tenant")
	h, err := p.SignWithParams(r, params, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Verify(signed(r, h), params.KeyID, key, time.Unix(params.Created, 0)); err != nil {
		t.Fatal(err)
	}
	for _, changed := range []Request{drop(r, "x-outgate-user-assertion"), drop(r, "x-outgate-hop-limit"), drop(r, "x-outgate-deployment-grant-id"), drop(r, "x-tunnel-instance"), drop(r, "x-tunnel-version"), drop(r, "x-forwarded-prefix"), set(r, "x-outgate-hop-limit", "0"), set(r, "x-outgate-hop-limit", "9"), set(r, "x-outgate-hop-limit", "08"), set(r, "x-user-tenant-id", strings.Repeat("a", 1025)), set(r, "x-forwarded-prefix", "/bad/../path")} {
		if _, err = p.SignWithParams(changed, params, key); err != ErrAuth {
			t.Fatal("required production/binding field accepted")
		}
	}
	dev, r, key, params := setup(t, vectors(t)[0])
	if _, err = dev.SignWithParams(set(r, "x-outgate-user-assertion", "unexpected"), params, key); err != ErrAuth {
		t.Fatal("unsigned assertion")
	}
	prod, err := New(Config{Leg: Call})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = prod.SignWithParams(r, params, key); err != ErrAuth {
		t.Fatal("production default bypassed")
	}
	for _, name := range []string{"Host", "host", "x-user-id", "signature", "authorization", "cookie", "connection", "proxy-authorization", "x-outgate-caller-service", "x-tunnel-instance", "x-forwarded-prefix"} {
		if _, err = New(Config{Leg: Call, AttributeHeaders: []string{name}}); err != ErrAuth {
			t.Fatal("reserved allowlist name accepted", name)
		}
	}
}

func TestStructuredFieldsRepresentationsAndRejections(t *testing.T) {
	v := vectors(t)[0]
	p, r, key, params := setup(t, v)
	now := time.Unix(params.Created, 0)
	valid := []Headers{
		{" \t" + strings.ReplaceAll(strings.ReplaceAll(v.Input, "(\"", "(  \""), "\" \"", "\"   \"") + "\t ", " " + v.Signature + "\t"},
		{strings.ReplaceAll(v.Input, ";", "; "), strings.TrimSuffix(v.Signature, "=:") + ":"},
		{strings.Replace(v.Input, "created=1700000000", "created=01700000000", 1), v.Signature},
	}
	for _, h := range valid {
		if _, err := p.Verify(signed(r, h), params.KeyID, key, now); err != nil {
			t.Fatal("RFC whitespace/padding/integer form rejected", err)
		}
	}
	for _, input := range []string{
		v.Input + ", other=(\"@method\")", v.Input + ";created=1700000000", strings.Replace(v.Input, ";created=1700000000;expires=1700000060", ";expires=1700000060;created=1700000000", 1),
		strings.Replace(v.Input, "created=1700000000", "created=1.7", 1), strings.Replace(v.Input, "created=1700000000", "created=9999999999999999", 1),
		strings.Replace(v.Input, "hmac-sha256", "rsa-pss-sha512", 1), strings.Replace(v.Input, `"@method"`, `"@method";req`, 1), strings.Replace(v.Input, `"@method"`, `"@method" "@method"`, 1),
		strings.Replace(v.Input, `"@method"`, `"@method\q"`, 1), strings.Replace(v.Input, `"@method"`, `"@method\"`, 1), strings.Repeat("a", 32769), "", v.Input + "\n",
	} {
		if _, err := p.Verify(signed(r, Headers{input, v.Signature}), params.KeyID, key, now); err != ErrAuth {
			t.Fatal("malformed signature input")
		}
	}
	for _, signature := range []string{v.Signature + ";x=1", strings.Replace(v.Signature, "outgatecall", "outgategateway", 1), "outgatecall=:AA==:", "outgatecall=:" + strings.Repeat("_", 43) + ":", v.Signature + ", " + v.Signature} {
		if _, err := p.Verify(signed(r, Headers{v.Input, signature}), params.KeyID, key, now); err != ErrAuth {
			t.Fatal("invalid signature field")
		}
	}
	for _, name := range []string{"signature", "signature-input"} {
		signedRequest := signed(r, Headers{v.Input, v.Signature})
		value := v.Signature
		if name == "signature-input" {
			value = v.Input
		}
		signedRequest.Headers = append(signedRequest.Headers, v1.Header{strings.ToUpper(name), value})
		if _, err := p.Verify(signedRequest, params.KeyID, key, now); err != ErrAuth {
			t.Fatal("duplicate signature field")
		}
	}
}

func TestHeaderBoundsAndFreshSigning(t *testing.T) {
	v := vectors(t)[0]
	p, r, key, params := setup(t, v)
	if _, err := p.SignWithParams(r, params, key[:31]); err != ErrAuth {
		t.Fatal("short secret")
	}
	for _, h := range []v1.Header{{"x", "a\r\nb"}, {"x", "\x00"}, {strings.Repeat("x", 129), "a"}, {"x", strings.Repeat("x", 32769)}} {
		changed := r
		changed.Headers = append(append([]v1.Header{}, r.Headers...), h)
		if _, err := p.SignWithParams(changed, params, key); err != ErrAuth {
			t.Fatal("header bounds")
		}
	}
	changed := r
	changed.Headers = make([]v1.Header, 257)
	if _, err := p.SignWithParams(changed, params, key); err != ErrAuth {
		t.Fatal("header count")
	}
	h, err := p.Sign(r, params.KeyID, key, time.Unix(params.Created, 0))
	if err != nil {
		t.Fatal(err)
	}
	h2, err := p.Sign(r, params.KeyID, key, time.Unix(params.Created, 0))
	if err != nil || h == h2 {
		t.Fatal("fresh nonce missing")
	}
	if _, err = p.Verify(signed(r, h), params.KeyID, key, time.Unix(params.Created, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Sign(signed(r, h), params.KeyID, key, time.Unix(params.Created, 0)); err != ErrAuth {
		t.Fatal("silently replaced signature")
	}
	for _, lines := range [][]string{{" a\t", "b "}, {"a\r\n b"}, {"a\x7f"}, {strings.Repeat("a", 32769)}} {
		value, err := CanonicalField(lines)
		if len(lines) == 2 {
			if err != nil || value != "a, b" {
				t.Fatal(value, err)
			}
		} else if err != ErrAuth {
			t.Fatal("unsafe field canonicalization")
		}
	}
}

func FuzzSignatureInput(f *testing.F) {
	for _, v := range vectors(f) {
		f.Add(v.Input)
	}
	f.Add("")
	f.Fuzz(func(t *testing.T, input string) {
		parsed, err := ParseSignatureInput(input)
		if err != nil {
			if err != ErrAuth {
				t.Fatal(err)
			}
			return
		}
		canonical := parsed.Label + "=" + serialize(parsed.Components, parsed.Params)
		again, err := ParseSignatureInput(canonical)
		if err != nil || !sameNames(parsed.Components, again.Components) || parsed.Params != again.Params {
			t.Fatal("parser round trip")
		}
	})
}
func FuzzVerifyProfile(f *testing.F) {
	vv := vectors(f)
	for i, v := range vv {
		f.Add(uint8(i), v.Input, v.Signature, v.RawURI)
	}
	v := vv[0]
	f.Add(uint8(0), v.Input, v.Signature, "/%D1%8F?x=1+2&x=%2f")
	f.Add(uint8(0), v.Input, v.Signature, "/%2f")
	f.Add(uint8(0), v.Input, v.Signature+"\r\n", v.RawURI)
	f.Fuzz(func(t *testing.T, seed uint8, input, signature, uri string) {
		v := vv[int(seed)%len(vv)]
		p, r, key, params := setup(t, v)
		r.RawURI = uri
		_, err := p.Verify(signed(r, Headers{input, signature}), params.KeyID, key, time.Unix(params.Created, 0))
		if err != nil && err != ErrAuth {
			t.Fatal(err)
		}
	})
}

func TestValidMACWithWrongComponentProfileIsRejected(t *testing.T) {
	v := vectors(t)[1]
	p, r, key, params := setup(t, v)
	for _, replacement := range []string{`"@authority" "@method"`, `"@method"`} {
		input := strings.Replace(v.Input, `"@method" "@authority"`, replacement, 1)
		lines := strings.Split(v.Base, "\n")
		if replacement == `"@method"` {
			lines = append(lines[:1], lines[2:]...)
		} else {
			lines[0], lines[1] = lines[1], lines[0]
		}
		lines[len(lines)-1] = `"@signature-params": ` + strings.TrimPrefix(input, Call+"=")
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(strings.Join(lines, "\n")))
		headers := Headers{input, Call + "=:" + base64.StdEncoding.EncodeToString(mac.Sum(nil)) + ":"}
		if _, err := p.Verify(signed(r, headers), params.KeyID, key, time.Unix(params.Created, 0)); err != ErrAuth {
			t.Fatal("valid MAC bypassed fixed component coverage")
		}
	}
}

func TestContextBoundaries(t *testing.T) {
	v := vectors(t)[1]
	p, r, key, params := setup(t, v)
	for _, n := range []int{32, 33} {
		roles := make([]string, n)
		for i := range roles {
			roles[i] = strings.Repeat("r", 64)
		}
		encoded, _ := json.Marshal(roles)
		changed := set(set(r, "x-user-roles", string(encoded)), "x-user-id", strings.Repeat("u", 128))
		if _, err := p.SignWithParams(changed, params, key); (err == nil) != (n == 32) {
			t.Fatal("role count/length boundary", n, err)
		}
	}
	// Application headers may repeat; strict identity headers may not.
	repeated := r
	repeated.Headers = append(append([]v1.Header{}, r.Headers...), v1.Header{"X-Example", "a"}, v1.Header{"x-example", "b"})
	if _, err := p.SignWithParams(repeated, params, key); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"/api?q=b&q=a", "/api?q=a&q=b", "/api?x=%2f", "/api?x=%2F", "/api", "/api?"} {
		changed := r
		changed.RawURI = query
		h, err := p.SignWithParams(changed, params, key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = p.Verify(signed(changed, h), params.KeyID, key, time.Unix(params.Created, 0)); err != nil {
			t.Fatal(err)
		}
	}
}

type storeFunc func(context.Context, Reservation) error

func (f storeFunc) Reserve(ctx context.Context, r Reservation) error { return f(ctx, r) }
func TestReplayFailureAndInclusiveRetention(t *testing.T) {
	v := vectors(t)[0]
	p, r, key, params := setup(t, v)
	now := time.Unix(params.Created, 0)
	verified, err := p.Verify(signed(r, Headers{v.Input, v.Signature}), params.KeyID, key, now)
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{entries: map[ReplayKey]time.Time{}, capacity: 8}
	until := time.Unix(params.Expires+30, 0)
	if err := verified.Reserve(context.Background(), store, "one", until); err != nil {
		t.Fatal("inclusive boundary rejected", err)
	}
	calls := store.calls
	if err := verified.Reserve(context.Background(), store, "two", until.Add(time.Nanosecond)); err != ErrAuth || store.calls != calls {
		t.Fatal("expired reservation reached backend")
	}
	if err := verified.Reserve(context.Background(), nil, "one", now); err != ErrReplayUnavailable {
		t.Fatal(err)
	}
	failed := storeFunc(func(context.Context, Reservation) error { return errors.New("sensitive backend details") })
	if err := verified.Reserve(context.Background(), failed, "one", now); err != ErrReplayUnavailable {
		t.Fatal("backend detail leaked", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	committed := false
	cancelling := storeFunc(func(context.Context, Reservation) error { committed = true; cancel(); return nil })
	if err := verified.Reserve(ctx, cancelling, "one", now); err != ErrReplayUnavailable || !committed {
		t.Fatal("uncertain commit handling", err)
	}
}
func TestReplayNamespaces(t *testing.T) {
	store := &fakeStore{entries: map[ReplayKey]time.Time{}, capacity: 16}
	vv := vectors(t)
	for _, v := range []vector{vv[0], vv[2]} {
		p, r, key, params := setup(t, v)
		params.Nonce = "AAAAAAAAAAAAAAAAAAAAAA"
		for _, caller := range []string{"caller-a", "caller-b"} {
			r = set(r, "x-outgate-caller-service", caller)
			for _, keyID := range []string{"key-a", "key-b"} {
				params.KeyID = keyID
				h, err := p.SignWithParams(r, params, key)
				if err != nil {
					t.Fatal(err)
				}
				verified, err := p.Verify(signed(r, h), keyID, key, time.Unix(params.Created, 0))
				if err != nil {
					t.Fatal(err)
				}
				for _, namespace := range []string{"verifier-a", "verifier-b"} {
					if err = verified.Reserve(context.Background(), store, namespace, time.Unix(params.Created, 0)); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
	}
	if len(store.entries) != 16 {
		t.Fatal("namespace collision", len(store.entries))
	}
}

func TestSignerReservesGeneratedHeaderSpace(t *testing.T) {
	v := vectors(t)[0]
	p, r, key, params := setup(t, v)
	h, err := p.SignWithParams(r, params, key)
	if err != nil {
		t.Fatal(err)
	}
	total := 2
	for _, line := range signed(r, h).Headers {
		total += len(line[0]) + len(line[1]) + 4
	}
	filler := maxHeaders - total - len("filler") - 4
	for _, extra := range []int{0, 1} {
		changed := set(r, "filler", strings.Repeat("x", filler+extra))
		h, err := p.SignWithParams(changed, params, key)
		if extra == 0 {
			if err != nil {
				t.Fatal("exact output header bound", err)
			}
			if _, err = p.Verify(signed(changed, h), params.KeyID, key, time.Unix(params.Created, 0)); err != nil {
				t.Fatal(err)
			}
		} else if err != ErrAuth {
			t.Fatal("generated signature fields exceeded field section budget")
		}
	}
	for _, n := range []int{254, 255} {
		changed := r
		changed.Headers = append([]v1.Header{}, r.Headers...)
		for len(changed.Headers) < n {
			changed.Headers = append(changed.Headers, v1.Header{"x-extra", ""})
		}
		if _, err := p.SignWithParams(changed, params, key); (err == nil) != (n == 254) {
			t.Fatal("output header count", n, err)
		}
	}
}

func TestRFCAuthorityNormalization(t *testing.T) {
	v := vectors(t)[0]
	p, r, key, params := setup(t, v)
	for _, tt := range []struct{ scheme, host, want string }{
		{"https", "EXAMPLE.test:443", "example.test"}, {"http", "EXAMPLE.test:80", "example.test"},
		{"https", "EXAMPLE.test:80", "example.test:80"}, {"http", "EXAMPLE.test:443", "example.test:443"},
		{"https", "[2001:DB8::1]:443", "[2001:db8::1]"}, {"https", "EXAMPLE.test:0443", "example.test"},
	} {
		changed := r
		changed.Scheme = tt.scheme
		changed.Authority = tt.host
		base, _, err := p.SignatureBase(changed, params)
		if err != nil || !strings.Contains(base, `"@authority": `+tt.want+"\n") {
			t.Fatal("RFC authority", tt, err)
		}
		h, err := p.SignWithParams(changed, params, key)
		if err != nil {
			t.Fatal(err)
		}
		changed.Authority = tt.want
		if _, err = p.Verify(signed(changed, h), params.KeyID, key, time.Unix(params.Created, 0)); err != nil {
			t.Fatal(err)
		}
	}
	changed := r
	changed.Scheme = ""
	if _, err := p.SignWithParams(changed, params, key); err != ErrAuth {
		t.Fatal("implicit scheme")
	}
}
