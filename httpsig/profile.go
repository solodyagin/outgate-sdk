// Package httpsig implements the fixed Outgate RFC 9421 HMAC profile, not a
// general HTTP signature engine. It does not authenticate TLS/JWT/grants,
// authorize routes, dispatch requests or read bodies.
package httpsig

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

const (
	Call               = "outgatecall"
	Gateway            = "outgategateway"
	maxHeaders         = 32768
	maxTimestamp int64 = 253402300799
)

var ErrAuth = errors.New("outgate: signature authentication failed")

// Request is the original public request before strip/rewrite. Authority is the
// application Host, never the tunnel address. Headers preserve repeated lines.
// No body is accepted or retained by this package.
type Request struct {
	Method, Scheme, Authority, RawURI string
	Headers                           []v1.Header
}
type Config struct {
	Leg              string
	Development      bool
	AttributeHeaders []string
}
type Profile struct {
	leg         string
	development bool
	attributes  map[string]bool
}
type Params struct {
	Created, Expires int64
	Nonce, KeyID     string
}
type Headers struct{ SignatureInput, Signature string }

// New defaults to production and copies the optional attribute allowlist.
func New(c Config) (*Profile, error) {
	if c.Leg != Call && c.Leg != Gateway || len(c.AttributeHeaders) > 16 {
		return nil, ErrAuth
	}
	p := &Profile{leg: c.Leg, development: c.Development, attributes: make(map[string]bool, len(c.AttributeHeaders))}
	for _, name := range c.AttributeHeaders {
		if len(name) > 128 || !fieldName(name) || name != strings.ToLower(name) || reserved(name) || name == "x-user-id" || name == "x-user-roles" || p.attributes[name] {
			return nil, ErrAuth
		}
		p.attributes[name] = true
	}
	return p, nil
}

// NewNonce returns canonical base64url of 16 cryptographically random bytes.
func NewNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", ErrAuth
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Sign generates a new nonce and a 60-second signature. It does not mutate r.
func (p *Profile) Sign(r Request, keyID string, secret []byte, now time.Time) (Headers, error) {
	if now.IsZero() {
		return Headers{}, ErrAuth
	}
	nonce, err := NewNonce()
	if err != nil {
		return Headers{}, err
	}
	return p.SignWithParams(r, Params{Created: now.Unix(), Expires: now.Unix() + 60, Nonce: nonce, KeyID: keyID}, secret)
}

// SignWithParams is deterministic; production callers must supply a fresh random
// nonce for each request and must never retry a business operation implicitly.
func (p *Profile) SignWithParams(r Request, params Params, secret []byte) (Headers, error) {
	if len(secret) < 32 || len(r.Headers) > 254 {
		return Headers{}, ErrAuth
	}
	for _, h := range r.Headers {
		if strings.EqualFold(h[0], "signature") || strings.EqualFold(h[0], "signature-input") {
			return Headers{}, ErrAuth
		}
	}
	base, input, err := p.SignatureBase(r, params)
	if err != nil {
		return Headers{}, err
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(base))
	out := Headers{SignatureInput: input, Signature: p.leg + "=:" + base64.StdEncoding.EncodeToString(mac.Sum(nil)) + ":"}
	// The generated fields must also fit the bounded HTTP field section.
	total := 2 + len("signature-input") + len(out.SignatureInput) + 4 + len("signature") + len(out.Signature) + 4
	for _, h := range r.Headers {
		total += len(h[0]) + len(h[1]) + 4
	}
	if total > maxHeaders {
		return Headers{}, ErrAuth
	}
	return out, nil
}

// SignatureBase checks the exact profile and returns RFC signature base and
// canonical Signature-Input. It authenticates nothing and never reads a body.
func (p *Profile) SignatureBase(r Request, params Params) (string, string, error) {
	if p == nil || (p.leg != Call && p.leg != Gateway) || !validParams(params) {
		return "", "", ErrAuth
	}
	names, values, err := p.components(r)
	if err != nil {
		return "", "", err
	}
	inner := serialize(names, params)
	var base strings.Builder
	for i, name := range names {
		if i > 0 {
			base.WriteByte('\n')
		}
		base.WriteString(`"` + name + `": ` + values[i])
	}
	base.WriteString("\n\"@signature-params\": " + inner)
	return base.String(), p.leg + "=" + inner, nil
}

// Verified proves profile/HMAC/time checks only. Its private fields cannot be
// constructed from unverified peer data. Identity/issuer/route/revision/binding
// authorization MUST precede Reserve and dispatch. No trusted context is installed.
type Verified struct {
	valid                             bool
	leg, caller, target, keyID, nonce string
	created, expires                  int64
}
type Info struct {
	Leg, Caller, Target, KeyID, Nonce string
	Created, Expires                  int64
}

func (v Verified) Info() Info {
	return Info{Leg: v.leg, Caller: v.caller, Target: v.target, KeyID: v.keyID, Nonce: v.nonce, Created: v.created, Expires: v.expires}
}

// Verify uses a key selected from pinned leg/caller configuration after transport
// identity checks. expectedKeyID prevents a valid MAC from bypassing key selection.
// It performs no replay I/O; an accepted MAC alone is insufficient for dispatch.
func (p *Profile) Verify(r Request, expectedKeyID string, secret []byte, now time.Time) (Verified, error) {
	if p == nil || len(secret) < 32 || now.IsZero() {
		return Verified{}, ErrAuth
	}
	fields, err := readHeaders(r.Headers)
	if err != nil {
		return Verified{}, err
	}
	input, ok := single(fields, "signature-input")
	if !ok {
		return Verified{}, ErrAuth
	}
	parsed, err := ParseSignatureInput(input)
	if err != nil || parsed.Label != p.leg || parsed.Params.KeyID != expectedKeyID || !validTime(parsed.Params, now) {
		return Verified{}, ErrAuth
	}
	names, _, err := p.components(r)
	if err != nil || !sameNames(names, parsed.Components) {
		return Verified{}, ErrAuth
	}
	base, _, err := p.SignatureBase(r, parsed.Params)
	if err != nil {
		return Verified{}, err
	}
	value, ok := single(fields, "signature")
	if !ok {
		return Verified{}, ErrAuth
	}
	signature, err := parseSignature(value, p.leg)
	if err != nil {
		return Verified{}, err
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(base))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return Verified{}, ErrAuth
	}
	return Verified{valid: true, leg: p.leg, caller: fields["x-outgate-caller-service"][0], target: fields["x-outgate-target-service"][0], keyID: parsed.Params.KeyID, nonce: parsed.Params.Nonce, created: parsed.Params.Created, expires: parsed.Params.Expires}, nil
}

func (p *Profile) components(r Request) ([]string, []string, error) {
	scheme := strings.ToLower(r.Scheme)
	if scheme != "https" && scheme != "http" || !p.development && scheme != "https" {
		return nil, nil, ErrAuth
	}
	// Reuse bounded metadata/path validation without changing public URI bytes.
	metadata := v1.RequestStart{Type: "request_start", StreamID: 1, Method: r.Method, Host: r.Authority, RawRequestURI: r.RawURI, Headers: []v1.Header{}}
	if metadata.Validate() != nil {
		return nil, nil, ErrAuth
	}
	fields, err := readHeaders(r.Headers)
	if err != nil {
		return nil, nil, err
	}
	get := func(name string) (string, bool) {
		value, ok := single(fields, name)
		return value, ok && identityValue(value)
	}
	caller, ok := get("x-outgate-caller-service")
	if !ok || !identifier(caller, 64) {
		return nil, nil, ErrAuth
	}
	target, ok := get("x-outgate-target-service")
	if !ok || !identifier(target, 64) {
		return nil, nil, ErrAuth
	}
	manifest, ok := get("x-outgate-context-headers")
	if !ok {
		return nil, nil, ErrAuth
	}
	users, err := compactStrings(manifest, 18, 128)
	if err != nil || len(users) > 18 {
		return nil, nil, ErrAuth
	}
	allowed := map[string]bool{"x-user-id": true, "x-user-roles": true}
	for n := range p.attributes {
		allowed[n] = true
	}
	present := make(map[string]bool, len(users))
	for i, name := range users {
		if !allowed[name] || i > 0 && name <= users[i-1] {
			return nil, nil, ErrAuth
		}
		present[name] = true
	}
	if len(users) > 0 && (!present["x-user-id"] || !present["x-user-roles"]) {
		return nil, nil, ErrAuth
	}
	path, query, hasQuery := strings.Cut(r.RawURI, "?")
	if !hasQuery {
		query = ""
	}
	names := []string{"@method", "@authority", "@path", "@query", "x-outgate-caller-service", "x-outgate-target-service", "x-outgate-context-headers"}
	values := []string{r.Method, canonicalAuthority(r.Authority, scheme), path, "?" + query, caller, target, manifest}
	appendField := func(name string) bool {
		value, ok := get(name)
		if !ok {
			return false
		}
		names = append(names, name)
		values = append(values, value)
		return true
	}
	expected := map[string]bool{"x-outgate-caller-service": true, "x-outgate-target-service": true, "x-outgate-context-headers": true}
	if _, exists := fields["x-outgate-expected-route-revision"]; exists {
		if !appendField("x-outgate-expected-route-revision") || !positiveDecimal(values[len(values)-1]) {
			return nil, nil, ErrAuth
		}
		expected["x-outgate-expected-route-revision"] = true
	}
	if !p.development {
		for _, name := range []string{"x-outgate-hop-limit", "x-outgate-deployment-grant-id"} {
			if !appendField(name) {
				return nil, nil, ErrAuth
			}
			expected[name] = true
		}
		hop := fields["x-outgate-hop-limit"][0]
		if len(hop) != 1 || hop[0] < '1' || hop[0] > '8' {
			return nil, nil, ErrAuth
		}
		if len(users) > 0 {
			if !appendField("x-outgate-user-assertion") {
				return nil, nil, ErrAuth
			}
			expected["x-outgate-user-assertion"] = true
		}
	}
	for _, name := range users {
		if !appendField(name) {
			return nil, nil, ErrAuth
		}
		expected[name] = true
	}
	if len(users) > 0 {
		if _, err := compactStrings(fields["x-user-roles"][0], 32, 64); err != nil {
			return nil, nil, ErrAuth
		}
	}
	if len(users) > 0 {
		if len(fields["x-user-id"][0]) > 128 {
			return nil, nil, ErrAuth
		}
		contextBytes := len(manifest) + len("x-outgate-context-headers") + 4
		for _, name := range users {
			value := fields[name][0]
			if name != "x-user-id" && name != "x-user-roles" && len(value) > 1024 {
				return nil, nil, ErrAuth
			}
			contextBytes += len(name) + len(value) + 4
		}
		if contextBytes > 8192 {
			return nil, nil, ErrAuth
		}
	}

	if p.leg == Gateway {
		for _, name := range []string{"x-tunnel-instance", "x-tunnel-version", "x-forwarded-prefix"} {
			if !appendField(name) {
				return nil, nil, ErrAuth
			}
			expected[name] = true
		}
		if !identifier(fields["x-tunnel-instance"][0], 128) || len(fields["x-tunnel-version"][0]) > 128 || strings.Contains(fields["x-tunnel-version"][0], " ") {
			return nil, nil, ErrAuth
		}
		if _, err := v1.NormalizePrefix(fields["x-forwarded-prefix"][0]); err != nil {
			return nil, nil, ErrAuth
		}
	}
	for name := range fields {
		if (strings.HasPrefix(name, "x-outgate-") || strings.HasPrefix(name, "x-user-") || strings.HasPrefix(name, "x-tunnel-") || name == "x-forwarded-prefix" || allowed[name]) && !expected[name] {
			return nil, nil, ErrAuth
		}
	}
	return names, values, nil
}

func readHeaders(headers []v1.Header) (map[string][]string, error) {
	if len(headers) > 256 {
		return nil, ErrAuth
	}
	total := 2
	// First pass bounds the entire field section before allocating a map.
	for _, h := range headers {
		if len(h[0]) > 128 || len(h[1]) > maxHeaders || !fieldName(h[0]) || !utf8.ValidString(h[1]) {
			return nil, ErrAuth
		}
		total += len(h[0]) + len(h[1]) + 4
		if total > maxHeaders {
			return nil, ErrAuth
		}
		for i := 0; i < len(h[1]); i++ {
			c := h[1][i]
			if c < 32 && c != '\t' || c == 127 {
				return nil, ErrAuth
			}
		}
	}
	fields := make(map[string][]string, len(headers))
	for _, h := range headers {
		name := strings.ToLower(h[0])
		fields[name] = append(fields[name], h[1])
	}
	// Host is explicit, never a second authority in the header list.
	if _, ok := fields["host"]; ok {
		return nil, ErrAuth
	}
	return fields, nil
}
func single(m map[string][]string, name string) (string, bool) {
	v := m[name]
	if len(v) != 1 {
		return "", false
	}
	return v[0], true
}
func identityValue(s string) bool {
	if len(s) == 0 || s[0] == ' ' || s[len(s)-1] == ' ' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 32 || s[i] > 126 {
			return false
		}
	}
	return true
}
func fieldName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			return false
		}
	}
	return true
}
func identifier(s string, max int) bool {
	if len(s) < 1 || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func positiveDecimal(s string) bool {
	n, err := strconv.ParseUint(s, 10, 64)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == s
}
func reserved(s string) bool {
	return strings.HasPrefix(s, "x-outgate-") || strings.HasPrefix(s, "x-tunnel-") || strings.HasPrefix(s, "@") || s == "x-forwarded-prefix" || s == "host" || s == "signature" || s == "signature-input" || s == "authorization" || s == "cookie" || s == "connection" || s == "upgrade" || s == "transfer-encoding" || s == "content-length" || s == "trailer" || s == "te" || s == "keep-alive" || s == "proxy-connection" || s == "proxy-authenticate" || s == "proxy-authorization"
}
func compactStrings(value string, maxCount, maxLen int) ([]string, error) {
	if len(value) > 8192 || v1.ValidateControlJSON([]byte(`{"v":`+value+`}`)) != nil {
		return nil, ErrAuth
	}
	var compact bytes.Buffer
	if json.Compact(&compact, []byte(value)) != nil || compact.String() != value {
		return nil, ErrAuth
	}
	d := json.NewDecoder(strings.NewReader(value))
	token, err := d.Token()
	if err != nil || token != json.Delim('[') {
		return nil, ErrAuth
	}
	result := make([]string, 0, maxCount)
	for d.More() {
		if len(result) >= maxCount {
			return nil, ErrAuth
		}
		token, err := d.Token()
		text, ok := token.(string)
		if err != nil || !ok || len(text) > maxLen || !utf8.ValidString(text) {
			return nil, ErrAuth
		}
		for _, c := range text {
			if c < 32 || c == 127 {
				return nil, ErrAuth
			}
		}
		result = append(result, text)
	}
	token, err = d.Token()
	if err != nil || token != json.Delim(']') {
		return nil, ErrAuth
	}
	return result, nil
}

func sameNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Host is validated before this derivation. RFC 9421 §2.2.3 lowercases the
// hostname and omits the scheme's default port without changing the request.
func canonicalAuthority(authority, scheme string) string {
	lower := strings.ToLower(authority)
	host, port, err := net.SplitHostPort(lower)
	if err != nil {
		return lower
	}
	n, _ := strconv.ParseUint(port, 10, 16)
	if scheme == "https" && n == 443 || scheme == "http" && n == 80 {
		if strings.Contains(host, ":") {
			return "[" + host + "]"
		}
		return host
	}
	return lower
}
