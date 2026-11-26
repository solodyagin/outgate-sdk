// Package delegation verifies the fixed Outgate issuer JWT profile. It does
// not fetch keys, issue assertions, authorize routes or check revocation stores.
package delegation

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

const MaxTokenBytes = 16384

var ErrAssertion = errors.New("outgate: invalid user assertion")
var ErrConfig = errors.New("outgate: invalid delegation config")

type User struct {
	ID         string
	Roles      []string
	Attributes map[string]string
}

// CopyUser validates limits before taking ownership. It authenticates nothing.
func CopyUser(in User) (User, error) {
	if !text(in.ID, 128) || len(in.Roles) > 32 || len(in.Attributes) > 16 {
		return User{}, ErrAssertion
	}
	total := len(in.ID)
	for _, s := range in.Roles {
		if !text(s, 64) {
			return User{}, ErrAssertion
		}
		total += len(s)
	}
	for k, s := range in.Attributes {
		if !name(k, 64) || !text(s, 1024) {
			return User{}, ErrAssertion
		}
		total += len(k) + len(s)
	}
	if total > 8192 {
		return User{}, ErrAssertion
	}
	out := User{ID: in.ID, Roles: append([]string{}, in.Roles...), Attributes: make(map[string]string, len(in.Attributes))}
	for k, s := range in.Attributes {
		out.Attributes[k] = s
	}
	return out, nil
}
func text(s string, max int) bool {
	return len(s) > 0 && len(s) <= max && utf8.ValidString(s) && strings.TrimSpace(s) != "" && !strings.ContainsFunc(s, unicode.IsControl)
}
func name(s string, max int) bool {
	if len(s) == 0 || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	return !strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) })
}

type ClaimMap struct {
	UserID, Roles, SessionID string
	Attributes               map[string]string
}

// KeySnapshot is configured trusted state, never a token-supplied JWK/URL.
// Known keys cease to verify at ValidUntil; snapshots cover at most five minutes.
type KeySnapshot struct {
	Keys                 map[string]*rsa.PublicKey
	LoadedAt, ValidUntil time.Time
}
type Config struct {
	Issuer    string
	Claims    ClaimMap
	Keys      KeySnapshot
	ClockSkew time.Duration
}
type Verifier struct {
	mu     sync.RWMutex
	issuer string
	claims ClaimMap
	keys   KeySnapshot
	skew   time.Duration
}

// Identity is returned only after signature/profile/claims checks. It is not a
// revocation or route authorization result and contains no token/private data.
type Identity struct {
	Issuer, Subject, Actor, Target, KeyID, SessionID, TokenID string
	IssuedAt, NotBefore, ExpiresAt                            time.Time
}
type Verified struct {
	identity Identity
	user     User
	valid    bool
}

func (v Verified) Identity() Identity { return v.identity }
func (v Verified) User() (User, error) {
	if !v.valid {
		return User{}, ErrAssertion
	}
	return CopyUser(v.user)
}

func New(config Config) (*Verifier, error) {
	u, err := url.Parse(config.Issuer)
	if err != nil || !text(config.Issuer, 2048) || strings.ContainsFunc(config.Issuer, unicode.IsSpace) || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery || len(config.Issuer) > 2048 || config.ClockSkew < 0 || config.ClockSkew > 30*time.Second {
		return nil, ErrConfig
	}
	m := config.Claims
	if !name(m.UserID, 128) || !name(m.Roles, 128) || !name(m.SessionID, 128) || m.UserID == m.Roles || m.UserID == m.SessionID || m.Roles == m.SessionID || len(m.Attributes) > 16 {
		return nil, ErrConfig
	}
	attributes := make(map[string]string, len(m.Attributes))
	seen := map[string]bool{m.UserID: true, m.Roles: true, m.SessionID: true}
	for logical, claim := range m.Attributes {
		if !name(logical, 64) || !name(claim, 128) || seen[claim] {
			return nil, ErrConfig
		}
		attributes[logical] = claim
		seen[claim] = true
	}
	m.Attributes = attributes
	keys, err := copyKeys(config.Keys)
	if err != nil {
		return nil, err
	}
	return &Verifier{issuer: config.Issuer, claims: m, keys: keys, skew: config.ClockSkew}, nil
}
func copyKeys(in KeySnapshot) (KeySnapshot, error) {
	if len(in.Keys) == 0 || len(in.Keys) > 32 || in.LoadedAt.IsZero() || !in.ValidUntil.After(in.LoadedAt) || in.ValidUntil.Sub(in.LoadedAt) > 5*time.Minute {
		return KeySnapshot{}, ErrConfig
	}
	out := KeySnapshot{Keys: make(map[string]*rsa.PublicKey, len(in.Keys)), LoadedAt: in.LoadedAt, ValidUntil: in.ValidUntil}
	for id, k := range in.Keys {
		if !name(id, 128) || k == nil || k.N == nil || k.N.Sign() <= 0 || k.N.BitLen() < 2048 || k.N.BitLen() > 8192 || k.N.Bit(0) != 1 || k.E < 3 || k.E > 2147483647 || k.E%2 == 0 {
			return KeySnapshot{}, ErrConfig
		}
		out.Keys[id] = &rsa.PublicKey{N: new(big.Int).Set(k.N), E: k.E}
	}
	return out, nil
}

// ReplaceKeys atomically publishes an owned bounded snapshot. A loader must
// authenticate its configured source; there is no unknown-kid network fallback.
func (v *Verifier) ReplaceKeys(snapshot KeySnapshot) error {
	if v == nil {
		return ErrConfig
	}
	keys, err := copyKeys(snapshot)
	if err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if keys.LoadedAt.Before(v.keys.LoadedAt) {
		return ErrConfig
	}
	v.keys = keys
	return nil
}
func decodePart(s string, max int) ([]byte, error) {
	if len(s) == 0 || base64.RawURLEncoding.DecodedLen(len(s)) > max {
		return nil, ErrAssertion
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != s {
		return nil, ErrAssertion
	}
	return raw, nil
}
func object(b []byte) (map[string]json.RawMessage, error) {
	if v1.ValidateControlJSON(b) != nil {
		return nil, ErrAssertion
	}
	var out map[string]json.RawMessage
	if json.Unmarshal(b, &out) != nil || out == nil {
		return nil, ErrAssertion
	}
	return out, nil
}
func field(fields map[string]json.RawMessage, key string, max int) (string, error) {
	var value string
	if json.Unmarshal(fields[key], &value) != nil || !text(value, max) {
		return "", ErrAssertion
	}
	return value, nil
}
func date(fields map[string]json.RawMessage, key string) (int64, error) {
	var n int64
	if json.Unmarshal(fields[key], &n) != nil || string(fields[key]) == "null" || n < 0 || n > 253402300799 {
		return 0, ErrAssertion
	}
	return n, nil
}
func serviceID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || i > 0 && (c == '_' || c == '-' || c == '.')) {
			return false
		}
	}
	return true
}

func (v *Verifier) Verify(token, caller, target string, now time.Time) (Verified, error) {
	bad := func() (Verified, error) { return Verified{}, ErrAssertion }
	if v == nil || len(token) > MaxTokenBytes || !serviceID(caller) || !serviceID(target) || now.IsZero() {
		return bad()
	}
	head, rest, ok := strings.Cut(token, ".")
	if !ok {
		return bad()
	}
	payload, signature, ok := strings.Cut(rest, ".")
	if !ok || strings.Contains(signature, ".") {
		return bad()
	}
	headerBytes, err := decodePart(head, 1024)
	if err != nil {
		return bad()
	}
	header, err := object(headerBytes)
	if err != nil {
		return bad()
	}
	alg, err := field(header, "alg", 16)
	if err != nil || alg != "RS256" {
		return bad()
	}
	typ, err := field(header, "typ", 64)
	if err != nil || typ != "outgate-delegation+jwt" {
		return bad()
	}
	kid, err := field(header, "kid", 128)
	if err != nil {
		return bad()
	}
	// Critical extensions/unencoded payloads are unsupported. jku/x5u/jwk/x5c
	// never select a key or trigger I/O, regardless of their token values.
	if _, ok := header["crit"]; ok {
		return bad()
	}
	if _, ok := header["b64"]; ok {
		return bad()
	}
	raw, err := decodePart(payload, 10752)
	if err != nil {
		return bad()
	}
	fields, err := object(raw)
	if err != nil {
		return bad()
	}
	sig, err := decodePart(signature, 1024)
	if err != nil {
		return bad()
	}
	v.mu.RLock()
	key := v.keys.Keys[kid]
	fresh := !now.Before(v.keys.LoadedAt) && now.Before(v.keys.ValidUntil)
	v.mu.RUnlock()
	if key == nil || !fresh {
		return bad()
	}
	digest := sha256.Sum256([]byte(head + "." + payload))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig) != nil {
		return bad()
	}
	issuer, err := field(fields, "iss", 2048)
	if err != nil || issuer != v.issuer {
		return bad()
	}
	subject, err := field(fields, "sub", 128)
	if err != nil {
		return bad()
	}
	var audience string
	if json.Unmarshal(fields["aud"], &audience) != nil {
		var audiences []string
		if json.Unmarshal(fields["aud"], &audiences) != nil || len(audiences) != 1 {
			return bad()
		}
		audience = audiences[0]
	}
	if audience != target {
		return bad()
	}
	var actor map[string]json.RawMessage
	if json.Unmarshal(fields["act"], &actor) != nil {
		return bad()
	}
	actorID, err := field(actor, "sub", 64)
	if err != nil || actorID != caller {
		return bad()
	}
	issued, err := date(fields, "iat")
	if err != nil {
		return bad()
	}
	expires, err := date(fields, "exp")
	if err != nil || expires <= issued || expires-issued > 300 {
		return bad()
	}
	notBefore := issued
	if _, exists := fields["nbf"]; exists {
		notBefore, err = date(fields, "nbf")
		if err != nil || notBefore > expires {
			return bad()
		}
	}
	if now.Add(v.skew).Before(time.Unix(issued, 0)) || now.Add(v.skew).Before(time.Unix(notBefore, 0)) || !now.Add(-v.skew).Before(time.Unix(expires, 0)) {
		return bad()
	}
	sid, err := field(fields, "sid", 128)
	if err != nil {
		return bad()
	}
	jti, err := field(fields, "jti", 128)
	if err != nil {
		return bad()
	}
	userID, err := field(fields, v.claims.UserID, 128)
	if err != nil {
		return bad()
	}
	mappedSID, err := field(fields, v.claims.SessionID, 128)
	if err != nil || mappedSID != sid {
		return bad()
	}
	var roles []json.RawMessage
	if json.Unmarshal(fields[v.claims.Roles], &roles) != nil || roles == nil || len(roles) > 32 {
		return bad()
	}
	user := User{ID: userID, Roles: make([]string, 0, len(roles)), Attributes: make(map[string]string)}
	for _, rawRole := range roles {
		var role string
		if json.Unmarshal(rawRole, &role) != nil || !text(role, 64) {
			return bad()
		}
		user.Roles = append(user.Roles, role)
	}
	for logical, claim := range v.claims.Attributes {
		if _, ok := fields[claim]; ok {
			value, err := field(fields, claim, 1024)
			if err != nil {
				return bad()
			}
			user.Attributes[logical] = value
		}
	}
	user, err = CopyUser(user)
	if err != nil {
		return bad()
	}
	return Verified{valid: true, user: user, identity: Identity{Issuer: issuer, Subject: subject, Actor: caller, Target: target, KeyID: kid, SessionID: sid, TokenID: jti, IssuedAt: time.Unix(issued, 0), NotBefore: time.Unix(notBefore, 0), ExpiresAt: time.Unix(expires, 0)}}, nil
}
