// Package delivery composes production HTTP signature and issuer JWT checks on
// original public metadata. It performs no transport authorization, replay I/O,
// context installation, dispatch, path rewriting or body reads.
package delivery

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/solodyagin/outgate-sdk/delegation"
	"github.com/solodyagin/outgate-sdk/httpsig"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

var ErrDelivery = errors.New("outgate: invalid signed delivery")

// Config fixes the production signing leg and logical attribute mapping.
// JWT may be nil for a background-only verifier; user deliveries then fail closed.
type Config struct {
	Leg              string
	AttributeHeaders map[string]string
	JWT              *delegation.Verifier
}

type Verifier struct {
	leg        string
	profile    *httpsig.Profile
	attributes map[string]string
	jwt        *delegation.Verifier
}

// Key must be selected from trusted leg/caller configuration AFTER transport
// identity/grant checks. An unverified Signature-Input is not a trust source.
type Key struct {
	ID     string
	Secret []byte
}

// Binding is trusted expected delivery state, never copied from request headers.
// Gateway deliveries require the exact registered instance/version/mount tuple.
// Call deliveries must leave that tuple empty. GrantID is the authenticated
// caller deployment grant ID, not its secret.
type Binding struct {
	Caller, Target, GrantID   string
	Instance, Version, Prefix string
}

// Verified proves HMAC, expected binding and user-claim equality only. Route,
// revocation/security freshness and durable replay MUST still precede dispatch.
// No assertion is retained and background deliveries contain no invented user.
type Verified struct {
	signature httpsig.Verified
	binding   Binding
	user      delegation.User
	identity  delegation.Identity
	hasUser   bool
	hop       int
}

func (v Verified) Signature() httpsig.Verified { return v.signature }
func (v Verified) Binding() Binding            { return v.binding }
func (v Verified) HopLimit() int               { return v.hop }
func (v Verified) Identity() (delegation.Identity, bool) {
	return v.identity, v.hasUser
}
func (v Verified) User() (delegation.User, bool) {
	if !v.hasUser {
		return delegation.User{}, false
	}
	copy, err := delegation.CopyUser(v.user)
	return copy, err == nil
}

// New copies attribute configuration and starts no I/O or workers. JWT is shared
// intentionally so its thread-safe ReplaceKeys affects subsequent verification.
func New(config Config) (*Verifier, error) {
	if len(config.AttributeHeaders) > 16 {
		return nil, ErrDelivery
	}
	attributes := make(map[string]string, len(config.AttributeHeaders))
	names := make([]string, 0, len(config.AttributeHeaders))
	for logical, header := range config.AttributeHeaders {
		if _, err := delegation.CopyUser(delegation.User{ID: "config", Attributes: map[string]string{logical: "value"}}); err != nil {
			return nil, ErrDelivery
		}
		header = strings.ToLower(header)
		attributes[logical] = header
		names = append(names, header)
	}
	profile, err := httpsig.New(httpsig.Config{Leg: config.Leg, AttributeHeaders: names})
	if err != nil {
		return nil, ErrDelivery
	}
	return &Verifier{leg: config.Leg, profile: profile, attributes: attributes, jwt: config.JWT}, nil
}

// Verify preserves exact signed bytes and uses semantic equality only for the
// separately authenticated JWT claims. The caller must keep request/key slices
// immutable during this call and supply the original URI/authority before strip.
func (v *Verifier) Verify(request httpsig.Request, key Key, expected Binding, now time.Time) (Verified, error) {
	bad := func() (Verified, error) { return Verified{}, ErrDelivery }
	if v == nil || expected.Caller == "" || expected.Target == "" || expected.GrantID == "" {
		return bad()
	}
	signature, err := v.profile.Verify(request, key.ID, key.Secret, now)
	if err != nil {
		return bad()
	}
	info := signature.Info()
	if info.Caller != expected.Caller || info.Target != expected.Target {
		return bad()
	}
	// Profile.Verify already bounded the complete field section and rejected
	// duplicates/unknown/unsigned identity fields. Allocate only after that gate.
	fields := make(map[string]string, len(request.Headers))
	for _, h := range request.Headers {
		fields[strings.ToLower(h[0])] = h[1]
	}
	if fields["x-outgate-deployment-grant-id"] != expected.GrantID {
		return bad()
	}
	if v.leg == httpsig.Gateway {
		prefix, err := v1.NormalizePrefix(expected.Prefix)
		path, pathErr := v1.DecodeRoutePath(request.RawURI)
		if err != nil || pathErr != nil || prefix != expected.Prefix || !v1.MatchesPrefix(prefix, path) || expected.Instance == "" || expected.Version == "" || fields["x-tunnel-instance"] != expected.Instance || fields["x-tunnel-version"] != expected.Version || fields["x-forwarded-prefix"] != expected.Prefix {
			return bad()
		}
	} else if expected.Instance != "" || expected.Version != "" || expected.Prefix != "" {
		return bad()
	}
	result := Verified{signature: signature, binding: expected, hop: int(fields["x-outgate-hop-limit"][0] - '0')}
	var manifest []string
	if json.Unmarshal([]byte(fields["x-outgate-context-headers"]), &manifest) != nil {
		return bad()
	}
	if len(manifest) == 0 {
		return result, nil
	}
	if v.jwt == nil {
		return bad()
	}
	assertion, err := v.jwt.Verify(fields["x-outgate-user-assertion"], info.Caller, info.Target, now)
	if err != nil || !now.Before(assertion.Identity().ExpiresAt) {
		return bad()
	}
	user, err := assertion.User()
	if err != nil || fields["x-user-id"] != user.ID {
		return bad()
	}
	var roles []string
	if json.Unmarshal([]byte(fields["x-user-roles"]), &roles) != nil || len(roles) != len(user.Roles) {
		return bad()
	}
	for i, role := range roles {
		if role != user.Roles[i] {
			return bad()
		}
	}
	present := make(map[string]bool, len(manifest))
	for _, name := range manifest {
		present[name] = true
	}
	matched := 0
	for logical, header := range v.attributes {
		value, exists := user.Attributes[logical]
		if present[header] != exists || exists && fields[header] != value {
			return bad()
		}
		if exists {
			matched++
		}
	}
	// Also reject claims whose logical attribute has no configured header map.
	if matched != len(user.Attributes) {
		return bad()
	}
	result.user, result.identity, result.hasUser = user, assertion.Identity(), true
	return result, nil
}
