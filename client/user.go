package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/solodyagin/outgate-sdk/delegation"
	"github.com/solodyagin/outgate-sdk/delivery"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

type UserContext = delegation.User

// DelegationConfig requires a separately authenticated view of user security
// state. Returning an error must fail closed. The returned validity deadline is
// capped at 30s and assertion expiry; this first adapter does not renew streams.
type DelegationConfig struct {
	Verifier      *delegation.Verifier
	SecurityCheck func(context.Context, delegation.Identity) (time.Time, error)
}
type userContextKey struct{}
type userAssertionKey struct{}
type localUser struct {
	user  UserContext
	valid bool
}
type userAssertion struct {
	token string
	valid bool
}

// WithUserContext copies local API context. It proves no production identity.
func WithUserContext(ctx context.Context, user UserContext) context.Context {
	copy, err := delegation.CopyUser(user)
	return context.WithValue(ctx, userContextKey{}, localUser{copy, err == nil})
}
func UserContextFromContext(ctx context.Context) (UserContext, bool) {
	v, ok := ctx.Value(userContextKey{}).(localUser)
	if !ok {
		verified, _, _ := delivery.FromContext(ctx)
		return verified.User()
	}
	if !v.valid {
		return UserContext{}, false
	}
	copy, err := delegation.CopyUser(v.user)
	return copy, err == nil
}

// CallerServiceFromContext returns the authenticated caller of a signed delivery.
func CallerServiceFromContext(ctx context.Context) (string, bool) {
	verified, _, ok := delivery.FromContext(ctx)
	return verified.Binding().Caller, ok
}

// MountInfoFromContext returns the authenticated mount of a signed delivery.
func MountInfoFromContext(ctx context.Context) (delivery.MountInfo, bool) {
	_, mount, ok := delivery.FromContext(ctx)
	return mount, ok
}

// WithUserAssertion installs only a bounded unverified token; verification is
// repeated for the actual caller/target at send time, before signing/network I/O.
func WithUserAssertion(ctx context.Context, token string) context.Context {
	value := userAssertion{valid: len(token) > 0 && len(token) <= delegation.MaxTokenBytes}
	if value.valid {
		value.token = token
	}
	return context.WithValue(ctx, userAssertionKey{}, value)
}
func sameUser(a, b UserContext) bool {
	if a.ID != b.ID || len(a.Roles) != len(b.Roles) || len(a.Attributes) != len(b.Attributes) {
		return false
	}
	for i, v := range a.Roles {
		if b.Roles[i] != v {
			return false
		}
	}
	for k, v := range a.Attributes {
		if other, ok := b.Attributes[k]; !ok || other != v {
			return false
		}
	}
	return true
}
func asciiIdentity(s string) bool {
	if s == "" || strings.TrimSpace(s) != s {
		return false
	}
	for _, b := range []byte(s) {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}
func asciiRoles(roles []string) string {
	raw, _ := json.Marshal(roles)
	var out strings.Builder
	for _, r := range string(raw) {
		if r <= 127 {
			out.WriteRune(r)
		} else if r <= 0xffff {
			fmt.Fprintf(&out, "\\u%04x", r)
		} else {
			a, b := utf16.EncodeRune(r)
			fmt.Fprintf(&out, "\\u%04x\\u%04x", a, b)
		}
	}
	return out.String()
}
func (call *serviceHTTPCall) limit(deadline time.Time) {
	s := call.owner
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, active := s.active[call]; !active {
		return
	}
	if call.deadline.IsZero() || deadline.Before(call.deadline) {
		call.deadline = deadline
		delay := max(time.Nanosecond, time.Until(deadline))
		if call.timer == nil {
			call.timer = time.AfterFunc(delay, call.cancel)
		} else {
			call.timer.Reset(delay)
		}
	}
}
func safeUserCheck(ctx context.Context, check func(context.Context, delegation.Identity) (time.Time, error), identity delegation.Identity) (until time.Time, err error) {
	defer func() {
		if recover() != nil {
			err = &Error{Code: CallbackFailed}
			until = time.Time{}
		}
	}()
	until, err = check(ctx, identity)
	if err != nil {
		var safe *Error
		if errors.As(err, &safe) && safe.Code == CallbackFailed {
			return time.Time{}, &Error{Code: CallbackFailed}
		}
		return time.Time{}, &Error{Code: SecurityFailure}
	}
	return until, nil
}
func (s *serviceHTTPState) userHeaders(call *serviceHTTPCall, ctx context.Context, target string) ([]v1.Header, error) {
	local, hasLocal := ctx.Value(userContextKey{}).(localUser)
	if !hasLocal && !s.development {
		verified, _, _ := delivery.FromContext(ctx)
		local.user, hasLocal = verified.User()
		local.valid = hasLocal
	}
	assertion, hasAssertion := ctx.Value(userAssertionKey{}).(userAssertion)
	if hasLocal && !local.valid || hasAssertion && !assertion.valid {
		return nil, &Error{Code: InvalidRequest}
	}
	if !hasLocal && !hasAssertion {
		return []v1.Header{{"x-outgate-context-headers", "[]"}}, nil
	}
	user := local.user
	if s.development {
		if hasAssertion {
			return nil, &Error{Code: InvalidRequest}
		}
	} else {
		config := s.config.Delegation
		if !hasAssertion || config == nil {
			return nil, &Error{Code: SecurityFailure}
		}
		verified, err := config.Verifier.Verify(assertion.token, s.caller, target, time.Now())
		if err != nil {
			return nil, &Error{Code: SecurityFailure}
		}
		user, err = verified.User()
		if err != nil || hasLocal && !sameUser(local.user, user) {
			return nil, &Error{Code: SecurityFailure}
		}
		identity := verified.Identity()
		if !time.Now().Before(identity.ExpiresAt) {
			return nil, &Error{Code: SecurityFailure}
		}
		call.limit(identity.ExpiresAt)
		checkCtx, cancel := context.WithTimeout(call.ctx, 5*time.Second)
		defer cancel()
		select {
		case s.userSlot <- struct{}{}:
		case <-checkCtx.Done():
			return nil, &Error{Code: SecurityFailure}
		}
		if checkCtx.Err() != nil {
			<-s.userSlot
			return nil, &Error{Code: SecurityFailure, cause: checkCtx.Err()}
		}
		// Slot remains occupied until actual callback return, even past its deadline.
		started := time.Now()
		until, err := safeUserCheck(checkCtx, config.SecurityCheck, identity)
		<-s.userSlot
		bound, _ := checkCtx.Deadline()
		if err != nil {
			return nil, err
		}
		if checkCtx.Err() != nil || !time.Now().Before(bound) || !time.Now().Before(until) {
			return nil, &Error{Code: SecurityFailure}
		}
		until = earlierDeadline(until, earlierDeadline(started.Add(30*time.Second), identity.ExpiresAt))
		if !time.Now().Before(until) {
			return nil, &Error{Code: SecurityFailure}
		}
		call.limit(until)
		if _, err := config.Verifier.Verify(assertion.token, s.caller, target, time.Now()); err != nil {
			return nil, &Error{Code: SecurityFailure}
		}
	}
	if !asciiIdentity(user.ID) {
		return nil, &Error{Code: InvalidRequest}
	}
	fields := map[string]string{"x-user-id": user.ID, "x-user-roles": asciiRoles(user.Roles)}
	for logical, value := range user.Attributes {
		header, ok := s.config.AttributeHeaders[logical]
		if !ok || !asciiIdentity(value) {
			return nil, &Error{Code: InvalidRequest}
		}
		fields[header] = value
	}
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	manifest, _ := json.Marshal(names)
	headers := []v1.Header{{"x-outgate-context-headers", string(manifest)}}
	for _, name := range names {
		headers = append(headers, v1.Header{name, fields[name]})
	}
	if !s.development {
		headers = append(headers, v1.Header{"x-outgate-user-assertion", assertion.token})
	}
	return headers, nil
}
