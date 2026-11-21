package httpsig

import (
	"context"
	"errors"
	"time"
)

var (
	ErrReplay            = errors.New("outgate: signature nonce already reserved")
	ErrReplayUnavailable = errors.New("outgate: signature replay store unavailable")
)

// ReplayKey separates both signing legs, verifier installations, callers and keys.
type ReplayKey struct{ Leg, Namespace, Caller, KeyID, Nonce string }

// Reservation remains live THROUGH RetainUntil (expires+30), inclusively.
// Failure after dispatch must never delete or shorten this reservation.
type Reservation struct {
	Key         ReplayKey
	RetainUntil time.Time
}

// ReplayStore must atomically check unique key and caller/global capacity and
// COMMIT insertion before returning nil. Live entries cannot be evicted. Return
// ErrReplay for duplicates; any capacity, integrity, storage or commit failure
// fails closed. Production requires durable SQL and its recovery barrier; this
// interface cannot prove durability or make a volatile store production-safe.
// The caller supplies backend namespaces/quotas and services recovery readiness.
type ReplayStore interface {
	Reserve(context.Context, Reservation) error
}

// Reserve is a separate step AFTER transport/issuer/route/delegation/revision and
// target/instance binding checks, immediately before dispatch. Namespace comes
// from trusted verifier configuration. No automatic reserve occurs in Verify.
// Recheck time if authorization took long enough to exhaust the signature window.
func (v Verified) Reserve(ctx context.Context, store ReplayStore, namespace string, now time.Time) error {
	if !v.valid || len(namespace) < 1 || len(namespace) > 128 || !identityValue(namespace) || !validTime(Params{Created: v.created, Expires: v.expires, Nonce: v.nonce, KeyID: v.keyID}, now) {
		return ErrAuth
	}
	if ctx == nil || store == nil || ctx.Err() != nil {
		return ErrReplayUnavailable
	}
	entry := Reservation{Key: ReplayKey{Leg: v.leg, Namespace: namespace, Caller: v.caller, KeyID: v.keyID, Nonce: v.nonce}, RetainUntil: time.Unix(v.expires+30, 0)}
	if err := store.Reserve(ctx, entry); err != nil {
		if errors.Is(err, ErrReplay) {
			return ErrReplay
		}
		return ErrReplayUnavailable
	}
	if ctx.Err() != nil {
		return ErrReplayUnavailable
	} // insertion may already have committed; never roll it back
	return nil
}
