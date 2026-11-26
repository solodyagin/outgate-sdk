package client

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

// Run owns this state. The sole acquisition worker is joined before the next
// Connect or final clear; the connector's slot also serializes source access.
type quicRenewal struct {
	config            QUICConfig
	register          v1.Register
	slot              chan struct{}
	generation        uint64
	fingerprint       [32]byte
	expiry, refreshAt time.Time
	pending           *CredentialSnapshot
}

func earlierDeadline(a, b time.Time) time.Time {
	if a.IsZero() || !b.IsZero() && b.Before(a) {
		return b
	}
	return a
}

func renewalTime(accepted, expiry time.Time) time.Time {
	remaining := expiry.Sub(accepted)
	if remaining <= 0 {
		return accepted
	}
	return expiry.Add(-min(5*time.Minute, remaining/5))
}

// Full jitter bounded to [1s, cap], with a conservative minimum on RNG failure.
// The active service's independent security deadline always preempts retry.
func renewalRetry(cap time.Duration) time.Duration {
	cap = max(time.Second, min(30*time.Second, cap))
	var data [8]byte
	if _, err := rand.Read(data[:]); err != nil {
		return time.Second
	}
	return time.Second + time.Duration(binary.BigEndian.Uint64(data[:])%uint64(cap-time.Second+1))
}

func (q *quicRenewal) clear() {
	if q.pending != nil {
		clear(q.pending.Credential)
		q.pending = nil
	}
}

func (q *quicRenewal) prepare(parent context.Context) (err error) {
	// A malformed candidate/provider panic must leave the accepted pair working.
	defer func() {
		if recover() != nil {
			err = &Error{Code: SecurityFailure}
		}
	}()
	ctx, cancel := context.WithTimeout(parent, q.config.SourceTimeout)
	defer cancel()
	select {
	case q.slot <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-q.slot }()
	if err := ctx.Err(); err != nil {
		return err
	}
	candidate, err := callCredentialSource(ctx, q.config.Credentials)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	candidate, err = copyCredentials(candidate)
	if err != nil {
		return err
	}
	transferred := false
	defer func() {
		if !transferred {
			clear(candidate.Credential)
		}
	}()
	if _, err = validateSnapshot(candidate, q.register, q.config); err != nil {
		return err
	}
	if candidate.Generation <= q.generation || snapshotFingerprint(candidate) == q.fingerprint {
		return errors.New("outgate: credential generation unchanged")
	}
	deadline, _ := ctx.Deadline()
	if ctx.Err() != nil || !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	q.clear()
	q.pending = &candidate
	transferred = true
	return nil
}
