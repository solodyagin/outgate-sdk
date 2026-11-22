package sessionstate

import "time"

// NativeLease tracks one native transport exchange through both directions.
// Only its issuing State can complete it, exactly once. It does not represent
// wire IDs, flow-control credit, HTTP bytes, or request authorization.
type NativeLease struct {
	owner     *State
	completed bool
}

// AdmitNative reserves negotiated concurrency after readiness/security checks.
// Native transport must call CompleteNative only when upload and response have
// both ended or been canceled. Serialize these calls with all State methods.
func (s *State) AdmitNative(now time.Time) (*NativeLease, Effect, error) {
	e, err := s.Advance(now)
	if err != nil {
		return nil, e, err
	}
	if !s.config.NativeStreams || !s.registered {
		return nil, Effect{}, ErrState
	}
	allowed := s.phase == Ready && !s.fence
	if s.config.Local == Service {
		allowed = s.admitted && !s.fence && s.securityReady && !now.Before(s.barrier)
	}
	if !allowed {
		return nil, Effect{}, ErrState
	}
	if s.nativeActive >= s.nativeLimit {
		return nil, Effect{}, ErrCapacity
	}
	s.nativeActive++
	return &NativeLease{owner: s}, Effect{}, nil
}

// CompleteNative also accepts completion after transport failure so cleanup
// cannot silently forget old exchanges. Cleaned remains blocked until all leases
// return. A stale/duplicate/foreign lease never releases another request's slot.
func (s *State) CompleteNative(lease *NativeLease, now time.Time) (Effect, error) {
	if !s.config.NativeStreams || lease == nil || lease.owner != s || lease.completed || s.nativeActive == 0 {
		return Effect{}, ErrState
	}
	if err := s.clock(now); err != nil {
		return s.finish(false), err
	}
	lease.completed = true
	s.nativeActive--
	if s.active {
		return s.Advance(now)
	}
	return Effect{}, nil
}
