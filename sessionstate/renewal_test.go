package sessionstate

import (
	"errors"
	"testing"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

func TestRenewSecuritySurvivesReplayBarrierWithoutGrantingReadiness(t *testing.T) {
	s := register(t, Gateway)
	s.barrier = epoch.Add(120 * time.Second)
	apply(t, s, Service, status(1, true), epoch)
	for seconds := 0; seconds < 120; seconds += 2 {
		now := epoch.Add(time.Duration(seconds) * time.Second)
		effect, err := s.RenewSecurity(true, now.Add(5*time.Second), now)
		must(t, effect, err)
		if s.Snapshot().Phase != Registered {
			t.Fatal("renewal bypassed replay barrier")
		}
	}
	now := epoch.Add(120 * time.Second)
	effect, err := s.RenewSecurity(true, now.Add(5*time.Second), now)
	must(t, effect, err)
	if s.Snapshot().Phase != Registered {
		t.Fatal("renewal refreshed stale instance_status")
	}
	apply(t, s, Service, status(2, true), now)
	if s.Snapshot().Phase != Ready {
		t.Fatal("healthy renewed transport did not become ready")
	}
}

func TestRenewSecurityPreservesHardLimits(t *testing.T) {
	for _, kind := range []string{"legacy_security", "credential", "drain"} {
		t.Run(kind, func(t *testing.T) {
			s := ready(t, Gateway)
			bound := epoch.Add(2 * time.Second)
			switch kind {
			case "legacy_security":
				effect, err := s.Security(true, bound, epoch)
				must(t, effect, err)
			case "credential":
				s.expiry = bound
			case "drain":
				apply(t, s, Gateway, v1.Drain{Type: "drain", CommandID: 1, DeadlineMS: 2000, Code: "shutdown"}, epoch)
			}
			effect, err := s.RenewSecurity(true, epoch.Add(5*time.Second), epoch)
			must(t, effect, err)
			if !s.Snapshot().Deadline.Equal(bound) {
				t.Fatal("renewal extended a hard limit")
			}
			if kind == "drain" && s.Snapshot().Phase != Draining {
				t.Fatal("renewal removed drain intent")
			}
			effect, err = s.Advance(bound)
			if err == nil || !effect.CloseTransport || !effect.CleanupRequired {
				t.Fatal("hard limit did not close", effect, err)
			}
		})
	}
}

func TestRenewSecurityRejectsInvalidOrLateAssertions(t *testing.T) {
	for _, kind := range []string{"zero", "past", "equal", "long", "lease_expired", "backward", "revoked", "disconnected", "terminal"} {
		t.Run(kind, func(t *testing.T) {
			s := ready(t, Gateway)
			effect, err := s.RenewSecurity(true, epoch.Add(time.Second), epoch)
			must(t, effect, err)
			now := epoch.Add(time.Millisecond)
			deadline := now.Add(5 * time.Second)
			switch kind {
			case "zero":
				deadline = time.Time{}
			case "past":
				deadline = epoch
			case "equal":
				deadline = now
			case "long":
				deadline = now.Add(5*time.Second + time.Nanosecond)
			case "lease_expired":
				now = epoch.Add(time.Second)
				deadline = now.Add(5 * time.Second)
			case "backward":
				now = epoch.Add(-time.Nanosecond)
			case "revoked":
				_, _ = s.Revoke(now)
			case "disconnected":
				_, _ = s.Disconnected(true, now)
			case "terminal":
				s.finish(false)
			}
			effect, err = s.RenewSecurity(true, deadline, now)
			if err == nil || s.Snapshot().TransportActive || s.Snapshot().Phase == Ready {
				t.Fatal("invalid renewal revived transport", effect, err)
			}
			if kind == "zero" || kind == "past" || kind == "equal" || kind == "long" || kind == "lease_expired" {
				if !errors.Is(err, ErrSecurity) || !effect.CloseTransport || !effect.CleanupRequired {
					t.Fatal("invalid lease did not close", effect, err)
				}
			}
		})
	}
}

func TestRenewSecurityPreservesProbeStatusAndFalseReadiness(t *testing.T) {
	for _, role := range []Role{Gateway, Service} {
		s := ready(t, role)
		now := epoch.Add(time.Millisecond)
		effect, err := s.RenewSecurity(false, now.Add(5*time.Second), now)
		must(t, effect, err)
		if s.Snapshot().Phase != Registered {
			t.Fatal("unhealthy source left readiness true")
		}
		effect, err = s.RenewSecurity(true, now.Add(5*time.Second), now)
		must(t, effect, err)
		if s.Snapshot().Phase != Ready {
			t.Fatal("fresh status/probe lost")
		}
		if role == Service {
			s.probeReady = false
			effect, err = s.RenewSecurity(true, now.Add(5*time.Second), now)
			must(t, effect, err)
			if s.Snapshot().LocalReady || s.Snapshot().Phase == Ready {
				t.Fatal("renewal substituted for local probe")
			}
		}
	}
}

func TestRenewSecurityRequiresAckAndRetainsNativeCleanup(t *testing.T) {
	for _, begin := range []bool{false, true} {
		s, err := New(config(Gateway))
		if err != nil {
			t.Fatal(err)
		}
		if begin {
			if err := s.Begin(epoch); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.RenewSecurity(true, epoch.Add(time.Second), epoch); !errors.Is(err, ErrState) {
			t.Fatal("renewal before ack", err)
		}
	}
	cfg := config(Gateway)
	cfg.NativeStreams = true
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Begin(epoch); err != nil {
		t.Fatal(err)
	}
	reg, ack := fixtures(t)
	apply(t, s, Service, reg, epoch)
	effect, err := s.AuthorizeRegistration(epoch)
	must(t, effect, err)
	apply(t, s, Gateway, ack, epoch)
	effect, err = s.RenewSecurity(true, epoch.Add(time.Second), epoch)
	must(t, effect, err)
	apply(t, s, Service, status(1, true), epoch)
	lease, effect, err := s.AdmitNative(epoch)
	must(t, effect, err)
	effect, err = s.RenewSecurity(true, epoch.Add(3*time.Second), epoch.Add(time.Second))
	if !errors.Is(err, ErrSecurity) || !effect.CloseTransport || s.Snapshot().NativeActive != 1 {
		t.Fatal("late refresh lost native cleanup", effect, err)
	}
	if err := s.Cleaned(epoch.Add(time.Second)); !errors.Is(err, ErrState) {
		t.Fatal("cleanup ignored native lease", err)
	}
	effect, err = s.CompleteNative(lease, epoch.Add(time.Second))
	must(t, effect, err)
	if err := s.Cleaned(epoch.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
}
