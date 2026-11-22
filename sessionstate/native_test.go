package sessionstate

import (
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"testing"
	"time"
)

func nativeState(t *testing.T, role Role, readyState bool) *State {
	t.Helper()
	c := config(role)
	c.NativeStreams = true
	c.MaxPendingCancels = 0
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Begin(epoch); err != nil {
		t.Fatal(err)
	}
	r, a := fixtures(t)
	a.Limits.MaxInflight = 2
	apply(t, s, Service, r, epoch)
	if role == Gateway {
		e, err := s.AuthorizeRegistration(epoch)
		must(t, e, err)
	}
	apply(t, s, Gateway, a, epoch)
	if readyState {
		e, err := s.Security(true, time.Time{}, epoch)
		must(t, e, err)
		if role == Service {
			for range a.Readiness.SuccessThreshold {
				probe(t, s, true, epoch)
			}
		}
		apply(t, s, Service, status(1, true), epoch)
	}
	return s
}

func TestNativeLeasesAndCleanup(t *testing.T) {
	for _, role := range []Role{Gateway, Service} {
		s := nativeState(t, role, false)
		if _, _, err := s.AdmitNative(epoch); err != ErrState {
			t.Fatal("admitted before readiness", err)
		}
		e, err := s.Security(true, time.Time{}, epoch)
		must(t, e, err)
		if role == Service {
			for range s.readiness.SuccessThreshold {
				probe(t, s, true, epoch)
			}
		}
		apply(t, s, Service, status(1, true), epoch)
		first, e, err := s.AdmitNative(epoch)
		must(t, e, err)
		second, e, err := s.AdmitNative(epoch)
		must(t, e, err)
		if s.streams != nil || s.Snapshot().NativeActive != 2 {
			t.Fatal("native mode allocated WSS state or lost streams")
		}
		if _, _, err := s.AdmitNative(epoch); err != ErrCapacity {
			t.Fatal("native capacity ignored")
		}
		other := nativeState(t, role, true)
		if _, err := other.CompleteNative(first, epoch); err != ErrState {
			t.Fatal("foreign lease accepted")
		}
		e, err = s.Disconnected(true, epoch)
		must(t, e, err)
		if s.Cleaned(epoch) != ErrState || s.Begin(epoch) != ErrState {
			t.Fatal("cleanup forgot active native requests")
		}
		e, err = s.CompleteNative(first, epoch)
		must(t, e, err)
		if _, err = s.CompleteNative(first, epoch); err != ErrState || s.Snapshot().NativeActive != 1 {
			t.Fatal("duplicate completion released another request")
		}
		e, err = s.CompleteNative(second, epoch)
		must(t, e, err)
		if err = s.Cleaned(epoch); err != nil {
			t.Fatal(err)
		}
		if err = s.Begin(epoch); err != nil {
			t.Fatal(err)
		}
		if _, err = s.CompleteNative(first, epoch); err != ErrState {
			t.Fatal("old lease accepted in new transport")
		}
	}
}

func TestNativeDrainWaitsForBothDirections(t *testing.T) {
	s := nativeState(t, Gateway, true)
	lease, e, err := s.AdmitNative(epoch)
	must(t, e, err)
	e = apply(t, s, Service, drain(7, 30000, "shutdown"), epoch)
	apply(t, s, Gateway, *e.Reply, epoch)
	if s.empty() {
		t.Fatal("drain forgot native exchange")
	}
	if _, _, err = s.AdmitNative(epoch); err != ErrState {
		t.Fatal("drain admitted new request")
	}
	e, err = s.CompleteNative(lease, epoch)
	must(t, e, err)
	apply(t, s, Service, v1.Unregister{Type: "unregister", CommandID: 8, DeadlineMS: 1000, Code: "shutdown"}, epoch)
	e, err = s.ConfirmExcluded(epoch)
	must(t, e, err)
	apply(t, s, Gateway, v1.UnregisterAck{Type: "unregister_ack", CommandID: 8}, epoch)
	if s.Snapshot().TransportActive || !s.Snapshot().CleanupRequired {
		t.Fatal("unregister did not terminate native session")
	}
}

func TestNativeStatusFreshnessSecurityAndBudget(t *testing.T) {
	s := nativeState(t, Gateway, true)
	e, err := s.Advance(epoch.Add(15000*time.Millisecond + time.Nanosecond))
	must(t, e, err)
	if _, _, err = s.AdmitNative(s.lastTime); err != ErrState {
		t.Fatal("stale status admitted request")
	}
	apply(t, s, Service, status(2, true), s.lastTime)
	e, err = s.Security(false, time.Time{}, s.lastTime)
	must(t, e, err)
	if _, _, err = s.AdmitNative(s.lastTime); err != ErrState {
		t.Fatal("security recovery admitted request")
	}
	c := config(Gateway)
	c.NativeStreams = true
	c.MaxPendingCancels = 0
	s, err = New(c)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Begin(epoch); err != nil {
		t.Fatal(err)
	}
	r, a := fixtures(t)
	a.Limits.BufferBytes = c.MaxCommands*128 + a.Limits.MaxInflight*64 - 1
	apply(t, s, Service, r, epoch)
	e, err = s.AuthorizeRegistration(epoch)
	must(t, e, err)
	if _, err = s.Apply(Gateway, a, epoch); err != ErrCapacity {
		t.Fatal("native fixed budget ignored", err)
	}
}

func TestNativeCannotUseWSSFramesAndWaitsForExpiryCleanup(t *testing.T) {
	s := nativeState(t, Gateway, true)
	if _, err := s.Apply(Gateway, request(1), epoch); err != ErrProtocol {
		t.Fatal("native transport accepted WSS stream accounting")
	}
	lease, e, err := s.AdmitNative(epoch)
	must(t, e, err)
	e, err = s.Security(true, epoch.Add(time.Second), epoch)
	must(t, e, err)
	e, err = s.Advance(epoch.Add(time.Second))
	if err != ErrSecurity || !e.CloseTransport || !e.StopAll || s.Cleaned(epoch.Add(time.Second)) != ErrState {
		t.Fatal("expiry skipped native cleanup")
	}
	e, err = s.CompleteNative(lease, epoch.Add(time.Second))
	must(t, e, err)
	if err = s.Cleaned(epoch.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
}
