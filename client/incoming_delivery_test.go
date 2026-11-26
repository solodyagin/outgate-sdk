package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/solodyagin/outgate-sdk/delivery"
	"github.com/solodyagin/outgate-sdk/httpsig"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/transport/quichttp"
)

type testDeliveryReplay struct{ entries sync.Map }

func (s *testDeliveryReplay) Reserve(_ context.Context, reservation httpsig.Reservation) error {
	if _, loaded := s.entries.LoadOrStore(reservation.Key, struct{}{}); loaded {
		return httpsig.ErrReplay
	}
	return nil
}

func TestClientSignedRecipientAndInheritedHopOverQUIC(t *testing.T) {
	e := dialEnv(t)
	_, accepted := listen(t, e)
	var forwards atomic.Int32
	server := serviceHTTPServer(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwards.Add(1)
		var headers []v1.Header
		for name, values := range r.Header {
			for _, value := range values {
				headers = append(headers, v1.Header{strings.ToLower(name), value})
			}
		}
		profile, _ := httpsig.New(httpsig.Config{Leg: httpsig.Call})
		outgoing := serviceHTTPKey()
		proof, err := profile.Verify(httpsig.Request{Method: r.Method, Scheme: "https", Authority: r.Host, RawURI: r.RequestURI, Headers: headers}, outgoing.ID, outgoing.Secret, time.Now())
		if err != nil || proof.Info().Caller != e.config.Register.ServiceID || r.Header.Get("X-Outgate-Hop-Limit") != "2" {
			t.Error("outgoing delivery has incorrect caller, signature or inherited hop", err)
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(204)
	}))
	verifier, err := delivery.New(delivery.Config{Leg: httpsig.Gateway})
	must(t, err)
	profile, err := httpsig.New(httpsig.Config{Leg: httpsig.Gateway})
	must(t, err)
	key := delivery.Key{ID: "recipient-key", Secret: []byte(strings.Repeat("r", 32))}
	binding := delivery.Binding{Caller: "caller-service", Target: e.config.Register.ServiceID, GrantID: "authenticated-caller-grant", Instance: e.config.Register.InstanceID, Version: e.config.Register.Version, Prefix: "/api/v2"}
	incoming := delivery.HandlerConfig{
		Verifier: verifier, ReplayStore: &testDeliveryReplay{}, ReplayNamespace: "recipient-instance", StripPrefix: true,
		Prepare: func(_ context.Context, peer *tls.ConnectionState, _ httpsig.Request) (delivery.Key, delivery.Binding, error) {
			if len(peer.PeerCertificates) == 0 || peer.PeerCertificates[0].SerialNumber.Int64() != 2 {
				return delivery.Key{}, delivery.Binding{}, delivery.ErrDelivery
			}
			return key, binding, nil
		},
		Authorize: func(context.Context, httpsig.Request, delivery.Verified) (time.Time, error) {
			return time.Now().Add(time.Minute), nil
		},
	}
	var outbound *http.Client
	c, err := New(Config{QUIC: &e.config, ServiceHTTP: &ServiceHTTPConfig{ServerRoots: e.config.ServerRoots, SigningKey: serviceHTTPKey()}, IncomingDelivery: &incoming,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			caller, ok := CallerServiceFromContext(r.Context())
			mount, mounted := MountInfoFromContext(r.Context())
			_, hasUser := UserContextFromContext(r.Context())
			if !ok || caller != binding.Caller || !mounted || mount.Prefix != "/api/v2" || mount.OriginalRequestURI != "/api/v2/items?" || r.RequestURI != "/items?" || hasUser {
				t.Error("client handler did not receive authenticated context or stripped path")
				w.WriteHeader(500)
				return
			}
			req, err := http.NewRequestWithContext(WithTargetService(r.Context(), "other-service"), "GET", server.URL+"/other", nil)
			if err == nil {
				var response *http.Response
				response, err = outbound.Do(req)
				if err == nil {
					_ = response.Body.Close()
					w.WriteHeader(response.StatusCode)
					return
				}
			}
			if errors.Is(err, &Error{Code: HopLimitExhausted}) {
				w.WriteHeader(http.StatusLoopDetected)
				return
			}
			t.Error("outgoing request failed", err)
			w.WriteHeader(500)
		}),
	})
	must(t, err)
	outbound, err = c.ServiceHTTPClient(server.URL)
	must(t, err)
	running := run(t, c, t.Context())
	t.Cleanup(func() { c.Revoke(); _ = await(t, running) })
	peer := await(t, accepted)
	must(t, peer.err)
	receive(t, peer.carrier, "status")
	must(t, c.WaitReady(t.Context()))
	gateway, err := quichttp.NewGateway(peer.carrier)
	must(t, err)
	t.Cleanup(func() { _ = gateway.Close() })
	makeRequest := func(hop string) *http.Request {
		r, err := http.NewRequestWithContext(t.Context(), "GET", "https://public.example.test/api/v2/items?", nil)
		must(t, err)
		headers := []v1.Header{{"x-outgate-caller-service", binding.Caller}, {"x-outgate-target-service", binding.Target},
			{"x-outgate-deployment-grant-id", binding.GrantID}, {"x-outgate-hop-limit", hop}, {"x-outgate-context-headers", "[]"},
			{"x-tunnel-instance", binding.Instance}, {"x-tunnel-version", binding.Version}, {"x-forwarded-prefix", binding.Prefix}}
		sig, err := profile.Sign(httpsig.Request{Method: r.Method, Scheme: "https", Authority: r.Host, RawURI: r.URL.RequestURI(), Headers: headers}, key.ID, key.Secret, time.Now())
		must(t, err)
		for _, header := range headers {
			r.Header.Add(header[0], header[1])
		}
		r.Header.Set("Signature", sig.Signature)
		r.Header.Set("Signature-Input", sig.SignatureInput)
		return r
	}
	first := makeRequest("3")
	for _, tc := range []struct {
		request *http.Request
		status  int
	}{{first, 204}, {first.Clone(t.Context()), 401}, {makeRequest("1"), 508}} {
		response, err := gateway.RoundTrip(tc.request)
		must(t, err)
		must(t, response.Body.Close())
		if response.StatusCode != tc.status {
			t.Fatalf("status %d, want %d", response.StatusCode, tc.status)
		}
	}
	if forwards.Load() != 1 {
		t.Fatal("replay or exhausted hop reached outgoing server")
	}
}
