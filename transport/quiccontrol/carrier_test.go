package quiccontrol

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/solodyagin/outgate-sdk/internal/quictest"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func fixtures(t *testing.T, production bool) (v1.Register, v1.RegisterAck) {
	return quictest.Fixtures(t, production)
}
func pair(t *testing.T, mutual bool, alpn string) (*quic.Conn, *quic.Conn) {
	return quictest.Pair(t, mutual, alpn)
}

func await[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case result := <-ch:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("operation did not complete")
		var zero T
		return zero
	}
}

func session(t *testing.T, production bool) (*Carrier, *Carrier) {
	t.Helper()
	service, gateway := pair(t, production, v1.QUICALPN)
	reg, ack := fixtures(t, production)
	o := Options{Development: !production}
	type accepted struct {
		c   *Carrier
		err error
	}
	result := make(chan accepted, 1)
	go func() {
		c, err := Accept(t.Context(), gateway, o, func(ctx context.Context, peer tls.ConnectionState, credential []byte, got v1.Register) (v1.RegisterAck, error) {
			if !bytes.Equal(credential, []byte("test-only-credential")) || got.InstanceID != reg.InstanceID || production && len(peer.VerifiedChains) == 0 {
				return v1.RegisterAck{}, errors.New("authorization failed")
			}
			return ack, nil
		})
		result <- accepted{c, err}
	}()
	ctx, cancel := context.WithCancel(t.Context())
	s, got, err := Open(ctx, service, o, []byte("test-only-credential"), reg)
	must(t, err)
	cancel() // Registration context must not cancel the established carrier.
	if got.SessionID != ack.SessionID {
		t.Fatal("ack changed")
	}
	g := await(t, result)
	must(t, g.err)
	t.Cleanup(func() { _ = s.Close(); _ = g.c.Close() })
	return s, g.c
}

func TestRegistrationAndReverseHTTP3(t *testing.T) {
	for _, production := range []bool{false, true} {
		name := "development"
		if production {
			name = "production"
		}
		t.Run(name, func(t *testing.T) {
			s, g := session(t, production)
			if s.stream.StreamID() != 0 || g.stream.StreamID() != 0 {
				t.Fatal("control stream is not zero")
			}
			server := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				_, _ = io.Copy(w, req.Body)
			})}
			served := make(chan error, 1)
			go func() { served <- server.ServeQUICConn(s.conn) }()
			t.Cleanup(func() { _ = server.Close(); _ = await(t, served) })
			transport := &http3.Transport{DisableCompression: true}
			client := transport.NewClientConn(g.conn)
			t.Cleanup(func() { _ = transport.Close() })
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			// SETTINGS and requests use native streams while status stays on stream 0.
			for i := 1; i <= 2; i++ {
				must(t, s.Send(ctx, v1.InstanceStatus{Type: "instance_status", Sequence: v1.U64(i), Ready: true, Code: "ready", ObservedAt: time.Now().Unix()}))
				message, err := g.Receive(ctx)
				must(t, err)
				if message.(v1.InstanceStatus).Sequence != v1.U64(i) {
					t.Fatal("status changed")
				}
				req, err := http.NewRequestWithContext(ctx, "POST", "https://application.test/echo", bytes.NewBufferString("streamed body"))
				must(t, err)
				response, err := client.RoundTrip(req)
				must(t, err)
				body, err := io.ReadAll(response.Body)
				must(t, err)
				must(t, response.Body.Close())
				if string(body) != "streamed body" {
					t.Fatal("HTTP/3 body changed")
				}
			}
			must(t, g.Send(ctx, v1.Drain{Type: "drain", CommandID: 7, DeadlineMS: 1000, Code: "shutdown"}))
			message, err := s.Receive(ctx)
			must(t, err)
			if message.(v1.Drain).CommandID != 7 {
				t.Fatal("drain changed")
			}
		})
	}
}

func TestCarrierLossClosesConnection(t *testing.T) {
	for _, reset := range []bool{false, true} {
		name := "fin"
		if reset {
			name = "reset"
		}
		t.Run(name, func(t *testing.T) {
			s, g := session(t, false)
			if reset {
				s.stream.CancelWrite(1)
			} else {
				must(t, s.stream.Close())
			}
			await(t, g.Done())
			await(t, s.conn.Context().Done())
			if g.Err() == nil {
				t.Fatal("lost carrier still valid")
			}
		})
	}
}

func TestCloseUnblocksReceiverAndConcurrentWriters(t *testing.T) {
	s, g := session(t, false)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 30 {
				if s.Send(t.Context(), v1.DrainAck{Type: "drain_ack", CommandID: 1}) != nil {
					return
				}
			}
		})
	}
	received := make(chan error, 1)
	go func() { _, err := s.Receive(t.Context()); received <- err }()
	must(t, s.Close())
	must(t, s.Close())
	if await(t, received) == nil {
		t.Fatal("Receive survived Close")
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	await(t, done)
	await(t, g.Done())
}

func TestMalformedAndWrongDirectionTerminate(t *testing.T) {
	for name, payload := range map[string][]byte{
		"register_again":  []byte(`{"type":"register"}`),
		"http_frame":      []byte(`{"type":"request_end","stream_id":"1","bytes_sent":"0"}`),
		"wrong_direction": []byte(`{"type":"instance_status","sequence":"1","ready":true,"code":"ready","observed_at":0}`),
		"unknown_field":   []byte(`{"type":"drain_ack","command_id":"1","extra":true}`),
	} {
		t.Run(name, func(t *testing.T) {
			s, g := session(t, false)
			must(t, v1.WriteControl(g.stream, payload, v1.MaxControlBytes))
			await(t, s.Done())
			if !errors.Is(s.Err(), v1.ErrProtocol) {
				t.Fatalf("cause = %v", s.Err())
			}
		})
	}
}

func TestOversizedAndTruncatedFrames(t *testing.T) {
	for name, b := range map[string][]byte{"oversized": {0, 1, 0, 1}, "truncated": {0, 0, 0, 20, '{', '}'}} {
		t.Run(name, func(t *testing.T) {
			s, g := session(t, false)
			_, err := g.stream.Write(b)
			must(t, err)
			if name == "truncated" {
				must(t, g.stream.Close())
			}
			await(t, s.Done())
		})
	}
}

func TestSendValidationAndReceiveCancellation(t *testing.T) {
	s, g := session(t, false)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := g.Receive(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, value := range []any{v1.InstanceStatus{Type: "instance_status"}, v1.Reconnect{Type: "reconnect", CommandID: 1, DeadlineMS: 1, Code: "shutdown"}, v1.Register{}, (*v1.Drain)(nil)} {
		if !errors.Is(s.Send(t.Context(), value), v1.ErrProtocol) {
			t.Fatal("invalid outgoing message accepted")
		}
	}
	if !errors.Is(s.Send(ctx, v1.DrainAck{Type: "drain_ack", CommandID: 1}), context.Canceled) {
		t.Fatal("canceled send accepted")
	}
	must(t, s.Send(t.Context(), v1.DrainAck{Type: "drain_ack", CommandID: 9}))
	message, err := g.Receive(t.Context())
	must(t, err)
	if message.(v1.DrainAck).CommandID != 9 {
		t.Fatal("Receive cancellation lost frame")
	}
}

func TestSecurityProfile(t *testing.T) {
	for _, name := range []string{"wrong_alpn", "production_without_mtls"} {
		t.Run(name, func(t *testing.T) {
			alpn := v1.QUICALPN
			if name == "wrong_alpn" {
				alpn = "other-profile"
			}
			_, gateway := pair(t, false, alpn)
			called := false
			_, err := Accept(t.Context(), gateway, Options{}, func(context.Context, tls.ConnectionState, []byte, v1.Register) (v1.RegisterAck, error) {
				called = true
				return v1.RegisterAck{}, nil
			})
			if !errors.Is(err, ErrSecurity) || called {
				t.Fatal("unverified security admitted")
			}
			await(t, gateway.Context().Done())
		})
	}
}

func TestBootstrapDeadlineAndCancellation(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		name := "timeout"
		if canceled {
			name = "cancel"
		}
		t.Run(name, func(t *testing.T) {
			service, gateway := pair(t, false, v1.QUICALPN)
			stream, err := service.OpenStreamSync(t.Context())
			must(t, err)
			_, err = stream.Write([]byte("O"))
			must(t, err) // stall in preface
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			options := Options{Development: true, RegisterTimeout: 100 * time.Millisecond}
			if canceled {
				cancel()
			}
			_, err = Accept(ctx, gateway, options, func(context.Context, tls.ConnectionState, []byte, v1.Register) (v1.RegisterAck, error) {
				return v1.RegisterAck{}, nil
			})
			if canceled && !errors.Is(err, context.Canceled) || !canceled && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("cause = %v", err)
			}
			await(t, service.Context().Done())
		})
	}
}

func TestWriteBackpressureDeadline(t *testing.T) {
	s, g := session(t, false)
	s.writeTimeout = 100 * time.Millisecond
	// The gateway reader holds at most one message while no Receive is running.
	// Filling the native QUIC stream window must time out and invalidate both ends.
	message := v1.Drain{Type: "drain", CommandID: 1, DeadlineMS: 1000, Code: "shutdown", Extensions: map[string]json.RawMessage{"padding": json.RawMessage(`"` + string(bytes.Repeat([]byte("x"), 12000)) + `"`)}}
	result := make(chan error, 1)
	go func() {
		for range 100 {
			if err := s.Send(t.Context(), message); err != nil {
				result <- err
				return
			}
		}
		result <- nil
	}()
	if err := await(t, result); err == nil {
		t.Fatal("unbounded writes to slow receiver")
	}
	await(t, s.Done())
	await(t, g.Done())
}

func TestBootstrapRejections(t *testing.T) {
	for _, name := range []string{"wrong_kind", "wrong_first_message", "unsupported_major", "second_bidi", "bad_ack", "authorization_error", "nack"} {
		t.Run(name, func(t *testing.T) {
			service, gateway := pair(t, false, v1.QUICALPN)
			reg, ack := fixtures(t, false)
			serverResult := make(chan error, 1)
			go func() {
				o := Options{Development: true}
				// quic-go exposes client streams in ID order, including an
				// implicitly opened but empty stream 0 when ID 4 arrives first.
				if name == "second_bidi" {
					o.RegisterTimeout = 100 * time.Millisecond
				}
				_, err := Accept(t.Context(), gateway, o, func(context.Context, tls.ConnectionState, []byte, v1.Register) (v1.RegisterAck, error) {
					if name == "unsupported_major" {
						return v1.RegisterAck{}, errors.New("unsupported major reached authorization")
					}
					switch name {
					case "bad_ack":
						ack.Paths = nil
					case "authorization_error":
						return v1.RegisterAck{}, errors.New("secret-must-not-leak")
					case "nack":
						return v1.RegisterAck{}, &Rejection{Nack: v1.RegisterNack{Type: "register_nack", Code: "path_forbidden", Detail: "denied", Retryable: false}}
					}
					return ack, nil
				})
				serverResult <- err
			}()
			if name == "bad_ack" || name == "authorization_error" || name == "nack" {
				_, _, err := Open(t.Context(), service, Options{Development: true}, []byte("credential"), reg)
				if err == nil || bytes.Contains([]byte(err.Error()), []byte("secret-must-not-leak")) {
					t.Fatal("invalid acceptance or secret in error")
				}
			} else {
				if name == "second_bidi" {
					_, err := service.OpenStreamSync(t.Context())
					must(t, err)
				}
				stream, err := service.OpenStreamSync(t.Context())
				must(t, err)
				kind := v1.DevelopmentBearer
				if name == "wrong_kind" {
					kind = v1.ProductionGrant
				}
				must(t, v1.WriteBootstrap(stream, kind, []byte("credential")))
				if name == "unsupported_major" {
					reg.ProtocolVersion = v1.Major + 1
				}
				b, _ := json.Marshal(reg)
				if name == "wrong_first_message" {
					b = []byte(`{"type":"drain_ack","command_id":"1"}`)
				}
				// A peer close may race this write; either outcome is acceptable.
				_ = v1.WriteControl(stream, b, v1.MaxControlBytes)
			}
			serverErr := await(t, serverResult)
			if name == "unsupported_major" {
				var refusal *Rejection
				if !errors.As(serverErr, &refusal) || refusal.Nack.Code != "unsupported_protocol_version" {
					t.Fatal("missing negotiation refusal", serverErr)
				}
			}
			if serverErr == nil {
				t.Fatal("invalid bootstrap accepted")
			}
			await(t, service.Context().Done())
		})
	}
}

func TestConcurrentFramesRemainAtomic(t *testing.T) {
	s, g := session(t, false)
	const count = 32
	results := make(chan error, count)
	for id := 1; id <= count; id++ {
		go func(id int) { results <- s.Send(t.Context(), v1.DrainAck{Type: "drain_ack", CommandID: v1.U64(id)}) }(id)
	}
	seen := make(map[v1.U64]bool)
	for range count {
		message, err := g.Receive(t.Context())
		must(t, err)
		id := message.(v1.DrainAck).CommandID
		if seen[id] {
			t.Fatal("duplicated concurrent frame")
		}
		seen[id] = true
	}
	for range count {
		must(t, await(t, results))
	}
}

func TestNegotiatedControlLimit(t *testing.T) {
	service, gateway := pair(t, false, v1.QUICALPN)
	reg, ack := fixtures(t, false)
	ack.Limits.MaxControlBytes = 512
	result := make(chan *Carrier, 1)
	errors := make(chan error, 1)
	var borrowed []byte
	go func() {
		c, err := Accept(t.Context(), gateway, Options{Development: true}, func(_ context.Context, _ tls.ConnectionState, credential []byte, _ v1.Register) (v1.RegisterAck, error) {
			borrowed = credential
			return ack, nil
		})
		errors <- err
		result <- c
	}()
	s, _, err := Open(t.Context(), service, Options{Development: true}, []byte("test-only-credential"), reg)
	must(t, err)
	must(t, await(t, errors))
	g := await(t, result)
	t.Cleanup(func() { _ = s.Close(); _ = g.Close() })
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("credential retained after authorization")
	}
	message := v1.Drain{Type: "drain", CommandID: 1, DeadlineMS: 1000, Code: "shutdown", Extensions: map[string]json.RawMessage{"padding": json.RawMessage(`"` + string(bytes.Repeat([]byte("x"), 600)) + `"`)}}
	if s.Send(t.Context(), message) != v1.ErrProtocol {
		t.Fatal("outgoing negotiated limit ignored")
	}
	// The ack itself exceeds 512 bytes and is legal under the bootstrap limit.
	// Only subsequent control frames use the negotiated smaller limit.
	b, err := json.Marshal(message)
	must(t, err)
	must(t, v1.WriteControl(g.stream, b, v1.MaxControlBytes))
	await(t, s.Done())
}

func TestServiceRejectsForgedAckAndParsesNack(t *testing.T) {
	for _, name := range []string{"forged_ack", "nack"} {
		t.Run(name, func(t *testing.T) {
			service, gateway := pair(t, false, v1.QUICALPN)
			reg, ack := fixtures(t, false)
			result := make(chan error, 1)
			go func() {
				stream, err := gateway.AcceptStream(t.Context())
				if err == nil {
					_, err = v1.ReadBootstrap(stream, v1.DevelopmentBearer)
				}
				if err == nil {
					_, err = v1.ReadControl(stream, v1.MaxControlBytes)
				}
				var b []byte
				if name == "nack" {
					b, _ = json.Marshal(v1.RegisterNack{Type: "register_nack", Code: "duplicate_instance", Detail: "denied", Retryable: true})
				} else {
					ack.Paths[0].Path = "/different-path"
					b, _ = json.Marshal(ack)
				}
				if err == nil {
					err = v1.WriteControl(stream, b, v1.MaxControlBytes)
				}
				result <- err
			}()
			_, _, err := Open(t.Context(), service, Options{Development: true}, []byte("credential"), reg)
			must(t, await(t, result))
			if name == "forged_ack" {
				if !errors.Is(err, v1.ErrProtocol) {
					t.Fatal("forged ack accepted", err)
				}
			} else {
				var refusal *Rejection
				if !errors.As(err, &refusal) || refusal.Nack.Code != "duplicate_instance" || !refusal.Nack.Retryable {
					t.Fatal("lost typed refusal", err)
				}
			}
			await(t, gateway.Context().Done())
		})
	}
}
