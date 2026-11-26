package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/solodyagin/outgate-sdk/httpsig"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

func serviceHTTPKey() HMACKey {
	return HMACKey{ID: "caller-2026", Secret: bytes.Repeat([]byte{42}, 32)}
}

func serviceHTTPServer(t *testing.T, e *dialEnvironment, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{e.server}, ClientCAs: e.config.ClientRoots, ClientAuth: tls.RequireAndVerifyClientCert, NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func readyServiceHTTP(t *testing.T, e *dialEnvironment, options ServiceHTTPConfig) (*Client, *quiccontrolTestPair) {
	t.Helper()
	_, accepted := listen(t, e)
	c, err := New(Config{QUIC: &e.config, ServiceHTTP: &options, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})})
	must(t, err)
	running := run(t, c, t.Context())
	g := await(t, accepted)
	must(t, g.err)
	receive(t, g.carrier, "status")
	must(t, c.WaitReady(t.Context()))
	t.Cleanup(func() {
		c.Revoke()
		select {
		case <-c.Done():
		case <-time.After(3 * time.Second):
			t.Error("outgoing client cleanup stalled")
		}
	})
	return c, &quiccontrolTestPair{g: g, running: running, accepted: accepted}
}

type quiccontrolTestPair struct {
	g        acceptedCarrier
	running  <-chan error
	accepted <-chan acceptedCarrier
}

func httpRequest(t *testing.T, method, uri string, body io.Reader) *http.Request {
	t.Helper()
	ctx := WithTargetService(t.Context(), "target-service")
	req, err := http.NewRequestWithContext(ctx, method, uri, body)
	must(t, err)
	return req
}

func verifyHTTPCall(t *testing.T, e *dialEnvironment, r *http.Request) {
	t.Helper()
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		t.Error("missing verified mTLS")
	}
	var headers []v1.Header
	for name, values := range r.Header {
		for _, value := range values {
			headers = append(headers, v1.Header{strings.ToLower(name), value})
		}
	}
	profile, _ := httpsig.New(httpsig.Config{Leg: httpsig.Call})
	key := serviceHTTPKey()
	verified, err := profile.Verify(httpsig.Request{Method: r.Method, Scheme: "https", Authority: r.Host, RawURI: r.RequestURI, Headers: headers}, key.ID, key.Secret, time.Now())
	if err != nil {
		t.Errorf("invalid outgoing signature: %v", err)
		return
	}
	if verified.Info().Caller != e.config.Register.ServiceID || verified.Info().Target != "target-service" {
		t.Error("wrong identity")
	}
	if r.Header.Get("X-Outgate-Context-Headers") != "[]" || r.Header.Get("X-User-ID") != "" || r.Header.Get("X-Outgate-Hop-Limit") != "8" {
		t.Error("not a background profile")
	}
	if r.Header.Get("X-Outgate-Deployment-Grant-ID") != strings.Split(string(grant(1)), ".")[0] {
		t.Error("wrong public grant ID")
	}
	if strings.Contains(r.Header.Get("X-Outgate-Deployment-Grant-ID"), ".") {
		t.Error("grant secret disclosed")
	}
}

func TestServiceHTTPBackgroundMTLSAndImmutableSignedRequest(t *testing.T) {
	e := dialEnv(t)
	seen := make(chan string, 1)
	server := serviceHTTPServer(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verifyHTTPCall(t, e, r)
		seen <- r.RequestURI
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("streamed"))
	}))
	key := serviceHTTPKey()
	config := ServiceHTTPConfig{ServerRoots: e.config.ServerRoots, SigningKey: key}
	c, _ := readyServiceHTTP(t, e, config)
	key.Secret[0] ^= 1 // Config takes independent ownership.
	httpClient, err := c.ServiceHTTPClient(server.URL)
	must(t, err)
	req := httpRequest(t, "GET", server.URL+"/%E2%82%AC?a=2&a=1&x=%2b", nil)
	req.Header["x-outgate-expected-route-revision"] = []string{"42"}
	req.Header.Set("Authorization", "Bearer application-only")
	original := req.Clone(req.Context())
	response, err := httpClient.Do(req)
	must(t, err)
	data, err := io.ReadAll(response.Body)
	must(t, err)
	must(t, response.Body.Close())
	if string(data) != "streamed" || await(t, seen) != "/%E2%82%AC?a=2&a=1&x=%2b" {
		t.Fatal("changed raw URI or body")
	}
	if !reflect.DeepEqual(req.Header, original.Header) || req.URL.String() != original.URL.String() || req.Close {
		t.Fatal("mutated caller request")
	}
}

func TestServiceHTTPReadyGateOriginsAndHeaderRejection(t *testing.T) {
	e := dialEnv(t)
	var hits atomic.Int32
	server := serviceHTTPServer(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(204) }))
	_, accepted := listen(t, e)
	cfg := ServiceHTTPConfig{ServerRoots: e.config.ServerRoots, SigningKey: serviceHTTPKey()}
	c, err := New(Config{QUIC: &e.config, ServiceHTTP: &cfg, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})})
	must(t, err)
	client, err := c.ServiceHTTPClient(server.URL)
	must(t, err)
	if _, err := client.Do(httpRequest(t, "GET", server.URL+"/", nil)); !errors.Is(err, ErrClientNotReady) {
		t.Fatal(err)
	}
	running := run(t, c, t.Context())
	g := await(t, accepted)
	must(t, g.err)
	receive(t, g.carrier, "status")
	for _, kind := range []string{"missing_target", "origin", "host", "userinfo", "raw_path", "reserved", "user", "signature", "upgrade", "trailer", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			req := httpRequest(t, "POST", server.URL+"/api", strings.NewReader("body"))
			switch kind {
			case "missing_target":
				req = req.WithContext(t.Context())
			case "origin":
				req.URL.Host = "other.example:443"
			case "host":
				req.Host = "other.example"
			case "userinfo":
				u, _ := url.Parse("https://user:secret@other.example")
				req.URL.User = u.User
			case "raw_path":
				req.URL.RawPath = "/different"
			case "reserved":
				req.Header.Set("X-Outgate-Caller-Service", "attacker")
			case "user":
				req.Header.Set("X-User-ID", "unverified")
			case "signature":
				req.Header.Set("Signature", "attacker=:YWJj:")
			case "upgrade":
				req.Header.Set("Connection", "Upgrade")
				req.Header.Set("Upgrade", "websocket")
			case "trailer":
				req.Trailer = http.Header{"X-Trailer": []string{"value"}}
			case "oversized":
				req.Header.Set("X-Large", strings.Repeat("a", 32768))
			}
			if _, err := client.Do(req); !errors.Is(err, &Error{Code: InvalidRequest}) {
				t.Fatal(err)
			}
		})
	}
	if hits.Load() != 0 {
		t.Fatal("rejected call sent to listener")
	}
	must(t, c.SetSecurity(false, time.Time{}))
	if _, err := client.Do(httpRequest(t, "GET", server.URL+"/", nil)); !errors.Is(err, ErrClientNotReady) {
		t.Fatal(err)
	}
	c.Revoke()
	if err := await(t, running); !errors.Is(err, &Error{Code: SecurityFailure}) {
		t.Fatal(err)
	}
	if _, err := client.Do(httpRequest(t, "GET", server.URL+"/", nil)); !errors.Is(err, ErrClientClosed) {
		t.Fatal(err)
	}
}

func TestServiceHTTPStreamingUploadAndResponse(t *testing.T) {
	e := dialEnv(t)
	uploadSeen, continueUpload := make(chan struct{}), make(chan struct{})
	server := serviceHTTPServer(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verifyHTTPCall(t, e, r)
		data := make([]byte, 1)
		if _, err := io.ReadFull(r.Body, data); err != nil {
			t.Error(err)
			return
		}
		close(uploadSeen)
		rest, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if string(data)+string(rest) != "ab" {
			t.Error("body changed")
		}
		_, _ = w.Write([]byte("first"))
		w.(http.Flusher).Flush()
		<-continueUpload
		_, _ = w.Write([]byte("last"))
	}))
	c, _ := readyServiceHTTP(t, e, ServiceHTTPConfig{ServerRoots: e.config.ServerRoots, SigningKey: serviceHTTPKey()})
	client, err := c.ServiceHTTPClient(server.URL)
	must(t, err)
	reader, writer := io.Pipe()
	responses := make(chan *http.Response, 1)
	failures := make(chan error, 1)
	go func() {
		response, err := client.Do(httpRequest(t, "POST", server.URL+"/api", reader))
		responses <- response
		failures <- err
	}()
	_, err = writer.Write([]byte("a"))
	must(t, err)
	await(t, uploadSeen)
	_, err = writer.Write([]byte("b"))
	must(t, err)
	must(t, writer.Close())
	response := await(t, responses)
	must(t, await(t, failures))
	first := make([]byte, 5)
	_, err = io.ReadFull(response.Body, first)
	must(t, err)
	if string(first) != "first" {
		t.Fatal("response buffered or changed")
	}
	close(continueUpload)
	data, err := io.ReadAll(response.Body)
	must(t, err)
	if string(data) != "last" {
		t.Fatal("missing stream tail")
	}
	must(t, response.Body.Close())
}

func TestServiceHTTPNoRedirectAndNoBusinessReplay(t *testing.T) {
	for _, method := range []string{"GET", "POST"} {
		t.Run(method, func(t *testing.T) {
			e := dialEnv(t)
			var hits atomic.Int32
			server := serviceHTTPServer(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if r.URL.Path == "/redirect" {
					w.Header().Set("Location", "/next")
					w.WriteHeader(307)
					return
				}
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
			}))
			c, _ := readyServiceHTTP(t, e, ServiceHTTPConfig{ServerRoots: e.config.ServerRoots, SigningKey: serviceHTTPKey()})
			client, err := c.ServiceHTTPClient(server.URL)
			must(t, err)
			response, err := client.Do(httpRequest(t, method, server.URL+"/redirect", strings.NewReader("payload")))
			must(t, err)
			if response.StatusCode != 307 || hits.Load() != 1 {
				t.Fatal("followed redirect")
			}
			_ = response.Body.Close()
			req := httpRequest(t, method, server.URL+"/disconnect", strings.NewReader("payload"))
			req.Header.Set("Idempotency-Key", "application-key")
			if _, err := client.Do(req); err == nil {
				t.Fatal("expected disconnect")
			}
			if hits.Load() != 2 {
				t.Fatal("request replayed")
			}
		})
	}
}

func TestServiceHTTPQuotaCancellationIdleAndShutdown(t *testing.T) {
	for _, mode := range []string{"request_cancel", "idle", "revoke", "close", "security_deadline"} {
		t.Run(mode, func(t *testing.T) {
			e := dialEnv(t)
			entered, serverCanceled := make(chan struct{}), make(chan struct{})
			server := serviceHTTPServer(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("one"))
				w.(http.Flusher).Flush()
				close(entered)
				<-r.Context().Done()
				close(serverCanceled)
			}))
			options := ServiceHTTPConfig{ServerRoots: e.config.ServerRoots, SigningKey: serviceHTTPKey(), MaxConcurrent: 1}
			if mode == "idle" {
				options.BodyIdleTimeout = 40 * time.Millisecond
			}
			c, pair := readyServiceHTTP(t, e, options)
			client, err := c.ServiceHTTPClient(server.URL)
			must(t, err)
			reqCtx, cancel := context.WithCancel(WithTargetService(t.Context(), "target-service"))
			defer cancel()
			req, err := http.NewRequestWithContext(reqCtx, "GET", server.URL+"/stream", nil)
			must(t, err)
			response, err := client.Do(req)
			must(t, err)
			await(t, entered)
			if _, err := client.Do(httpRequest(t, "GET", server.URL+"/quota", nil)); !errors.Is(err, &Error{Code: CallQuotaExceeded}) {
				t.Fatal(err)
			}
			switch mode {
			case "request_cancel":
				cancel()
			case "idle":
			case "revoke":
				c.Revoke()
			case "security_deadline":
				must(t, c.SetSecurity(true, time.Now().Add(60*time.Millisecond)))
			case "close":
				closed := make(chan error, 1)
				go func() {
					ctx, cancel := context.WithTimeout(t.Context(), 80*time.Millisecond)
					defer cancel()
					closed <- c.Close(ctx)
				}()
				acknowledgeDrain(t, pair.g.carrier)
				if err := await(t, closed); !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal(err)
				}
			}
			await(t, serverCanceled)
			_, readErr := io.ReadAll(response.Body)
			if readErr == nil {
				t.Fatal("stream did not abort")
			}
			_ = response.Body.Close()
			eventually(t, func() bool { c.http.mu.Lock(); defer c.http.mu.Unlock(); return len(c.http.active) == 0 })
		})
	}
}

func TestServiceHTTPTrustAndConstructionFailClosed(t *testing.T) {
	e := dialEnv(t)
	var hits atomic.Int32
	server := serviceHTTPServer(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(204) }))
	other := dialEnv(t)
	c, _ := readyServiceHTTP(t, e, ServiceHTTPConfig{ServerRoots: other.config.ServerRoots, SigningKey: serviceHTTPKey()})
	client, err := c.ServiceHTTPClient(server.URL)
	must(t, err)
	if _, err := client.Do(httpRequest(t, "GET", server.URL+"/", nil)); !errors.Is(err, &Error{Code: SecurityFailure}) {
		t.Fatal(err)
	}
	if hits.Load() != 0 {
		t.Fatal("unverified server received request")
	}
	for _, origin := range []string{"http://example.test", "https://example.test/api", "https://user:secret@example.test", "https://example.test?", "https://example.test#", "https://example.test:0"} {
		if _, err := c.ServiceHTTPClient(origin); !errors.Is(err, &Error{Code: InvalidConfig}) {
			t.Fatal("accepted invalid origin")
		}
	}
	for _, mode := range []string{"missing_roots", "missing_key", "bad_key_id", "oversize_key", "limit", "timeout", "custom_connect"} {
		t.Run(mode, func(t *testing.T) {
			config := ServiceHTTPConfig{ServerRoots: e.config.ServerRoots, SigningKey: serviceHTTPKey()}
			switch mode {
			case "missing_roots":
				config.ServerRoots = nil
			case "missing_key":
				config.SigningKey.Secret = nil
			case "bad_key_id":
				config.SigningKey.ID = "a\nb"
			case "oversize_key":
				config.SigningKey.Secret = make([]byte, 4097)
			case "limit":
				config.MaxConcurrent = 1001
			case "timeout":
				config.DialTimeout = 6 * time.Second
			}
			cfg := Config{QUIC: &e.config, ServiceHTTP: &config, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})}
			if mode == "custom_connect" {
				cfg.QUIC = nil
			}
			if _, err := New(cfg); !errors.Is(err, &Error{Code: InvalidConfig}) {
				t.Fatal("accepted invalid HTTP config")
			}
		})
	}
}

func TestServiceHTTPCredentialGenerationSwitchAndOldRequestRevoke(t *testing.T) {
	e := dialEnv(t)
	oldEntered, oldCanceled := make(chan struct{}), make(chan struct{})
	newIdentity := make(chan string, 1)
	server := serviceHTTPServer(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/old" {
			_, _ = w.Write([]byte("old"))
			w.(http.Flusher).Flush()
			close(oldEntered)
			<-r.Context().Done()
			close(oldCanceled)
			return
		}
		newIdentity <- r.TLS.PeerCertificates[0].SerialNumber.String() + ":" + r.Header.Get("X-Outgate-Deployment-Grant-ID")
		w.WriteHeader(204)
	}))
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	leaf, err := x509.ParseCertificate(e.snapshot.Certificate.Certificate[0])
	must(t, err)
	leaf.SerialNumber = big.NewInt(77)
	der, err := x509.CreateCertificate(rand.Reader, leaf, e.root, &newKey.PublicKey, e.rootKey)
	must(t, err)
	second := CredentialSnapshot{Certificate: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: newKey}, Credential: grant(2), Generation: 2}
	var sources atomic.Int32
	e.config.Credentials = func(context.Context) (CredentialSnapshot, error) {
		if sources.Add(1) == 1 {
			return e.snapshot, nil
		}
		return second, nil
	}
	c, pair := readyServiceHTTP(t, e, ServiceHTTPConfig{ServerRoots: e.config.ServerRoots, SigningKey: serviceHTTPKey()})
	client, err := c.ServiceHTTPClient(server.URL)
	must(t, err)
	response, err := client.Do(httpRequest(t, "GET", server.URL+"/old", nil))
	must(t, err)
	await(t, oldEntered)
	must(t, pair.g.carrier.Send(t.Context(), v1.Reconnect{Type: "reconnect", CommandID: 1, DeadlineMS: 2000, Code: "credential_rotation", Extensions: v1.QUICQuiescentFenceExtensions(0)}))
	u := receive(t, pair.g.carrier, "unregister").(v1.Unregister)
	must(t, pair.g.carrier.Send(t.Context(), v1.UnregisterAck{Type: "unregister_ack", CommandID: u.CommandID}))
	next := await(t, pair.accepted)
	must(t, next.err)
	receive(t, next.carrier, "status")
	fresh, err := client.Do(httpRequest(t, "GET", server.URL+"/new", nil))
	must(t, err)
	_ = fresh.Body.Close()
	if id := await(t, newIdentity); id != "77:"+strings.Split(string(grant(2)), ".")[0] {
		t.Fatal("new delivery used old credentials")
	}
	select {
	case <-oldCanceled:
		t.Fatal("rotation prematurely canceled old accepted HTTPS call")
	default:
	}
	c.Revoke()
	await(t, oldCanceled)
	_, err = io.ReadAll(response.Body)
	if err == nil {
		t.Fatal("old-generation stream survived revoke")
	}
	_ = response.Body.Close()
	if err := await(t, pair.running); !errors.Is(err, &Error{Code: SecurityFailure}) {
		t.Fatal(err)
	}
}

type countedHTTPBody struct {
	io.Reader
	closed atomic.Int32
}

func (b *countedHTTPBody) Close() error { b.closed.Add(1); return nil }

func TestServiceHTTPClosesRequestBodyOnceOnTransportError(t *testing.T) {
	e := dialEnv(t)
	server := serviceHTTPServer(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	c, _ := readyServiceHTTP(t, e, ServiceHTTPConfig{ServerRoots: e.config.ServerRoots, SigningKey: serviceHTTPKey()})
	client, err := c.ServiceHTTPClient(server.URL)
	must(t, err)
	body := &countedHTTPBody{Reader: strings.NewReader("payload")}
	if _, err := client.Do(httpRequest(t, "POST", server.URL+"/", body)); err == nil {
		t.Fatal("missing transport error")
	}
	eventually(t, func() bool { return body.closed.Load() > 0 })
	if n := body.closed.Load(); n != 1 {
		t.Fatalf("body closed %d times", n)
	}
}

func TestServiceHTTPGracefulCloseWaitsForAcceptedResponse(t *testing.T) {
	e := dialEnv(t)
	release := make(chan struct{})
	server := serviceHTTPServer(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("first"))
		w.(http.Flusher).Flush()
		select {
		case <-release:
			_, _ = w.Write([]byte("last"))
		case <-r.Context().Done():
			t.Error("graceful Close canceled accepted outgoing response")
		}
	}))
	c, pair := readyServiceHTTP(t, e, ServiceHTTPConfig{ServerRoots: e.config.ServerRoots, SigningKey: serviceHTTPKey()})
	client, err := c.ServiceHTTPClient(server.URL)
	must(t, err)
	response, err := client.Do(httpRequest(t, "GET", server.URL+"/", nil))
	must(t, err)
	closed := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		closed <- c.Close(ctx)
	}()
	acknowledgeDrain(t, pair.g.carrier)
	select {
	case <-c.Done():
		t.Fatal("Close skipped accepted HTTPS response")
	default:
	}
	if _, err := client.Do(httpRequest(t, "GET", server.URL+"/", nil)); !errors.Is(err, ErrClientClosed) {
		t.Fatal(err)
	}
	close(release)
	data, err := io.ReadAll(response.Body)
	must(t, err)
	_ = response.Body.Close()
	if string(data) != "firstlast" {
		t.Fatal("truncated response")
	}
	must(t, await(t, closed))
	must(t, await(t, pair.running))
}
