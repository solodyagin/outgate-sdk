package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
	"github.com/solodyagin/outgate-sdk/transport/quicsession"
)

type dialEnvironment struct {
	config   QUICConfig
	snapshot CredentialSnapshot
	server   tls.Certificate
	ack      v1.RegisterAck
	root     *x509.Certificate
	rootKey  *ecdsa.PrivateKey
}

func grant(generation byte) []byte {
	id, secret := make([]byte, 16), make([]byte, 32)
	id[0], secret[0] = generation, generation
	return []byte(base64.RawURLEncoding.EncodeToString(id) + "." + base64.RawURLEncoding.EncodeToString(secret))
}

func dialEnv(t *testing.T) *dialEnvironment {
	t.Helper()
	b, err := os.ReadFile("../tests/fixtures/protocol/v1/control-messages.json")
	must(t, err)
	var corpus struct{ Positive []json.RawMessage }
	must(t, json.Unmarshal(b, &corpus))
	e := &dialEnvironment{}
	for _, b := range corpus.Positive {
		var tag struct{ Type string }
		must(t, json.Unmarshal(b, &tag))
		switch tag.Type {
		case "register":
			e.config.Register, err = v1.DecodeRegister(b)
			must(t, err)
		case "register_ack":
			e.ack, err = v1.DecodeRegisterAck(b)
			must(t, err)
		}
	}
	e.config.Register.ProtocolMinor = 1
	e.config.Register.ReadinessCheckConfigured = false
	e.ack.Readiness.Required = false
	e.ack.ReadyNotBefore = time.Now().Add(-time.Second).Unix()
	expiry := time.Now().Add(20 * time.Minute).Unix()
	e.ack.CredentialExpiresAt = &expiry
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(2 * time.Hour), KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	must(t, err)
	root, err := x509.ParseCertificate(der)
	must(t, err)
	e.root, e.rootKey = root, key
	roots := x509.NewCertPool()
	roots.AddCert(root)
	e.config.ServerRoots, e.config.ClientRoots = roots, roots
	e.config.ServerName = "127.0.0.1"
	e.config.TrustDomain = "test.example"
	issue := func(id int64, server bool) tls.Certificate {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(t, err)
		leaf := &x509.Certificate{SerialNumber: big.NewInt(id), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
		if server {
			leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		} else {
			u, _ := url.Parse("spiffe://test.example/service/" + e.config.Register.ServiceID + "/instance/" + e.config.Register.InstanceID)
			leaf.URIs = []*url.URL{u}
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, root, &k.PublicKey, key)
		must(t, err)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
	}
	e.server = issue(2, true)
	e.snapshot = CredentialSnapshot{Certificate: issue(3, false), Credential: grant(1), Generation: 1}
	e.config.Session = quicsession.Options{SecurityReady: true} // Synthetic external security gate, not a durable production check.
	e.config.Credentials, err = StaticCredentials(e.snapshot)
	must(t, err)
	e.config.Address = "127.0.0.1:1"
	return e
}

type acceptedCarrier struct {
	carrier  *quiccontrol.Carrier
	register v1.Register
	err      error
}

func listen(t *testing.T, e *dialEnvironment) (*quic.Listener, <-chan acceptedCarrier) {
	t.Helper()
	development := e.config.Development
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{e.server}, NextProtos: []string{v1.QUICALPN}}
	if !development {
		serverTLS.ClientAuth = tls.RequireAndVerifyClientCert
		serverTLS.ClientCAs = e.config.ClientRoots
	}
	l, err := quic.ListenAddr("127.0.0.1:0", serverTLS, nil)
	must(t, err)
	e.config.Address = l.Addr().String()
	out := make(chan acceptedCarrier, 8)
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		var sequence byte
		for {
			conn, err := l.Accept(t.Context())
			if err != nil {
				return
			}
			sequence++
			var register v1.Register
			c, err := quiccontrol.Accept(t.Context(), conn, quiccontrol.Options{Development: development}, func(_ context.Context, peer tls.ConnectionState, credential []byte, r v1.Register) (v1.RegisterAck, error) {
				register = r
				if !development && (len(peer.VerifiedChains) == 0 || r.CredentialGeneration == nil || !bytes.Equal(credential, grant(byte(*r.CredentialGeneration)))) || development && (r.CredentialGeneration != nil || string(credential) != "dev-token") {
					return v1.RegisterAck{}, errors.New("denied")
				}
				a := e.ack
				a.ProtocolMinor = r.ProtocolMinor
				a.Capabilities = r.Capabilities
				a.RequiredCapabilities = r.RequiredCapabilities
				a.CredentialGeneration = r.CredentialGeneration
				var sid [16]byte
				sid[0] = sequence
				a.SessionID = base64.RawURLEncoding.EncodeToString(sid[:])
				return a, nil
			})
			if c != nil {
				t.Cleanup(func() { _ = c.Close() })
			}
			select {
			case out <- acceptedCarrier{c, register, err}:
			case <-t.Context().Done():
				return
			}
		}
	}()
	return l, out
}

func TestBuiltInDialerClientAndCredentialGenerationRotation(t *testing.T) {
	e := dialEnv(t)
	_, accepted := listen(t, e)
	var calls atomic.Uint64
	e.config.Credentials = func(ctx context.Context) (CredentialSnapshot, error) {
		if d, ok := ctx.Deadline(); !ok || time.Until(d) > 5*time.Second {
			t.Error("unbounded source")
		}
		s := e.snapshot
		s.Generation = calls.Add(1)
		s.Credential = grant(byte(s.Generation))
		return s, nil
	}
	c, err := New(Config{QUIC: &e.config, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})})
	must(t, err)
	if calls.Load() != 0 {
		t.Fatal("New invoked source")
	}
	// Caller-owned registration slices must not change the accepted identity.
	wantPath := e.config.Register.Paths[0]
	e.config.Register.Paths[0] = "/mutated"
	running := run(t, c, t.Context())
	g1 := await(t, accepted)
	must(t, g1.err)
	must(t, c.WaitReady(t.Context()))
	receive(t, g1.carrier, "status")
	if g1.register.Paths[0] != wantPath || *g1.register.CredentialGeneration != 1 {
		t.Fatal("incorrect registration snapshot")
	}
	must(t, g1.carrier.Send(t.Context(), v1.Reconnect{Type: "reconnect", CommandID: 1, DeadlineMS: 2000, Code: "credential_rotation", Extensions: v1.QUICQuiescentFenceExtensions(0)}))
	u := receive(t, g1.carrier, "unregister").(v1.Unregister)
	if calls.Load() != 1 {
		t.Fatal("source ran before old cleanup")
	}
	must(t, g1.carrier.Send(t.Context(), v1.UnregisterAck{Type: "unregister_ack", CommandID: u.CommandID}))
	g2 := await(t, accepted)
	must(t, g2.err)
	must(t, c.WaitReady(t.Context()))
	receive(t, g2.carrier, "status")
	if *g2.register.CredentialGeneration != 2 {
		t.Fatal("new generation not registered")
	}
	closed := make(chan error, 1)
	go func() { closed <- c.Close(t.Context()) }()
	acknowledgeDrain(t, g2.carrier)
	must(t, await(t, closed))
	must(t, await(t, running))
}

func TestSnapshotValidationBeforeDial(t *testing.T) {
	for _, scenario := range []string{"generation", "grant", "key", "san", "trust", "expiry_gate", "expired_cert", "future_cert", "empty_chain", "oversize"} {
		t.Run(scenario, func(t *testing.T) {
			e := dialEnv(t)
			switch scenario {
			case "generation":
				e.snapshot.Generation = 0
			case "grant":
				e.snapshot.Credential = []byte("private-invalid-grant")
			case "key":
				k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				must(t, err)
				e.snapshot.Certificate.PrivateKey = k
			case "san":
				e.config.TrustDomain = "wrong.example"
			case "trust":
				e.config.ClientRoots = x509.NewCertPool()
				e.config.ClientRoots.AddCert(&x509.Certificate{Raw: []byte{1}, RawSubject: []byte{1}})
			case "expiry_gate":
				e.config.Session.SecurityDeadline = time.Now().Add(-time.Second)
			case "expired_cert", "future_cert":
				leaf, err := x509.ParseCertificate(e.snapshot.Certificate.Certificate[0])
				must(t, err)
				if scenario == "expired_cert" {
					leaf.NotBefore = time.Now().Add(-time.Hour)
					leaf.NotAfter = time.Now().Add(-time.Minute)
				} else {
					leaf.NotBefore = time.Now().Add(time.Hour)
					leaf.NotAfter = time.Now().Add(2 * time.Hour)
				}
				der, err := x509.CreateCertificate(rand.Reader, leaf, e.root, leaf.PublicKey, e.rootKey)
				must(t, err)
				e.snapshot.Certificate.Certificate[0] = der
			case "empty_chain":
				e.snapshot.Certificate = tls.Certificate{}
			case "oversize":
				e.snapshot.Certificate.Certificate = [][]byte{make([]byte, 65537)}
			}
			e.config.Credentials = func(context.Context) (CredentialSnapshot, error) { return e.snapshot, nil }
			connect, err := NewQUICConnector(e.config)
			must(t, err)
			c, _, err := connect(t.Context())
			var safe *Error
			if c != nil || !errors.As(err, &safe) || safe.Code != SecurityFailure {
				t.Fatal("invalid snapshot reached dial", err)
			}
		})
	}
}

func TestTLSVerificationAndAckExpiry(t *testing.T) {
	for _, scenario := range []string{"name", "roots", "ack_expiry"} {
		t.Run(scenario, func(t *testing.T) {
			e := dialEnv(t)
			switch scenario {
			case "name":
				e.config.ServerName = "wrong.example"
			case "roots":
				e.config.ServerRoots = dialEnv(t).config.ServerRoots
			case "ack_expiry":
				late := time.Now().Add(90 * time.Minute).Unix()
				e.ack.CredentialExpiresAt = &late
			}
			_, accepted := listen(t, e)
			connect, err := NewQUICConnector(e.config)
			must(t, err)
			carrier, _, err := connect(t.Context())
			var safe *Error
			if carrier != nil || !errors.As(err, &safe) || safe.Code != SecurityFailure {
				t.Fatal("security check bypass", err)
			}
			if scenario == "ack_expiry" {
				g := await(t, accepted)
				must(t, g.err)
				await(t, g.carrier.Done())
			}
		})
	}
}

func TestCredentialSourceTimeoutPanicAndSingleSlot(t *testing.T) {
	e := dialEnv(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	e.config.SourceTimeout = 5 * time.Millisecond
	e.config.Credentials = func(context.Context) (CredentialSnapshot, error) {
		calls.Add(1)
		close(entered)
		<-release
		return e.snapshot, nil
	}
	connect, err := NewQUICConnector(e.config)
	must(t, err)
	first := make(chan error, 1)
	go func() { _, _, err := connect(t.Context()); first <- err }()
	await(t, entered)
	_, _, err = connect(t.Context())
	if !errors.Is(err, context.DeadlineExceeded) || calls.Load() != 1 {
		t.Fatal("callback slot not retained", err)
	}
	close(release)
	if err := await(t, first); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("late source result accepted", err)
	}
	e.config.Credentials = func(context.Context) (CredentialSnapshot, error) { panic("private panic text") }
	connect, err = NewQUICConnector(e.config)
	must(t, err)
	_, _, err = connect(t.Context())
	if err == nil || err.Error() != "outgate: callback_failed" {
		t.Fatal(err)
	}
	safe, retry := classify(err)
	if !retry || safe.Code != CallbackFailed {
		t.Fatal("source retry classification")
	}
}

func TestGenerationRollbackAndSameGenerationReplacement(t *testing.T) {
	for _, change := range []string{"rollback", "replacement"} {
		t.Run(change, func(t *testing.T) {
			e := dialEnv(t)
			_, accepted := listen(t, e)
			e.snapshot.Generation = 2
			e.snapshot.Credential = grant(2)
			var calls atomic.Int32
			e.config.Credentials = func(context.Context) (CredentialSnapshot, error) {
				s := e.snapshot
				if calls.Add(1) > 1 {
					if change == "rollback" {
						s.Generation = 1
						s.Credential = grant(1)
					} else {
						s.Credential = grant(3)
					}
				}
				return s, nil
			}
			connect, err := NewQUICConnector(e.config)
			must(t, err)
			c, _, err := connect(t.Context())
			must(t, err)
			g := await(t, accepted)
			must(t, g.err)
			must(t, c.Close())
			c, _, err = connect(t.Context())
			var safe *Error
			if c != nil || !errors.As(err, &safe) || safe.Code != SecurityFailure {
				t.Fatal("generation ledger bypass", err)
			}
		})
	}
}

func TestStaticCredentialCopiesAndConstructorValidation(t *testing.T) {
	e := dialEnv(t)
	source, err := StaticCredentials(e.snapshot)
	must(t, err)
	a, err := source(t.Context())
	must(t, err)
	a.Credential[0] = '!'
	a.Certificate.Certificate[0][0] = 0
	a.Certificate.PrivateKey.(*ecdsa.PrivateKey).D.SetInt64(1)
	b, err := source(t.Context())
	must(t, err)
	if !bytes.Equal(b.Credential, e.snapshot.Credential) || !bytes.Equal(b.Certificate.Certificate[0], e.snapshot.Certificate.Certificate[0]) || b.Certificate.PrivateKey.(*ecdsa.PrivateKey).D.Cmp(e.snapshot.Certificate.PrivateKey.(*ecdsa.PrivateKey).D) != 0 {
		t.Fatal("static source shared mutable data")
	}
	for _, mutate := range []func(*QUICConfig){func(c *QUICConfig) { c.ServerRoots = nil }, func(c *QUICConfig) { c.Address = "https://gateway.example:443" }, func(c *QUICConfig) { c.ServerName = "" }, func(c *QUICConfig) { c.SourceTimeout = 6 * time.Second }, func(c *QUICConfig) { c.TrustDomain = "bad/domain" }} {
		cfg := e.config
		mutate(&cfg)
		if _, err := NewQUICConnector(cfg); err == nil {
			t.Fatal("invalid dial config accepted")
		}
	}
	if _, err := New(Config{QUIC: &e.config, Connect: func(context.Context) (*quiccontrol.Carrier, quicsession.Options, error) {
		return nil, quicsession.Options{}, nil
	}, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})}); err == nil {
		t.Fatal("ambiguous connector accepted")
	}
}

func TestExplicitDevelopmentDialer(t *testing.T) {
	e := dialEnv(t)
	e.config.Development = true
	e.config.ClientRoots = nil
	e.config.TrustDomain = ""
	e.config.Credentials, _ = StaticCredentials(CredentialSnapshot{Credential: []byte("dev-token")})
	_, accepted := listen(t, e)
	if _, err := New(Config{QUIC: &e.config, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})}); err == nil {
		t.Fatal("implicit development mode accepted")
	}
	c, err := New(Config{QUIC: &e.config, Development: true, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})})
	must(t, err)
	running := run(t, c, t.Context())
	g := await(t, accepted)
	must(t, g.err)
	must(t, c.WaitReady(t.Context()))
	closed := make(chan error, 1)
	go func() { closed <- c.Close(t.Context()) }()
	acknowledgeDrain(t, g.carrier)
	must(t, await(t, closed))
	must(t, await(t, running))
}

func TestCredentialErrorsRetryOnlySourceUntilValid(t *testing.T) {
	e := dialEnv(t)
	_, accepted := listen(t, e)
	var calls atomic.Int32
	e.config.Credentials = func(context.Context) (CredentialSnapshot, error) {
		switch calls.Add(1) {
		case 1:
			panic("private source panic")
		case 2:
			return CredentialSnapshot{}, errors.New("private store diagnostic")
		}
		return e.snapshot, nil
	}
	c, err := New(Config{QUIC: &e.config, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), BackoffMin: time.Millisecond, BackoffMax: 2 * time.Millisecond})
	must(t, err)
	running := run(t, c, t.Context())
	g := await(t, accepted)
	must(t, g.err)
	must(t, c.WaitReady(t.Context()))
	if calls.Load() != 3 {
		t.Fatal("unexpected source attempts", calls.Load())
	}
	closed := make(chan error, 1)
	go func() { closed <- c.Close(t.Context()) }()
	acknowledgeDrain(t, g.carrier)
	must(t, await(t, closed))
	must(t, await(t, running))
	for _, cause := range []error{v1.ErrProtocol, &Error{Code: SecurityFailure}} {
		_, retry := classify(&credentialError{cause: cause})
		if retry {
			t.Fatal("credential wrapper overrode terminal failure")
		}
	}
}

func TestGrantCanonicalBoundaries(t *testing.T) {
	encode := func(id, secret int) []byte {
		return []byte(base64.RawURLEncoding.EncodeToString(make([]byte, id)) + "." + base64.RawURLEncoding.EncodeToString(make([]byte, secret)))
	}
	for _, value := range [][]byte{encode(16, 32), encode(96, 192)} {
		if !validGrant(value) {
			t.Fatal("valid boundary rejected")
		}
	}
	for _, value := range [][]byte{nil, encode(15, 32), encode(16, 31), encode(97, 32), encode(16, 193), append(grant(1), '='), append(grant(1), '.'), append([]byte("\n"), grant(1)...), []byte("秘密"), bytes.Repeat([]byte{'A'}, 4097)} {
		if validGrant(value) {
			t.Fatal("invalid credential accepted")
		}
	}
	noncanonical := grant(1)
	noncanonical[len(noncanonical)-1] = 'B'
	if validGrant(noncanonical) {
		t.Fatal("noncanonical trailing base64 bits accepted")
	}
}

func TestSoftwareKeyCopies(t *testing.T) {
	e := dialEnv(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	must(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	for _, key := range []any{rsaKey, edKey} {
		s := e.snapshot
		s.Certificate.PrivateKey = key
		source, err := StaticCredentials(s)
		must(t, err)
		a, err := source(t.Context())
		must(t, err)
		b, err := source(t.Context())
		must(t, err)
		switch k := a.Certificate.PrivateKey.(type) {
		case *rsa.PrivateKey:
			k.D.SetInt64(1)
			if b.Certificate.PrivateKey.(*rsa.PrivateKey).D.Cmp(rsaKey.D) != 0 {
				t.Fatal("RSA key shared")
			}
		case ed25519.PrivateKey:
			k[0] ^= 1
			if !bytes.Equal(b.Certificate.PrivateKey.(ed25519.PrivateKey), edKey) {
				t.Fatal("Ed25519 key shared")
			}
		}
	}
}

func FuzzGrantCredential(f *testing.F) {
	for _, seed := range [][]byte{grant(1), nil, []byte("a.b"), bytes.Repeat([]byte{'A'}, 4097)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value []byte) { _ = validGrant(value) })
}
