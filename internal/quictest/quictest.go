// Package quictest supplies verified loopback connections and fixtures for SDK tests.
package quictest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/quic-go/quic-go"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"math/big"
	"net"
	"os"
	"testing"
	"time"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func Fixtures(t *testing.T, production bool) (v1.Register, v1.RegisterAck) {
	t.Helper()
	b, err := os.ReadFile("../../tests/fixtures/protocol/v1/control-messages.json")
	must(t, err)
	var corpus struct{ Positive []json.RawMessage }
	must(t, json.Unmarshal(b, &corpus))
	var reg v1.Register
	var ack v1.RegisterAck
	for _, b := range corpus.Positive {
		var tag struct{ Type string }
		must(t, json.Unmarshal(b, &tag))
		switch tag.Type {
		case "register":
			reg, err = v1.DecodeRegister(b)
			must(t, err)
		case "register_ack":
			ack, err = v1.DecodeRegisterAck(b)
			must(t, err)
		}
	}
	if production {
		expiry := time.Now().Add(time.Hour).Unix()
		ack.CredentialExpiresAt = &expiry
	}
	must(t, ack.ValidateForRegister(reg, v1.RegisterAckValidationOptions{Development: !production}))
	return reg, ack
}

func Pair(t *testing.T, mutual bool, alpn string) (*quic.Conn, *quic.Conn) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	must(t, err)
	cert, err := x509.ParseCertificate(der)
	must(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, NextProtos: []string{alpn}}
	clientTLS := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "127.0.0.1", NextProtos: []string{alpn}}
	if mutual {
		serverTLS.ClientAuth = tls.RequireAndVerifyClientCert
		serverTLS.ClientCAs = roots
		clientTLS.Certificates = []tls.Certificate{certificate}
	}
	// Small native stream windows exercise write backpressure without large data.
	config := &quic.Config{MaxIdleTimeout: 45 * time.Second, KeepAlivePeriod: 15 * time.Second,
		InitialStreamReceiveWindow: 32 * 1024, MaxStreamReceiveWindow: 32 * 1024}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, config)
	must(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	service, err := quic.DialAddr(ctx, listener.Addr().String(), clientTLS, config)
	must(t, err)
	t.Cleanup(func() { _ = service.CloseWithError(quic.ApplicationErrorCode(0x4f475400), "normal") })
	gateway, err := listener.Accept(ctx)
	must(t, err)
	t.Cleanup(func() { _ = gateway.CloseWithError(quic.ApplicationErrorCode(0x4f475400), "normal") })
	return service, gateway
}
