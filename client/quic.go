package client

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
	"github.com/solodyagin/outgate-sdk/transport/quicsession"
)

// QUICConfig has explicit trust and one credential source. There is no custom
// tls.Config, ambient system trust, 0-RTT, or transport/security fallback.
type QUICConfig struct {
	Address, ServerName, TrustDomain            string
	ServerRoots, ClientRoots                    *x509.CertPool
	Register                                    v1.Register
	Credentials                                 CredentialSource
	Development                                 bool
	SourceTimeout, DialTimeout, RegisterTimeout time.Duration
	Session                                     quicsession.Options
}

type credentialError struct {
	cause error
	code  Code
}

func (e *credentialError) Error() string {
	code := e.code
	if code == "" {
		code = CredentialUnavailable
	}
	return "outgate: " + string(code)
}
func (e *credentialError) Unwrap() error { return e.cause }

// NewQUICConnector validates/copies config without I/O or goroutines. Each call
// obtains a whole new snapshot, verifies it, dials and registers on native QUIC.
// The one source slot stays occupied until an uncooperative invocation returns.
func NewQUICConnector(config QUICConfig) (Connect, error) {
	invalid := func() (Connect, error) { return nil, &Error{Code: InvalidConfig} }
	host, port, err := net.SplitHostPort(config.Address)
	number, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || host == "" || portErr != nil || number == 0 || config.ServerName == "" || strings.ContainsAny(config.ServerName, "/*@?#\\ \r\n\t") || config.Credentials == nil || config.ServerRoots == nil || len(config.ServerRoots.Subjects()) == 0 {
		return invalid()
	}
	if !config.Development && (config.ClientRoots == nil || len(config.ClientRoots.Subjects()) == 0 || !validTrustDomain(config.TrustDomain)) {
		return invalid()
	}
	if config.SourceTimeout == 0 {
		config.SourceTimeout = 5 * time.Second
	}
	if config.DialTimeout == 0 {
		config.DialTimeout = 5 * time.Second
	}
	if config.RegisterTimeout == 0 {
		config.RegisterTimeout = 10 * time.Second
	}
	if config.SourceTimeout <= 0 || config.SourceTimeout > 5*time.Second || config.DialTimeout <= 0 || config.DialTimeout > 10*time.Second || config.RegisterTimeout <= 0 || config.RegisterTimeout > 10*time.Second {
		return invalid()
	}
	if config.Session.MaxCommands < 0 || config.Session.MaxCommands > 2048 || config.Session.TickInterval < 0 || config.Session.TickInterval > time.Second {
		return invalid()
	}
	b, err := json.Marshal(config.Register)
	if err != nil {
		return invalid()
	}
	r, err := v1.DecodeRegister(b)
	if err != nil || r.ProtocolMinor < 1 || r.CredentialGeneration != nil || r.ReadinessCheckConfigured != (config.Session.ReadinessCheck != nil) {
		return invalid()
	}
	for _, capability := range []string{v1.QUICQuiescentFenceCapability, "credential_generation"} {
		if config.Development && capability == "credential_generation" {
			continue
		}
		if !contains(r.Capabilities, capability) {
			r.Capabilities = append(r.Capabilities, capability)
		}
		if !contains(r.RequiredCapabilities, capability) {
			r.RequiredCapabilities = append(r.RequiredCapabilities, capability)
		}
	}
	if r.Validate() != nil {
		return invalid()
	}
	config.ServerRoots = config.ServerRoots.Clone()
	if config.ClientRoots != nil {
		config.ClientRoots = config.ClientRoots.Clone()
	}
	encoded, _ := json.Marshal(r)
	slot := make(chan struct{}, 1)
	var highWater uint64
	var fingerprint [32]byte
	return func(parent context.Context) (carrier *quiccontrol.Carrier, options quicsession.Options, err error) {
		// Serializes the source and its generation ledger, including standalone
		// concurrent Connect calls. Waiting callers don't spawn source goroutines.
		ctx, cancel := context.WithTimeout(parent, config.SourceTimeout)
		defer cancel()
		select {
		case slot <- struct{}{}:
		case <-ctx.Done():
			return nil, options, &credentialError{cause: ctx.Err()}
		}
		defer func() { <-slot }()
		if ctx.Err() != nil {
			return nil, options, &credentialError{cause: ctx.Err()}
		}
		var conn *quic.Conn
		defer func() {
			if recover() != nil {
				if conn != nil {
					_ = conn.CloseWithError(quiccontrol.CodeProtocol, "protocol_error")
				}
				if carrier != nil {
					_ = carrier.Abort()
				}
				carrier = nil
				err = &Error{Code: SecurityFailure}
			}
		}()
		snapshot, sourceErr := callCredentialSource(ctx, config.Credentials)
		if deadline, _ := ctx.Deadline(); ctx.Err() != nil || !time.Now().Before(deadline) {
			cause := ctx.Err()
			if cause == nil {
				cause = context.DeadlineExceeded
			}
			return nil, options, &credentialError{cause: cause}
		}
		if sourceErr != nil {
			var safe *Error
			if errors.As(sourceErr, &safe) {
				return nil, options, safe
			}
			var unavailable *credentialError
			if errors.As(sourceErr, &unavailable) {
				return nil, options, unavailable
			}
			return nil, options, &credentialError{cause: sourceErr}
		}
		snapshot, err = copyCredentials(snapshot)
		if err != nil {
			return nil, options, err
		}
		defer clear(snapshot.Credential)
		register, _ := v1.DecodeRegister(encoded)
		deadline, err := validateSnapshot(snapshot, register, config)
		if err != nil {
			return nil, options, err
		}
		if !config.Development {
			digest := snapshotFingerprint(snapshot)
			if snapshot.Generation < highWater || snapshot.Generation == highWater && digest != fingerprint {
				return nil, options, &Error{Code: SecurityFailure}
			}
			highWater, fingerprint = snapshot.Generation, digest
			generation := v1.U64(snapshot.Generation)
			register.CredentialGeneration = &generation
		}
		if !config.Session.SecurityDeadline.IsZero() && !time.Now().Before(config.Session.SecurityDeadline) {
			return nil, options, &Error{Code: SecurityFailure}
		}
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: config.ServerRoots, ServerName: config.ServerName, NextProtos: []string{v1.QUICALPN}, SessionTicketsDisabled: true}
		if len(snapshot.Certificate.Certificate) != 0 {
			tlsConfig.Certificates = []tls.Certificate{snapshot.Certificate}
		}
		dialCtx, cancelDial := context.WithTimeout(parent, config.DialTimeout)
		// quic.DialAddr resolves names without ctx in this pinned version. Resolve
		// with our deadline first, then pass a literal endpoint to its owned socket.
		addresses, resolveErr := net.DefaultResolver.LookupIPAddr(dialCtx, host)
		if resolveErr != nil {
			cancelDial()
			return nil, options, resolveErr
		}
		if len(addresses) == 0 || len(addresses) > 64 {
			cancelDial()
			return nil, options, &Error{Code: TransportFailure}
		}
		endpoint := net.JoinHostPort(addresses[0].String(), port)
		conn, err = quic.DialAddr(dialCtx, endpoint, tlsConfig, &quic.Config{HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 45 * time.Second, KeepAlivePeriod: 15 * time.Second})
		cancelDial()
		if err != nil {
			var verification *tls.CertificateVerificationError
			var transport *quic.TransportError
			if errors.As(err, &verification) || errors.As(err, &transport) && uint64(transport.ErrorCode) >= 0x100 && uint64(transport.ErrorCode) <= 0x1ff {
				return nil, options, &Error{Code: SecurityFailure, cause: err}
			}
			return nil, options, err
		}
		// All post-dial failure paths own and close the physical connection.
		defer func() {
			if err != nil {
				_ = conn.CloseWithError(quiccontrol.CodeProtocol, "protocol_error")
			}
		}()
		carrier, ack, err := quiccontrol.Open(parent, conn, quiccontrol.Options{Development: config.Development, RegisterTimeout: config.RegisterTimeout}, snapshot.Credential, register)
		if err != nil {
			return nil, options, err
		}
		now := time.Now()
		if !deadline.IsZero() && !now.Before(deadline) || !config.Session.SecurityDeadline.IsZero() && !now.Before(config.Session.SecurityDeadline) || ack.CredentialExpiresAt != nil && !now.Before(time.Unix(*ack.CredentialExpiresAt, 0)) {
			_ = carrier.Revoke()
			return nil, options, &Error{Code: SecurityFailure}
		}
		if !config.Development && (ack.CredentialExpiresAt == nil || *ack.CredentialExpiresAt > snapshot.Certificate.Leaf.NotAfter.Unix()) {
			_ = carrier.Revoke()
			return nil, options, &Error{Code: SecurityFailure}
		}
		options = config.Session
		if !deadline.IsZero() && (options.SecurityDeadline.IsZero() || deadline.Before(options.SecurityDeadline)) {
			options.SecurityDeadline = deadline
		}
		return carrier, options, nil
	}, nil
}

func callCredentialSource(ctx context.Context, source CredentialSource) (snapshot CredentialSnapshot, err error) {
	defer func() {
		if recover() != nil {
			snapshot = CredentialSnapshot{}
			err = &credentialError{cause: errors.New("callback_failed"), code: CallbackFailed}
		}
	}()
	return source(ctx)
}

func validateSnapshot(s CredentialSnapshot, r v1.Register, c QUICConfig) (time.Time, error) {
	bad := func() (time.Time, error) { return time.Time{}, &Error{Code: SecurityFailure} }
	if c.Development {
		if s.Generation != 0 || len(s.Certificate.Certificate) != 0 {
			return bad()
		}
		for _, b := range s.Credential {
			if b <= 32 || b == 127 {
				return bad()
			}
		}
		return time.Time{}, nil
	}
	if s.Generation == 0 || !validGrant(s.Credential) || s.Certificate.Leaf == nil {
		return bad()
	}
	leaf := s.Certificate.Leaf
	expected := (&url.URL{Scheme: "spiffe", Host: c.TrustDomain, Path: "/service/" + r.ServiceID + "/instance/" + r.InstanceID}).String()
	if leaf.IsCA || len(leaf.URIs) != 1 || leaf.URIs[0].String() != expected || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return bad()
	}
	signer, ok := s.Certificate.PrivateKey.(crypto.Signer)
	if !ok {
		return bad()
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(public, leaf.RawSubjectPublicKeyInfo) {
		return bad()
	}
	intermediates := x509.NewCertPool()
	for _, der := range s.Certificate.Certificate[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return bad()
		}
		intermediates.AddCert(cert)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: c.ClientRoots, Intermediates: intermediates, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return bad()
	}
	deadline := leaf.NotAfter
	for _, chain := range chains {
		for _, cert := range chain {
			if cert.NotAfter.Before(deadline) {
				deadline = cert.NotAfter
			}
		}
	}
	return deadline, nil
}

func snapshotFingerprint(s CredentialSnapshot) [32]byte {
	h := sha256.New()
	var size [8]byte
	for _, part := range append([][]byte{s.Credential}, s.Certificate.Certificate...) {
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		_, _ = h.Write(size[:])
		_, _ = h.Write(part)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func validTrustDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, b := range []byte(label) {
			if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
				return false
			}
		}
	}
	return true
}
