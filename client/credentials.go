package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"strings"
	"unicode/utf8"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

// CredentialSnapshot is one immutable certificate/key + opaque credential pair.
// Production requires a positive generation bound into the grant by its issuer.
// Development explicitly uses a bearer, no certificate and generation zero.
type CredentialSnapshot struct {
	Certificate tls.Certificate
	Credential  []byte
	Generation  uint64
}

// CredentialSource must honor ctx and not mutate a published pair. The dialer
// copies supported software private keys; hardware signers are not supported yet.
type CredentialSource func(context.Context) (CredentialSnapshot, error)

// StaticCredentials takes an owned copy without I/O. Every invocation returns
// another copy. X.509 identity/trust/expiry is checked by the dialer each time.
func StaticCredentials(snapshot CredentialSnapshot) (CredentialSource, error) {
	copy, err := copyCredentials(snapshot)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context) (CredentialSnapshot, error) {
		if err := ctx.Err(); err != nil {
			return CredentialSnapshot{}, err
		}
		return copyCredentials(copy)
	}, nil
}

func copyCredentials(in CredentialSnapshot) (CredentialSnapshot, error) {
	bad := func() (CredentialSnapshot, error) { return CredentialSnapshot{}, &Error{Code: SecurityFailure} }
	if len(in.Credential) == 0 || len(in.Credential) > v1.MaxCredentialBytes || !utf8.Valid(in.Credential) {
		return bad()
	}
	if len(in.Certificate.Certificate) > 8 {
		return bad()
	}
	total := 0
	for _, der := range in.Certificate.Certificate {
		if len(der) == 0 || len(der) > 64*1024-total {
			return bad()
		}
		total += len(der)
	}
	out := CredentialSnapshot{Generation: in.Generation}
	if len(in.Certificate.Certificate) == 0 {
		if in.Certificate.PrivateKey != nil {
			return bad()
		}
		out.Credential = bytes.Clone(in.Credential)
		return out, nil
	}
	// Bound key encoding before allocation and accept only independently cloned
	// standard software keys. No caller-owned crypto.Signer enters TLS callbacks.
	var privateKey any
	switch k := in.Certificate.PrivateKey.(type) {
	case *rsa.PrivateKey:
		if k == nil || k.N == nil || k.D == nil || k.D.Sign() <= 0 || k.D.BitLen() > 8192 || k.N.BitLen() < 2048 || k.N.BitLen() > 8192 || len(k.Primes) != 2 {
			return bad()
		}
		copy := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: new(big.Int).Set(k.N), E: k.E}, D: new(big.Int).Set(k.D)}
		for _, p := range k.Primes {
			if p == nil || p.Sign() <= 0 || p.BitLen() > 8192 {
				return bad()
			}
			copy.Primes = append(copy.Primes, new(big.Int).Set(p))
		}
		if copy.Validate() != nil {
			return bad()
		}
		privateKey = copy
	case *ecdsa.PrivateKey:
		if k == nil || k.D == nil || k.Curve != elliptic.P256() && k.Curve != elliptic.P384() && k.Curve != elliptic.P521() {
			return bad()
		}
		if k.X == nil || k.Y == nil || k.X.Sign() < 0 || k.Y.Sign() < 0 || k.X.BitLen() > k.Curve.Params().BitSize || k.Y.BitLen() > k.Curve.Params().BitSize || k.D.Sign() <= 0 || k.D.Cmp(k.Curve.Params().N) >= 0 || !k.Curve.IsOnCurve(k.X, k.Y) {
			return bad()
		}
		x, y := k.Curve.ScalarBaseMult(k.D.Bytes())
		if x.Cmp(k.X) != 0 || y.Cmp(k.Y) != 0 {
			return bad()
		}
		privateKey = &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: k.Curve, X: new(big.Int).Set(k.X), Y: new(big.Int).Set(k.Y)}, D: new(big.Int).Set(k.D)}
	case ed25519.PrivateKey:
		if len(k) != ed25519.PrivateKeySize {
			return bad()
		}
		privateKey = ed25519.PrivateKey(bytes.Clone(k))
	default:
		return bad()
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return bad()
	}
	defer clear(keyBytes)
	key, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return bad()
	}
	out.Certificate.PrivateKey = key
	for _, der := range in.Certificate.Certificate {
		out.Certificate.Certificate = append(out.Certificate.Certificate, bytes.Clone(der))
	}
	leaf, err := x509.ParseCertificate(out.Certificate.Certificate[0])
	if err != nil {
		return bad()
	}
	out.Certificate.Leaf = leaf
	out.Credential = bytes.Clone(in.Credential)
	return out, nil
}

func validGrant(credential []byte) bool {
	if len(credential) < 66 || len(credential) > 385 {
		return false
	}
	parts := strings.Split(string(credential), ".")
	if len(parts) != 2 || len(parts[0]) < 22 || len(parts[0]) > 128 || len(parts[1]) < 43 || len(parts[1]) > 256 {
		return false
	}
	for i, p := range parts {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(p)
		if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != p || len(decoded) < []int{16, 32}[i] {
			clear(decoded)
			return false
		}
		clear(decoded)
	}
	return true
}
