package client

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fileSourceFixture(t *testing.T) (string, map[string]string, *dialEnvironment) {
	t.Helper()
	e := dialEnv(t)
	dir := t.TempDir()
	key, err := x509.MarshalPKCS8PrivateKey(e.snapshot.Certificate.PrivateKey)
	must(t, err)
	defer clear(key)
	must(t, os.WriteFile(filepath.Join(dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.snapshot.Certificate.Certificate[0]}), 0600))
	must(t, os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600))
	must(t, os.WriteFile(filepath.Join(dir, "grant"), e.snapshot.Credential, 0600))
	manifest := map[string]string{"generation": "1", "certificate_file": "cert.pem", "private_key_file": "key.pem", "deployment_grant_file": "grant"}
	writeManifest(t, dir, manifest)
	return dir, manifest, e
}

func writeManifest(t *testing.T, dir string, manifest map[string]string) {
	t.Helper()
	b, err := json.Marshal(manifest)
	must(t, err)
	must(t, os.WriteFile(filepath.Join(dir, "next.json"), b, 0600))
	must(t, os.Rename(filepath.Join(dir, "next.json"), filepath.Join(dir, "manifest.json")))
}

func TestFileCredentialsAtomicGenerationAndOwnership(t *testing.T) {
	dir, manifest, e := fileSourceFixture(t)
	source, err := FileCredentials(dir, "manifest.json")
	must(t, err)
	first, err := source(t.Context())
	must(t, err)
	if first.Generation != 1 || !bytes.Equal(first.Credential, e.snapshot.Credential) {
		t.Fatal("wrong snapshot")
	}
	if _, err := validateSnapshot(first, e.config.Register, e.config); err != nil {
		t.Fatal(err)
	}
	first.Credential[0] ^= 1
	first.Certificate.Certificate[0][0] ^= 1
	first.Certificate.PrivateKey = nil
	second, err := source(t.Context())
	must(t, err)
	if !bytes.Equal(second.Credential, e.snapshot.Credential) || !bytes.Equal(second.Certificate.Certificate[0], e.snapshot.Certificate.Certificate[0]) {
		t.Fatal("aliased result")
	}
	// Publish a complete generation through a single manifest replacement.
	must(t, os.WriteFile(filepath.Join(dir, "grant2"), grant(2), 0600))
	manifest["generation"], manifest["deployment_grant_file"] = "2", "grant2"
	writeManifest(t, dir, manifest)
	next, err := source(t.Context())
	must(t, err)
	if next.Generation != 2 || !bytes.Equal(next.Credential, grant(2)) {
		t.Fatal("stale generation")
	}
	if !bytes.Equal(second.Credential, grant(1)) {
		t.Fatal("old snapshot changed")
	}
	// Absolute references are supported; relative references use root, not the manifest directory.
	manifest["certificate_file"] = filepath.Join(dir, "cert.pem")
	writeManifest(t, dir, manifest)
	_, err = source(t.Context())
	must(t, err)
}

func TestCredentialManifestStrictSchema(t *testing.T) {
	valid := `{"generation":"18446744073709551615","certificate_file":"cert","private_key_file":"key","deployment_grant_file":"grant"}`
	n, _, err := decodeCredentialManifest([]byte(valid))
	must(t, err)
	if n != ^uint64(0) {
		t.Fatal(n)
	}
	for _, replacement := range []string{`"0"`, `"01"`, `"+1"`, `"18446744073709551616"`, `1`, `null`, `true`, `""`} {
		t.Run("generation_"+replacement, func(t *testing.T) {
			_, _, err := decodeCredentialManifest([]byte(strings.Replace(valid, `"18446744073709551615"`, replacement, 1)))
			if err == nil {
				t.Fatal("accepted invalid generation")
			}
		})
	}
	cases := []string{
		strings.Replace(valid, `"generation"`, `"Generation"`, 1),
		strings.Replace(valid, `"cert"`, `null`, 1),
		strings.Replace(valid, `"cert"`, `" "`, 1),
		strings.Replace(valid, `"cert"`, `"a\u0080"`, 1),
		strings.Replace(valid, `"cert"`, `"\ud800"`, 1),
		strings.Replace(valid, `"cert"`, `"`+strings.Repeat("a", 4097)+`"`, 1),
		valid[:len(valid)-1] + `,"extra":1}`,
		valid[:len(valid)-1] + `,"generation":"2"}`,
		valid + `{}`, `[]`, `{}`, string([]byte{0xff}),
	}
	for i, data := range cases {
		if _, _, err := decodeCredentialManifest([]byte(data)); err == nil {
			t.Fatalf("accepted case %d", i)
		}
	}
	// JSON escaping does not change manifest string semantics.
	_, _, err = decodeCredentialManifest([]byte(strings.Replace(valid, `"18446744073709551615"`, `"\u0031"`, 1)))
	must(t, err)
}

func TestFileCredentialsRejectPartialAndUnsafeFiles(t *testing.T) {
	for _, tc := range []struct {
		name, file string
		data       []byte
	}{
		{"missing", "grant", nil},
		{"empty", "grant", []byte{}},
		{"oversize grant", "grant", bytes.Repeat([]byte("a"), 386)},
		{"grant newline", "grant", append(grant(1), '\n')},
		{"bad key", "key.pem", []byte("private secret")},
		{"oversize key", "key.pem", bytes.Repeat([]byte("a"), 32*1024+1)},
		{"bad cert", "cert.pem", []byte("not a certificate")},
		{"oversize cert", "cert.pem", bytes.Repeat([]byte("a"), 96*1024+1)},
		{"bad manifest", "manifest.json", []byte(`{"generation":"1"}`)},
		{"oversize manifest", "manifest.json", bytes.Repeat([]byte("a"), 65537)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, _, _ := fileSourceFixture(t)
			name := filepath.Join(dir, tc.file)
			if tc.data == nil {
				must(t, os.Remove(name))
			} else {
				must(t, os.WriteFile(name, tc.data, 0600))
			}
			source, err := FileCredentials(dir, "manifest.json")
			must(t, err)
			s, err := source(t.Context())
			if err == nil || len(s.Credential) != 0 || s.Generation != 0 {
				t.Fatal("accepted partial pair")
			}
			for current := err; current != nil; current = errors.Unwrap(current) {
				if strings.Contains(current.Error(), dir) || strings.Contains(current.Error(), "private secret") {
					t.Fatal("leaked source data")
				}
			}
			safe, retry := classify(err)
			if !retry || safe.Code != CredentialUnavailable {
				t.Fatal("not retryable source failure")
			}
		})
	}
	t.Run("key mismatch", func(t *testing.T) {
		dir, _, _ := fileSourceFixture(t)
		other := dialEnv(t)
		key, err := x509.MarshalPKCS8PrivateKey(other.snapshot.Certificate.PrivateKey)
		must(t, err)
		must(t, os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600))
		source, err := FileCredentials(dir, "manifest.json")
		must(t, err)
		if _, err := source(t.Context()); err == nil {
			t.Fatal("accepted mismatched key")
		}
	})
	t.Run("directory", func(t *testing.T) {
		dir, manifest, _ := fileSourceFixture(t)
		manifest["private_key_file"] = dir
		writeManifest(t, dir, manifest)
		source, err := FileCredentials(dir, "manifest.json")
		must(t, err)
		if _, err := source(t.Context()); err == nil {
			t.Fatal("accepted directory")
		}
	})
}

func TestFileCredentialsConstructorAndCancellation(t *testing.T) {
	// Construction succeeds before deployment has written any files.
	source, err := FileCredentials(t.TempDir(), "absent.json")
	must(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := source(ctx); err == nil {
		t.Fatal("ignored cancellation")
	}
	for _, path := range []string{"", " ", "a\x00b", "a\nb", string([]byte{0xff})} {
		if _, err := FileCredentials(path, "manifest.json"); err == nil {
			t.Fatal("invalid root")
		}
		if _, err := FileCredentials(".", path); err == nil {
			t.Fatal("invalid manifest")
		}
	}
}

func TestFileCredentialsRejectAmbiguousPEM(t *testing.T) {
	dir, _, _ := fileSourceFixture(t)
	cert, err := os.ReadFile(filepath.Join(dir, "cert.pem"))
	must(t, err)
	key, err := os.ReadFile(filepath.Join(dir, "key.pem"))
	must(t, err)
	for _, data := range [][]byte{append([]byte("garbage\n"), cert...), bytes.Repeat(cert, 9), append([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n"), cert...), append(bytes.Clone(cert), []byte("garbage")...)} {
		if validCertificatePEM(data) {
			t.Fatal("accepted ambiguous certificate PEM")
		}
	}
	for _, data := range [][]byte{append([]byte("garbage\n"), key...), append(bytes.Clone(key), key...), append([]byte("-----BEGIN PRIVATE KEY-----\ninvalid\n"), key...), append(bytes.Clone(key), []byte("garbage")...)} {
		if validPrivateKeyPEM(data) {
			t.Fatal("accepted ambiguous private key PEM")
		}
	}
}

func TestFileCredentialsNativeQUIC(t *testing.T) {
	dir, manifest, e := fileSourceFixture(t)
	source, err := FileCredentials(dir, "manifest.json")
	must(t, err)
	e.config.Credentials = source
	_, accepted := listen(t, e)
	connector, err := NewQUICConnector(e.config)
	must(t, err)
	carrier, _, err := connector(t.Context())
	must(t, err)
	remote := <-accepted
	must(t, remote.err)
	if remote.register.CredentialGeneration == nil || *remote.register.CredentialGeneration != 1 {
		t.Fatal("generation not registered")
	}
	must(t, carrier.Close())
	must(t, os.WriteFile(filepath.Join(dir, "grant2"), grant(2), 0600))
	manifest["generation"], manifest["deployment_grant_file"] = "2", "grant2"
	writeManifest(t, dir, manifest)
	carrier, _, err = connector(t.Context())
	must(t, err)
	remote = <-accepted
	must(t, remote.err)
	if *remote.register.CredentialGeneration != 2 {
		t.Fatal("new generation not registered")
	}
	must(t, carrier.Close())
	manifest["generation"], manifest["deployment_grant_file"] = "1", "grant"
	writeManifest(t, dir, manifest)
	if _, _, err := connector(t.Context()); !errors.Is(err, &Error{Code: SecurityFailure}) {
		t.Fatal("rollback accepted")
	}
}
