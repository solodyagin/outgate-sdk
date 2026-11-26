package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

// FileCredentials creates a production CredentialSource without reading files.
// Relative manifest and credential paths resolve against root, captured as an
// absolute path at construction. Absolute paths are allowed. This is not a
// filesystem sandbox: deployment must protect paths/ACLs and publish a manifest
// atomically only after its immutable generation files have been written.
// Certificate and key files are PEM; the grant file contains exactly grant_id.secret.
// Context is checked between bounded regular-file reads; it cannot interrupt an
// OS filesystem operation. The connector retains its source slot until return.
func FileCredentials(root, manifest string) (CredentialSource, error) {
	if !validCredentialPath(root) || !validCredentialPath(manifest) {
		return nil, &Error{Code: InvalidConfig}
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, &Error{Code: InvalidConfig}
	}
	resolve := func(name string) string {
		if filepath.IsAbs(name) {
			return name
		}
		return filepath.Join(root, name)
	}
	manifest = resolve(manifest)
	return func(ctx context.Context) (CredentialSnapshot, error) {
		// Filesystem/parser errors deliberately carry no paths, secret data or parser
		// text, including through Unwrap. A subsequent acquisition may see a complete
		// newly published generation; this source never caches a partial snapshot.
		unavailable := func() (CredentialSnapshot, error) {
			return CredentialSnapshot{}, &credentialError{cause: errors.New("credential_files_unavailable")}
		}
		data, err := readCredentialFile(ctx, manifest, v1.MaxControlBytes)
		if err != nil {
			return unavailable()
		}
		defer clear(data)
		generation, paths, err := decodeCredentialManifest(data)
		if err != nil {
			return unavailable()
		}
		limits := []int{96 * 1024, 32 * 1024, 385}
		var files [3][]byte
		defer func() {
			for _, b := range files {
				clear(b)
			}
		}()
		for i, name := range paths {
			files[i], err = readCredentialFile(ctx, resolve(name), limits[i])
			if err != nil {
				return unavailable()
			}
		}
		if !validGrant(files[2]) || !validCertificatePEM(files[0]) || !validPrivateKeyPEM(files[1]) {
			return unavailable()
		}
		pair, err := tls.X509KeyPair(files[0], files[1])
		if err != nil {
			return unavailable()
		}
		snapshot, err := copyCredentials(CredentialSnapshot{Certificate: pair, Credential: files[2], Generation: generation})
		if err != nil {
			return unavailable()
		}
		if ctx.Err() != nil {
			clear(snapshot.Credential)
			return unavailable()
		}
		return snapshot, nil
	}, nil
}

func validCredentialPath(s string) bool {
	if !utf8.ValidString(s) || len(s) == 0 || len(s) > 4096 || strings.TrimSpace(s) == "" {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r >= 0x7f && r <= 0x9f {
			return false
		}
	}
	return true
}

func decodeCredentialManifest(data []byte) (uint64, [3]string, error) {
	var paths [3]string
	if v1.ValidateControlJSON(data) != nil {
		return 0, paths, v1.ErrProtocol
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || len(fields) != 4 {
		return 0, paths, v1.ErrProtocol
	}
	// Exact names avoid encoding/json's case-insensitive struct field matching.
	var value string
	if json.Unmarshal(fields["generation"], &value) != nil {
		return 0, paths, v1.ErrProtocol
	}
	generation, err := strconv.ParseUint(value, 10, 64)
	if err != nil || generation == 0 || strconv.FormatUint(generation, 10) != value {
		return 0, paths, v1.ErrProtocol
	}
	for i, name := range []string{"certificate_file", "private_key_file", "deployment_grant_file"} {
		if json.Unmarshal(fields[name], &paths[i]) != nil || !validCredentialPath(paths[i]) {
			return 0, paths, v1.ErrProtocol
		}
	}
	return generation, paths, nil
}

func readCredentialFile(ctx context.Context, name string, limit int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Reject special files before opening, then recheck the opened descriptor.
	// Paths are deployment-controlled; these checks are not an ACL/TOCTOU sandbox.
	info, err := os.Stat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > int64(limit) {
		return nil, v1.ErrProtocol
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || opened.Size() <= 0 || opened.Size() > int64(limit) {
		return nil, v1.ErrProtocol
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil || len(data) == 0 || len(data) > limit || ctx.Err() != nil {
		clear(data)
		return nil, v1.ErrProtocol
	}
	return data, nil
}

func validCertificatePEM(data []byte) bool {
	count, total := 0, 0
	for len(bytes.TrimSpace(data)) != 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return false
		}
		block, rest := decodeFirstPEM(data)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(block.Bytes) == 0 {
			return false
		}
		count++
		total += len(block.Bytes)
		if count > 8 || total > 64*1024 {
			return false
		}
		data = rest
	}
	return count > 0
}

func validPrivateKeyPEM(data []byte) bool {
	data = bytes.TrimSpace(data)
	if !bytes.HasPrefix(data, []byte("-----BEGIN ")) {
		return false
	}
	block, rest := decodeFirstPEM(data)
	if block == nil {
		return false
	}
	defer clear(block.Bytes)
	return len(bytes.TrimSpace(rest)) == 0 && len(block.Headers) == 0 && len(block.Bytes) != 0 &&
		(block.Type == "PRIVATE KEY" || block.Type == "RSA PRIVATE KEY" || block.Type == "EC PRIVATE KEY")
}

// pem.Decode searches past malformed blocks. Restrict it to the first block so
// malformed leading credentials cannot be silently skipped in favor of later ones.
func decodeFirstPEM(data []byte) (*pem.Block, []byte) {
	const begin = "-----BEGIN "
	if !bytes.HasPrefix(data, []byte(begin)) {
		return nil, nil
	}
	end := bytes.Index(data[len(begin):], []byte("-----END "))
	if end < 0 {
		return nil, nil
	}
	end += len(begin)
	if bytes.Contains(data[len(begin):end], []byte(begin)) {
		return nil, nil
	}
	suffix := bytes.Index(data[end+len("-----END "):], []byte("-----"))
	if suffix < 0 {
		return nil, nil
	}
	end += len("-----END ") + suffix + len("-----")
	block, rest := pem.Decode(data[:end])
	if block == nil || len(rest) != 0 {
		return nil, nil
	}
	return block, data[end:]
}
