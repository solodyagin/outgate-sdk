package v1

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"testing/iotest"
)

func fixture(t *testing.T, name string, target any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "protocol", "v1", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, target); err != nil {
		t.Fatal(err)
	}
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestWSSGolden(t *testing.T) {
	var vectors struct {
		Maximum int `json:"max_chunk_bytes"`
		Cases   []struct {
			Name, Hex  string
			Valid      bool
			Kind       ChunkKind
			StreamID   U64    `json:"stream_id"`
			PayloadHex string `json:"payload_hex"`
		} `json:"cases"`
	}
	fixture(t, "wss-frames.json", &vectors)
	for _, tc := range vectors.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			b := unhex(t, tc.Hex)
			chunk, err := DecodeChunk(b, vectors.Maximum)
			if (err == nil) != tc.Valid {
				t.Fatalf("valid=%v, error=%v", tc.Valid, err)
			}
			if !tc.Valid {
				return
			}
			if chunk.Kind != tc.Kind || chunk.StreamID != uint64(tc.StreamID) || !bytes.Equal(chunk.Payload, unhex(t, tc.PayloadHex)) {
				t.Fatal("fields differ")
			}
			encoded, err := EncodeChunk(chunk, vectors.Maximum)
			if err != nil || !bytes.Equal(encoded, b) {
				t.Fatal("golden encoding differs", err)
			}
		})
	}
}

func TestQUICGolden(t *testing.T) {
	var v struct {
		BootstrapHex   string         `json:"bootstrap_hex"`
		CredentialKind CredentialKind `json:"credential_kind"`
		Credential     string         `json:"credential_utf8"`
		ControlHex     string         `json:"control_json_hex"`
	}
	fixture(t, "quic-bootstrap.json", &v)
	raw := unhex(t, v.BootstrapHex)
	r := iotest.OneByteReader(bytes.NewReader(raw))
	credential, err := ReadBootstrap(r, v.CredentialKind)
	if err != nil || string(credential) != v.Credential {
		t.Fatal("bootstrap differs", err)
	}
	control, err := ReadControl(r, MaxControlBytes)
	if err != nil || !bytes.Equal(control, unhex(t, v.ControlHex)) {
		t.Fatal("control differs", err)
	}
	if _, err := DecodeRegister(control); err != nil {
		t.Fatal("golden register", err)
	}
	var encoded bytes.Buffer
	if err := WriteBootstrap(&encoded, v.CredentialKind, credential); err != nil {
		t.Fatal(err)
	}
	if err := WriteControl(&encoded, control, MaxControlBytes); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, encoded.Bytes()) {
		t.Fatal("golden bytes differ")
	}
	for n := 0; n < len(raw); n++ {
		r := bytes.NewReader(raw[:n])
		_, err := ReadBootstrap(r, v.CredentialKind)
		if err == nil {
			_, err = ReadControl(r, MaxControlBytes)
		}
		if err == nil {
			t.Fatalf("accepted truncation at %d", n)
		}
	}
	if _, err := ReadBootstrap(bytes.NewReader(raw), ProductionGrant); err == nil {
		t.Fatal("security mode mismatch accepted")
	}
}

func TestBootstrapBoundaries(t *testing.T) {
	for _, kind := range []CredentialKind{DevelopmentBearer, ProductionGrant} {
		for _, size := range []int{1, MaxCredentialBytes} {
			credential := bytes.Repeat([]byte("x"), size)
			var wire bytes.Buffer
			if err := WriteBootstrap(&wire, kind, credential); err != nil {
				t.Fatal(err)
			}
			if wire.Len() != 11+size || string(wire.Bytes()[:8]) != "Outgate1" {
				t.Fatal("unexpected preface layout")
			}
			got, err := ReadBootstrap(iotest.OneByteReader(&wire), kind)
			if err != nil || !bytes.Equal(got, credential) || wire.Len() != 0 {
				t.Fatal("credential boundary", size, err)
			}
		}
	}
	for _, tc := range []struct {
		name   string
		header []byte
	}{
		{"wrong_magic", []byte("outgate1\x01\x00\x01")},
		{"legacy_preface", []byte{0x52, 0x41, 0x47, 0x31, 1, 0, 4, 't', 'e', 's', 't'}},
		{"wrong_kind", []byte("Outgate1\x02\x00\x01")},
		{"zero_length", []byte("Outgate1\x01\x00\x00")},
		{"over_limit", []byte("Outgate1\x01\x10\x01")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ReadBootstrap(bytes.NewReader(tc.header), DevelopmentBearer); !errors.Is(err, ErrProtocol) {
				t.Fatal("invalid header not rejected before credential read", err)
			}
		})
	}
	if _, err := ReadBootstrap(bytes.NewReader([]byte("Outgate1\x01\x00\x01\xff")), DevelopmentBearer); !errors.Is(err, ErrProtocol) {
		t.Fatal("invalid UTF-8 accepted", err)
	}
	for _, credential := range [][]byte{nil, bytes.Repeat([]byte("x"), MaxCredentialBytes+1), {0xff}} {
		var wire bytes.Buffer
		if err := WriteBootstrap(&wire, DevelopmentBearer, credential); !errors.Is(err, ErrProtocol) || wire.Len() != 0 {
			t.Fatal("invalid credential written", err)
		}
	}
}

func TestControlFramesBoundaries(t *testing.T) {
	var b bytes.Buffer
	for _, value := range []string{`{"type":"a"}`, `{"type":"b"}`} {
		if err := WriteControl(&b, []byte(value), MaxControlBytes); err != nil {
			t.Fatal(err)
		}
	}
	for _, expected := range []string{`{"type":"a"}`, `{"type":"b"}`} {
		got, err := ReadControl(&b, MaxControlBytes)
		if err != nil || string(got) != expected {
			t.Fatal("frame boundary", err)
		}
	}
	for _, n := range []uint32{0, MaxControlBytes + 1, ^uint32(0)} {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], n)
		if _, err := ReadControl(bytes.NewReader(header[:]), MaxControlBytes); !errors.Is(err, ErrProtocol) {
			t.Fatal("length not rejected before body read", n, err)
		}
	}
	if err := WriteControl(shortWriter{}, []byte(`{}`), MaxControlBytes); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	if _, err := EncodeChunk(Chunk{Kind: RequestBody, StreamID: 1, Payload: []byte("ab")}, 1); err == nil {
		t.Fatal("negotiated limit ignored")
	}
	if _, err := DecodeChunk(make([]byte, 16), MaxChunkBytes+1); err == nil {
		t.Fatal("invalid configured maximum accepted")
	}
}

type shortWriter struct{}

func (shortWriter) Write([]byte) (int, error) { return 0, nil }

func FuzzDecodeChunk(f *testing.F) {
	chunk := []byte{1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 'x'}
	f.Add(chunk)
	f.Add(chunk[:15]) // Truncated header.
	f.Add(chunk[:16]) // Missing declared payload.
	invalidFlags := bytes.Clone(chunk)
	invalidFlags[3] = 1
	f.Add(invalidFlags)
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := DecodeChunk(b, MaxChunkBytes)
		if err != nil {
			return
		}
		encoded, err := EncodeChunk(c, MaxChunkBytes)
		if err != nil || !bytes.Equal(b, encoded) {
			t.Fatal("round trip")
		}
	})
}
