package v1

import (
	"encoding/binary"
	"io"
	"unicode/utf8"
)

type CredentialKind uint8

const (
	DevelopmentBearer CredentialKind = 1
	ProductionGrant   CredentialKind = 2
)

func validKind(k CredentialKind) bool { return k == DevelopmentBearer || k == ProductionGrant }

// ReadBootstrap reads only the QUIC preface. expected comes from local security
// configuration, never from the peer. Call only after a verified TLS handshake.
// Errors must terminate the session; no stream resynchronization is supported.
func ReadBootstrap(r io.Reader, expected CredentialKind) ([]byte, error) {
	var h [11]byte
	if !validKind(expected) {
		return nil, ErrProtocol
	}
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(h[9:]))
	if string(h[:8]) != "Outgate1" || CredentialKind(h[8]) != expected || n == 0 || n > MaxCredentialBytes {
		return nil, ErrProtocol
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	if !utf8.Valid(b) {
		return nil, ErrProtocol
	}
	return b, nil
}

func WriteBootstrap(w io.Writer, kind CredentialKind, credential []byte) error {
	if !validKind(kind) || len(credential) == 0 || len(credential) > MaxCredentialBytes || !utf8.Valid(credential) {
		return ErrProtocol
	}
	var h [11]byte
	copy(h[:], "Outgate1")
	h[8] = byte(kind)
	binary.BigEndian.PutUint16(h[9:], uint16(len(credential)))
	if err := writeFull(w, h[:]); err != nil {
		return err
	}
	return writeFull(w, credential)
}

// ReadControl reads one length-delimited QUIC control object without consuming
// bytes from the next object. maximum may tighten, but never expand, wire limits.
func ReadControl(r io.Reader, maximum int) ([]byte, error) {
	if maximum < 1 || maximum > MaxControlBytes {
		return nil, ErrProtocol
	}
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > uint32(maximum) {
		return nil, ErrProtocol
	}
	b := make([]byte, int(n))
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	if err := ValidateControlJSON(b); err != nil {
		return nil, err
	}
	return b, nil
}

func WriteControl(w io.Writer, b []byte, maximum int) error {
	if maximum < 1 || maximum > MaxControlBytes || len(b) > maximum {
		return ErrProtocol
	}
	if err := ValidateControlJSON(b); err != nil {
		return err
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(b)))
	if err := writeFull(w, h[:]); err != nil {
		return err
	}
	return writeFull(w, b)
}

type ChunkKind uint8

const (
	RequestBody          ChunkKind = 1
	ResponseBody         ChunkKind = 2
	WebSocketToHandler   ChunkKind = 3
	WebSocketFromHandler ChunkKind = 4
)

// Chunk is one assembled WSS binary message. Payload is opaque HTTP/WS bytes.
type Chunk struct {
	Kind     ChunkKind
	StreamID uint64
	Payload  []byte
}

// DecodeChunk returns a view of message; the caller must retain it until consumed.
// The WSS reader must enforce the assembled-message limit before allocation.
func DecodeChunk(message []byte, maximum int) (Chunk, error) {
	if maximum < 1 || maximum > MaxChunkBytes || len(message) < 16 {
		return Chunk{}, ErrProtocol
	}
	h := message[:16]
	kind := ChunkKind(h[1])
	stream := binary.BigEndian.Uint64(h[4:12])
	n := binary.BigEndian.Uint32(h[12:16])
	if h[0] != Major || kind < RequestBody || kind > WebSocketFromHandler || binary.BigEndian.Uint16(h[2:4]) != 0 || stream == 0 || n == 0 || n > uint32(maximum) || uint64(len(message)-16) != uint64(n) {
		return Chunk{}, ErrProtocol
	}
	return Chunk{Kind: kind, StreamID: stream, Payload: message[16:]}, nil
}

func EncodeChunk(c Chunk, maximum int) ([]byte, error) {
	if maximum < 1 || maximum > MaxChunkBytes || c.Kind < RequestBody || c.Kind > WebSocketFromHandler || c.StreamID == 0 || len(c.Payload) == 0 || len(c.Payload) > maximum {
		return nil, ErrProtocol
	}
	b := make([]byte, 16+len(c.Payload))
	b[0] = Major
	b[1] = byte(c.Kind)
	binary.BigEndian.PutUint64(b[4:12], c.StreamID)
	binary.BigEndian.PutUint32(b[12:16], uint32(len(c.Payload)))
	copy(b[16:], c.Payload)
	return b, nil
}

func writeFull(w io.Writer, b []byte) error {
	// Writer's contract requires an error on a short write; don't loop forever
	// on an adapter that accidentally returns (0, nil).
	n, err := w.Write(b)
	if err == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return err
}
