package v1

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

// ValidateControlJSON checks bounded UTF-8 JSON objects, duplicate keys at every
// level and nesting depth. It does not validate a particular message schema.
func ValidateControlJSON(b []byte) error {
	if len(b) == 0 || len(b) > MaxControlBytes || !utf8.Valid(b) {
		return ErrProtocol
	}
	// encoding/json replaces unpaired UTF-16 surrogates; reject those rather
	// than silently changing a peer's strings (including object keys).
	if !validSurrogates(b) {
		return ErrProtocol
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return ErrProtocol
	}
	if err := scanContainer(d, '{', 1); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrProtocol
	}
	return nil
}

func scanContainer(d *json.Decoder, open json.Delim, depth int) error {
	if depth > MaxJSONDepth {
		return ErrProtocol
	}
	keys := make(map[string]struct{})
	for d.More() {
		if open == '{' {
			t, err := d.Token()
			key, ok := t.(string)
			if err != nil || !ok {
				return ErrProtocol
			}
			if _, found := keys[key]; found {
				return ErrProtocol
			}
			keys[key] = struct{}{}
		}
		t, err := d.Token()
		if err != nil {
			return ErrProtocol
		}
		if delim, ok := t.(json.Delim); ok {
			if delim != '{' && delim != '[' {
				return ErrProtocol
			}
			if err := scanContainer(d, delim, depth+1); err != nil {
				return err
			}
		}
	}
	close := json.Delim('}')
	if open == '[' {
		close = ']'
	}
	t, err := d.Token()
	if err != nil || t != close {
		return ErrProtocol
	}
	return nil
}

func hex4(b []byte) (uint16, bool) {
	if len(b) < 4 {
		return 0, false
	}
	var n uint16
	for _, c := range b[:4] {
		n <<= 4
		switch {
		case c >= '0' && c <= '9':
			n += uint16(c - '0')
		case c >= 'a' && c <= 'f':
			n += uint16(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			n += uint16(c - 'A' + 10)
		default:
			return 0, false
		}
	}
	return n, true
}

func validSurrogates(b []byte) bool {
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' {
			continue
		}
		i++
		if i >= len(b) {
			return false
		}
		if b[i] != 'u' {
			continue
		}
		n, ok := hex4(b[i+1:])
		if !ok {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n < 0xd800 || n > 0xdbff {
			continue
		}
		if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
			return false
		}
		low, ok := hex4(b[i+3:])
		if !ok || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return true
}
