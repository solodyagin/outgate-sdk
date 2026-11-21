package v1

import (
	"encoding/json"
	"errors"
	"strconv"
)

const (
	Major              = 1
	Minor              = 0
	MaxControlBytes    = 65536
	MaxChunkBytes      = 32768
	MaxCredentialBytes = 4096
	MaxRawURIBytes     = 8192
	MaxJSONDepth       = 32
	WSSSubprotocol     = "outgate.tunnel.v1"
	QUICALPN           = "outgate-tunnel/1"
)

// ErrProtocol never includes peer-controlled input, credentials or claims.
var ErrProtocol = errors.New("outgate: invalid protocol data")

// U64 is encoded as a canonical JSON decimal string, never a JSON number.
type U64 uint64

func (v U64) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatUint(uint64(v), 10))
}

func (v *U64) UnmarshalJSON(b []byte) error {
	// Check raw bytes too: escaped digits are not canonical decimal wire strings.
	if len(b) < 3 || len(b) > 22 || b[0] != '"' || b[len(b)-1] != '"' {
		return ErrProtocol
	}
	s := string(b[1 : len(b)-1])
	if len(s) > 1 && s[0] == '0' {
		return ErrProtocol
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return ErrProtocol
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return ErrProtocol
	}
	*v = U64(n)
	return nil
}
