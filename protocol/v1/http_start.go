package v1

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Header is an ordered name/value pair. Repeated fields retain their order.
// Decoders check exact pair length before unmarshalling into this array.
type Header [2]string

// RequestStart describes an ordinary WSS HTTP request. Validation does not
// authenticate it, reserve credit or enforce session/negotiated limits.
type RequestStart struct {
	Type           string                     `json:"type"`
	StreamID       U64                        `json:"stream_id"`
	Method         string                     `json:"method"`
	RawRequestURI  string                     `json:"raw_request_uri"`
	Host           string                     `json:"host"`
	Headers        []Header                   `json:"headers"`
	ResponseCredit U64                        `json:"response_credit"`
	Extensions     map[string]json.RawMessage `json:"extensions,omitempty"`
}

// ResponseStart describes final ordinary HTTP headers, never a WebSocket 101.
// Body eligibility and Content-Length accounting require request/stream state.
type ResponseStart struct {
	Type       string                     `json:"type"`
	StreamID   U64                        `json:"stream_id"`
	Status     int                        `json:"status"`
	Headers    []Header                   `json:"headers"`
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}

func decodeHTTPStart(b []byte, required []string, result any) error {
	if ValidateControlJSON(b) != nil {
		return ErrProtocol
	}
	fields, err := controlObject(b, required, []string{"extensions"}, "")
	if err != nil {
		return ErrProtocol
	}
	var headers []json.RawMessage
	if json.Unmarshal(fields["headers"], &headers) != nil || headers == nil || len(headers) > 256 {
		return ErrProtocol
	}
	for _, raw := range headers {
		var pair []json.RawMessage
		if json.Unmarshal(raw, &pair) != nil || len(pair) != 2 {
			return ErrProtocol
		}
		for _, value := range pair {
			var s string
			if string(value) == "null" || json.Unmarshal(value, &s) != nil {
				return ErrProtocol
			}
		}
	}
	if json.Unmarshal(b, result) != nil {
		return ErrProtocol
	}
	return nil
}

// DecodeRequestStart strictly checks the closed wire object and HTTP metadata.
func DecodeRequestStart(b []byte) (RequestStart, error) {
	var r RequestStart
	if decodeHTTPStart(b, []string{"type", "stream_id", "method", "raw_request_uri", "host", "headers", "response_credit"}, &r) != nil || r.Validate() != nil {
		return RequestStart{}, ErrProtocol
	}
	return r, nil
}

// DecodeResponseStart strictly checks the closed wire object and HTTP metadata.
func DecodeResponseStart(b []byte) (ResponseStart, error) {
	var r ResponseStart
	if decodeHTTPStart(b, []string{"type", "stream_id", "status", "headers"}, &r) != nil || r.Validate() != nil {
		return ResponseStart{}, ErrProtocol
	}
	return r, nil
}

func (r RequestStart) Validate() error {
	if r.Type != "request_start" || r.StreamID == 0 || len(r.Method) > 32 || !httpToken(r.Method, false) || r.Method == http.MethodConnect || !validHTTPHost(r.Host) {
		return ErrProtocol
	}
	// Bound and validate the URI before allocating a parsed representation.
	if _, err := DecodeRoutePath(r.RawRequestURI); err != nil {
		return err
	}
	// Parse without reserializing; retain the original escaped path/query.
	u, err := url.ParseRequestURI(r.RawRequestURI)
	if err != nil || u.IsAbs() || u.Host != "" || !utf8.ValidString(r.RawRequestURI) {
		return ErrProtocol
	}
	for i := 0; i < len(r.RawRequestURI); i++ {
		c := r.RawRequestURI[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~!$&'()*+,;=:@/?%", rune(c))) {
			return ErrProtocol
		}
		if c == '%' {
			if i+2 >= len(r.RawRequestURI) {
				return ErrProtocol
			}
			if !isHex(r.RawRequestURI[i+1]) || !isHex(r.RawRequestURI[i+2]) {
				return ErrProtocol
			}
			i += 2
		}
	}
	if validateOrdinaryHeaders(r.Headers) != nil {
		return ErrProtocol
	}
	return validateResponseJSON(r, r.Extensions)
}

func (r ResponseStart) Validate() error {
	if r.Type != "response_start" || r.StreamID == 0 || r.Status < 200 || r.Status > 599 || validateOrdinaryHeaders(r.Headers) != nil {
		return ErrProtocol
	}
	return validateResponseJSON(r, r.Extensions)
}

func httpToken(s string, lower bool) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || !lower && c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			continue
		}
		return false
	}
	return true
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func validHTTPHost(host string) bool {
	if len(host) == 0 || len(host) > 255 {
		return false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune(".-_:[]", rune(c))) {
			return false
		}
	}
	u, err := url.Parse("//" + host)
	if err != nil || u.Host != host || u.Hostname() == "" || u.User != nil {
		return false
	}
	if strings.HasPrefix(host, "[") {
		if net.ParseIP(u.Hostname()) == nil || !strings.Contains(u.Hostname(), ":") {
			return false
		}
	} else if strings.ContainsAny(u.Hostname(), ":[]") {
		return false
	}
	if strings.HasSuffix(host, ":") {
		return false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return false
		}
	}
	return true
}

// This validates wire field bounds and ordinary end-to-end semantics. Adapters
// must additionally bound their serialized HTTP header block and negotiated
// limits before writing it. No fields are removed, merged or canonicalized.
func validateOrdinaryHeaders(headers []Header) error {
	if headers == nil || len(headers) > 256 {
		return ErrProtocol
	}
	var length uint64
	hasLength := false
	total := 0
	for _, h := range headers {
		if len(h[0]) > 128 || !httpToken(h[0], true) || len(h[1]) > 32768 || !utf8.ValidString(h[1]) {
			return ErrProtocol
		}
		// Raw field bytes are a lower bound on serialized control size.
		total += len(h[0]) + len(h[1])
		if total > MaxControlBytes {
			return ErrProtocol
		}
		for i := 0; i < len(h[1]); i++ {
			c := h[1][i]
			if c < 32 && c != '\t' || c == 127 {
				return ErrProtocol
			}
		}
		switch h[0] {
		case "host", "connection", "proxy-connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "proxy-authenticate", "proxy-authorization":
			return ErrProtocol
		case "content-length":
			// Accept equal repeated decimal lengths without changing their bytes.
			s := strings.Trim(h[1], " \t")
			if s == "" {
				return ErrProtocol
			}
			for i := 0; i < len(s); i++ {
				if s[i] < '0' || s[i] > '9' {
					return ErrProtocol
				}
			}
			n, err := strconv.ParseUint(s, 10, 63)
			if err != nil || hasLength && n != length {
				return ErrProtocol
			}
			length, hasLength = n, true
		}
	}
	return nil
}
