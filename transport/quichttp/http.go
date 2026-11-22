// Package quichttp forwards ordinary streaming HTTP on a registered reverse
// QUIC connection. It does not authorize requests or implement application
// WebSocket CONNECT, routing, readiness, reconnect, or the public Client API.
package quichttp

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

const requestIDHeader = "X-Tunnel-Request-Id"

var (
	ErrBusy      = errors.New("outgate: QUIC request capacity exhausted")
	ErrRequest   = errors.New("outgate: invalid ordinary HTTP metadata")
	ErrQuiescing = errors.New("outgate: QUIC session is quiescing")
)

// headerPairs bounds the expanded HTTP/3 field section before allocating the
// pair slice. RFC field accounting includes 32 bytes per field. max_header_bytes
// also covers pseudo fields and the transport request ID.
func headerPairs(h http.Header, maximum, pseudoSize int) ([]v1.Header, error) {
	size, count := pseudoSize, 0
	for name, values := range h {
		for _, value := range values {
			count++
			if count > 256 || len(name) > maximum || len(value) > maximum {
				return nil, ErrRequest
			}
			size += len(name) + len(value) + 32
			if size > maximum {
				return nil, ErrRequest
			}
		}
	}
	if size > maximum {
		return nil, ErrRequest
	}
	pairs := make([]v1.Header, 0, count)
	for name, values := range h {
		for _, value := range values {
			pairs = append(pairs, v1.Header{strings.ToLower(name), value})
		}
	}
	return pairs, nil
}

func checkRequest(req *http.Request, limits v1.RegisterAckLimits, incoming bool) error {
	if req == nil || req.URL == nil || req.Method == "GET_0RTT" || req.Method == "HEAD_0RTT" ||
		(!incoming && req.URL.Scheme != "https" || incoming && req.URL.Scheme != "") || req.URL.User != nil || req.URL.Fragment != "" || req.URL.RawFragment != "" || req.URL.Opaque != "" ||
		req.URL.RawPath != "" && req.URL.RawPath != req.URL.EscapedPath() || len(req.Trailer) != 0 || req.ContentLength < -1 {
		return ErrRequest
	}
	// Bound URL components before RequestURI concatenates them.
	if len(req.URL.Path) > limits.MaxRawURIBytes || len(req.URL.RawPath) > limits.MaxRawURIBytes || len(req.URL.RawQuery) > limits.MaxRawURIBytes {
		return ErrRequest
	}
	uri := req.URL.RequestURI()
	// quic-go exposes server URLs in origin form, like net/http. Preserve the
	// exact :path rather than manufacturing an absolute application URL.
	if incoming && req.RequestURI != uri {
		return ErrRequest
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if len(uri) > limits.MaxRawURIBytes || len(host) > limits.MaxHeaderBytes || len(req.Method) > 32 {
		return ErrRequest
	}
	pairs, err := headerPairs(req.Header, limits.MaxHeaderBytes, len(req.Method)+len(host)+len(uri)+len("https")+len(":method:authority:path:scheme")+4*32)
	if err != nil {
		return err
	}
	if v1.ValidateHTTPRequestMetadata(req.Method, host, uri, pairs) != nil {
		return ErrRequest
	}
	// net/http derives Content-Length from ContentLength. Reject a conflicting
	// supplied field rather than silently rewriting signed HTTP metadata.
	for _, field := range pairs {
		if field[0] == "content-length" {
			parsed, err := strconv.ParseInt(field[1], 10, 64)
			if err != nil || parsed < 0 || parsed != req.ContentLength {
				return ErrRequest
			}
		}
	}
	return nil
}
