package v1

import (
	"reflect"
	"strings"
	"testing"
)

func TestWebSocketMetadata(t *testing.T) {
	base, err := DecodeWebSocketOpen(responseFixtures(t)["websocket_open"])
	if err != nil {
		t.Fatal(err)
	}
	for field, values := range map[string][]string{
		"method":          {"", "get", "POST", "CONNECT", "GET "},
		"host":            {"", "user@host", "host/path", "host:65536", "[bad]", "::1", strings.Repeat("a", 256)},
		"raw_request_uri": {"", "*", "https://host/ws", "//host/ws", "/ws#x", "/a%2fb", "/%2e%2e", "/a//b", "/a?x=%", "/я", "/a?x= ", "/" + strings.Repeat("a", MaxRawURIBytes)},
	} {
		for _, value := range values {
			m := responseFields(t, responseBytes(t, base))
			m[field] = value
			if _, err := DecodeWebSocketOpen(responseBytes(t, m)); err == nil {
				t.Fatalf("accepted invalid %s", field)
			}
		}
	}
	for _, uri := range []string{"/", "/%252f?x=2&x=1+2&z=%2f", "/" + strings.Repeat("a", MaxRawURIBytes-1)} {
		r := base
		r.RawRequestURI = uri
		r.Host = "[::1]:443"
		r.Headers = append(append([]Header{}, base.Headers...), Header{"sec-websocket-protocol", "first"}, Header{"sec-websocket-protocol", "second"}, Header{"sec-websocket-extensions", "permessage-deflate"})
		next, err := DecodeWebSocketOpen(responseBytes(t, r))
		if err != nil || !reflect.DeepEqual(r, next) {
			t.Fatal("metadata/order changed", err)
		}
	}
	for _, headers := range []any{
		[]any{[]string{"x"}}, []any{[]string{"x", "y", "z"}}, []any{[]any{"x", nil}}, []any{[]any{true, "v"}},
		[]Header{{"Upgrade", "websocket"}}, []Header{{"connection", "Upgrade\r\nx:y"}},
		[]Header{{"x", "\x7f"}}, []Header{{"x", strings.Repeat("a", 32769)}},
		[]Header{{strings.Repeat("a", 129), "v"}},
		[]Header{{"content-length", "3"}, {"content-length", "4"}}, []Header{{"content-length", "3, 3"}},
	} {
		m := responseFields(t, responseBytes(t, base))
		m["headers"] = headers
		if _, err := DecodeWebSocketOpen(responseBytes(t, m)); err == nil {
			t.Fatal("accepted invalid headers")
		}
	}
	for _, name := range []string{"host", "proxy-connection", "keep-alive", "transfer-encoding", "te", "trailer", "proxy-authenticate", "proxy-authorization"} {
		r := base
		r.Headers = []Header{{name, "v"}}
		if r.Validate() == nil {
			t.Fatal("accepted forbidden header", name)
		}
	}
	for _, count := range []int{256, 257} {
		r := base
		r.Headers = make([]Header, count)
		for i := range r.Headers {
			r.Headers[i] = Header{"x", ""}
		}
		if (r.Validate() == nil) != (count == 256) {
			t.Fatal("header count")
		}
	}
	r := base
	r.Headers = []Header{{strings.Repeat("a", 128), strings.Repeat("v", 32768)}}
	if r.Validate() != nil {
		t.Fatal("exact header bounds")
	}
}

func TestWebSocketEndDirections(t *testing.T) {
	for _, direction := range []string{"websocket_to_handler", "websocket_from_handler", "request_body", "response_body", "all", "WEBSOCKET_TO_HANDLER", ""} {
		r := WebSocketEnd{Type: "websocket_end", StreamID: 1, Direction: direction}
		valid := direction == "websocket_to_handler" || direction == "websocket_from_handler"
		if (r.Validate() == nil) != valid {
			t.Fatal(direction)
		}
		if _, err := DecodeWebSocketEnd(responseBytes(t, r)); (err == nil) != valid {
			t.Fatal("decoder direction", direction)
		}
	}
}
