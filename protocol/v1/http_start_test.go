package v1

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func decodeStart(b []byte, request bool) (any, error) {
	if request {
		return DecodeRequestStart(b)
	}
	return DecodeResponseStart(b)
}

func TestHTTPStartGolden(t *testing.T) {
	fixtures := responseFixtures(t)
	for _, name := range []string{"request_start", "response_start"} {
		v, err := decodeStart(fixtures[name], name == "request_start")
		if err != nil {
			t.Fatal(name, err)
		}
		b := responseBytes(t, v)
		if !reflect.DeepEqual(responseFields(t, b), responseFields(t, fixtures[name])) {
			t.Fatal("golden fields changed")
		}
		if _, err := decodeStart(b, name == "request_start"); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile("../../tests/fixtures/protocol/v1/control-messages.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Negative []struct{ Message json.RawMessage }
	}
	if json.Unmarshal(b, &corpus) != nil {
		t.Fatal("corpus")
	}
	for _, n := range corpus.Negative {
		if responseFields(t, n.Message)["type"] == "response_start" {
			if _, err := DecodeResponseStart(n.Message); err == nil {
				t.Fatal("accepted negative fixture")
			}
		}
	}
}

func TestHTTPStartStrict(t *testing.T) {
	fixtures := responseFixtures(t)
	for _, name := range []string{"request_start", "response_start"} {
		request := name == "request_start"
		check := func(m map[string]any) {
			t.Helper()
			if _, err := decodeStart(responseBytes(t, m), request); err == nil {
				t.Fatalf("accepted %v", m)
			}
		}
		for field := range responseFields(t, fixtures[name]) {
			for _, mutation := range []string{"missing", "null", "type", "case", "alias"} {
				t.Run(name+"/"+field+"/"+mutation, func(t *testing.T) {
					m := responseFields(t, fixtures[name])
					switch mutation {
					case "missing":
						delete(m, field)
					case "null":
						m[field] = nil
					case "type":
						m[field] = true
					case "case", "alias":
						m[strings.ToUpper(field)] = m[field]
						if mutation == "case" {
							delete(m, field)
						}
					}
					check(m)
				})
			}
		}
		for _, headers := range []any{[]any{nil}, []any{[]any{"a"}}, []any{[]any{"a", "b", "c"}}, []any{[]any{nil, "b"}}, []any{[]any{"a", nil}}, []any{[]any{1, "b"}}, []any{[]any{"a", false}}} {
			m := responseFields(t, fixtures[name])
			m["headers"] = headers
			check(m)
		}
		for _, ext := range []any{nil, []any{}, map[string]any{"bad": strings.Repeat("x", MaxControlBytes)}} {
			m := responseFields(t, fixtures[name])
			m["extensions"] = ext
			check(m)
		}
		for _, id := range []any{"0", "01", "18446744073709551616", 1} {
			m := responseFields(t, fixtures[name])
			m["stream_id"] = id
			check(m)
		}
		base := string(fixtures[name])
		for _, b := range []string{strings.Replace(base, `"type":`, `"type":"wrong","type":`, 1), strings.Replace(base, `"headers":`, `"extensions":{"x":1,"x":2},"headers":`, 1), strings.Replace(base, `"headers":`, `"extensions":{"x":"\ud800"},"headers":`, 1)} {
			if _, err := decodeStart([]byte(b), request); err == nil {
				t.Fatal("accepted invalid JSON")
			}
		}
	}
}

func TestHTTPRequestMetadata(t *testing.T) {
	base, err := DecodeRequestStart(responseFixtures(t)["request_start"])
	if err != nil {
		t.Fatal(err)
	}
	for _, uri := range []string{"/", "/a%20b/%D1%8F?x=2&x=1+2&z=%2f", "/%252f?", "/a?x=%FF"} {
		r := base
		r.RawRequestURI = uri
		if r.Validate() != nil || r.RawRequestURI != uri {
			t.Fatalf("rejected or changed URI %q", uri)
		}
	}
	for _, uri := range []string{"", "*", "https://example.com/a", "//host/a", "/a#b", "/a%2fb", "/a%5Cb", "/%2e%2e/b", "/a/./b", "/a//b", "/a\\b", "/%ff", "/я", "/a?x=%", "/a?x=%+a", "/a?x=%gg", "/a?x= ", "/a?x=\\", "/a\x00", "/a?x=<", "/a?x={", "/a?x=\"", "/a|b"} {
		r := base
		r.RawRequestURI = uri
		if r.Validate() == nil {
			t.Fatalf("accepted URI %q", uri)
		}
	}
	for _, host := range []string{"example.com", "example.com:443", "[::1]:9443", "127.0.0.1"} {
		r := base
		r.Host = host
		if r.Validate() != nil {
			t.Fatal(host)
		}
	}
	for _, host := range []string{"", "user@host", "host/path", "host?x", "host#x", "host ", "host\r\nx:y", "host:", "host:65536", "[bad]", "::1", "[::1", "[::1]evil"} {
		r := base
		r.Host = host
		if r.Validate() == nil {
			t.Fatalf("accepted host %q", host)
		}
	}
	for _, method := range []string{"get", "M-SEARCH", "X!"} {
		r := base
		r.Method = method
		if r.Validate() != nil {
			t.Fatal(method)
		}
	}
	for _, method := range []string{"", "CONNECT", "GET ", "GÉT", strings.Repeat("A", 33)} {
		r := base
		r.Method = method
		if r.Validate() == nil {
			t.Fatal(method)
		}
	}
	r := base
	r.ResponseCredit = ^U64(0)
	if r.Validate() != nil {
		t.Fatal("wire u64 credit; budget belongs to session")
	}
}

func TestHTTPHeaders(t *testing.T) {
	for _, h := range [][]Header{
		{}, {{"set-cookie", "a=1"}, {"set-cookie", "b=2"}},
		{{"x-value", "\t текст \t"}}, {{"content-length", "03"}, {"content-length", " 3\t"}},
		{{strings.Repeat("a", 128), strings.Repeat("x", 32768)}},
	} {
		if validateOrdinaryHeaders(h) != nil {
			t.Fatalf("rejected headers %v", h)
		}
	}
	for _, h := range [][]Header{
		nil, {{"", ""}}, {{"X-Value", "v"}}, {{"x:y", "v"}}, {{"я", "v"}},
		{{"x", "\r"}}, {{"x", "\n"}}, {{"x", "\x00"}}, {{"x", "\x7f"}}, {{"x", "\xff"}},
		{{strings.Repeat("a", 129), "v"}}, {{"x", strings.Repeat("x", 32769)}},
		{{"content-length", "3"}, {"content-length", "4"}}, {{"content-length", "3, 3"}},
		{{"content-length", "+3"}}, {{"content-length", "-1"}}, {{"content-length", "9223372036854775808"}},
	} {
		if validateOrdinaryHeaders(h) == nil {
			t.Fatalf("accepted headers %v", h)
		}
	}
	for _, name := range []string{"host", "connection", "proxy-connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "proxy-authenticate", "proxy-authorization"} {
		if validateOrdinaryHeaders([]Header{{name, "v"}}) == nil {
			t.Fatal(name)
		}
	}
	h := make([]Header, 256)
	for i := range h {
		h[i] = Header{"x", ""}
	}
	if validateOrdinaryHeaders(h) != nil || validateOrdinaryHeaders(append(h, Header{"x", ""})) == nil {
		t.Fatal("field count")
	}
}

func TestHTTPStartBounds(t *testing.T) {
	request, _ := DecodeRequestStart(responseFixtures(t)["request_start"])
	for _, n := range []int{MaxRawURIBytes, MaxRawURIBytes + 1} {
		r := request
		r.RawRequestURI = "/" + strings.Repeat("a", n-1)
		if (r.Validate() == nil) != (n == MaxRawURIBytes) {
			t.Fatal("URI byte limit")
		}
	}
	response, _ := DecodeResponseStart(responseFixtures(t)["response_start"])
	for _, status := range []int{199, 200, 204, 304, 599, 600} {
		r := response
		r.Status = status
		if (r.Validate() == nil) != (status >= 200 && status <= 599) {
			t.Fatal(status)
		}
	}
	for _, ext := range []map[string]json.RawMessage{{"x": json.RawMessage(`{"a":1,"a":2}`)}, {"x": json.RawMessage(`"\ud800"`)}, {"x": json.RawMessage(`"` + strings.Repeat("x", MaxControlBytes) + `"`)}} {
		r := response
		r.Extensions = ext
		if r.Validate() == nil {
			t.Fatal("invalid extension")
		}
	}
}

func FuzzDecodeRequestStart(f *testing.F) {
	golden := responseFixtures(f)["request_start"]
	f.Add([]byte(golden))
	fields := responseFields(f, golden)
	for _, uri := range []string{"/%D1%8F?x=1+2&x=%2f", "/%252f?", "/a%2fb", "/%2e%2e/b", "/a?x=%"} {
		fields["raw_request_uri"] = uri
		f.Add(responseBytes(f, fields))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DecodeRequestStart(b)
		if err == nil {
			next, err := DecodeRequestStart(responseBytes(t, r))
			if err != nil || !reflect.DeepEqual(r, next) {
				t.Fatal("round trip")
			}
		}
	})
}

func FuzzDecodeResponseStart(f *testing.F) {
	f.Add([]byte(responseFixtures(f)["response_start"]))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DecodeResponseStart(b)
		if err == nil {
			next, err := DecodeResponseStart(responseBytes(t, r))
			if err != nil || !reflect.DeepEqual(r, next) {
				t.Fatal("round trip")
			}
		}
	})
}
