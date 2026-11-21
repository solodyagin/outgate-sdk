package v1

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

type streamControlMessage interface{ Validate() error }

func decodeStreamMessage(name string, b []byte) (streamControlMessage, error) {
	switch name {
	case "instance_status":
		return DecodeInstanceStatus(b)
	case "drain":
		return DecodeDrain(b)
	case "drain_ack":
		return DecodeDrainAck(b)
	case "unregister":
		return DecodeUnregister(b)
	case "unregister_ack":
		return DecodeUnregisterAck(b)
	case "reconnect":
		return DecodeReconnect(b)
	case "websocket_open":
		return DecodeWebSocketOpen(b)
	case "websocket_open_ack":
		return DecodeWebSocketOpenAck(b)
	case "websocket_end":
		return DecodeWebSocketEnd(b)
	case "request_end":
		return DecodeRequestEnd(b)
	case "response_end":
		return DecodeResponseEnd(b)
	case "window_update":
		return DecodeWindowUpdate(b)
	case "cancel":
		return DecodeCancel(b)
	case "cancel_ack":
		return DecodeCancelAck(b)
	default:
		panic("unknown test message")
	}
}

var streamMessageNames = []string{"request_end", "response_end", "window_update", "cancel", "cancel_ack", "websocket_open", "websocket_open_ack", "websocket_end", "instance_status", "drain", "drain_ack", "unregister", "unregister_ack", "reconnect"}

func TestStreamControlGolden(t *testing.T) {
	fixtures := responseFixtures(t)
	for _, name := range streamMessageNames {
		t.Run(name, func(t *testing.T) {
			original := fixtures[name]
			r, err := decodeStreamMessage(name, original)
			if err != nil || r.Validate() != nil {
				t.Fatal("golden rejected", err)
			}
			b := responseBytes(t, r)
			if !reflect.DeepEqual(responseFields(t, original), responseFields(t, b)) {
				t.Fatal("golden fields changed")
			}
			next, err := decodeStreamMessage(name, b)
			if err != nil || !reflect.DeepEqual(r, next) {
				t.Fatal("round trip", err)
			}
		})
	}
	b, err := os.ReadFile("../../tests/fixtures/protocol/v1/control-messages.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Negative []struct {
			Name    string
			Message json.RawMessage
		}
	}
	if err := json.Unmarshal(b, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, n := range corpus.Negative {
		var header struct{ Type string }
		if err := json.Unmarshal(n.Message, &header); err != nil {
			t.Fatal(err)
		}
		if contains(streamMessageNames, header.Type) {
			if _, err := decodeStreamMessage(header.Type, n.Message); !errors.Is(err, ErrProtocol) {
				t.Fatalf("accepted negative %s", n.Name)
			}
		}
	}
}

func TestStreamControlStrict(t *testing.T) {
	fixtures := responseFixtures(t)
	for _, name := range streamMessageNames {
		t.Run(name, func(t *testing.T) {
			reject := func(b []byte) {
				t.Helper()
				if _, err := decodeStreamMessage(name, b); !errors.Is(err, ErrProtocol) {
					t.Fatal("expected ErrProtocol")
				}
			}
			for field := range responseFields(t, fixtures[name]) {
				for _, mutation := range []string{"missing", "null", "type", "case", "alias"} {
					t.Run(field+"/"+mutation, func(t *testing.T) {
						m := responseFields(t, fixtures[name])
						switch mutation {
						case "missing":
							delete(m, field)
						case "null":
							m[field] = nil
						case "type":
							m[field] = true
							if field == "ready" {
								m[field] = "true"
							}
						case "case", "alias":
							m[strings.ToUpper(field)] = m[field]
							if mutation == "case" {
								delete(m, field)
							}
						}
						reject(responseBytes(t, m))
					})
				}
			}
			m := responseFields(t, fixtures[name])
			m["unknown"] = 1
			reject(responseBytes(t, m))
			m = responseFields(t, fixtures[name])
			m["type"] = "other"
			reject(responseBytes(t, m))
			for _, extension := range []any{nil, true, []any{}, "text"} {
				m = responseFields(t, fixtures[name])
				m["extensions"] = extension
				reject(responseBytes(t, m))
			}
			base := strings.TrimSpace(string(fixtures[name]))
			withExtension := func(raw string) []byte { return []byte(base[:len(base)-1] + `,"extensions":` + raw + `}`) }
			for _, b := range [][]byte{
				[]byte(base[:len(base)-1] + `,"type":"` + name + `"}`),
				withExtension(`{"x":{"a":1,"a":2}}`),
				withExtension("{\"x\":\"\xff\"}"),
				withExtension(`{"x":"\ud800"}`),
				withExtension(`{"x":` + strings.Repeat("[", MaxJSONDepth) + `0` + strings.Repeat("]", MaxJSONDepth) + `}`),
				withExtension(`{"x":"` + strings.Repeat("a", MaxControlBytes) + `"}`),
				[]byte(base + ` {}`), []byte(`null`), []byte(`[]`),
			} {
				reject(b)
			}
			extensions := map[string]json.RawMessage{}
			for i := 0; i < 33; i++ {
				extensions[fmt.Sprint(i)] = json.RawMessage(`null`)
			}
			m = responseFields(t, fixtures[name])
			m["extensions"] = extensions
			reject(responseBytes(t, m))
			delete(extensions, "32")
			m["extensions"] = extensions
			if _, err := decodeStreamMessage(name, responseBytes(t, m)); err != nil {
				t.Fatal("32 extensions", err)
			}
			m["extensions"] = map[string]any{"opaque": map[string]any{"x": []any{true, nil, "value"}}}
			r, err := decodeStreamMessage(name, responseBytes(t, m))
			if err != nil {
				t.Fatal("valid extensions", err)
			}
			if _, err := decodeStreamMessage(name, responseBytes(t, r)); err != nil {
				t.Fatal(err)
			}
			// Whitespace counts toward the incoming wire limit, even if remarshal is smaller.
			base = string(responseBytes(t, responseFields(t, fixtures[name])))
			atLimit := []byte(base + strings.Repeat(" ", MaxControlBytes-len(base)))
			if _, err := decodeStreamMessage(name, atLimit); err != nil {
				t.Fatal("exact control limit", err)
			}
			reject(append(atLimit, ' '))
		})
	}
}

func TestStreamControlU64(t *testing.T) {
	fixtures := responseFixtures(t)
	for _, name := range streamMessageNames {
		for field := range responseFields(t, fixtures[name]) {
			if field != "command_id" && field != "sequence" && field != "stream_id" && field != "cancel_id" && field != "credit" && field != "bytes_sent" && field != "from_handler_credit" && field != "to_handler_credit" {
				continue
			}
			t.Run(name+"/"+field, func(t *testing.T) {
				for _, raw := range []string{`"0"`, `"1"`, `"18446744073709551615"`, `"18446744073709551616"`, `0`, `1`, `"01"`, `""`, `"-1"`, `"1.0"`, `"\u0031"`, `null`} {
					m := responseFields(t, fixtures[name])
					m[field] = json.RawMessage(raw)
					r, err := decodeStreamMessage(name, responseBytes(t, m))
					valid := raw == `"1"` || raw == `"18446744073709551615"` || raw == `"0"` && (field == "bytes_sent" || field == "from_handler_credit" || field == "to_handler_credit")
					if valid {
						if err != nil || r.Validate() != nil {
							t.Fatalf("rejected %s", raw)
						}
						b := responseFields(t, responseBytes(t, r))
						if b[field] != strings.Trim(raw, `"`) {
							t.Fatal("u64 changed")
						}
					} else if !errors.Is(err, ErrProtocol) {
						t.Fatalf("accepted %s", raw)
					}
				}
			})
		}
	}
}

func TestStreamControlEnumsAndCode(t *testing.T) {
	fixtures := responseFixtures(t)
	for _, name := range []string{"window_update", "cancel", "cancel_ack"} {
		field := "scope"
		validValues := []string{"request_body", "response_body", "all"}
		invalidValues := []string{"", "ALL", "unknown", "websocket_to_handler", "websocket_from_handler"}
		if name == "window_update" {
			field = "direction"
			validValues = []string{"request_body", "response_body", "websocket_to_handler", "websocket_from_handler"}
			invalidValues = []string{"", "all", "REQUEST_BODY", "unknown"}
		}
		for _, value := range append(validValues, invalidValues...) {
			m := responseFields(t, fixtures[name])
			m[field] = value
			_, err := decodeStreamMessage(name, responseBytes(t, m))
			if (err == nil) != contains(validValues, value) {
				t.Fatalf("%s %s", name, value)
			}
		}
	}
	validCodes := []string{"a", "custom_reason_42", "a" + strings.Repeat("0", 63)}
	for _, code := range append(validCodes, "", "A", "1reason", "a-b", "a b", "a\n", "é", strings.Repeat("a", 65)) {
		m := responseFields(t, fixtures["cancel"])
		m["code"] = code
		_, err := DecodeCancel(responseBytes(t, m))
		if (err == nil) != contains(validCodes, code) {
			t.Fatalf("code %q", code)
		}
	}
}

func TestStreamControlConstructed(t *testing.T) {
	max := U64(^uint64(0))
	tooManyExtensions := map[string]json.RawMessage{}
	for i := 0; i < 33; i++ {
		tooManyExtensions[fmt.Sprint(i)] = json.RawMessage(`null`)
	}
	for _, r := range []streamControlMessage{
		RequestEnd{Type: "request_end", StreamID: 1}, ResponseEnd{Type: "response_end", StreamID: max, BytesSent: max},
		WindowUpdate{Type: "window_update", StreamID: 1, Direction: "request_body", Credit: max},
		Cancel{Type: "cancel", StreamID: 1, CancelID: max, Scope: "all", Code: "custom"},
		CancelAck{Type: "cancel_ack", StreamID: 1, CancelID: 1, Scope: "response_body"},
		WebSocketOpen{Type: "websocket_open", StreamID: 1, Method: "GET", RawRequestURI: "/ws", Host: "example.com", Headers: []Header{}, FromHandlerCredit: max},
		WebSocketOpenAck{Type: "websocket_open_ack", StreamID: max, ToHandlerCredit: max},
		WebSocketEnd{Type: "websocket_end", StreamID: 1, Direction: "websocket_from_handler", BytesSent: max},
		InstanceStatus{Type: "instance_status", Sequence: max, Ready: false, Code: "security_recovery", ObservedAt: maxTimestamp},
		Drain{Type: "drain", CommandID: max, DeadlineMS: 30000, Code: "shutdown"},
		Unregister{Type: "unregister", CommandID: 1, DeadlineMS: 1, Code: "shutdown"},
		Reconnect{Type: "reconnect", CommandID: 1, DeadlineMS: 1, Code: "credential_rotation"},
		DrainAck{Type: "drain_ack", CommandID: max}, UnregisterAck{Type: "unregister_ack", CommandID: 1},
	} {
		if err := r.Validate(); err != nil {
			t.Fatal("valid constructed", err)
		}
		original := reflect.ValueOf(r)
		for _, field := range []string{"Type", "StreamID", "CancelID", "Direction", "Credit", "Scope", "Code", "Method", "RawRequestURI", "Host", "Headers", "CommandID", "Sequence", "DeadlineMS"} {
			if !original.FieldByName(field).IsValid() {
				continue
			}
			copy := reflect.New(original.Type()).Elem()
			copy.Set(original)
			copy.FieldByName(field).SetZero()
			if !errors.Is(copy.Interface().(streamControlMessage).Validate(), ErrProtocol) {
				t.Fatalf("zero %s accepted", field)
			}
		}
		for _, extensions := range []map[string]json.RawMessage{
			tooManyExtensions,
			{"x": json.RawMessage(`{"a":1,"a":2}`)}, {"x": json.RawMessage(`"\ud800"`)},
			{"x": json.RawMessage("\xff")}, {"\xff": json.RawMessage(`null`)},
			{"x": json.RawMessage(strings.Repeat("[", MaxJSONDepth) + "0" + strings.Repeat("]", MaxJSONDepth))},
			{"x": json.RawMessage(`"` + strings.Repeat("a", MaxControlBytes) + `"`)},
			{"x": json.RawMessage(`{`)},
		} {
			copy := reflect.New(original.Type()).Elem()
			copy.Set(original)
			copy.FieldByName("Extensions").Set(reflect.ValueOf(extensions))
			if !errors.Is(copy.Interface().(streamControlMessage).Validate(), ErrProtocol) {
				t.Fatal("invalid extensions accepted")
			}
		}
	}
}

func fuzzStreamControl(f *testing.F, name string) {
	fixture := responseFixtures(f)[name]
	f.Add([]byte(fixture))
	m := responseFields(f, fixture)
	m["extensions"] = map[string]any{}
	f.Add(responseBytes(f, m))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := decodeStreamMessage(name, b)
		if err != nil {
			if !errors.Is(err, ErrProtocol) {
				t.Fatal("unexpected error")
			}
			return
		}
		if r.Validate() != nil {
			t.Fatal("decoded invalid message")
		}
		encoded := responseBytes(t, r)
		next, err := decodeStreamMessage(name, encoded)
		// Empty extensions are omitted on marshal; compare the canonical wire
		// representation rather than nil versus empty Go maps.
		if err != nil || next.Validate() != nil || !bytes.Equal(encoded, responseBytes(t, next)) {
			t.Fatal("round trip")
		}
	})
}

func FuzzDecodeRequestEnd(f *testing.F)   { fuzzStreamControl(f, "request_end") }
func FuzzDecodeResponseEnd(f *testing.F)  { fuzzStreamControl(f, "response_end") }
func FuzzDecodeWindowUpdate(f *testing.F) { fuzzStreamControl(f, "window_update") }
func FuzzDecodeCancel(f *testing.F)       { fuzzStreamControl(f, "cancel") }
func FuzzDecodeCancelAck(f *testing.F)    { fuzzStreamControl(f, "cancel_ack") }

func FuzzDecodeWebSocketOpen(f *testing.F)    { fuzzStreamControl(f, "websocket_open") }
func FuzzDecodeWebSocketOpenAck(f *testing.F) { fuzzStreamControl(f, "websocket_open_ack") }
func FuzzDecodeWebSocketEnd(f *testing.F)     { fuzzStreamControl(f, "websocket_end") }
