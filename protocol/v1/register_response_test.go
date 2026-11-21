package v1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func responseFixtures(t testing.TB) map[string]json.RawMessage {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "protocol", "v1", "control-messages.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct{ Positive []json.RawMessage }
	if err := json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	result := make(map[string]json.RawMessage)
	for _, b := range vectors.Positive {
		var message struct{ Type string }
		if err := json.Unmarshal(b, &message); err != nil {
			t.Fatal(err)
		}
		result[message.Type] = b
	}
	return result
}

func responseFields(t testing.TB, b []byte) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(b, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func responseBytes(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func decodeResponse(b []byte, ack bool) error {
	if ack {
		_, err := DecodeRegisterAck(b)
		return err
	}
	_, err := DecodeRegisterNack(b)
	return err
}

func TestRegisterResponsesGolden(t *testing.T) {
	fixtures := responseFixtures(t)
	ack, err := DecodeRegisterAck(fixtures["register_ack"])
	if err != nil {
		t.Fatal(err)
	}
	nack, err := DecodeRegisterNack(fixtures["register_nack"])
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{"register_ack": ack, "register_nack": nack} {
		b := responseBytes(t, value)
		if !reflect.DeepEqual(responseFields(t, fixtures[name]), responseFields(t, b)) {
			t.Fatal(name, "changed golden fields")
		}
		if err := decodeResponse(b, name == "register_ack"); err != nil {
			t.Fatal("round trip", err)
		}
	}
	if ack.CredentialExpiresAt != nil || ack.Limits.MaxInflight != 100 || ack.Readiness.FailureThreshold != 3 || nack.Code != "duplicate_instance" || !nack.Retryable {
		t.Fatal("golden fields differ")
	}
}

// Exercise presence/null/type/case checks at every closed object, including
// zero-valued booleans and integers that a plain struct decoder cannot detect.
func TestRegisterResponsesStrictFields(t *testing.T) {
	fixtures := responseFixtures(t)
	for _, message := range []string{"register_ack", "register_nack"} {
		locations := []string{""}
		if message == "register_ack" {
			locations = append(locations, "limits", "timeouts", "readiness", "path")
		}
		object := func(m map[string]any, location string) map[string]any {
			if location == "" {
				return m
			}
			if location == "path" {
				return m["paths"].([]any)[0].(map[string]any)
			}
			return m[location].(map[string]any)
		}
		for _, location := range locations {
			for field := range object(responseFields(t, fixtures[message]), location) {
				for _, mutation := range []string{"missing", "null", "type", "case", "case_alias"} {
					if field == "credential_expires_at" && mutation == "null" {
						continue
					}
					t.Run(message+"/"+location+"/"+field+"/"+mutation, func(t *testing.T) {
						m := responseFields(t, fixtures[message])
						fields := object(m, location)
						switch mutation {
						case "missing":
							delete(fields, field)
						case "null":
							fields[field] = nil
						case "type":
							fields[field] = true
							if _, ok := object(responseFields(t, fixtures[message]), location)[field].(bool); ok {
								fields[field] = "false"
							}
						case "case", "case_alias":
							fields[strings.ToUpper(field)] = fields[field]
							if mutation == "case" {
								delete(fields, field)
							}
						}
						if err := decodeResponse(responseBytes(t, m), message == "register_ack"); err != ErrProtocol {
							t.Fatal("want ErrProtocol, got", err)
						}
					})
				}
			}
			m := responseFields(t, fixtures[message])
			object(m, location)["unknown"] = "secret"
			if decodeResponse(responseBytes(t, m), message == "register_ack") != ErrProtocol {
				t.Fatal("unknown field accepted", message, location)
			}
		}
		for _, field := range []string{"extensions", "credential_generation"} {
			if message == "register_nack" && field == "credential_generation" {
				continue
			}
			for _, value := range []any{nil, true, []any{}} {
				m := responseFields(t, fixtures[message])
				m[field] = value
				if decodeResponse(responseBytes(t, m), message == "register_ack") != ErrProtocol {
					t.Fatal("invalid optional field accepted", field, value)
				}
			}
		}
	}
}

func TestRegisterAckRanges(t *testing.T) {
	golden := responseFixtures(t)["register_ack"]
	for _, tc := range []struct {
		object, field string
		max           int64
	}{
		{"", "protocol_minor", 65535}, {"", "ready_not_before", maxTimestamp}, {"", "credential_expires_at", maxTimestamp},
		{"limits", "max_control_bytes", 65536}, {"limits", "max_chunk_bytes", 32768},
		{"limits", "initial_window_bytes", 65536}, {"limits", "max_header_bytes", 32768},
		{"limits", "max_raw_uri_bytes", 8192}, {"limits", "max_inflight", 1000}, {"limits", "buffer_bytes", 16777216},
		{"timeouts", "register_ms", 300000}, {"timeouts", "write_ms", 300000},
		{"timeouts", "cancel_ack_ms", 300000}, {"timeouts", "status_interval_ms", 300000},
		{"timeouts", "status_stale_ms", 300000}, {"timeouts", "drain_ms", 300000},
		{"readiness", "interval_ms", 300000}, {"readiness", "timeout_ms", 300000},
		{"readiness", "stale_after_ms", 300000}, {"readiness", "failure_threshold", 100}, {"readiness", "success_threshold", 100},
	} {
		min := int64(1)
		if tc.object == "" {
			min = 0
		}
		for _, value := range []any{min - 1, min, tc.max, tc.max + 1, 1.5, "1", 1e30} {
			t.Run(fmt.Sprint(tc.object, "/", tc.field, "/", value), func(t *testing.T) {
				m := responseFields(t, golden)
				fields := m
				if tc.object != "" {
					fields = m[tc.object].(map[string]any)
				}
				fields[tc.field] = value
				_, err := DecodeRegisterAck(responseBytes(t, m))
				valid := value == min || value == tc.max
				if (err == nil) != valid {
					t.Fatal("valid", valid, "error", err)
				}
			})
		}
	}
}

func TestRegisterAckSemantics(t *testing.T) {
	golden := responseFixtures(t)["register_ack"]
	for name, mutate := range map[string]func(map[string]any){
		"major":                  func(m map[string]any) { m["protocol_version"] = 2 },
		"type":                   func(m map[string]any) { m["type"] = "register" },
		"session_short":          func(m map[string]any) { m["session_id"] = "AA" },
		"session_noncanonical":   func(m map[string]any) { m["session_id"] = "AAECAwQFBgcICQoLDA0ODx" },
		"session_padding":        func(m map[string]any) { m["session_id"] = "AAECAwQFBgcICQoLDA0ODw==" },
		"session_newline":        func(m map[string]any) { m["session_id"] = "AAECAwQFBgcICQoLDA0OD\n" },
		"session_alphabet":       func(m map[string]any) { m["session_id"] = "AAECAwQFBgcICQoLDA0O+w" },
		"revision_overflow":      func(m map[string]any) { m["route_revision"] = "18446744073709551616" },
		"revision_number":        func(m map[string]any) { m["route_revision"] = 1 },
		"revision_leading_zero":  func(m map[string]any) { m["route_revision"] = "01" },
		"capabilities_baseline":  func(m map[string]any) { m["capabilities"] = []string{"mount_discovery"} },
		"required_baseline":      func(m map[string]any) { m["required_capabilities"] = []string{"mount_discovery"} },
		"capabilities_duplicate": func(m map[string]any) { m["capabilities"] = append(BaselineCapabilities(), "streaming") },
		"required_duplicate":     func(m map[string]any) { m["required_capabilities"] = append(BaselineCapabilities(), "streaming") },
		"required_unsupported":   func(m map[string]any) { m["required_capabilities"] = append(BaselineCapabilities(), "future") },
		"capabilities_invalid":   func(m map[string]any) { m["capabilities"] = append(BaselineCapabilities(), "Future") },
		"capabilities_null_item": func(m map[string]any) { m["capabilities"] = append(m["capabilities"].([]any), nil) },
		"empty_paths":            func(m map[string]any) { m["paths"] = []any{} },
		"null_path":              func(m map[string]any) { m["paths"] = []any{nil} },
		"path_traversal":         func(m map[string]any) { m["paths"] = []RegisterAckPath{{"/api/../x", "active"}} },
		"path_encoded":           func(m map[string]any) { m["paths"] = []RegisterAckPath{{"/api/%2f", "active"}} },
		"path_duplicate":         func(m map[string]any) { m["paths"] = []RegisterAckPath{{"/api", "active"}, {"/api/", "pending"}} },
		"path_state":             func(m map[string]any) { m["paths"] = []RegisterAckPath{{"/api", "ready"}} },
		"generation_zero":        func(m map[string]any) { m["credential_generation"] = "0" },
		"generation_overflow":    func(m map[string]any) { m["credential_generation"] = "18446744073709551616" },
		"generation_capability":  func(m map[string]any) { m["credential_generation"] = "1" },
	} {
		t.Run(name, func(t *testing.T) {
			m := responseFields(t, golden)
			mutate(m)
			if _, err := DecodeRegisterAck(responseBytes(t, m)); err != ErrProtocol {
				t.Fatal("want ErrProtocol, got", err)
			}
		})
	}
	for _, state := range []string{"active", "pending", "retired"} {
		m := responseFields(t, golden)
		m["paths"] = []RegisterAckPath{{"/", state}}
		m["route_revision"] = "18446744073709551615"
		m["credential_generation"] = "18446744073709551615"
		m["capabilities"] = append(BaselineCapabilities(), "credential_generation")
		m["required_capabilities"] = append(BaselineCapabilities(), "credential_generation")
		if _, err := DecodeRegisterAck(responseBytes(t, m)); err != nil {
			t.Fatal("valid semantic boundary", state, err)
		}
	}
	for _, count := range []int{32, 33} {
		m := responseFields(t, golden)
		var paths []RegisterAckPath
		for i := 0; i < count; i++ {
			paths = append(paths, RegisterAckPath{fmt.Sprint("/p", i), "pending"})
		}
		m["paths"] = paths
		if err := decodeResponse(responseBytes(t, m), true); (err == nil) != (count == 32) {
			t.Fatal("path count", count, err)
		}
		m = responseFields(t, golden)
		caps := BaselineCapabilities()
		for i := len(caps); i < count; i++ {
			caps = append(caps, fmt.Sprint("feature_", i))
		}
		m["capabilities"], m["required_capabilities"] = caps, caps
		if err := decodeResponse(responseBytes(t, m), true); (err == nil) != (count == 32) {
			t.Fatal("capability count", count, err)
		}
	}
}

func TestRegisterNackCodesAndDetail(t *testing.T) {
	for code, retryable := range map[string]bool{
		"auth_failed": false, "invalid_register": false, "unsupported_protocol_version": false,
		"path_forbidden": false, "path_conflict": false, "duplicate_instance": true,
		"quota_exceeded": true, "state_unavailable": true, "server_shutdown": true,
	} {
		for _, actual := range []bool{false, true} {
			r := RegisterNack{Type: "register_nack", Code: code, Retryable: actual}
			if err := r.Validate(); (err == nil) != (actual == retryable) {
				t.Fatal(code, actual, err)
			}
			if err := decodeResponse(responseBytes(t, r), false); (err == nil) != (actual == retryable) {
				t.Fatal("decode", code, actual, err)
			}
		}
	}
	for _, r := range []RegisterNack{
		{Type: "register_nack", Code: "protocol_error"},
		{Type: "register_nack", Code: "unknown", Retryable: true},
		{Type: "register_ack", Code: "auth_failed"},
		{Type: "register_nack", Code: "auth_failed", Detail: string([]byte{0xff})},
	} {
		if r.Validate() != ErrProtocol {
			t.Fatal("accepted invalid nack")
		}
	}
	for _, detail := range []string{"", strings.Repeat("x", 512), strings.Repeat("я", 256), strings.Repeat("x", 513), strings.Repeat("я", 257)} {
		r := RegisterNack{Type: "register_nack", Code: "auth_failed", Detail: detail}
		valid := len(detail) <= 512
		if err := decodeResponse(responseBytes(t, r), false); (err == nil) != valid {
			t.Fatal("detail byte limit", len(detail), err)
		}
	}
}

func TestRegisterResponsesJSONAndExtensions(t *testing.T) {
	fixtures := responseFixtures(t)
	for _, message := range []string{"register_ack", "register_nack"} {
		ack := message == "register_ack"
		compact := bytes.TrimSpace(responseBytes(t, json.RawMessage(fixtures[message])))
		for _, b := range [][]byte{
			nil, []byte(`[]`), []byte(`null`), append(append([]byte{}, compact...), []byte(` {}`)...),
			bytes.Replace(compact, []byte(`"type":`), []byte(`"type":"secret","type":`), 1),
			append(append([]byte{}, compact[:len(compact)-1]...), []byte(`,"extensions":{"x":{"a":1,"a":2}}}`)...),
			append(append([]byte{}, compact[:len(compact)-1]...), []byte(`,"extensions":{"x":"\ud800"}}`)...),
			append(append([]byte{}, compact[:len(compact)-1]...), []byte(",\"extensions\":{\"x\":\"\xff\"}}")...),
		} {
			if decodeResponse(b, ack) != ErrProtocol {
				t.Fatal(message, "accepted invalid JSON")
			}
		}
		if ack {
			b := bytes.Replace(compact, []byte(`"max_inflight":100`), []byte(`"max_inflight":100,"max_inflight":1`), 1)
			if decodeResponse(b, true) != ErrProtocol {
				t.Fatal("nested duplicate accepted")
			}
		}
		for _, count := range []int{0, 32, 33} {
			m := responseFields(t, compact)
			ext := make(map[string]any)
			for i := 0; i < count; i++ {
				ext[fmt.Sprint(i)] = []any{nil, true, map[string]any{"future": 1}}
			}
			m["extensions"] = ext
			if err := decodeResponse(responseBytes(t, m), ack); (err == nil) != (count <= 32) {
				t.Fatal("extension count", count, err)
			}
		}
		for _, size := range []int{MaxControlBytes, MaxControlBytes + 1} {
			b := append(append([]byte{}, compact...), bytes.Repeat([]byte(" "), size-len(compact))...)
			if err := decodeResponse(b, ack); (err == nil) != (size == MaxControlBytes) {
				t.Fatal("control limit", size, err)
			}
		}
		for _, depth := range []int{30, 31} {
			m := responseFields(t, compact)
			m["extensions"] = map[string]json.RawMessage{"x": json.RawMessage(strings.Repeat("[", depth) + "0" + strings.Repeat("]", depth))}
			if err := decodeResponse(responseBytes(t, m), ack); (err == nil) != (depth == 30) {
				t.Fatal("extension depth", depth, err)
			}
		}
	}
	ack, _ := DecodeRegisterAck(fixtures["register_ack"])
	nack, _ := DecodeRegisterNack(fixtures["register_nack"])
	for _, ext := range []map[string]json.RawMessage{
		{"bad": json.RawMessage(`{"x":1,"x":2}`)},
		{"bad": json.RawMessage(`"\ud800"`)},
		{"bad": json.RawMessage(`{`)},
		{"bad": json.RawMessage{'"', 0xff, '"'}},
		{string([]byte{0xff}): json.RawMessage(`null`)},
		{"large": json.RawMessage(`"` + strings.Repeat("x", MaxControlBytes) + `"`)},
	} {
		ack.Extensions, nack.Extensions = ext, ext
		if ack.Validate() != ErrProtocol || nack.Validate() != ErrProtocol {
			t.Fatal("programmatic extensions bypassed validation")
		}
	}
}

func TestRegisterAckForRegister(t *testing.T) {
	fixtures := responseFixtures(t)
	newPair := func() (Register, RegisterAck) {
		r, err := DecodeRegister(fixtures["register"])
		if err != nil {
			t.Fatal(err)
		}
		a, err := DecodeRegisterAck(fixtures["register_ack"])
		if err != nil {
			t.Fatal(err)
		}
		return r, a
	}
	r, a := newPair()
	dev := RegisterAckValidationOptions{Development: true}
	if a.ValidateForRegister(r, dev) != nil || a.ValidateForRegister(r, RegisterAckValidationOptions{}) != ErrProtocol {
		t.Fatal("development must be explicit for null expiry")
	}
	expiry := int64(1700001000)
	a.CredentialExpiresAt = &expiry
	if err := a.ValidateForRegister(r, RegisterAckValidationOptions{}); err != nil {
		t.Fatal("production", err)
	}
	for name, mutate := range map[string]func(*Register, *RegisterAck){
		"invalid_ack":            func(r *Register, a *RegisterAck) { a.Type = "wrong" },
		"invalid_register":       func(r *Register, a *RegisterAck) { r.Type = "wrong" },
		"higher_minor":           func(r *Register, a *RegisterAck) { a.ProtocolMinor = 1 },
		"inflight":               func(r *Register, a *RegisterAck) { a.Limits.MaxInflight = r.MaxConcurrentRequests + 1 },
		"readiness":              func(r *Register, a *RegisterAck) { r.ReadinessCheckConfigured = false },
		"missing_path":           func(r *Register, a *RegisterAck) { r.Paths = append(r.Paths, "/other") },
		"extra_path":             func(r *Register, a *RegisterAck) { a.Paths = append(a.Paths, RegisterAckPath{"/other", "pending"}) },
		"different_path":         func(r *Register, a *RegisterAck) { a.Paths[0].Path = "/different" },
		"unsupported_capability": func(r *Register, a *RegisterAck) { a.Capabilities = append(a.Capabilities, "future") },
		"missing_sdk_required": func(r *Register, a *RegisterAck) {
			a.Capabilities, a.RequiredCapabilities = BaselineCapabilities(), BaselineCapabilities()
		},
		"gateway_required_unsupported": func(r *Register, a *RegisterAck) {
			a.Capabilities = append(a.Capabilities, "future")
			a.RequiredCapabilities = append(a.RequiredCapabilities, "future")
		},
		"generation_ack_only": func(r *Register, a *RegisterAck) {
			a.Capabilities = append(a.Capabilities, "credential_generation")
			a.RequiredCapabilities = append(a.RequiredCapabilities, "credential_generation")
			r.Capabilities = append(r.Capabilities, "credential_generation")
			g := U64(1)
			a.CredentialGeneration = &g
		},
		"generation_register_only": func(r *Register, a *RegisterAck) {
			r.Capabilities = append(r.Capabilities, "credential_generation")
			r.RequiredCapabilities = append(r.RequiredCapabilities, "credential_generation")
			a.Capabilities = append(a.Capabilities, "credential_generation")
			g := U64(1)
			r.CredentialGeneration = &g
		},
		"generation_mismatch": func(r *Register, a *RegisterAck) {
			r.Capabilities = append(r.Capabilities, "credential_generation")
			r.RequiredCapabilities = append(r.RequiredCapabilities, "credential_generation")
			a.Capabilities = append(a.Capabilities, "credential_generation")
			a.RequiredCapabilities = append(a.RequiredCapabilities, "credential_generation")
			g1, g2 := U64(1), U64(2)
			r.CredentialGeneration, a.CredentialGeneration = &g1, &g2
		},
	} {
		t.Run(name, func(t *testing.T) {
			r, a := newPair()
			mutate(&r, &a)
			if err := a.ValidateForRegister(r, dev); err != ErrProtocol {
				t.Fatal("want ErrProtocol, got", err)
			}
		})
	}
	r, a = newPair()
	r.ProtocolMinor = 2
	a.ProtocolMinor = 1
	r.Paths = append(r.Paths, "/other/")
	a.Paths = append([]RegisterAckPath{{"/other", "pending"}}, a.Paths...)
	r.ReadinessCheckConfigured, a.Readiness.Required = false, false
	g := U64(2)
	r.CredentialGeneration, a.CredentialGeneration = &g, &g
	r.Capabilities = append(r.Capabilities, "credential_generation", "optional")
	r.RequiredCapabilities = append(r.RequiredCapabilities, "credential_generation")
	a.Capabilities = append(a.Capabilities, "credential_generation")
	a.RequiredCapabilities = append(a.RequiredCapabilities, "credential_generation")
	before := responseBytes(t, []any{r, a})
	if err := a.ValidateForRegister(r, dev); err != nil {
		t.Fatal("normalized paths, optional feature, lower minor, matching generation", err)
	}
	if !bytes.Equal(before, responseBytes(t, []any{r, a})) {
		t.Fatal("helper mutated input")
	}
}

func FuzzDecodeRegisterAck(f *testing.F) {
	f.Add([]byte(responseFixtures(f)["register_ack"]))
	f.Add([]byte(`{"type":"register_ack"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DecodeRegisterAck(b)
		if err != nil {
			if err != ErrProtocol || !reflect.DeepEqual(r, RegisterAck{}) {
				t.Fatal("unsafe failure result")
			}
			return
		}
		if r.Validate() != nil || ValidateControlJSON(b) != nil {
			t.Fatal("invalid accepted ack")
		}
		next, err := DecodeRegisterAck(responseBytes(t, r))
		if err != nil || !bytes.Equal(responseBytes(t, r), responseBytes(t, next)) {
			t.Fatal("round trip", err)
		}
	})
}

func FuzzDecodeRegisterNack(f *testing.F) {
	f.Add([]byte(responseFixtures(f)["register_nack"]))
	f.Add([]byte(`{"type":"register_nack"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DecodeRegisterNack(b)
		if err != nil {
			if err != ErrProtocol || !reflect.DeepEqual(r, RegisterNack{}) {
				t.Fatal("unsafe failure result")
			}
			return
		}
		if r.Validate() != nil || ValidateControlJSON(b) != nil {
			t.Fatal("invalid accepted nack")
		}
		next, err := DecodeRegisterNack(responseBytes(t, r))
		if err != nil || !bytes.Equal(responseBytes(t, r), responseBytes(t, next)) {
			t.Fatal("round trip", err)
		}
	})
}
