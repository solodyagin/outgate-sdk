package v1

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestSessionControlNumbers(t *testing.T) {
	fixtures := responseFixtures(t)
	for _, name := range []string{"instance_status", "drain", "unregister", "reconnect"} {
		field := "deadline_ms"
		if name == "instance_status" {
			field = "observed_at"
		}
		values := []string{`-1`, `0`, `1`, `30000`, `30001`, `253402300799`, `253402300800`, `9223372036854775808`, `"1"`, `null`, `true`, `1.5`, `1.0`, `1e0`}
		for _, raw := range values {
			t.Run(name+"/"+raw, func(t *testing.T) {
				m := responseFields(t, fixtures[name])
				m[field] = json.RawMessage(raw)
				valid := raw == "1" || raw == "30000" || name == "instance_status" && (raw == "0" || raw == "30001" || raw == "253402300799")
				r, err := decodeStreamMessage(name, responseBytes(t, m))
				if (err == nil) != valid {
					t.Fatalf("accepted=%v, expected=%v", err == nil, valid)
				}
				if valid && r.Validate() != nil {
					t.Fatal("decoded invalid message")
				}
			})
		}
	}
}

func TestSessionControlStatus(t *testing.T) {
	for _, code := range []string{"ready", "initializing", "dependency_unavailable", "security_recovery", "draining", "", "READY", "unknown", "ready\n"} {
		for _, ready := range []bool{false, true} {
			// Cross-field readiness/security policy belongs to the session layer;
			// codecs enforce the normative closed code enum and boolean wire type.
			m := InstanceStatus{Type: "instance_status", Sequence: 1, Ready: ready, Code: code}
			valid := contains([]string{"ready", "initializing", "dependency_unavailable", "security_recovery", "draining"}, code)
			if (m.Validate() == nil) != valid {
				t.Fatalf("status %q", code)
			}
			if _, err := DecodeInstanceStatus(responseBytes(t, m)); (err == nil) != valid {
				t.Fatalf("decode %q", code)
			}
		}
	}
	for _, timestamp := range []int64{-1, maxTimestamp + 1} {
		m := InstanceStatus{Type: "instance_status", Sequence: 1, Code: "ready", ObservedAt: timestamp}
		if !errors.Is(m.Validate(), ErrProtocol) {
			t.Fatal("constructed timestamp")
		}
	}
}

func TestSessionCommandCodeAndConstructedBounds(t *testing.T) {
	fixtures := responseFixtures(t)
	for _, name := range []string{"drain", "unregister", "reconnect"} {
		validCodes := []string{"a", "custom_reason_42", "a" + strings.Repeat("0", 63)}
		for _, code := range append(validCodes, "", "A", "1reason", "a-b", "a b", "a\n", "é", strings.Repeat("a", 65)) {
			m := responseFields(t, fixtures[name])
			m["code"] = code
			if _, err := decodeStreamMessage(name, responseBytes(t, m)); (err == nil) != contains(validCodes, code) {
				t.Fatalf("%s code %q", name, code)
			}
		}
		for _, deadline := range []int{-1, 0, 30001} {
			var r streamControlMessage
			switch name {
			case "drain":
				r = Drain{Type: name, CommandID: 1, DeadlineMS: deadline, Code: "shutdown"}
			case "unregister":
				r = Unregister{Type: name, CommandID: 1, DeadlineMS: deadline, Code: "shutdown"}
			case "reconnect":
				r = Reconnect{Type: name, CommandID: 1, DeadlineMS: deadline, Code: "shutdown"}
			}
			if !errors.Is(r.Validate(), ErrProtocol) {
				t.Fatal("constructed deadline")
			}
		}
	}
}

func FuzzDecodeInstanceStatus(f *testing.F) { fuzzStreamControl(f, "instance_status") }
func FuzzDecodeDrain(f *testing.F)          { fuzzStreamControl(f, "drain") }
func FuzzDecodeDrainAck(f *testing.F)       { fuzzStreamControl(f, "drain_ack") }
func FuzzDecodeUnregister(f *testing.F)     { fuzzStreamControl(f, "unregister") }
func FuzzDecodeUnregisterAck(f *testing.F)  { fuzzStreamControl(f, "unregister_ack") }
func FuzzDecodeReconnect(f *testing.F)      { fuzzStreamControl(f, "reconnect") }
