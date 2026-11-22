package v1

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestQUICQuiescentFenceGolden(t *testing.T) {
	b, err := os.ReadFile("../../tests/fixtures/protocol/v1/quic-quiescent-fence.json")
	if err != nil {
		t.Fatal(err)
	}
	// Underscore field names must match the external golden corpus explicitly.
	var corpus struct {
		Positive []struct {
			Name    string
			Message json.RawMessage
			JSON    string `json:"control_json_utf8"`
			Frame   string `json:"frame_hex"`
			Fence   U64
		}
		Negative []struct {
			Name       string
			Extensions map[string]json.RawMessage
		}
	}
	if err = json.Unmarshal(b, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, c := range corpus.Positive {
		var control struct{ Extensions map[string]json.RawMessage }
		if err = json.Unmarshal(c.Message, &control); err != nil {
			t.Fatal(err)
		}
		got, err := DecodeQUICQuiescentFence(control.Extensions)
		if err != nil || got != uint64(c.Fence) {
			t.Fatal(c.Name, got, err)
		}
		var frame bytes.Buffer
		if err = WriteControl(&frame, []byte(c.JSON), MaxControlBytes); err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(frame.Bytes()) != c.Frame {
			t.Fatal(c.Name, "golden frame changed")
		}
		generated := QUICQuiescentFenceExtensions(got)
		if !bytes.Equal(generated[QUICQuiescentFenceCapability], control.Extensions[QUICQuiescentFenceCapability]) {
			t.Fatal("canonical marker changed")
		}
	}
	for _, c := range corpus.Negative {
		if _, err := DecodeQUICQuiescentFence(c.Extensions); err != ErrProtocol {
			t.Fatal(c.Name, "invalid marker accepted", err)
		}
	}
	ack := RegisterAck{ProtocolMinor: 1, Capabilities: []string{QUICQuiescentFenceCapability}, RequiredCapabilities: []string{QUICQuiescentFenceCapability}}
	if !HasQUICQuiescentFence(ack) {
		t.Fatal("negotiated capability ignored")
	}
	ack.ProtocolMinor = 0
	if HasQUICQuiescentFence(ack) {
		t.Fatal("minor 0 enabled fence")
	}
	ack.ProtocolMinor = 1
	ack.RequiredCapabilities = nil
	if HasQUICQuiescentFence(ack) {
		t.Fatal("optional unknown extension enabled fence")
	}
}

func TestQUICFenceNegotiation(t *testing.T) {
	var corpus struct{ Positive []json.RawMessage }
	fixture(t, "control-messages.json", &corpus)
	r, err := DecodeRegister(corpus.Positive[0])
	if err != nil {
		t.Fatal(err)
	}
	a, err := DecodeRegisterAck(corpus.Positive[1])
	if err != nil {
		t.Fatal(err)
	}
	r.ProtocolMinor = 1
	a.ProtocolMinor = 1
	r.Capabilities = append(r.Capabilities, QUICQuiescentFenceCapability)
	r.RequiredCapabilities = append(r.RequiredCapabilities, QUICQuiescentFenceCapability)
	a.Capabilities = append(a.Capabilities, QUICQuiescentFenceCapability)
	a.RequiredCapabilities = append(a.RequiredCapabilities, QUICQuiescentFenceCapability)
	if err = a.ValidateForRegister(r, RegisterAckValidationOptions{Development: true}); err != nil {
		t.Fatal(err)
	}
	saved := a.RequiredCapabilities
	a.RequiredCapabilities = a.RequiredCapabilities[:len(a.RequiredCapabilities)-1]
	if a.ValidateForRegister(r, RegisterAckValidationOptions{Development: true}) != ErrProtocol {
		t.Fatal("required fence silently disabled")
	}
	a.RequiredCapabilities = saved
	r.ProtocolMinor = 0
	if r.Validate() != ErrProtocol {
		t.Fatal("minor 0 required native fence")
	}
	r.ProtocolMinor = 1
	r.RequiredCapabilities = r.RequiredCapabilities[:len(r.RequiredCapabilities)-1]
	if a.ValidateForRegister(r, RegisterAckValidationOptions{Development: true}) != ErrProtocol {
		t.Fatal("fence not required by both peers")
	}
}

func FuzzDecodeQUICQuiescentFence(f *testing.F) {
	for _, s := range []string{`"0"`, `"1"`, `"18446744073709551615"`, `"01"`, `null`, `1`, `"18446744073709551616"`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		value, err := DecodeQUICQuiescentFence(map[string]json.RawMessage{QUICQuiescentFenceCapability: json.RawMessage(s)})
		if err == nil {
			canonical := QUICQuiescentFenceExtensions(value)
			again, e := DecodeQUICQuiescentFence(canonical)
			if e != nil || again != value {
				t.Fatal("unstable fence")
			}
		}
	})
}
