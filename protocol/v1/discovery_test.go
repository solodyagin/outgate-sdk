package v1

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func discoveryFixtures(t *testing.T) ([]json.RawMessage, []struct{ Name, JSON string }) {
	t.Helper()
	data, err := os.ReadFile("../../tests/fixtures/discovery/v1/responses.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct {
		Positive []json.RawMessage
		Negative []struct{ Name, JSON string }
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures.Positive, fixtures.Negative
}
func TestDiscoveryGoldenAndStrictDecoder(t *testing.T) {
	positive, negative := discoveryFixtures(t)
	for _, raw := range positive {
		response, err := DecodeDiscoveryResponse(raw)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		var compact bytes.Buffer
		_ = json.Compact(&compact, raw)
		if !bytes.Equal(encoded, compact.Bytes()) {
			t.Fatal("golden bytes changed")
		}
		again, err := DecodeDiscoveryResponse(encoded)
		if err != nil || !reflect.DeepEqual(again, response) {
			t.Fatal("round trip")
		}
	}
	for _, test := range negative {
		t.Run(test.Name, func(t *testing.T) {
			if _, err := DecodeDiscoveryResponse([]byte(test.JSON)); err == nil {
				t.Fatal("accepted negative")
			}
		})
	}
	base := string(positive[0])
	for _, raw := range []string{strings.Replace(base, `"service_id"`, `"Service_ID"`, 1), strings.Replace(base, `"path_mode"`, `"Path_mode"`, 1), strings.Replace(base, `"path_mode": "strip"`, `"path_mode": null`, 1), base + `{}`, strings.Repeat(" ", MaxDiscoveryBytes+1), string([]byte{0xff})} {
		if _, err := DecodeDiscoveryResponse([]byte(raw)); err == nil {
			t.Fatal("accepted malformed discovery")
		}
	}
	response, _ := DecodeDiscoveryResponse(positive[0])
	response.Mounts = map[string]DiscoveryMount{}
	for i := 0; i < 33; i++ {
		response.Mounts["a"+strings.Repeat("a", i)] = DiscoveryMount{Path: "/api", PathMode: "strip"}
	}
	if response.Validate() == nil {
		t.Fatal("unbounded mount count")
	}
}
func FuzzDecodeDiscoveryResponse(f *testing.F) {
	data, err := os.ReadFile("../../tests/fixtures/discovery/v1/responses.json")
	if err != nil {
		f.Fatal(err)
	}
	var fixtures struct{ Positive []json.RawMessage }
	if err := json.Unmarshal(data, &fixtures); err != nil {
		f.Fatal(err)
	}
	for _, raw := range fixtures.Positive {
		f.Add([]byte(raw))
	}
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		response, err := DecodeDiscoveryResponse(raw)
		if err != nil {
			return
		}
		if response.Validate() != nil {
			t.Fatal("invalid decoded object")
		}
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		if len(encoded) <= MaxDiscoveryBytes {
			again, err := DecodeDiscoveryResponse(encoded)
			if err != nil || !reflect.DeepEqual(again, response) {
				t.Fatal("unstable discovery decode")
			}
		}
	})
}
