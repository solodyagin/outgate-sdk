package v1

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestJSONValidation(t *testing.T) {
	for _, s := range []string{`{}`, `{"extensions":{"items":[{},1,null,true]}}`, `{"a":"\ud83d\ude00"}`, `{"a":"\\ud800"}`} {
		if err := ValidateControlJSON([]byte(s)); err != nil {
			t.Fatalf("valid JSON rejected: %s", s)
		}
	}
	for _, s := range []string{
		``, `[]`, `null`, `{} {}`, `{"x":1,"x":2}`, `{"x":1,"\u0078":2}`,
		`{"x":{"a":1,"a":2}}`, `{"a":NaN}`, `{"a":"\ud800"}`, `{"a":"\udc00"}`,
		`{"a":"\ud800\u0000"}`, "{\"a\":\"\xff\"}",
		`{"a":` + strings.Repeat(`[`, 32) + `0` + strings.Repeat(`]`, 32) + `}`,
		`{"a":"` + strings.Repeat("x", MaxControlBytes) + `"}`,
	} {
		if err := ValidateControlJSON([]byte(s)); err == nil {
			t.Fatalf("invalid JSON accepted: %.80s", s)
		}
	}
	if err := ValidateControlJSON([]byte(`{"a":` + strings.Repeat(`[`, 31) + `0` + strings.Repeat(`]`, 31) + `}`)); err != nil {
		t.Fatal("depth 32 rejected")
	}
}

func TestU64(t *testing.T) {
	for _, s := range []string{`"0"`, `"1"`, `"18446744073709551615"`} {
		var n U64
		if err := json.Unmarshal([]byte(s), &n); err != nil {
			t.Fatal(s, err)
		}
		b, err := json.Marshal(n)
		if err != nil || string(b) != s {
			t.Fatal("round trip", s, err)
		}
	}
	for _, s := range []string{`0`, `null`, `""`, `"00"`, `"+1"`, `"-1"`, `"1.0"`, `"1e2"`, `"18446744073709551616"`, `"\u0031"`} {
		var n U64
		if json.Unmarshal([]byte(s), &n) == nil {
			t.Fatal("accepted", s)
		}
	}
}

func TestPaths(t *testing.T) {
	for _, tc := range []struct{ raw, decoded string }{
		{"/api/v1/", "/api/v1/"}, {"/caf%C3%A9?q=%2f&b=2&a=1", "/café"},
		{"/api/%252f", "/api/%2f"}, {"/", "/"}, {"/a%20b", "/a b"},
	} {
		got, err := DecodeRoutePath(tc.raw)
		if err != nil || got != tc.decoded {
			t.Fatal(tc, got, err)
		}
	}
	for _, raw := range []string{"", "api", "//a", "/a//b", "/a/../b", "/a/%2e", "/a/%2F", "/a/%5c", "/a\\b", "/a%00", "/a%7f", "/a%", "/a#b", "/%ff", "/a?b=\n", "/a b", "/a?b=c d"} {
		if _, err := DecodeRoutePath(raw); err == nil {
			t.Fatal("accepted URI", raw)
		}
	}
	for _, raw := range []string{"/a//", "/a%20", "/a?b", "/a#b", "/a b", "/a/./b"} {
		if _, err := NormalizePrefix(raw); err == nil {
			t.Fatal("accepted prefix", raw)
		}
	}
	if got, err := NormalizePrefix("/api/"); err != nil || got != "/api" {
		t.Fatal(got, err)
	}
	if !MatchesPrefix("/api", "/api/users") || MatchesPrefix("/api", "/apix") {
		t.Fatal("segment boundary")
	}
	if PrefixAllowed("/", "/api") || !PrefixAllowed("/", "/") || !PrefixAllowed("/api/", "/api/v1") || PrefixAllowed("/api", "/apix") {
		t.Fatal("permissions")
	}
}

func TestRegisterGoldenAndRejections(t *testing.T) {
	var vectors struct{ Positive []json.RawMessage }
	fixture(t, "control-messages.json", &vectors)
	var fields map[string]any
	if err := json.Unmarshal(vectors.Positive[0], &fields); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRegister(vectors.Positive[0]); err != nil {
		t.Fatal(err)
	}
	for name, mutation := range map[string]func(map[string]any){
		"unknown":              func(m map[string]any) { m["token"] = "secret" },
		"missing_boolean":      func(m map[string]any) { delete(m, "rewrite_mount_headers") },
		"null_boolean":         func(m map[string]any) { m["rewrite_mount_headers"] = nil },
		"null_metadata_value":  func(m map[string]any) { m["metadata"] = map[string]any{"key": nil} },
		"major":                func(m map[string]any) { m["protocol_version"] = 2 },
		"normalized_duplicate": func(m map[string]any) { m["paths"] = []string{"/api/v2", "/api/v2/"} },
		"mount_not_exact":      func(m map[string]any) { m["mounts"] = map[string]string{"api": "/api/v2/"} },
		"blank_version":        func(m map[string]any) { m["version"] = "  " },
		"version_bytes":        func(m map[string]any) { m["version"] = strings.Repeat("я", 65) },
		"metadata_budget": func(m map[string]any) {
			meta := map[string]string{}
			for i := 0; i < 9; i++ {
				meta[string(rune('a'+i))] = strings.Repeat("x", 1024)
			}
			m["metadata"] = meta
		},
		"generation_capability": func(m map[string]any) { m["credential_generation"] = "1" },
		"baseline":              func(m map[string]any) { m["required_capabilities"] = []string{"mount_discovery"} },
		"duplicate_capability":  func(m map[string]any) { m["capabilities"] = append(BaselineCapabilities(), "streaming") },
	} {
		t.Run(name, func(t *testing.T) {
			m := make(map[string]any)
			for k, v := range fields {
				m[k] = v
			}
			mutation(m)
			b, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeRegister(b); err == nil {
				t.Fatal("accepted invalid registration")
			}
		})
	}
	base := BaselineCapabilities()
	if _, err := NegotiateCapabilities(base, base, append(BaselineCapabilities(), "optional"), base); err != nil {
		t.Fatal(err)
	}
	if _, err := NegotiateCapabilities(base, base, append(BaselineCapabilities(), "required"), append(BaselineCapabilities(), "required")); err == nil {
		t.Fatal("unmet peer capability")
	}
	if _, err := NegotiateCapabilities(append(BaselineCapabilities(), "required"), append(BaselineCapabilities(), "required"), base, base); err == nil {
		t.Fatal("unmet local capability")
	}
}

func FuzzControlJSON(f *testing.F) {
	f.Add([]byte(`{"type":"register"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if ValidateControlJSON(b) == nil && !json.Valid(b) {
			t.Fatal("accepted invalid JSON")
		}
	})
}
