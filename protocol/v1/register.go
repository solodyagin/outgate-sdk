package v1

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	idPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	featurePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	mountPattern   = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
)

// BaselineCapabilities returns a fresh slice so callers cannot change the baseline.
func BaselineCapabilities() []string {
	return []string{"streaming", "cancellation", "duplex_websocket", "bounded_flow_control"}
}

// Register contains wire data only, never credentials or gateway policy.
type Register struct {
	Type                     string                     `json:"type"`
	ProtocolVersion          int                        `json:"protocol_version"`
	ProtocolMinor            int                        `json:"protocol_minor"`
	Capabilities             []string                   `json:"capabilities"`
	RequiredCapabilities     []string                   `json:"required_capabilities"`
	ServiceID                string                     `json:"service_id"`
	InstanceID               string                     `json:"instance_id"`
	Version                  string                     `json:"version"`
	Paths                    []string                   `json:"paths"`
	Mounts                   map[string]string          `json:"mounts,omitempty"`
	PathMode                 string                     `json:"path_mode"`
	RewriteMountHeaders      bool                       `json:"rewrite_mount_headers"`
	Metadata                 map[string]string          `json:"metadata,omitempty"`
	ReadinessCheckConfigured bool                       `json:"readiness_check_configured"`
	MaxConcurrentRequests    int                        `json:"max_concurrent_requests"`
	CredentialGeneration     *U64                       `json:"credential_generation,omitempty"`
	Extensions               map[string]json.RawMessage `json:"extensions,omitempty"`
}

// DecodeRegister rejects missing/null/unknown fields before semantic validation.
// No routing state may be published until the caller also checks credentials,
// permissions, conflicts and durable registration requirements.
func DecodeRegister(b []byte) (Register, error) {
	var result Register
	if err := ValidateControlJSON(b); err != nil {
		return result, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		return result, ErrProtocol
	}
	for _, name := range []string{"type", "protocol_version", "protocol_minor", "capabilities", "required_capabilities", "service_id", "instance_id", "version", "paths", "path_mode", "rewrite_mount_headers", "readiness_check_configured", "max_concurrent_requests"} {
		if _, ok := fields[name]; !ok {
			return result, ErrProtocol
		}
	}
	for _, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return result, ErrProtocol
		}
	}
	for _, name := range []string{"mounts", "metadata"} {
		if raw, ok := fields[name]; ok {
			var entries map[string]json.RawMessage
			if json.Unmarshal(raw, &entries) != nil {
				return result, ErrProtocol
			}
			for _, entry := range entries {
				if bytes.Equal(bytes.TrimSpace(entry), []byte("null")) {
					return result, ErrProtocol
				}
			}
		}
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&result); err != nil {
		return Register{}, ErrProtocol
	}
	if err := result.Validate(); err != nil {
		return Register{}, err
	}
	return result, nil
}

func (r Register) Validate() error {
	if len(r.Extensions) > 32 {
		return ErrProtocol
	}
	if r.Type != "register" || r.ProtocolVersion != Major || r.ProtocolMinor < 0 || r.ProtocolMinor > 65535 || !idPattern.MatchString(r.ServiceID) || !idPattern.MatchString(r.InstanceID) {
		return ErrProtocol
	}
	if !utf8.ValidString(r.Version) || len(r.Version) < 1 || len(r.Version) > 128 || strings.TrimSpace(r.Version) == "" || strings.ContainsFunc(r.Version, unicode.IsControl) {
		return ErrProtocol
	}
	if r.PathMode != "preserve" && r.PathMode != "strip" || r.MaxConcurrentRequests < 1 || r.MaxConcurrentRequests > 1000000 {
		return ErrProtocol
	}
	if _, err := capabilitySet(r.Capabilities, r.RequiredCapabilities); err != nil {
		return err
	}
	if len(r.Paths) < 1 || len(r.Paths) > 32 {
		return ErrProtocol
	}
	paths := make(map[string]bool)
	exactPaths := make(map[string]bool)
	for _, path := range r.Paths {
		normalized, err := NormalizePrefix(path)
		if err != nil || paths[normalized] {
			return ErrProtocol
		}
		paths[normalized] = true
		exactPaths[path] = true
	}
	if r.Mounts != nil {
		if len(r.Mounts) < 1 || len(r.Mounts) > 32 || !contains(r.RequiredCapabilities, "mount_discovery") {
			return ErrProtocol
		}
		for id, path := range r.Mounts {
			if !mountPattern.MatchString(id) || !exactPaths[path] {
				return ErrProtocol
			}
		}
	}
	if r.CredentialGeneration != nil && (*r.CredentialGeneration == 0 || !contains(r.RequiredCapabilities, "credential_generation")) {
		return ErrProtocol
	}
	if len(r.Metadata) > 32 {
		return ErrProtocol
	}
	total := 0
	for key, value := range r.Metadata {
		if !utf8.ValidString(key) || !utf8.ValidString(value) || len(key) < 1 || len(key) > 64 || len(value) > 1024 {
			return ErrProtocol
		}
		total += len(key) + len(value)
	}
	if total > 8192 {
		return ErrProtocol
	}
	return nil
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func capabilitySet(supported, required []string) (map[string]bool, error) {
	if len(supported) > 32 || len(required) > 32 {
		return nil, ErrProtocol
	}
	s := make(map[string]bool)
	for _, value := range supported {
		if !featurePattern.MatchString(value) || s[value] {
			return nil, ErrProtocol
		}
		s[value] = true
	}
	r := make(map[string]bool)
	for _, value := range required {
		if !featurePattern.MatchString(value) || r[value] || !s[value] {
			return nil, ErrProtocol
		}
		r[value] = true
	}
	for _, value := range BaselineCapabilities() {
		if !s[value] || !r[value] {
			return nil, ErrProtocol
		}
	}
	return s, nil
}

// NegotiateCapabilities checks both peers' required features. Intersection order
// follows localSupported, making the result deterministic. Minor is negotiated
// separately as min(localMinor, peerMinor) after major compatibility is checked.
func NegotiateCapabilities(localSupported, localRequired, peerSupported, peerRequired []string) ([]string, error) {
	l, err := capabilitySet(localSupported, localRequired)
	if err != nil {
		return nil, err
	}
	p, err := capabilitySet(peerSupported, peerRequired)
	if err != nil {
		return nil, err
	}
	for _, value := range localRequired {
		if !p[value] {
			return nil, ErrProtocol
		}
	}
	for _, value := range peerRequired {
		if !l[value] {
			return nil, ErrProtocol
		}
	}
	var intersection []string
	for _, value := range localSupported {
		if p[value] {
			intersection = append(intersection, value)
		}
	}
	return intersection, nil
}
