package v1

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"unicode/utf8"
)

const maxTimestamp int64 = 253402300799

// RegisterAck contains accepted wire parameters, not proof of authentication,
// durable registration, route activation or readiness.
type RegisterAck struct {
	Type                 string                     `json:"type"`
	ProtocolVersion      int                        `json:"protocol_version"`
	ProtocolMinor        int                        `json:"protocol_minor"`
	Capabilities         []string                   `json:"capabilities"`
	RequiredCapabilities []string                   `json:"required_capabilities"`
	SessionID            string                     `json:"session_id"`
	RouteRevision        U64                        `json:"route_revision"`
	Paths                []RegisterAckPath          `json:"paths"`
	Limits               RegisterAckLimits          `json:"limits"`
	Timeouts             RegisterAckTimeouts        `json:"timeouts"`
	Readiness            RegisterAckReadiness       `json:"readiness"`
	CredentialExpiresAt  *int64                     `json:"credential_expires_at"`
	ReadyNotBefore       int64                      `json:"ready_not_before"`
	CredentialGeneration *U64                       `json:"credential_generation,omitempty"`
	Extensions           map[string]json.RawMessage `json:"extensions,omitempty"`
}

// RegisterAckPath reports the accepted state of a registered prefix.
type RegisterAckPath struct {
	Path  string `json:"path"`
	State string `json:"state"`
}

// RegisterAckLimits are negotiated maxima. InitialWindowBytes is a target,
// not issued flow-control credit; BufferBytes does not reserve a budget.
type RegisterAckLimits struct {
	MaxControlBytes    int `json:"max_control_bytes"`
	MaxChunkBytes      int `json:"max_chunk_bytes"`
	InitialWindowBytes int `json:"initial_window_bytes"`
	MaxHeaderBytes     int `json:"max_header_bytes"`
	MaxRawURIBytes     int `json:"max_raw_uri_bytes"`
	MaxInflight        int `json:"max_inflight"`
	BufferBytes        int `json:"buffer_bytes"`
}

// RegisterAckTimeouts expresses wire durations in integer milliseconds.
type RegisterAckTimeouts struct {
	RegisterMS       int `json:"register_ms"`
	WriteMS          int `json:"write_ms"`
	CancelAckMS      int `json:"cancel_ack_ms"`
	StatusIntervalMS int `json:"status_interval_ms"`
	StatusStaleMS    int `json:"status_stale_ms"`
	DrainMS          int `json:"drain_ms"`
}

// RegisterAckReadiness expresses wire durations in integer milliseconds.
type RegisterAckReadiness struct {
	Required         bool `json:"required"`
	IntervalMS       int  `json:"interval_ms"`
	TimeoutMS        int  `json:"timeout_ms"`
	StaleAfterMS     int  `json:"stale_after_ms"`
	FailureThreshold int  `json:"failure_threshold"`
	SuccessThreshold int  `json:"success_threshold"`
}

// RegisterNack is a registration refusal. Detail must be safe text supplied by
// the sender; validation cannot detect arbitrary credentials embedded in text.
type RegisterNack struct {
	Type       string                     `json:"type"`
	Code       string                     `json:"code"`
	Detail     string                     `json:"detail"`
	Retryable  bool                       `json:"retryable"`
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}

// controlObject checks exact names, presence and nullability. The caller must
// first run ValidateControlJSON over the entire message, including extensions.
// Unlike encoding/json's struct matching, field matching is case-sensitive.
func controlObject(b []byte, required, optional []string, nullable string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil || fields == nil {
		return nil, ErrProtocol
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return nil, ErrProtocol
		}
	}
	for name, value := range fields {
		if !contains(required, name) && !contains(optional, name) || name != nullable && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, ErrProtocol
		}
	}
	return fields, nil
}

// DecodeRegisterAck validates wire data only. Use ValidateForRegister to check
// the original registration and the production/development null-expiry rule.
func DecodeRegisterAck(b []byte) (RegisterAck, error) {
	if err := ValidateControlJSON(b); err != nil {
		return RegisterAck{}, err
	}
	fields, err := controlObject(b, []string{
		"type", "protocol_version", "protocol_minor", "capabilities", "required_capabilities", "session_id", "route_revision", "paths", "limits", "timeouts", "readiness", "credential_expires_at", "ready_not_before",
	}, []string{"credential_generation", "extensions"}, "credential_expires_at")
	if err != nil {
		return RegisterAck{}, err
	}
	for _, object := range []struct {
		name     string
		required []string
	}{
		{"limits", []string{"max_control_bytes", "max_chunk_bytes", "initial_window_bytes", "max_header_bytes", "max_raw_uri_bytes", "max_inflight", "buffer_bytes"}},
		{"timeouts", []string{"register_ms", "write_ms", "cancel_ack_ms", "status_interval_ms", "status_stale_ms", "drain_ms"}},
		{"readiness", []string{"required", "interval_ms", "timeout_ms", "stale_after_ms", "failure_threshold", "success_threshold"}},
	} {
		if _, err := controlObject(fields[object.name], object.required, nil, ""); err != nil {
			return RegisterAck{}, err
		}
	}
	var paths []json.RawMessage
	if json.Unmarshal(fields["paths"], &paths) != nil || len(paths) < 1 || len(paths) > 32 {
		return RegisterAck{}, ErrProtocol
	}
	for _, path := range paths {
		if _, err := controlObject(path, []string{"path", "state"}, nil, ""); err != nil {
			return RegisterAck{}, err
		}
	}
	var result RegisterAck
	if json.Unmarshal(b, &result) != nil || result.Validate() != nil {
		return RegisterAck{}, ErrProtocol
	}
	return result, nil
}

// DecodeRegisterNack strictly decodes a refusal and checks its retry policy.
func DecodeRegisterNack(b []byte) (RegisterNack, error) {
	if err := ValidateControlJSON(b); err != nil {
		return RegisterNack{}, err
	}
	if _, err := controlObject(b, []string{"type", "code", "detail", "retryable"}, []string{"extensions"}, ""); err != nil {
		return RegisterNack{}, err
	}
	var result RegisterNack
	if json.Unmarshal(b, &result) != nil || result.Validate() != nil {
		return RegisterNack{}, ErrProtocol
	}
	return result, nil
}

// Validate checks message semantics and bounded serialization. Null expiry is
// structurally valid; ValidateForRegister enforces the environment-specific rule.
func (r RegisterAck) Validate() error {
	if r.Type != "register_ack" || r.ProtocolVersion != Major || r.ProtocolMinor < 0 || r.ProtocolMinor > 65535 {
		return ErrProtocol
	}
	if _, err := capabilitySet(r.Capabilities, r.RequiredCapabilities); err != nil {
		return err
	}
	if len(r.SessionID) != 22 {
		return ErrProtocol
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(r.SessionID)
	if err != nil || len(id) != 16 || base64.RawURLEncoding.EncodeToString(id) != r.SessionID {
		return ErrProtocol
	}
	if len(r.Paths) < 1 || len(r.Paths) > 32 {
		return ErrProtocol
	}
	paths := make(map[string]bool)
	for _, path := range r.Paths {
		normalized, err := NormalizePrefix(path.Path)
		if err != nil || paths[normalized] || path.State != "active" && path.State != "pending" && path.State != "retired" {
			return ErrProtocol
		}
		paths[normalized] = true
	}
	l := r.Limits
	for _, bound := range []struct{ value, max int }{
		{l.MaxControlBytes, MaxControlBytes}, {l.MaxChunkBytes, MaxChunkBytes},
		{l.InitialWindowBytes, 65536}, {l.MaxHeaderBytes, 32768},
		{l.MaxRawURIBytes, MaxRawURIBytes}, {l.MaxInflight, 1000}, {l.BufferBytes, 16777216},
		{r.Timeouts.RegisterMS, 300000}, {r.Timeouts.WriteMS, 300000},
		{r.Timeouts.CancelAckMS, 300000}, {r.Timeouts.StatusIntervalMS, 300000},
		{r.Timeouts.StatusStaleMS, 300000}, {r.Timeouts.DrainMS, 300000},
		{r.Readiness.IntervalMS, 300000}, {r.Readiness.TimeoutMS, 300000},
		{r.Readiness.StaleAfterMS, 300000}, {r.Readiness.FailureThreshold, 100}, {r.Readiness.SuccessThreshold, 100},
	} {
		if bound.value < 1 || bound.value > bound.max {
			return ErrProtocol
		}
	}
	if r.ReadyNotBefore < 0 || r.ReadyNotBefore > maxTimestamp || r.CredentialExpiresAt != nil && (*r.CredentialExpiresAt < 0 || *r.CredentialExpiresAt > maxTimestamp) {
		return ErrProtocol
	}
	if r.CredentialGeneration != nil && (*r.CredentialGeneration == 0 || !contains(r.RequiredCapabilities, "credential_generation")) {
		return ErrProtocol
	}
	return validateResponseJSON(r, r.Extensions)
}

// Validate checks message semantics, retry policy and bounded serialization.
func (r RegisterNack) Validate() error {
	if r.Type != "register_nack" || !utf8.ValidString(r.Detail) || len(r.Detail) > 512 {
		return ErrProtocol
	}
	var retryable bool
	switch r.Code {
	case "auth_failed", "invalid_register", "unsupported_protocol_version", "path_forbidden", "path_conflict":
	case "duplicate_instance", "quota_exceeded", "state_unavailable", "server_shutdown":
		retryable = true
	default:
		return ErrProtocol
	}
	if r.Retryable != retryable {
		return ErrProtocol
	}
	return validateResponseJSON(r, r.Extensions)
}

// Check programmatically constructed messages too: RawMessage must not bypass
// bounded JSON, duplicate-key, surrogate or UTF-8 checks during serialization.
func validateResponseJSON(message any, extensions map[string]json.RawMessage) error {
	if len(extensions) > 32 {
		return ErrProtocol
	}
	total := 0
	for key, value := range extensions {
		if len(key) > MaxControlBytes || len(value) > MaxControlBytes || !utf8.ValidString(key) || !utf8.Valid(value) {
			return ErrProtocol
		}
		total += len(key) + len(value)
		if total > MaxControlBytes {
			return ErrProtocol
		}
	}
	b, err := json.Marshal(message)
	if err != nil {
		return ErrProtocol
	}
	return ValidateControlJSON(b)
}

// RegisterAckValidationOptions defaults to production. Development explicitly
// permits a null credential expiry; it does not disable other validation.
type RegisterAckValidationOptions struct {
	Development bool
}

// ValidateForRegister checks agreement with an outgoing register, without I/O,
// clocks, credential verification, budget reservation or session state changes.
// A non-null expiry is range-checked, not checked for freshness or authenticity.
func (r RegisterAck) ValidateForRegister(register Register, options RegisterAckValidationOptions) error {
	if r.Validate() != nil || register.Validate() != nil {
		return ErrProtocol
	}
	if r.ProtocolMinor > register.ProtocolMinor || r.Limits.MaxInflight > register.MaxConcurrentRequests ||
		r.Readiness.Required && !register.ReadinessCheckConfigured || !options.Development && r.CredentialExpiresAt == nil {
		return ErrProtocol
	}
	for _, feature := range r.Capabilities {
		if !contains(register.Capabilities, feature) {
			return ErrProtocol
		}
	}
	for _, feature := range register.RequiredCapabilities {
		if !contains(r.Capabilities, feature) {
			return ErrProtocol
		}
	}
	if (r.CredentialGeneration == nil) != (register.CredentialGeneration == nil) ||
		r.CredentialGeneration != nil && *r.CredentialGeneration != *register.CredentialGeneration {
		return ErrProtocol
	}
	paths := make(map[string]bool)
	for _, path := range register.Paths {
		normalized, _ := NormalizePrefix(path)
		paths[normalized] = true
	}
	if len(r.Paths) != len(paths) {
		return ErrProtocol
	}
	for _, path := range r.Paths {
		normalized, _ := NormalizePrefix(path.Path)
		if !paths[normalized] {
			return ErrProtocol
		}
	}
	return nil
}
