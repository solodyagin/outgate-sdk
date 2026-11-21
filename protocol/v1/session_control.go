package v1

import "encoding/json"

// InstanceStatus reports readiness. Sequence ordering, receiver freshness and
// security readiness require session state; ObservedAt is an untrusted timestamp.
type InstanceStatus struct {
	Type       string                     `json:"type"`
	Sequence   U64                        `json:"sequence"`
	Ready      bool                       `json:"ready"`
	Code       string                     `json:"code"`
	ObservedAt int64                      `json:"observed_at"`
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}

// DecodeInstanceStatus strictly decodes readiness fields, without session state.
func DecodeInstanceStatus(b []byte) (InstanceStatus, error) {
	var r InstanceStatus
	if decodeStreamControl(b, []string{"type", "sequence", "ready", "code", "observed_at"}, &r) != nil || r.Validate() != nil {
		return InstanceStatus{}, ErrProtocol
	}
	return r, nil
}

// Validate checks bounded fields, not sequence ordering, freshness or readiness.
func (r InstanceStatus) Validate() error {
	if r.Type != "instance_status" || r.Sequence == 0 || r.ObservedAt < 0 || r.ObservedAt > maxTimestamp {
		return ErrProtocol
	}
	switch r.Code {
	case "ready", "initializing", "dependency_unavailable", "security_recovery", "draining":
	default:
		return ErrProtocol
	}
	return validateResponseJSON(r, r.Extensions)
}

// Drain requests bounded drain in either direction.
// ID uniqueness, deadlines, direction and lifecycle require session state.
type Drain struct {
	Type       string                     `json:"type"`
	CommandID  U64                        `json:"command_id"`
	DeadlineMS int                        `json:"deadline_ms"`
	Code       string                     `json:"code"`
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}

// DecodeDrain strictly decodes command fields, without executing the command.
func DecodeDrain(b []byte) (Drain, error) {
	var r Drain
	if decodeStreamControl(b, []string{"type", "command_id", "deadline_ms", "code"}, &r) != nil || r.Validate() != nil {
		return Drain{}, ErrProtocol
	}
	return r, nil
}

// Validate checks fields and bounded serialization, without session state.
func (r Drain) Validate() error {
	if r.Type != "drain" || r.CommandID == 0 || r.DeadlineMS < 1 || r.DeadlineMS > 30000 || !featurePattern.MatchString(r.Code) {
		return ErrProtocol
	}
	return validateResponseJSON(r, r.Extensions)
}

// Unregister requests session closure from Service to Gateway.
// ID uniqueness, deadlines, direction and lifecycle require session state.
type Unregister struct {
	Type       string                     `json:"type"`
	CommandID  U64                        `json:"command_id"`
	DeadlineMS int                        `json:"deadline_ms"`
	Code       string                     `json:"code"`
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}

// DecodeUnregister strictly decodes command fields, without executing the command.
func DecodeUnregister(b []byte) (Unregister, error) {
	var r Unregister
	if decodeStreamControl(b, []string{"type", "command_id", "deadline_ms", "code"}, &r) != nil || r.Validate() != nil {
		return Unregister{}, ErrProtocol
	}
	return r, nil
}

// Validate checks fields and bounded serialization, without session state.
func (r Unregister) Validate() error {
	if r.Type != "unregister" || r.CommandID == 0 || r.DeadlineMS < 1 || r.DeadlineMS > 30000 || !featurePattern.MatchString(r.Code) {
		return ErrProtocol
	}
	return validateResponseJSON(r, r.Extensions)
}

// Reconnect requests bounded drain and reconnection from Gateway to Service.
// ID uniqueness, deadlines, direction and lifecycle require session state.
type Reconnect struct {
	Type       string                     `json:"type"`
	CommandID  U64                        `json:"command_id"`
	DeadlineMS int                        `json:"deadline_ms"`
	Code       string                     `json:"code"`
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}

// DecodeReconnect strictly decodes command fields, without executing the command.
func DecodeReconnect(b []byte) (Reconnect, error) {
	var r Reconnect
	if decodeStreamControl(b, []string{"type", "command_id", "deadline_ms", "code"}, &r) != nil || r.Validate() != nil {
		return Reconnect{}, ErrProtocol
	}
	return r, nil
}

// Validate checks fields and bounded serialization, without session state.
func (r Reconnect) Validate() error {
	if r.Type != "reconnect" || r.CommandID == 0 || r.DeadlineMS < 1 || r.DeadlineMS > 30000 || !featurePattern.MatchString(r.Code) {
		return ErrProtocol
	}
	return validateResponseJSON(r, r.Extensions)
}

// DrainAck acknowledges drain; the Gateway acknowledgement fences prior starts.
// Matching the command and enforcing its fence require session state.
type DrainAck struct {
	Type       string                     `json:"type"`
	CommandID  U64                        `json:"command_id"`
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}

// DecodeDrainAck strictly decodes acknowledgement fields, without a command ledger.
func DecodeDrainAck(b []byte) (DrainAck, error) {
	var r DrainAck
	if decodeStreamControl(b, []string{"type", "command_id"}, &r) != nil || r.Validate() != nil {
		return DrainAck{}, ErrProtocol
	}
	return r, nil
}

// Validate checks fields and bounded serialization, without session state.
func (r DrainAck) Validate() error {
	if r.Type != "drain_ack" || r.CommandID == 0 {
		return ErrProtocol
	}
	return validateResponseJSON(r, r.Extensions)
}

// UnregisterAck acknowledges session exclusion and cleanup from Gateway to Service.
// Matching the command and enforcing its fence require session state.
type UnregisterAck struct {
	Type       string                     `json:"type"`
	CommandID  U64                        `json:"command_id"`
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}

// DecodeUnregisterAck strictly decodes acknowledgement fields, without a command ledger.
func DecodeUnregisterAck(b []byte) (UnregisterAck, error) {
	var r UnregisterAck
	if decodeStreamControl(b, []string{"type", "command_id"}, &r) != nil || r.Validate() != nil {
		return UnregisterAck{}, ErrProtocol
	}
	return r, nil
}

// Validate checks fields and bounded serialization, without session state.
func (r UnregisterAck) Validate() error {
	if r.Type != "unregister_ack" || r.CommandID == 0 {
		return ErrProtocol
	}
	return validateResponseJSON(r, r.Extensions)
}
