package v1

import "encoding/json"

// RequestEnd reports request EOF; byte totals require stream state.
type RequestEnd struct {
	Type       string                     `json:"type"`
	StreamID   U64                        `json:"stream_id"`
	BytesSent  U64                        `json:"bytes_sent"`
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}

// ResponseEnd reports response EOF independently of request EOF.
type ResponseEnd struct {
	Type       string                     `json:"type"`
	StreamID   U64                        `json:"stream_id"`
	BytesSent  U64                        `json:"bytes_sent"`
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}

// WindowUpdate grants wire credit; validation does not reserve memory or add credit.
type WindowUpdate struct {
	Type       string                     `json:"type"`
	StreamID   U64                        `json:"stream_id"`
	Direction  string                     `json:"direction"`
	Credit     U64                        `json:"credit"`
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}

// Cancel requests cancellation; ID ordering and WebSocket scope require stream state.
type Cancel struct {
	Type       string                     `json:"type"`
	StreamID   U64                        `json:"stream_id"`
	CancelID   U64                        `json:"cancel_id"`
	Scope      string                     `json:"scope"`
	Code       string                     `json:"code"`
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}

// CancelAck acknowledges a cancellation; matching it requires the cancel ledger.
type CancelAck struct {
	Type       string                     `json:"type"`
	StreamID   U64                        `json:"stream_id"`
	CancelID   U64                        `json:"cancel_id"`
	Scope      string                     `json:"scope"`
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}

// decodeStreamControl checks the closed wire object before struct unmarshalling.
func decodeStreamControl(b []byte, required []string, result any) error {
	if ValidateControlJSON(b) != nil {
		return ErrProtocol
	}
	if _, err := controlObject(b, required, []string{"extensions"}, ""); err != nil {
		return ErrProtocol
	}
	if json.Unmarshal(b, result) != nil {
		return ErrProtocol
	}
	return nil
}

// DecodeRequestEnd strictly decodes and validates wire data, without stream state.
func DecodeRequestEnd(b []byte) (RequestEnd, error) {
	var r RequestEnd
	if decodeStreamControl(b, []string{"type", "stream_id", "bytes_sent"}, &r) != nil || r.Validate() != nil {
		return RequestEnd{}, ErrProtocol
	}
	return r, nil
}

// Validate checks message fields and bounded serialization, without session state.
func (r RequestEnd) Validate() error {
	if r.Type != "request_end" || r.StreamID == 0 {
		return ErrProtocol
	}
	return validateResponseJSON(r, r.Extensions)
}

// DecodeResponseEnd strictly decodes and validates wire data, without stream state.
func DecodeResponseEnd(b []byte) (ResponseEnd, error) {
	var r ResponseEnd
	if decodeStreamControl(b, []string{"type", "stream_id", "bytes_sent"}, &r) != nil || r.Validate() != nil {
		return ResponseEnd{}, ErrProtocol
	}
	return r, nil
}

// Validate checks message fields and bounded serialization, without session state.
func (r ResponseEnd) Validate() error {
	if r.Type != "response_end" || r.StreamID == 0 {
		return ErrProtocol
	}
	return validateResponseJSON(r, r.Extensions)
}

// DecodeWindowUpdate strictly decodes and validates wire data, without stream state.
func DecodeWindowUpdate(b []byte) (WindowUpdate, error) {
	var r WindowUpdate
	if decodeStreamControl(b, []string{"type", "stream_id", "direction", "credit"}, &r) != nil || r.Validate() != nil {
		return WindowUpdate{}, ErrProtocol
	}
	return r, nil
}

// Validate checks message fields and bounded serialization, without session state.
func (r WindowUpdate) Validate() error {
	if r.Type != "window_update" || r.StreamID == 0 || r.Credit == 0 || !validStreamDirection(r.Direction) {
		return ErrProtocol
	}
	return validateResponseJSON(r, r.Extensions)
}

// DecodeCancel strictly decodes and validates wire data, without stream state.
func DecodeCancel(b []byte) (Cancel, error) {
	var r Cancel
	if decodeStreamControl(b, []string{"type", "stream_id", "cancel_id", "scope", "code"}, &r) != nil || r.Validate() != nil {
		return Cancel{}, ErrProtocol
	}
	return r, nil
}

// Validate checks message fields and bounded serialization, without session state.
func (r Cancel) Validate() error {
	if r.Type != "cancel" || r.StreamID == 0 || r.CancelID == 0 || !validCancelScope(r.Scope) || !featurePattern.MatchString(r.Code) {
		return ErrProtocol
	}
	return validateResponseJSON(r, r.Extensions)
}

// DecodeCancelAck strictly decodes and validates wire data, without stream state.
func DecodeCancelAck(b []byte) (CancelAck, error) {
	var r CancelAck
	if decodeStreamControl(b, []string{"type", "stream_id", "cancel_id", "scope"}, &r) != nil || r.Validate() != nil {
		return CancelAck{}, ErrProtocol
	}
	return r, nil
}

// Validate checks message fields and bounded serialization, without session state.
func (r CancelAck) Validate() error {
	if r.Type != "cancel_ack" || r.StreamID == 0 || r.CancelID == 0 || !validCancelScope(r.Scope) {
		return ErrProtocol
	}
	return validateResponseJSON(r, r.Extensions)
}

func validStreamDirection(direction string) bool {
	switch direction {
	case "request_body", "response_body", "websocket_to_handler", "websocket_from_handler":
		return true
	default:
		return false
	}
}

func validCancelScope(scope string) bool {
	return scope == "request_body" || scope == "response_body" || scope == "all"
}
