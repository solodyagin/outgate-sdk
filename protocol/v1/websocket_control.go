package v1

import "encoding/json"

// WebSocketOpen describes an application WebSocket byte channel. It does not
// authenticate the handshake, reserve credit or verify inner HTTP metadata.
type WebSocketOpen struct {
	Type              string                     `json:"type"`
	StreamID          U64                        `json:"stream_id"`
	Method            string                     `json:"method"`
	RawRequestURI     string                     `json:"raw_request_uri"`
	Host              string                     `json:"host"`
	Headers           []Header                   `json:"headers"`
	FromHandlerCredit U64                        `json:"from_handler_credit"`
	Extensions        map[string]json.RawMessage `json:"extensions,omitempty"`
}

// WebSocketOpenAck opens the byte channel, without confirming authentication
// or a successful application handshake. Initial credit may be zero.
type WebSocketOpenAck struct {
	Type            string                     `json:"type"`
	StreamID        U64                        `json:"stream_id"`
	ToHandlerCredit U64                        `json:"to_handler_credit"`
	Extensions      map[string]json.RawMessage `json:"extensions,omitempty"`
}

// WebSocketEnd reports directional EOF including inner handshake bytes.
// It neither closes the opposite direction nor replaces an application Close.
type WebSocketEnd struct {
	Type       string                     `json:"type"`
	StreamID   U64                        `json:"stream_id"`
	Direction  string                     `json:"direction"`
	BytesSent  U64                        `json:"bytes_sent"`
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}

// DecodeWebSocketOpen strictly decodes wire fields and HTTP metadata.
func DecodeWebSocketOpen(b []byte) (WebSocketOpen, error) {
	var r WebSocketOpen
	if decodeHTTPStart(b, []string{"type", "stream_id", "method", "raw_request_uri", "host", "headers", "from_handler_credit"}, &r) != nil || r.Validate() != nil {
		return WebSocketOpen{}, ErrProtocol
	}
	return r, nil
}

// Validate checks bounded metadata, preserving handshake headers and their order.
func (r WebSocketOpen) Validate() error {
	if r.Type != "websocket_open" || r.StreamID == 0 || r.Method != "GET" || !validHTTPHost(r.Host) || validateRequestURI(r.RawRequestURI) != nil || validateHTTPHeaders(r.Headers, true) != nil {
		return ErrProtocol
	}
	return validateResponseJSON(r, r.Extensions)
}

// DecodeWebSocketOpenAck strictly decodes channel acknowledgement fields.
func DecodeWebSocketOpenAck(b []byte) (WebSocketOpenAck, error) {
	var r WebSocketOpenAck
	if decodeStreamControl(b, []string{"type", "stream_id", "to_handler_credit"}, &r) != nil || r.Validate() != nil {
		return WebSocketOpenAck{}, ErrProtocol
	}
	return r, nil
}

// Validate checks fields, without enforcing channel order or credit budgets.
func (r WebSocketOpenAck) Validate() error {
	if r.Type != "websocket_open_ack" || r.StreamID == 0 {
		return ErrProtocol
	}
	return validateResponseJSON(r, r.Extensions)
}

// DecodeWebSocketEnd strictly decodes directional EOF fields.
func DecodeWebSocketEnd(b []byte) (WebSocketEnd, error) {
	var r WebSocketEnd
	if decodeStreamControl(b, []string{"type", "stream_id", "direction", "bytes_sent"}, &r) != nil || r.Validate() != nil {
		return WebSocketEnd{}, ErrProtocol
	}
	return r, nil
}

// Validate checks fields; actual byte totals and EOF order require channel state.
func (r WebSocketEnd) Validate() error {
	if r.Type != "websocket_end" || r.StreamID == 0 || (r.Direction != "websocket_to_handler" && r.Direction != "websocket_from_handler") {
		return ErrProtocol
	}
	return validateResponseJSON(r, r.Extensions)
}
