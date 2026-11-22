package v1

import "encoding/json"

const QUICQuiescentFenceCapability = "quic_quiescent_fence"

// HasQUICQuiescentFence requires minor 1 and an explicitly required capability;
// an optional, unknown extension can never silently enable security semantics.
func HasQUICQuiescentFence(ack RegisterAck) bool {
	return ack.ProtocolMinor >= 1 && contains(ack.Capabilities, QUICQuiescentFenceCapability) && contains(ack.RequiredCapabilities, QUICQuiescentFenceCapability)
}

// QUICQuiescentFenceExtensions returns fresh extensions for a G-origin native
// lifecycle command. The caller must have stopped admission and completed or
// canceled BOTH directions of every admitted exchange before transmitting it.
func QUICQuiescentFenceExtensions(lastID uint64) map[string]json.RawMessage {
	b, _ := json.Marshal(U64(lastID))
	return map[string]json.RawMessage{QUICQuiescentFenceCapability: b}
}

// DecodeQUICQuiescentFence checks exact canonical u64 bytes only. Negotiation,
// sender/direction, no-increase and actual quiescence are lifecycle obligations.
func DecodeQUICQuiescentFence(extensions map[string]json.RawMessage) (uint64, error) {
	b, ok := extensions[QUICQuiescentFenceCapability]
	if !ok {
		return 0, ErrProtocol
	}
	var value U64
	if json.Unmarshal(b, &value) != nil {
		return 0, ErrProtocol
	}
	return uint64(value), nil
}
