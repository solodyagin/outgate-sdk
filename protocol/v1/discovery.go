package v1

import "encoding/json"

const MaxDiscoveryBytes = 65536

// DiscoveryResponse is authenticated by the HTTPS listener, not this codec.
// It grants no route permission and contains only activated public mounts.
type DiscoveryResponse struct {
	ServiceID     string                    `json:"service_id"`
	RouteRevision U64                       `json:"route_revision"`
	Mounts        map[string]DiscoveryMount `json:"mounts"`
}
type DiscoveryMount struct {
	Path     string `json:"path"`
	PathMode string `json:"path_mode"`
}

// DecodeDiscoveryResponse bounds JSON before allocation and validates exact
// names, duplicate keys, UTF-8, uint64 and normalized public prefixes.
func DecodeDiscoveryResponse(data []byte) (DiscoveryResponse, error) {
	var result DiscoveryResponse
	if len(data) > MaxDiscoveryBytes || ValidateControlJSON(data) != nil {
		return result, ErrProtocol
	}
	fields, err := controlObject(data, []string{"service_id", "route_revision", "mounts"}, nil, "")
	if err != nil {
		return result, ErrProtocol
	}
	var mounts map[string]json.RawMessage
	if json.Unmarshal(fields["mounts"], &mounts) != nil || mounts == nil || len(mounts) > 32 {
		return result, ErrProtocol
	}
	for _, mount := range mounts {
		if _, err := controlObject(mount, []string{"path", "path_mode"}, nil, ""); err != nil {
			return result, ErrProtocol
		}
	}
	if json.Unmarshal(data, &result) != nil || result.Validate() != nil {
		return DiscoveryResponse{}, ErrProtocol
	}
	return result, nil
}

// Validate checks semantic fields; encoded body size is enforced by Decode.
func (r DiscoveryResponse) Validate() error {
	if len(r.ServiceID) > 64 || !idPattern.MatchString(r.ServiceID) || r.RouteRevision == 0 || r.Mounts == nil || len(r.Mounts) > 32 {
		return ErrProtocol
	}
	for id, mount := range r.Mounts {
		if !mountPattern.MatchString(id) {
			return ErrProtocol
		}
		normalized, err := NormalizePrefix(mount.Path)
		if err != nil || normalized != mount.Path || mount.PathMode != "strip" && mount.PathMode != "preserve" {
			return ErrProtocol
		}
	}
	return nil
}
