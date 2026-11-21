package v1

import (
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// NormalizePrefix removes one trailing slash and rejects ambiguous registrations.
// It does not authorize root or any other path.
func NormalizePrefix(path string) (string, error) {
	if len(path) == 0 || len(path) > MaxRawURIBytes || strings.ContainsAny(path, "%?#") {
		return "", ErrProtocol
	}
	if err := validatePath(path, true); err != nil {
		return "", err
	}
	if path != "/" {
		path = strings.TrimSuffix(path, "/")
	}
	return path, nil
}

// DecodeRoutePath performs exactly one decode for route selection. Retain the
// original raw URI for signatures and forwarding. The query is opaque.
func DecodeRoutePath(rawURI string) (string, error) {
	if len(rawURI) == 0 || len(rawURI) > MaxRawURIBytes || strings.Contains(rawURI, "#") || strings.ContainsFunc(rawURI, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) {
		return "", ErrProtocol
	}
	raw, _, _ := strings.Cut(rawURI, "?")
	// Encoded separators must not change routing boundaries.
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return "", ErrProtocol
	}
	path, err := url.PathUnescape(raw)
	if err != nil {
		return "", ErrProtocol
	}
	if err := validatePath(path, false); err != nil {
		return "", err
	}
	return path, nil
}

func validatePath(path string, registration bool) error {
	if !utf8.ValidString(path) || !strings.HasPrefix(path, "/") || strings.Contains(path, "\\") || strings.Contains(path, "//") {
		return ErrProtocol
	}
	for _, c := range path {
		if unicode.IsControl(c) || (registration && unicode.IsSpace(c)) {
			return ErrProtocol
		}
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return ErrProtocol
		}
	}
	return nil
}

// MatchesPrefix requires an already validated decoded path and normalized prefix.
func MatchesPrefix(prefix, path string) bool {
	return prefix == "/" || path == prefix || strings.HasPrefix(path, prefix+"/")
}

// PrefixAllowed implements registration permission, including the special rule
// that allowed root grants only exact root, never an arbitrary subtree.
func PrefixAllowed(allowed, requested string) bool {
	a, err := NormalizePrefix(allowed)
	if err != nil {
		return false
	}
	r, err := NormalizePrefix(requested)
	if err != nil {
		return false
	}
	if a == "/" {
		return r == "/"
	}
	return MatchesPrefix(a, r)
}
