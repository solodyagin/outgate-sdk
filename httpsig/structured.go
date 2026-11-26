package httpsig

import (
	"encoding/base64"
	"strconv"
	"strings"
	"time"
)

// Parsed is untrusted parsed metadata, suitable only for selecting a pinned key.
// It is not evidence of HMAC, transport identity, authorization or replay checks.
type Parsed struct {
	Label      string
	Components []string
	Params     Params
}

// ParseSignatureInput supports precisely the Outgate Structured Fields subset:
// one named inner list of strings, then created/expires/nonce/keyid/alg in order.
// RFC whitespace in the inner list/parameters is accepted and reserialized for
// the signature base. Extra members, duplicates and item parameters are rejected.
func ParseSignatureInput(value string) (Parsed, error) {
	bad := func() (Parsed, error) { return Parsed{}, ErrAuth }
	if len(value) > maxHeaders {
		return bad()
	}
	s := strings.Trim(value, " \t")
	label, s, ok := strings.Cut(s, "=")
	if !ok || label != Call && label != Gateway || !strings.HasPrefix(s, "(") {
		return bad()
	}
	s = s[1:]
	names := make([]string, 0, 16)
	for {
		s = strings.TrimLeft(s, " ")
		if s == "" {
			return bad()
		}
		if s[0] == ')' {
			s = s[1:]
			break
		}
		if len(names) >= 32 {
			return bad()
		}
		name, rest, ok := quoted(s)
		if !ok || name == "" || len(name) > 128 || len(rest) == 0 || rest[0] != ' ' && rest[0] != ')' {
			return bad()
		}
		for _, prior := range names {
			if prior == name {
				return bad()
			}
		}
		names = append(names, name)
		s = rest
	}
	var p Params
	for _, name := range []string{"created", "expires", "nonce", "keyid", "alg"} {
		if !strings.HasPrefix(s, ";") {
			return bad()
		}
		s = strings.TrimLeft(s[1:], " ")
		if !strings.HasPrefix(s, name+"=") {
			return bad()
		}
		s = s[len(name)+1:]
		if name == "created" || name == "expires" {
			i := 0
			if len(s) > 0 && s[0] == '-' {
				i = 1
			}
			digits := i
			// Parse an SF integer, then enforce non-negative Outgate timestamps.
			for i < len(s) && s[i] >= '0' && s[i] <= '9' {
				i++
			}
			if i-digits < 1 || i-digits > 15 {
				return bad()
			}
			n, err := strconv.ParseInt(s[:i], 10, 64)
			if err != nil {
				return bad()
			}
			s = s[i:]
			if name == "created" {
				p.Created = n
			} else {
				p.Expires = n
			}
		} else {
			value, rest, ok := quoted(s)
			if !ok {
				return bad()
			}
			s = rest
			switch name {
			case "nonce":
				p.Nonce = value
			case "keyid":
				p.KeyID = value
			case "alg":
				if value != "hmac-sha256" {
					return bad()
				}
			}
		}
	}
	if s != "" || !validParams(p) {
		return bad()
	}
	return Parsed{Label: label, Components: names, Params: p}, nil
}

// quoted accepts RFC SF strings. Outgate's allowed string values do not contain
// quote/backslash, so escaped values fail subsequent profile checks as needed.
func quoted(s string) (string, string, bool) {
	if len(s) == 0 || s[0] != '"' {
		return "", "", false
	}
	var out strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			return out.String(), s[i+1:], true
		}
		if c == '\\' {
			i++
			if i >= len(s) || s[i] != '"' && s[i] != '\\' {
				return "", "", false
			}
			c = s[i]
		}
		if c < 32 || c > 126 {
			return "", "", false
		}
		out.WriteByte(c)
	}
	return "", "", false
}
func validParams(p Params) bool {
	if p.Created < 0 || p.Created > maxTimestamp-signatureTTLSeconds || p.Expires != p.Created+signatureTTLSeconds || len(p.KeyID) < 1 || len(p.KeyID) > 128 {
		return false
	}
	for i := 0; i < len(p.KeyID); i++ {
		c := p.KeyID[i]
		if c < 32 || c > 126 || c == '"' || c == '\\' {
			return false
		}
	}
	if len(p.Nonce) != 22 {
		return false
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(p.Nonce)
	return err == nil && len(nonce) == 16 && base64.RawURLEncoding.EncodeToString(nonce) == p.Nonce
}
func validTime(p Params, now time.Time) bool {
	return !now.IsZero() && validParams(p) && !now.Before(time.Unix(p.Created-signatureSkewSeconds, 0)) && !now.After(time.Unix(p.Expires+signatureSkewSeconds, 0))
}
func serialize(names []string, p Params) string {
	quoted := make([]string, len(names))
	for i, name := range names {
		quoted[i] = `"` + name + `"`
	}
	return "(" + strings.Join(quoted, " ") + ");created=" + strconv.FormatInt(p.Created, 10) + ";expires=" + strconv.FormatInt(p.Expires, 10) + `;nonce="` + p.Nonce + `";keyid="` + p.KeyID + `";alg="hmac-sha256"`
}
func parseSignature(value, leg string) ([]byte, error) {
	if len(value) > maxHeaders {
		return nil, ErrAuth
	}
	s := strings.Trim(value, " \t")
	if !strings.HasPrefix(s, leg+"=:") || !strings.HasSuffix(s, ":") {
		return nil, ErrAuth
	}
	s = s[len(leg)+2 : len(s)-1]
	if len(s) < 43 || len(s) > 44 {
		return nil, ErrAuth
	}
	// SF byte sequences permit omitted padding; reject all non-base64 bytes.
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=') {
			return nil, ErrAuth
		}
	}
	if len(s) == 43 {
		s += "="
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, ErrAuth
	}
	return b, nil
}

// CanonicalField combines ordinary list-based field lines per RFC 9421 §2.1.
// Outgate identity fields instead require exactly one untouched ASCII value.
// Obs-fold and CTLs fail closed under Outgate's HTTP metadata contract.
func CanonicalField(lines []string) (string, error) {
	if len(lines) == 0 || len(lines) > 256 {
		return "", ErrAuth
	}
	n := 0
	for _, line := range lines {
		n += len(line) + 2
		if n > maxHeaders {
			return "", ErrAuth
		}
		for i := 0; i < len(line); i++ {
			c := line[i]
			if c < 32 && c != '\t' || c > 126 {
				return "", ErrAuth
			}
		}
	}
	trimmed := make([]string, len(lines))
	for i, line := range lines {
		trimmed[i] = strings.Trim(line, " \t")
	}
	return strings.Join(trimmed, ", "), nil
}
