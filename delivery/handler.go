package delivery

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/solodyagin/outgate-sdk/httpsig"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

var (
	ErrForbidden   = errors.New("outgate: delivery forbidden")
	ErrUnavailable = errors.New("outgate: delivery security state unavailable")
	ErrRateLimited = errors.New("outgate: delivery rate limited")
)

// MountInfo describes the authenticated mount and original public request URI.
type MountInfo struct {
	Prefix, OriginalRequestURI string
}

type deliveryContextKey struct{}
type deliveryContext struct {
	verified Verified
	mount    MountInfo
}

// FromContext returns the verified delivery and mount installed after replay commit.
func FromContext(ctx context.Context) (Verified, MountInfo, bool) {
	value, ok := ctx.Value(deliveryContextKey{}).(deliveryContext)
	return value.verified, value.mount, ok
}

// HandlerConfig supplies runtime admission for signed recipient requests. The
// callbacks must honor cancellation and treat metadata and TLS state as read-only.
// They may return ErrDelivery, ErrForbidden, ErrRateLimited or ErrUnavailable.
// Other callback failures are reported as unavailable, without exposing details.
type HandlerConfig struct {
	Verifier        *Verifier
	ReplayStore     httpsig.ReplayStore
	ReplayNamespace string
	StripPrefix     bool

	// Prepare rate-limits the request and authenticates the TLS peer, grant and
	// recipient session. Select the accepted key and expected binding using that
	// trusted state. The HTTP fields supplied here are still unverified hints.
	Prepare func(context.Context, *tls.ConnectionState, httpsig.Request) (Key, Binding, error)
	// Authorize checks current route, revision, active session, delegation and
	// credential/user revocation state. It grants a lease through the returned
	// deadline. An expired lease prevents dispatch and cancels active handling.
	// Until lease renewal exists, this boundary caps the lease at five seconds
	// from the start of transport admission and at assertion expiry.
	Authorize func(context.Context, httpsig.Request, Verified) (time.Time, error)
}

// NewHandler wraps a recipient handler for signed HTTPS delivery. Supply the
// same durable replay store/namespace across the recipient's transports. Store
// readiness, recovery and admission policy remain the runtime's responsibility.
func NewHandler(config HandlerConfig, next http.Handler) (http.Handler, error) {
	if next == nil || config.Verifier == nil || config.Verifier.leg != httpsig.Gateway ||
		config.Prepare == nil || config.Authorize == nil || config.ReplayStore == nil ||
		!httpsig.ValidReplayNamespace(config.ReplayNamespace) {
		return nil, ErrDelivery
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		config.serve(w, r, next, time.Now)
	}), nil
}

func (c HandlerConfig) serve(w http.ResponseWriter, r *http.Request, next http.Handler, now func() time.Time) {
	if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || !r.TLS.HandshakeComplete || len(r.TLS.VerifiedChains) == 0 {
		reject(w, ErrDelivery)
		return
	}
	metadata, err := requestMetadata(r)
	if err != nil {
		reject(w, err)
		return
	}
	admissionDeadline := now().Add(5 * time.Second)
	admission, stopAdmission := context.WithDeadline(r.Context(), admissionDeadline)
	defer stopAdmission()
	key, binding, err := c.Prepare(admission, r.TLS, metadata)
	if err != nil {
		reject(w, err)
		return
	}
	verified, err := c.Verifier.Verify(metadata, key, binding, now())
	if err != nil {
		reject(w, err)
		return
	}
	until, err := c.Authorize(admission, metadata, verified)
	if err != nil {
		reject(w, err)
		return
	}
	until = minTime(until, admissionDeadline)
	if identity, ok := verified.Identity(); ok {
		if !now().Before(identity.ExpiresAt) {
			reject(w, ErrDelivery)
			return
		}
		until = minTime(until, identity.ExpiresAt)
	}
	if !now().Before(until) {
		reject(w, ErrUnavailable)
		return
	}
	ctx, cancel := context.WithDeadline(admission, until)
	defer cancel()
	if err := verified.Signature().Reserve(ctx, c.ReplayStore, c.ReplayNamespace, now()); err != nil {
		reject(w, err)
		return
	}
	// Commit can finish after a deadline. Keep the nonce and stop dispatch.
	current := now()
	if ctx.Err() != nil || !current.Before(until) {
		reject(w, ErrUnavailable)
		return
	}
	if !verified.Signature().ValidAt(current) {
		reject(w, ErrDelivery)
		return
	}
	mount := MountInfo{Prefix: binding.Prefix, OriginalRequestURI: metadata.RawURI}
	ctx = context.WithValue(ctx, deliveryContextKey{}, deliveryContext{verified: verified, mount: mount})
	handlerRequest := r.Clone(ctx)
	for name := range handlerRequest.Header {
		lower := strings.ToLower(name)
		if lower == "signature" || lower == "signature-input" || strings.HasPrefix(lower, "x-outgate-") || strings.HasPrefix(lower, "x-tunnel-") {
			delete(handlerRequest.Header, name)
		}
	}
	if c.StripPrefix && mount.Prefix != "/" {
		stripMount(handlerRequest, mount.Prefix)
	}
	if ctx.Err() != nil {
		reject(w, ErrUnavailable)
		return
	}
	next.ServeHTTP(w, handlerRequest)
}

func requestMetadata(r *http.Request) (httpsig.Request, error) {
	u := r.URL
	if u == nil || u.IsAbs() || u.Host != "" || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.RawFragment != "" || r.Method == "GET_0RTT" || r.Method == "HEAD_0RTT" ||
		len(u.Path) > v1.MaxRawURIBytes || len(u.RawPath) > v1.MaxRawURIBytes || len(u.RawQuery) > v1.MaxRawURIBytes || len(r.RequestURI) > v1.MaxRawURIBytes ||
		u.RawPath != "" && u.RawPath != u.EscapedPath() || u.RequestURI() != r.RequestURI || len(r.Header) > 256 {
		return httpsig.Request{}, ErrDelivery
	}
	count, size := 0, 2
	for name, values := range r.Header {
		if len(name) > 128 || len(values) == 0 || len(values) > 256-count {
			return httpsig.Request{}, ErrDelivery
		}
		count += len(values)
		for _, value := range values {
			if len(value) > 32768 {
				return httpsig.Request{}, ErrDelivery
			}
			size += len(name) + len(value) + 4
			if size > 32768 {
				return httpsig.Request{}, ErrDelivery
			}
		}
	}
	headers := make([]v1.Header, 0, count)
	for name, values := range r.Header {
		for _, value := range values {
			headers = append(headers, v1.Header{strings.ToLower(name), value})
		}
	}
	if v1.ValidateHTTPRequestMetadata(r.Method, r.Host, r.RequestURI, headers) != nil {
		return httpsig.Request{}, ErrDelivery
	}
	return httpsig.Request{Method: r.Method, Scheme: "https", Authority: r.Host, RawURI: r.RequestURI, Headers: headers}, nil
}

func stripMount(r *http.Request, prefix string) {
	// Verification proved decoded segment matching. Encoded separators are
	// forbidden, so count the same literal slashes in the original escaped path.
	escaped := r.URL.EscapedPath()
	cut := 0
	for range strings.Count(prefix, "/") {
		next := strings.IndexByte(escaped[cut+1:], '/')
		if next < 0 {
			cut = len(escaped)
			break
		}
		cut += next + 1
	}
	r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
	if r.URL.Path == "" {
		r.URL.Path = "/"
	}
	r.URL.RawPath = escaped[cut:]
	if r.URL.RawPath == (&url.URL{Path: r.URL.Path}).EscapedPath() {
		r.URL.RawPath = ""
	}
	r.RequestURI = r.URL.RequestURI()
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func reject(w http.ResponseWriter, err error) {
	status := http.StatusServiceUnavailable
	switch {
	case errors.Is(err, ErrDelivery), errors.Is(err, httpsig.ErrAuth), errors.Is(err, httpsig.ErrReplay):
		status = http.StatusUnauthorized
	case errors.Is(err, ErrForbidden):
		status = http.StatusForbidden
	case errors.Is(err, ErrRateLimited), errors.Is(err, httpsig.ErrReplayCallerQuota):
		status = http.StatusTooManyRequests
	}
	if status == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", "1")
	}
	http.Error(w, http.StatusText(status), status)
}
