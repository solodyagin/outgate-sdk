package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/solodyagin/outgate-sdk/httpsig"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/sessionstate"
)

// HMACKey is a service signing key, independent of the TLS key and opaque grant.
type HMACKey struct {
	ID     string
	Secret []byte
}

// ServiceHTTPConfig enables ordinary background HTTPS calls with Config.QUIC.
// ServerRoots is explicit service-listener trust, separate from tunnel trust.
// Discovery uses a separate bounded authenticated GET; user delegation and WebSocket upgrades are not supported yet.
type ServiceHTTPConfig struct {
	ServerRoots                                                              *x509.CertPool
	SigningKey                                                               HMACKey
	MaxConcurrent                                                            int
	DialTimeout, TLSHandshakeTimeout, ResponseHeaderTimeout, BodyIdleTimeout time.Duration
	DiscoveryTimeout                                                         time.Duration
}

type targetServiceKey struct{}

// WithTargetService selects the target without modifying the parent context.
// Invalid/missing IDs are rejected before any network operation.
func WithTargetService(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, targetServiceKey{}, id)
}

type serviceHTTPState struct {
	mu          sync.Mutex
	config      ServiceHTTPConfig
	caller      string
	development bool
	active      map[*serviceHTTPCall]struct{}
	changed     chan struct{}
	discovery   discoveryCache
}

func newServiceHTTP(config *ServiceHTTPConfig, quic *QUICConfig) (*serviceHTTPState, error) {
	if config == nil {
		return nil, nil
	}
	bad := func() (*serviceHTTPState, error) { return nil, &Error{Code: InvalidConfig} }
	if quic == nil || !serviceID(quic.Register.ServiceID) || config.ServerRoots == nil || len(config.ServerRoots.Subjects()) == 0 || len(config.SigningKey.Secret) < 32 || len(config.SigningKey.Secret) > 4096 {
		return bad()
	}
	c := *config
	if c.MaxConcurrent == 0 {
		c.MaxConcurrent = 100
	}
	if c.MaxConcurrent < 1 || c.MaxConcurrent > 1000 {
		return bad()
	}
	durations := []*time.Duration{&c.DialTimeout, &c.TLSHandshakeTimeout, &c.ResponseHeaderTimeout, &c.BodyIdleTimeout, &c.DiscoveryTimeout}
	defaults := []time.Duration{5 * time.Second, 5 * time.Second, 60 * time.Second, 60 * time.Second, 5 * time.Second}
	for i, d := range durations {
		if *d == 0 {
			*d = defaults[i]
		}
		if *d <= 0 || *d > defaults[i] {
			return bad()
		}
	}
	// Key IDs use the printable RFC signature string subset from httpsig.
	if len(c.SigningKey.ID) == 0 || len(c.SigningKey.ID) > 128 {
		return bad()
	}
	for _, ch := range []byte(c.SigningKey.ID) {
		if ch < 32 || ch > 126 || ch == '"' || ch == '\\' {
			return bad()
		}
	}
	c.ServerRoots = c.ServerRoots.Clone()
	c.SigningKey.Secret = bytes.Clone(c.SigningKey.Secret)
	return &serviceHTTPState{config: c, caller: quic.Register.ServiceID, development: quic.Development, active: make(map[*serviceHTTPCall]struct{}), changed: make(chan struct{})}, nil
}

func serviceID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i, b := range []byte(s) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || i > 0 && (b == '.' || b == '_' || b == '-')) {
			return false
		}
	}
	return true
}

func httpOrigin(u *url.URL) (string, error) {
	if u == nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Host == "" || u.Fragment != "" || u.RawFragment != "" || strings.ContainsAny(u.Host, "\\ \r\n\t") {
		return "", &Error{Code: InvalidRequest}
	}
	if len(u.Host) > 512 {
		return "", &Error{Code: InvalidRequest}
	}
	parsed, err := url.Parse("https://" + u.Host)
	if err != nil || parsed.Host != u.Host {
		return "", &Error{Code: InvalidRequest}
	}
	host := strings.ToLower(u.Hostname())
	for _, ch := range []byte(host) {
		if ch <= 32 || ch >= 127 {
			return "", &Error{Code: InvalidRequest}
		}
	}
	port := u.Port()
	if host == "" || strings.ContainsAny(host, "%") {
		return "", &Error{Code: InvalidRequest}
	}
	if port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != port {
			return "", &Error{Code: InvalidRequest}
		}
	}
	if port == "443" {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return "https://" + host, nil
}

// ServiceHTTPClient constructs a bound HTTPS client without sockets. Every call
// is admitted against current Ready/security state and uses the accepted pair.
// Redirects and transparent business retries are disabled. Ordinary HTTP/1.1
// uses a fresh connection per request until a no-replay pooling adapter exists.
func (c *Client) ServiceHTTPClient(gatewayURL string) (*http.Client, error) {
	u, err := url.Parse(gatewayURL)
	origin, originErr := httpOrigin(u)
	if err != nil || originErr != nil || u.Path != "" && u.Path != "/" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(gatewayURL, "#") {
		return nil, &Error{Code: InvalidConfig}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.finished || c.closing {
		return nil, ErrClientClosed
	}
	if c.http == nil {
		return nil, &Error{Code: InvalidConfig}
	}
	return &http.Client{Transport: &serviceHTTPTransport{client: c, origin: origin}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

type serviceHTTPTransport struct {
	client    *Client
	origin    string
	discovery bool
}

func (t *serviceHTTPTransport) RoundTrip(req *http.Request) (response *http.Response, err error) {
	if req == nil {
		return nil, &Error{Code: InvalidRequest}
	}
	bodyTransferred := false
	defer func() {
		if err != nil && !bodyTransferred && req.Body != nil {
			_ = req.Body.Close()
		}
	}()
	headers, err := serviceRequestHeaders(req, t.origin)
	if err != nil {
		return nil, err
	}
	target, _ := req.Context().Value(targetServiceKey{}).(string)
	if !serviceID(target) {
		return nil, &Error{Code: InvalidRequest}
	}
	c := t.client
	c.mu.Lock()
	if c.finished || c.closing {
		c.mu.Unlock()
		return nil, ErrClientClosed
	}
	if c.service == nil || c.statusLocked().State != sessionstate.Ready {
		c.mu.Unlock()
		return nil, ErrClientNotReady
	}
	if binding, ok := req.Context().Value(discoveryBindingKey{}).(discoveryBinding); ok && (binding.generation != c.renewal.httpEpoch || binding.key.target != target) {
		c.mu.Unlock()
		return nil, &Error{Code: DiscoveryUnavailable}
	}
	certificate, grantID := c.renewal.httpCertificate, c.renewal.httpGrantID
	bearer := c.renewal.httpDiscoveryBearer
	deadline := earlierDeadline(c.renewal.expiry, c.service.Snapshot().Deadline)
	call, err := c.http.acquire(req.Context(), deadline)
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			call.finish()
		}
	}()
	config := c.http.config
	var signature httpsig.Headers
	method := req.Method
	if method == "" {
		method = "GET"
	}
	if t.discovery {
		if c.http.development {
			headers = append(headers, v1.Header{"authorization", "Bearer " + bearer})
		} else {
			headers = append(headers, v1.Header{"x-outgate-deployment-grant-id", grantID})
		}
	} else {
		headers = append(headers, v1.Header{"x-outgate-caller-service", c.http.caller}, v1.Header{"x-outgate-target-service", target}, v1.Header{"x-outgate-context-headers", "[]"})
		if !c.http.development {
			headers = append(headers, v1.Header{"x-outgate-hop-limit", "8"}, v1.Header{"x-outgate-deployment-grant-id", grantID})
		}
		profile, _ := httpsig.New(httpsig.Config{Leg: httpsig.Call, Development: c.http.development})
		authority := req.Host
		if authority == "" {
			authority = req.URL.Host
		}
		var signErr error
		signature, signErr = profile.Sign(httpsig.Request{Method: method, Scheme: "https", Authority: authority, RawURI: req.URL.RequestURI(), Headers: headers}, config.SigningKey.ID, config.SigningKey.Secret, time.Now())
		if signErr != nil {
			return nil, &Error{Code: InvalidRequest}
		}
	}
	clone := req.Clone(call.ctx)
	clone.Method = method
	clone.Header = make(http.Header, len(headers)+2)
	clone.GetBody = nil
	clone.Close = true
	for _, h := range headers {
		clone.Header.Add(h[0], h[1])
	}
	if !t.discovery {
		clone.Header.Set("Signature-Input", signature.SignatureInput)
		clone.Header.Set("Signature", signature.Signature)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: config.ServerRoots, ServerName: req.URL.Hostname(), NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true}
	if !c.http.development {
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: config.DialTimeout}).DialContext, TLSClientConfig: tlsConfig, TLSHandshakeTimeout: config.TLSHandshakeTimeout, ResponseHeaderTimeout: config.ResponseHeaderTimeout, MaxResponseHeaderBytes: 32768, DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: false, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	defer transport.CloseIdleConnections()
	if clone.Body != nil && clone.Body != http.NoBody {
		clone.Body = newHTTPProgressBody(call.ctx, clone.Body, config.BodyIdleTimeout, call.cancel, nil)
	}
	bodyTransferred = true
	response, err = transport.RoundTrip(clone)
	if err != nil {
		code := TransportFailure
		var verification *tls.CertificateVerificationError
		if errors.As(err, &verification) {
			code = SecurityFailure
		}
		return nil, &Error{Code: code, cause: err}
	}
	if response.StatusCode == http.StatusSwitchingProtocols {
		_ = response.Body.Close()
		return nil, &Error{Code: ProtocolFailure}
	}
	if response.StatusCode == http.StatusConflict {
		if binding, ok := req.Context().Value(discoveryBindingKey{}).(discoveryBinding); ok {
			c.http.discovery.invalidate(binding.key)
		}
	}
	if response.Body == nil || response.Body == http.NoBody {
		call.finish()
		response.Body = http.NoBody
		return response, nil
	}
	response.Body = newHTTPProgressBody(call.ctx, response.Body, config.BodyIdleTimeout, call.cancel, call.finish)
	return response, nil
}

func serviceRequestHeaders(req *http.Request, origin string) ([]v1.Header, error) {
	bad := func() ([]v1.Header, error) { return nil, &Error{Code: InvalidRequest} }
	if req.URL == nil || len(req.URL.Path) > 8192 || len(req.URL.RawPath) > 8192 || len(req.URL.RawQuery) > 8192 || len(req.Header) > 248 {
		return bad()
	}
	got, err := httpOrigin(req.URL)
	if err != nil || got != origin || req.RequestURI != "" || len(req.TransferEncoding) != 0 || len(req.Trailer) != 0 || req.ContentLength < -1 || req.ContentLength > 0 && req.Body == nil {
		return bad()
	}
	if req.Host != "" {
		u := *req.URL
		u.Host = req.Host
		got, err = httpOrigin(&u)
		if err != nil || got != origin {
			return bad()
		}
	}
	if req.URL.RawPath != "" {
		decoded, err := url.PathUnescape(req.URL.RawPath)
		if err != nil || decoded != req.URL.Path || req.URL.EscapedPath() != req.URL.RawPath {
			return bad()
		}
	}
	count, total := 0, 0
	for name, values := range req.Header {
		if len(values) == 0 {
			return bad()
		}
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-outgate-") && lower != "x-outgate-expected-route-revision" || strings.HasPrefix(lower, "x-user-") || strings.HasPrefix(lower, "x-tunnel-") || lower == "signature" || lower == "signature-input" {
			return bad()
		}
		for _, value := range values {
			count++
			total += len(name) + len(value) + 4
			if count > 248 || total > 30000 {
				return bad()
			}
		}
	}
	headers := make([]v1.Header, 0, count)
	for name, values := range req.Header {
		for _, value := range values {
			if strings.EqualFold(name, "content-length") && value != strconv.FormatInt(req.ContentLength, 10) {
				return bad()
			}
			headers = append(headers, v1.Header{strings.ToLower(name), value})
		}
	}
	method := req.Method
	if method == "" {
		method = "GET"
	}
	authority := req.Host
	if authority == "" {
		authority = req.URL.Host
	}
	metadata := v1.RequestStart{Type: "request_start", StreamID: 1, Method: method, Host: authority, RawRequestURI: req.URL.RequestURI(), Headers: headers}
	if metadata.Validate() != nil {
		return bad()
	}
	return headers, nil
}

type serviceHTTPCall struct {
	owner    *serviceHTTPState
	ctx      context.Context
	cancel   context.CancelFunc
	once     sync.Once
	timer    *time.Timer // protected by owner.mu
	deadline time.Time
}

func (s *serviceHTTPState) acquire(parent context.Context, deadline time.Time) (*serviceHTTPCall, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.active) >= s.config.MaxConcurrent {
		return nil, &Error{Code: CallQuotaExceeded}
	}
	if parent.Err() != nil {
		return nil, &Error{Code: TransportFailure, cause: parent.Err()}
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return nil, &Error{Code: SecurityFailure}
	}
	ctx, cancel := context.WithCancel(parent)
	call := &serviceHTTPCall{owner: s, ctx: ctx, cancel: cancel, deadline: deadline}
	if !deadline.IsZero() {
		call.timer = time.AfterFunc(max(time.Nanosecond, time.Until(deadline)), cancel)
	}
	s.active[call] = struct{}{}
	return call, nil
}
func (call *serviceHTTPCall) finish() {
	call.once.Do(func() {
		call.cancel()
		s := call.owner
		s.mu.Lock()
		defer s.mu.Unlock()
		if call.timer != nil {
			call.timer.Stop()
		}
		delete(s.active, call)
		close(s.changed)
		s.changed = make(chan struct{})
	})
}
func (s *serviceHTTPState) shorten(deadline time.Time) {
	if s == nil || deadline.IsZero() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for call := range s.active {
		if call.deadline.IsZero() || deadline.Before(call.deadline) {
			call.deadline = deadline
			delay := max(time.Nanosecond, time.Until(deadline))
			if call.timer == nil {
				call.timer = time.AfterFunc(delay, call.cancel)
			} else {
				call.timer.Reset(delay)
			}
		}
	}
}
func (s *serviceHTTPState) stop() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for call := range s.active {
		call.cancel()
	}
}
func (s *serviceHTTPState) wait() {
	if s == nil {
		return
	}
	for {
		s.mu.Lock()
		if len(s.active) == 0 {
			s.mu.Unlock()
			return
		}
		changed := s.changed
		s.mu.Unlock()
		<-changed
	}
}

type httpProgressBody struct {
	io.ReadCloser
	mu        sync.Mutex
	idle      time.Duration
	timer     *time.Timer
	cancel    context.CancelFunc
	finish    func()
	closeOnce sync.Once
	closeErr  error
	closed    bool
}

func newHTTPProgressBody(ctx context.Context, body io.ReadCloser, idle time.Duration, cancel context.CancelFunc, finish func()) *httpProgressBody {
	b := &httpProgressBody{ReadCloser: body, idle: idle, cancel: cancel, finish: finish}
	// Response idle time starts at headers; upload idle time starts on first Read.
	if finish != nil {
		b.timer = time.AfterFunc(idle, cancel)
	}
	context.AfterFunc(ctx, func() { _ = b.Close() })
	return b
}
func (b *httpProgressBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	if !b.closed && b.timer == nil {
		b.timer = time.AfterFunc(b.idle, b.cancel)
	}
	b.mu.Unlock()
	n, err := b.ReadCloser.Read(p)
	b.mu.Lock()
	if !b.closed {
		if err != nil {
			b.closed = true
			b.timer.Stop()
		} else if n > 0 {
			b.timer.Reset(b.idle)
		}
	}
	b.mu.Unlock()
	if err != nil && b.finish != nil {
		b.finish()
	}
	return n, err
}
func (b *httpProgressBody) Close() error {
	b.mu.Lock()
	b.closed = true
	if b.timer != nil {
		b.timer.Stop()
	}
	b.mu.Unlock()
	b.closeOnce.Do(func() { b.closeErr = b.ReadCloser.Close() })
	if b.finish != nil {
		b.finish()
	}
	return b.closeErr
}
