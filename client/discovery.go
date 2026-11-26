package client

import (
	"context"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/sessionstate"
)

type discoveryKey struct{ origin, target, mount string }
type discoveryBindingKey struct{}
type discoveryBinding struct {
	key        discoveryKey
	generation uint64
}
type discoveryEntry struct {
	mount            v1.DiscoveryMount
	revision         v1.U64
	generation, used uint64
	expires          time.Time
	missing          bool
}
type discoveryCache struct {
	mu              sync.Mutex
	entries         map[discoveryKey]discoveryEntry
	epoch, sequence uint64
}

func (d *discoveryCache) lookup(key discoveryKey, generation uint64, now time.Time) (discoveryEntry, bool, uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	entry, ok := d.entries[key]
	if ok && (entry.generation != generation || !now.Before(entry.expires)) {
		delete(d.entries, key)
		ok = false
	}
	if ok {
		d.sequence++
		entry.used = d.sequence
		d.entries[key] = entry
	}
	return entry, ok, d.epoch
}
func (d *discoveryCache) store(key discoveryKey, entry discoveryEntry, epoch uint64) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.epoch != epoch {
		return false
	}
	if d.entries == nil {
		d.entries = make(map[discoveryKey]discoveryEntry)
	}
	if _, ok := d.entries[key]; !ok && len(d.entries) >= 256 {
		var oldest discoveryKey
		var used uint64 = ^uint64(0)
		for k, v := range d.entries {
			if v.used < used {
				oldest, used = k, v.used
			}
		}
		delete(d.entries, oldest)
	}
	d.sequence++
	entry.used = d.sequence
	d.entries[key] = entry
	return true
}
func (d *discoveryCache) invalidate(key discoveryKey) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.epoch++
	for k := range d.entries {
		if k.origin == key.origin && k.target == key.target {
			delete(d.entries, k)
		}
	}
}
func (d *discoveryCache) current(epoch uint64) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.epoch == epoch
}
func mountID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i, b := range []byte(s) {
		if !(b >= 'a' && b <= 'z' || i > 0 && (b >= '0' && b <= '9' || b == '_' || b == '-')) {
			return false
		}
	}
	return true
}
func (c *Client) discoveryGeneration() (uint64, time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.finished || c.closing {
		return 0, time.Time{}, ErrClientClosed
	}
	if c.http == nil {
		return 0, time.Time{}, &Error{Code: InvalidConfig}
	}
	if c.service == nil || c.statusLocked().State != sessionstate.Ready {
		return 0, time.Time{}, ErrClientNotReady
	}
	return c.renewal.httpEpoch, earlierDeadline(c.renewal.expiry, c.service.Snapshot().Deadline), nil
}

// NewServiceRequest resolves an activated public mount and constructs a request.
// It performs a bounded authenticated discovery GET only on a cache miss; it
// never reads body or sends/retries the resulting business request. Callers use
// ServiceHTTPClient.Do separately, and rebuild explicitly after a 409 response.
func (c *Client) NewServiceRequest(ctx context.Context, gatewayURL, method, targetService, mount, localRequestURI string, body io.Reader) (*http.Request, error) {
	bad := func() (*http.Request, error) { return nil, &Error{Code: InvalidRequest} }
	if ctx == nil || !serviceID(targetService) || !mountID(mount) {
		return bad()
	}
	if _, err := v1.DecodeRoutePath(localRequestURI); err != nil {
		return bad()
	}
	httpClient, err := c.ServiceHTTPClient(gatewayURL)
	if err != nil {
		return nil, err
	}
	transport := *httpClient.Transport.(*serviceHTTPTransport)
	if method == "" {
		method = "GET"
	}
	metadata := v1.RequestStart{Type: "request_start", StreamID: 1, Method: method, Host: strings.TrimPrefix(transport.origin, "https://"), RawRequestURI: localRequestURI, Headers: []v1.Header{}}
	if metadata.Validate() != nil {
		return bad()
	}
	generation, deadline, err := c.discoveryGeneration()
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, &Error{Code: DiscoveryUnavailable, cause: err}
	}
	key := discoveryKey{transport.origin, targetService, mount}
	entry, found, epoch := c.http.discovery.lookup(key, generation, time.Now())
	if !found {
		timeout := c.http.config.DiscoveryTimeout
		lookupCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		transport.discovery = true
		httpClient.Transport = &transport
		req, err := http.NewRequestWithContext(context.WithValue(WithTargetService(lookupCtx, targetService), discoveryBindingKey{}, false), "GET", transport.origin+"/outgate/discovery/services/"+targetService, nil)
		if err != nil {
			return bad()
		}
		req.Header.Set("Accept", "application/json")
		response, err := httpClient.Do(req)
		if err != nil {
			return nil, &Error{Code: DiscoveryUnavailable, cause: err}
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			return nil, &Error{Code: DiscoveryUnavailable}
		}
		media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil || media != "application/json" || response.Header.Get("Content-Encoding") != "" || response.ContentLength > v1.MaxDiscoveryBytes {
			return nil, &Error{Code: DiscoveryUnavailable}
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, v1.MaxDiscoveryBytes+1))
		if err != nil {
			return nil, &Error{Code: DiscoveryUnavailable, cause: err}
		}
		decoded, err := v1.DecodeDiscoveryResponse(data)
		if err != nil || decoded.ServiceID != targetService {
			return nil, &Error{Code: DiscoveryUnavailable}
		}
		lookupDeadline, _ := lookupCtx.Deadline()
		if lookupCtx.Err() != nil || !time.Now().Before(lookupDeadline) {
			return nil, &Error{Code: DiscoveryUnavailable, cause: context.DeadlineExceeded}
		}
		value, exists := decoded.Mounts[mount]
		entry = discoveryEntry{mount: value, revision: decoded.RouteRevision, generation: generation, missing: !exists, expires: earlierDeadline(time.Now().Add(30*time.Second), deadline)}
		// A completed lookup cannot repopulate state invalidated by an in-flight 409.
		current, _, err := c.discoveryGeneration()
		if err != nil {
			return nil, err
		}
		if current != generation || !c.http.discovery.store(key, entry, epoch) {
			return nil, &Error{Code: DiscoveryUnavailable}
		}
	}
	current, securityDeadline, err := c.discoveryGeneration()
	if err != nil {
		return nil, err
	}
	if current != generation || !time.Now().Before(entry.expires) || !securityDeadline.IsZero() && !time.Now().Before(securityDeadline) {
		return nil, &Error{Code: DiscoveryUnavailable}
	}
	if ctx.Err() != nil || !c.http.discovery.current(epoch) {
		return nil, &Error{Code: DiscoveryUnavailable, cause: ctx.Err()}
	}
	if entry.missing {
		return nil, &Error{Code: MountNotFound}
	}
	prefix := ""
	if entry.mount.Path != "/" {
		prefix = (&url.URL{Path: entry.mount.Path}).EscapedPath()
	}
	if len(prefix)+len(localRequestURI) > v1.MaxRawURIBytes {
		return bad()
	}
	publicURI := prefix + localRequestURI
	requestCtx := context.WithValue(WithTargetService(ctx, targetService), discoveryBindingKey{}, discoveryBinding{key: key, generation: generation})
	request, err := http.NewRequestWithContext(requestCtx, method, transport.origin+publicURI, body)
	if err != nil {
		return bad()
	}
	request.Header.Set("X-Outgate-Expected-Route-Revision", strconv.FormatUint(uint64(entry.revision), 10))
	return request, nil
}
