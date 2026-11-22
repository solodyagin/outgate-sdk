package quichttp

import (
	"context"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/quic-go/quic-go/http3"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
)

// Gateway is a single-session RoundTripper. The caller must gate each request
// on routing, readiness and authorization before calling RoundTrip. It neither
// dials nor redirects nor retries, including on reset/GOAWAY and reused streams.
type Gateway struct {
	carrier   *quiccontrol.Carrier
	transport *http3.Transport
	client    *http3.ClientConn
	limits    v1.RegisterAckLimits
	slots     chan struct{}
	idMu      sync.Mutex
	next      uint64
}

var _ http.RoundTripper = (*Gateway)(nil)

func NewGateway(carrier *quiccontrol.Carrier) (*Gateway, error) {
	if carrier == nil {
		return nil, v1.ErrProtocol
	}
	conn, limits, err := carrier.ClaimHTTP3(false)
	if err != nil {
		return nil, err
	}
	transport := &http3.Transport{DisableCompression: true, MaxResponseHeaderBytes: limits.MaxHeaderBytes}
	return &Gateway{carrier: carrier, transport: transport, client: transport.NewClientConn(conn), limits: limits, slots: make(chan struct{}, limits.MaxInflight)}, nil
}

func (g *Gateway) RoundTrip(req *http.Request) (*http.Response, error) {
	return g.RoundTripWithCompletion(req, nil)
}

// RoundTripWithCompletion calls completed exactly once when both directions
// finish or are canceled, including pre-I/O rejection. It may run before this
// method returns or asynchronously afterwards, outside transport mutexes. The
// callback must not block. It lets an outer lifecycle retain admission through
// an early response EOF without buffering bodies or synthesizing WSS frames.
func (g *Gateway) RoundTripWithCompletion(req *http.Request, completed func()) (*http.Response, error) {
	fail := func(err error) (*http.Response, error) {
		if req != nil && req.Body != nil {
			_ = req.Body.Close()
		}
		if completed != nil {
			completed()
		}
		return nil, err
	}
	if req == nil {
		return fail(ErrRequest)
	}
	if err := req.Context().Err(); err != nil {
		return fail(err)
	}
	if err := g.carrier.Err(); err != nil {
		return fail(err)
	}
	// Bound metadata before Clone allocates a second copy. External transport IDs
	// are removed case-insensitively, including manually constructed Header maps.
	if _, err := headerPairs(req.Header, g.limits.MaxHeaderBytes, 0); err != nil {
		return fail(err)
	}
	forward := req.Clone(req.Context())
	for name := range forward.Header {
		if strings.EqualFold(name, requestIDHeader) {
			delete(forward.Header, name)
		}
	}
	if forward.Header == nil {
		forward.Header = make(http.Header)
	}
	forward.Header.Set(requestIDHeader, "18446744073709551615") // reserve worst-case ID space in the limit
	if err := checkRequest(forward, g.limits, false); err != nil {
		return fail(err)
	}
	select {
	case g.slots <- struct{}{}:
	default:
		return fail(ErrBusy)
	}
	g.idMu.Lock()
	if g.next == math.MaxUint64 {
		g.idMu.Unlock()
		<-g.slots
		return fail(ErrBusy)
	}
	g.next++
	id := g.next
	g.idMu.Unlock()
	forward.Header.Set(requestIDHeader, strconv.FormatUint(id, 10))
	ctx, cancel := context.WithCancel(req.Context())
	stopConn := context.AfterFunc(g.client.Context(), cancel)
	x := &exchange{cancel: cancel, stopConn: stopConn, release: func() {
		<-g.slots
		if completed != nil {
			completed()
		}
	}}
	if req.Body == nil || req.Body == http.NoBody {
		x.uploaded = true
		forward.Body = nil
	} else {
		x.upload = &uploadBody{ReadCloser: req.Body, done: func() { x.finish(true, false) }}
		forward.Body = x.upload
	}
	forward = forward.WithContext(ctx)
	context.AfterFunc(ctx, func() {
		if x.upload != nil {
			_ = x.upload.Close()
		}
		x.finish(true, true)
	})
	response, err := g.client.RoundTrip(forward)
	if err != nil {
		cancel()
		return nil, err
	}
	pairs, err := headerPairs(response.Header, g.limits.MaxHeaderBytes, len(":status")+3+32)
	if err == nil && v1.ValidateHTTPResponseMetadata(response.StatusCode, pairs) != nil {
		err = ErrRequest
	}
	if err != nil {
		_ = response.Body.Close()
		cancel()
		return nil, err
	}
	response.Body = &responseBody{ReadCloser: response.Body, exchange: x}
	response.Request = req
	return response, nil
}

func (g *Gateway) Close() error {
	_ = g.carrier.Close()
	return g.transport.Close()
}

// A request occupies its slot until both directions end. An early response EOF
// must not admit another request while the original upload is still in flight.
type exchange struct {
	mu                            sync.Mutex
	uploaded, responded, released bool
	upload                        *uploadBody
	cancel                        context.CancelFunc
	stopConn                      func() bool
	release                       func()
}

func (x *exchange) finish(upload, response bool) {
	x.mu.Lock()
	x.uploaded = x.uploaded || upload
	x.responded = x.responded || response
	finish := x.uploaded && x.responded && !x.released
	if finish {
		x.released = true
	}
	x.mu.Unlock()
	if finish {
		x.release()
		x.stopConn()
		x.cancel()
	}
}

type uploadBody struct {
	io.ReadCloser
	once sync.Once
	err  error
	done func()
}

func (b *uploadBody) Close() error {
	b.once.Do(func() { b.err = b.ReadCloser.Close(); b.done() })
	return b.err
}

type responseBody struct {
	io.ReadCloser
	exchange *exchange
}

func (b *responseBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.exchange.finish(false, true)
		if err != io.EOF {
			b.exchange.cancel()
		}
	}
	return n, err
}
func (b *responseBody) Close() error {
	err := b.ReadCloser.Close()
	b.exchange.cancel()
	b.exchange.finish(false, true)
	return err
}
