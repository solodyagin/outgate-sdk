package quichttp

import (
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
)

// Service owns the reverse HTTP/3 server for one registered service connection.
// Handler must include the deployment's signature/authorization middleware;
// successful registration and a request ID alone do not authorize dispatch.
type Service struct {
	carrier *quiccontrol.Carrier
	conn    *quic.Conn
	server  *http3.Server
	started atomic.Bool
}

func NewService(carrier *quiccontrol.Carrier, handler http.Handler) (*Service, error) {
	if carrier == nil || handler == nil {
		return nil, v1.ErrProtocol
	}
	conn, limits, err := carrier.ClaimHTTP3(true)
	if err != nil {
		return nil, err
	}
	// Ranges compress normal monotonic traffic to a single entry. Sparse gaps
	// consume fixed capacity instead of an unbounded session-long tombstone map.
	capacity := max(1, min(limits.MaxInflight+1, limits.BufferBytes/64))
	ids := &requestIDs{spans: make([]idSpan, 0, capacity)}
	slots := make(chan struct{}, limits.MaxInflight)
	s := &Service{carrier: carrier, conn: conn}
	s.server = &http3.Server{MaxHeaderBytes: limits.MaxHeaderBytes, Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		id, err := requestID(req.Header)
		if err == nil {
			err = checkRequest(req, limits, true)
		}
		if err == nil {
			err = ids.admit(id)
		}
		if err != nil {
			code, reason := quiccontrol.CodeProtocol, "protocol_error"
			if err == ErrBusy {
				code, reason = 0x4f475407, "quota_exceeded"
			}
			_ = conn.CloseWithError(code, reason)
			return
		}
		for name := range req.Header {
			if strings.EqualFold(name, requestIDHeader) {
				delete(req.Header, name)
			}
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			_ = req.Body.Close()
			http.Error(w, "request capacity exhausted", http.StatusServiceUnavailable)
			return
		}
		if carrier.Err() != nil {
			panic(http.ErrAbortHandler)
		}
		handler.ServeHTTP(w, req)
	})}
	return s, nil
}

// Serve blocks for the connection lifetime. Only the registered reverse
// connection is served; no TCP/UDP listener or additional dial is created.
func (s *Service) Serve() error {
	if !s.started.CompareAndSwap(false, true) {
		return v1.ErrProtocol
	}
	err := s.server.ServeQUICConn(s.conn)
	_ = s.carrier.Close()
	return err
}

func (s *Service) Close() error {
	_ = s.carrier.Close()
	return s.server.Close()
}

func requestID(headers http.Header) (uint64, error) {
	var value string
	count := 0
	for name, values := range headers {
		if strings.EqualFold(name, requestIDHeader) {
			for _, v := range values {
				count++
				value = v
			}
		}
	}
	if count != 1 || len(value) < 1 || len(value) > 20 || value[0] == '0' {
		return 0, ErrRequest
	}
	id, err := strconv.ParseUint(value, 10, 64)
	if err != nil || id == 0 || strconv.FormatUint(id, 10) != value {
		return 0, ErrRequest
	}
	return id, nil
}

type idSpan struct{ first, last uint64 }
type requestIDs struct {
	mu    sync.Mutex
	spans []idSpan
}

func (r *requestIDs) admit(id uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := sort.Search(len(r.spans), func(i int) bool { return r.spans[i].last >= id })
	if i < len(r.spans) && r.spans[i].first <= id {
		return ErrRequest
	}
	left := i > 0 && r.spans[i-1].last != math.MaxUint64 && r.spans[i-1].last+1 == id
	right := i < len(r.spans) && id != math.MaxUint64 && id+1 == r.spans[i].first
	switch {
	case left && right:
		r.spans[i-1].last = r.spans[i].last
		r.spans = append(r.spans[:i], r.spans[i+1:]...)
	case left:
		r.spans[i-1].last = id
	case right:
		r.spans[i].first = id
	default:
		if len(r.spans) == cap(r.spans) {
			return ErrBusy
		}
		r.spans = append(r.spans, idSpan{})
		copy(r.spans[i+1:], r.spans[i:])
		r.spans[i] = idSpan{first: id, last: id}
	}
	return nil
}
