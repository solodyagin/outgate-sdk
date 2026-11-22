package quichttp

import (
	"context"
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
	gate    sync.Mutex
	fenced  bool
	ceiling uint64
	active  int
	idle    chan struct{}
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
	idle := make(chan struct{})
	close(idle)
	s := &Service{carrier: carrier, conn: conn, idle: idle}
	s.server = &http3.Server{MaxHeaderBytes: limits.MaxHeaderBytes, Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		s.gate.Lock()
		id, err := requestID(req.Header)
		if err == nil {
			err = checkRequest(req, limits, true)
		}
		if err == nil {
			err = ids.admit(id)
		}
		if err == nil && s.fenced && id > s.ceiling {
			err = ErrRequest
		}
		if err != nil {
			s.gate.Unlock()
			code, reason := quiccontrol.CodeProtocol, "protocol_error"
			if err == ErrBusy {
				code, reason = 0x4f475407, "quota_exceeded"
			}
			_ = conn.CloseWithError(code, reason)
			return
		}
		if s.fenced {
			s.gate.Unlock()
			// G's negotiated quiescent fence proves this late request is already
			// canceled/completed. Take over without sending response headers.
			stream, err := w.(http3.HTTPStreamer).HTTPStream()
			if err != nil {
				panic(http.ErrAbortHandler)
			}
			stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
			stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
			return
		}
		for name := range req.Header {
			if strings.EqualFold(name, requestIDHeader) {
				delete(req.Header, name)
			}
		}
		select {
		case slots <- struct{}{}:
			if s.active == 0 {
				s.idle = make(chan struct{})
			}
			s.active++
			defer func() {
				<-slots
				s.gate.Lock()
				s.active--
				if s.active == 0 {
					close(s.idle)
				}
				s.gate.Unlock()
			}()
		default:
			s.gate.Unlock()
			_ = req.Body.Close()
			http.Error(w, "request capacity exhausted", http.StatusServiceUnavailable)
			return
		}
		s.gate.Unlock()
		if carrier.Err() != nil {
			panic(http.ErrAbortHandler)
		}
		handler.ServeHTTP(w, req)
	})}
	return s, nil
}

// Quiesce consumes a verified, negotiated G-origin quiescent fence. The caller
// validates capability/direction and command ledger before calling it. It stops
// handler admission immediately, resets late already-canceled IDs <= lastID,
// rejects IDs above the ceiling, and waits for actual handler cleanup. Timeout
// never reopens admission; the lifecycle owner must then close the carrier.
func (s *Service) Quiesce(ctx context.Context, lastID uint64) error {
	if err := s.Fence(lastID); err != nil {
		return err
	}
	s.gate.Lock()
	idle := s.idle
	s.gate.Unlock()
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.carrier.Done():
		return s.carrier.Err()
	}
}

// Fence stops admission without waiting, so a control reader can keep processing
// crossed commands while handlers finish. Only consume a verified negotiated G
// quiescent marker. Quiesce additionally waits for actual handler cleanup.
func (s *Service) Fence(lastID uint64) error {
	s.gate.Lock()
	defer s.gate.Unlock()
	if s.fenced && lastID > s.ceiling {
		return v1.ErrProtocol
	}
	s.fenced = true
	s.ceiling = lastID
	return nil
}

func (s *Service) Active() int { s.gate.Lock(); defer s.gate.Unlock(); return s.active }

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
