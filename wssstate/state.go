// Package wssstate checks ordinary HTTP stream transitions in a registered WSS
// session. It performs no I/O, queues, clocks, callbacks or authentication.
// A State has one owner; callers serialize all methods at frame boundaries.
// Application WebSocket channels and session registration/drain are not implemented.
package wssstate

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

// Role identifies a wire sender, not the direction of a local API call.
type Role uint8

const (
	Gateway Role = iota
	Service
)

func (r Role) valid() bool { return r == Gateway || r == Service }
func (r Role) peer() Role  { return 1 - r }

var (
	ErrProtocol   = v1.ErrProtocol
	ErrCapacity   = errors.New("outgate: WSS state capacity exhausted")
	ErrBodyLength = errors.New("outgate: HTTP body length mismatch; cancel stream")
	ErrClosed     = errors.New("outgate: stream already released")
	ErrTimeout    = errors.New("outgate: cancel acknowledgement deadline exceeded")
)

// Config must come from validated registration negotiation. BufferBytes includes
// prepaid conservative capacity for stream/ledger maps, plus locally issued credit
// and received unconsumed payload. It does not account for transport queues.
type Config struct {
	Local             Role
	Limits            v1.RegisterAckLimits
	CancelAckTimeout  time.Duration
	MaxPendingCancels int
}

const (
	streamCharge uint64 = 512
	cancelCharge uint64 = 256
)

// Effect tells the adapter what must happen at this frame boundary. StopScope
// requires cancelling contexts and dropping queued data/end (and an unsent
// response_start for a cancelled response). Discard forbids delivering payload.
// Ack is populated for received cancels. For StatelessAck, write it directly;
// otherwise commit it through Apply before writing it on the ordered writer.
// Released means the handler/stream resources may be removed.
type Effect struct {
	StopScope    string
	Discard      bool
	Ack          *v1.CancelAck
	StatelessAck bool
	Released     bool
}

// Stats exposes counters without exposing mutable internal state.
type Stats struct {
	Opened         uint64
	Active         int
	PendingCancels int
	ReservedBytes  uint64
	StateBytes     uint64
	Failed         bool
}

type body struct {
	started, ended, blocked, cancelling, granted, forbidden bool
	peerStopped, acked                                      bool
	credit, buffered, renewable, sent                       uint64
	length                                                  uint64
	hasLength                                               bool
}
type stream struct {
	head    bool
	fault   bool
	bodies  [2]body
	pending int
}
type cancelKey struct {
	sender Role
	id     uint64
}
type cancellation struct {
	stream   uint64
	scope    string
	digest   [32]byte
	deadline time.Time
}

// State tracks only HTTP IDs; do not use it on a mixed HTTP/WebSocket session
// until WebSocket transitions share the same opened watermark and budget.
type State struct {
	config           Config
	streams          map[uint64]stream
	cancels          map[cancelKey]cancellation
	lastCancel       [2]uint64
	opened, reserved uint64
	fixed            uint64
	failed           error
	lastTime         time.Time
}

func New(config Config) (*State, error) {
	l := config.Limits
	if !config.Local.valid() || l.MaxControlBytes < 1 || l.MaxControlBytes > v1.MaxControlBytes ||
		l.MaxChunkBytes < 1 || l.MaxChunkBytes > v1.MaxChunkBytes || l.InitialWindowBytes < 1 || l.InitialWindowBytes > 65536 ||
		l.MaxHeaderBytes < 1 || l.MaxHeaderBytes > 32768 || l.MaxRawURIBytes < 1 || l.MaxRawURIBytes > v1.MaxRawURIBytes ||
		l.MaxInflight < 1 || l.MaxInflight > 1000 || l.BufferBytes < 1 || l.BufferBytes > 16777216 ||
		config.CancelAckTimeout <= 0 || config.CancelAckTimeout > 300*time.Second || config.MaxPendingCancels < 1 || config.MaxPendingCancels > 2048 {
		return nil, ErrProtocol
	}
	fixed := uint64(l.MaxInflight)*streamCharge + uint64(config.MaxPendingCancels)*cancelCharge
	if fixed > uint64(l.BufferBytes) {
		return nil, ErrCapacity
	}
	return &State{config: config, fixed: fixed, reserved: fixed,
		streams: make(map[uint64]stream, l.MaxInflight),
		cancels: make(map[cancelKey]cancellation, config.MaxPendingCancels)}, nil
}

func (s *State) Stats() Stats {
	return Stats{Opened: s.opened, Active: len(s.streams), PendingCancels: len(s.cancels), ReservedBytes: s.reserved, StateBytes: s.fixed, Failed: s.failed != nil}
}

// CheckTimeout must be driven by an adapter timer even when no frames arrive.
// Time is supplied by the caller and must be monotonic. Failure is terminal.
func (s *State) CheckTimeout(now time.Time) error {
	if s.failed != nil {
		return s.failed
	}
	if now.IsZero() || !s.lastTime.IsZero() && now.Before(s.lastTime) {
		s.failed = ErrProtocol
		return s.failed
	}
	s.lastTime = now
	for _, c := range s.cancels {
		if !now.Before(c.deadline) {
			s.failed = ErrTimeout
			return s.failed
		}
	}
	return nil
}

func (s *State) fail(from Role, err error) (Effect, error) {
	if from != s.config.Local {
		s.failed = err
	}
	return Effect{}, err
}

func (s *State) reservation(st stream) uint64 {
	b := st.bodies[int(s.config.Local.peer())] // body sender opposite local receiver
	return b.credit + b.buffered
}
func (s *State) commit(id uint64, st stream, old uint64) (Effect, error) {
	next := s.reservation(st)
	if next > uint64(s.config.Limits.BufferBytes) || s.reserved-old > uint64(s.config.Limits.BufferBytes)-next {
		return Effect{}, ErrCapacity
	}
	s.reserved = s.reserved - old + next
	done := st.pending == 0
	for _, b := range st.bodies {
		done = done && (b.ended || b.blocked) && b.buffered == 0
	}
	if done {
		delete(s.streams, id)
		s.reserved -= next
	} else {
		s.streams[id] = st
	}
	return Effect{Released: done}, nil
}

// Apply commits an outgoing frame immediately before ordered transmission, or an
// incoming frame before delivery. Pass values (not pointers) of the supported
// v1 messages or v1.Chunk. A write failure after commitment must close the session;
// it must never retry the business request. Payload slices are never retained.
// Local validation/capacity errors leave stream state unchanged; remote protocol
// or capacity errors poison the session. ErrBodyLength isolates a faulty stream:
// send cancel all before the next frame; bounded in-flight bytes may then be
// discarded until ack. A body-length error still accounts for received payload.
func (s *State) Apply(from Role, message any, now time.Time) (Effect, error) {
	if err := s.CheckTimeout(now); err != nil {
		return Effect{}, err
	}
	if !from.valid() {
		return s.fail(from, ErrProtocol)
	}
	var id uint64
	switch m := message.(type) {
	case v1.RequestStart:
		if from != Gateway || m.Validate() != nil || uint64(m.ResponseCredit) > uint64(s.config.Limits.InitialWindowBytes) || len(m.RawRequestURI) > s.config.Limits.MaxRawURIBytes || !s.headersFit(m.Headers, m.Host) || !s.controlFits(m) {
			return s.fail(from, ErrProtocol)
		}
		id = uint64(m.StreamID)
		if s.opened == math.MaxUint64 || id != s.opened+1 {
			return s.fail(from, ErrProtocol)
		}
		if len(s.streams) >= s.config.Limits.MaxInflight || len(s.cancels) >= s.config.MaxPendingCancels {
			return s.fail(from, ErrCapacity)
		}
		st := stream{head: m.Method == "HEAD"}
		st.bodies[Gateway].started = true
		st.bodies[Gateway].length, st.bodies[Gateway].hasLength = contentLength(m.Headers)
		st.bodies[Service].credit = uint64(m.ResponseCredit)
		st.bodies[Service].granted = m.ResponseCredit > 0
		effect, err := s.commit(id, st, 0)
		if err != nil {
			return s.fail(from, err)
		}
		s.opened = id
		return effect, nil
	case v1.ResponseStart:
		id = uint64(m.StreamID)
	case v1.RequestEnd:
		id = uint64(m.StreamID)
	case v1.ResponseEnd:
		id = uint64(m.StreamID)
	case v1.WindowUpdate:
		id = uint64(m.StreamID)
	case v1.Cancel:
		id = uint64(m.StreamID)
	case v1.CancelAck:
		id = uint64(m.StreamID)
	case v1.Chunk:
		id = m.StreamID
	default:
		return s.fail(from, ErrProtocol)
	}
	st, ok := s.streams[id]
	if !ok {
		if m, yes := message.(v1.Cancel); yes && from != s.config.Local && id > 0 && id <= s.opened && m.Validate() == nil && s.controlFits(m) {
			// Late cancellation is stateless and does not re-enter the handler. IDs
			// remain monotonic even though no tombstone or pending ledger is allocated.
			if uint64(m.CancelID) <= s.lastCancel[from] {
				return s.fail(from, ErrProtocol)
			}
			s.lastCancel[from] = uint64(m.CancelID)
			return Effect{Ack: &v1.CancelAck{Type: "cancel_ack", StreamID: m.StreamID, CancelID: m.CancelID, Scope: m.Scope}, StatelessAck: true}, nil
		}
		if _, yes := message.(v1.Cancel); yes && from == s.config.Local && id > 0 && id <= s.opened {
			return Effect{}, ErrClosed
		}
		return s.fail(from, ErrProtocol)
	}
	old := s.reservation(st)
	if st.fault {
		switch message.(type) {
		case v1.Cancel, v1.CancelAck:
		case v1.Chunk, v1.RequestEnd, v1.ResponseEnd, v1.ResponseStart:
			if !st.bodies[0].cancelling || !st.bodies[1].cancelling {
				return Effect{}, ErrBodyLength
			}
		default:
			return s.fail(from, ErrProtocol)
		}
	}
	var effect Effect
	var addKey, removeKey *cancelKey
	var addCancel cancellation
	switch m := message.(type) {
	case v1.ResponseStart:
		b := &st.bodies[Service]
		if from != Service || m.Validate() != nil || !s.controlFits(m) || !s.headersFit(m.Headers, "") || b.started || b.blocked {
			return s.fail(from, ErrProtocol)
		}
		b.started = true
		effect.Discard = b.cancelling
		b.forbidden = st.head || m.Status == 204 || m.Status == 304
		b.length, b.hasLength = contentLength(m.Headers)
	case v1.WindowUpdate:
		if m.Validate() != nil || !s.controlFits(m) {
			return s.fail(from, ErrProtocol)
		}
		dir, valid := httpDirection(m.Direction)
		if !valid || from == Role(dir) {
			return s.fail(from, ErrProtocol)
		}
		b := &st.bodies[dir]
		n := uint64(m.Credit)
		inflightGrant := b.cancelling && from != s.config.Local && !b.peerStopped && !b.acked
		if b.ended || (b.blocked || b.cancelling) && !inflightGrant || n > math.MaxUint64-b.credit {
			return s.fail(from, ErrProtocol)
		}
		effect.Discard = inflightGrant
		if !b.granted {
			if n > uint64(s.config.Limits.InitialWindowBytes) {
				return s.fail(from, ErrProtocol)
			}
			b.granted = true
		} else {
			if n > b.renewable {
				return s.fail(from, ErrProtocol)
			}
			b.renewable -= n
		}
		b.credit += n
	case v1.Chunk:
		if m.Kind != v1.RequestBody && m.Kind != v1.ResponseBody || m.StreamID == 0 || len(m.Payload) == 0 || len(m.Payload) > s.config.Limits.MaxChunkBytes {
			return s.fail(from, ErrProtocol)
		}
		dir := int(m.Kind - v1.RequestBody)
		b := &st.bodies[dir]
		n := uint64(len(m.Payload))
		if from != Role(dir) || !b.started || b.ended || b.blocked || n > b.credit || n > math.MaxUint64-b.sent {
			return s.fail(from, ErrProtocol)
		}
		badLength := !b.cancelling && (b.forbidden || b.hasLength && (b.sent > b.length || n > b.length-b.sent))
		if badLength && from == s.config.Local {
			st.fault = true
			s.streams[id] = st
			return Effect{StopScope: "all"}, ErrBodyLength
		}
		b.credit -= n
		b.sent += n
		effect.Discard = b.cancelling || badLength
		if from != s.config.Local {
			if !effect.Discard {
				b.buffered += n
			}
		} else {
			b.renewable += n
		} // upper bound on the peer's possible consumption
		if badLength {
			st.fault = true
			if _, err := s.commit(id, st, old); err != nil {
				return s.fail(from, err)
			}
			return Effect{StopScope: "all", Discard: true}, ErrBodyLength
		}
	case v1.RequestEnd:
		if from != Gateway || m.Validate() != nil || !s.controlFits(m) {
			return s.fail(from, ErrProtocol)
		}
		if err := end(&st.bodies[Gateway], uint64(m.BytesSent)); err != nil {
			return s.endError(from, id, st, err)
		}
	case v1.ResponseEnd:
		if from != Service || m.Validate() != nil || !s.controlFits(m) {
			return s.fail(from, ErrProtocol)
		}
		if err := end(&st.bodies[Service], uint64(m.BytesSent)); err != nil {
			return s.endError(from, id, st, err)
		}
	case v1.Cancel:
		if m.Validate() != nil || !s.controlFits(m) {
			return s.fail(from, ErrProtocol)
		}
		key := cancelKey{from, uint64(m.CancelID)}
		encoded, _ := json.Marshal(m)
		digest := sha256.Sum256(encoded)
		if prior, exists := s.cancels[key]; exists {
			if prior.stream != id || prior.digest != digest {
				return s.fail(from, ErrProtocol)
			}
			return s.cancelEffect(from, m), nil
		}
		if uint64(m.CancelID) <= s.lastCancel[from] {
			return s.fail(from, ErrProtocol)
		}
		if len(s.cancels) >= s.config.MaxPendingCancels {
			return s.fail(from, ErrCapacity)
		}
		st.pending++
		for i := range st.bodies {
			if covers(m.Scope, i) {
				b := &st.bodies[i]
				b.cancelling = true
				// Received cancels fence the peer's preceding frames and stop our
				// writer. Outgoing cancels keep peer in-flight credit until ack.
				if from != s.config.Local || Role(i) == s.config.Local {
					b.blocked = true
					if from != s.config.Local {
						b.peerStopped = true
						b.credit = 0
					}
				}
				if Role(i) != s.config.Local {
					b.buffered = 0
				}
			}
		}
		addKey = &key
		addCancel = cancellation{id, m.Scope, digest, now.Add(s.config.CancelAckTimeout)}
		effect = s.cancelEffect(from, m)
	case v1.CancelAck:
		if m.Validate() != nil || !s.controlFits(m) {
			return s.fail(from, ErrProtocol)
		}
		key := cancelKey{from.peer(), uint64(m.CancelID)}
		pending, exists := s.cancels[key]
		if !exists || pending.stream != id || pending.scope != m.Scope {
			return s.fail(from, ErrProtocol)
		}
		for i := range st.bodies {
			if covers(m.Scope, i) {
				b := &st.bodies[i]
				b.blocked = true
				b.acked = true
				b.credit = 0
				b.buffered = 0
			}
		}
		st.pending--
		removeKey = &key
	}
	committed, err := s.commit(id, st, old)
	if err != nil {
		return s.fail(from, err)
	}
	if addKey != nil {
		s.cancels[*addKey] = addCancel
		s.lastCancel[from] = addKey.id
	}
	if removeKey != nil {
		delete(s.cancels, *removeKey)
	}
	effect.Released = committed.Released
	return effect, nil
}

func (s *State) cancelEffect(from Role, m v1.Cancel) Effect {
	effect := Effect{StopScope: m.Scope}
	if from != s.config.Local {
		effect.Ack = &v1.CancelAck{Type: "cancel_ack", StreamID: m.StreamID, CancelID: m.CancelID, Scope: m.Scope}
	}
	return effect
}
func end(b *body, total uint64) error {
	if !b.started || b.ended || b.blocked {
		return ErrProtocol
	}
	if total != b.sent || b.hasLength && !b.forbidden && !b.cancelling && total != b.length {
		return ErrBodyLength
	}
	b.ended = true
	b.credit = 0
	return nil
}
func (s *State) endError(from Role, id uint64, st stream, err error) (Effect, error) {
	if err == ErrBodyLength {
		st.fault = true
		s.streams[id] = st
		return Effect{StopScope: "all"}, err
	}
	return s.fail(from, err)
}

// Consume reports bytes actually delivered downstream, never bytes merely read
// into a queue. It releases local receive reservations and permits replenishment.
// Cancel effects already drop queued bytes; do not Consume them again.
func (s *State) Consume(id uint64, direction string, n uint64) (Effect, error) {
	if s.failed != nil {
		return Effect{}, s.failed
	}
	dir, ok := httpDirection(direction)
	st, exists := s.streams[id]
	if !ok || !exists || Role(dir) == s.config.Local || n == 0 || n > st.bodies[dir].buffered {
		return Effect{}, ErrProtocol
	}
	old := s.reservation(st)
	b := &st.bodies[dir]
	b.buffered -= n
	if n > math.MaxUint64-b.renewable {
		return Effect{}, ErrProtocol
	}
	b.renewable += n
	return s.commit(id, st, old)
}
func httpDirection(direction string) (int, bool) {
	switch direction {
	case "request_body":
		return 0, true
	case "response_body":
		return 1, true
	default:
		return 0, false
	}
}
func covers(scope string, dir int) bool {
	return scope == "all" || scope == "request_body" && dir == 0 || scope == "response_body" && dir == 1
}
func contentLength(headers []v1.Header) (uint64, bool) {
	for _, h := range headers {
		if h[0] == "content-length" {
			n, _ := strconv.ParseUint(strings.Trim(h[1], " \t"), 10, 63)
			return n, true
		}
	}
	return 0, false
}
func (s *State) controlFits(message any) bool {
	b, err := json.Marshal(message)
	return err == nil && len(b) <= s.config.Limits.MaxControlBytes
}

// Bound HTTP field serialization (name + colon/SP + value + CRLF, final CRLF),
// including the explicit request Host. Transport start lines are not headers.
func (s *State) headersFit(headers []v1.Header, host string) bool {
	total := 2
	if host != "" {
		total += len("host") + len(host) + 4
	}
	for _, h := range headers {
		total += len(h[0]) + len(h[1]) + 4
	}
	return total <= s.config.Limits.MaxHeaderBytes
}
