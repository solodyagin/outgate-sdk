package wssstate

import (
	"errors"
	"math"
	"reflect"
	"testing"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

var epoch = time.Unix(1000, 0)

func config(local Role) Config {
	return Config{Local: local, Limits: v1.RegisterAckLimits{MaxControlBytes: 65536, MaxChunkBytes: 32768, InitialWindowBytes: 65536, MaxHeaderBytes: 32768, MaxRawURIBytes: 8192, MaxInflight: 1000, BufferBytes: 16777216}, CancelAckTimeout: 10 * time.Second, MaxPendingCancels: 2048}
}
func machine(t testing.TB, local Role) *State {
	t.Helper()
	s, err := New(config(local))
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func request(id uint64, credit uint64) v1.RequestStart {
	return v1.RequestStart{Type: "request_start", StreamID: v1.U64(id), Method: "POST", RawRequestURI: "/api?q=%2F", Host: "example.test", Headers: []v1.Header{}, ResponseCredit: v1.U64(credit)}
}
func response(id uint64) v1.ResponseStart {
	return v1.ResponseStart{Type: "response_start", StreamID: v1.U64(id), Status: 200, Headers: []v1.Header{}}
}
func window(id uint64, direction string, credit uint64) v1.WindowUpdate {
	return v1.WindowUpdate{Type: "window_update", StreamID: v1.U64(id), Direction: direction, Credit: v1.U64(credit)}
}
func chunk(id uint64, kind v1.ChunkKind, n int) v1.Chunk {
	return v1.Chunk{StreamID: id, Kind: kind, Payload: make([]byte, n)}
}
func cancel(id, cid uint64, scope string) v1.Cancel {
	return v1.Cancel{Type: "cancel", StreamID: v1.U64(id), CancelID: v1.U64(cid), Scope: scope, Code: "request_cancelled"}
}
func ack(id, cid uint64, scope string) v1.CancelAck {
	return v1.CancelAck{Type: "cancel_ack", StreamID: v1.U64(id), CancelID: v1.U64(cid), Scope: scope}
}
func apply(t testing.TB, s *State, from Role, m any) Effect {
	t.Helper()
	e, err := s.Apply(from, m, epoch)
	if err != nil {
		t.Fatalf("%T: %v", m, err)
	}
	return e
}
func wantError(t testing.TB, s *State, from Role, m any, want error) {
	t.Helper()
	if _, err := s.Apply(from, m, epoch); !errors.Is(err, want) {
		t.Fatalf("%T: got %v want %v", m, err, want)
	}
}

func TestIndependentEOFAndConsumption(t *testing.T) {
	for _, local := range []Role{Gateway, Service} {
		t.Run(map[Role]string{Gateway: "gateway", Service: "service"}[local], func(t *testing.T) {
			s := machine(t, local)
			apply(t, s, Gateway, request(1, 10))
			apply(t, s, Service, window(1, "request_body", 10))
			apply(t, s, Gateway, chunk(1, v1.RequestBody, 4))
			apply(t, s, Service, response(1))
			apply(t, s, Service, chunk(1, v1.ResponseBody, 3))
			apply(t, s, Service, v1.ResponseEnd{Type: "response_end", StreamID: 1, BytesSent: 3})
			if s.Stats().Active != 1 {
				t.Fatal("response EOF closed request")
			}
			apply(t, s, Gateway, chunk(1, v1.RequestBody, 2))
			apply(t, s, Gateway, v1.RequestEnd{Type: "request_end", StreamID: 1, BytesSent: 6})
			if s.Stats().Active != 1 {
				t.Fatal("unconsumed bytes forgotten")
			}
			direction, n := "request_body", uint64(6)
			if local == Gateway {
				direction, n = "response_body", 3
			}
			e, err := s.Consume(1, direction, n)
			if err != nil || !e.Released || s.Stats().ReservedBytes != s.fixed {
				t.Fatal(e, err, s.Stats())
			}
			apply(t, s, Gateway, request(2, 0))
		})
	}
}

func TestCreditAndBudget(t *testing.T) {
	s := machine(t, Service)
	apply(t, s, Gateway, request(1, 0))
	// Local invalid events are atomic and do not poison the session.
	wantError(t, s, Service, window(1, "request_body", 65537), ErrProtocol)
	apply(t, s, Service, window(1, "request_body", 8))
	apply(t, s, Gateway, chunk(1, v1.RequestBody, 8))
	wantError(t, s, Service, window(1, "request_body", 1), ErrProtocol)
	if _, err := s.Consume(1, "request_body", 4); err != nil {
		t.Fatal(err)
	}
	apply(t, s, Service, window(1, "request_body", 4))
	wantError(t, s, Service, window(1, "request_body", 1), ErrProtocol)
	if s.Stats().ReservedBytes != s.fixed+8 {
		t.Fatal(s.Stats())
	}
	// Reservations across streams include credit and queued unconsumed bytes.
	c := config(Gateway)
	c.Limits.MaxInflight = 2
	c.MaxPendingCancels = 1
	c.Limits.BufferBytes = int(2*streamCharge + cancelCharge + 10)
	limited, _ := New(c)
	apply(t, limited, Gateway, request(1, 10))
	before := limited.Stats()
	wantError(t, limited, Gateway, request(2, 1), ErrCapacity)
	if limited.Stats() != before {
		t.Fatal("failed admission changed counters")
	}
	apply(t, limited, Gateway, request(2, 0))
	c = config(Gateway)
	c.Limits.MaxInflight = 1
	limited, _ = New(c)
	apply(t, limited, Gateway, request(1, 0))
	wantError(t, limited, Gateway, request(2, 0), ErrCapacity)
	// Directly exercise arithmetic near uint64 limits without huge payloads.
	s = machine(t, Gateway)
	apply(t, s, Gateway, request(1, 0))
	st := s.streams[1]
	st.bodies[0].credit = math.MaxUint64
	st.bodies[0].granted = true
	st.bodies[0].renewable = 1
	s.streams[1] = st
	wantError(t, s, Service, window(1, "request_body", 1), ErrProtocol)
	if !s.Stats().Failed {
		t.Fatal("remote overflow did not poison session")
	}
}

func TestEarlyResponseAndCancelRace(t *testing.T) {
	s := machine(t, Service)
	apply(t, s, Gateway, request(1, 20))
	apply(t, s, Service, window(1, "request_body", 10))
	r := response(1)
	r.Status = 429
	apply(t, s, Service, r)
	apply(t, s, Service, chunk(1, v1.ResponseBody, 5))
	apply(t, s, Service, cancel(1, 1, "request_body"))
	if s.Stats().ReservedBytes != s.fixed+10 {
		t.Fatal("credit forgotten before ack", s.Stats())
	}
	if e := apply(t, s, Gateway, chunk(1, v1.RequestBody, 4)); !e.Discard {
		t.Fatal("in-flight chunk delivered")
	}
	apply(t, s, Gateway, v1.RequestEnd{Type: "request_end", StreamID: 1, BytesSent: 4})
	apply(t, s, Gateway, ack(1, 1, "request_body"))
	if s.Stats().PendingCancels != 0 {
		t.Fatal(s.Stats())
	}
	e := apply(t, s, Service, v1.ResponseEnd{Type: "response_end", StreamID: 1, BytesSent: 5})
	if !e.Released || s.Stats().ReservedBytes != s.fixed {
		t.Fatal("early response lost", s.Stats())
	}
	// Bytes exceeding retained credit are never discardable.
	s = machine(t, Service)
	apply(t, s, Gateway, request(1, 0))
	apply(t, s, Service, window(1, "request_body", 1))
	apply(t, s, Service, cancel(1, 1, "all"))
	wantError(t, s, Gateway, chunk(1, v1.RequestBody, 2), ErrProtocol)
}

func TestCancelFencesAndSimultaneousCancels(t *testing.T) {
	for _, local := range []Role{Gateway, Service} {
		s := machine(t, local)
		apply(t, s, Gateway, request(1, 5))
		apply(t, s, Service, window(1, "request_body", 5))
		apply(t, s, local, cancel(1, 1, "all"))
		e := apply(t, s, local.peer(), cancel(1, 1, "all"))
		if e.Ack == nil || e.StopScope != "all" || s.Stats().PendingCancels != 2 {
			t.Fatal(e, s.Stats())
		}
		apply(t, s, local, *e.Ack)
		if s.Stats().Active != 1 {
			t.Fatal("two cancels replaced two acks")
		}
		e = apply(t, s, local.peer(), ack(1, 1, "all"))
		if !e.Released || s.Stats().PendingCancels != 0 {
			t.Fatal(e, s.Stats())
		}
	}
	s := machine(t, Gateway)
	apply(t, s, Gateway, request(1, 5))
	apply(t, s, Gateway, cancel(1, 1, "response_body"))
	// A response already in flight may start and finish before ack.
	apply(t, s, Service, response(1))
	e := apply(t, s, Service, chunk(1, v1.ResponseBody, 2))
	if !e.Discard {
		t.Fatal(e)
	}
	apply(t, s, Service, v1.ResponseEnd{Type: "response_end", StreamID: 1, BytesSent: 2})
	apply(t, s, Service, ack(1, 1, "response_body"))
	wantError(t, s, Service, chunk(1, v1.ResponseBody, 1), ErrProtocol)
	s = machine(t, Service)
	apply(t, s, Gateway, request(1, 0))
	apply(t, s, Gateway, cancel(1, 1, "response_body"))
	wantError(t, s, Service, response(1), ErrProtocol)
	apply(t, s, Service, ack(1, 1, "response_body"))
}

func TestCancelIdentityAndTimeout(t *testing.T) {
	s := machine(t, Gateway)
	apply(t, s, Gateway, request(1, 0))
	c := cancel(1, 1, "all")
	apply(t, s, Gateway, c)
	before := s.Stats()
	apply(t, s, Gateway, c)
	if before != s.Stats() {
		t.Fatal("duplicate allocated ledger")
	}
	c.Code = "other"
	wantError(t, s, Gateway, c, ErrProtocol)
	wantError(t, s, Service, ack(1, 1, "request_body"), ErrProtocol)
	s = machine(t, Gateway)
	apply(t, s, Gateway, request(1, 0))
	apply(t, s, Gateway, cancel(1, 1, "all"))
	if err := s.CheckTimeout(epoch.Add(10*time.Second - time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckTimeout(epoch.Add(10 * time.Second)); !errors.Is(err, ErrTimeout) {
		t.Fatal(err)
	}
	if _, err := s.Apply(Gateway, request(2, 0), epoch.Add(11*time.Second)); !errors.Is(err, ErrTimeout) {
		t.Fatal(err)
	}
	s = machine(t, Gateway)
	apply(t, s, Gateway, request(1, 0))
	apply(t, s, Gateway, cancel(1, 1, "all"))
	// Duplicate does not extend deadline.
	if _, err := s.Apply(Gateway, cancel(1, 1, "all"), epoch.Add(9*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckTimeout(epoch.Add(10 * time.Second)); !errors.Is(err, ErrTimeout) {
		t.Fatal(err)
	}
}

func TestLateCancelWatermarkAndLedgerBound(t *testing.T) {
	s := machine(t, Service)
	for id := uint64(1); id <= 100; id++ {
		apply(t, s, Gateway, request(id, 0))
		apply(t, s, Service, response(id))
		apply(t, s, Gateway, v1.RequestEnd{Type: "request_end", StreamID: v1.U64(id)})
		apply(t, s, Service, v1.ResponseEnd{Type: "response_end", StreamID: v1.U64(id)})
	}
	e := apply(t, s, Gateway, cancel(1, 1, "all"))
	if !e.StatelessAck || e.Ack == nil || s.Stats().Active != 0 || s.Stats().PendingCancels != 0 || s.Stats().ReservedBytes != s.fixed {
		t.Fatal(e, s.Stats())
	}
	wantError(t, s, Service, cancel(1, 1, "all"), ErrClosed)
	wantError(t, s, Gateway, cancel(101, 2, "all"), ErrProtocol)
	c := config(Gateway)
	c.MaxPendingCancels = 1
	s, _ = New(c)
	apply(t, s, Gateway, request(1, 0))
	apply(t, s, Gateway, cancel(1, 1, "request_body"))
	before := s.Stats()
	wantError(t, s, Gateway, cancel(1, 2, "response_body"), ErrCapacity)
	if s.Stats() != before {
		t.Fatal("ledger exhaustion mutated state")
	}
	wantError(t, s, Gateway, request(2, 0), ErrCapacity)
	apply(t, s, Service, ack(1, 1, "request_body"))
	apply(t, s, Gateway, request(2, 0))
}

func TestBodyLengthAndBodylessResponses(t *testing.T) {
	for _, scenario := range []struct {
		method string
		status int
	}{{"HEAD", 200}, {"POST", 204}, {"POST", 304}} {
		s := machine(t, Gateway)
		q := request(1, 4)
		q.Method = scenario.method
		apply(t, s, Gateway, q)
		r := response(1)
		r.Status = scenario.status
		r.Headers = []v1.Header{{"content-length", "99"}}
		apply(t, s, Service, r)
		apply(t, s, Service, v1.ResponseEnd{Type: "response_end", StreamID: 1})
		apply(t, s, Gateway, v1.RequestEnd{Type: "request_end", StreamID: 1})
		if s.Stats().Active != 0 {
			t.Fatal(s.Stats())
		}
		s = machine(t, Gateway)
		apply(t, s, Gateway, q)
		apply(t, s, Service, r)
		wantError(t, s, Service, chunk(1, v1.ResponseBody, 1), ErrBodyLength)
		if s.Stats().Failed {
			t.Fatal("body error poisoned unrelated streams")
		}
		apply(t, s, Gateway, cancel(1, 1, "all"))
		apply(t, s, Service, ack(1, 1, "all"))
		apply(t, s, Gateway, request(2, 0))
	}
	for _, dir := range []Role{Gateway, Service} {
		for _, mismatch := range []string{"short", "long", "total"} {
			s := machine(t, dir.peer())
			q := request(1, 5)
			if dir == Gateway {
				q.Headers = []v1.Header{{"content-length", "2"}}
			}
			apply(t, s, Gateway, q)
			apply(t, s, Service, window(1, "request_body", 5))
			r := response(1)
			if dir == Service {
				r.Headers = []v1.Header{{"content-length", "2"}}
			}
			apply(t, s, Service, r)
			kind := v1.RequestBody
			if dir == Service {
				kind = v1.ResponseBody
			}
			if mismatch == "long" {
				wantError(t, s, dir, chunk(1, kind, 3), ErrBodyLength)
			} else {
				n := 1
				if mismatch == "total" {
					n = 2
				}
				apply(t, s, dir, chunk(1, kind, n))
				var end any = v1.RequestEnd{Type: "request_end", StreamID: 1, BytesSent: 1}
				if dir == Service {
					end = v1.ResponseEnd{Type: "response_end", StreamID: 1, BytesSent: 1}
				}
				wantError(t, s, dir, end, ErrBodyLength)
			}
			apply(t, s, dir.peer(), cancel(1, 1, "all"))
			apply(t, s, dir, ack(1, 1, "all"))
		}
	}
}

func TestProtocolRejections(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(*State)
		from    Role
		message any
	}{
		{"gap", nil, Gateway, request(2, 0)},
		{"wrong start sender", nil, Service, request(1, 0)},
		{"response without request", nil, Service, response(1)},
		{"reuse", func(s *State) { apply(t, s, Gateway, request(1, 0)) }, Gateway, request(1, 0)},
		{"request without credit", func(s *State) { apply(t, s, Gateway, request(1, 0)) }, Gateway, chunk(1, v1.RequestBody, 1)},
		{"body before response", func(s *State) { apply(t, s, Gateway, request(1, 1)) }, Service, chunk(1, v1.ResponseBody, 1)},
		{"response end before start", func(s *State) { apply(t, s, Gateway, request(1, 0)) }, Service, v1.ResponseEnd{Type: "response_end", StreamID: 1}},
		{"wrong window sender", func(s *State) { apply(t, s, Gateway, request(1, 0)) }, Gateway, window(1, "request_body", 1)},
		{"websocket window", func(s *State) { apply(t, s, Gateway, request(1, 0)) }, Service, window(1, "websocket_to_handler", 1)},
		{"websocket chunk", func(s *State) { apply(t, s, Gateway, request(1, 0)) }, Gateway, chunk(1, v1.WebSocketToHandler, 1)},
		{"unsolicited ack", func(s *State) { apply(t, s, Gateway, request(1, 0)) }, Service, ack(1, 1, "all")},
		{"duplicate response", func(s *State) { apply(t, s, Gateway, request(1, 0)); apply(t, s, Service, response(1)) }, Service, response(1)},
		{"duplicate end", func(s *State) {
			apply(t, s, Gateway, request(1, 0))
			apply(t, s, Gateway, v1.RequestEnd{Type: "request_end", StreamID: 1})
		}, Gateway, v1.RequestEnd{Type: "request_end", StreamID: 1}},
		{"body after end", func(s *State) {
			apply(t, s, Gateway, request(1, 0))
			apply(t, s, Gateway, v1.RequestEnd{Type: "request_end", StreamID: 1})
		}, Gateway, chunk(1, v1.RequestBody, 1)},
		{"credit after end", func(s *State) {
			apply(t, s, Gateway, request(1, 0))
			apply(t, s, Gateway, v1.RequestEnd{Type: "request_end", StreamID: 1})
		}, Service, window(1, "request_body", 1)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := machine(t, c.from.peer())
			if c.setup != nil {
				c.setup(s)
			}
			wantError(t, s, c.from, c.message, ErrProtocol)
			if !s.Stats().Failed {
				t.Fatal("remote protocol error not terminal")
			}
		})
	}
}

func TestConfigAndNegotiatedBounds(t *testing.T) {
	c := config(Gateway)
	for _, field := range []string{"MaxControlBytes", "MaxChunkBytes", "InitialWindowBytes", "MaxHeaderBytes", "MaxRawURIBytes", "MaxInflight", "BufferBytes"} {
		copy := c
		v := reflect.ValueOf(&copy.Limits).Elem().FieldByName(field)
		v.SetInt(0)
		if _, err := New(copy); !errors.Is(err, ErrProtocol) {
			t.Fatal(field, err)
		}
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.Local = 3 }, func(c *Config) { c.MaxPendingCancels = 2049 }, func(c *Config) { c.CancelAckTimeout = 0 }} {
		copy := c
		mutate(&copy)
		if _, err := New(copy); !errors.Is(err, ErrProtocol) {
			t.Fatal(err)
		}
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.Limits.MaxRawURIBytes = 1 }, func(c *Config) { c.Limits.MaxControlBytes = 20 }, func(c *Config) { c.Limits.MaxHeaderBytes = 5 }} {
		copy := c
		mutate(&copy)
		s, _ := New(copy)
		wantError(t, s, Gateway, request(1, 0), ErrProtocol)
	}
	s := machine(t, Gateway)
	apply(t, s, Gateway, request(1, 0))
	if _, err := s.Consume(1, "request_body", 1); !errors.Is(err, ErrProtocol) {
		t.Fatal(err)
	}
	if err := s.CheckTimeout(epoch.Add(-time.Second)); !errors.Is(err, ErrProtocol) {
		t.Fatal(err)
	}
}

func TestLengthFailureRetainsBoundedInflightLedger(t *testing.T) {
	s := machine(t, Gateway)
	apply(t, s, Gateway, request(1, 8))
	r := response(1)
	r.Headers = []v1.Header{{"content-length", "1"}}
	apply(t, s, Service, r)
	wantError(t, s, Service, chunk(1, v1.ResponseBody, 2), ErrBodyLength)
	// Even the rejected payload consumes credit, so cancelling cannot authorize
	// a second full window of discarded bytes.
	if s.Stats().ReservedBytes != s.fixed+6 {
		t.Fatal(s.Stats())
	}
	apply(t, s, Gateway, cancel(1, 1, "all"))
	if e := apply(t, s, Service, chunk(1, v1.ResponseBody, 6)); !e.Discard {
		t.Fatal(e)
	}
	apply(t, s, Service, ack(1, 1, "all"))
	if s.Stats().ReservedBytes != s.fixed {
		t.Fatal(s.Stats())
	}
	apply(t, s, Gateway, request(2, 0))
}

func FuzzHTTPStreamLifecycle(f *testing.F) {
	f.Add([]byte{0, 1, 10, 20, 30})
	f.Add([]byte{1, 0, 255, 4})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 32 {
			input = input[:32]
		}
		for _, local := range []Role{Gateway, Service} {
			s := machine(t, local)
			for i, value := range input {
				id := uint64(i + 1)
				n := int(value) + 1
				apply(t, s, Gateway, request(id, uint64(n)))
				apply(t, s, Service, window(id, "request_body", uint64(n)))
				apply(t, s, Service, response(id))
				// Split/replenish credit after actual consumption; early response is
				// deliberately completed before request EOF on every other stream.
				for _, dir := range []Role{Service, Gateway} {
					kind, direction := v1.ResponseBody, "response_body"
					if dir == Gateway {
						kind, direction = v1.RequestBody, "request_body"
					}
					apply(t, s, dir, chunk(id, kind, n))
					if dir != local {
						if _, err := s.Consume(id, direction, uint64(n)); err != nil {
							t.Fatal(err)
						}
					}
					if value%2 == 0 {
						apply(t, s, dir.peer(), window(id, direction, uint64(n)))
					}
					if dir == Service {
						apply(t, s, dir, v1.ResponseEnd{Type: "response_end", StreamID: v1.U64(id), BytesSent: v1.U64(n)})
					} else {
						apply(t, s, dir, v1.RequestEnd{Type: "request_end", StreamID: v1.U64(id), BytesSent: v1.U64(n)})
					}
				}
				if got := s.Stats(); got.Active != 0 || got.ReservedBytes != s.fixed || got.PendingCancels != 0 || got.Failed {
					t.Fatal(got)
				}
				if value%3 == 0 {
					e := apply(t, s, local.peer(), cancel(id, uint64(i+1), "all"))
					if !e.StatelessAck {
						t.Fatal(e)
					}
				}
			}
		}
	})
}

func TestWindowUpdateCrossesCancel(t *testing.T) {
	s := machine(t, Gateway)
	apply(t, s, Gateway, request(1, 0))
	apply(t, s, Gateway, cancel(1, 1, "request_body"))
	if e := apply(t, s, Service, window(1, "request_body", 5)); !e.Discard {
		t.Fatal("in-flight grant not ignored", e)
	}
	wantError(t, s, Gateway, chunk(1, v1.RequestBody, 1), ErrProtocol)
	apply(t, s, Service, ack(1, 1, "request_body"))
	wantError(t, s, Service, window(1, "request_body", 1), ErrProtocol)
}

func TestCancelAfterEOFStillAcknowledged(t *testing.T) {
	s := machine(t, Service)
	apply(t, s, Gateway, request(1, 0))
	apply(t, s, Gateway, v1.RequestEnd{Type: "request_end", StreamID: 1})
	e := apply(t, s, Gateway, cancel(1, 1, "request_body"))
	if e.Ack == nil {
		t.Fatal("EOF suppressed ack")
	}
	apply(t, s, Service, *e.Ack)
	apply(t, s, Service, response(1))
	apply(t, s, Service, v1.ResponseEnd{Type: "response_end", StreamID: 1})
	if s.Stats().Active != 0 {
		t.Fatal(s.Stats())
	}
}

func TestPrepaidStateCapacity(t *testing.T) {
	c := config(Gateway)
	c.Limits.BufferBytes = 512
	if _, err := New(c); !errors.Is(err, ErrCapacity) {
		t.Fatal("state map capacity not reserved", err)
	}
	c.Limits.MaxInflight = 1
	c.MaxPendingCancels = 1
	c.Limits.BufferBytes = int(streamCharge + cancelCharge)
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if s.Stats().StateBytes != streamCharge+cancelCharge || s.Stats().ReservedBytes != s.Stats().StateBytes {
		t.Fatal(s.Stats())
	}
	apply(t, s, Gateway, request(1, 0))
	before := s.Stats()
	wantError(t, s, Gateway, request(2, 0), ErrCapacity)
	if before != s.Stats() {
		t.Fatal("failed reservation mutated state")
	}
}
