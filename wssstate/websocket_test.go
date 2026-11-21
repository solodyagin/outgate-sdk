package wssstate

import (
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"math"
	"testing"
)

func wsOpen(id, credit uint64) v1.WebSocketOpen {
	return v1.WebSocketOpen{Type: "websocket_open", StreamID: v1.U64(id), Method: "GET", RawRequestURI: "/ws", Host: "example.test", Headers: []v1.Header{{"connection", "Upgrade"}, {"upgrade", "websocket"}}, FromHandlerCredit: v1.U64(credit)}
}
func wsAck(id, credit uint64) v1.WebSocketOpenAck {
	return v1.WebSocketOpenAck{Type: "websocket_open_ack", StreamID: v1.U64(id), ToHandlerCredit: v1.U64(credit)}
}
func wsEnd(id uint64, dir string, n uint64) v1.WebSocketEnd {
	return v1.WebSocketEnd{Type: "websocket_end", StreamID: v1.U64(id), Direction: dir, BytesSent: v1.U64(n)}
}

func TestMixedChannelsLifecycle(t *testing.T) {
	for _, local := range []Role{Gateway, Service} {
		s := machine(t, local)
		apply(t, s, Gateway, request(1, 0))
		apply(t, s, Gateway, wsOpen(2, 100))
		apply(t, s, Service, wsAck(2, 100))
		// Raw inner handshakes and bytes read together with their headers all count.
		up, down := []byte("GET /ws HTTP/1.1\r\n\r\nframe"), []byte("HTTP/1.1 101 Switching Protocols\r\n\r\nframe")
		apply(t, s, Gateway, v1.Chunk{StreamID: 2, Kind: v1.WebSocketToHandler, Payload: up})
		apply(t, s, Service, v1.Chunk{StreamID: 2, Kind: v1.WebSocketFromHandler, Payload: down})
		apply(t, s, Service, wsEnd(2, "websocket_from_handler", uint64(len(down))))
		apply(t, s, Gateway, chunk(2, v1.WebSocketToHandler, 1))
		apply(t, s, Gateway, wsEnd(2, "websocket_to_handler", uint64(len(up)+1)))
		if s.Stats().Active != 2 {
			t.Fatal(s.Stats())
		}
		dir, n := "websocket_to_handler", uint64(len(up)+1)
		if local == Gateway {
			dir, n = "websocket_from_handler", uint64(len(down))
		}
		e, err := s.Consume(2, dir, n)
		if err != nil || !e.Released {
			t.Fatal(e, err)
		}
		apply(t, s, Service, response(1))
		apply(t, s, Service, v1.ResponseEnd{Type: "response_end", StreamID: 1})
		apply(t, s, Gateway, v1.RequestEnd{Type: "request_end", StreamID: 1})
		if s.Stats().ReservedBytes != s.fixed || s.Stats().Active != 0 || s.Stats().Opened != 2 {
			t.Fatal(s.Stats())
		}
		e = apply(t, s, local.peer(), cancel(2, 1, "all"))
		if !e.StatelessAck {
			t.Fatal(e)
		}
		apply(t, s, Gateway, request(3, 0))
	}
}
func TestWebSocketRefusal(t *testing.T) {
	for _, local := range []Role{Gateway, Service} {
		s := machine(t, local)
		apply(t, s, Gateway, wsOpen(1, 4))
		r := response(1)
		r.Status = 403
		r.Headers = []v1.Header{{"content-length", "4"}}
		apply(t, s, Service, r)
		apply(t, s, Service, chunk(1, v1.ResponseBody, 4))
		apply(t, s, Service, v1.ResponseEnd{Type: "response_end", StreamID: 1, BytesSent: 4})
		if local == Gateway {
			e, err := s.Consume(1, "response_body", 4)
			if err != nil || !e.Released {
				t.Fatal(e, err)
			}
		}
		if s.Stats().Active != 0 || s.Stats().ReservedBytes != s.fixed {
			t.Fatal(s.Stats())
		}
	}
}
func TestWebSocketInvalidTransitions(t *testing.T) {
	type scenario struct {
		name    string
		channel bool
		from    Role
		msg     any
	}
	tests := []scenario{
		{"data before ack", false, Gateway, chunk(1, v1.WebSocketToHandler, 1)},
		{"return data before ack", false, Service, chunk(1, v1.WebSocketFromHandler, 1)},
		{"end before ack", false, Gateway, wsEnd(1, "websocket_to_handler", 0)},
		{"window before ack", false, Service, window(1, "websocket_to_handler", 1)},
		{"HTTP request end", false, Gateway, v1.RequestEnd{Type: "request_end", StreamID: 1}},
		{"HTTP response end", false, Service, v1.ResponseEnd{Type: "response_end", StreamID: 1}},
		{"partial cancel", false, Gateway, cancel(1, 1, "request_body")},
		{"wrong ack sender", false, Gateway, wsAck(1, 1)},
		{"huge ack", false, Service, wsAck(1, math.MaxUint64)},
		{"duplicate ack", true, Service, wsAck(1, 1)},
		{"HTTP response in channel", true, Service, response(1)},
		{"HTTP data in channel", true, Gateway, chunk(1, v1.RequestBody, 1)},
		{"HTTP window in channel", true, Gateway, window(1, "response_body", 1)},
		{"wrong EOF sender", true, Service, wsEnd(1, "websocket_to_handler", 0)},
		{"partial channel cancel", true, Service, cancel(1, 1, "response_body")},
		{"wrong chunk sender", true, Service, chunk(1, v1.WebSocketToHandler, 1)},
		{"unknown ID", true, Gateway, chunk(2, v1.WebSocketToHandler, 1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, local := range []Role{Gateway, Service} {
				s := machine(t, local)
				apply(t, s, Gateway, wsOpen(1, 10))
				if tt.channel {
					apply(t, s, Service, wsAck(1, 10))
				}
				before := s.Stats()
				wantError(t, s, tt.from, tt.msg, ErrProtocol)
				after := s.Stats()
				if after.Failed != (tt.from != local) {
					t.Fatal(after)
				}
				before.Failed = after.Failed
				if before != after {
					t.Fatal("invalid frame mutated counters", before, after)
				}
			}
		})
	}
}
func TestWebSocketCreditAndSharedAdmission(t *testing.T) {
	s := machine(t, Service)
	apply(t, s, Gateway, wsOpen(1, 0))
	apply(t, s, Service, wsAck(1, 4))
	apply(t, s, Gateway, chunk(1, v1.WebSocketToHandler, 4))
	wantError(t, s, Service, window(1, "websocket_to_handler", 1), ErrProtocol)
	if _, err := s.Consume(1, "request_body", 1); err != ErrProtocol {
		t.Fatal(err)
	}
	if _, err := s.Consume(1, "websocket_to_handler", 2); err != nil {
		t.Fatal(err)
	}
	apply(t, s, Service, window(1, "websocket_to_handler", 2))
	wantError(t, s, Service, window(1, "websocket_to_handler", 1), ErrProtocol)
	apply(t, s, Gateway, chunk(1, v1.WebSocketToHandler, 2))
	c := config(Gateway)
	c.Limits.MaxInflight = 2
	c.Limits.BufferBytes = 2*int(streamCharge) + c.MaxPendingCancels*int(cancelCharge) + 5
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	apply(t, s, Gateway, request(1, 3))
	wantError(t, s, Gateway, wsOpen(2, 3), ErrCapacity)
	if s.Stats().Opened != 1 {
		t.Fatal(s.Stats())
	}
	apply(t, s, Gateway, wsOpen(2, 2))
	wantError(t, s, Gateway, request(3, 0), ErrCapacity)
	wantError(t, s, Gateway, wsOpen(4, 0), ErrProtocol)
	if s.Stats().ReservedBytes != uint64(c.Limits.BufferBytes) {
		t.Fatal(s.Stats())
	}
}
func TestWebSocketCancelRaces(t *testing.T) {
	for _, local := range []Role{Gateway, Service} {
		for _, opened := range []bool{false, true} {
			s := machine(t, local)
			apply(t, s, Gateway, wsOpen(1, 10))
			if opened {
				apply(t, s, Service, wsAck(1, 10))
			}
			apply(t, s, local, cancel(1, 1, "all"))
			if !opened && local == Gateway {
				e := apply(t, s, Service, wsAck(1, 10))
				if !e.Discard {
					t.Fatal(e)
				}
				opened = true
			}
			if opened {
				kind, dir := v1.WebSocketToHandler, "websocket_to_handler"
				if local == Gateway {
					kind, dir = v1.WebSocketFromHandler, "websocket_from_handler"
				}
				if !apply(t, s, local.peer(), chunk(1, kind, 2)).Discard {
					t.Fatal("inflight delivered")
				}
				apply(t, s, local.peer(), wsEnd(1, dir, 2))
			}
			e := apply(t, s, local.peer(), cancel(1, 1, "all"))
			if e.Ack == nil {
				t.Fatal(e)
			}
			apply(t, s, local, *e.Ack)
			e = apply(t, s, local.peer(), ack(1, 1, "all"))
			if !e.Released || s.Stats().ReservedBytes != s.fixed || s.Stats().PendingCancels != 0 {
				t.Fatal(e, s.Stats())
			}
		}
	}
}
func TestWebSocketTotalsAndRefusalBoundaries(t *testing.T) {
	s := machine(t, Gateway)
	apply(t, s, Gateway, wsOpen(1, 1))
	apply(t, s, Service, wsAck(1, 0))
	apply(t, s, Service, chunk(1, v1.WebSocketFromHandler, 1))
	wantError(t, s, Service, wsEnd(1, "websocket_from_handler", 0), ErrBodyLength)
	apply(t, s, Gateway, cancel(1, 1, "all"))
	apply(t, s, Service, ack(1, 1, "all"))
	s = machine(t, Gateway)
	apply(t, s, Gateway, wsOpen(1, 1))
	r := response(1)
	r.Status = 502
	apply(t, s, Service, r)
	wantError(t, s, Gateway, chunk(1, v1.WebSocketToHandler, 1), ErrProtocol)
	wantError(t, s, Gateway, cancel(1, 1, "request_body"), ErrProtocol)
	wantError(t, s, Service, wsAck(1, 0), ErrProtocol)
}

func TestWebSocketNegotiatedLimits(t *testing.T) {
	for _, field := range []string{"headers", "uri", "control", "window"} {
		t.Run(field, func(t *testing.T) {
			c := config(Gateway)
			m := wsOpen(1, 1)
			switch field {
			case "headers":
				c.Limits.MaxHeaderBytes = 10
			case "uri":
				c.Limits.MaxRawURIBytes = 2
			case "control":
				c.Limits.MaxControlBytes = 10
			case "window":
				m.FromHandlerCredit = 65537
			}
			s, err := New(c)
			if err != nil {
				t.Fatal(err)
			}
			wantError(t, s, Gateway, m, ErrProtocol)
			if s.Stats().Opened != 0 || s.Stats().Active != 0 {
				t.Fatal(s.Stats())
			}
		})
	}
	c := config(Service)
	c.Limits.MaxInflight = 1
	c.MaxPendingCancels = 1
	c.Limits.BufferBytes = int(streamCharge+cancelCharge) + 3
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	apply(t, s, Gateway, wsOpen(1, 0))
	before := s.Stats()
	wantError(t, s, Service, wsAck(1, 4), ErrCapacity)
	if s.Stats() != before {
		t.Fatal(s.Stats())
	}
	apply(t, s, Service, wsAck(1, 3))
}

func TestWebSocketZeroCreditAndTerminalFrames(t *testing.T) {
	s := machine(t, Gateway)
	apply(t, s, Gateway, wsOpen(1, 0))
	apply(t, s, Service, wsAck(1, 0))
	wantError(t, s, Gateway, chunk(1, v1.WebSocketToHandler, 1), ErrProtocol)
	apply(t, s, Service, window(1, "websocket_to_handler", 1))
	apply(t, s, Gateway, chunk(1, v1.WebSocketToHandler, 1))
	apply(t, s, Gateway, wsEnd(1, "websocket_to_handler", 1))
	wantError(t, s, Gateway, wsEnd(1, "websocket_to_handler", 1), ErrProtocol)
	wantError(t, s, Gateway, chunk(1, v1.WebSocketToHandler, 1), ErrProtocol)
	apply(t, s, Service, wsEnd(1, "websocket_from_handler", 0))
	wantError(t, s, Gateway, chunk(1, v1.WebSocketToHandler, 1), ErrProtocol)
	s = machine(t, Gateway)
	apply(t, s, Gateway, request(1, 0))
	wantError(t, s, Gateway, chunk(1, v1.WebSocketToHandler, 1), ErrProtocol)
	wantError(t, s, Gateway, wsEnd(1, "websocket_to_handler", 0), ErrProtocol)
}

func FuzzMixedStreamLifecycle(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64 {
			data = data[:64]
		}
		for _, local := range []Role{Gateway, Service} {
			s := machine(t, local)
			for i, value := range data {
				id := uint64(i + 1)
				n := int(value%16) + 1
				switch value % 3 {
				case 0:
					apply(t, s, Gateway, request(id, 0))
					apply(t, s, Gateway, v1.RequestEnd{Type: "request_end", StreamID: v1.U64(id)})
					apply(t, s, Service, response(id))
					apply(t, s, Service, v1.ResponseEnd{Type: "response_end", StreamID: v1.U64(id)})
				case 1:
					apply(t, s, Gateway, wsOpen(id, uint64(n)))
					apply(t, s, Service, wsAck(id, uint64(n)))
					for _, sender := range []Role{Gateway, Service} {
						kind, dir := v1.WebSocketToHandler, "websocket_to_handler"
						if sender == Service {
							kind, dir = v1.WebSocketFromHandler, "websocket_from_handler"
						}
						apply(t, s, sender, chunk(id, kind, n))
						if sender != local {
							if _, err := s.Consume(id, dir, uint64(n)); err != nil {
								t.Fatal(err)
							}
						}
						if value%2 == 0 {
							apply(t, s, sender.peer(), window(id, dir, uint64(n)))
						}
						apply(t, s, sender, wsEnd(id, dir, uint64(n)))
					}
				case 2:
					apply(t, s, Gateway, wsOpen(id, 0))
					if value%2 == 0 {
						r := response(id)
						r.Status = 503
						apply(t, s, Service, r)
						apply(t, s, Service, v1.ResponseEnd{Type: "response_end", StreamID: v1.U64(id)})
					} else {
						apply(t, s, local, cancel(id, id, "all"))
						apply(t, s, local.peer(), ack(id, id, "all"))
					}
				}
				if got := s.Stats(); got.Active != 0 || got.PendingCancels != 0 || got.ReservedBytes != s.fixed || got.Failed || got.Opened != id {
					t.Fatal(got)
				}
			}
		}
	})
}
