package quiccontrol

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

// Carrier owns stream 0. A reader retains at most one bounded decoded frame;
// Send serializes writes without an unbounded queue. Receive calls must have one
// owner. It validates message schemas/directions, not sessionstate transitions,
// command ledgers, readiness freshness or security/credential deadlines.
type Carrier struct {
	conn         *quic.Conn
	stream       *quic.Stream
	service      bool
	maximum      int
	writeTimeout time.Duration
	ctx          context.Context
	cancel       context.CancelCauseFunc
	once         sync.Once
	writes       chan struct{}
	messages     chan any
	readerDone   chan struct{}
}

func newCarrier(conn *quic.Conn, stream *quic.Stream, service bool, o Options, ack v1.RegisterAck) *Carrier {
	ctx, cancel := context.WithCancelCause(context.Background())
	c := &Carrier{conn: conn, stream: stream, service: service, maximum: ack.Limits.MaxControlBytes,
		writeTimeout: min(o.WriteTimeout, time.Duration(ack.Timeouts.WriteMS)*time.Millisecond),
		ctx:          ctx, cancel: cancel, writes: make(chan struct{}, 1), messages: make(chan any), readerDone: make(chan struct{})}
	go c.readLoop()
	go func() {
		select {
		case <-conn.Context().Done():
			c.fail(context.Cause(conn.Context()), CodeProtocol, "protocol_error")
		case <-ctx.Done():
		}
	}()
	return c
}

// Done closes on explicit Close, connection loss, carrier FIN/reset, malformed
// input, or an interrupted write. Err then reports the terminal cause.
func (c *Carrier) Done() <-chan struct{} { return c.ctx.Done() }
func (c *Carrier) Err() error            { return context.Cause(c.ctx) }

// Close ends the entire QUIC session, never half-closes the carrier. It unblocks
// pending Send/Receive calls and joins the carrier reader. It is idempotent.
func (c *Carrier) Close() error {
	c.fail(context.Canceled, CodeNormal, "normal")
	<-c.readerDone
	return nil
}

func (c *Carrier) fail(err error, code quic.ApplicationErrorCode, reason string) {
	c.once.Do(func() {
		c.cancel(err)
		_ = c.conn.CloseWithError(code, reason)
	})
}

func (c *Carrier) readLoop() {
	defer close(c.readerDone)
	for {
		b, err := v1.ReadControl(c.stream, c.maximum)
		var message any
		if err == nil {
			message, err = decode(b, !c.service)
		}
		if err != nil {
			c.fail(err, CodeProtocol, "protocol_error")
			return
		}
		select {
		case c.messages <- message:
		case <-c.ctx.Done():
			return
		}
	}
}

// Receive returns a typed v1 session-control value. Canceling a waiting Receive
// does not consume a message or close the connection. Check Err before applying
// it to session state; the connection can fail concurrently with delivery.
func (c *Carrier) Receive(ctx context.Context) (any, error) {
	if err := c.Err(); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, c.Err()
	case message := <-c.messages:
		if err := c.Err(); err != nil {
			return nil, err
		}
		return message, nil
	}
}

// Send accepts v1 session-control values (or pointers). Invalid outgoing data is
// rejected before I/O. Cancellation while waiting for another writer is safe;
// interruption after starting a frame closes the session, with no retry.
func (c *Carrier) Send(ctx context.Context, message any) error {
	if err := c.Err(); err != nil {
		return err
	}
	// Accept only concrete wire messages; arbitrary MarshalJSON implementations
	// must not allocate unbounded data or inject other control-message families.
	switch message.(type) {
	case v1.InstanceStatus, *v1.InstanceStatus, v1.Drain, *v1.Drain, v1.DrainAck, *v1.DrainAck,
		v1.Unregister, *v1.Unregister, v1.UnregisterAck, *v1.UnregisterAck, v1.Reconnect, *v1.Reconnect:
	default:
		return v1.ErrProtocol
	}
	b, err := json.Marshal(message)
	if err != nil || len(b) > c.maximum {
		return v1.ErrProtocol
	}
	if _, err = decode(b, c.service); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.ctx.Done():
		return c.Err()
	case c.writes <- struct{}{}:
	}
	defer func() { <-c.writes }()
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = c.Err(); err != nil {
		return err
	}
	writeCtx, cancel := context.WithTimeout(ctx, c.writeTimeout)
	defer cancel()
	deadline, _ := writeCtx.Deadline()
	_ = c.stream.SetWriteDeadline(deadline)
	done := make(chan struct{})
	stop := context.AfterFunc(writeCtx, func() { _ = c.stream.SetWriteDeadline(time.Now()); close(done) })
	err = v1.WriteControl(c.stream, b, c.maximum)
	if !stop() {
		<-done
	}
	_ = c.stream.SetWriteDeadline(time.Time{})
	if err != nil {
		err = operationError(writeCtx, err)
		c.fail(err, CodeProtocol, "protocol_error")
	}
	return err
}

func decode(b []byte, fromService bool) (any, error) {
	var tag struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(b, &tag) != nil {
		return nil, v1.ErrProtocol
	}
	switch tag.Type {
	case "instance_status":
		if fromService {
			return v1.DecodeInstanceStatus(b)
		}
	case "drain":
		return v1.DecodeDrain(b)
	case "drain_ack":
		return v1.DecodeDrainAck(b)
	case "unregister":
		if fromService {
			return v1.DecodeUnregister(b)
		}
	case "unregister_ack":
		if !fromService {
			return v1.DecodeUnregisterAck(b)
		}
	case "reconnect":
		if !fromService {
			return v1.DecodeReconnect(b)
		}
	}
	return nil, v1.ErrProtocol
}
