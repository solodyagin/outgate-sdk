// Package quiccontrol implements the Outgate stream 0 carrier on an existing
// quic-go connection. It does not dial, authorize routes, or serve HTTP/3.
package quiccontrol

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

const (
	CodeNormal     quic.ApplicationErrorCode = 0x4f475400
	CodeAuthFailed quic.ApplicationErrorCode = 0x4f475401
	CodeProtocol   quic.ApplicationErrorCode = 0x4f475408
)

var ErrSecurity = errors.New("outgate: unverified QUIC security profile")

// Options defaults to production and ten-second registration/write deadlines.
// Nonzero deadlines may only tighten these defaults. Development explicitly
// permits bearer credentials and a gateway without client certificates.
type Options struct {
	Development     bool
	RegisterTimeout time.Duration
	WriteTimeout    time.Duration
}

func (o Options) normalized() (Options, error) {
	if o.RegisterTimeout == 0 {
		o.RegisterTimeout = 10 * time.Second
	}
	if o.WriteTimeout == 0 {
		o.WriteTimeout = 10 * time.Second
	}
	if o.RegisterTimeout <= 0 || o.RegisterTimeout > 10*time.Second || o.WriteTimeout <= 0 || o.WriteTimeout > 10*time.Second {
		return o, v1.ErrProtocol
	}
	return o, nil
}

func (o Options) kind() v1.CredentialKind {
	if o.Development {
		return v1.DevelopmentBearer
	}
	return v1.ProductionGrant
}

// Rejection is a validated registration refusal. Error excludes peer detail.
// It is not permission to retry an application request.
type Rejection struct{ Nack v1.RegisterNack }

func (r *Rejection) Error() string { return "outgate: registration rejected" }

// Authorize runs after bounded parsing on a verified connection. The gateway
// must check identity/grant, expiry/revocation, permissions, conflicts and durable
// commit before returning an ack. Return *Rejection for a safe explicit nack;
// other errors become state_unavailable, without exposing their text. The
// callback must honor ctx. Credential bytes are cleared when the callback returns;
// copy them only if the authorization implementation requires ownership.
type Authorize func(ctx context.Context, peer tls.ConnectionState, credential []byte, register v1.Register) (v1.RegisterAck, error)

func prepare(ctx context.Context, conn *quic.Conn, options Options, service bool) (context.Context, context.CancelFunc, Options, error) {
	o, err := options.normalized()
	if err != nil || conn == nil {
		return nil, nil, o, v1.ErrProtocol
	}
	ctx, cancel := context.WithTimeout(ctx, o.RegisterTimeout)
	select {
	case <-conn.HandshakeComplete():
	case <-conn.Context().Done():
		cancel()
		return nil, nil, o, context.Cause(conn.Context())
	case <-ctx.Done():
		_ = conn.CloseWithError(CodeProtocol, "protocol_error")
		cancel()
		return nil, nil, o, ctx.Err()
	}
	s := conn.ConnectionState()
	if !s.TLS.HandshakeComplete || s.TLS.Version != tls.VersionTLS13 || s.TLS.NegotiatedProtocol != v1.QUICALPN || s.Used0RTT ||
		((service || !o.Development) && len(s.TLS.VerifiedChains) == 0) {
		cancel()
		_ = conn.CloseWithError(CodeAuthFailed, "auth_failed")
		return nil, nil, o, ErrSecurity
	}
	return ctx, cancel, o, nil
}

// Open sends the only registration on a new service-side connection. On success
// stream 0 remains owned by Carrier; the caller can start reverse HTTP/3 on the
// same connection. Do not open other service-initiated bidirectional streams.
// The registration context ends at return; Close or connection loss ends Carrier.
func Open(ctx context.Context, conn *quic.Conn, options Options, credential []byte, register v1.Register) (*Carrier, v1.RegisterAck, error) {
	ctx, cancel, o, err := prepare(ctx, conn, options, true)
	if err != nil {
		return nil, v1.RegisterAck{}, err
	}
	defer cancel()
	fail := func(err error) (*Carrier, v1.RegisterAck, error) {
		_ = conn.CloseWithError(CodeProtocol, "protocol_error")
		return nil, v1.RegisterAck{}, err
	}
	b, err := json.Marshal(register)
	if err != nil {
		return fail(v1.ErrProtocol)
	}
	// Snapshot mutable registration slices/maps before I/O and ack validation.
	register, err = v1.DecodeRegister(b)
	if err != nil {
		return fail(err)
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fail(err)
	}
	if stream.StreamID() != 0 {
		return fail(v1.ErrProtocol)
	}
	stop := interrupt(ctx, stream)
	defer stop()
	if err = v1.WriteBootstrap(stream, o.kind(), credential); err == nil {
		err = v1.WriteControl(stream, b, v1.MaxControlBytes)
	}
	if err != nil {
		return fail(operationError(ctx, err))
	}
	b, err = v1.ReadControl(stream, v1.MaxControlBytes)
	if err != nil {
		return fail(operationError(ctx, err))
	}
	var tag struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(b, &tag)
	if tag.Type == "register_nack" {
		nack, err := v1.DecodeRegisterNack(b)
		if err != nil {
			return fail(err)
		}
		_ = conn.CloseWithError(rejectionCode(nack.Code), nack.Code)
		return nil, v1.RegisterAck{}, &Rejection{Nack: nack}
	}
	ack, err := v1.DecodeRegisterAck(b)
	if err == nil {
		err = ack.ValidateForRegister(register, v1.RegisterAckValidationOptions{Development: o.Development})
	}
	if err != nil {
		return fail(err)
	}
	stop()
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	return newCarrier(conn, stream, true, o, ack), ack, nil
}

// Accept consumes stream 0 before the gateway attaches HTTP/3 machinery. The
// caller retains the connection and must exclude it from routing on any failure
// or Carrier.Done. Successful authorization/ack does not establish readiness.
func Accept(ctx context.Context, conn *quic.Conn, options Options, authorize Authorize) (*Carrier, error) {
	ctx, cancel, o, err := prepare(ctx, conn, options, false)
	if err != nil {
		return nil, err
	}
	defer cancel()
	fail := func(err error) (*Carrier, error) {
		_ = conn.CloseWithError(CodeProtocol, "protocol_error")
		return nil, err
	}
	if authorize == nil {
		return fail(v1.ErrProtocol)
	}
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return fail(err)
	}
	if stream.StreamID() != 0 {
		return fail(v1.ErrProtocol)
	}
	stop := interrupt(ctx, stream)
	defer stop()
	credential, err := v1.ReadBootstrap(stream, o.kind())
	if err != nil {
		return fail(operationError(ctx, err))
	}
	defer clear(credential)
	b, err := v1.ReadControl(stream, v1.MaxControlBytes)
	if err != nil {
		return fail(operationError(ctx, err))
	}
	// DecodeRegister intentionally accepts only the current major. Preserve the
	// negotiation refusal required by the protocol before using that codec.
	var version struct {
		Type  string `json:"type"`
		Major *int   `json:"protocol_version"`
	}
	if json.Unmarshal(b, &version) == nil && version.Type == "register" && version.Major != nil && *version.Major > 0 && *version.Major != v1.Major {
		return nil, refuse(ctx, conn, stream, v1.RegisterNack{Type: "register_nack", Code: "unsupported_protocol_version", Detail: "unsupported protocol version", Retryable: false})
	}
	register, err := v1.DecodeRegister(b)
	if err != nil {
		return fail(err)
	}
	// Preserve an independent snapshot even if the callback mutates its argument.
	validationRegister, _ := v1.DecodeRegister(b)
	ack, authErr := authorize(ctx, conn.ConnectionState().TLS, credential, register)
	clear(credential)
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	if authErr != nil {
		nack := v1.RegisterNack{Type: "register_nack", Code: "state_unavailable", Detail: "registration unavailable", Retryable: true}
		var rejected *Rejection
		if errors.As(authErr, &rejected) && rejected != nil {
			nack = rejected.Nack
		}
		return nil, refuse(ctx, conn, stream, nack)
	}
	if ack.ValidateForRegister(validationRegister, v1.RegisterAckValidationOptions{Development: o.Development}) != nil {
		return fail(v1.ErrProtocol)
	}
	b, err = json.Marshal(ack)
	if err == nil {
		err = v1.WriteControl(stream, b, v1.MaxControlBytes)
	}
	if err != nil {
		return fail(operationError(ctx, err))
	}
	stop()
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	return newCarrier(conn, stream, false, o, ack), nil
}

func refuse(ctx context.Context, conn *quic.Conn, stream *quic.Stream, nack v1.RegisterNack) error {
	if nack.Validate() != nil {
		_ = conn.CloseWithError(CodeProtocol, "protocol_error")
		return v1.ErrProtocol
	}
	b, err := json.Marshal(nack)
	if err == nil {
		err = v1.WriteControl(stream, b, v1.MaxControlBytes)
	}
	_ = conn.CloseWithError(rejectionCode(nack.Code), nack.Code)
	if err != nil {
		return operationError(ctx, err)
	}
	return &Rejection{Nack: nack}
}

func rejectionCode(code string) quic.ApplicationErrorCode {
	switch code {
	case "auth_failed":
		return CodeAuthFailed
	case "invalid_register":
		return 0x4f475402
	case "unsupported_protocol_version":
		return 0x4f475403
	case "path_forbidden":
		return 0x4f475404
	case "path_conflict":
		return 0x4f475405
	case "duplicate_instance":
		return 0x4f475406
	case "quota_exceeded":
		return 0x4f475407
	case "server_shutdown":
		return 0x4f475409
	case "state_unavailable":
		return 0x4f47540a
	case "credential_revoked":
		return 0x4f47540b
	default:
		return CodeProtocol
	}
}

// interrupt joins the cancellation callback before resetting the deadline. This
// prevents late context cancellation from poisoning a successfully handed-off stream.
func interrupt(ctx context.Context, stream *quic.Stream) func() {
	deadline, _ := ctx.Deadline()
	_ = stream.SetDeadline(deadline)
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = stream.SetDeadline(time.Now()); close(done) })
	var once sync.Once
	return func() {
		once.Do(func() {
			if !stop() {
				<-done
			}
			_ = stream.SetDeadline(time.Time{})
		})
	}
}

func operationError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// The QUIC deadline timer can fire before context's timer is scheduled.
	// Preserve errors.Is(DeadlineExceeded) regardless of that scheduling race.
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return err
}
