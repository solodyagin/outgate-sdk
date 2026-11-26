// Package client owns a single Run and sequential QUIC session lifetimes.
package client

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/sessionstate"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
	"github.com/solodyagin/outgate-sdk/transport/quicsession"
)

type Code string

const (
	AlreadyStarted        Code = "already_started"
	ClientClosed          Code = "client_closed"
	ClientNotReady        Code = "client_not_ready"
	InvalidConfig         Code = "invalid_config"
	SecurityFailure       Code = "security_failure"
	ProtocolFailure       Code = "protocol_error"
	TransportFailure      Code = "transport_failure"
	ShutdownTimeout       Code = "shutdown_timeout"
	CredentialUnavailable Code = "credential_unavailable"
	CallbackFailed        Code = "callback_failed"
	InvalidRequest        Code = "invalid_request"
	CallQuotaExceeded     Code = "quota_exceeded"
	DiscoveryUnavailable  Code = "discovery_unavailable"
	MountNotFound         Code = "mount_not_found"
)

// Error exposes a safe code. Unwrap is for internal diagnostics only; an
// underlying connector/remote error may contain text unsuitable for public logs.
type Error struct {
	Code  Code
	cause error
}

func (e *Error) Error() string        { return "outgate: " + string(e.Code) }
func (e *Error) Unwrap() error        { return e.cause }
func (e *Error) Is(target error) bool { t, ok := target.(*Error); return ok && e.Code == t.Code }

var (
	ErrAlreadyStarted = &Error{Code: AlreadyStarted}
	ErrClientClosed   = &Error{Code: ClientClosed}
	ErrClientNotReady = &Error{Code: ClientNotReady}
)

// Connect acquires current credentials, dials and registers a fresh carrier.
// It owns cleanup on error; a nonnil returned carrier transfers to Client even
// alongside an error. It must honor ctx; only one invocation may be outstanding.
// Options assert externally verified local security readiness, default false.
type Connect func(context.Context) (*quiccontrol.Carrier, quicsession.Options, error)

type Config struct {
	Connect                Connect
	QUIC                   *QUICConfig
	ServiceHTTP            *ServiceHTTPConfig
	Handler                http.Handler
	Development            bool
	ConnectTimeout         time.Duration
	BackoffMin, BackoffMax time.Duration
}

type ClientStatus struct {
	State                      sessionstate.Phase
	Connected                  bool
	ConnectedSince, ReadySince time.Time
	Transport                  string
	LastErrorCode              Code
}

// Client never overlaps old handlers/callbacks with a new Connect invocation.
// New performs validation only; Run starts I/O exactly once.
type Client struct {
	mu                         sync.Mutex
	config                     Config
	status                     ClientStatus
	started, closing, finished bool
	revoked                    bool
	deadline                   time.Time
	err                        error
	service                    *quicsession.Service
	renewal                    *quicRenewal
	http                       *serviceHTTPState
	connectCancel              context.CancelFunc
	wake, changed, done        chan struct{}
}

func New(config Config) (*Client, error) {
	outgoing, err := newServiceHTTP(config.ServiceHTTP, config.QUIC)
	if err != nil {
		return nil, err
	}
	config.ServiceHTTP = nil
	var renewal *quicRenewal
	if config.QUIC != nil {
		if config.Connect != nil || config.QUIC.Development != config.Development {
			return nil, &Error{Code: InvalidConfig}
		}
		renewal = &quicRenewal{}
		connect, err := newQUICConnector(*config.QUIC, renewal)
		if err != nil {
			return nil, err
		}
		config.Connect = connect
		config.QUIC = nil
	}
	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = 10 * time.Second
	}
	if config.BackoffMin == 0 {
		config.BackoffMin = 250 * time.Millisecond
	}
	if config.BackoffMax == 0 {
		config.BackoffMax = 30 * time.Second
	}
	if config.Connect == nil || config.Handler == nil || config.ConnectTimeout <= 0 || config.ConnectTimeout > 30*time.Second || config.BackoffMin < time.Millisecond || config.BackoffMax < config.BackoffMin || config.BackoffMax > 30*time.Second {
		return nil, &Error{Code: InvalidConfig}
	}
	return &Client{config: config, renewal: renewal, http: outgoing, status: ClientStatus{State: sessionstate.Created}, wake: make(chan struct{}, 1), changed: make(chan struct{}), done: make(chan struct{})}, nil
}

func (c *Client) Done() <-chan struct{} { return c.done }
func (c *Client) notifyLocked() {
	close(c.changed)
	c.changed = make(chan struct{})
	select {
	case c.wake <- struct{}{}:
	default:
	}
}
func (c *Client) statusLocked() ClientStatus {
	if c.service != nil && !c.finished {
		snapshot := c.service.Snapshot()
		phase := snapshot.Phase
		c.status.Connected = snapshot.TransportActive
		if phase == sessionstate.Connecting || phase == sessionstate.Closed {
			phase = sessionstate.Draining
		}
		if c.closing {
			phase = sessionstate.Draining
		}
		if phase == sessionstate.Ready && c.status.State != sessionstate.Ready {
			c.status.ReadySince = time.Now()
		}
		if phase != sessionstate.Ready {
			c.status.ReadySince = time.Time{}
		}
		if c.status.State != phase {
			c.status.State = phase
			c.notifyLocked()
		}
	}
	return c.status
}
func (c *Client) Status() ClientStatus { c.mu.Lock(); defer c.mu.Unlock(); return c.statusLocked() }

func (c *Client) WaitReady(ctx context.Context) error {
	for {
		c.mu.Lock()
		status := c.statusLocked()
		changed := c.changed
		err := c.err
		c.mu.Unlock()
		if status.State == sessionstate.Ready {
			return nil
		}
		if status.State == sessionstate.Closed {
			if err != nil {
				return err
			}
			return ErrClientClosed
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

// SetSecurity propagates an externally verified gate/deadline to the current
// session. No transport is created or credentials verified by this method.
func (c *Client) SetSecurity(ready bool, deadline time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.finished || c.closing {
		return ErrClientClosed
	}
	if c.service == nil {
		return ErrClientNotReady
	}
	err := c.service.SetSecurity(ready, deadline)
	c.http.shorten(deadline)
	c.statusLocked()
	c.notifyLocked()
	return err
}

// Revoke is final and suppresses reconnect, including during Connect/cleanup.
func (c *Client) Revoke() {
	c.mu.Lock()
	if c.finished {
		c.mu.Unlock()
		return
	}
	c.revoked, c.closing = true, true
	c.http.stop()
	c.deadline = time.Now()
	c.status.State, c.status.LastErrorCode = sessionstate.Draining, SecurityFailure
	if c.connectCancel != nil {
		c.connectCancel()
	}
	service := c.service
	c.notifyLocked()
	if !c.started {
		c.finishLocked(nil)
	}
	c.mu.Unlock()
	if service != nil {
		service.Revoke()
	}
}

// Close coalesces final shutdown, with the earliest caller deadline (30s when
// absent). An expired wait forces cancellation; Done still waits actual cleanup.
func (c *Client) Close(ctx context.Context) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	c.requestClose(deadline)
	select {
	case <-c.done:
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.err
	default:
	}
	select {
	case <-c.done:
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.err
	case <-ctx.Done():
		c.requestClose(time.Now())
		return ctx.Err()
	}
}

func (c *Client) requestClose(deadline time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.finished {
		return
	}
	c.closing = true
	if c.deadline.IsZero() || deadline.Before(c.deadline) {
		c.deadline = deadline
	}
	if c.connectCancel != nil {
		c.connectCancel()
	}
	c.http.shorten(c.deadline)
	c.status.State = sessionstate.Draining
	c.notifyLocked()
	if !c.started {
		c.finishLocked(nil)
	}
}

func (c *Client) finishLocked(err error) {
	if c.finished {
		return
	}
	if c.revoked {
		err = &Error{Code: SecurityFailure, cause: sessionstate.ErrSecurity}
	} else if err == nil && c.started && c.closing && !time.Now().Before(c.deadline) {
		err = &Error{Code: ShutdownTimeout, cause: context.DeadlineExceeded}
	}
	c.finished = true
	c.err = err
	c.service = nil
	c.status.State = sessionstate.Closed
	c.status.Connected = false
	c.status.ReadySince = time.Time{}
	if e, ok := err.(*Error); ok {
		c.status.LastErrorCode = e.Code
	}
	c.notifyLocked()
	if c.http == nil {
		close(c.done)
	} else {
		c.http.stop()
		go func() { c.http.wait(); close(c.done) }()
	}
}

// Run owns all reconnect attempts. Canceling ctx requests graceful final drain;
// active handler contexts remain independent until their own/drain deadlines.
func (c *Client) Run(ctx context.Context) (result error) {
	c.mu.Lock()
	if c.closing || c.finished {
		c.mu.Unlock()
		return ErrClientClosed
	}
	if c.started {
		c.mu.Unlock()
		return ErrAlreadyStarted
	}
	c.started = true
	c.status.State = sessionstate.Connecting
	c.notifyLocked()
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		finished := c.finished
		if finished {
			result = c.err
		}
		c.mu.Unlock()
		if finished {
			<-c.done
		}
	}()
	stop := context.AfterFunc(ctx, func() { c.requestClose(time.Now().Add(30 * time.Second)) })
	defer stop()
	if ctx.Err() != nil {
		c.requestClose(time.Now().Add(30 * time.Second))
	}
	if c.renewal != nil {
		defer c.renewal.clear()
	}
	backoff := c.config.BackoffMin
	var registration, previousID string
	var previousGeneration uint64
	var generationPresent bool
	for {
		c.mu.Lock()
		if c.closing {
			c.finishLocked(nil)
			c.mu.Unlock()
			return nil
		}
		attempt, cancel := context.WithTimeout(context.Background(), c.config.ConnectTimeout)
		c.connectCancel = cancel
		c.status.State = sessionstate.Connecting
		c.notifyLocked()
		c.mu.Unlock()
		carrier, options, err := c.connect(attempt)
		attemptErr := attempt.Err()
		cancel()
		c.mu.Lock()
		c.connectCancel = nil
		closing := c.closing
		c.mu.Unlock()
		if closing || attemptErr != nil || err != nil {
			if carrier != nil {
				_ = carrier.Close()
			}
			if closing {
				c.mu.Lock()
				c.finishLocked(nil)
				c.mu.Unlock()
				return nil
			}
			if attemptErr != nil {
				err = attemptErr
			}
		} else if carrier == nil {
			err = v1.ErrProtocol
		} else {
			r, ack, development := carrier.Registration()
			var generation uint64
			present := r.CredentialGeneration != nil
			if present {
				generation = uint64(*r.CredentialGeneration)
			}
			r.CredentialGeneration = nil // generation rotates; registration identity does not
			encoded, _ := json.Marshal(r)
			if development != c.config.Development || registration != "" && (registration != string(encoded) || generationPresent != present || generation < previousGeneration) {
				_ = carrier.Revoke()
				err = sessionstate.ErrSecurity
			} else if previousID == ack.SessionID {
				_ = carrier.Abort()
				err = v1.ErrProtocol
			} else {
				var service *quicsession.Service
				service, err = quicsession.NewService(carrier, c.config.Handler, options)
				if err != nil {
					_ = carrier.Abort()
				} else {
					registration, previousID = string(encoded), ack.SessionID
					previousGeneration, generationPresent = generation, present
					c.mu.Lock()
					c.service = service
					c.status.Connected = true
					c.status.ConnectedSince = time.Now()
					c.status.Transport = "quic"
					c.status.LastErrorCode = ""
					c.statusLocked()
					c.notifyLocked()
					c.mu.Unlock()
					var wasReady, rotated bool
					err, wasReady, rotated = c.serve(service)
					if wasReady {
						backoff = c.config.BackoffMin
					}
					c.mu.Lock()
					closing = c.closing
					c.service = nil
					c.status.Connected = false
					c.status.ReadySince = time.Time{}
					c.mu.Unlock()
					if closing || err == nil && !rotated && !service.ReconnectRequested() {
						if err != nil {
							err, _ = classify(err)
						}
						c.mu.Lock()
						c.finishLocked(err)
						c.mu.Unlock()
						return err
					}
					if rotated && (err == nil || errors.Is(err, sessionstate.ErrTimeout) || errors.Is(err, context.DeadlineExceeded)) && time.Now().Before(c.renewal.expiry) {
						// A bounded drain may force the old transport closed. Actual cleanup
						// has completed; only security/protocol failures suppress the rotation.
						continue
					}
					if err == nil {
						err = &quic.ApplicationError{Remote: true, ErrorCode: quiccontrol.CodeNormal}
					}
				}
			}
		}
		safe, retry := classify(err)
		c.mu.Lock()
		c.status.LastErrorCode = safe.Code
		c.status.State = sessionstate.Connecting
		c.notifyLocked()
		if !retry {
			c.finishLocked(safe)
			c.mu.Unlock()
			return safe
		}
		c.mu.Unlock()
		proceed, pauseErr := c.pause(backoff)
		if !proceed {
			c.mu.Lock()
			c.finishLocked(pauseErr)
			c.mu.Unlock()
			return pauseErr
		}
		backoff = min(c.config.BackoffMax, backoff*2)
	}
}

func (c *Client) connect(ctx context.Context) (carrier *quiccontrol.Carrier, options quicsession.Options, err error) {
	defer func() {
		if recover() != nil {
			err = &Error{Code: TransportFailure}
		}
	}()
	return c.config.Connect(ctx)
}

func (c *Client) serve(service *quicsession.Service) (error, bool, bool) {
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	var drainCancel context.CancelFunc
	var deadlineTimer *time.Timer
	var deadlineC <-chan time.Time
	var draining bool
	var drainDone chan struct{}
	var armedDeadline time.Time
	securityApplied := false
	wasReady := false
	rotated := false
	var rotationDeadline time.Time
	var refreshDone chan error
	var refreshCancel context.CancelFunc
	nextRefresh := time.Time{}
	var refreshTimer *time.Timer
	var refreshC <-chan time.Time
	retry := time.Second
	if c.renewal != nil {
		nextRefresh = c.renewal.refreshAt
		if !nextRefresh.IsZero() {
			refreshTimer = time.NewTimer(max(time.Nanosecond, time.Until(nextRefresh)))
			refreshC = refreshTimer.C
			defer refreshTimer.Stop()
		}
	}
	// Join actual callback completion before reconnect, while expiry/revoke remains independent.
	defer func() {
		if refreshCancel != nil {
			refreshCancel()
			<-refreshDone
		}
	}()
	defer func() {
		if deadlineTimer != nil {
			deadlineTimer.Stop()
		}
	}()
	for {
		c.mu.Lock()
		status := c.statusLocked()
		wasReady = wasReady || status.State == sessionstate.Ready
		closing, deadline, revoked := c.closing, c.deadline, c.revoked
		c.mu.Unlock()
		if revoked && !securityApplied {
			service.Revoke()
			securityApplied = true
		}
		if closing || revoked {
			if refreshCancel != nil {
				refreshCancel()
			}
		}
		if !closing && !revoked && !rotated && refreshDone == nil && !nextRefresh.IsZero() && !time.Now().Before(nextRefresh) && status.State != sessionstate.Draining && status.Connected {
			currentDeadline := earlierDeadline(c.renewal.expiry, service.Snapshot().Deadline)
			refreshCtx, cancel := context.WithDeadline(context.Background(), currentDeadline)
			refreshCancel = cancel
			refreshDone = make(chan error, 1)
			refreshTimer.Stop()
			refreshC = nil
			go func(done chan error) { done <- c.renewal.prepare(refreshCtx) }(refreshDone)
		}
		if rotated {
			if !closing || rotationDeadline.Before(deadline) {
				deadline = rotationDeadline
			}
		}
		if (closing || rotated) && !revoked {
			if !draining {
				draining = true
				var drainCtx context.Context
				drainCtx, drainCancel = context.WithDeadline(context.Background(), deadline)
				defer drainCancel()
				drainDone = make(chan struct{})
				go func() { defer close(drainDone); _ = service.Drain(drainCtx) }()
			}
			if !time.Now().Before(deadline) {
				drainCancel()
				if deadlineTimer != nil {
					deadlineTimer.Stop()
				}
				deadlineC = nil
			} else if deadlineTimer == nil {
				deadlineTimer = time.NewTimer(max(time.Nanosecond, time.Until(deadline)))
				deadlineC = deadlineTimer.C
				armedDeadline = deadline
			} else if deadline != armedDeadline {
				deadlineTimer.Reset(max(time.Nanosecond, time.Until(deadline)))
				deadlineC = deadlineTimer.C
				armedDeadline = deadline
			}
		}
		select {
		case <-service.Done():
			if drainDone != nil {
				<-drainDone
			}
			// Source completion is part of cleanup too. Observe final intent and
			// the Close deadline only after an outstanding callback has returned.
			if refreshCancel != nil {
				refreshCancel()
				<-refreshDone
				refreshCancel, refreshDone = nil, nil
			}
			c.mu.Lock()
			finalClose := c.closing
			c.mu.Unlock()
			if finalClose {
				c.http.wait()
			}
			err := service.Err()
			rotated = rotated && !service.PeerShutdownRequested()
			c.mu.Lock()
			closing, deadline = c.closing, c.deadline
			revoked = c.revoked
			c.mu.Unlock()
			if revoked {
				return &Error{Code: SecurityFailure, cause: sessionstate.ErrSecurity}, wasReady, false
			}
			if closing && !time.Now().Before(deadline) {
				return &Error{Code: ShutdownTimeout, cause: context.DeadlineExceeded}, wasReady, false
			}
			if err == nil {
				return nil, wasReady, rotated
			}
			return err, wasReady, rotated
		case refreshErr := <-refreshDone:
			refreshCancel()
			refreshCancel, refreshDone = nil, nil
			c.mu.Lock()
			closing, revoked = c.closing, c.revoked
			c.mu.Unlock()
			snapshot := service.Snapshot()
			if refreshErr == nil && !closing && !revoked && snapshot.TransportActive && snapshot.Phase != sessionstate.Draining {
				rotated = true
				rotationDeadline = earlierDeadline(time.Now().Add(30*time.Second), snapshot.Deadline)
			} else {
				nextRefresh = time.Now().Add(renewalRetry(retry))
				refreshTimer.Reset(max(time.Nanosecond, time.Until(nextRefresh)))
				refreshC = refreshTimer.C
				retry = min(30*time.Second, retry*2)
			}
		case <-refreshC:
		case <-tick.C:
		case <-c.wake:
		case <-deadlineC:
		}
	}
}

func (c *Client) pause(backoff time.Duration) (bool, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return false, &Error{Code: TransportFailure, cause: err}
	}
	// Equal jitter stays in [backoff/2, backoff], including the configured cap.
	delay := backoff/2 + time.Duration(binary.BigEndian.Uint64(b[:])%uint64(backoff/2+1))
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		c.mu.Lock()
		closing := c.closing
		c.mu.Unlock()
		if closing {
			return false, nil
		}
		select {
		case <-timer.C:
			return true, nil
		case <-c.wake:
		}
	}
}

func classify(err error) (*Error, bool) {
	if err == nil {
		return &Error{Code: TransportFailure}, false
	}
	var safe *Error
	if errors.As(err, &safe) {
		return safe, false
	}
	if errors.Is(err, sessionstate.ErrSecurity) || errors.Is(err, quiccontrol.ErrSecurity) {
		return &Error{Code: SecurityFailure, cause: err}, false
	}
	var app *quic.ApplicationError
	if errors.As(err, &app) {
		if app.ErrorCode == quiccontrol.CodeCredentialRevoked || app.ErrorCode == quiccontrol.CodeAuthFailed {
			return &Error{Code: SecurityFailure, cause: err}, false
		}
		if app.ErrorCode == quiccontrol.CodeProtocol {
			return &Error{Code: ProtocolFailure, cause: err}, false
		}
		return &Error{Code: TransportFailure, cause: err}, app.Remote && (app.ErrorCode == quiccontrol.CodeNormal || app.ErrorCode == 0x4f475409)
	}
	var rejection *quiccontrol.Rejection
	if errors.As(err, &rejection) {
		return &Error{Code: TransportFailure, cause: err}, rejection.Nack.Retryable && (rejection.Nack.Code == "duplicate_instance" || rejection.Nack.Code == "state_unavailable" || rejection.Nack.Code == "server_shutdown" || rejection.Nack.Code == "quota_exceeded")
	}
	if errors.Is(err, v1.ErrProtocol) {
		return &Error{Code: ProtocolFailure, cause: err}, false
	}
	var credentials *credentialError
	if errors.As(err, &credentials) {
		code := credentials.code
		if code == "" {
			code = CredentialUnavailable
		}
		return &Error{Code: code, cause: credentials.cause}, true
	}
	var network net.Error
	return &Error{Code: TransportFailure, cause: err}, errors.As(err, &network) || errors.Is(err, context.DeadlineExceeded)
}
