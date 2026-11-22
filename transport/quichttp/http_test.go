package quichttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/solodyagin/outgate-sdk/internal/quictest"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func await[T any](t *testing.T, c <-chan T) T {
	t.Helper()
	select {
	case v := <-c:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("operation stalled")
		var zero T
		return zero
	}
}

func session(t *testing.T, limit int, handler http.Handler) (*Gateway, *Service, *quiccontrol.Carrier, *quiccontrol.Carrier) {
	t.Helper()
	sc, gc := quictest.Pair(t, true, v1.QUICALPN)
	reg, ack := quictest.Fixtures(t, true)
	ack.Limits.MaxInflight = limit
	type accepted struct {
		c   *quiccontrol.Carrier
		err error
	}
	result := make(chan accepted, 1)
	go func() {
		c, err := quiccontrol.Accept(t.Context(), gc, quiccontrol.Options{}, func(_ context.Context, peer tls.ConnectionState, credential []byte, _ v1.Register) (v1.RegisterAck, error) {
			if len(peer.VerifiedChains) == 0 || string(credential) != "test-only-grant" {
				return v1.RegisterAck{}, errors.New("authorization failed")
			}
			return ack, nil
		})
		result <- accepted{c, err}
	}()
	s, _, err := quiccontrol.Open(t.Context(), sc, quiccontrol.Options{}, []byte("test-only-grant"), reg)
	must(t, err)
	g := await(t, result)
	must(t, g.err)
	service, err := NewService(s, handler)
	must(t, err)
	served := make(chan error, 1)
	go func() { served <- service.Serve() }()
	gateway, err := NewGateway(g.c)
	must(t, err)
	t.Cleanup(func() { _ = gateway.Close(); _ = service.Close(); _ = await(t, served) })
	return gateway, service, s, g.c
}

func request(t *testing.T, ctx context.Context, method, path string, body io.Reader) *http.Request {
	t.Helper()
	r, err := http.NewRequestWithContext(ctx, method, "https://public.example.test:8443"+path, body)
	must(t, err)
	return r
}
func drain(t *testing.T, r *http.Response) []byte {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	must(t, err)
	must(t, r.Body.Close())
	return b
}

func TestStreamingMetadataAndControlProgress(t *testing.T) {
	uploadDone := make(chan struct{})
	seen := make(chan error, 1)
	g, _, s, c := session(t, 4, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(requestIDHeader) != "" || r.Host != "public.example.test:8443" || r.URL.EscapedPath() != "/api/%D1%81%D1%82%D1%80%D0%B8%D0%BC" || r.URL.RawQuery != "tag=%2f&tag=one" ||
			!slices.Equal(r.Header.Values("X-Probe"), []string{"first", "second"}) || r.Header.Get("Accept-Encoding") != "" {
			seen <- errors.New("request metadata changed")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Add("X-Reply", "first")
		w.Header().Add("X-Reply", "second")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		_, err := io.Copy(io.Discard, r.Body)
		seen <- err
		close(uploadDone)
		_, _ = io.WriteString(w, "data: end\n\n")
	}))
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	r := request(t, t.Context(), "POST", "/api/%D1%81%D1%82%D1%80%D0%B8%D0%BC?tag=%2f&tag=one", reader)
	r.Header["x-TUNNEL-request-ID"] = []string{"untrusted", "also-untrusted"}
	r.Header["X-Probe"] = []string{"first", "second"}
	response, err := g.RoundTrip(r)
	must(t, err)
	first := make([]byte, len("data: first\n\n"))
	_, err = io.ReadFull(response.Body, first)
	must(t, err)
	select {
	case <-uploadDone:
		t.Fatal("upload finished before first SSE flush")
	default:
	}
	if !slices.Equal(response.Header.Values("X-Reply"), []string{"first", "second"}) {
		t.Fatal("response fields reordered")
	}
	if !slices.Equal(r.Header["x-TUNNEL-request-ID"], []string{"untrusted", "also-untrusted"}) {
		t.Fatal("original request mutated")
	}
	must(t, s.Send(t.Context(), v1.InstanceStatus{Type: "instance_status", Sequence: 1, Ready: true, Code: "ready", ObservedAt: time.Now().Unix()}))
	message, err := c.Receive(t.Context())
	must(t, err)
	if message.(v1.InstanceStatus).Sequence != 1 {
		t.Fatal("control progress failed")
	}
	_, err = writer.Write([]byte("streaming upload"))
	must(t, err)
	must(t, writer.Close())
	if string(drain(t, response)) != "data: end\n\n" {
		t.Fatal("response truncated")
	}
	must(t, await(t, seen))
}

func TestResponseEOFDoesNotReleaseOutstandingUpload(t *testing.T) {
	finished := make(chan error, 1)
	g, _, _, _ := session(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/half-close" {
			w.WriteHeader(204)
			return
		}
		w.WriteHeader(200)
		stream, err := w.(http3.HTTPStreamer).HTTPStream()
		if err == nil {
			err = stream.Close()
		} // FIN only the response direction
		if err == nil {
			_, err = io.Copy(io.Discard, r.Body)
		}
		finished <- err
	}))
	reader, writer := io.Pipe()
	defer writer.Close()
	completed := make(chan struct{}, 2)
	response, err := g.RoundTripWithCompletion(request(t, t.Context(), "POST", "/half-close", reader), func() { completed <- struct{}{} })
	must(t, err)
	_, err = io.ReadAll(response.Body)
	must(t, err)
	select {
	case <-completed:
		t.Fatal("outer completion forgot outstanding upload")
	default:
	}
	if _, err := g.RoundTrip(request(t, t.Context(), "GET", "/too-early", nil)); err != ErrBusy {
		t.Fatal("EOF released an unfinished upload", err)
	}
	_, err = writer.Write([]byte("upload after response FIN"))
	must(t, err)
	must(t, writer.Close())
	must(t, await(t, finished))
	must(t, response.Body.Close())
	await(t, completed)
	select {
	case <-completed:
		t.Fatal("completion called twice")
	default:
	}
}

func TestPreIOFailureCompletesExactlyOnce(t *testing.T) {
	g, _, _, _ := session(t, 1, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unexpected dispatch") }))
	count := 0
	if _, err := g.RoundTripWithCompletion(nil, func() { count++ }); err != ErrRequest || count != 1 {
		t.Fatal("pre-I/O completion lost", err, count)
	}
}

func TestQuiescentFenceDropsLateCanceledRequests(t *testing.T) {
	for _, invalid := range []string{"above", "reuse"} {
		t.Run(invalid, func(t *testing.T) {
			var calls atomic.Int32
			g, s, c, _ := session(t, 2, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(204) }))
			// Logical IDs allocated by G before cancellation need not all reach S.
			g.idMu.Lock()
			g.next = 7
			g.idMu.Unlock()
			if g.Pause() != 7 || g.Pause() != 7 {
				t.Fatal("watermark changed after pause")
			}
			if _, err := g.RoundTrip(request(t, t.Context(), "GET", "/new", nil)); err != ErrQuiescing {
				t.Fatal("paused gateway admitted request", err)
			}
			must(t, s.Quiesce(t.Context(), 7))
			late := request(t, t.Context(), "GET", "/late-canceled", nil)
			late.Header.Set(requestIDHeader, "5")
			response, err := g.client.RoundTrip(late)
			if err == nil {
				response.Body.Close()
				t.Fatal("late canceled request dispatched")
			}
			var streamErr *quic.StreamError
			if !errors.As(err, &streamErr) || streamErr.ErrorCode != quic.StreamErrorCode(http3.ErrCodeRequestCanceled) {
				t.Fatal("wrong late stream reset", err)
			}
			if calls.Load() != 0 || c.Err() != nil {
				t.Fatal("late canceled stream damaged session")
			}
			bad := request(t, t.Context(), "GET", "/invalid-fence", nil)
			id := "8"
			if invalid == "reuse" {
				id = "5"
			}
			bad.Header.Set(requestIDHeader, id)
			if response, err := g.client.RoundTrip(bad); err == nil {
				response.Body.Close()
				t.Fatal("invalid ID escaped fence")
			}
			await(t, c.Done())
		})
	}
}

func TestQuiesceWaitsForActualHandlerCleanup(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	g, s, _, _ := session(t, 2, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(entered)
		<-release
	}))
	response, err := g.RoundTrip(request(t, t.Context(), "GET", "/active", nil))
	must(t, err)
	await(t, entered)
	fence := g.Pause()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := s.Quiesce(ctx, fence); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("quiesce skipped active handler", err)
	}
	once.Do(func() { close(release) })
	drain(t, response)
	must(t, s.Quiesce(t.Context(), fence))
	if err := s.Quiesce(t.Context(), fence+1); err != v1.ErrProtocol {
		t.Fatal("fence increased")
	}
}

func TestServiceEnforcesAdmissionAgainstPeer(t *testing.T) {
	var calls atomic.Int32
	g, _, _, _ := session(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	first := request(t, ctx, "GET", "/first", nil)
	first.Header.Set(requestIDHeader, "1")
	response, err := g.client.RoundTrip(first)
	must(t, err)
	defer response.Body.Close()
	second := request(t, t.Context(), "GET", "/second", nil)
	second.Header.Set(requestIDHeader, "2")
	busy, err := g.client.RoundTrip(second)
	must(t, err)
	drain(t, busy)
	if busy.StatusCode != 503 || calls.Load() != 1 {
		t.Fatal("service admission bypassed")
	}
	cancel()
}

func TestCancellationStopsUploadAndHandlerOnly(t *testing.T) {
	started := make(chan struct{})
	ended := make(chan error, 1)
	g, _, _, _ := session(t, 2, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cancel" {
			close(started)
			<-r.Context().Done()
			ended <- r.Context().Err()
			return
		}
		_, _ = io.WriteString(w, "healthy")
	}))
	reader, writer := io.Pipe()
	defer writer.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := g.RoundTrip(request(t, ctx, "POST", "/cancel", reader)); result <- err }()
	await(t, started)
	cancel()
	if !errors.Is(await(t, result), context.Canceled) {
		t.Fatal("cancellation cause lost")
	}
	if !errors.Is(await(t, ended), context.Canceled) {
		t.Fatal("handler survived cancellation")
	}
	write := make(chan error, 1)
	go func() { _, err := writer.Write([]byte("blocked")); write <- err }()
	if await(t, write) == nil {
		t.Fatal("upload remained open")
	}
	response, err := g.RoundTrip(request(t, t.Context(), "GET", "/healthy", nil))
	must(t, err)
	if string(drain(t, response)) != "healthy" {
		t.Fatal("neighbor request failed")
	}
}

func TestCapacityHeldThroughUploadAndReleasedOnClose(t *testing.T) {
	started := make(chan struct{})
	g, _, _, _ := session(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/early" {
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			close(started)
			_, _ = io.Copy(io.Discard, r.Body)
			return
		}
		w.WriteHeader(204)
	}))
	reader, writer := io.Pipe()
	defer writer.Close()
	response, err := g.RoundTrip(request(t, t.Context(), "POST", "/early", reader))
	must(t, err)
	await(t, started)
	_, err = g.RoundTrip(request(t, t.Context(), "GET", "/second", nil))
	if !errors.Is(err, ErrBusy) {
		t.Fatal("inflight limit ignored", err)
	}
	must(t, response.Body.Close())
	// Closing a response cancels its outstanding upload and releases admission.
	deadline := time.Now().Add(5 * time.Second)
	for {
		r, err := g.RoundTrip(request(t, t.Context(), "GET", "/next", nil))
		if err == nil {
			drain(t, r)
			break
		}
		if !errors.Is(err, ErrBusy) || time.Now().After(deadline) {
			t.Fatal("admission not released", err)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestResetNeverRetriesOrReplaysBody(t *testing.T) {
	for _, method := range []string{"GET", "HEAD", "OPTIONS", "POST"} {
		t.Run(method, func(t *testing.T) {
			var invoked, replayed atomic.Int32
			g, _, _, _ := session(t, 2, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/reset" {
					invoked.Add(1)
					panic(http.ErrAbortHandler)
				}
				w.WriteHeader(204)
			}))
			r := request(t, t.Context(), method, "/reset", bytes.NewBufferString("body"))
			r.GetBody = func() (io.ReadCloser, error) {
				replayed.Add(1)
				return io.NopCloser(bytes.NewBufferString("body")), nil
			}
			r.Header.Set("Idempotency-Key", "does-not-authorize-retry")
			if response, err := g.RoundTrip(r); err == nil {
				response.Body.Close()
				t.Fatal("reset succeeded")
			}
			if invoked.Load() != 1 || replayed.Load() != 0 {
				t.Fatal("request retried", invoked.Load(), replayed.Load())
			}
			response, err := g.RoundTrip(request(t, t.Context(), "GET", "/healthy", nil))
			must(t, err)
			drain(t, response)
		})
	}
}

func TestMalformedAndReusedIDsNeverReachHandler(t *testing.T) {
	for _, id := range []string{"", "0", "01", "18446744073709551616", "1, 2", "duplicate"} {
		t.Run(id, func(t *testing.T) {
			var calls atomic.Int32
			g, _, _, _ := session(t, 2, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(204) }))
			if id == "duplicate" {
				r := request(t, t.Context(), "GET", "/first", nil)
				r.Header.Set(requestIDHeader, "7")
				response, err := g.client.RoundTrip(r)
				must(t, err)
				drain(t, response)
			}
			r := request(t, t.Context(), "GET", "/invalid", nil)
			if id != "" {
				if id == "duplicate" {
					id = "7"
				}
				r.Header.Set(requestIDHeader, id)
			}
			if response, err := g.client.RoundTrip(r); err == nil {
				response.Body.Close()
				t.Fatal("invalid ID accepted")
			}
			expected := int32(0)
			if id == "7" {
				expected = 1
			}
			if calls.Load() != expected {
				t.Fatal("invalid ID dispatched")
			}
		})
	}
}

func TestConcurrentRequestsAndIDRanges(t *testing.T) {
	var calls atomic.Int32
	g, _, _, _ := session(t, 40, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = io.WriteString(w, r.URL.RawQuery) }))
	result := make(chan error, 32)
	for i := 0; i < 32; i++ {
		go func(i int) {
			r := request(t, t.Context(), "GET", "/parallel?id="+strconv.Itoa(i), nil)
			response, err := g.RoundTrip(r)
			if err == nil {
				body, e := io.ReadAll(response.Body)
				_ = response.Body.Close()
				err = e
				if string(body) != r.URL.RawQuery {
					err = errors.New("response mismatch")
				}
			}
			result <- err
		}(i)
	}
	for range 32 {
		must(t, await(t, result))
	}
	if calls.Load() != 32 {
		t.Fatal("lost dispatch")
	}
	ids := requestIDs{spans: make([]idSpan, 0, 2)}
	for _, id := range []uint64{3, 1, 2, 5, 4, 6, math.MaxUint64} {
		must(t, ids.admit(id))
	}
	if ids.admit(2) != ErrRequest || ids.admit(math.MaxUint64) != ErrRequest || ids.admit(10) != ErrBusy {
		t.Fatal("ID uniqueness/capacity ignored")
	}
}

func TestInvalidMetadataAndRedirectDoNotDispatchTwice(t *testing.T) {
	var calls atomic.Int32
	g, _, s, c := session(t, 2, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Location", "https://external.example.test/")
		w.WriteHeader(307)
	}))
	if _, err := NewGateway(c); err == nil {
		t.Fatal("HTTP/3 attached twice")
	}
	if _, err := NewGateway(s); err == nil {
		t.Fatal("HTTP/3 role mismatch accepted")
	}
	for _, path := range []string{"/bad%2fpath", "/a/../b"} {
		if response, err := g.RoundTrip(request(t, t.Context(), "GET", path, nil)); err == nil {
			response.Body.Close()
			t.Fatal("invalid URI sent")
		}
	}
	r := request(t, t.Context(), "GET", "/", nil)
	r.Header.Set("Connection", "upgrade")
	if _, err := g.RoundTrip(r); !errors.Is(err, ErrRequest) {
		t.Fatal("hop header accepted")
	}
	response, err := g.RoundTrip(request(t, t.Context(), "GET", "/redirect", nil))
	must(t, err)
	drain(t, response)
	if response.StatusCode != 307 || calls.Load() != 1 {
		t.Fatal("redirect followed")
	}
}
