package replay

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/solodyagin/outgate-sdk/httpsig"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

func testConfig(t *testing.T) SQLiteConfig {
	return SQLiteConfig{
		Path: filepath.Join(t.TempDir(), "recipient #1.db"), Namespace: "outgate:recipient",
		Epoch: [32]byte{1, 2, 3}, Capacity: 150, CallerCapacity: 2, AdmittedRPS: 1,
	}
}

func require(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func newStore(t *testing.T, config SQLiteConfig, now *time.Time) *SQLite {
	t.Helper()
	store, err := openSQLite(t.Context(), config, func() time.Time { return *now })
	require(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func reservation(config SQLiteConfig, caller string, id uint64, created time.Time) httpsig.Reservation {
	var raw [16]byte
	binary.BigEndian.PutUint64(raw[:], id)
	return httpsig.Reservation{
		Key: httpsig.ReplayKey{Leg: httpsig.Call, Namespace: config.Namespace, Caller: caller,
			KeyID: "key / 2026", Nonce: base64.RawURLEncoding.EncodeToString(raw[:])},
		RetainUntil: created.Add(90 * time.Second),
	}
}

func TestSQLiteReplayPersistsThroughStartupBarrier(t *testing.T) {
	config := testConfig(t)
	require(t, InitializeSQLite(t.Context(), config))
	start := time.Now().Truncate(time.Second)
	now := start
	first := newStore(t, config, &now)
	if err := first.Ready(t.Context()); !errors.Is(err, httpsig.ErrReplayUnavailable) {
		t.Fatalf("startup readiness: %v", err)
	}
	now = start.Add(RecoveryBarrier)

	// The latest valid created time is still at the inclusive replay boundary
	// when another process has waited out its full startup barrier.
	created := now.Add(30 * time.Second)
	profile, err := httpsig.New(httpsig.Config{Leg: httpsig.Call})
	require(t, err)
	req := httpsig.Request{Method: "GET", Scheme: "https", Authority: "service.example", RawURI: "/api", Headers: []v1.Header{
		{"x-outgate-caller-service", "service-a"}, {"x-outgate-target-service", "service-b"},
		{"x-outgate-deployment-grant-id", "grant-1"}, {"x-outgate-hop-limit", "8"}, {"x-outgate-context-headers", "[]"},
	}}
	key := bytes.Repeat([]byte("s"), 32)
	headers, err := profile.Sign(req, "key / 2026", key, created)
	require(t, err)
	req.Headers = append(req.Headers, v1.Header{"signature", headers.Signature}, v1.Header{"signature-input", headers.SignatureInput})
	proof, err := profile.Verify(req, "key / 2026", key, now)
	require(t, err)
	require(t, proof.Reserve(t.Context(), first, config.Namespace, now))
	require(t, first.Close())

	reopened := newStore(t, config, &now)
	if err := proof.Reserve(t.Context(), reopened, config.Namespace, now); !errors.Is(err, httpsig.ErrReplayUnavailable) {
		t.Fatalf("reservation during restart: %v", err)
	}
	now = now.Add(RecoveryBarrier)
	require(t, reopened.Ready(t.Context()))
	n, err := reopened.Prune(t.Context())
	require(t, err)
	if n != 0 {
		t.Fatalf("pruned %d live reservations at inclusive boundary", n)
	}
	proof, err = profile.Verify(req, "key / 2026", key, now)
	require(t, err)
	if err := proof.Reserve(t.Context(), reopened, config.Namespace, now); !errors.Is(err, httpsig.ErrReplay) {
		t.Fatalf("nonce lost after restart: %v", err)
	}
	now = now.Add(time.Second)
	n, err = reopened.Prune(t.Context())
	require(t, err)
	if n != 1 {
		t.Fatalf("pruned %d expired reservations, want 1", n)
	}
	now = now.Add(-time.Second)
	if err := reopened.Ready(t.Context()); !errors.Is(err, httpsig.ErrReplayUnavailable) {
		t.Fatalf("clock rollback accepted: %v", err)
	}
}

func TestSQLiteConcurrentNonceAndTransactionalQuotas(t *testing.T) {
	config := testConfig(t)
	require(t, InitializeSQLite(t.Context(), config))
	now := time.Now().Truncate(time.Second)
	stores := []*SQLite{newStore(t, config, &now), newStore(t, config, &now)}
	now = now.Add(RecoveryBarrier)
	ctx := t.Context()
	nonce := reservation(config, "sender", 1, now)

	var workers sync.WaitGroup
	results := make(chan error, 16)
	for i := range cap(results) {
		workers.Go(func() { results <- stores[i%2].Reserve(ctx, nonce) })
	}
	workers.Wait()
	close(results)
	accepted := 0
	for err := range results {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, httpsig.ErrReplay):
		default:
			t.Fatalf("concurrent reserve: %v", err)
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted %d reservations for the same nonce", accepted)
	}
	sameNonceDifferentLeg := nonce
	sameNonceDifferentLeg.Key.Leg = httpsig.Gateway
	require(t, stores[1].Reserve(ctx, sameNonceDifferentLeg))
	if err := stores[0].Reserve(ctx, reservation(config, "sender", 2, now)); !errors.Is(err, httpsig.ErrReplayCallerQuota) {
		t.Fatalf("caller overflow: %v", err)
	}
	results = make(chan error, config.Capacity)
	for i := range config.Capacity {
		workers.Go(func() {
			results <- stores[i%2].Reserve(ctx, reservation(config, "sender-"+strconv.FormatInt(i, 10), 1, now))
		})
	}
	workers.Wait()
	close(results)
	accepted = 0
	for err := range results {
		if err == nil {
			accepted++
		} else if !errors.Is(err, httpsig.ErrReplayUnavailable) {
			t.Fatalf("global quota: %v", err)
		}
	}
	if accepted != int(config.Capacity)-2 {
		t.Fatalf("global capacity allowed %d new entries", accepted)
	}
	if err := stores[0].Reserve(ctx, nonce); !errors.Is(err, httpsig.ErrReplay) {
		t.Fatalf("capacity hid or evicted a live nonce: %v", err)
	}
	now = now.Add(91 * time.Second)
	require(t, stores[1].Reserve(ctx, reservation(config, "sender", 2, now)))
}

func TestSQLiteRejectsMissingWALAndWrongEpoch(t *testing.T) {
	ctx := t.Context()
	config := testConfig(t)
	if _, err := OpenSQLite(ctx, config); !errors.Is(err, httpsig.ErrReplayUnavailable) {
		t.Fatalf("missing database: %v", err)
	}
	require(t, InitializeSQLite(ctx, config))
	if err := InitializeSQLite(ctx, config); !errors.Is(err, httpsig.ErrReplayUnavailable) {
		t.Fatalf("reinitialization: %v", err)
	}
	mismatch := config
	mismatch.Epoch[0] ^= 1
	if _, err := OpenSQLite(ctx, mismatch); !errors.Is(err, httpsig.ErrReplayUnavailable) {
		t.Fatalf("wrong epoch: %v", err)
	}
	require(t, os.Remove(config.Path+"-wal"))
	if _, err := OpenSQLite(ctx, config); !errors.Is(err, httpsig.ErrReplayUnavailable) {
		t.Fatalf("missing WAL: %v", err)
	}
	if _, err := os.Stat(config.Path + "-wal"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected WAL recreation: %v", err)
	}
}

func TestSQLiteRecoversCommittedWALAfterProcessKill(t *testing.T) {
	const childPath = "OUTGATE_REPLAY_CRASH_TEST_PATH"
	const committed = "COMMITTED"
	const caller = "sender"
	config := testConfig(t)
	now := time.Unix(1750000000, 0)
	entry := reservation(config, caller, 1, now.Add(30*time.Second))
	if path := os.Getenv(childPath); path != "" {
		config.Path = path
		now = now.Add(-RecoveryBarrier)
		store := newStore(t, config, &now)
		now = now.Add(RecoveryBarrier)
		require(t, store.Reserve(t.Context(), entry))
		_, err := fmt.Fprintln(os.Stdout, committed)
		require(t, err)
		// The parent kills this process before SQLite can close or checkpoint.
		time.Sleep(time.Minute)
		t.Fatal("parent did not kill replay process")
	}
	require(t, InitializeSQLite(t.Context(), config))
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSQLiteRecoversCommittedWALAfterProcessKill$")
	cmd.Env = append(os.Environ(), childPath+"="+config.Path)
	stdout, err := cmd.StdoutPipe()
	require(t, err)
	require(t, cmd.Start())
	line, readErr := bufio.NewReader(stdout).ReadString('\n')
	killErr := cmd.Process.Kill()
	_ = cmd.Wait()
	require(t, readErr)
	require(t, killErr)
	if line != committed+"\n" {
		t.Fatal("child did not confirm commit")
	}
	reopened := newStore(t, config, &now)
	now = now.Add(RecoveryBarrier)
	if err := reopened.Reserve(t.Context(), entry); !errors.Is(err, httpsig.ErrReplay) {
		t.Fatalf("committed nonce lost after process kill: %v", err)
	}
}

func TestSQLiteWriteFailureAndMetadataLossFailClosed(t *testing.T) {
	ctx := t.Context()
	config := testConfig(t)
	require(t, InitializeSQLite(ctx, config))
	now := time.Now().Truncate(time.Second)
	store := newStore(t, config, &now)
	now = now.Add(RecoveryBarrier)
	nonce := reservation(config, "sender", 1, now)
	exec := func(query string, args ...any) {
		t.Helper()
		_, err := store.db.ExecContext(ctx, query, args...)
		require(t, err)
	}
	exec(`CREATE TRIGGER fail_insert AFTER INSERT ON replay_nonces
          BEGIN SELECT RAISE(ABORT, 'test failure'); END`)
	if err := store.Reserve(ctx, nonce); !errors.Is(err, httpsig.ErrReplayUnavailable) {
		t.Fatalf("failed write admitted: %v", err)
	}
	exec("DROP TRIGGER fail_insert")
	require(t, store.Reserve(ctx, nonce))
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := store.Ready(canceled); !errors.Is(err, httpsig.ErrReplayUnavailable) {
		t.Fatalf("canceled readiness check: %v", err)
	}
	require(t, store.Ready(ctx))
	exec("UPDATE replay_metadata SET clock_ns=0")
	if err := store.Ready(ctx); !errors.Is(err, httpsig.ErrReplayUnavailable) {
		t.Fatalf("rolled-back watermark: %v", err)
	}
	exec("UPDATE replay_metadata SET clock_ns=?", now.UnixNano())
	if err := store.Ready(ctx); !errors.Is(err, httpsig.ErrReplayUnavailable) {
		t.Fatalf("store resumed after integrity loss: %v", err)
	}
}

func TestSQLiteRejectsUndersizedQuota(t *testing.T) {
	config := testConfig(t)
	config.AdmittedBurst = 1
	if err := InitializeSQLite(t.Context(), config); !errors.Is(err, ErrConfig) {
		t.Fatalf("undersized quota: %v", err)
	}
}
