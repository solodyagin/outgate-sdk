// Package replay supplies durable storage for verified Outgate HTTP signatures.
package replay

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/solodyagin/outgate-sdk/httpsig"
	"modernc.org/sqlite"
)

const RecoveryBarrier = 120 * time.Second

var ErrConfig = errors.New("outgate: invalid SQLite replay configuration")

// SQLiteConfig describes one local database dedicated to one verifier namespace.
// Epoch must be independently provisioned in trusted control state. A restored
// or reset installation needs an authorized recovery procedure and a new epoch.
type SQLiteConfig struct {
	Path, Namespace            string
	Epoch                      [32]byte
	Capacity, CallerCapacity   int64
	AdmittedRPS, AdmittedBurst int64
}

// SQLite implements httpsig.ReplayStore. It requires an existing initialized
// database and keeps a recovery barrier on each open.
type SQLite struct {
	db                  *sql.DB
	config              SQLiteConfig
	files               [3]os.FileInfo
	broken              atomic.Bool
	readyAt, minCreated time.Time
	clock               func() time.Time
	lastCommit          int64 // serialized by the single checked-out database connection
}

var _ httpsig.ReplayStore = (*SQLite)(nil)

// InitializeSQLite provisions a new database. It never overwrites or repairs
// an existing database. Provisioning failures leave the files for inspection.
func InitializeSQLite(ctx context.Context, config SQLiteConfig) error {
	config, err := config.normalized()
	if err != nil {
		return err
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(config.Path + suffix); !errors.Is(err, os.ErrNotExist) {
			return httpsig.ErrReplayUnavailable
		}
	}
	file, err := os.OpenFile(config.Path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return httpsig.ErrReplayUnavailable
	}
	if err := file.Close(); err != nil {
		return httpsig.ErrReplayUnavailable
	}
	db := openDB(config.Path)
	err = initialize(ctx, db, config)
	closeErr := db.Close()
	if err != nil || closeErr != nil {
		return httpsig.ErrReplayUnavailable
	}
	return nil
}

func initialize(ctx context.Context, db *sql.DB, config SQLiteConfig) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	var mode string
	if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&mode); err != nil || mode != "wal" {
		return httpsig.ErrReplayUnavailable
	}
	if err := durableConnection(ctx, conn); err != nil {
		return err
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, schema); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO replay_metadata(id, version, namespace, epoch) VALUES (1, 1, ?, ?)", config.Namespace, config.Epoch[:]); err != nil {
		return err
	}
	return tx.Commit()
}

// OpenSQLite checks the persisted epoch and storage integrity, then starts the
// recovery barrier. It never implicitly initializes a missing database or WAL.
func OpenSQLite(ctx context.Context, config SQLiteConfig) (*SQLite, error) {
	return openSQLite(ctx, config, time.Now)
}

func openSQLite(ctx context.Context, config SQLiteConfig, clock func() time.Time) (*SQLite, error) {
	config, err := config.normalized()
	if err != nil {
		return nil, err
	}
	store := &SQLite{db: openDB(config.Path), config: config, clock: clock}
	if err := store.inspect(ctx); err != nil {
		_ = store.db.Close()
		return nil, httpsig.ErrReplayUnavailable
	}
	started := clock()
	store.readyAt = started.Add(RecoveryBarrier)
	store.minCreated = started.Truncate(time.Second)
	if store.minCreated.Before(started) {
		store.minCreated = store.minCreated.Add(time.Second)
	}
	return store, nil
}

func (c SQLiteConfig) normalized() (SQLiteConfig, error) {
	// 120 seconds of nonce storage times 1.25, plus the admitted burst.
	const entriesPerRPS = 150
	if c.Path == "" || !httpsig.ValidReplayNamespace(c.Namespace) || c.Epoch == [32]byte{} ||
		c.AdmittedRPS <= 0 || c.AdmittedBurst < 0 || c.Capacity < c.AdmittedBurst ||
		c.AdmittedRPS > (c.Capacity-c.AdmittedBurst)/entriesPerRPS ||
		c.CallerCapacity <= 0 || c.CallerCapacity >= c.Capacity {
		return SQLiteConfig{}, ErrConfig
	}
	path, err := filepath.Abs(c.Path)
	if err != nil || strings.HasPrefix(filepath.ToSlash(path), "//") {
		return SQLiteConfig{}, ErrConfig
	}
	c.Path = path
	return c, nil
}

func openDB(path string) *sql.DB {
	path = filepath.ToSlash(path)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	uri := url.URL{Scheme: "file", Path: path}
	uri.RawQuery = url.Values{
		"mode": {"rw"}, "_txlock": {"immediate"},
		"_pragma": {"busy_timeout(1000)", "synchronous(FULL)"},
	}.Encode()
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		panic("outgate: SQLite driver missing")
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db
}

func durableConnection(ctx context.Context, conn *sql.Conn) error {
	var mode string
	var syncLevel int
	if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		return httpsig.ErrReplayUnavailable
	}
	if err := conn.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&syncLevel); err != nil || syncLevel != 2 {
		return httpsig.ErrReplayUnavailable
	}
	return conn.Raw(func(raw any) error {
		// Preserve the WAL even after a clean close so a missing WAL cannot be
		// mistaken for a normal restart.
		_, err := raw.(sqlite.FileControl).FileControlPersistWAL("main", 1)
		return err
	})
}

func (s *SQLite) inspect(ctx context.Context) error {
	names := s.filenames()
	// SHM may be regenerated by SQLite. DB and WAL must preexist before open.
	for i := range 2 {
		file, err := snapshotFile(names[i])
		if err != nil {
			return httpsig.ErrReplayUnavailable
		}
		s.files[i] = file
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := durableConnection(ctx, conn); err != nil {
		return err
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var integrity string
	var consistent bool
	if err := tx.QueryRowContext(ctx, "PRAGMA integrity_check(1)").Scan(&integrity); err != nil || integrity != "ok" {
		return httpsig.ErrReplayUnavailable
	}
	watermark, err := s.watermark(ctx, tx)
	if err != nil || s.clock().UnixNano() < watermark {
		return httpsig.ErrReplayUnavailable
	}
	if err := tx.QueryRowContext(ctx, countersConsistent).Scan(&consistent); err != nil || !consistent {
		return httpsig.ErrReplayUnavailable
	}
	shm, err := snapshotFile(names[2])
	if err != nil {
		return httpsig.ErrReplayUnavailable
	}
	s.files[2] = shm
	if !s.filesIntact() {
		return httpsig.ErrReplayUnavailable
	}
	s.lastCommit = watermark
	return nil
}

func (s *SQLite) filenames() [3]string {
	return [3]string{s.config.Path, s.config.Path + "-wal", s.config.Path + "-shm"}
}

func snapshotFile(path string) (os.FileInfo, error) {
	current, err := os.Lstat(path)
	if err != nil || !current.Mode().IsRegular() {
		return nil, httpsig.ErrReplayUnavailable
	}
	// Windows resolves a path stat's file ID lazily. Resolve it now so the
	// baseline cannot follow a replacement. On Unix Lstat already has the ID;
	// opening and closing a separate descriptor could release SQLite's locks.
	if runtime.GOOS == "windows" && !os.SameFile(current, current) {
		return nil, httpsig.ErrReplayUnavailable
	}
	return current, nil
}

func (s *SQLite) filesIntact() bool {
	if s.broken.Load() {
		return false
	}
	for i, path := range s.filenames() {
		current, err := os.Lstat(path)
		if err != nil || !current.Mode().IsRegular() || !os.SameFile(current, s.files[i]) {
			s.broken.Store(true)
			return false
		}
	}
	return true
}

func (s *SQLite) watermark(ctx context.Context, tx *sql.Tx) (int64, error) {
	var timestamp int64
	err := tx.QueryRowContext(ctx, "SELECT clock_ns FROM replay_metadata WHERE id=1 AND version=1 AND namespace=? AND epoch=?",
		s.config.Namespace, s.config.Epoch[:]).Scan(&timestamp)
	return timestamp, err
}

// Ready verifies the local replay store. The runtime must additionally confirm
// current revocation/control state before admitting any protected request.
func (s *SQLite) Ready(ctx context.Context) error {
	return s.transaction(ctx, false, nil)
}

// Health verifies files, WAL/FULL, namespace/epoch and the retained clock
// watermark even during recovery warmup. It returns the immutable earliest
// readiness time, NOT permission to reserve/dispatch. Ready and Reserve retain
// the full startup barrier and created cutoff. Revocation health is external.
func (s *SQLite) Health(ctx context.Context) (time.Time, error) {
	if err := s.transactionHealth(ctx, false, nil, true); err != nil {
		return time.Time{}, err
	}
	return s.readyAt, nil
}

// Prune removes up to 256 expired rows and returns the number removed.
func (s *SQLite) Prune(ctx context.Context) (int64, error) {
	var deleted int64
	err := s.transaction(ctx, true, func(tx *sql.Tx, now time.Time) error {
		result, err := tx.ExecContext(ctx, pruneExpired, now.Unix())
		if err != nil {
			return err
		}
		deleted, err = result.RowsAffected()
		return err
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

// Close releases storage resources. Reservations always fail closed afterward.
func (s *SQLite) Close() error { return s.db.Close() }

func (s *SQLite) Reserve(ctx context.Context, reservation httpsig.Reservation) error {
	if reservation.Key.Namespace != s.config.Namespace {
		return httpsig.ErrReplayUnavailable
	}
	return s.transaction(ctx, true, func(tx *sql.Tx, now time.Time) error {
		if reservation.CreatedAt().Before(s.minCreated) || !reservation.ValidAt(now) {
			return httpsig.ErrReplay
		}
		return s.reserve(ctx, tx, reservation, now)
	})
}

func (s *SQLite) reserve(ctx context.Context, tx *sql.Tx, reservation httpsig.Reservation, now time.Time) error {
	if _, err := tx.ExecContext(ctx, pruneExpired, now.Unix()); err != nil {
		return err
	}
	key := reservation.Key
	var exists bool
	var used, callerUsed int64
	err := tx.QueryRowContext(ctx, `
        SELECT EXISTS(SELECT 1 FROM replay_nonces WHERE leg=? AND caller=? AND key_id=? AND nonce=?),
            used, coalesce((SELECT used FROM replay_callers WHERE caller=?), 0)
        FROM replay_metadata WHERE id=1`, key.Leg, key.Caller, key.KeyID, key.Nonce, key.Caller).Scan(&exists, &used, &callerUsed)
	if err != nil {
		return err
	}
	switch {
	case exists:
		return httpsig.ErrReplay
	case callerUsed >= s.config.CallerCapacity:
		return httpsig.ErrReplayCallerQuota
	case used >= s.config.Capacity:
		return httpsig.ErrReplayUnavailable
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO replay_nonces(leg,caller,key_id,nonce,retain_until) VALUES (?,?,?,?,?)",
		key.Leg, key.Caller, key.KeyID, key.Nonce, reservation.RetainUntil.Unix())
	return err
}

func (s *SQLite) transaction(ctx context.Context, write bool, operation func(*sql.Tx, time.Time) error) error {
	return s.transactionHealth(ctx, write, operation, false)
}

// allowWarmup is used only by the read-only Health assertion, never mutations.
func (s *SQLite) transactionHealth(ctx context.Context, write bool, operation func(*sql.Tx, time.Time) error, allowWarmup bool) error {
	if !s.filesIntact() || !allowWarmup && s.clock().Before(s.readyAt) {
		return httpsig.ErrReplayUnavailable
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return httpsig.ErrReplayUnavailable
	}
	defer conn.Close()
	if !s.filesIntact() || durableConnection(ctx, conn) != nil {
		return httpsig.ErrReplayUnavailable
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return httpsig.ErrReplayUnavailable
	}
	defer tx.Rollback()
	now := s.clock()
	stamp := now.UnixNano()
	watermark, err := s.watermark(ctx, tx)
	if err != nil || watermark < s.lastCommit {
		if errors.Is(err, sql.ErrNoRows) || err == nil {
			s.broken.Store(true)
		}
		return httpsig.ErrReplayUnavailable
	}
	if stamp < watermark || !allowWarmup && now.Before(s.readyAt) || ctx.Err() != nil || !s.filesIntact() {
		return httpsig.ErrReplayUnavailable
	}
	if !write {
		return nil
	}
	if err := operation(tx, now); err != nil {
		if err == httpsig.ErrReplay || err == httpsig.ErrReplayCallerQuota {
			return err
		}
		return httpsig.ErrReplayUnavailable
	}
	if _, err := tx.ExecContext(ctx, "UPDATE replay_metadata SET clock_ns=? WHERE id=1", stamp); err != nil ||
		!s.filesIntact() || tx.Commit() != nil {
		return httpsig.ErrReplayUnavailable
	}
	s.lastCommit = stamp
	if ctx.Err() != nil || !s.filesIntact() {
		return httpsig.ErrReplayUnavailable
	}
	return nil
}
