// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	sqlite "github.com/mattn/go-sqlite3"
	"serverdeck.local/agent/internal/contracts"
)

//go:embed migrations/001.sql
var migration string

const releaseID = "development-E02"
const applicationID = 1396982083

func init() {
	sql.Register("serverdeck-critical", &sqlite.SQLiteDriver{ConnectHook: func(c *sqlite.SQLiteConn) error {
		for _, q := range []string{"PRAGMA cache_spill=OFF", "PRAGMA cache_size=-8192", "PRAGMA wal_autocheckpoint=0", "PRAGMA journal_size_limit=0", "PRAGMA temp_store=MEMORY", "PRAGMA trusted_schema=OFF"} {
			stmt, e := c.Prepare(q)
			if e != nil {
				return e
			}
			_, e = stmt.Exec(nil)
			closeErr := stmt.Close()
			if e != nil {
				return e
			}
			if closeErr != nil {
				return closeErr
			}
		}
		return nil
	}})
}
func itoa(n int64) string { return strconv.FormatInt(n, 10) }

type Store struct {
	db              *sql.DB
	dir, lock       *os.File
	path            string
	key             []byte
	limits          Limits
	gate            chan struct{}
	waiting         chan struct{}
	healthMu        sync.Mutex
	health          Health
	started         time.Time
	wallStart       time.Time
	expiryTrusted   bool
	closed          bool
	useRuntimeAudit bool
}

// Open never silently replaces a corrupt DB or a lost HMAC key. Initial seed
// is used only when explicitly creating a previously absent database.
func Open(ctx context.Context, path, installation string, seed []byte, create bool, limits Limits) (s *Store, err error) {
	if limits.Operations < 1 || limits.Operations > 10000 || limits.WALBytes < 262144 || limits.WALBytes > 8000000 || limits.StateBytes < 65536 || limits.StateBytes > 64000000 || limits.AuditBytes < 2048 || limits.AuditBytes > 2000000000 || limits.AuditDays < 1 || limits.AuditDays > 365 || limits.PhysicalBytes < 1048576 {
		return nil, ErrInvalid
	}
	dir, e := privateDir(path, create)
	if e != nil {
		return nil, e
	}
	if _, markerErr := os.Lstat(descriptorPath(dir) + "/restore-incomplete"); !errors.Is(markerErr, os.ErrNotExist) {
		dir.Close()
		return nil, ErrSafety
	}
	s = &Store{dir: dir, path: descriptorPath(dir) + "/critical.db", limits: limits, gate: make(chan struct{}, 1), waiting: make(chan struct{}, 32), started: time.Now(), wallStart: time.Now().UTC(), health: Health{Available: true, AuditAvailable: true, SecurityFloorAvailable: true}}
	cleanupStore := s
	s.useRuntimeAudit = limits == DefaultLimits()
	defer func() {
		if err != nil {
			cleanupStore.Close()
		}
	}()
	s.lock, _, e = privateFile(dir, "owner.lock", true)
	if e != nil {
		return nil, e
	}
	if e = lockFile(s.lock); e != nil {
		return nil, e
	}
	f, made, e := privateFile(dir, "critical.db", create)
	if e != nil {
		return nil, e
	}
	f.Close()
	for _, name := range []string{"critical.db-wal", "critical.db-shm"} {
		if _, e := os.Lstat(descriptorPath(dir) + "/" + name); e == nil {
			v, _, err := privateFile(dir, name, false)
			if err != nil {
				return nil, err
			}
			v.Close()
		} else if !errors.Is(e, os.ErrNotExist) {
			return nil, ErrSafety
		}
	}
	k, newKey, e := privateFile(dir, "request.key", made)
	if e != nil {
		return nil, e
	}
	if newKey {
		key := make([]byte, 32)
		if _, e = rand.Read(key); e == nil {
			_, e = k.Write(key)
		}
		if e == nil {
			e = k.Sync()
		}
		if e == nil {
			e = dir.Sync()
		}
	}
	if e == nil {
		_, e = k.Seek(0, 0)
	}
	if e == nil {
		s.key, e = io.ReadAll(io.LimitReader(k, 33))
	}
	k.Close()
	if e != nil || len(s.key) != 32 {
		return nil, ErrSafety
	}
	s.db, e = openDB(s.path, false)
	if e != nil {
		return nil, ErrStorage
	}
	var version int
	if e = s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); e != nil {
		return nil, ErrStorage
	}
	if made {
		if !ValidID(installation) || len(seed) > 65536 || validateRuntime(seed) != nil {
			return nil, ErrInvalid
		}
		if e = s.migrate(ctx, installation, seed); e != nil {
			return nil, e
		}
	} else if version != 1 && version != 2 && version != 3 && version != 4 && version != 5 {
		return nil, ErrSchema
	}
	if e = s.compatibility(ctx); e != nil {
		return nil, e
	}
	if installation != "" {
		var actual string
		if !ValidID(installation) || s.db.QueryRowContext(ctx, "SELECT installation_id FROM identity WHERE singleton=1").Scan(&actual) != nil || actual != installation {
			return nil, ErrSafety
		}
	}
	if e = s.verifyFloor(ctx); e != nil {
		return nil, e
	}
	var mode string
	var syncMode, fk, page int
	if e = s.db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&mode); e != nil || mode != "wal" {
		return nil, ErrStorage
	}
	if e = s.db.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&syncMode); e != nil || syncMode != 2 {
		return nil, ErrStorage
	}
	if e = s.db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); e != nil || fk != 1 {
		return nil, ErrStorage
	}
	if e = s.db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&page); e != nil || page != 4096 {
		return nil, ErrSchema
	}
	if e = migrateRulesAfterAuth(ctx, s.db); e != nil {
		return nil, e
	}
	if e = migrateInventoryDB(ctx, s.db); e != nil {
		return nil, e
	}
	if e = migrateFilesDB(ctx, s.db); e != nil {
		return nil, e
	}
	if e = s.compatibility(ctx); e != nil {
		return nil, e
	}
	// Recover in one bounded transaction. No effect is dispatched by Open.
	if e = s.write(ctx, func(tx *sql.Tx) error {
		if _, e := tx.ExecContext(ctx, "DELETE FROM pairing_codes"); e != nil {
			return e
		}
		_, e := tx.ExecContext(ctx, `UPDATE operations SET state='unknown',phase='reconcile_required',effect='unknown',audit_status='durable',code='RECOVERY_REQUIRED',revision=revision+1,updated=? WHERE state IN ('preparing','running')`, time.Now().UTC().UnixMicro())
		return e
	}); e != nil {
		return nil, e
	}
	// Refresh only from the verified live authority. A stale export is never
	// accepted instead of that DB, including across the v1 -> v2 migration.
	if e = s.publishAuthFloor(ctx); e != nil {
		return nil, e
	}
	if e = dir.Sync(); e != nil {
		return nil, ErrStorage
	}
	// Publish a clean WAL boundary after schema/startup recovery, before any
	// reader can pin migration frames and block the first admission.
	var busy, frames, done int
	if e = s.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &frames, &done); e != nil || busy != 0 {
		return nil, ErrBusy
	}
	return s, nil
}
func openDB(path string, readonly bool) (*sql.DB, error) {
	return openDBMode(path, readonly, "immediate")
}
func openDBMode(path string, readonly bool, txlock string) (*sql.DB, error) {
	mode := "rw"
	if readonly {
		mode = "ro"
	}
	u := url.URL{Scheme: "file", Path: path}
	q := u.Query()
	q.Set("mode", mode)
	q.Set("_busy_timeout", "1000")
	q.Set("_foreign_keys", "on")
	q.Set("_synchronous", "FULL")
	q.Set("_txlock", txlock)
	q.Set("_stmt_cache_size", "0")
	u.RawQuery = q.Encode()
	db, e := sql.Open("serverdeck-critical", u.String())
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}
func validateRuntime(b []byte) error {
	_, e := contracts.Decode[contracts.RuntimeConfig](bytes.NewReader(b), contracts.Target{Family: "api", Definition: "Runtime"}, 65536)
	return e
}
func (s *Store) migrate(ctx context.Context, id string, seed []byte) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return ErrStorage
	}
	defer tx.Rollback()
	hash := sha256.Sum256([]byte(migration))
	if _, e = tx.ExecContext(ctx, migration); e != nil {
		return ErrStorage
	}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO schema_migrations VALUES(1,?,?,?)", []any{hex.EncodeToString(hash[:]), releaseID, time.Now().UTC().UnixMicro()}},
		{"INSERT INTO identity(singleton,installation_id,security_generation) VALUES(1,?,1)", []any{id}},
		{"INSERT INTO settings VALUES(1,1,?)", []any{seed}},
		{"INSERT INTO security_policy VALUES(1,?)", []any{[]byte(`{"deny_actions":[],"max_changes":4}`)}},
		{"INSERT INTO storage_meta(singleton,epoch) VALUES(1,?)", []any{id}},
	} {
		if _, e = tx.ExecContext(ctx, q.sql, q.args...); e != nil {
			return ErrStorage
		}
	}
	if _, e = tx.ExecContext(ctx, fmt.Sprintf("PRAGMA application_id=%d", applicationID)); e != nil {
		return ErrStorage
	}
	if e = tx.Commit(); e != nil {
		return ErrStorage
	}
	return nil
}
func (s *Store) compatibility(ctx context.Context) error {
	var check, checksum string
	var app, v, count int
	if s.db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&check) != nil || check != "ok" {
		return ErrStorage
	}
	if s.db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&app) != nil || app != applicationID {
		return ErrSchema
	}
	if s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v) != nil || (v != 1 && v != 2 && v != 3 && v != 4 && v != 5) {
		return ErrSchema
	}
	if s.db.QueryRowContext(ctx, "SELECT count(*),coalesce(max(checksum),'') FROM schema_migrations WHERE version=1").Scan(&count, &checksum) != nil {
		return ErrSchema
	}
	hash := sha256.Sum256([]byte(migration))
	if count != 1 || checksum != hex.EncodeToString(hash[:]) {
		return ErrSchema
	}
	if s.db.QueryRowContext(ctx, "SELECT count(*) FROM schema_migrations").Scan(&count) != nil || count != v {
		return ErrSchema
	}
	// Verify live schema, not merely its recorded migration checksum.
	expected, e := sql.Open("sqlite3", ":memory:")
	if e != nil {
		return ErrStorage
	}
	defer expected.Close()
	expected.SetMaxOpenConns(1)
	if _, e = expected.ExecContext(ctx, migration); e != nil {
		return ErrSchema
	}
	if v >= 2 {
		hash := sha256.Sum256([]byte(authMigration))
		if s.db.QueryRowContext(ctx, "SELECT checksum FROM schema_migrations WHERE version=2").Scan(&checksum) != nil || checksum != hex.EncodeToString(hash[:]) {
			return ErrSchema
		}
		if _, e = expected.ExecContext(ctx, authMigration); e != nil {
			return ErrSchema
		}
	}
	schema := func(db *sql.DB) (string, error) {
		var x string
		e := db.QueryRowContext(ctx, `SELECT group_concat(type||':'||name||':'||coalesce(sql,''),char(10)) FROM (SELECT type,name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name)`).Scan(&x)
		return x, e
	}
	if v >= 3 {
		hash := sha256.Sum256([]byte(rulesMigration))
		if s.db.QueryRowContext(ctx, "SELECT checksum FROM schema_migrations WHERE version=3").Scan(&checksum) != nil || checksum != hex.EncodeToString(hash[:]) {
			return ErrSchema
		}
		if _, e = expected.ExecContext(ctx, rulesMigration); e != nil {
			return ErrSchema
		}
	}
	if v >= 4 {
		h := sha256.Sum256([]byte(inventoryMigration))
		if s.db.QueryRowContext(ctx, "SELECT checksum FROM schema_migrations WHERE version=4").Scan(&checksum) != nil || checksum != hex.EncodeToString(h[:]) {
			return ErrSchema
		}
		if _, e = expected.ExecContext(ctx, inventoryMigration); e != nil {
			return ErrSchema
		}
		if _, e = inventoryFromDB(ctx, s.db); e != nil {
			return e
		}
	}
	if v >= 5 {
		h := sha256.Sum256([]byte(filesMigration))
		if s.db.QueryRowContext(ctx, "SELECT checksum FROM schema_migrations WHERE version=5").Scan(&checksum) != nil || checksum != hex.EncodeToString(h[:]) {
			return ErrSchema
		}
		if _, e = expected.ExecContext(ctx, filesMigration); e != nil {
			return ErrSchema
		}
	}
	a, e := schema(s.db)
	if e != nil {
		return ErrSchema
	}
	b, e := schema(expected)
	if e != nil || a != b {
		return ErrSchema
	}
	var seed []byte
	if s.db.QueryRowContext(ctx, "SELECT document FROM settings WHERE singleton=1").Scan(&seed) != nil || validateRuntime(seed) != nil {
		return ErrStorage
	}
	return nil
}
func (s *Store) acquire(ctx context.Context) (func(), error) {
	select {
	case s.waiting <- struct{}{}:
	default:
		return nil, ErrBusy
	}
	select {
	case s.gate <- struct{}{}:
		<-s.waiting
		return func() { <-s.gate }, nil
	case <-ctx.Done():
		<-s.waiting
		return nil, ErrBusy
	}
}
func (s *Store) failure(e error) error {
	if errors.Is(e, context.DeadlineExceeded) || errors.Is(e, context.Canceled) {
		return ErrBusy
	}
	for _, x := range []error{ErrQuota, ErrBusy, ErrVersion, ErrConflict, ErrNotFound, ErrInvalid, ErrCursor, ErrUnauthorized, ErrPolicy} {
		if errors.Is(e, x) {
			return x
		}
	}
	safe := ErrStorage
	var se sqlite.Error
	if errors.As(e, &se) {
		switch se.Code {
		case sqlite.ErrFull:
			safe = ErrSpace
		case sqlite.ErrBusy, sqlite.ErrLocked:
			safe = ErrBusy
		}
	}
	for _, x := range []error{ErrSpace, ErrQuota, ErrBusy, ErrVersion, ErrConflict, ErrSafety, ErrNotFound, ErrInvalid, ErrSchema} {
		if errors.Is(e, x) {
			safe = x
		}
	}
	s.healthMu.Lock()
	s.health.Available = false
	s.health.AuditAvailable = false
	s.health.Failures++
	s.health.Code = safe.Error()
	s.healthMu.Unlock()
	return safe
}
func (s *Store) Health() Health { s.healthMu.Lock(); defer s.healthMu.Unlock(); return s.health }
func (s *Store) write(ctx context.Context, fn func(*sql.Tx) error) error {
	ctx, cancel := context.WithTimeout(ctx, readerTimeout)
	defer cancel()
	release, e := s.acquire(ctx)
	if e != nil {
		return e
	}
	defer release()
	if s.closed {
		return ErrStorage
	}
	if e = s.admission(ctx); e != nil {
		return s.failure(e)
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return s.failure(e)
	}
	defer tx.Rollback()
	var auditBefore, auditAfter int64
	if e = tx.QueryRowContext(ctx, "SELECT coalesce(max(seq),0) FROM audit").Scan(&auditBefore); e != nil {
		return s.failure(e)
	}
	if e = fn(tx); e != nil {
		return s.failure(e)
	}
	if e = tx.QueryRowContext(ctx, "SELECT coalesce(max(seq),0) FROM audit").Scan(&auditAfter); e != nil {
		return s.failure(e)
	}
	if e = tx.Commit(); e != nil {
		return s.failure(e)
	}
	s.healthMu.Lock()
	s.health.Available = true
	if auditAfter > auditBefore {
		s.health.AuditAvailable = true
	}
	if s.health.AuditAvailable {
		s.health.Code = ""
	}
	s.healthMu.Unlock()
	return nil
}
func (s *Store) admission(ctx context.Context) error {
	if s.useRuntimeAudit {
		var document []byte
		var runtimeConfig contracts.RuntimeConfig
		if s.db.QueryRowContext(ctx, "SELECT document FROM settings WHERE singleton=1").Scan(&document) != nil || json.Unmarshal(document, &runtimeConfig) != nil {
			return ErrStorage
		}
		s.limits.AuditBytes = runtimeConfig.Audit.BudgetBytes
		s.limits.AuditDays = runtimeConfig.Audit.RetentionDays
	}
	var busy, log, done int
	if e := s.db.QueryRowContext(ctx, "PRAGMA main.wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &done); e != nil {
		return e
	}
	if busy != 0 {
		return ErrBusy
	}
	var pageCount int64
	if e := s.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pageCount); e != nil {
		return e
	}
	// Conservative bound: a transaction can dirty every database page. Start at
	// a truncated WAL and limit growth to the WAL frame budget. Refuse early,
	// rather than pretending journal_size_limit is a hard WAL limiter.
	maxPages := (s.limits.WALBytes - 65536 - 32) / 4120
	if maxPages < pageCount {
		return ErrQuota
	}
	physicalPages := (s.limits.PhysicalBytes - s.limits.WALBytes - 65536) / 4096
	if physicalPages < maxPages {
		maxPages = physicalPages
	}
	if _, e := s.db.ExecContext(ctx, "PRAGMA max_page_count="+itoa(maxPages)); e != nil {
		return e
	}
	var used, wal int64
	for _, name := range []string{"critical.db", "critical.db-wal", "critical.db-shm"} {
		f, e := os.Stat(descriptorPath(s.dir) + "/" + name)
		if e == nil {
			used += allocated(f)
			if name == "critical.db-wal" {
				wal = f.Size()
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return ErrStorage
		}
	}
	free, e := diskFree(s.dir)
	if e != nil {
		return e
	}
	s.healthMu.Lock()
	s.health.AllocatedBytes = used
	s.health.WALBytes = wal
	s.healthMu.Unlock()
	if used+s.limits.WALBytes > s.limits.PhysicalBytes {
		return ErrQuota
	}
	if free < s.limits.WALBytes+65536 {
		return ErrSpace
	}
	return nil
}
func (s *Store) read(ctx context.Context, fn func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, readerTimeout)
	defer cancel()
	release, e := s.acquire(ctx)
	if e != nil {
		return e
	}
	defer release()
	if s.closed {
		return ErrStorage
	}
	if e = fn(ctx); e != nil {
		return s.failure(e)
	}
	return nil
}
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.gate <- struct{}{}
	defer func() { <-s.gate }()
	if s.closed {
		return nil
	}
	s.closed = true
	var e error
	if s.db != nil {
		e = s.db.Close()
	}
	if s.lock != nil {
		s.lock.Close()
	}
	if s.dir != nil {
		s.dir.Close()
	}
	return e
}
func (s *Store) Fingerprint(actor, action string, params []byte, expected string) ([]byte, error) {
	if !SafeLabel(actor) || !SafeLabel(action) || len(params) > 65536 || len(expected) > 256 {
		return nil, ErrInvalid
	}
	v, e := contracts.Parse(bytes.NewReader(params), 65536)
	if e != nil {
		return nil, ErrInvalid
	}
	var normalize func(any) any
	normalize = func(x any) any {
		switch n := x.(type) {
		case json.Number:
			f, _ := strconv.ParseFloat(string(n), 64)
			if f == 0 {
				return json.Number("0")
			}
			return json.Number(strconv.FormatFloat(f, 'g', -1, 64))
		case map[string]any:
			for k, v := range n {
				n[k] = normalize(v)
			}
		case []any:
			for i, v := range n {
				n[i] = normalize(v)
			}
		}
		return x
	}
	v = normalize(v)
	b, e := json.Marshal(struct {
		Actor, Action, Expected string
		Params                  any
	}{actor, action, expected, v})
	if e != nil {
		return nil, ErrInvalid
	}
	h := hmac.New(sha256.New, s.key)
	h.Write(b)
	return h.Sum(nil), nil
}
func (s *Store) Settings(ctx context.Context) ([]byte, int64, error) {
	var b []byte
	var rev int64
	e := s.read(ctx, func(ctx context.Context) error {
		return s.db.QueryRowContext(ctx, "SELECT document,revision FROM settings WHERE singleton=1").Scan(&b, &rev)
	})
	return b, rev, e
}

// Cleanup observes durable truth; it does not bypass the audit retention clock.
func (s *Store) AuditRetentionPending(ctx context.Context, before int64) (bool, error) {
	var pending bool
	err := s.read(ctx, func(ctx context.Context) error {
		return s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM audit WHERE at<?)", before).Scan(&pending)
	})
	return pending, err
}

func (s *Store) RetentionClockTrusted(ctx context.Context) bool {
	trusted := false
	if s.read(ctx, func(context.Context) error { trusted = s.trustworthyClock(time.Now()); return nil }) != nil {
		return false
	}
	return trusted
}
func (s *Store) ApplySettings(ctx context.Context, operationID string, expected int64, b []byte) error {
	if len(b) > 65536 || validateRuntime(b) != nil {
		return ErrInvalid
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		var action, state string
		if tx.QueryRowContext(ctx, "SELECT action,state FROM operations WHERE id=?", operationID).Scan(&action, &state) != nil || action != "config.set" || state != "running" {
			return ErrSafety
		}
		r, e := tx.ExecContext(ctx, "UPDATE settings SET document=?,revision=revision+1 WHERE singleton=1 AND revision=? AND revision<9223372036854775807", b, expected)
		if e != nil {
			return e
		}
		n, e := r.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrVersion
		}
		return nil
	})
}
