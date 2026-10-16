// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	sqlite "github.com/mattn/go-sqlite3"
	"serverdeck.local/agent/internal/contracts"
)

// Telemetry databases are independent transactions, never part of critical intent.
// They use the critical store's pinned private directory and lifetime/owner lock.
type Telemetry struct {
	mu                        sync.Mutex
	db                        *sql.DB
	owner                     *Store
	name                      string
	budget, walLimit, reserve int64
	journalBudget             int64
	failed                    bool
	capacity                  bool
}

//go:embed migrations/telemetry/001.sql
var telemetrySchema string

type TelemetryRecord struct {
	Kind, ID, Series, Segment    string
	Level, Start, Stop, Revision int64
	Data                         json.RawMessage
}

func (t *Telemetry) sqlFailure(err error) error {
	var failure sqlite.Error
	if errors.As(err, &failure) && failure.Code == sqlite.ErrFull {
		t.capacity = true
		return ErrQuota
	}
	return ErrStorage
}

func (s *Store) OpenTelemetry(ctx context.Context, name string, budget int64) (*Telemetry, error) {
	if (name != "history" && name != "events") || budget < 1000000 || budget > 16000000000 {
		return nil, ErrInvalid
	}
	t := &Telemetry{owner: s, name: name, budget: budget, walLimit: 8000000, reserve: budget / 10}
	agentID, e := s.AgentID(ctx)
	if e != nil {
		return nil, e
	}
	if t.reserve > 8000000 {
		t.reserve = 8000000
	}
	if name == "events" {
		t.walLimit = 4000000
		t.journalBudget = budget
		t.budget += 8000000
	}
	f, made, e := privateFile(s.dir, name+".db", true)
	if e != nil {
		return nil, e
	}
	f.Close()
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, e := os.Lstat(descriptorPath(s.dir) + "/" + name + ".db" + suffix); e == nil {
			f, _, e := privateFile(s.dir, name+".db"+suffix, false)
			if e != nil {
				return nil, e
			}
			f.Close()
		} else if !errors.Is(e, os.ErrNotExist) {
			return nil, ErrSafety
		}
	}
	u := url.URL{Scheme: "file", Path: descriptorPath(s.dir) + "/" + name + ".db"}
	q := url.Values{"_journal_mode": {"WAL"}, "_synchronous": {"FULL"}, "_busy_timeout": {"1000"}, "_foreign_keys": {"on"}, "mode": {"rw"}}
	u.RawQuery = q.Encode()
	t.db, e = sql.Open("serverdeck-critical", u.String())
	if e != nil {
		return nil, ErrStorage
	}
	t.db.SetMaxOpenConns(1)
	success := false
	defer func() {
		if !success {
			t.db.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if made {
		if _, e = t.db.ExecContext(ctx, "PRAGMA auto_vacuum=INCREMENTAL"); e != nil {
			return nil, ErrStorage
		}
	}
	pageLimit := (t.budget - t.reserve - min(t.walLimit, t.budget/4) - 65536) / 4096
	if pageLimit < 16 {
		return nil, ErrQuota
	}
	var actualLimit int64
	if e = t.db.QueryRowContext(ctx, "PRAGMA max_page_count="+itoa(pageLimit)).Scan(&actualLimit); e != nil || actualLimit > pageLimit {
		return nil, ErrQuota
	}
	var version int
	e = t.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version)
	if e != nil {
		return nil, ErrStorage
	}
	h := sha256.Sum256([]byte(name + "\n" + telemetrySchema))
	checksum := hex.EncodeToString(h[:])
	migrationHash := sha256.Sum256([]byte(telemetrySchema))
	migrationChecksum := hex.EncodeToString(migrationHash[:])
	if made {
		var epoch string
		epoch, e = RandomID()
		if e != nil {
			return nil, e
		}
		var tx *sql.Tx
		tx, e = t.db.BeginTx(ctx, nil)
		if e != nil {
			return nil, ErrStorage
		}
		defer tx.Rollback()
		if _, e = tx.ExecContext(ctx, telemetrySchema); e == nil {
			_, e = tx.ExecContext(ctx, "INSERT INTO meta VALUES(1,?,?,1,0,?)", checksum, epoch, agentID)
		}
		if e == nil {
			_, e = tx.ExecContext(ctx, "INSERT INTO schema_migrations VALUES(1,?,'development-E05',?)", migrationChecksum, time.Now().UTC().UnixMicro())
		}
		if e == nil {
			e = tx.Commit()
		}
		if e != nil {
			return nil, ErrStorage
		}
	} else if version != 1 {
		return nil, ErrSafety
	}
	var stored, mode, integrity string
	var syncMode int
	if e = t.db.QueryRowContext(ctx, "SELECT checksum FROM meta WHERE singleton=1").Scan(&stored); e != nil || stored != checksum {
		return nil, ErrSafety
	}
	var bound, migrationStored string
	var count int
	if t.db.QueryRowContext(ctx, "SELECT agent_id FROM meta").Scan(&bound) != nil || bound != agentID {
		return nil, ErrSafety
	}
	if t.db.QueryRowContext(ctx, "SELECT count(*),coalesce(max(checksum),'') FROM schema_migrations WHERE version=1").Scan(&count, &migrationStored) != nil || count != 1 || migrationStored != migrationChecksum {
		return nil, ErrSchema
	}
	if t.db.QueryRowContext(ctx, "SELECT count(*) FROM schema_migrations").Scan(&count) != nil || count != 1 {
		return nil, ErrSchema
	}
	if e = t.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); e != nil || mode != "wal" {
		return nil, ErrSafety
	}
	if e = t.db.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&syncMode); e != nil || syncMode != 2 {
		return nil, ErrSafety
	}
	if e = t.db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&integrity); e != nil || integrity != "ok" {
		return nil, ErrSafety
	}
	// Compare all live SQL definitions with the migration, not only a metadata hash.
	var expected *sql.DB
	expected, e = sql.Open("sqlite3", ":memory:")
	if e != nil {
		return nil, ErrStorage
	}
	defer expected.Close()
	expected.SetMaxOpenConns(1)
	if _, e = expected.ExecContext(ctx, telemetrySchema); e != nil {
		return nil, ErrStorage
	}
	readSchema := func(db *sql.DB) (string, error) {
		rows, e := db.QueryContext(ctx, "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")
		if e != nil {
			return "", e
		}
		defer rows.Close()
		var all string
		for rows.Next() {
			var a, b, c string
			if e = rows.Scan(&a, &b, &c); e != nil {
				return "", e
			}
			all += a + "|" + b + "|" + c + "\n"
		}
		return all, rows.Err()
	}
	a, ea := readSchema(t.db)
	b, eb := readSchema(expected)
	if ea != nil || eb != nil || a != b {
		return nil, ErrSafety
	}
	_, e = t.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	if e != nil {
		return nil, ErrStorage
	}
	success = true
	return t, nil
}

func (t *Telemetry) Close() error { return t.db.Close() }

func (t *Telemetry) Reserve() int64 { t.mu.Lock(); defer t.mu.Unlock(); return t.reserve }

func (t *Telemetry) EventRules(ctx context.Context) ([]contracts.APIRule, error) {
	return t.owner.Rules(ctx)
}

func (t *Telemetry) RetentionPending(ctx context.Context, before int64) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	var pending bool
	if t.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM changes WHERE at<?)", before).Scan(&pending) != nil {
		return true, ErrStorage
	}
	return pending, nil
}

func (t *Telemetry) CanBudget(budget int64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	used, _, err := t.usage()
	if err != nil {
		return err
	}
	if budget < 1000000 || budget > 16000000000 || used+min(int64(8000000), budget/10)+262144 > budget {
		return ErrQuota
	}
	return nil
}

func (t *Telemetry) SetBudget(budget int64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if budget < 1000000 || budget > 16000000000 {
		t.failed = true
		return ErrInvalid
	}
	t.budget = budget
	t.reserve = min(int64(8000000), budget/10)
	if t.name == "events" {
		t.journalBudget = budget
		t.budget += 8000000
	}
	used, _, err := t.usage()
	if err != nil || used+t.reserve > t.budget {
		t.failed = true
		t.capacity = true
		return ErrQuota
	}
	if t.name == "events" {
		var journalSize int64
		if t.db.QueryRow("SELECT coalesce(sum(length(data)+length(id)+512),0) FROM changes").Scan(&journalSize) != nil {
			t.failed = true
			return ErrStorage
		}
		if journalSize > t.journalBudget {
			t.failed = true
			t.capacity = true
			return ErrQuota
		}
	}
	pages := (t.budget - t.reserve - min(t.walLimit, t.budget/4) - 65536) / 4096
	if pages < 1 {
		t.failed = true
		return ErrQuota
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var actual int64
	if t.db.QueryRowContext(ctx, "PRAGMA max_page_count="+strconv.FormatInt(pages, 10)).Scan(&actual) != nil {
		t.failed = true
		return ErrStorage
	}
	if actual > pages {
		t.capacity = true
		t.failed = true
		return ErrQuota
	}
	return nil
}
func (t *Telemetry) usage() (total, wal int64, err error) {
	for _, s := range []string{"", "-wal", "-shm"} {
		st, e := os.Stat(descriptorPath(t.owner.dir) + "/" + t.name + ".db" + s)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return 0, 0, ErrStorage
		}
		n := allocated(st)
		total += n
		if s == "-wal" {
			wal = n
		}
	}
	return
}
func (t *Telemetry) Health() (int64, int64, int64, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	used, wal, e := t.usage()
	return used, wal, t.budget, t.failed || e != nil
}

// Update atomically stores related event state/change/offset within one DB.
// History batches and events are never claimed atomic with one another.
func (t *Telemetry) Update(ctx context.Context, records []TelemetryRecord, changes []TelemetryRecord, deletes []string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	fail := func(e error) error { t.failed = true; return e }
	if len(records)+len(changes)+len(deletes) > 256 {
		return fail(ErrQuota)
	}
	worst := int64(262144)
	for _, r := range append(append([]TelemetryRecord{}, records...), changes...) {
		if len(r.ID) < 1 || len(r.ID) > 512 || len(r.Kind) > 32 || len(r.Series) > 256 || len(r.Segment) > 128 || len(r.Data) > 64000 || !json.Valid(r.Data) || r.Revision < 1 || r.Stop < r.Start {
			return fail(ErrInvalid)
		}
		worst += int64(len(r.Data))*4 + 20*4096
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	var busy, log, done int
	if e := t.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &done); e != nil {
		return fail(t.sqlFailure(e))
	}
	used, wal, e := t.usage()
	free, fe := diskFree(t.owner.dir)
	if e != nil || fe != nil {
		return fail(t.sqlFailure(e))
	}
	if used+worst+t.reserve > t.budget || wal+worst > t.walLimit || free < worst+t.reserve {
		t.capacity = true
		return fail(ErrQuota)
	}
	tx, e := t.db.BeginTx(ctx, nil)
	if e != nil {
		return fail(t.sqlFailure(e))
	}
	defer tx.Rollback()
	var revision, sequence int64
	if tx.QueryRowContext(ctx, "SELECT revision,coalesce((SELECT seq FROM sqlite_sequence WHERE name='changes'),0) FROM meta").Scan(&revision, &sequence) != nil {
		return fail(ErrStorage)
	}
	if revision >= 9223372036854775806 || sequence >= 9223372036854775807-int64(len(changes)) {
		epoch, err := RandomID()
		if err != nil {
			return fail(err)
		}
		if sequence >= 9223372036854775807-int64(len(changes)) {
			if _, e = tx.ExecContext(ctx, "DELETE FROM changes"); e != nil {
				return fail(t.sqlFailure(e))
			}
			if _, e = tx.ExecContext(ctx, "DELETE FROM sqlite_sequence WHERE name='changes'"); e != nil {
				return fail(t.sqlFailure(e))
			}
			if _, e = tx.ExecContext(ctx, "UPDATE meta SET floor=0"); e != nil {
				return fail(t.sqlFailure(e))
			}
		}
		if _, e = tx.ExecContext(ctx, "UPDATE meta SET epoch=?,revision=1", epoch); e != nil {
			return fail(t.sqlFailure(e))
		}
		if _, e = tx.ExecContext(ctx, "UPDATE records SET revision=1 WHERE kind='problem'"); e != nil {
			return fail(t.sqlFailure(e))
		}
	}
	for _, kind := range []string{"series", "problem"} {
		var count, size int64
		if tx.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(length(data)+512),0) FROM records WHERE kind=?", kind).Scan(&count, &size) != nil {
			return fail(t.sqlFailure(e))
		}
		added := int64(0)
		newCount := int64(0)
		seen := map[string]bool{}
		for _, r := range records {
			if r.Kind == kind && !seen[r.ID] {
				seen[r.ID] = true
				var old int64
				err := tx.QueryRowContext(ctx, "SELECT length(data) FROM records WHERE kind=? AND id=?", kind, r.ID).Scan(&old)
				if err == sql.ErrNoRows {
					newCount++
					added += 512
				} else if err != nil {
					return fail(t.sqlFailure(err))
				}
				added += int64(len(r.Data)) - old
			}
		}
		limit := int64(4096)
		if kind == "problem" {
			limit = 10000
		}
		if count+newCount > limit || kind == "problem" && size+added > 8000000 {
			return fail(ErrQuota)
		}
	}
	for _, r := range records {
		_, e = tx.ExecContext(ctx, `INSERT INTO records VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(kind,id) DO UPDATE SET series=excluded.series,segment=excluded.segment,level=excluded.level,start=excluded.start,stop=excluded.stop,revision=CASE WHEN records.kind='problem' THEN records.revision+1 ELSE excluded.revision END,data=excluded.data WHERE excluded.revision>records.revision OR records.kind='problem'`, r.Kind, r.ID, r.Series, r.Segment, r.Level, r.Start, r.Stop, r.Revision, r.Data)
		if e != nil {
			return fail(t.sqlFailure(e))
		}
	}
	for _, r := range changes {
		if r.Kind == "event" {
			var existing []byte
			err := tx.QueryRowContext(ctx, "SELECT data FROM changes WHERE kind='event' AND id=?", r.ID).Scan(&existing)
			if err == nil {
				if !bytes.Equal(existing, r.Data) {
					return fail(ErrConflict)
				}
				continue
			}
			if err != sql.ErrNoRows {
				return fail(t.sqlFailure(err))
			}
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO changes(kind,id,at,data) VALUES(?,?,?,?)", r.Kind, r.ID, r.Start, r.Data); e != nil {
			return fail(t.sqlFailure(e))
		}
	}
	for _, id := range deletes {
		if _, e = tx.ExecContext(ctx, "DELETE FROM records WHERE kind='problem' AND id=?", id); e != nil {
			return fail(t.sqlFailure(e))
		}
	}
	if t.name == "events" {
		// Journal bytes are charged independently of the protected active-state
		// allowance. Rotation and its cursor floor commit with the new events.
		var bytes int64
		if tx.QueryRowContext(ctx, "SELECT coalesce(sum(length(data)+length(id)+512),0) FROM changes").Scan(&bytes) != nil {
			return fail(ErrStorage)
		}
		for bytes > t.journalBudget {
			var seq, charge int64
			if tx.QueryRowContext(ctx, "SELECT seq,length(data)+length(id)+512 FROM changes ORDER BY seq LIMIT 1").Scan(&seq, &charge) != nil {
				return fail(ErrStorage)
			}
			if _, e = tx.ExecContext(ctx, "DELETE FROM changes WHERE seq=?", seq); e != nil {
				return fail(t.sqlFailure(e))
			}
			if _, e = tx.ExecContext(ctx, "UPDATE meta SET floor=max(floor,?)", seq); e != nil {
				return fail(t.sqlFailure(e))
			}
			bytes -= charge
		}
	}
	if _, e = tx.ExecContext(ctx, "UPDATE meta SET revision=revision+1 WHERE revision<9223372036854775807"); e != nil {
		return fail(t.sqlFailure(e))
	}
	if e = tx.Commit(); e != nil {
		return fail(t.sqlFailure(e))
	}
	used, wal, e = t.usage()
	if e != nil || used > t.budget || wal > t.walLimit {
		return fail(ErrQuota)
	}
	t.failed = false
	t.capacity = false
	return nil
}

func (t *Telemetry) Records(ctx context.Context, kind, series string, level, from, to int64, after string, limit int) ([]TelemetryRecord, string, int64, error) {
	if limit < 1 || limit > 2000 {
		return nil, "", 0, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	rows, e := t.db.QueryContext(ctx, `SELECT kind,id,series,segment,level,start,stop,revision,data FROM records WHERE kind=? AND (?='' OR series=?) AND (?=0 OR level=?) AND stop>? AND start<? AND id>? ORDER BY id LIMIT ?`, kind, series, series, level, level, from, to, after, limit)
	if e != nil {
		return nil, "", 0, ErrStorage
	}
	defer rows.Close()
	out := []TelemetryRecord{}
	bytes := 0
	for rows.Next() {
		var r TelemetryRecord
		if e = rows.Scan(&r.Kind, &r.ID, &r.Series, &r.Segment, &r.Level, &r.Start, &r.Stop, &r.Revision, &r.Data); e != nil {
			return nil, "", 0, ErrStorage
		}
		bytes += len(r.Data)
		if bytes > 3500000 {
			return nil, "", 0, ErrQuota
		}
		out = append(out, r)
	}
	if rows.Err() != nil {
		return nil, "", 0, ErrStorage
	}
	rows.Close()
	var epoch string
	var rev int64
	if t.db.QueryRowContext(ctx, "SELECT epoch,revision FROM meta").Scan(&epoch, &rev) != nil {
		return nil, "", 0, ErrStorage
	}
	return out, epoch, rev, nil
}

func (t *Telemetry) Changes(ctx context.Context, epoch string, after int64, limit int) ([]TelemetryRecord, string, int64, error) {
	if limit < 1 || limit > 100 || after < 0 {
		return nil, "", 0, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	var current string
	var floor, revision int64
	if t.db.QueryRowContext(ctx, "SELECT epoch,floor,revision FROM meta").Scan(&current, &floor, &revision) != nil {
		return nil, "", 0, ErrStorage
	}
	if epoch == "" && after == 0 {
		after = floor
	}
	if (epoch != "" && epoch != current) || after < floor {
		return nil, current, floor, ErrCursor
	}
	rows, e := t.db.QueryContext(ctx, "SELECT seq,kind,id,at,data FROM changes WHERE seq>? ORDER BY seq LIMIT ?", after, limit)
	if e != nil {
		return nil, current, after, ErrStorage
	}
	defer rows.Close()
	out := []TelemetryRecord{}
	last := after
	for rows.Next() {
		var r TelemetryRecord
		if rows.Scan(&r.Revision, &r.Kind, &r.ID, &r.Start, &r.Data) != nil {
			return nil, current, after, ErrStorage
		}
		last = r.Revision
		out = append(out, r)
	}
	if rows.Err() != nil {
		return nil, current, after, ErrStorage
	}
	return out, current, last, nil
}

func (t *Telemetry) Bounds(ctx context.Context) (epoch string, floor, latest int64, err error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if t.db.QueryRowContext(ctx, "SELECT epoch,floor,coalesce((SELECT max(seq) FROM changes),floor) FROM meta").Scan(&epoch, &floor, &latest) != nil {
		err = ErrStorage
	}
	return
}

// Retention never deletes problem records or offsets. Monotonic age/clock trust
// is supplied by the engine; an untrusted clock disables time-based deletion.
func (t *Telemetry) Prune(ctx context.Context, before int64, maxChanges int) (retErr error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	defer func() {
		if retErr != nil {
			t.failed = true
		}
	}()
	if maxChanges < 1 || maxChanges > 100000 {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	var busy, log, done int
	if t.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &done) != nil {
		return ErrStorage
	}
	used, wal, usageErr := t.usage()
	free, freeErr := diskFree(t.owner.dir)
	if usageErr != nil || freeErr != nil {
		return ErrStorage
	}
	available := min(t.walLimit-wal, t.budget-t.reserve-used, free-t.reserve)
	query := "SELECT length(data) FROM records WHERE kind='bucket' AND (stop<? OR (level=15000 AND stop<?) OR (level=60000 AND stop<?)) ORDER BY rowid LIMIT 32"
	args := []any{before, before + int64((7*24*time.Hour-time.Hour)/time.Microsecond), before + int64((7*24*time.Hour-24*time.Hour)/time.Microsecond)}
	if t.name == "events" {
		query = "SELECT length(data) FROM changes WHERE at<? OR seq < coalesce((SELECT seq FROM changes ORDER BY seq DESC LIMIT 1 OFFSET ?),0) ORDER BY seq LIMIT 32"
		args = []any{before, maxChanges - 1}
	}
	rows, queryErr := t.db.QueryContext(ctx, query, args...)
	if queryErr != nil {
		return ErrStorage
	}
	admitted := 0
	candidate := false
	worst := int64(262144)
	for rows.Next() {
		candidate = true
		var size int64
		if rows.Scan(&size) != nil {
			rows.Close()
			return ErrStorage
		}
		next := worst + size*4 + 20*4096
		if next > available {
			break
		}
		worst = next
		admitted++
	}
	queryErr = rows.Err()
	rows.Close()
	if queryErr != nil {
		return ErrStorage
	}
	if admitted == 0 {
		if candidate || worst > available {
			t.capacity = true
			return ErrQuota
		}
		return nil
	}
	tx, e := t.db.BeginTx(ctx, nil)
	if e != nil {
		return ErrStorage
	}
	defer tx.Rollback()
	var result sql.Result
	if t.name == "history" {
		result, e = tx.ExecContext(ctx, "DELETE FROM records WHERE rowid IN (SELECT rowid FROM records WHERE kind='bucket' AND (stop<? OR (level=15000 AND stop<?) OR (level=60000 AND stop<?)) ORDER BY rowid LIMIT ?)", before, before+int64((7*24*time.Hour-time.Hour)/time.Microsecond), before+int64((7*24*time.Hour-24*time.Hour)/time.Microsecond), admitted)
	} else {
		_, e = tx.ExecContext(ctx, "DELETE FROM changes WHERE seq IN (SELECT seq FROM changes WHERE at<? OR seq < coalesce((SELECT seq FROM changes ORDER BY seq DESC LIMIT 1 OFFSET ?),0) ORDER BY seq LIMIT ?)", before, maxChanges-1, admitted)
	}
	if e != nil {
		return ErrStorage
	}
	if t.name == "history" {
		n, err := result.RowsAffected()
		if err != nil {
			return ErrStorage
		}
		if n > 0 {
			epoch, err := RandomID()
			if err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "UPDATE meta SET epoch=?,revision=revision+1", epoch); err != nil {
				return ErrStorage
			}
		}
	}
	if _, e = tx.ExecContext(ctx, "UPDATE meta SET floor=max(floor,coalesce((SELECT min(seq)-1 FROM changes),coalesce((SELECT seq FROM sqlite_sequence WHERE name='changes'),0)))"); e != nil {
		return ErrStorage
	}
	if e = tx.Commit(); e != nil {
		return ErrStorage
	}
	return nil
}
