// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	sqlite "github.com/mattn/go-sqlite3"
	"serverdeck.local/agent/internal/contracts"
)

// This floor schema is deliberately narrow and versioned. E03/E11 adapters
// must enforce/extend it before adding authentication or trusted TUF metadata.
type Policy struct {
	DenyActions []string `json:"deny_actions"`
	MaxChanges  int      `json:"max_changes"`
}
type Floor struct {
	Version      int                `json:"version"`
	Installation string             `json:"installation_id"`
	Generation   int64              `json:"generation"`
	Revoked      []string           `json:"revoked"`
	Policy       Policy             `json:"policy"`
	AgentID      string             `json:"agent_id,omitempty"`
	Active       []activeCredential `json:"active_credentials,omitempty"`
	Inventory    *Inventory         `json:"inventory,omitempty"`
}
type activeCredential struct {
	ID   string `json:"device_id"`
	Hash string `json:"verifier_sha256"`
}
type backupManifest struct {
	Version      int    `json:"version"`
	Installation string `json:"installation_id"`
	Schema       int    `json:"schema"`
	Generation   int64  `json:"security_generation"`
	SHA256       string `json:"sha256"`
	Bytes        int64  `json:"bytes"`
	Consistent   bool   `json:"consistent"`
}
type sealed struct {
	Payload json.RawMessage `json:"payload"`
	MAC     string          `json:"hmac_sha256"`
}

func (s *Store) seal(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, ErrSafety
	}
	h := hmac.New(sha256.New, s.key)
	h.Write(b)
	return json.Marshal(sealed{b, hex.EncodeToString(h.Sum(nil))})
}
func (s *Store) unseal(b []byte, v any) error {
	if _, e := contracts.Parse(bytes.NewReader(b), 65536); e != nil {
		return ErrSafety
	}
	var env sealed
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&env) != nil {
		return ErrSafety
	}
	h := hmac.New(sha256.New, s.key)
	h.Write(env.Payload)
	mac, e := hex.DecodeString(env.MAC)
	if e != nil || !hmac.Equal(mac, h.Sum(nil)) {
		return ErrSafety
	}
	d = json.NewDecoder(bytes.NewReader(env.Payload))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return ErrSafety
	}
	return nil
}
func validPolicy(p Policy) bool {
	if p.MaxChanges < 1 || p.MaxChanges > 4 || len(p.DenyActions) > 128 {
		return false
	}
	for _, a := range p.DenyActions {
		if !SafeLabel(a) {
			return false
		}
	}
	return true
}
func floorFromDB(ctx context.Context, db *sql.DB) (f Floor, e error) {
	f.Version = 1
	f.Revoked = []string{}
	if e = db.QueryRowContext(ctx, "SELECT installation_id,security_generation FROM identity WHERE singleton=1").Scan(&f.Installation, &f.Generation); e != nil {
		return f, ErrSafety
	}
	var b []byte
	if e = db.QueryRowContext(ctx, "SELECT document FROM security_policy WHERE singleton=1").Scan(&b); e != nil {
		return f, ErrSafety
	}
	if json.Unmarshal(b, &f.Policy) != nil || !validPolicy(f.Policy) {
		return f, ErrSafety
	}
	if !ValidID(f.Installation) || f.Generation < 1 {
		return f, ErrSafety
	}
	rows, e := db.QueryContext(ctx, "SELECT id FROM devices WHERE revoked=1 ORDER BY id LIMIT 33")
	if e != nil {
		return f, ErrSafety
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil || !ValidID(id) {
			return f, ErrSafety
		}
		f.Revoked = append(f.Revoked, id)
	}
	if rows.Err() != nil || len(f.Revoked) > 32 {
		return f, ErrSafety
	}
	rows.Close()
	var version int
	if db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version) != nil {
		return f, ErrSafety
	}
	if version >= 2 {
		f.Version = 2
		if db.QueryRowContext(ctx, "SELECT agent_id FROM auth_meta WHERE singleton=1").Scan(&f.AgentID) != nil || !ValidID(f.AgentID) {
			return f, ErrSafety
		}
		active, e := db.QueryContext(ctx, "SELECT id,token_hash FROM devices WHERE revoked=0 ORDER BY id LIMIT 33")
		if e != nil {
			return f, ErrSafety
		}
		defer active.Close()
		for active.Next() {
			var id string
			var hash []byte
			if active.Scan(&id, &hash) != nil || !ValidID(id) || len(hash) != 32 {
				return f, ErrSafety
			}
			f.Active = append(f.Active, activeCredential{id, hex.EncodeToString(hash)})
		}
		if active.Err() != nil || len(f.Active) > 32 {
			return f, ErrSafety
		}
	}
	if version >= 4 {
		i, e := inventoryFromDB(ctx, db)
		if e != nil {
			return f, e
		}
		f.Version = 3
		if version >= 5 {
			f.Version = 5
		}
		f.Inventory = &i
	}
	return f, nil
}
func syncWrite(dir *os.File, name string, b []byte) error {
	f, _, e := privateFile(dir, name, true)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = f.Truncate(0); e != nil {
		return ErrStorage
	}
	if _, e = f.WriteAt(b, 0); e != nil {
		return ErrStorage
	}
	if e = f.Sync(); e != nil {
		return ErrStorage
	}
	return dir.Sync()
}
func (s *Store) exportFloor(ctx context.Context) (Floor, error) {
	f, e := floorFromDB(ctx, s.db)
	if e != nil {
		return f, ErrSafety
	}
	b, e := s.seal(f)
	if e != nil {
		return f, e
	}
	if e = syncWrite(s.dir, "security-floor.next", b); e != nil {
		return f, e
	}
	if e = os.Rename(descriptorPath(s.dir)+"/security-floor.next", descriptorPath(s.dir)+"/security-floor.json"); e != nil {
		return f, ErrStorage
	}
	if e = s.dir.Sync(); e != nil {
		return f, ErrStorage
	}
	// Proof of current export is the live critical generation AND contents. A
	// stale export alone is never sufficient authority for restoring a backup.
	b, e = readPrivate(s.dir, "security-floor.json", 65536)
	if e != nil {
		return f, e
	}
	var exported Floor
	if s.unseal(b, &exported) != nil {
		return f, ErrSafety
	}
	a, _ := json.Marshal(f)
	b, _ = json.Marshal(exported)
	if !bytes.Equal(a, b) {
		return f, ErrSafety
	}
	if _, e = s.db.ExecContext(ctx, "UPDATE identity SET floor_required=1 WHERE singleton=1"); e != nil {
		return f, ErrSafety
	}
	return f, nil
}
func (s *Store) verifyFloor(ctx context.Context) error {
	var required int
	if s.db.QueryRowContext(ctx, "SELECT floor_required FROM identity WHERE singleton=1").Scan(&required) != nil {
		return ErrSafety
	}
	b, e := readPrivate(s.dir, "security-floor.json", 65536)
	if e != nil {
		if required == 0 {
			if _, missing := os.Lstat(descriptorPath(s.dir) + "/security-floor.json"); os.IsNotExist(missing) {
				return nil
			}
		}
		return ErrSafety
	}
	var floor Floor
	if s.unseal(b, &floor) != nil || (floor.Version != 1 && floor.Version != 2 && floor.Version != 3 && floor.Version != 4 && floor.Version != 5) {
		return ErrSafety
	}
	current, e := floorFromDB(ctx, s.db)
	if e != nil || current.Installation != floor.Installation || current.Generation < floor.Generation {
		return ErrSafety
	}
	if floor.Version >= 3 && !inventoryContains(current.Inventory, floor.Inventory) {
		return ErrSafety
	}
	if current.Generation == floor.Generation {
		if floor.Version == 4 {
			current.Version = 4
		}
		if floor.Version == 3 && current.Inventory != nil {
			current.Version = 3
			current.Inventory.Attestation = nil
		}
		if floor.Version < 3 {
			current.Inventory = nil
			current.Version = 2
		}
		if floor.Version == 1 {
			if len(current.Active) != 0 {
				return ErrSafety
			}
			current.Version = 1
			current.AgentID = ""
			current.Active = nil
		}
		a, _ := json.Marshal(floor)
		b, _ = json.Marshal(current)
		if !bytes.Equal(a, b) {
			return ErrSafety
		}
	}
	return nil
}
func readPrivate(dir *os.File, name string, max int64) ([]byte, error) {
	f, _, e := privateFile(dir, name, false)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max {
		return nil, ErrSafety
	}
	return b, nil
}
func digestFile(dir *os.File, name string, max int64) (string, int64, error) {
	f, _, e := privateFile(dir, name, false)
	if e != nil {
		return "", 0, e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, max+1))
	if e != nil || n > max {
		return "", 0, ErrQuota
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// SQLite's online backup API copies a consistent single database, including
// committed WAL pages. It is not an atomic backup of independent databases.
func copyDatabase(ctx context.Context, src, dst *sql.DB) error {
	sc, e := src.Conn(ctx)
	if e != nil {
		return e
	}
	defer sc.Close()
	dc, e := dst.Conn(ctx)
	if e != nil {
		return e
	}
	defer dc.Close()
	return sc.Raw(func(rawSrc any) error {
		return dc.Raw(func(rawDst any) error {
			backup, e := rawDst.(*sqlite.SQLiteConn).Backup("main", rawSrc.(*sqlite.SQLiteConn), "main")
			if e != nil {
				return e
			}
			defer backup.Close()
			for {
				if ctx.Err() != nil {
					return ErrBusy
				}
				done, e := backup.Step(128)
				if e != nil {
					return e
				}
				if done {
					return backup.Finish()
				}
				select {
				case <-ctx.Done():
					return ErrBusy
				case <-time.After(time.Millisecond):
				}
			}
		})
	})
}
func requireRunning(ctx context.Context, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, id, action string) error {
	var n int
	if db.QueryRowContext(ctx, "SELECT count(*) FROM operations WHERE id=? AND action=? AND state='running'", id, action).Scan(&n) != nil || n != 1 {
		return ErrSafety
	}
	return nil
}

// Backup is an effect adapter; operation ID must already have a durable intent.
// Call under the Service maintenance barrier. Existing destination is rejected.
func (s *Store) Backup(ctx context.Context, operationID, path string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	release, e := s.acquire(ctx)
	if e != nil {
		return e
	}
	defer release()
	if e = requireRunning(ctx, s.db, operationID, "storage.backup"); e != nil {
		return e
	}
	if e = s.compatibility(ctx); e != nil {
		return e
	}
	var floor Floor
	if _, e = os.Lstat(path); !os.IsNotExist(e) {
		return ErrSafety
	}
	floor, e = s.reserveOwned(ctx, operationID, "backup", path)
	if e != nil {
		return e
	}
	dir, e := privateDir(path, true)
	if e != nil {
		return e
	}
	defer dir.Close()
	free, e := diskFree(dir)
	if e != nil || free < s.limits.PhysicalBytes {
		return ErrSpace
	}
	f, _, e := privateFile(dir, "critical.db", true)
	if e != nil {
		return e
	}
	f.Close()
	dst, e := openDB(descriptorPath(dir)+"/critical.db", false)
	if e != nil {
		return ErrStorage
	}
	if e = copyDatabase(ctx, s.db, dst); e == nil {
		_, e = dst.ExecContext(ctx, "PRAGMA journal_mode=DELETE")
	}
	closeErr := dst.Close()
	if e != nil || closeErr != nil {
		return ErrStorage
	}
	hash, n, e := digestFile(dir, "critical.db", s.limits.PhysicalBytes)
	if e != nil {
		return e
	}
	f, _, e = privateFile(dir, "critical.db", false)
	if e != nil {
		return e
	}
	e = f.Sync()
	f.Close()
	if e != nil {
		return ErrStorage
	}
	var schema int
	if s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&schema) != nil {
		return ErrSchema
	}
	m := backupManifest{1, floor.Installation, schema, floor.Generation, hash, n, true}
	b, e := s.seal(m)
	if e != nil {
		return e
	}
	// Manifest is written last. Incomplete destinations never pass restore.
	return syncWrite(dir, "manifest.json", b)
}

// Restore creates a NEW private state directory; it never overwrites the live
// store, copies its HMAC key from current authority, and overlays current floor
// before publishing a complete marker. Switching service paths is E11 work.
func (s *Store) Restore(ctx context.Context, operationID, backupPath, target string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	release, e := s.acquire(ctx)
	if e != nil {
		return e
	}
	defer release()
	if e = requireRunning(ctx, s.db, operationID, "storage.restore"); e != nil {
		return e
	}
	if e = s.compatibility(ctx); e != nil {
		return ErrSafety
	}
	if e = s.verifyFloor(ctx); e != nil {
		return e
	}
	floor, e := s.exportFloor(ctx)
	if e != nil {
		return ErrSafety
	}
	backup, e := privateDir(backupPath, false)
	if e != nil {
		return e
	}
	defer backup.Close()
	b, e := readPrivate(backup, "manifest.json", 65536)
	if e != nil {
		return e
	}
	var m backupManifest
	if s.unseal(b, &m) != nil || m.Version != 1 || (m.Schema != 1 && m.Schema != 2 && m.Schema != 3 && m.Schema != 4 && m.Schema != 5) || !m.Consistent || m.Installation != floor.Installation || m.Generation > floor.Generation {
		return ErrSafety
	}
	hash, n, e := digestFile(backup, "critical.db", s.limits.PhysicalBytes)
	if e != nil || hash != m.SHA256 || n != m.Bytes {
		return ErrSafety
	}
	src, e := openDB(descriptorPath(backup)+"/critical.db", true)
	if e != nil {
		return ErrSafety
	}
	defer src.Close()
	probe := &Store{db: src}
	if e = probe.compatibility(ctx); e != nil {
		return e
	}
	old, e := floorFromDB(ctx, src)
	if e != nil || old.Installation != floor.Installation || old.Generation != m.Generation {
		return ErrSafety
	}
	// A divergent backup branch must not lose an owned footprint by overlaying
	// current tables. Refuse before effects rather than trusting hints to merge.
	if old.Inventory != nil && !inventoryContains(floor.Inventory, old.Inventory) {
		return ErrSafety
	}
	if _, e = os.Lstat(target); !os.IsNotExist(e) {
		return ErrSafety
	}
	floor, e = s.reserveOwned(ctx, operationID, "restore", target)
	if e != nil {
		return e
	}
	dir, e := privateDir(target, true)
	if e != nil {
		return e
	}
	defer dir.Close()
	if e = syncWrite(dir, "restore-incomplete", []byte("1")); e != nil {
		return e
	}
	if e = syncWrite(dir, "request.key", s.key); e != nil {
		return e
	}
	f, _, e := privateFile(dir, "critical.db", true)
	if e != nil {
		return e
	}
	f.Close()
	dst, e := openDBMode(descriptorPath(dir)+"/critical.db", false, "deferred")
	if e != nil {
		return ErrStorage
	}
	defer dst.Close()
	if e = copyDatabase(ctx, src, dst); e != nil {
		return ErrStorage
	}
	if e = migrateRulesAfterAuth(ctx, dst); e != nil {
		return e
	}
	if e = migrateInventoryDB(ctx, dst); e != nil {
		return e
	}
	if e = migrateFilesDB(ctx, dst); e != nil {
		return e
	}
	if e = rotateRuleEpochDB(ctx, dst); e != nil {
		return e
	}
	var checkpointBusy, checkpointLog, checkpointDone int
	if e = dst.QueryRowContext(ctx, "PRAGMA main.wal_checkpoint(TRUNCATE)").Scan(&checkpointBusy, &checkpointLog, &checkpointDone); e != nil || checkpointBusy != 0 {
		return ErrBusy
	}
	maxPages := (s.limits.WALBytes - 65536 - 32) / 4120
	if _, e = dst.ExecContext(ctx, "PRAGMA max_page_count="+itoa(maxPages)); e != nil {
		return ErrQuota
	}
	// Current operation identities/audit are authority too: an old snapshot
	// must never forget an unresolved operation or the seven-day dedup window.
	// Source is quiesced and read-only; only destination is written. This is
	// not a distributed atomic commit across two independent databases.
	merged := floor.Policy
	merged.DenyActions = append(append([]string{}, floor.Policy.DenyActions...), old.Policy.DenyActions...)
	sort.Strings(merged.DenyActions)
	unique := merged.DenyActions[:0]
	for _, a := range merged.DenyActions {
		if len(unique) == 0 || unique[len(unique)-1] != a {
			unique = append(unique, a)
		}
	}
	merged.DenyActions = unique
	if old.Policy.MaxChanges < merged.MaxChanges {
		merged.MaxChanges = old.Policy.MaxChanges
	}
	policy, _ := json.Marshal(merged)
	tx, e := dst.BeginTx(ctx, nil)
	if e != nil {
		return ErrStorage
	}
	defer tx.Rollback()
	for _, q := range []string{
		"DELETE FROM object_locks", "DELETE FROM operation_changes", "DELETE FROM operations", "DELETE FROM audit",
		"DELETE FROM file_inventory_attestation", "DELETE FROM file_journal", "DELETE FROM owned_artifacts", "DELETE FROM inventory_meta",
		"DELETE FROM storage_meta", "DELETE FROM sqlite_sequence WHERE name IN ('audit','operation_changes')", "DELETE FROM devices", "DELETE FROM auth_meta",
	} {
		if _, e = tx.ExecContext(ctx, q); e != nil {
			return ErrStorage
		}
	}
	for _, table := range []string{"operations", "object_locks", "operation_changes", "audit", "storage_meta", "sqlite_sequence", "devices", "auth_meta", "owned_artifacts", "inventory_meta", "file_inventory_attestation", "file_journal"} {
		if e = copyAuthorityTable(ctx, s.db, tx, table); e != nil {
			return ErrStorage
		}
	}
	epochBytes := make([]byte, 16)
	if _, e = rand.Read(epochBytes); e != nil {
		return ErrSafety
	}
	epochBytes[6] = (epochBytes[6] & 15) | 64
	epochBytes[8] = (epochBytes[8] & 63) | 128
	epoch := fmt.Sprintf("%x-%x-%x-%x-%x", epochBytes[:4], epochBytes[4:6], epochBytes[6:8], epochBytes[8:10], epochBytes[10:])
	if _, e = tx.ExecContext(ctx, "UPDATE storage_meta SET epoch=? WHERE singleton=1", epoch); e != nil {
		return ErrStorage
	}
	var currentRevision, oldRevision int64
	if s.db.QueryRowContext(ctx, "SELECT revision FROM settings WHERE singleton=1").Scan(&currentRevision) != nil || tx.QueryRowContext(ctx, "SELECT revision FROM settings WHERE singleton=1").Scan(&oldRevision) != nil {
		return ErrStorage
	}
	if oldRevision > currentRevision {
		currentRevision = oldRevision
	}
	if currentRevision == 9223372036854775807 {
		return ErrQuota
	}
	if _, e = tx.ExecContext(ctx, "UPDATE settings SET revision=? WHERE singleton=1", currentRevision+1); e != nil {
		return ErrStorage
	}
	for _, id := range floor.Revoked {
		if _, e = tx.ExecContext(ctx, "INSERT INTO devices(id,revoked) VALUES(?,1) ON CONFLICT(id) DO UPDATE SET revoked=1,token_hash=NULL", id); e != nil {
			return ErrStorage
		}
	}
	if _, e = tx.ExecContext(ctx, "UPDATE security_policy SET document=? WHERE singleton=1", policy); e != nil {
		return ErrStorage
	}
	if _, e = tx.ExecContext(ctx, "UPDATE identity SET security_generation=? WHERE singleton=1", floor.Generation); e != nil {
		return ErrStorage
	}
	if e = tx.Commit(); e != nil {
		return ErrStorage
	}
	probe.db = dst
	if e = probe.compatibility(ctx); e != nil {
		return e
	}
	if _, e = dst.ExecContext(ctx, "PRAGMA main.wal_checkpoint(TRUNCATE)"); e != nil {
		return ErrStorage
	}
	floor.Policy = merged
	b, e = s.seal(floor)
	if e != nil {
		return e
	}
	if e = syncWrite(dir, "security-floor.json", b); e != nil {
		return e
	}
	if e = syncWrite(dir, "restore-complete.json", []byte(`{"schema":1,"current_security_floor_applied":true}`)); e != nil {
		return e
	}
	if e = os.Remove(descriptorPath(dir) + "/restore-incomplete"); e != nil {
		return ErrStorage
	}
	return dir.Sync()
}

func copyAuthorityTable(ctx context.Context, source *sql.DB, target *sql.Tx, table string) error {
	// Table names are a closed compiled allowlist, never caller-controlled SQL.
	switch table {
	case "operations", "object_locks", "operation_changes", "audit", "storage_meta", "sqlite_sequence", "devices", "auth_meta", "owned_artifacts", "inventory_meta", "file_inventory_attestation", "file_journal":
	default:
		return ErrSafety
	}
	query := "SELECT * FROM " + table
	if table == "sqlite_sequence" {
		query += " WHERE name IN ('audit','operation_changes')"
	}
	rows, e := source.QueryContext(ctx, query)
	if e != nil {
		return e
	}
	defer rows.Close()
	columns, e := rows.Columns()
	if e != nil {
		return e
	}
	placeholders := ""
	for i := range columns {
		if i > 0 {
			placeholders += ","
		}
		placeholders += "?"
	}
	insert := "INSERT INTO " + table + " VALUES(" + placeholders + ")"
	for rows.Next() {
		values := make([]any, len(columns))
		dest := make([]any, len(columns))
		for i := range values {
			dest[i] = &values[i]
		}
		if e = rows.Scan(dest...); e != nil {
			return e
		}
		if _, e = target.ExecContext(ctx, insert, values...); e != nil {
			return e
		}
	}
	return rows.Err()
}
