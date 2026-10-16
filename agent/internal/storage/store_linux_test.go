// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testInstallation = "11111111-1111-4111-8111-111111111111"
const testOperation = "22222222-2222-4222-8222-222222222222"
const testDevice = "33333333-3333-4333-8333-333333333333"

func seed(t *testing.T) []byte {
	t.Helper()
	b, e := os.ReadFile("../../../Документация ServerDeck/Документация ServerDeck Agent/contracts/examples/config.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Runtime json.RawMessage `json:"runtime_initial"`
	}
	if json.Unmarshal(b, &v) != nil {
		t.Fatal("fixture")
	}
	return v.Runtime
}
func testStore(t *testing.T, limits Limits) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state")
	s, e := Open(context.Background(), path, testInstallation, seed(t), true, limits)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}
func intent(t *testing.T, s *Store, id, action, key string) {
	t.Helper()
	mac, e := s.Fingerprint("local:1000", action, []byte(`{}`), "")
	if e != nil {
		t.Fatal(e)
	}
	_, _, e = s.Intent(context.Background(), Operation{ID: id, Actor: "local:1000", Action: action, MAC: mac}, []string{key})
	if e != nil {
		t.Fatal(e)
	}
}
func running(t *testing.T, s *Store, id, action, key string) {
	intent(t, s, id, action, key)
	if e := s.MarkRunning(context.Background(), id); e != nil {
		t.Fatal(e)
	}
}
func TestDurabilityMigrationPermissions(t *testing.T) {
	s, path := testStore(t, DefaultLimits())
	ctx := context.Background()
	for p, want := range map[string]int{"PRAGMA synchronous": 2, "PRAGMA foreign_keys": 1, "PRAGMA page_size": 4096, "PRAGMA user_version": 5} {
		var got int
		if s.db.QueryRow(p).Scan(&got) != nil || got != want {
			t.Fatalf("%s=%d", p, got)
		}
	}
	for _, name := range []string{"critical.db", "request.key", "owner.lock"} {
		st, e := os.Stat(filepath.Join(path, name))
		if e != nil || st.Mode().Perm() != 0600 {
			t.Fatalf("permissions %s", name)
		}
	}
	if _, e := Open(ctx, path, "", nil, false, DefaultLimits()); e != ErrBusy {
		t.Fatalf("exclusive owner: %v", e)
	}
	before, rev, e := s.Settings(ctx)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = Open(ctx, path, testInstallation, []byte(`bad`), true, DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	after, v, e := s.Settings(ctx)
	if e != nil || rev != v || !bytes.Equal(before, after) {
		t.Fatal("seed overwrote settings")
	}
}
func TestMigrationAndCorruptionFailClosed(t *testing.T) {
	for _, kind := range []string{"future", "checksum", "extra_table", "corrupt", "lost_key", "incomplete"} {
		t.Run(kind, func(t *testing.T) {
			s, path := testStore(t, DefaultLimits())
			switch kind {
			case "future":
				s.db.Exec("PRAGMA user_version=6")
			case "checksum":
				s.db.Exec("UPDATE schema_migrations SET checksum='bad'")
			case "extra_table":
				s.db.Exec("CREATE TABLE unexpected(x)")
			}
			s.Close()
			switch kind {
			case "corrupt":
				os.WriteFile(filepath.Join(path, "critical.db"), []byte("not a database"), 0600)
			case "lost_key":
				os.Remove(filepath.Join(path, "request.key"))
			case "incomplete":
				os.WriteFile(filepath.Join(path, "restore-incomplete"), []byte("1"), 0600)
			}
			if restored, e := Open(context.Background(), path, "", nil, false, DefaultLimits()); e == nil {
				restored.Close()
				t.Fatal("unsafe reopen accepted")
			}
		})
	}
}
func TestPrivatePaths(t *testing.T) {
	parent := t.TempDir()
	real := filepath.Join(parent, "real")
	os.Mkdir(real, 0700)
	alias := filepath.Join(parent, "alias")
	os.Symlink(real, alias)
	if s, e := Open(context.Background(), alias, testInstallation, seed(t), true, DefaultLimits()); e == nil {
		s.Close()
		t.Fatal("symlink accepted")
	}
	s, path := testStore(t, DefaultLimits())
	s.Close()
	os.Chmod(filepath.Join(path, "request.key"), 0644)
	if s, e := Open(context.Background(), path, "", nil, false, DefaultLimits()); e == nil {
		s.Close()
		t.Fatal("public key accepted")
	}
}
func TestRealSQLiteWriteFailures(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"read_only", "sqlite_full", "audit_abort"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := testStore(t, DefaultLimits())
			var e error
			switch kind {
			case "read_only":
				s.db.Exec("PRAGMA query_only=ON")
				_, _, e = s.Intent(ctx, Operation{ID: testOperation, Actor: "local:1000", Action: "fixture", MAC: make([]byte, 32)}, []string{"object"})
			case "sqlite_full":
				e = s.write(ctx, func(tx *sql.Tx) error {
					var pages int
					tx.QueryRow("PRAGMA page_count").Scan(&pages)
					if _, err := tx.Exec("PRAGMA max_page_count=" + itoa(int64(pages))); err != nil {
						return err
					}
					_, err := tx.Exec("UPDATE settings SET document=zeroblob(64000)")
					return err
				})
				if e != ErrSpace {
					t.Fatalf("expected real SQLITE_FULL: %v", e)
				}
			case "audit_abort":
				if _, err := s.db.Exec(`CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'sensitive test text'); END`); err != nil {
					t.Fatal(err)
				}
				_, _, e = s.Intent(ctx, Operation{ID: testOperation, Actor: "local:1000", Action: "fixture", MAC: make([]byte, 32)}, []string{"object"})
			}
			if e == nil || strings.Contains(e.Error(), "sensitive") {
				t.Fatalf("unsafe failure: %v", e)
			}
			var n int
			if s.db.QueryRow("SELECT count(*) FROM operations").Scan(&n) != nil || n != 0 {
				t.Fatal("partial intent committed")
			}
			if kind != "sqlite_full" && s.Health().AuditAvailable {
				t.Fatal("audit failure invisible")
			}
		})
	}
}
func TestBusyCheckpointLongReaderAndBoundedRead(t *testing.T) {
	s, path := testStore(t, DefaultLimits())
	ctx := context.Background()
	reader, e := openDB(filepath.Join(path, "critical.db"), true)
	if e != nil {
		t.Fatal(e)
	}
	defer reader.Close()
	tx, e := reader.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	var rev int
	tx.QueryRow("SELECT revision FROM settings").Scan(&rev)
	intent(t, s, testOperation, "fixture", "object")
	start := time.Now()
	e = s.MarkRunning(ctx, testOperation)
	if e != ErrBusy {
		t.Fatalf("checkpoint with reader: %v", e)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("unbounded busy wait")
	}
	tx.Rollback()
	if e = s.MarkRunning(ctx, testOperation); e != nil {
		t.Fatal(e)
	}
	start = time.Now()
	e = s.read(ctx, func(ctx context.Context) error {
		var sum int
		return s.db.QueryRowContext(ctx, `WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000000000) SELECT sum(x) FROM n`).Scan(&sum)
	})
	if e == nil || time.Since(start) > 3*time.Second {
		t.Fatal("read deadline not enforced")
	}
}
func TestRetentionUnknownProtectionAndCursor(t *testing.T) {
	limits := DefaultLimits()
	limits.AuditBytes = 2048
	limits.Operations = 2
	s, _ := testStore(t, limits)
	ctx := context.Background()
	running(t, s, testOperation, "fixture", "object")
	if e := s.Finish(ctx, testOperation, "unknown", "unknown", "RECOVERY_REQUIRED", []byte("null")); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 20; i++ {
		if e := s.Rejection(ctx, Operation{ID: testOperation, Actor: "local:1000", Action: "fixture"}, "VERSION_CONFLICT"); e != nil {
			t.Fatal(e)
		}
	}
	rows, floor, e := s.Audit(ctx, 0, 100)
	if e != nil || floor == 0 || len(rows) > 4 {
		t.Fatal("audit not bounded")
	}
	if _, _, e = s.Audit(ctx, 1, 100); e != ErrCursor {
		t.Fatal("cursor gap hidden")
	}
	s.started = time.Now().Add(-31 * 24 * time.Hour)
	s.wallStart = time.Now().UTC().Add(-31 * 24 * time.Hour)
	if e = s.Rotate(ctx); e != nil {
		t.Fatal(e)
	}
	o, e := s.Lookup(ctx, testOperation)
	if e != nil || o.State != "unknown" {
		t.Fatal("unknown evicted")
	}
	other := "44444444-4444-4444-8444-444444444444"
	intent(t, s, other, "fixture", "other")
	if e = s.Finish(ctx, other, "cancelled", "none", "CANCELLED", []byte("null")); e != nil {
		t.Fatal(e)
	}
	s.db.Exec("UPDATE operations SET expires=1 WHERE id=?", other)
	if e = s.Rotate(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Lookup(ctx, other); e != ErrNotFound {
		t.Fatal("completed retention failed")
	}
	// A wall-clock jump inhibits expiry, even if a recorded expiry looks old.
	intent(t, s, other, "fixture", "other")
	s.Finish(ctx, other, "cancelled", "none", "CANCELLED", []byte("null"))
	s.db.Exec("UPDATE operations SET expires=1 WHERE id=?", other)
	s.wallStart = s.wallStart.Add(2 * time.Hour)
	s.Rotate(ctx)
	if _, e = s.Lookup(ctx, other); e != nil {
		t.Fatal("jump deleted dedup")
	}
}
func TestBackupRestoreSecurityFloor(t *testing.T) {
	s, path := testStore(t, DefaultLimits())
	ctx := context.Background()
	if _, e := s.db.Exec("INSERT INTO devices(id,token_hash,revoked) VALUES(?,?,0)", testDevice, bytes.Repeat([]byte{7}, 32)); e != nil {
		t.Fatal(e)
	}
	// The directed credential fixture must advance authority just like E03's
	// real credential transaction; unchanged-generation tampering is rejected.
	if _, e := s.db.Exec("UPDATE identity SET security_generation=security_generation+1"); e != nil {
		t.Fatal(e)
	}
	backup := filepath.Join(filepath.Dir(path), "backup")
	running(t, s, testOperation, "storage.backup", "storage.maintenance")
	if e := s.Backup(ctx, testOperation, backup); e != nil {
		t.Fatal(e)
	}
	s.Finish(ctx, testOperation, "succeeded", "applied", "", []byte("null"))
	// Directed E03/E11 fixture: no real token/auth endpoint or policy API exists.
	if _, e := s.db.Exec("UPDATE devices SET revoked=1,token_hash=NULL;UPDATE identity SET security_generation=security_generation+1;UPDATE security_policy SET document=?", []byte(`{"deny_actions":["files.trash"],"max_changes":2}`)); e != nil {
		t.Fatal(e)
	}
	id := "44444444-4444-4444-8444-444444444444"
	running(t, s, id, "storage.restore", "storage.maintenance")
	target := filepath.Join(filepath.Dir(path), "restored")
	if e := s.Restore(ctx, id, backup, target); e != nil {
		t.Fatal(e)
	}
	restored, e := Open(ctx, target, "", nil, false, DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	var revoked int
	var token []byte
	if e = restored.db.QueryRow("SELECT revoked,token_hash FROM devices WHERE id=?", testDevice).Scan(&revoked, &token); e != nil || revoked != 1 || len(token) != 0 {
		t.Fatal("revoked access resurrected")
	}
	f, e := floorFromDB(ctx, restored.db)
	if e != nil || f.Generation != 5 || f.Policy.MaxChanges != 2 || len(f.Policy.DenyActions) != 1 {
		t.Fatal("policy floor weakened")
	}
	o, e := restored.Lookup(ctx, testOperation)
	if e != nil || o.State != "succeeded" {
		t.Fatal("current completed operation identity lost")
	}
	restoredOp, e := restored.Lookup(ctx, id)
	if e != nil || restoredOp.State != "unknown" {
		t.Fatal("current in-flight restore identity lost")
	}
	_, settingsRevision, e := restored.Settings(ctx)
	if e != nil || settingsRevision != 2 {
		t.Fatal("restore reused an old settings revision")
	}
	_, _, originalEpoch, e := s.AuditPage(ctx, "", 0, 1)
	if e != nil {
		t.Fatal(e)
	}
	_, _, restoredEpoch, e := restored.AuditPage(ctx, "", 0, 1)
	if e != nil || restoredEpoch == originalEpoch {
		t.Fatal("restore reused audit cursor namespace")
	}
	if _, _, _, e = restored.AuditPage(ctx, originalEpoch, 0, 1); e != ErrCursor {
		t.Fatal("pre-restore cursor accepted")
	}
	// Tampering, lost authority or an incomplete destination fails closed.
	b, _ := os.ReadFile(filepath.Join(backup, "critical.db"))
	digest := sha256.Sum256(b)
	_ = digest
	b[100] ^= 1
	os.WriteFile(filepath.Join(backup, "critical.db"), b, 0600)
	if e = s.Restore(ctx, id, backup, filepath.Join(filepath.Dir(path), "tampered")); e != ErrSafety {
		t.Fatalf("tampered accepted: %v", e)
	}
}
func TestFingerprintCanonicalAndNoRawParams(t *testing.T) {
	s, _ := testStore(t, DefaultLimits())
	a, e := s.Fingerprint("local:1000", "fixture", []byte(`{"n":1e1,"secret":"never-log-me","a":0}`), "1")
	if e != nil {
		t.Fatal(e)
	}
	b, e := s.Fingerprint("local:1000", "fixture", []byte(`{"a":-0,"secret":"never-log-me","n":10}`), "1")
	if e != nil || !bytes.Equal(a, b) {
		t.Fatal("noncanonical fingerprint")
	}
	if bytes.Contains(a, []byte("never-log-me")) {
		t.Fatal("raw parameters retained")
	}
	_, e = s.Fingerprint("local:1000", "fixture", []byte(`{"a":1,"a":2}`), "1")
	if !errors.Is(e, ErrInvalid) {
		t.Fatal("duplicate key accepted")
	}
}

func TestOperationQuotaAndAdministrativeResolution(t *testing.T) {
	limits := DefaultLimits()
	limits.Operations = 1
	s, _ := testStore(t, limits)
	ctx := context.Background()
	running(t, s, testOperation, "fixture", "object")
	if e := s.Finish(ctx, testOperation, "unknown", "unknown", "RECOVERY_REQUIRED", []byte("null")); e != nil {
		t.Fatal(e)
	}
	mac, _ := s.Fingerprint("local:1000", "fixture", []byte(`{}`), "")
	other := "44444444-4444-4444-8444-444444444444"
	if _, _, e := s.Intent(ctx, Operation{ID: other, Actor: "local:1000", Action: "fixture", MAC: mac}, []string{"other"}); e != ErrQuota {
		t.Fatalf("quota not enforced: %v", e)
	}
	if e := s.Resolve(ctx, testOperation, "local:1000", "applied"); e != nil {
		t.Fatal(e)
	}
	o, e := s.Lookup(ctx, testOperation)
	if e != nil || o.State != "succeeded" || o.Code != "ADMIN_RESOLUTION" || o.Expires == 0 {
		t.Fatal("resolution dishonest")
	}
	a, _, e := s.Audit(ctx, 0, 100)
	if e != nil {
		t.Fatal(e)
	}
	gap := false
	for _, entry := range a {
		gap = gap || entry.Kind == "gap" && entry.Actor == "local:1000"
	}
	if !gap {
		t.Fatal("operator observation not recorded")
	}
}

func TestRawRollbackAndLostFloorRefused(t *testing.T) {
	for _, kind := range []string{"rollback", "lost_floor", "read_only_file"} {
		t.Run(kind, func(t *testing.T) {
			s, path := testStore(t, DefaultLimits())
			ctx := context.Background()
			backup := filepath.Join(filepath.Dir(path), "backup")
			running(t, s, testOperation, "storage.backup", "storage.maintenance")
			if e := s.Backup(ctx, testOperation, backup); e != nil {
				t.Fatal(e)
			}
			if _, e := s.db.Exec("UPDATE identity SET security_generation=security_generation+1"); e != nil {
				t.Fatal(e)
			}
			if _, e := s.exportFloor(ctx); e != nil {
				t.Fatal(e)
			}
			s.Close()
			switch kind {
			case "rollback":
				b, e := os.ReadFile(filepath.Join(backup, "critical.db"))
				if e != nil {
					t.Fatal(e)
				}
				if os.WriteFile(filepath.Join(path, "critical.db"), b, 0600) != nil {
					t.Fatal("copy")
				}
			case "lost_floor":
				os.Remove(filepath.Join(path, "security-floor.json"))
			case "read_only_file":
				os.Chmod(filepath.Join(path, "critical.db"), 0400)
			}
			if reopened, e := Open(ctx, path, "", nil, false, DefaultLimits()); e == nil {
				reopened.Close()
				t.Fatal("unsafe store admitted")
			}
		})
	}
}
