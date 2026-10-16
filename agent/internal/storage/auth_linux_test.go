// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestAuthMigrationPreservesV1ChecksumAndDisablesLegacyPlaceholders(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state")
	dir, e := privateDir(path, true)
	if e != nil {
		t.Fatal(e)
	}
	key, _, e := privateFile(dir, "request.key", true)
	if e != nil {
		t.Fatal(e)
	}
	key.Write(bytes.Repeat([]byte{1}, 32))
	key.Sync()
	key.Close()
	file, _, e := privateFile(dir, "critical.db", true)
	if e != nil {
		t.Fatal(e)
	}
	file.Close()
	db, e := openDB(filepath.Join(path, "critical.db"), false)
	if e != nil {
		t.Fatal(e)
	}
	legacy := &Store{db: db, dir: dir}
	if e = legacy.migrate(ctx, testInstallation, seed(t)); e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256([]byte("legacy fixture is not a real issued token"))
	if _, e = db.Exec("INSERT INTO devices(id,token_hash) VALUES(?,?)", testDevice, hash[:]); e != nil {
		t.Fatal(e)
	}
	db.Close()
	dir.Close()
	s, e := Open(ctx, path, "", nil, false, DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	var version int
	var checksum string
	s.db.QueryRow("PRAGMA user_version").Scan(&version)
	s.db.QueryRow("SELECT checksum FROM schema_migrations WHERE version=1").Scan(&checksum)
	original := sha256.Sum256([]byte(migration))
	if version != 5 || checksum != hex.EncodeToString(original[:]) {
		t.Fatal("migration changed v1 history")
	}
	if _, e = s.Authenticate(ctx, hash); !errors.Is(e, ErrUnauthorized) {
		t.Fatal("migration activated placeholder")
	}
	var revoked int
	s.db.QueryRow("SELECT revoked FROM devices WHERE id=?", testDevice).Scan(&revoked)
	if revoked != 1 {
		t.Fatal("legacy credential retained")
	}
	s.Close()
	db, e = openDB(filepath.Join(path, "critical.db"), false)
	if e != nil {
		t.Fatal(e)
	}
	db.Exec("UPDATE schema_migrations SET checksum='tampered' WHERE version=2")
	db.Close()
	if broken, e := Open(ctx, path, "", nil, false, DefaultLimits()); !errors.Is(e, ErrSchema) {
		if broken != nil {
			broken.Close()
		}
		t.Fatal("bad auth checksum accepted")
	}
}

func TestOperationChangeRotationReportsGap(t *testing.T) {
	s, _ := testStore(t, DefaultLimits())
	ctx := context.Background()
	intent(t, s, testOperation, "fixture", "fixture")
	_, epoch, _, e := s.OperationPage(ctx, "", 0, 1, "")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec("UPDATE storage_meta SET operation_floor=10"); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = s.OperationPage(ctx, epoch, 1, 10, ""); !errors.Is(e, ErrCursor) {
		t.Fatal("expired operation cursor accepted")
	}
}

func TestRealV1BackupRestoresThroughV2Migration(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	path := filepath.Join(base, "state")
	dir, e := privateDir(path, true)
	if e != nil {
		t.Fatal(e)
	}
	key := bytes.Repeat([]byte{7}, 32)
	if e = syncWrite(dir, "request.key", key); e != nil {
		t.Fatal(e)
	}
	file, _, e := privateFile(dir, "critical.db", true)
	if e != nil {
		t.Fatal(e)
	}
	file.Close()
	db, e := openDB(filepath.Join(path, "critical.db"), false)
	if e != nil {
		t.Fatal(e)
	}
	legacy := &Store{db: db, dir: dir, path: filepath.Join(path, "critical.db"), key: key, limits: DefaultLimits(), gate: make(chan struct{}, 1), waiting: make(chan struct{}, 32), started: time.Now(), wallStart: time.Now().UTC(), health: Health{Available: true, AuditAvailable: true, SecurityFloorAvailable: true}}
	if e = legacy.migrate(ctx, testInstallation, seed(t)); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("PRAGMA journal_mode=WAL"); e != nil {
		t.Fatal(e)
	}
	running(t, legacy, testOperation, "storage.backup", "storage.maintenance")
	backup := filepath.Join(base, "v1-backup")
	if e = createLegacyBackupFixture(ctx, legacy, backup); e != nil {
		t.Fatal(e)
	}
	if e = legacy.Finish(ctx, testOperation, "succeeded", "applied", "", []byte(`{"complete":true}`)); e != nil {
		t.Fatal(e)
	}
	legacy.Close()
	s, e := Open(ctx, path, "", nil, false, DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	agentID, e := s.AgentID(ctx)
	if e != nil {
		t.Fatal(e)
	}
	control := "44444444-4444-4444-8444-444444444444"
	running(t, s, control, "storage.restore", "storage.maintenance")
	target := filepath.Join(base, "restored")
	if e = s.Restore(ctx, control, backup, target); e != nil {
		t.Fatal(e)
	}
	restored, e := Open(ctx, target, "", nil, false, DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	id, e := restored.AgentID(ctx)
	if e != nil || id != agentID {
		t.Fatal("restore replaced current identity")
	}
	var version int
	restored.db.QueryRow("PRAGMA user_version").Scan(&version)
	if version != 5 {
		t.Fatal("legacy backup not migrated")
	}
}

func TestOpenRejectsBootstrapInstallationMismatch(t *testing.T) {
	s, path := testStore(t, DefaultLimits())
	s.Close()
	if other, e := Open(context.Background(), path, testOperation, nil, false, DefaultLimits()); !errors.Is(e, ErrSafety) {
		if other != nil {
			other.Close()
		}
		t.Fatal("wrong installation accepted")
	}
}

// Exercise an actual schema1 backup rather than asking the current writer to
// bypass its mandatory inventory migration.
func createLegacyBackupFixture(ctx context.Context, s *Store, path string) error {
	f, e := s.exportFloor(ctx)
	if e != nil {
		return e
	}
	dir, e := privateDir(path, true)
	if e != nil {
		return e
	}
	defer dir.Close()
	file, _, e := privateFile(dir, "critical.db", true)
	if e != nil {
		return e
	}
	file.Close()
	dst, e := openDB(descriptorPath(dir)+"/critical.db", false)
	if e != nil {
		return e
	}
	if e = copyDatabase(ctx, s.db, dst); e != nil {
		dst.Close()
		return e
	}
	if _, e = dst.ExecContext(ctx, "PRAGMA journal_mode=DELETE"); e != nil {
		dst.Close()
		return e
	}
	if e = dst.Close(); e != nil {
		return e
	}
	hash, n, e := digestFile(dir, "critical.db", s.limits.PhysicalBytes)
	if e != nil {
		return e
	}
	b, e := s.seal(backupManifest{Version: 1, Installation: f.Installation, Schema: 1, Generation: f.Generation, SHA256: hash, Bytes: n, Consistent: true})
	if e != nil {
		return e
	}
	return syncWrite(dir, "manifest.json", b)
}
