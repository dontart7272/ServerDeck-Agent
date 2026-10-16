// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestE08InventoryReceiptFailurePreventsDestination(t *testing.T) {
	s, path := testStore(t, DefaultLimits())
	ctx := context.Background()
	running(t, s, testOperation, "storage.backup", "storage.maintenance")
	// Preparing the next receipt must fail after the DB transaction, while the
	// existing floor remains valid for pre-effect verification.
	if e := os.Mkdir(filepath.Join(path, "security-floor.next"), 0700); e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(filepath.Dir(path), "copy")
	if e := s.Backup(ctx, testOperation, target); !errors.Is(e, ErrSecurityPublish) {
		t.Fatalf("publication: %v", e)
	}
	if _, e := os.Lstat(target); !os.IsNotExist(e) {
		t.Fatal("destination created without receipt")
	}
	i, e := s.OwnedInventory(ctx)
	if e != nil || len(i.Artifacts) != 1 || i.Baseline != "unknown" {
		t.Fatalf("durable unknown receipt: %+v %v", i, e)
	}
}
func TestE08InventoryRestoreRetainsCurrentFootprints(t *testing.T) {
	s, path := testStore(t, DefaultLimits())
	ctx := context.Background()
	running(t, s, testOperation, "storage.backup", "storage.maintenance")
	backup := filepath.Join(filepath.Dir(path), "backup")
	if e := s.Backup(ctx, testOperation, backup); e != nil {
		t.Fatal(e)
	}
	if e := s.Finish(ctx, testOperation, "succeeded", "applied", "", []byte("null")); e != nil {
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
	i, e := restored.OwnedInventory(ctx)
	if e != nil || i.Generation != 3 || len(i.Artifacts) != 2 || i.Baseline != "unknown" {
		t.Fatalf("current inventory lost: %+v %v", i, e)
	}
	// Even a greater security generation must not legitimize missing receipts.
	if _, e := restored.db.Exec("DELETE FROM owned_artifacts;UPDATE identity SET security_generation=security_generation+1"); e != nil {
		t.Fatal(e)
	}
	if e := restored.verifyFloor(ctx); !errors.Is(e, ErrSafety) {
		t.Fatalf("rollback accepted: %v", e)
	}
}
func TestE08InventoryQuotaNeverEvictsUnknown(t *testing.T) {
	s, path := testStore(t, DefaultLimits())
	ctx := context.Background()
	for n := 0; n < maxOwnedArtifacts; n++ {
		id, e := RandomID()
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.reserveOwned(ctx, id, "backup", filepath.Join(path, "copy")); e != nil {
			t.Fatal(e)
		}
	}
	id, _ := RandomID()
	if _, e := s.reserveOwned(ctx, id, "restore", filepath.Join(path, "next")); !errors.Is(e, ErrQuota) {
		t.Fatalf("quota: %v", e)
	}
	i, e := s.OwnedInventory(ctx)
	if e != nil || len(i.Artifacts) != maxOwnedArtifacts {
		t.Fatal("unknown footprints evicted")
	}
	b, e := s.seal(Floor{Version: 3, Inventory: &i})
	if e != nil || len(b) > 65536 {
		t.Fatal("floor exceeds bounded decoder")
	}
}

func TestE08LegacyInventoryMigrationNeverInfersCompleteness(t *testing.T) {
	s, path := testStore(t, DefaultLimits())
	ctx := context.Background()
	if _, e := s.db.Exec("DROP TABLE file_inventory_attestation;DROP TABLE file_journal;DROP TABLE owned_artifacts;DROP TABLE inventory_meta;DELETE FROM schema_migrations WHERE version>=4;PRAGMA user_version=3"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.exportFloor(ctx); e != nil {
		t.Fatal(e)
	}
	s.Close()
	reopened, e := Open(ctx, path, "", nil, false, DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	i, e := reopened.OwnedInventory(ctx)
	if e != nil || i.Baseline != "unknown" || len(i.Artifacts) != 0 {
		t.Fatal("legacy absence inferred complete")
	}
	var version int
	if e := reopened.db.QueryRow("PRAGMA user_version").Scan(&version); e != nil || version != 5 {
		t.Fatal("migration4 missing")
	}
	f, e := floorFromDB(ctx, reopened.db)
	if e != nil || f.Version != 5 || f.Inventory == nil {
		t.Fatal("floor3 missing")
	}
}

func TestE08InventoryDatabaseFailurePreventsDestination(t *testing.T) {
	s, path := testStore(t, DefaultLimits())
	ctx := context.Background()
	running(t, s, testOperation, "storage.backup", "storage.maintenance")
	if _, e := s.db.Exec("CREATE TRIGGER inventory_failure BEFORE INSERT ON owned_artifacts BEGIN SELECT RAISE(ABORT,'fixture'); END"); e != nil {
		t.Fatal(e)
	}
	// Direct reservation tests the real SQLite failure below compatibility;
	// Backup itself additionally rejects any unexpected live schema.
	if _, e := s.reserveOwned(ctx, testOperation, "backup", filepath.Join(path, "copy")); e == nil {
		t.Fatal("receipt write failure ignored")
	}
	i, e := s.OwnedInventory(ctx)
	if e != nil || len(i.Artifacts) != 0 {
		t.Fatal("failed transaction left receipt")
	}
	if _, e := os.Lstat(filepath.Join(path, "copy")); !os.IsNotExist(e) {
		t.Fatal("destination effect before receipt")
	}
}

func TestE08DivergentBackupInventoryRefusedBeforeRestore(t *testing.T) {
	s, path := testStore(t, DefaultLimits())
	ctx := context.Background()
	running(t, s, testOperation, "storage.backup", "storage.maintenance")
	backup := filepath.Join(filepath.Dir(path), "backup")
	if e := s.Backup(ctx, testOperation, backup); e != nil {
		t.Fatal(e)
	}
	if e := s.Finish(ctx, testOperation, "succeeded", "applied", "", []byte("null")); e != nil {
		t.Fatal(e)
	}
	// Directed divergent-authority fixture; normal runtime never deletes receipts.
	if _, e := s.db.Exec("DELETE FROM owned_artifacts;UPDATE identity SET security_generation=security_generation+1"); e != nil {
		t.Fatal(e)
	}
	id := "44444444-4444-4444-8444-444444444444"
	running(t, s, id, "storage.restore", "storage.maintenance")
	target := filepath.Join(filepath.Dir(path), "divergent")
	if e := s.Restore(ctx, id, backup, target); !errors.Is(e, ErrSafety) {
		t.Fatalf("missing backup receipt accepted: %v", e)
	}
	if _, e := os.Lstat(target); !os.IsNotExist(e) {
		t.Fatal("destination created before inventory consistency check")
	}
}
