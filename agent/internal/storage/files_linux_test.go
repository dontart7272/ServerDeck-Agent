//go:build linux && cgo

// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestE08InventoryPublishedAssertionAndInvalidation(t *testing.T) {
	s, path := testStore(t, DefaultLimits())
	ctx := context.Background()
	if _, e := s.VerifiedInventory(ctx); e == nil {
		t.Fatal("unattested baseline accepted")
	}
	region := filepath.Join(filepath.Dir(path), "owned")
	if e := os.Mkdir(region, 0700); e != nil {
		t.Fatal(e)
	}
	running(t, s, testOperation, "storage.inventory.confirm", "storage.maintenance")
	if e := s.ConfirmInventory(ctx, testOperation, InventoryConfirmation{KnownRegions: []string{region}, Absent: []string{}}); e != nil {
		t.Fatal(e)
	}
	i, e := s.VerifiedInventory(ctx)
	if e != nil || i.Attestation == nil || len(i.Attestation.Regions) != 1 {
		t.Fatal("published assertion absent", e)
	}
	id, _ := RandomID()
	if _, e := s.reserveOwned(ctx, id, "backup", filepath.Join(region, "copy")); e != nil {
		t.Fatal(e)
	}
	if _, e := s.VerifiedInventory(ctx); e == nil {
		t.Fatal("new footprint did not invalidate assertion")
	}
}
func TestE08InventoryCannotHideKnownCopyByAbsenceClaim(t *testing.T) {
	if ValidateInventoryConfirmation(InventoryConfirmation{KnownRegions: []string{}, Absent: []string{testOperation}}) == nil {
		t.Fatal("known footprint can be silently excluded")
	}
}

func TestE08ExplicitRegionReaccountingRetainsReceiptAfterMaintenance(t *testing.T) {
	s, path := testStore(t, DefaultLimits())
	ctx := context.Background()
	old := filepath.Join(filepath.Dir(path), "owned-old")
	moved := filepath.Join(filepath.Dir(path), "owned-moved")
	if e := os.Mkdir(old, 0700); e != nil {
		t.Fatal(e)
	}
	receipt, _ := RandomID()
	if _, e := s.reserveOwned(ctx, receipt, "backup", old); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(old, moved); e != nil {
		t.Fatal(e)
	}
	id, _ := RandomID()
	running(t, s, id, "storage.inventory.confirm", "storage.maintenance")
	if e := s.ConfirmInventory(ctx, id, InventoryConfirmation{KnownRegions: []string{moved}, Absent: []string{}}); e == nil {
		t.Fatal("missing hint inferred ownership correlation")
	}
	if e := s.ConfirmInventory(ctx, id, InventoryConfirmation{KnownRegions: []string{}, Absent: []string{}, Bindings: []OwnedArtifactBinding{{ID: receipt, Region: moved}}}); e != nil {
		t.Fatal(e)
	}
	inventory, e := s.VerifiedInventory(ctx)
	if e != nil || len(inventory.Artifacts) != 1 || inventory.Artifacts[0].LocationHint != old || len(inventory.Attestation.Bindings) != 1 {
		t.Fatal("receipt dropped/replaced", e)
	}
	f, e := floorFromDB(ctx, s.db)
	if e != nil || f.Version != 5 {
		t.Fatal("minimum writer gate missing", e)
	}
	if ValidateInventoryConfirmation(InventoryConfirmation{KnownRegions: []string{}, Absent: []string{}, Bindings: []OwnedArtifactBinding{{ID: receipt, Region: moved}, {ID: receipt, Region: moved}}}) == nil {
		t.Fatal("duplicate reaccounting accepted")
	}
}
