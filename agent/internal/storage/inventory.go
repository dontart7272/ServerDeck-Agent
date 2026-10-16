// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"time"
)

//go:embed migrations/004.sql
var inventoryMigration string

// Inventory is rollback authority, not proof that path hints still identify
// objects. Unknown baseline deliberately prevents production file reads.
type Inventory struct {
	Generation  int64                 `json:"generation"`
	Baseline    string                `json:"baseline"`
	Artifacts   []OwnedArtifact       `json:"artifacts"`
	Attestation *InventoryAttestation `json:"attestation,omitempty"`
}
type OwnedArtifact struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	LocationHint string `json:"location_hint"`
	State        string `json:"state"`
}

const maxOwnedArtifacts = 32

func migrateInventoryDB(ctx context.Context, db *sql.DB) error {
	var v int
	if db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v) != nil {
		return ErrSchema
	}
	if v == 4 || v == 5 {
		return nil
	}
	if v != 3 {
		return ErrSchema
	}
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		return ErrStorage
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, inventoryMigration); e != nil {
		return ErrStorage
	}
	h := sha256.Sum256([]byte(inventoryMigration))
	if _, e = tx.ExecContext(ctx, "INSERT INTO schema_migrations VALUES(4,?,?,?)", hex.EncodeToString(h[:]), "development-E08", time.Now().UnixMicro()); e != nil {
		return ErrStorage
	}
	return tx.Commit()
}
func inventoryFromDB(ctx context.Context, db *sql.DB) (Inventory, error) {
	i := Inventory{Artifacts: []OwnedArtifact{}}
	if db.QueryRowContext(ctx, "SELECT generation,baseline FROM inventory_meta WHERE singleton=1").Scan(&i.Generation, &i.Baseline) != nil || i.Generation < 1 || i.Baseline != "unknown" {
		return i, ErrSafety
	}
	rows, e := db.QueryContext(ctx, "SELECT id,kind,location_hint,state FROM owned_artifacts ORDER BY id LIMIT 33")
	if e != nil {
		return i, ErrSafety
	}
	defer rows.Close()
	for rows.Next() {
		var a OwnedArtifact
		if rows.Scan(&a.ID, &a.Kind, &a.LocationHint, &a.State) != nil || !ValidID(a.ID) || (a.Kind != "backup" && a.Kind != "restore") || a.State != "unknown" || !filepath.IsAbs(a.LocationHint) || filepath.Clean(a.LocationHint) != a.LocationHint || len(a.LocationHint) > 1024 || strings.ContainsRune(a.LocationHint, 0) {
			return i, ErrSafety
		}
		i.Artifacts = append(i.Artifacts, a)
	}
	if rows.Err() != nil || len(i.Artifacts) > maxOwnedArtifacts {
		return i, ErrSafety
	}
	var version int
	if db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version) != nil {
		return i, ErrSafety
	}
	if version >= 5 {
		var b []byte
		e := db.QueryRowContext(ctx, "SELECT document FROM file_inventory_attestation WHERE singleton=1").Scan(&b)
		if e == nil {
			var att InventoryAttestation
			if json.Unmarshal(b, &att) != nil || att.Generation < 1 || att.Generation > i.Generation || len(att.Regions) > 32 || len(att.Absent) > 32 {
				return i, ErrSafety
			}
			i.Attestation = &att
		} else if e != sql.ErrNoRows {
			return i, ErrSafety
		}
	}
	return i, nil
}
func (s *Store) OwnedInventory(ctx context.Context) (Inventory, error) {
	var out Inventory
	e := s.read(ctx, func(ctx context.Context) error { var e error; out, e = inventoryFromDB(ctx, s.db); return e })
	return out, e
}

// Called under the maintenance gate, after audited intent but BEFORE creating
// a destination. Receipt publication failure forbids any destination effect.
// Unknown entries never expire with their operation and are never evicted.
func (s *Store) reserveOwned(ctx context.Context, id, kind, path string) (Floor, error) {
	if !ValidID(id) || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 1024 || strings.ContainsRune(path, 0) {
		return Floor{}, ErrInvalid
	}
	if e := s.verifyFloor(ctx); e != nil {
		return Floor{}, e
	}
	if e := s.admission(ctx); e != nil {
		return Floor{}, s.failure(e)
	}
	current, e := inventoryFromDB(ctx, s.db)
	if e != nil {
		return Floor{}, e
	}
	current.Artifacts = append(current.Artifacts, OwnedArtifact{id, kind, path, "unknown"})
	encoded, e := json.Marshal(current)
	if e != nil || len(encoded) > 32000 {
		return Floor{}, ErrQuota
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return Floor{}, ErrStorage
	}
	defer tx.Rollback()
	var count int
	if tx.QueryRowContext(ctx, "SELECT count(*) FROM owned_artifacts").Scan(&count) != nil {
		return Floor{}, ErrSafety
	}
	if count >= maxOwnedArtifacts {
		return Floor{}, ErrQuota
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO owned_artifacts VALUES(?,?,?,'unknown')", id, kind, path); e != nil {
		return Floor{}, ErrSafety
	}
	if result, e := tx.ExecContext(ctx, "UPDATE inventory_meta SET generation=generation+1 WHERE generation<9223372036854775807"); e != nil {
		return Floor{}, ErrSafety
	} else if n, e := result.RowsAffected(); e != nil || n != 1 {
		return Floor{}, ErrQuota
	}
	result, e := tx.ExecContext(ctx, "UPDATE identity SET security_generation=security_generation+1 WHERE security_generation<9223372036854775807")
	if e != nil {
		return Floor{}, ErrSafety
	}
	n, e := result.RowsAffected()
	if e != nil || n != 1 {
		return Floor{}, ErrQuota
	}
	if e = tx.Commit(); e != nil {
		return Floor{}, ErrStorage
	}
	// A second admission establishes a fresh WAL boundary before the floor's
	// floor_required write, rather than treating two transactions as one bound.
	if e := s.admission(ctx); e != nil {
		s.healthMu.Lock()
		s.health.SecurityFloorAvailable = false
		s.healthMu.Unlock()
		return Floor{}, ErrSecurityPublish
	}
	f, e := s.exportFloor(ctx)
	s.healthMu.Lock()
	s.health.SecurityFloorAvailable = e == nil
	s.healthMu.Unlock()
	if e != nil {
		return f, ErrSecurityPublish
	}
	return f, nil
}

func inventoryContains(current, required *Inventory) bool {
	if current == nil || required == nil || current.Generation < required.Generation || current.Baseline != "unknown" || required.Baseline != "unknown" {
		return false
	}
	for _, want := range required.Artifacts {
		found := false
		for _, got := range current.Artifacts {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
