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
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/fileaccess"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/005.sql
var filesMigration string

func migrateFilesDB(ctx context.Context, db *sql.DB) error {
	var v int
	if db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v) != nil {
		return ErrSchema
	}
	if v == 5 {
		return nil
	}
	if v != 4 {
		return ErrSchema
	}
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		return ErrStorage
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, filesMigration); e != nil {
		return ErrStorage
	}
	h := sha256.Sum256([]byte(filesMigration))
	if _, e = tx.ExecContext(ctx, "INSERT INTO schema_migrations VALUES(5,?,?,?)", hex.EncodeToString(h[:]), "development-E08", time.Now().UnixMicro()); e != nil {
		return ErrStorage
	}
	return tx.Commit()
}

type OwnedRegion struct {
	Path  string `json:"path"`
	Proof string `json:"proof"`
}
type InventoryAttestation struct {
	Generation int64                  `json:"generation"`
	Regions    []OwnedRegion          `json:"regions"`
	Absent     []string               `json:"absent_operation_ids"`
	Bindings   []OwnedArtifactBinding `json:"artifact_bindings,omitempty"`
}
type OwnedArtifactBinding struct {
	ID     string `json:"artifact_id"`
	Region string `json:"region_path"`
}
type InventoryConfirmation struct {
	KnownRegions []string               `json:"known_regions"`
	Absent       []string               `json:"absent_operation_ids"`
	Bindings     []OwnedArtifactBinding `json:"artifact_bindings,omitempty"`
}

func ValidateInventoryConfirmation(p InventoryConfirmation) error {
	if p.KnownRegions == nil || p.Absent == nil || len(p.KnownRegions) > 32 || len(p.Absent) != 0 {
		return ErrInvalid
	}
	if len(p.Bindings) > 32 {
		return ErrInvalid
	}
	bindings := map[string]bool{}
	for _, b := range p.Bindings {
		if !ValidID(b.ID) || bindings[b.ID] || !contracts.CleanAbsolutePath(b.Region) || len(b.Region) > 1024 {
			return ErrInvalid
		}
		bindings[b.ID] = true
	}
	for _, path := range p.KnownRegions {
		if !contracts.CleanAbsolutePath(path) || len(path) > 1024 {
			return ErrInvalid
		}
	}
	seen := map[string]bool{}
	for _, id := range p.Absent {
		if !ValidID(id) || seen[id] {
			return ErrInvalid
		}
		seen[id] = true
	}
	return nil
}

// Explicit local operator assertion, audited before this method is invoked.
// No scan and no missing pathname silently establishes completeness.
func (s *Store) ConfirmInventory(ctx context.Context, operationID string, p InventoryConfirmation) error {
	if ValidateInventoryConfirmation(p) != nil {
		return ErrInvalid
	}
	current, e := s.OwnedInventory(ctx)
	if e != nil {
		return e
	}
	att := InventoryAttestation{Generation: current.Generation, Regions: []OwnedRegion{}, Absent: p.Absent, Bindings: p.Bindings}
	paths := append([]string{}, p.KnownRegions...)
	bindings := map[string]string{}
	for _, b := range p.Bindings {
		bindings[b.ID] = b.Region
		paths = append(paths, b.Region)
	}
	absent := map[string]bool{}
	for _, id := range p.Absent {
		absent[id] = true
	}
	for _, record := range current.Artifacts {
		if region, ok := bindings[record.ID]; ok {
			delete(bindings, record.ID)
			// A local operator explicitly reaccounts this retained receipt into
			// an existing protected region. A missing pathname alone never does so.
			old, e := fileaccess.PinAbsolute(record.LocationHint)
			if e == nil {
				old.Close()
				paths = append(paths, record.LocationHint)
			} else if !errors.Is(e, fileaccess.ErrMissing) {
				return ErrSafety
			}
			_ = region
			continue
		}
		if absent[record.ID] {
			delete(absent, record.ID)
			continue
		}
		paths = append(paths, record.LocationHint)
	}
	if len(bindings) != 0 {
		return ErrInvalid
	}
	if len(absent) != 0 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, path := range paths {
		if seen[path] {
			continue
		}
		seen[path] = true
		f, e := fileaccess.PinAbsolute(path)
		if e != nil {
			return ErrSafety
		}
		proof, e := fileaccess.IdentityProof(f)
		f.Close()
		if e != nil {
			return ErrSafety
		}
		att.Regions = append(att.Regions, OwnedRegion{path, proof})
	}
	if len(att.Regions) > 32 {
		return ErrQuota
	}
	b, e := json.Marshal(att)
	if e != nil || len(b) > 16000 {
		return ErrQuota
	}
	e = s.write(ctx, func(tx *sql.Tx) error {
		if e := requireRunning(ctx, tx, operationID, "storage.inventory.confirm"); e != nil {
			return e
		}
		var generation int64
		if tx.QueryRowContext(ctx, "SELECT generation FROM inventory_meta WHERE singleton=1").Scan(&generation) != nil || generation != current.Generation {
			return ErrVersion
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO file_inventory_attestation VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET document=excluded.document", b); e != nil {
			return e
		}
		result, e := tx.ExecContext(ctx, "UPDATE identity SET security_generation=security_generation+1 WHERE security_generation<9223372036854775807")
		if e != nil {
			return e
		}
		n, e := result.RowsAffected()
		if e != nil || n != 1 {
			return ErrQuota
		}
		return nil
	})
	if e != nil {
		return e
	}
	if e = s.publishAuthFloor(ctx); e != nil {
		return ErrSecurityPublish
	}
	return nil
}

type FileJournalRecord struct {
	ID, Kind, Owner, OperationID, State string
	Bytes, Created, Expires             int64
	Document                            json.RawMessage
}

func validFileRecord(r FileJournalRecord) bool {
	if !ValidID(r.ID) || !ValidID(r.OperationID) || (r.Kind != "transfer" && r.Kind != "trash") || !SafeLabel(r.Owner) || r.Bytes < 0 || r.Created <= 0 || r.Expires < r.Created || len(r.Document) > 8192 || !json.Valid(r.Document) {
		return false
	}
	switch r.State {
	case "planned", "receiving", "ready", "published", "trashed", "restored", "purged", "unknown", "failed", "expired":
		return true
	}
	return false
}
func (s *Store) SaveFileRecord(ctx context.Context, operationID string, r FileJournalRecord) error {
	if !validFileRecord(r) {
		return ErrInvalid
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		var action string
		if tx.QueryRowContext(ctx, "SELECT action FROM operations WHERE id=? AND state='running'", operationID).Scan(&action) != nil {
			return ErrSafety
		}
		switch action {
		case "files.write.begin", "files.upload.begin", "files.transfer.commit", "files.move", "files.trash", "trash.restore", "trash.purge", "system.trash.expire", "system.files.cleanup":
		default:
			return ErrSafety
		}
		var count int
		if tx.QueryRowContext(ctx, "SELECT count(*) FROM file_journal WHERE id<>?", r.ID).Scan(&count) != nil {
			return ErrStorage
		}
		if count >= 2048 {
			return ErrQuota
		}
		_, e := tx.ExecContext(ctx, "INSERT INTO file_journal VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,bytes=excluded.bytes,expires=excluded.expires,document=excluded.document", r.ID, r.Kind, r.Owner, r.OperationID, r.State, r.Bytes, r.Created, r.Expires, []byte(r.Document))
		return e
	})
}
func (s *Store) FileRecords(ctx context.Context, kind string) ([]FileJournalRecord, error) {
	if kind != "transfer" && kind != "trash" {
		return nil, ErrInvalid
	}
	out := []FileJournalRecord{}
	e := s.read(ctx, func(ctx context.Context) error {
		rows, e := s.db.QueryContext(ctx, "SELECT id,kind,owner,operation_id,state,bytes,created,expires,document FROM file_journal WHERE kind=? ORDER BY created,id LIMIT 2049", kind)
		if e != nil {
			return ErrStorage
		}
		defer rows.Close()
		for rows.Next() {
			var r FileJournalRecord
			if rows.Scan(&r.ID, &r.Kind, &r.Owner, &r.OperationID, &r.State, &r.Bytes, &r.Created, &r.Expires, &r.Document) != nil || !validFileRecord(r) {
				return ErrSafety
			}
			out = append(out, r)
		}
		if rows.Err() != nil || len(out) > 2048 {
			return ErrQuota
		}
		return nil
	})
	return out, e
}

// Require the published current floor, not a DB-only assertion whose publication
// failed or an older receipt that merely satisfies the minimum startup floor.
func (s *Store) VerifiedInventory(ctx context.Context) (Inventory, error) {
	var out Inventory
	e := s.read(ctx, func(ctx context.Context) error {
		current, e := floorFromDB(ctx, s.db)
		if e != nil {
			return e
		}
		b, e := readPrivate(s.dir, "security-floor.json", 65536)
		if e != nil {
			return ErrSafety
		}
		var exported Floor
		if s.unseal(b, &exported) != nil {
			return ErrSafety
		}
		a, _ := json.Marshal(current)
		b, _ = json.Marshal(exported)
		if !bytes.Equal(a, b) || current.Inventory == nil {
			return ErrSafety
		}
		out = *current.Inventory
		if out.Attestation == nil || out.Attestation.Generation != out.Generation {
			return ErrSafety
		}
		return nil
	})
	return out, e
}

func (s *Store) TransferProgress(ctx context.Context, id, owner, from, to string, document []byte, c *Credential) error {
	if !ValidID(id) || len(document) > 8192 || !json.Valid(document) || (from != "receiving" && from != "ready" && from != "failed") || (to != "ready" && to != "unknown" && to != "failed" && to != "receiving" && to != "expired") || (to == "receiving" && from != "failed") {
		return ErrInvalid
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		if e := credentialCheck(ctx, tx, c); e != nil {
			return e
		}
		if to == "ready" || to == "receiving" {
			var spec struct{ Revision string }
			if json.Unmarshal(document, &spec) != nil {
				return ErrInvalid
			}
			want, e := strconv.ParseInt(spec.Revision, 10, 64)
			if e != nil || want < 1 {
				return ErrInvalid
			}
			var current int64
			if tx.QueryRowContext(ctx, "SELECT revision FROM settings WHERE singleton=1").Scan(&current) != nil || current != want {
				return ErrVersion
			}
		}
		var begin string
		if tx.QueryRowContext(ctx, "SELECT operation_id FROM file_journal WHERE id=? AND kind='transfer' AND owner=? AND state=?", id, owner, from).Scan(&begin) != nil {
			return ErrSafety
		}
		var action, state string
		if tx.QueryRowContext(ctx, "SELECT action,state FROM operations WHERE id=? AND actor=?", begin, owner).Scan(&action, &state) != nil || (action != "files.upload.begin" && action != "files.write.begin") || state != "succeeded" {
			return ErrSafety
		}
		if to == "receiving" {
			operation, e := scanOperation(tx.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM operations WHERE id=?", begin))
			if e != nil {
				return e
			}
			if e = s.audit(tx, operation, "file_transfer", "intent", "TRANSFER_RETRY", "none", time.Now().UnixMicro()); e != nil {
				return e
			}
		}
		if to == "ready" || to == "failed" || to == "expired" {
			operation, e := scanOperation(tx.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM operations WHERE id=?", begin))
			if e != nil {
				return e
			}
			code := "TRANSFER_READY"
			effect := "applied"
			if to != "ready" {
				code = "TRANSFER_FAILED"
				effect = "partial"
			}
			if e = s.audit(tx, operation, "file_transfer", "result", code, effect, time.Now().UnixMicro()); e != nil {
				return e
			}
		}
		_, e := tx.ExecContext(ctx, "UPDATE file_journal SET state=?,document=? WHERE id=?", to, document, id)
		return e
	})
}

func (s *Store) TrustedExpiry() bool {
	trusted := false
	_ = s.read(context.Background(), func(context.Context) error { trusted = s.trustworthyClock(time.Now()); return nil })
	return trusted
}

// Offline wall-clock time is not evidence of age. After restart a full record
// retention interval measured in this process is a conservative lower bound.
func (s *Store) FileRetentionElapsed(ctx context.Context, retention time.Duration) bool {
	if retention <= 0 || retention > 365*24*time.Hour {
		return false
	}
	elapsed := false
	_ = s.read(ctx, func(context.Context) error { elapsed = time.Since(s.started) >= retention; return nil })
	return elapsed
}

func (s *Store) FilePhase(ctx context.Context, id, phase string) error {
	switch phase {
	case "copy", "verify", "publish", "source_trash", "source_cleanup":
	default:
		return ErrInvalid
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		r, e := tx.ExecContext(ctx, "UPDATE operations SET phase=?,revision=revision+1,updated=? WHERE id=? AND state='running' AND revision<9223372036854775807", phase, time.Now().UnixMicro(), id)
		if e != nil {
			return e
		}
		n, e := r.RowsAffected()
		if e != nil || n != 1 {
			return ErrSafety
		}
		return s.change(tx, id)
	})
}

// Metadata rotation is an audited operation; unfinished/unknown objects never
// qualify, and their only identity proof cannot be evicted for capacity.
func (s *Store) RotateFileRecords(ctx context.Context, id string) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		var action, actor string
		if tx.QueryRowContext(ctx, "SELECT action,actor FROM operations WHERE id=? AND state='running'", id).Scan(&action, &actor) != nil || action != "system.files.rotate" || actor != "system:files" || !s.trustworthyClock(time.Now()) {
			return ErrSafety
		}
		_, e := tx.ExecContext(ctx, "DELETE FROM file_journal WHERE id IN (SELECT id FROM file_journal WHERE state IN ('published','restored','purged') AND expires<? ORDER BY expires LIMIT 256)", time.Now().Add(-7*24*time.Hour).UnixMicro())
		return e
	})
}

func FileRecordVersion(r FileJournalRecord) string {
	b, e := json.Marshal(r)
	if e != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (s *Store) InstallationID(ctx context.Context) (string, error) {
	var id string
	e := s.read(ctx, func(ctx context.Context) error {
		return s.db.QueryRowContext(ctx, "SELECT installation_id FROM identity").Scan(&id)
	})
	if e != nil || !ValidID(id) {
		return "", ErrSafety
	}
	return id, nil
}

// Reconciliation changes only the journal after explicit offline inspection.
// It never retries a filesystem effect or releases an unknown operation lock.
func (s *Store) ReconcileFileRecord(ctx context.Context, operationID, expected string, r FileJournalRecord) error {
	if !validFileRecord(r) {
		return ErrInvalid
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		var action, actor string
		if tx.QueryRowContext(ctx, "SELECT action,actor FROM operations WHERE id=? AND state='running'", operationID).Scan(&action, &actor) != nil || action != "files.reconcile" || !strings.HasPrefix(actor, "local:") {
			return ErrSafety
		}
		var old FileJournalRecord
		if tx.QueryRowContext(ctx, "SELECT id,kind,owner,operation_id,state,bytes,created,expires,document FROM file_journal WHERE id=?", r.ID).Scan(&old.ID, &old.Kind, &old.Owner, &old.OperationID, &old.State, &old.Bytes, &old.Created, &old.Expires, &old.Document) != nil {
			return ErrNotFound
		}
		if FileRecordVersion(old) != expected || (old.State != "unknown" && old.State != "planned" && old.State != "receiving" && old.State != "ready" && old.State != "failed" && old.State != "expired") {
			return ErrVersion
		}
		_, e := tx.ExecContext(ctx, "UPDATE file_journal SET state=?,bytes=?,document=? WHERE id=?", r.State, r.Bytes, []byte(r.Document), r.ID)
		return e
	})
}
