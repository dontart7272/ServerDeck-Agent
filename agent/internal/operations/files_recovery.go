// SPDX-License-Identifier: Apache-2.0
package operations

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/fileaccess"
	"serverdeck.local/agent/internal/storage"
	"strings"
)

type fileReconcileParams struct {
	ID            string `json:"record_id"`
	Expected      string `json:"expected_version"`
	State         string `json:"state"`
	ObservedProof string `json:"observed_proof,omitempty"`
}
type recoveryFileSpec struct {
	RestoredProof                                                                                     string
	RootPath, Proof, AreaProof, NativeVersion, TreeDigest, Version, RecoveryOperationID, RootID, Name string
	Parent                                                                                            fileaccess.Location
	RestoreRoot, RestoreName                                                                          string
	RestoreTarget                                                                                     *fileaccess.Location
}
type fileReconcileHandler struct {
	s          *storage.Store
	protection *fileaccess.Guard
}

func (h fileReconcileHandler) Validate(b []byte) error {
	if _, e := contracts.Validate(bytes.NewReader(b), contracts.Target{Family: "api", Definition: "FileReconcileInput"}, 65536); e != nil {
		return storage.ErrInvalid
	}
	var p fileReconcileParams
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || !storage.ValidID(p.ID) || len(p.Expected) != 64 {
		return storage.ErrInvalid
	}
	if p.State == "discard" && (p.ObservedProof == "" || h.protection == nil) {
		return storage.ErrSafety
	}
	switch p.State {
	case "trashed", "purged", "published", "restored", "discard":
		return nil
	}
	return storage.ErrInvalid
}
func (fileReconcileHandler) Keys(Request) ([]string, error) { return []string{"files.reconcile"}, nil }
func (h fileReconcileHandler) Check(ctx context.Context, r Request) error {
	if !strings.HasPrefix(r.Actor, "local:") || r.Actor != Local().ID() {
		return storage.ErrUnauthorized
	}
	var p fileReconcileParams
	json.Unmarshal(r.Params, &p)
	rows, e := h.s.FileRecords(ctx, "transfer")
	if e != nil {
		return e
	}
	trash, e := h.s.FileRecords(ctx, "trash")
	if e != nil {
		return e
	}
	rows = append(rows, trash...)
	for _, row := range rows {
		if row.ID == p.ID {
			if storage.FileRecordVersion(row) != p.Expected || (row.State != "unknown" && row.State != "planned" && row.State != "receiving" && row.State != "ready" && row.State != "failed" && row.State != "expired") {
				return storage.ErrVersion
			}
			return nil
		}
	}
	return storage.ErrNotFound
}
func (h fileReconcileHandler) Effect(ctx context.Context, r Request) Outcome {
	if e := h.Check(ctx, r); e != nil {
		return Outcome{State: "failed", Effect: "none", Code: "OBJECT_CHANGED"}
	}
	var p fileReconcileParams
	json.Unmarshal(r.Params, &p)
	rows, _ := h.s.FileRecords(ctx, "transfer")
	trash, _ := h.s.FileRecords(ctx, "trash")
	rows = append(rows, trash...)
	var row storage.FileJournalRecord
	for _, v := range rows {
		if v.ID == p.ID {
			row = v
			break
		}
	}
	var spec recoveryFileSpec
	var doc map[string]json.RawMessage
	if json.Unmarshal(row.Document, &spec) != nil || json.Unmarshal(row.Document, &doc) != nil || !contracts.CleanAbsolutePath(spec.RootPath) {
		return Outcome{State: "failed", Effect: "none", Code: "SAFETY_UNAVAILABLE"}
	}
	pin, e := h.s.ProtectionDirectory(ctx)
	if e != nil {
		return Outcome{State: "failed", Effect: "none", Code: "SAFETY_UNAVAILABLE"}
	}
	g := h.protection
	if g == nil {
		g, e = fileaccess.New([]*os.File{pin})
		if e == nil {
			defer g.Close()
			g.EnableSharedRoots()
		}
	}
	pin.Close()
	if e != nil {
		return Outcome{State: "failed", Effect: "none", Code: "SAFETY_UNAVAILABLE"}
	}
	id, e := h.s.AgentID(ctx)
	if e != nil {
		return Outcome{State: "failed", Effect: "none", Code: "SAFETY_UNAVAILABLE"}
	}
	a, e := g.OpenArea(spec.RootPath, id)
	if errors.Is(e, fileaccess.ErrMissing) && p.State == "purged" && spec.Proof == "" && spec.AreaProof == "" {
		row.State = "purged"
		if e = h.s.ReconcileFileRecord(ctx, r.ID, p.Expected, row); e != nil {
			return Outcome{State: "unknown", Effect: "unknown", Code: "RECOVERY_REQUIRED"}
		}
		return Outcome{State: "succeeded", Effect: "applied", Result: []byte(`{"reconciled":true}`)}
	}
	if e != nil {
		return Outcome{State: "failed", Effect: "none", Code: "SAFETY_UNAVAILABLE"}
	}
	defer a.Close()
	areaProof, e := a.Proof()
	if e != nil || (spec.AreaProof != "" && spec.AreaProof != areaProof) {
		return Outcome{State: "failed", Effect: "none", Code: "SAFETY_UNAVAILABLE"}
	}
	entry, entryErr := a.Entry(row.ID)
	if p.State == "discard" {
		if entryErr != nil {
			return Outcome{State: "failed", Effect: "none", Code: "SAFETY_UNAVAILABLE"}
		}
		proof, pe := fileaccess.IdentityProof(entry)
		version, ve := fileaccess.Version(entry)
		entry.Close()
		if pe != nil || ve != nil || p.ObservedProof == "" || proof != p.ObservedProof || (spec.Proof != "" && spec.Proof != proof) {
			return Outcome{State: "failed", Effect: "none", Code: "OBJECT_CHANGED"}
		}
		if e = a.Purge(ctx, row.ID, version); e != nil {
			return Outcome{State: "unknown", Effect: "unknown", Code: "RECOVERY_REQUIRED"}
		}
		p.State = "purged"
		row.State = "purged"
		if e = h.s.ReconcileFileRecord(ctx, r.ID, p.Expected, row); e != nil {
			return Outcome{State: "unknown", Effect: "unknown", Code: "RECOVERY_REQUIRED"}
		}
		return Outcome{State: "succeeded", Effect: "applied", Result: []byte(`{"discarded":true}`)}
	}
	if p.State == "trashed" {
		if row.Kind != "trash" || entryErr != nil {
			return Outcome{State: "failed", Effect: "none", Code: "SAFETY_UNAVAILABLE"}
		}
		proof, e := fileaccess.IdentityProof(entry)
		version, ve := fileaccess.Version(entry)
		entry.Close()
		if e != nil || ve != nil || (spec.Proof != "" && spec.Proof != proof) {
			return Outcome{State: "failed", Effect: "none", Code: "OBJECT_CHANGED"}
		}
		tree, e := a.Scan(ctx, row.ID, 1000000000000)
		if e != nil {
			return Outcome{State: "failed", Effect: "none", Code: "SAFETY_UNAVAILABLE"}
		}
		set := func(k string, v any) { doc[k], _ = json.Marshal(v) }
		set("Proof", proof)
		set("AreaProof", areaProof)
		set("NativeVersion", version)
		set("TreeDigest", tree.Digest)
		b, _ := json.Marshal([]string{row.ID, version, tree.Digest})
		sum := sha256.Sum256(b)
		set("Version", hex.EncodeToString(sum[:]))
		row.Bytes = tree.Bytes
	} else {
		if entryErr == nil {
			entry.Close()
			return Outcome{State: "failed", Effect: "none", Code: "OBJECT_CHANGED"}
		}
		if !errors.Is(entryErr, fileaccess.ErrMissing) {
			return Outcome{State: "failed", Effect: "none", Code: "SAFETY_UNAVAILABLE"}
		}
		if p.State != "purged" {
			root := spec.RootPath
			parent := spec.Parent
			name := spec.Name
			if p.State == "restored" {
				if row.Kind != "trash" || spec.RestoreTarget == nil {
					return Outcome{State: "failed", Effect: "none", Code: "SAFETY_UNAVAILABLE"}
				}
				root = spec.RestoreRoot
				parent = *spec.RestoreTarget
				name = spec.RestoreName
			} else if row.Kind != "transfer" {
				return Outcome{State: "failed", Effect: "none", Code: "SAFETY_UNAVAILABLE"}
			}
			loc, e := fileaccess.Child(parent, name)
			if e != nil {
				return Outcome{State: "failed", Effect: "none", Code: "SAFETY_UNAVAILABLE"}
			}
			f, e := g.Open(root, loc)
			if e != nil {
				return Outcome{State: "failed", Effect: "none", Code: "SAFETY_UNAVAILABLE"}
			}
			proof, e := fileaccess.IdentityProof(f)
			f.Close()
			wanted := spec.Proof
			if p.State == "restored" && spec.RestoredProof != "" {
				wanted = spec.RestoredProof
			}
			if e != nil || wanted == "" || proof != wanted {
				return Outcome{State: "failed", Effect: "none", Code: "OBJECT_CHANGED"}
			}
		}
	}
	row.State = p.State
	row.Document, _ = json.Marshal(doc)
	if e := h.s.ReconcileFileRecord(ctx, r.ID, p.Expected, row); e != nil {
		return Outcome{State: "unknown", Effect: "unknown", Code: "RECOVERY_REQUIRED"}
	}
	return Outcome{State: "succeeded", Effect: "applied", Result: []byte(`{"reconciled":true}`)}
}
