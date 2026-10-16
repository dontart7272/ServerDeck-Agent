// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"serverdeck.local/agent/internal/fileaccess"
	"serverdeck.local/agent/internal/operations"
	"serverdeck.local/agent/internal/storage"
	"time"
)

func (s *fileService) rememberDeadline(r storage.FileJournalRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deadlines == nil {
		s.deadlines = map[string]time.Time{}
	}
	s.deadlines[r.ID] = time.Now().Add(time.Duration(r.Expires-r.Created) * time.Microsecond)
}
func (g *Gateway) fileExpired(r storage.FileJournalRecord) bool {
	g.Files.mu.Lock()
	deadline, ok := g.Files.deadlines[r.ID]
	ticket := g.Files.uploads[r.ID]
	g.Files.mu.Unlock()
	if r.Kind == "transfer" && ticket != nil {
		ticket.mu.Lock()
		idle := !ticket.busy && time.Since(ticket.used) >= 300*time.Second
		ticket.mu.Unlock()
		if idle {
			return true
		}
	}
	if ok {
		return !time.Now().Before(deadline)
	}
	return g.Store.FileRetentionElapsed(context.Background(), time.Duration(r.Expires-r.Created)*time.Microsecond)
}
func maintenanceFileID(action, id string) string {
	h := sha256.Sum256([]byte("serverdeck-file-maintenance-v1:" + action + ":" + id))
	h[6] = (h[6] & 15) | 64
	h[8] = (h[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[:4], h[4:6], h[6:8], h[8:10], h[10:16])
}
func (g *Gateway) startFileMaintenance() {
	ctx, cancel := context.WithCancel(context.Background())
	g.fileCancel = cancel
	g.fileDone = make(chan struct{})
	go func() {
		defer close(g.fileDone)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				g.sweepFiles(ctx)
			}
		}
	}()
}
func (g *Gateway) sweepFiles(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if g.filesReady(ctx) != nil {
		return
	}
	for _, kind := range []string{"trash", "transfer"} {
		rows, e := g.Store.FileRecords(ctx, kind)
		if e != nil {
			return
		}
		for _, row := range rows {
			if ctx.Err() != nil {
				return
			}
			action := "system.trash.expire"
			expected := ""
			if kind == "trash" {
				var spec trashSpec
				if row.State != "trashed" || !g.fileExpired(row) || json.Unmarshal(row.Document, &spec) != nil {
					continue
				}
				expected = spec.Version
				if spec.NativeVersion != "" && spec.TreeDigest != "" {
					expected = scopeJSON([]string{row.ID, spec.NativeVersion, spec.TreeDigest})
				}
			} else {
				var spec writeSpec
				if json.Unmarshal(row.Document, &spec) != nil || spec.Mode == "move" || spec.RecoveryOperationID != "" || spec.Proof == "" || (row.State != "receiving" && row.State != "ready" && row.State != "unknown" && row.State != "failed" && row.State != "expired") || !g.fileExpired(row) {
					continue
				}
				action = "system.files.cleanup"
				expected = scopeJSON([]string{row.ID, row.State, string(row.Document)})
			}
			params, _ := json.Marshal(purgeParams{row.ID, expected})
			r := operations.Request{ID: maintenanceFileID(action, row.ID), Action: action, Params: params}
			actor := operations.FileMaintenanceInitiator()
			p, e := g.Operations.Prepare(ctx, actor, r)
			if e != nil {
				continue
			}
			r.Plan = p.ID
			_, _ = g.Operations.Execute(ctx, actor, r)
		}
	}
	rows, e := g.Store.FileRecords(ctx, "transfer")
	if e != nil {
		return
	}
	trash, e := g.Store.FileRecords(ctx, "trash")
	if e != nil {
		return
	}
	rows = append(rows, trash...)
	if len(rows) < 1024 || !g.Store.TrustedExpiry() {
		return
	}
	pending := false
	cutoff := time.Now().Add(-7 * 24 * time.Hour).UnixMicro()
	for _, r := range rows {
		if (r.State == "published" || r.State == "purged" || r.State == "restored") && r.Expires < cutoff {
			pending = true
			break
		}
	}
	if pending {
		r := operations.Request{ID: maintenanceFileID("rotate", time.Now().UTC().Format("2006-01-02T15:04")), Action: "system.files.rotate", Params: []byte(`{}`)}
		a := operations.FileMaintenanceInitiator()
		p, e := g.Operations.Prepare(ctx, a, r)
		if e == nil {
			r.Plan = p.ID
			_, _ = g.Operations.Execute(ctx, a, r)
		}
	}
}

type fileCleanupHandler struct{ g *Gateway }

func (h fileCleanupHandler) Validate(b []byte) error {
	return (fileTrashHandler{h.g, "trash.purge"}).Validate(b)
}
func (h fileCleanupHandler) Keys(operations.Request) ([]string, error) {
	return []string{"files.mutations", "settings.runtime"}, nil
}
func (h fileCleanupHandler) Check(ctx context.Context, r operations.Request) error {
	if r.Actor != "system:files" {
		return storage.ErrUnauthorized
	}
	if e := h.g.filesReady(ctx); e != nil {
		return e
	}
	var p purgeParams
	json.Unmarshal(r.Params, &p)
	row, spec, e := h.g.transferRecord(ctx, p.ID)
	if e != nil {
		return e
	}
	if (row.State != "receiving" && row.State != "ready" && row.State != "unknown" && row.State != "failed" && row.State != "expired") || spec.Mode == "move" || spec.RecoveryOperationID != "" || !h.g.fileExpired(row) || p.Expected != scopeJSON([]string{row.ID, row.State, string(row.Document)}) || spec.Proof == "" {
		return storage.ErrVersion
	}
	begin, e := h.g.Store.Lookup(ctx, row.OperationID)
	if e != nil || begin.State != "succeeded" || (begin.Action != "files.upload.begin" && begin.Action != "files.write.begin") {
		return storage.ErrSafety
	}
	h.g.Files.mu.Lock()
	t := h.g.Files.uploads[p.ID]
	h.g.Files.mu.Unlock()
	if t != nil {
		t.mu.Lock()
		busy := t.busy
		t.mu.Unlock()
		if busy {
			return storage.ErrBusy
		}
	}
	return nil
}
func (h fileCleanupHandler) Effect(ctx context.Context, r operations.Request) operations.Outcome {
	if e := h.Check(ctx, r); e != nil {
		return fileMutationOutcome(nil, e, false)
	}
	var p purgeParams
	json.Unmarshal(r.Params, &p)
	row, spec, e := h.g.transferRecord(ctx, p.ID)
	if e != nil {
		return fileMutationOutcome(nil, e, false)
	}
	h.g.Files.mu.Lock()
	t := h.g.Files.uploads[p.ID]
	h.g.Files.mu.Unlock()
	if t != nil {
		t.mu.Lock()
		if t.busy {
			t.mu.Unlock()
			return fileMutationOutcome(nil, storage.ErrBusy, false)
		}
		t.closed = true
		t.mu.Unlock()
	}
	a, e := h.g.Files.guard.OpenArea(spec.RootPath, h.g.AgentID)
	if e != nil {
		return fileMutationOutcome(nil, e, false)
	}
	defer a.Close()
	f, e := a.Entry(row.ID)
	if e != nil {
		return fileMutationOutcome(nil, e, false)
	}
	proof, pe := fileaccess.IdentityProof(f)
	version, ve := fileaccess.Version(f)
	f.Close()
	if pe != nil || ve != nil || proof != spec.Proof {
		return fileMutationOutcome(nil, storage.ErrVersion, false)
	}
	row.State = "unknown"
	if e = h.g.Store.SaveFileRecord(ctx, r.ID, row); e != nil {
		return fileMutationOutcome(nil, e, false)
	}
	if e = a.Purge(ctx, row.ID, version); e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	row.State = "purged"
	if e = h.g.Store.SaveFileRecord(ctx, r.ID, row); e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	h.g.Files.mu.Lock()
	delete(h.g.Files.uploads, row.ID)
	delete(h.g.Files.deadlines, row.ID)
	h.g.Files.mu.Unlock()
	if t != nil {
		t.file.Close()
		t.area.Close()
	}
	return fileMutationOutcome([]byte(`{"cleaned":true}`), nil, false)
}

type fileRotateHandler struct{ g *Gateway }

func (h fileRotateHandler) Validate(b []byte) error { var p struct{}; return decodeStrict(b, &p) }
func (h fileRotateHandler) Keys(operations.Request) ([]string, error) {
	return []string{"files.mutations"}, nil
}
func (h fileRotateHandler) Check(ctx context.Context, r operations.Request) error {
	if r.Actor != "system:files" {
		return storage.ErrUnauthorized
	}
	if !h.g.Store.TrustedExpiry() {
		return storage.ErrSafety
	}
	return nil
}
func (h fileRotateHandler) Effect(ctx context.Context, r operations.Request) operations.Outcome {
	if e := h.Check(ctx, r); e != nil {
		return fileMutationOutcome(nil, e, false)
	}
	if e := h.g.Store.RotateFileRecords(ctx, r.ID); e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	return fileMutationOutcome([]byte(`{"rotated":true}`), nil, false)
}
