// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"encoding/json"
	"serverdeck.local/agent/internal/fileaccess"
	"serverdeck.local/agent/internal/operations"
	"serverdeck.local/agent/internal/storage"
	"time"
)

type fileMoveHandler struct{ g *Gateway }

func (h fileMoveHandler) Validate(raw []byte) error {
	return (fileMutationHandler{h.g, true}).Validate(raw)
}
func (h fileMoveHandler) Keys(operations.Request) ([]string, error) {
	return []string{"files.mutations", "settings.runtime"}, nil
}
func (h fileMoveHandler) roots(ctx context.Context, p fileRenameParams) (string, string, string, string, error) {
	c, _, e := h.g.fileConfig(ctx)
	if e != nil {
		return "", "", "", "", e
	}
	source, e := rootPath(c, p.Location.RootID)
	if e != nil {
		return "", "", "", "", e
	}
	target, e := rootPath(c, p.Target.RootID)
	if e != nil {
		return "", "", "", "", e
	}
	a, e := h.g.Files.guard.MutationRoot(source)
	if e != nil {
		return "", "", "", "", e
	}
	sourceKey, e := fileaccess.FilesystemDevice(a)
	a.Close()
	if e != nil {
		return "", "", "", "", e
	}
	b, e := h.g.Files.guard.MutationRoot(target)
	if e != nil {
		return "", "", "", "", e
	}
	targetKey, e := fileaccess.FilesystemDevice(b)
	b.Close()
	return source, target, sourceKey, targetKey, e
}
func (h fileMoveHandler) Check(ctx context.Context, r operations.Request) error {
	if e := h.g.filesReady(ctx); e != nil {
		return e
	}
	var p fileRenameParams
	json.Unmarshal(r.Params, &p)
	source, target, sourceKey, targetKey, e := h.roots(ctx, p)
	if e != nil {
		return e
	}
	if sourceKey == targetKey {
		return h.g.Files.guard.CheckRenameAcross(source, target, p.Location, p.Expected, p.Target, p.Name, p.ParentVersion)
	}
	f, e := h.g.Files.guard.Open(source, p.Location)
	if e != nil {
		return e
	}
	v, e := fileaccess.Version(f)
	f.Close()
	if e != nil || v != p.Expected {
		return storage.ErrVersion
	}
	if e = h.g.Files.guard.CheckCreate(target, p.Target, p.Name, p.ParentVersion); e != nil {
		return e
	}
	c, _, e := h.g.fileConfig(ctx)
	if e != nil {
		return e
	}
	tree, e := h.g.Files.guard.Scan(ctx, source, p.Location, c.Trash.BudgetBytesPerFS)
	if e != nil {
		return e
	}
	if e = h.g.Files.guard.CheckPrivateCapacity(2*tree.Nodes + 2); e != nil {
		return e
	}
	return h.g.trashQuota(ctx, sourceKey, tree.Bytes)
}
func moveOutcome(source string, target any, trash any, completed, unknown []string, e error) operations.Outcome {
	value := map[string]any{"source_status": source, "target": target, "trash_id": trash, "completed_phases": completed, "unknown_phases": unknown}
	b, _ := json.Marshal(value)
	if e == nil {
		return operations.Outcome{State: "succeeded", Effect: "applied", Result: b}
	}
	return operations.Outcome{State: "unknown", Effect: "partial", Code: errorCode(e), Result: b}
}
func (h fileMoveHandler) Effect(ctx context.Context, r operations.Request) operations.Outcome {
	ctx, cancel := context.WithTimeout(ctx, time.Hour)
	defer cancel()
	if r.Credential != nil {
		session, e := h.g.Auth.Session(*r.Credential)
		if e != nil {
			return fileMutationOutcome(nil, e, false)
		}
		defer session.Close()
		stop := context.AfterFunc(session.Context, cancel)
		defer stop()
	}
	if e := h.Check(ctx, r); e != nil {
		return fileMutationOutcome(nil, e, false)
	}
	var p fileRenameParams
	json.Unmarshal(r.Params, &p)
	source, target, sourceKey, targetKey, e := h.roots(ctx, p)
	if e != nil {
		return fileMutationOutcome(nil, e, false)
	}
	if sourceKey == targetKey {
		out, e := h.g.Files.guard.RenameAcross(source, target, p.Location, p.Expected, p.Target, p.Name, p.ParentVersion)
		if e != nil {
			return fileMutationOutcome(nil, e, e == fileaccess.ErrUncertain)
		}
		defer out.Close()
		record, e := h.g.presentFile(ctx, out, mustChild(p.Target, p.Name))
		if e != nil {
			return moveOutcome("unknown", nil, nil, []string{}, []string{"rename"}, e)
		}
		return moveOutcome("retained", record, nil, []string{"same_filesystem_rename"}, []string{}, nil)
	}
	c, revision, e := h.g.fileConfig(ctx)
	if e != nil {
		return fileMutationOutcome(nil, e, false)
	}
	releaseSlot, e := h.g.reserveTransfer(ctx)
	if e != nil {
		return fileMutationOutcome(nil, e, false)
	}
	defer releaseSlot()
	tree, e := h.g.Files.guard.Scan(ctx, source, p.Location, c.Trash.BudgetBytesPerFS)
	if e != nil {
		return fileMutationOutcome(nil, e, false)
	}
	spec := writeSpec{RootID: p.Target.RootID, RootPath: target, Parent: p.Target, Name: p.Name, ParentVersion: p.ParentVersion, Mode: "move", Revision: revision, Size: tree.Bytes, Source: &p.Location, SourceRoot: source, SourceVersion: p.Expected, RecoveryOperationID: r.ID}
	now := time.Now()
	finishJournal := h.g.Files.beginJournal(r.ID)
	defer finishJournal()
	doc, _ := json.Marshal(spec)
	journal := storage.FileJournalRecord{ID: r.ID, Kind: "transfer", Owner: r.Actor, OperationID: r.ID, State: "planned", Bytes: tree.Bytes, Created: now.UnixMicro(), Expires: now.Add(time.Hour).UnixMicro(), Document: doc}
	if e = h.g.Store.SaveFileRecord(ctx, r.ID, journal); e != nil {
		return fileMutationOutcome(nil, e, false)
	}
	if e = h.g.Store.FilePhase(ctx, r.ID, "copy"); e != nil {
		return moveOutcome("retained", nil, nil, []string{}, []string{"copy"}, e)
	}
	area, e := h.g.Files.guard.Area(target, h.g.AgentID)
	if e != nil {
		return moveOutcome("retained", nil, nil, []string{}, []string{"copy"}, e)
	}
	defer area.Close()
	spec.AreaProof, e = area.Proof()
	if e != nil {
		return moveOutcome("retained", nil, nil, []string{}, []string{"copy"}, e)
	}
	parent, e := h.g.Files.guard.Open(target, p.Target)
	if e != nil {
		return moveOutcome("retained", nil, nil, []string{}, []string{"copy"}, e)
	}
	spec.ParentVersion, e = fileaccess.Version(parent)
	parent.Close()
	if e != nil {
		return moveOutcome("retained", nil, nil, []string{}, []string{"copy"}, e)
	}
	input, e := h.g.Files.guard.Open(source, p.Location)
	if e != nil {
		return moveOutcome("retained", nil, nil, []string{}, []string{"copy"}, e)
	}
	copy, e := area.CopyObject(ctx, input, r.ID, c.Trash.BudgetBytesPerFS)
	input.Close()
	if e != nil {
		return moveOutcome("retained", nil, nil, []string{}, []string{"copy"}, e)
	}
	defer copy.Close()
	spec.Proof, e = fileaccess.IdentityProof(copy)
	if e != nil {
		return moveOutcome("retained", nil, nil, []string{"copy"}, []string{"verify"}, e)
	}
	spec.SHA, e = area.PayloadDigest(ctx, r.ID, c.Trash.BudgetBytesPerFS)
	if e != nil {
		return moveOutcome("retained", nil, nil, []string{"copy"}, []string{"verify"}, e)
	}
	journal.State = "ready"
	journal.Document, _ = json.Marshal(spec)
	if e = h.g.Store.SaveFileRecord(ctx, r.ID, journal); e != nil {
		return moveOutcome("retained", nil, nil, []string{"copy"}, []string{"verify"}, e)
	}
	if e = h.g.Store.FilePhase(ctx, r.ID, "verify"); e != nil {
		return moveOutcome("retained", nil, nil, []string{"copy"}, []string{"verify"}, e)
	}
	digest, e := h.g.Files.guard.PayloadDigest(ctx, source, p.Location, c.Trash.BudgetBytesPerFS)
	if e != nil || digest != spec.SHA {
		return moveOutcome("retained", nil, nil, []string{"copy"}, []string{"verify"}, storage.ErrVersion)
	}
	current, e := h.g.Files.guard.Scan(ctx, source, p.Location, c.Trash.BudgetBytesPerFS)
	if e != nil || current.Digest != tree.Digest {
		return moveOutcome("retained", nil, nil, []string{"copy"}, []string{"verify"}, storage.ErrVersion)
	}
	if r.Credential != nil {
		if e = h.g.Store.CheckCredential(ctx, *r.Credential); e != nil {
			return moveOutcome("retained", nil, nil, []string{"copy", "verified"}, []string{}, e)
		}
	}
	if e = h.g.Store.FilePhase(ctx, r.ID, "publish"); e != nil {
		return moveOutcome("retained", nil, nil, []string{"copy", "verified"}, []string{"publish"}, e)
	}
	stageVersion, e := fileaccess.Version(copy)
	if e != nil {
		return moveOutcome("retained", nil, nil, []string{"copy", "verified"}, []string{"publish"}, e)
	}
	out, e := area.Restore(r.ID, stageVersion, p.Target, p.Name, spec.ParentVersion)
	if e != nil {
		return moveOutcome("retained", nil, nil, []string{"copy", "verified"}, []string{"publish"}, e)
	}
	defer out.Close()
	value, e := h.g.presentFile(ctx, out, mustChild(p.Target, p.Name))
	if e != nil {
		return moveOutcome("retained", nil, nil, []string{"target_published"}, []string{"target_state"}, e)
	}
	journal.State = "published"
	if e = h.g.Store.SaveFileRecord(ctx, r.ID, journal); e != nil {
		return moveOutcome("retained", value, nil, []string{"target_published"}, []string{"target_state"}, e)
	}
	if e = h.g.Store.FilePhase(ctx, r.ID, "source_trash"); e != nil {
		return moveOutcome("retained", value, nil, []string{"copy", "verified", "target_published"}, []string{"source_trash"}, e)
	}
	digest, e = h.g.Files.guard.PayloadDigest(ctx, source, p.Location, c.Trash.BudgetBytesPerFS)
	if e != nil || digest != spec.SHA {
		return moveOutcome("retained", value, nil, []string{"copy", "verified", "target_published"}, []string{}, storage.ErrVersion)
	}
	if r.Credential != nil {
		if e = h.g.Store.CheckCredential(ctx, *r.Credential); e != nil {
			return moveOutcome("retained", value, nil, []string{"target_published"}, []string{}, e)
		}
	}
	id, _, e := h.g.trashObject(ctx, r, p.Location, p.Expected)
	if e != nil {
		return moveOutcome("unknown", value, nil, []string{"copy", "verified", "target_published"}, []string{"source_trash"}, e)
	}
	return moveOutcome("trashed", value, id, []string{"copy", "verified", "target_published", "source_trashed"}, []string{}, nil)
}
