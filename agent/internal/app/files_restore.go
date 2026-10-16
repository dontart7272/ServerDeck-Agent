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

// Cross-filesystem restore retains the original trash object until a checked
// target has been published. It never treats copying as an atomic rename.
func (h fileTrashHandler) crossRestore(ctx context.Context, r operations.Request, sourceRecord storage.FileJournalRecord, source trashSpec, area *fileaccess.Area, p restoreParams, targetRoot string) operations.Outcome {
	ctx, cancel := context.WithTimeout(ctx, time.Hour)
	defer cancel()
	if r.Credential != nil {
		session, e := h.g.Auth.Session(*r.Credential)
		if e != nil {
			return fileMutationOutcome(nil, e, true)
		}
		defer session.Close()
		stop := context.AfterFunc(session.Context, cancel)
		defer stop()
	}
	release, e := h.g.reserveTransfer(ctx)
	if e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	defer release()
	c, revision, e := h.g.fileConfig(ctx)
	if e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	id, e := storage.RandomID()
	if e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	finish := h.g.Files.beginJournal(id)
	defer finish()
	spec := writeSpec{RootID: p.Parent.RootID, RootPath: targetRoot, Parent: p.Parent, Name: p.Name, ParentVersion: p.ParentVersion, Mode: "restore", Revision: revision, Size: sourceRecord.Bytes, RecoveryOperationID: r.ID}
	now := time.Now()
	doc, _ := json.Marshal(spec)
	record := storage.FileJournalRecord{ID: id, Kind: "transfer", Owner: r.Actor, OperationID: r.ID, State: "planned", Bytes: sourceRecord.Bytes, Created: now.UnixMicro(), Expires: now.Add(time.Hour).UnixMicro(), Document: doc}
	if e = h.g.Store.SaveFileRecord(ctx, r.ID, record); e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	target, e := h.g.Files.guard.Area(targetRoot, h.g.AgentID)
	if e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	defer target.Close()
	spec.AreaProof, e = target.Proof()
	if e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	parent, e := h.g.Files.guard.Open(targetRoot, p.Parent)
	if e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	spec.ParentVersion, e = fileaccess.Version(parent)
	parent.Close()
	if e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	if e = h.g.Store.FilePhase(ctx, r.ID, "copy"); e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	expected, e := area.PayloadDigest(ctx, sourceRecord.ID, c.Trash.BudgetBytesPerFS)
	if e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	copy, e := area.CopyPrivateTo(ctx, sourceRecord.ID, source.Proof, target, id, c.Trash.BudgetBytesPerFS)
	if e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	defer copy.Close()
	spec.Proof, e = fileaccess.IdentityProof(copy)
	if e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	if e = h.g.Store.FilePhase(ctx, r.ID, "verify"); e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	actual, e := target.PayloadDigest(ctx, id, c.Trash.BudgetBytesPerFS)
	if e != nil || actual != expected {
		return fileMutationOutcome(nil, storage.ErrVersion, true)
	}
	after, e := area.PayloadDigest(ctx, sourceRecord.ID, c.Trash.BudgetBytesPerFS)
	if e != nil || after != expected {
		return fileMutationOutcome(nil, storage.ErrVersion, true)
	}
	spec.SHA = actual
	source.RestoredProof = spec.Proof
	sourceRecord.Document, _ = json.Marshal(source)
	if e = h.g.Store.SaveFileRecord(ctx, r.ID, sourceRecord); e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	record.State = "ready"
	record.Document, _ = json.Marshal(spec)
	if e = h.g.Store.SaveFileRecord(ctx, r.ID, record); e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	var replaced any
	replace := ""
	if p.Conflict == "replace" {
		replace = p.Replace
		backup, e := h.g.preserveReplacement(ctx, r, target, writeSpec{RootID: p.Parent.RootID, RootPath: targetRoot, Parent: p.Parent, Name: p.Name, ParentVersion: spec.ParentVersion, Replace: p.Replace})
		if e != nil {
			return fileMutationOutcome(nil, e, true)
		}
		replaced = backup
	}
	if r.Credential != nil {
		if e = h.g.Store.CheckCredential(ctx, *r.Credential); e != nil {
			return fileMutationOutcome(nil, e, true)
		}
	}
	if e = h.g.Store.FilePhase(ctx, r.ID, "publish"); e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	version, e := fileaccess.Version(copy)
	if e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	out, e := target.Restore(id, version, p.Parent, p.Name, spec.ParentVersion, replace)
	if e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	defer out.Close()
	value, e := h.g.presentFile(ctx, out, mustChild(p.Parent, p.Name))
	if e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	result, _ := json.Marshal(map[string]any{"file": value, "replaced_trash_id": replaced})
	partial := func(e error) operations.Outcome {
		return operations.Outcome{State: "unknown", Effect: "partial", Code: errorCode(e), Result: result}
	}
	record.State = "published"
	if e = h.g.Store.SaveFileRecord(ctx, r.ID, record); e != nil {
		return partial(e)
	}
	if e = h.g.Store.FilePhase(ctx, r.ID, "source_cleanup"); e != nil {
		return partial(e)
	}
	after, e = area.PayloadDigest(ctx, sourceRecord.ID, c.Trash.BudgetBytesPerFS)
	if e != nil || after != expected {
		return partial(storage.ErrVersion)
	}
	if r.Credential != nil {
		if e = h.g.Store.CheckCredential(ctx, *r.Credential); e != nil {
			return partial(e)
		}
	}
	if e = area.Purge(ctx, sourceRecord.ID, source.NativeVersion); e != nil {
		return partial(e)
	}
	sourceRecord.State = "restored"
	if e = h.g.Store.SaveFileRecord(ctx, r.ID, sourceRecord); e != nil {
		return partial(e)
	}
	return fileMutationOutcome(result, nil, false)
}
