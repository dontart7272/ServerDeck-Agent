// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"encoding/json"

	"serverdeck.local/agent/internal/fileaccess"
	"serverdeck.local/agent/internal/operations"
	"serverdeck.local/agent/internal/storage"
	"strconv"
	"time"
)

type trashSpec struct {
	RestoredProof                                                                                      string
	RecoveryOperationID                                                                                string
	RestoreTarget                                                                                      *fileaccess.Location
	RestoreRoot, RestoreName                                                                           string
	RootID, RootPath, Proof, AreaProof, NativeVersion, Version, Filesystem, QuotaKey, TreeDigest, Kind string
	Original                                                                                           fileaccess.Location
	Backup                                                                                             bool
}
type trashParams struct {
	Location fileaccess.Location `json:"location"`
	Expected string              `json:"expected_version"`
}
type restoreParams struct {
	ID            string              `json:"trash_id"`
	Expected      string              `json:"expected_version"`
	Parent        fileaccess.Location `json:"target_parent"`
	Name          string              `json:"target_name"`
	ParentVersion string              `json:"target_parent_version"`
	Conflict      string              `json:"conflict"`
	Replace       string              `json:"replace_version,omitempty"`
}
type purgeParams struct {
	ID       string `json:"trash_id"`
	Expected string `json:"expected_version"`
}
type fileTrashHandler struct {
	g      *Gateway
	action string
}

func (h fileTrashHandler) Validate(raw []byte) error {
	switch h.action {
	case "files.trash":
		var p trashParams
		if decodeStrict(raw, &p) != nil || p.Location.Validate() != nil || len(p.Location.Components) == 0 || p.Expected == "" {
			return storage.ErrInvalid
		}
	case "trash.restore":
		var p restoreParams
		if decodeStrict(raw, &p) != nil || !storage.ValidID(p.ID) || p.Expected == "" || p.Parent.Validate() != nil || p.ParentVersion == "" || (p.Conflict != "fail" && p.Conflict != "replace") || (p.Conflict == "replace" && p.Replace == "") || (p.Conflict == "fail" && p.Replace != "") {
			return storage.ErrInvalid
		}
		if _, e := fileaccessChild(p.Parent, p.Name); e != nil {
			return storage.ErrInvalid
		}
	case "trash.purge", "system.trash.expire":
		var p purgeParams
		if decodeStrict(raw, &p) != nil || !storage.ValidID(p.ID) || p.Expected == "" {
			return storage.ErrInvalid
		}
	default:
		return storage.ErrInvalid
	}
	return nil
}
func (h fileTrashHandler) Keys(operations.Request) ([]string, error) {
	return []string{"files.mutations", "settings.runtime"}, nil
}
func (g *Gateway) trashRecord(ctx context.Context, id string) (storage.FileJournalRecord, trashSpec, error) {
	records, e := g.Store.FileRecords(ctx, "trash")
	if e != nil {
		return storage.FileJournalRecord{}, trashSpec{}, e
	}
	for _, r := range records {
		if r.ID == id {
			var spec trashSpec
			if json.Unmarshal(r.Document, &spec) != nil {
				return r, spec, storage.ErrSafety
			}
			if spec.NativeVersion != "" && spec.TreeDigest != "" {
				spec.Version = scopeJSON([]string{r.ID, spec.NativeVersion, spec.TreeDigest})
			}
			return r, spec, nil
		}
	}
	return storage.FileJournalRecord{}, trashSpec{}, storage.ErrNotFound
}
func (g *Gateway) trashQuota(ctx context.Context, key string, wanted int64) error {
	c, _, e := g.fileConfig(ctx)
	if e != nil {
		return e
	}
	remaining := c.Trash.BudgetBytesPerFS
	records, e := g.Store.FileRecords(ctx, "trash")
	if e != nil {
		return e
	}
	for _, record := range records {
		if record.State == "purged" || record.State == "restored" {
			continue
		}
		var s trashSpec
		if json.Unmarshal(record.Document, &s) != nil {
			return storage.ErrSafety
		}
		if s.QuotaKey != key {
			continue
		}
		bytes := record.Bytes
		if bytes > remaining {
			return storage.ErrQuota
		}
		if s.Proof != "" {
			a, e := g.Files.guard.OpenArea(s.RootPath, g.AgentID)
			if e != nil {
				return storage.ErrSafety
			}
			info, e := a.Scan(ctx, record.ID, remaining)
			a.Close()
			if e != nil {
				return storage.ErrSafety
			}
			if info.Bytes > bytes {
				bytes = info.Bytes
			}
		}
		if bytes > remaining {
			return storage.ErrQuota
		}
		remaining -= bytes
	}
	if wanted > remaining {
		return storage.ErrQuota
	}
	return nil
}
func (h fileTrashHandler) Check(ctx context.Context, r operations.Request) error {
	if e := h.g.filesReady(ctx); e != nil {
		return e
	}
	c, _, e := h.g.fileConfig(ctx)
	if e != nil {
		return e
	}
	if h.action == "files.trash" {
		var p trashParams
		json.Unmarshal(r.Params, &p)
		root, e := rootPath(c, p.Location.RootID)
		if e != nil {
			return e
		}
		r, e := h.g.Files.guard.MutationRoot(root)
		if e != nil {
			return e
		}
		key, e := fileaccess.FilesystemDevice(r)
		r.Close()
		if e != nil {
			return e
		}
		f, e := h.g.Files.guard.Open(root, p.Location)
		if e != nil {
			return e
		}
		version, e := fileaccess.Version(f)
		f.Close()
		if e != nil || version != p.Expected {
			return storage.ErrVersion
		}
		info, e := h.g.Files.guard.Scan(ctx, root, p.Location, c.Trash.BudgetBytesPerFS)
		if e != nil {
			return e
		}
		if e = h.g.Files.guard.CheckPrivateCapacity(info.Nodes + 1); e != nil {
			return e
		}
		return h.g.trashQuota(ctx, key, info.Bytes)
	}
	var p purgeParams
	if h.action == "trash.restore" {
		var restore restoreParams
		json.Unmarshal(r.Params, &restore)
		p = purgeParams{restore.ID, restore.Expected}
	} else {
		json.Unmarshal(r.Params, &p)
	}
	record, spec, e := h.g.trashRecord(ctx, p.ID)
	if e != nil {
		return e
	}
	if record.State != "trashed" || spec.Version != p.Expected {
		return storage.ErrVersion
	}
	area, e := h.g.Files.guard.OpenArea(spec.RootPath, h.g.AgentID)
	if e != nil {
		return e
	}
	defer area.Close()
	proof, e := area.Proof()
	if e != nil || proof != spec.AreaProof {
		return storage.ErrSafety
	}
	entry, e := area.Entry(p.ID)
	if e != nil {
		return e
	}
	version, e := fileaccess.Version(entry)
	entry.Close()
	if e != nil || version != spec.NativeVersion {
		return storage.ErrVersion
	}
	tree, e := area.Scan(ctx, p.ID, c.Trash.BudgetBytesPerFS)
	if e != nil || tree.Digest != spec.TreeDigest {
		return storage.ErrVersion
	}
	if h.action == "system.trash.expire" && (r.Actor != "system:files" || !h.g.fileExpired(record)) {
		return storage.ErrSafety
	}
	if h.action == "trash.restore" {
		var p restoreParams
		json.Unmarshal(r.Params, &p)
		targetRoot, e := rootPath(c, p.Parent.RootID)
		if e != nil {
			return e
		}
		targetFD, e := h.g.Files.guard.MutationRoot(targetRoot)
		if e != nil {
			return e
		}
		targetKey, e := fileaccess.FilesystemDevice(targetFD)
		targetFD.Close()
		if e != nil {
			return storage.ErrSafety
		}
		if targetKey != spec.QuotaKey {
			if e = h.g.Files.guard.CheckPrivateCapacity(tree.Nodes + 1); e != nil {
				return e
			}
		}
		if p.Conflict == "replace" {
			location := mustChild(p.Parent, p.Name)
			f, e := h.g.Files.guard.Open(targetRoot, location)
			if e != nil {
				return e
			}
			info, ie := f.Stat()
			version, ve := fileaccess.Version(f)
			key, ke := fileaccess.FilesystemDevice(f)
			f.Close()
			if ie != nil || ve != nil || ke != nil || !info.Mode().IsRegular() || version != p.Replace {
				return storage.ErrVersion
			}
			return h.g.trashQuota(ctx, key, info.Size())
		}
		return h.g.Files.guard.CheckCreate(targetRoot, p.Parent, p.Name, p.ParentVersion)
	}
	return nil
}
func (h fileTrashHandler) Effect(ctx context.Context, r operations.Request) operations.Outcome {
	if e := h.Check(ctx, r); e != nil {
		return fileMutationOutcome(nil, e, false)
	}
	if r.Credential != nil {
		if e := h.g.Store.CheckCredential(ctx, *r.Credential); e != nil {
			return fileMutationOutcome(nil, e, false)
		}
	}
	if h.action == "files.trash" {
		var p trashParams
		json.Unmarshal(r.Params, &p)
		id, version, e := h.g.trashObject(ctx, r, p.Location, p.Expected)
		if e != nil {
			return fileMutationOutcome(nil, e, true)
		}
		b, _ := json.Marshal(map[string]any{"trash_id": id, "version": version})
		return fileMutationOutcome(b, nil, false)
	}
	var id string
	if h.action == "trash.restore" {
		var p restoreParams
		json.Unmarshal(r.Params, &p)
		id = p.ID
	} else {
		var p purgeParams
		json.Unmarshal(r.Params, &p)
		id = p.ID
	}
	record, spec, e := h.g.trashRecord(ctx, id)
	if e != nil {
		return fileMutationOutcome(nil, e, false)
	}
	area, e := h.g.Files.guard.OpenArea(spec.RootPath, h.g.AgentID)
	if e != nil {
		return fileMutationOutcome(nil, e, false)
	}
	defer area.Close()
	record.State = "unknown"
	spec.RecoveryOperationID = r.ID
	if h.action == "trash.restore" {
		var p restoreParams
		json.Unmarshal(r.Params, &p)
		spec.RestoreTarget = &p.Parent
		spec.RestoreName = p.Name
		c, _, _ := h.g.fileConfig(ctx)
		spec.RestoreRoot, _ = rootPath(c, p.Parent.RootID)
	}
	record.Document, _ = json.Marshal(spec)
	if e = h.g.Store.SaveFileRecord(ctx, r.ID, record); e != nil {
		return fileMutationOutcome(nil, e, false)
	}
	if h.action == "trash.restore" {
		var p restoreParams
		json.Unmarshal(r.Params, &p)
		var replace string
		var replacedID any
		c, _, e := h.g.fileConfig(ctx)
		if e != nil {
			return fileMutationOutcome(nil, e, true)
		}
		targetRoot, e := rootPath(c, p.Parent.RootID)
		if e != nil {
			return fileMutationOutcome(nil, e, true)
		}
		targetFD, e := h.g.Files.guard.MutationRoot(targetRoot)
		if e != nil {
			return fileMutationOutcome(nil, e, true)
		}
		targetKey, e := fileaccess.FilesystemDevice(targetFD)
		targetFD.Close()
		if e != nil {
			return fileMutationOutcome(nil, e, true)
		}
		if targetKey != spec.QuotaKey {
			return h.crossRestore(ctx, r, record, spec, area, p, targetRoot)
		}
		if p.Conflict == "replace" {
			replace = p.Replace
			write := writeSpec{RootID: p.Parent.RootID, RootPath: targetRoot, Parent: p.Parent, Name: p.Name, ParentVersion: p.ParentVersion, Replace: replace}
			backupArea, be := h.g.Files.guard.Area(targetRoot, h.g.AgentID)
			if be != nil {
				return fileMutationOutcome(nil, be, true)
			}
			var backupID string
			backupID, e = h.g.preserveReplacement(ctx, r, backupArea, write)
			backupArea.Close()
			if e != nil {
				return fileMutationOutcome(nil, e, true)
			}
			replacedID = backupID
		}
		out, e := area.RestoreTo(targetRoot, id, spec.NativeVersion, p.Parent, p.Name, p.ParentVersion, replace)
		if e != nil {
			return fileMutationOutcome(nil, e, true)
		}
		defer out.Close()
		record.State = "restored"
		if e = h.g.Store.SaveFileRecord(ctx, r.ID, record); e != nil {
			return fileMutationOutcome(nil, e, true)
		}
		value, e := h.g.presentFile(ctx, out, mustChild(p.Parent, p.Name))
		if e != nil {
			return fileMutationOutcome(nil, e, true)
		}
		b, _ := json.Marshal(map[string]any{"file": value, "replaced_trash_id": replacedID})
		return fileMutationOutcome(b, nil, false)
	}
	if e = area.Purge(ctx, id, spec.NativeVersion); e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	record.State = "purged"
	if e = h.g.Store.SaveFileRecord(ctx, r.ID, record); e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	b, _ := json.Marshal(map[string]any{"trash_id": id, "purged": true})
	return fileMutationOutcome(b, nil, false)
}
func (g *Gateway) trashObject(ctx context.Context, r operations.Request, location fileaccess.Location, expected string) (string, string, error) {
	c, _, e := g.fileConfig(ctx)
	if e != nil {
		return "", "", e
	}
	root, e := rootPath(c, location.RootID)
	if e != nil {
		return "", "", e
	}
	info, e := g.Files.guard.Scan(ctx, root, location, c.Trash.BudgetBytesPerFS)
	if e != nil {
		return "", "", e
	}
	f, e := g.Files.guard.Open(root, location)
	if e != nil {
		return "", "", e
	}
	version, e := fileaccess.Version(f)
	key, ke := fileaccess.FilesystemDevice(f)
	fs, fe := fileaccess.Filesystem(f)
	f.Close()
	if e != nil || ke != nil || fe != nil || version != expected {
		return "", "", storage.ErrVersion
	}
	if e = g.trashQuota(ctx, key, info.Bytes); e != nil {
		return "", "", e
	}
	id, e := storage.RandomID()
	if e != nil {
		return "", "", e
	}
	now := time.Now()
	finishJournal := g.Files.beginJournal(id)
	defer finishJournal()
	spec := trashSpec{RootID: location.RootID, RootPath: root, Original: location, Filesystem: fs, QuotaKey: key, Kind: info.Kind}
	doc, _ := json.Marshal(spec)
	record := storage.FileJournalRecord{ID: id, Kind: "trash", Owner: r.Actor, OperationID: r.ID, State: "planned", Bytes: info.Bytes, Created: now.UnixMicro(), Expires: now.Add(time.Duration(c.Trash.RetentionDays) * 24 * time.Hour).UnixMicro(), Document: doc}
	if e = g.Store.SaveFileRecord(ctx, r.ID, record); e != nil {
		return "", "", e
	}
	area, e := g.Files.guard.Area(root, g.AgentID)
	if e != nil {
		return "", "", e
	}
	defer area.Close()
	spec.AreaProof, e = area.Proof()
	if e != nil {
		return "", "", e
	}
	out, e := area.Trash(location, expected, id)
	if e != nil {
		return "", "", e
	}
	defer out.Close()
	return g.finishTrash(ctx, r.ID, record, spec, area, out)
}
func (g *Gateway) finishTrash(ctx context.Context, operationID string, record storage.FileJournalRecord, spec trashSpec, area *fileaccess.Area, out interface{ Close() error }) (string, string, error) {
	f, e := area.Entry(record.ID)
	if e != nil {
		return "", "", e
	}
	spec.Proof, e = fileaccess.IdentityProof(f)
	spec.NativeVersion, _ = fileaccess.Version(f)
	f.Close()
	if e != nil {
		return "", "", e
	}
	tree, e := area.Scan(ctx, record.ID, 9223372036854775807)
	if e != nil {
		return "", "", e
	}
	spec.TreeDigest = tree.Digest
	spec.Version = scopeJSON([]string{record.ID, spec.NativeVersion, spec.TreeDigest})
	record.State = "trashed"
	record.Bytes = tree.Bytes
	record.Document, _ = json.Marshal(spec)
	if e = g.Store.SaveFileRecord(ctx, operationID, record); e != nil {
		return "", "", e
	}
	g.Files.rememberDeadline(record)
	return record.ID, spec.Version, nil
}
func (g *Gateway) preserveReplacement(ctx context.Context, r operations.Request, area *fileaccess.Area, write writeSpec) (string, error) {
	location := mustChild(write.Parent, write.Name)
	f, e := g.Files.guard.Open(write.RootPath, location)
	if e != nil {
		return "", e
	}
	defer f.Close()
	version, e := fileaccess.Version(f)
	info, ie := f.Stat()
	if e != nil || ie != nil || !info.Mode().IsRegular() || version != write.Replace {
		return "", storage.ErrVersion
	}
	key, e := fileaccess.FilesystemDevice(f)
	if e != nil {
		return "", e
	}
	if e = g.trashQuota(ctx, key, info.Size()); e != nil {
		return "", e
	}
	c, _, e := g.fileConfig(ctx)
	if e != nil {
		return "", e
	}
	id, e := storage.RandomID()
	if e != nil {
		return "", e
	}
	proof, e := area.Proof()
	if e != nil {
		return "", e
	}
	fs, _ := fileaccess.Filesystem(f)
	spec := trashSpec{RootID: write.RootID, RootPath: write.RootPath, AreaProof: proof, Original: location, Filesystem: fs, QuotaKey: key, Kind: "file", Backup: true}
	finishJournal := g.Files.beginJournal(id)
	defer finishJournal()
	now := time.Now()
	doc, _ := json.Marshal(spec)
	record := storage.FileJournalRecord{ID: id, Kind: "trash", Owner: r.Actor, OperationID: r.ID, State: "planned", Bytes: info.Size(), Created: now.UnixMicro(), Expires: now.Add(time.Duration(c.Trash.RetentionDays) * 24 * time.Hour).UnixMicro(), Document: doc}
	if e = g.Store.SaveFileRecord(ctx, r.ID, record); e != nil {
		return "", e
	}
	copy, _, e := area.CopyFile(ctx, f, id, c.Trash.BudgetBytesPerFS)
	if e != nil {
		return "", e
	}
	defer copy.Close()
	savedID, _, e := g.finishTrash(ctx, r.ID, record, spec, area, copy)
	return savedID, e
}
func (g *Gateway) trashList(ctx context.Context, raw []byte) (any, error) {
	var p struct {
		Filesystem string `json:"filesystem_id"`
		Cursor     string `json:"cursor"`
		Limit      int    `json:"limit"`
	}
	if decodeStrict(raw, &p) != nil || p.Limit < 0 || p.Limit > 100 {
		return nil, storage.ErrInvalid
	}
	if p.Limit == 0 {
		p.Limit = 100
	}
	records, e := g.Store.FileRecords(ctx, "trash")
	if e != nil {
		return nil, e
	}
	items := []any{}
	ready := g.Files != nil && g.filesReady(ctx) == nil && g.Store.Health().AuditAvailable
	for _, record := range records {
		if record.State != "trashed" && record.State != "unknown" && record.State != "planned" {
			continue
		}
		var spec trashSpec
		if json.Unmarshal(record.Document, &spec) != nil {
			return nil, storage.ErrSafety
		}
		if p.Filesystem != "" && p.Filesystem != spec.Filesystem {
			continue
		}
		if spec.Version == "" {
			spec.Version = scopeJSON([]string{record.ID, record.State})
		}
		if spec.NativeVersion != "" && spec.TreeDigest != "" {
			spec.Version = scopeJSON([]string{record.ID, spec.NativeVersion, spec.TreeDigest})
		}
		available := ready && record.State == "trashed"
		var reason any
		if !available {
			reason = "SAFETY_UNAVAILABLE"
			if record.State != "trashed" {
				reason = "RECOVERY_REQUIRED"
			}
		}
		items = append(items, map[string]any{"trash_id": record.ID, "filesystem_id": spec.Filesystem, "original_location": spec.Original, "initiator": initiatorWire(record.Owner), "deleted_at": timestamp(time.UnixMicro(record.Created)), "expires_at": timestamp(time.UnixMicro(record.Expires)), "size_bytes": strconv.FormatInt(record.Bytes, 10), "version": spec.Version, "actions": []any{map[string]any{"id": "trash.restore", "available": available, "reason": reason, "version": spec.Version}, map[string]any{"id": "trash.purge", "available": available, "reason": reason, "version": spec.Version}}})
	}
	version := scopeJSON(items)
	scope := scopeJSON([]string{p.Filesystem, metricOwner(ctx)})
	start := int64(0)
	if p.Cursor != "" {
		position, e := g.position(p.Cursor, "trash.list", scope)
		if e != nil {
			return nil, e
		}
		if position.Epoch != version {
			return nil, storage.ErrCursor
		}
		start = position.Position
	}
	if start > int64(len(items)) {
		return nil, storage.ErrCursor
	}
	end := start + int64(p.Limit)
	if end > int64(len(items)) {
		end = int64(len(items))
	}
	var next any
	if end < int64(len(items)) {
		cursor, e := g.cursor("trash.list", version, scope, end)
		if e != nil {
			return nil, e
		}
		next = cursor
	}
	return page(items[start:end], next, version), nil
}

func metricOwner(ctx context.Context) string {
	owner, _ := ctx.Value(metricOwnerKey{}).(string)
	return owner
}
