// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/fileaccess"
	"serverdeck.local/agent/internal/operations"
	"serverdeck.local/agent/internal/storage"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"
)

type uploadParams struct {
	Parent        fileaccess.Location `json:"parent"`
	Name          string              `json:"name"`
	ParentVersion string              `json:"parent_version"`
	Size          int64               `json:"size_bytes"`
	SHA           string              `json:"sha256"`
	Conflict      string              `json:"conflict"`
	Replace       string              `json:"replace_version,omitempty"`
}
type editParams struct {
	Location fileaccess.Location `json:"location"`
	Expected string              `json:"expected_version"`
	Size     int64               `json:"size_bytes"`
	SHA      string              `json:"sha256"`
	Encoding string              `json:"encoding"`
}
type commitParams struct {
	ID       string `json:"transfer_id"`
	SHA      string `json:"sha256"`
	Size     int64  `json:"size_bytes"`
	Expected string `json:"expected_version"`
}
type writeSpec struct {
	Source                                                                                          *fileaccess.Location
	SourceRoot, SourceVersion                                                                       string
	RecoveryOperationID                                                                             string
	RootID, RootPath, Name, ParentVersion, Replace, Revision, Proof, AreaProof, Mode, Encoding, SHA string
	Parent                                                                                          fileaccess.Location
	Size                                                                                            int64
}
type writeTicket struct {
	mu     sync.Mutex
	record storage.FileJournalRecord
	spec   writeSpec
	file   *os.File
	area   *fileaccess.Area
	busy   bool
	closed bool
	used   time.Time
}
type fileTransferHandler struct {
	g      *Gateway
	action string
}

func validDigest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func (h fileTransferHandler) Validate(raw []byte) error {
	switch h.action {
	case "files.upload.begin":
		var p uploadParams
		if decodeStrict(raw, &p) != nil || p.Parent.Validate() != nil || p.ParentVersion == "" || p.Size < 0 || p.Size > 1000000000 || !validDigest(p.SHA) || (p.Conflict != "fail" && p.Conflict != "replace") || (p.Conflict == "replace" && p.Replace == "") || (p.Conflict == "fail" && p.Replace != "") {
			return storage.ErrInvalid
		}
		_, e := fileaccessChild(p.Parent, p.Name)
		if e != nil {
			return storage.ErrInvalid
		}
	case "files.write.begin":
		var p editParams
		if decodeStrict(raw, &p) != nil || p.Location.Validate() != nil || len(p.Location.Components) == 0 || p.Expected == "" || p.Size < 0 || p.Size > 512000 || !validDigest(p.SHA) || (p.Encoding != "utf-8" && p.Encoding != "utf-8-bom") {
			return storage.ErrInvalid
		}
	case "files.transfer.commit":
		var p commitParams
		if decodeStrict(raw, &p) != nil || !storage.ValidID(p.ID) || !validDigest(p.SHA) || p.Size < 0 || p.Size > 1000000000 || p.Expected == "" {
			return storage.ErrInvalid
		}
	default:
		return storage.ErrInvalid
	}
	return nil
}
func (h fileTransferHandler) Keys(operations.Request) ([]string, error) {
	return []string{"files.mutations", "settings.runtime"}, nil
}
func (h fileTransferHandler) specification(ctx context.Context, r operations.Request) (writeSpec, error) {
	c, revision, e := h.g.fileConfig(ctx)
	if e != nil {
		return writeSpec{}, e
	}
	spec := writeSpec{Revision: revision}
	if h.action == "files.write.begin" {
		var p editParams
		json.Unmarshal(r.Params, &p)
		spec.RootID = p.Location.RootID
		spec.Parent = fileaccess.Location{RootID: p.Location.RootID, Components: append([]string{}, p.Location.Components[:len(p.Location.Components)-1]...)}
		spec.Name = p.Location.Components[len(p.Location.Components)-1]
		spec.Replace = p.Expected
		spec.Size = p.Size
		spec.SHA = p.SHA
		spec.Encoding = p.Encoding
		spec.Mode = "edit"
		path, e := rootPath(c, p.Location.RootID)
		if e != nil {
			return spec, e
		}
		parent, e := h.g.Files.guard.Open(path, spec.Parent)
		if e != nil {
			return spec, e
		}
		spec.ParentVersion, e = fileaccess.Version(parent)
		parent.Close()
		if e != nil {
			return spec, e
		}
	} else {
		var p uploadParams
		json.Unmarshal(r.Params, &p)
		spec.RootID = p.Parent.RootID
		spec.Parent = p.Parent
		spec.Name = p.Name
		spec.ParentVersion = p.ParentVersion
		spec.Size = p.Size
		spec.SHA = p.SHA
		spec.Replace = p.Replace
		spec.Mode = "upload"
		if p.Size > c.Files.UploadBytes {
			return spec, fileaccess.ErrLimit
		}
	}
	spec.RootPath, e = rootPath(c, spec.RootID)
	if e != nil {
		return spec, e
	}
	if spec.Replace == "" {
		e = h.g.Files.guard.CheckCreate(spec.RootPath, spec.Parent, spec.Name, spec.ParentVersion)
	} else {
		target, _ := fileaccessChild(spec.Parent, spec.Name)
		f, oe := h.g.Files.guard.Open(spec.RootPath, target)
		if oe != nil {
			return spec, oe
		}
		version, ve := fileaccess.Version(f)
		info, ie := f.Stat()
		metaErr := fileaccess.CheckReplacementMeta(f)
		f.Close()
		if metaErr != nil {
			return spec, metaErr
		}
		if ve != nil || ie != nil || !info.Mode().IsRegular() || version != spec.Replace {
			return spec, storage.ErrVersion
		}
		root, oe := h.g.Files.guard.MutationRoot(spec.RootPath)
		if oe != nil {
			return spec, oe
		}
		root.Close()
	}
	return spec, e
}
func (h fileTransferHandler) Check(ctx context.Context, r operations.Request) error {
	if e := h.g.filesReady(ctx); e != nil {
		return e
	}
	if h.action == "files.transfer.commit" {
		var p commitParams
		json.Unmarshal(r.Params, &p)
		record, spec, e := h.g.transferRecord(ctx, p.ID)
		if e != nil {
			return e
		}
		if record.Owner != r.Actor {
			return storage.ErrUnauthorized
		}
		c, revision, e := h.g.fileConfig(ctx)
		if e != nil {
			return e
		}
		currentRoot, e := rootPath(c, spec.RootID)
		if e != nil || revision != spec.Revision || currentRoot != spec.RootPath {
			return storage.ErrVersion
		}
		if record.State != "ready" || (spec.Mode != "upload" && spec.Mode != "edit") || spec.SHA != p.SHA || spec.Size != p.Size || time.Now().UnixMicro() >= record.Expires {
			return storage.ErrVersion
		}
		if spec.Replace != "" {
			if p.Expected != spec.Replace {
				return storage.ErrVersion
			}
			f, e := h.g.Files.guard.Open(spec.RootPath, mustChild(spec.Parent, spec.Name))
			if e != nil {
				return e
			}
			defer f.Close()
			version, e := fileaccess.Version(f)
			if e != nil || version != spec.Replace {
				return storage.ErrVersion
			}
			if e = fileaccess.CheckReplacementMeta(f); e != nil {
				return e
			}
			info, e := f.Stat()
			if e != nil {
				return e
			}
			key, e := fileaccess.FilesystemDevice(f)
			if e != nil {
				return e
			}
			return h.g.trashQuota(ctx, key, info.Size())
		}
		return h.g.Files.guard.CheckCreate(spec.RootPath, spec.Parent, spec.Name, p.Expected)
	}
	if _, e := h.specification(ctx, r); e != nil {
		return e
	}
	if e := h.g.Files.guard.CheckPrivateCapacity(2); e != nil {
		return e
	}
	records, e := h.g.Store.FileRecords(ctx, "transfer")
	if e != nil {
		return e
	}
	pending := 0
	for _, record := range records {
		if record.State != "published" && record.State != "purged" {
			pending++
		}
	}
	h.g.Files.mu.Lock()
	slots := len(h.g.Files.tickets) + pending + h.g.Files.preparing
	closed := h.g.Files.closed
	h.g.Files.mu.Unlock()
	if closed || slots >= 2 {
		return storage.ErrBusy
	}
	return nil
}
func (g *Gateway) transferRecord(ctx context.Context, id string) (storage.FileJournalRecord, writeSpec, error) {
	records, e := g.Store.FileRecords(ctx, "transfer")
	if e != nil {
		return storage.FileJournalRecord{}, writeSpec{}, e
	}
	for _, r := range records {
		if r.ID == id {
			var s writeSpec
			if json.Unmarshal(r.Document, &s) != nil {
				return r, s, storage.ErrSafety
			}
			return r, s, nil
		}
	}
	return storage.FileJournalRecord{}, writeSpec{}, storage.ErrNotFound
}
func (h fileTransferHandler) Effect(ctx context.Context, r operations.Request) operations.Outcome {
	if e := h.Check(ctx, r); e != nil {
		return fileMutationOutcome(nil, e, false)
	}
	if h.action == "files.transfer.commit" {
		return h.commit(ctx, r)
	}
	spec, e := h.specification(ctx, r)
	if e != nil {
		return fileMutationOutcome(nil, e, false)
	}
	releaseSlot, e := h.g.reserveTransfer(ctx)
	if e != nil {
		return fileMutationOutcome(nil, e, false)
	}
	defer releaseSlot()
	now := time.Now()
	finishJournal := h.g.Files.beginJournal(r.ID)
	defer finishJournal()
	doc, _ := json.Marshal(spec)
	record := storage.FileJournalRecord{ID: r.ID, Kind: "transfer", Owner: r.Actor, OperationID: r.ID, State: "planned", Bytes: spec.Size, Created: now.UnixMicro(), Expires: now.Add(time.Hour).UnixMicro(), Document: doc}
	if e = h.g.Store.SaveFileRecord(ctx, r.ID, record); e != nil {
		return fileMutationOutcome(nil, e, false)
	}
	area, e := h.g.Files.guard.Area(spec.RootPath, h.g.AgentID)
	if e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	spec.AreaProof, e = area.Proof()
	if e != nil {
		area.Close()
		return fileMutationOutcome(nil, e, true)
	}
	parent, e := h.g.Files.guard.Open(spec.RootPath, spec.Parent)
	if e != nil {
		area.Close()
		return fileMutationOutcome(nil, e, true)
	}
	spec.ParentVersion, e = fileaccess.Version(parent)
	parent.Close()
	if e != nil {
		area.Close()
		return fileMutationOutcome(nil, e, true)
	}
	f, e := area.New(r.ID)
	if e != nil {
		area.Close()
		return fileMutationOutcome(nil, e, true)
	}
	if e = area.Allocate(f, spec.Size); e != nil {
		f.Close()
		area.Close()
		return fileMutationOutcome(nil, e, true)
	}
	spec.Proof, e = fileaccess.IdentityProof(f)
	if e != nil {
		f.Close()
		area.Close()
		return fileMutationOutcome(nil, e, true)
	}
	record.State = "receiving"
	record.Document, _ = json.Marshal(spec)
	if e = h.g.Store.SaveFileRecord(ctx, r.ID, record); e != nil {
		f.Close()
		area.Close()
		return fileMutationOutcome(nil, e, true)
	}
	ticket := &writeTicket{record: record, spec: spec, file: f, area: area, used: now}
	h.g.Files.rememberDeadline(record)
	h.g.Files.mu.Lock()
	if h.g.Files.closed {
		h.g.Files.mu.Unlock()
		f.Close()
		area.Close()
		return fileMutationOutcome(nil, storage.ErrSafety, true)
	}
	if h.g.Files.uploads == nil {
		h.g.Files.uploads = map[string]*writeTicket{}
	}
	h.g.Files.uploads[r.ID] = ticket
	h.g.Files.mu.Unlock()
	value := map[string]any{"transfer_id": r.ID, "mode": spec.Mode, "file_version": spec.ParentVersion, "size_bytes": strconv.FormatInt(spec.Size, 10), "sha256": spec.SHA, "encoding": nil, "expires_at": timestamp(now.Add(300 * time.Second)), "truncated": false, "byte_from": "0", "byte_to": strconv.FormatInt(spec.Size, 10), "next_cursor": nil}
	if spec.Encoding != "" {
		value["encoding"] = spec.Encoding
	}
	if spec.Replace != "" {
		value["file_version"] = spec.Replace
	}
	result, _ := json.Marshal(value)
	return fileMutationOutcome(result, nil, false)
}
func (h fileTransferHandler) commit(ctx context.Context, r operations.Request) operations.Outcome {
	var p commitParams
	json.Unmarshal(r.Params, &p)
	record, spec, e := h.g.transferRecord(ctx, p.ID)
	if e != nil {
		return fileMutationOutcome(nil, e, false)
	}
	_, revision, e := h.g.fileConfig(ctx)
	if e != nil || revision != spec.Revision {
		return fileMutationOutcome(nil, storage.ErrVersion, false)
	}
	area, e := h.g.Files.guard.OpenArea(spec.RootPath, h.g.AgentID)
	if e != nil {
		return fileMutationOutcome(nil, e, false)
	}
	defer area.Close()
	proof, e := area.Proof()
	if e != nil || proof != spec.AreaProof {
		return fileMutationOutcome(nil, storage.ErrSafety, false)
	}
	f, e := area.Open(p.ID, spec.Proof)
	if e != nil {
		return fileMutationOutcome(nil, e, false)
	}
	defer f.Close()
	hash := sha256.New()
	n, e := io.Copy(hash, io.LimitReader(contextFileReader{ctx, f}, spec.Size+1))
	if e != nil || n != spec.Size || hex.EncodeToString(hash.Sum(nil)) != spec.SHA {
		return fileMutationOutcome(nil, storage.ErrVersion, false)
	}
	if spec.Mode == "edit" {
		if _, e = f.Seek(0, 0); e != nil {
			return fileMutationOutcome(nil, e, false)
		}
		b, e := io.ReadAll(io.LimitReader(f, 512001))
		if e != nil || len(b) > 512000 || !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 || (spec.Encoding == "utf-8-bom" && !bytes.HasPrefix(b, []byte{0xef, 0xbb, 0xbf})) || (spec.Encoding == "utf-8" && bytes.HasPrefix(b, []byte{0xef, 0xbb, 0xbf})) {
			return fileMutationOutcome(nil, storage.ErrInvalid, false)
		}
	}
	spec.ParentVersion = p.Expected
	if spec.Replace != "" {
		parent, e := h.g.Files.guard.Open(spec.RootPath, spec.Parent)
		if e != nil {
			return fileMutationOutcome(nil, e, false)
		}
		spec.ParentVersion, e = fileaccess.Version(parent)
		parent.Close()
		if e != nil {
			return fileMutationOutcome(nil, e, false)
		}
	}
	// Persist uncertainty before any backup/publication effect. A crash or a
	// failed result write can never make this staging file eligible for retry.
	record.State = "unknown"
	spec.RecoveryOperationID = r.ID
	record.Document, _ = json.Marshal(spec)
	if e = h.g.Store.SaveFileRecord(ctx, r.ID, record); e != nil {
		return fileMutationOutcome(nil, e, false)
	}
	if spec.Replace != "" {
		if _, e = h.g.preserveReplacement(ctx, r, area, spec); e != nil {
			return fileMutationOutcome(nil, e, true)
		}
	}
	if r.Credential != nil {
		if e = h.g.Store.CheckCredential(ctx, *r.Credential); e != nil {
			return fileMutationOutcome(nil, e, true)
		}
	}
	out, e := area.Publish(p.ID, f, spec.Parent, spec.Name, spec.ParentVersion, spec.Replace)
	if e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	defer out.Close()
	record.State = "published"
	if e = h.g.Store.SaveFileRecord(ctx, r.ID, record); e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	h.g.Files.mu.Lock()
	if t := h.g.Files.uploads[p.ID]; t != nil {
		t.mu.Lock()
		if !t.busy {
			t.file.Close()
			t.area.Close()
			delete(h.g.Files.uploads, p.ID)
		}
		t.mu.Unlock()
	}
	h.g.Files.mu.Unlock()
	value, e := h.g.presentFile(ctx, out, mustChild(spec.Parent, spec.Name))
	if e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	b, _ := json.Marshal(value)
	if _, e = contracts.Validate(bytes.NewReader(b), contracts.Target{Family: "api", Definition: "File"}, contracts.MaxJSONBytes); e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	return fileMutationOutcome(b, nil, false)
}
func mustChild(parent fileaccess.Location, name string) fileaccess.Location {
	l, _ := fileaccessChild(parent, name)
	return l
}
