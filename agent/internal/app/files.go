// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/fileaccess"
	"serverdeck.local/agent/internal/storage"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

type fileService struct {
	inventoryVerified bool // Only a complete owned-artifact inventory may authorize live reads.
	preparing         int
	reads             chan struct{}
	guard             *fileaccess.Guard
	mu                sync.Mutex
	tickets           map[string]*readTicket
	uploads           map[string]*writeTicket
	inflight          map[string]bool
	deadlines         map[string]time.Time
	closed            bool
}
type readTicket struct {
	owner, revision, version, digest string
	file                             *os.File
	data                             []byte
	size                             int64
	created, timeUsed                time.Time
	busy                             bool
}
type fileParams struct {
	Location fileaccess.Location `json:"location"`
	Sort     string              `json:"sort"`
	Order    string              `json:"order"`
	Cursor   string              `json:"cursor"`
	Limit    int                 `json:"limit"`
	Mode     string              `json:"mode"`
	Lines    int                 `json:"lines"`
	Expected string              `json:"expected_version"`
}

func (g *Gateway) fileConfig(ctx context.Context) (contracts.RuntimeConfig, string, error) {
	b, revision, e := g.Store.Settings(ctx)
	var c contracts.RuntimeConfig
	if e != nil {
		return c, "", e
	}
	if json.Unmarshal(b, &c) != nil {
		return c, "", storage.ErrStorage
	}
	return c, strconv.FormatInt(revision, 10), nil
}
func rootPath(c contracts.RuntimeConfig, id string) (string, error) {
	for _, r := range c.Files.Roots {
		if string(r.RootID) == id {
			return r.Path, nil
		}
	}
	return "", storage.ErrPolicy
}
func (g *Gateway) fileQuery(ctx context.Context, name string, raw []byte) (result any, failure error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if g.Files == nil {
		return nil, storage.ErrSafety
	}
	select {
	case g.Files.reads <- struct{}{}:
		defer func() { <-g.Files.reads }()
	default:
		return nil, storage.ErrBusy
	}
	var p fileParams
	if decodeStrict(raw, &p) != nil {
		return nil, storage.ErrInvalid
	}
	c, revision, e := g.fileConfig(ctx)
	if e != nil {
		return nil, e
	}
	defer func() {
		if failure != nil {
			return
		}
		_, current, e := g.fileConfig(ctx)
		if e != nil || current != revision {
			failure = storage.ErrVersion
		} else if name != "files.roots" && g.filesReady(ctx) != nil {
			failure = storage.ErrSafety
		}
		if failure == nil {
			return
		}
		if m, ok := result.(map[string]any); ok {
			if id, ok := m["transfer_id"].(string); ok {
				g.Files.mu.Lock()
				if ticket := g.Files.tickets[id]; ticket != nil && !ticket.busy {
					if ticket.file != nil {
						ticket.file.Close()
					}
					delete(g.Files.tickets, id)
				}
				g.Files.mu.Unlock()
			}
		}
		result = nil
	}()
	if name == "files.roots" {
		items := []any{}
		for _, r := range c.Files.Roots {
			loc := fileaccess.Location{RootID: string(r.RootID), Components: []string{}}
			var f *os.File
			var e error
			if g.filesReady(ctx) != nil {
				e = storage.ErrSafety
			} else {
				f, e = g.Files.guard.Open(r.Path, loc)
			}
			var reason any
			actions := fileActions(revision)
			var availableBytes any
			fs := "unavailable:" + string(r.RootID)
			if e != nil {
				reason = errorCode(e)
			} else {
				fs, _ = fileaccess.Filesystem(f)
				actions = g.fileActionsFor(f, loc, r.Path)
				if free, e := fileaccess.AvailableBytes(f); e == nil {
					availableBytes = strconv.FormatInt(free, 10)
				}
				f.Close()
			}
			items = append(items, map[string]any{"root_id": r.RootID, "display_name": filepath.Base(r.Path), "path": r.Path, "version": revision, "filesystem_id": fs, "available_bytes": availableBytes, "actions": actions, "reason": reason})
		}
		return map[string]any{"items": items, "version": revision}, nil
	}
	if g.filesReady(ctx) != nil {
		return nil, storage.ErrSafety
	}
	path, e := rootPath(c, p.Location.RootID)
	if e != nil {
		return nil, e
	}
	f, e := g.Files.guard.Open(path, p.Location)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	switch name {
	case "files.stat":
		record, e := fileRecord(f, p.Location)
		if e == nil {
			record["actions"] = g.fileActionsFor(f, p.Location, path)
		}
		return record, e
	case "files.list":
		return g.fileList(ctx, c, p, f, path)
	case "files.text", "files.download":
		return g.fileTicket(ctx, name, c, revision, p, f)
	}
	return nil, storage.ErrInvalid
}
func fileActions(version string) []any {
	items := []any{}
	for _, id := range []string{"files.create", "files.write.begin", "files.upload.begin", "files.rename", "files.move", "files.trash"} {
		items = append(items, map[string]any{"id": id, "available": false, "reason": "SAFETY_UNAVAILABLE", "version": version})
	}
	return items
}

func (g *Gateway) fileActionsFor(f *os.File, l fileaccess.Location, root string) []any {
	v, e := fileaccess.Version(f)
	if e != nil {
		return fileActions("")
	}
	info, e := f.Stat()
	if e != nil {
		return fileActions(v)
	}
	writable := info.IsDir() && fileaccess.Access(f, 3) == nil
	removable := false
	if len(l.Components) > 0 && g.Files.guard.CanRemove(f) == nil {
		p := fileaccess.Location{RootID: l.RootID, Components: append([]string{}, l.Components[:len(l.Components)-1]...)}
		parent, e := g.Files.guard.Open(root, p)
		if e == nil {
			removable = fileaccess.Access(parent, 3) == nil
			parent.Close()
		}
	}
	health := g.Store.Health()
	audit := health.Available && health.AuditAvailable
	items := []any{}
	for _, id := range []string{"files.create", "files.upload.begin", "files.write.begin", "files.rename", "files.move", "files.trash"} {
		available := removable
		if id == "files.create" || id == "files.upload.begin" {
			available = writable
		}
		if id == "files.write.begin" {
			available = removable && info.Mode().IsRegular() && fileaccess.CheckReplacementMeta(f) == nil
		}
		var reason any
		if !available {
			reason = "SAFETY_UNAVAILABLE"
		}
		if !audit {
			available = false
			reason = "AUDIT_UNAVAILABLE"
		}
		items = append(items, map[string]any{"id": id, "available": available, "reason": reason, "version": v})
	}
	return items
}
func (g *Gateway) presentFile(ctx context.Context, f *os.File, l fileaccess.Location) (map[string]any, error) {
	r, e := fileRecord(f, l)
	if e != nil {
		return nil, e
	}
	c, _, e := g.fileConfig(ctx)
	if e != nil {
		return nil, e
	}
	root, e := rootPath(c, l.RootID)
	if e != nil {
		return nil, e
	}
	r["actions"] = g.fileActionsFor(f, l, root)
	return r, nil
}
func fileRecord(f *os.File, l fileaccess.Location) (map[string]any, error) {
	info, e := fileaccess.Stat(f)
	if e != nil {
		return nil, storage.ErrSafety
	}
	mode, uid, gid, mt, ct, e := fileaccess.StatFields(f)
	if e != nil {
		return nil, e
	}
	version, e := fileaccess.Version(f)
	if e != nil {
		return nil, e
	}
	fs, e := fileaccess.Filesystem(f)
	if e != nil {
		return nil, e
	}
	kind := "special"
	var size any
	if info.Mode().IsRegular() {
		if info.Size() < 0 {
			return nil, storage.ErrSafety
		}
		kind = "file"
		size = strconv.FormatInt(info.Size(), 10)
	} else if info.IsDir() {
		kind = "directory"
	} else if info.Mode()&os.ModeSymlink != 0 {
		kind = "symlink"
	}
	name := "/"
	if len(l.Components) > 0 {
		name = l.Components[len(l.Components)-1]
		b, _ := base64.RawURLEncoding.Strict().DecodeString(name)
		if utf8.Valid(b) && strings.IndexFunc(string(b), func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) < 0 {
			name = string(b)
		} else {
			name = "base64:" + name
		}
	}
	if !utf8.ValidString(name) {
		return nil, storage.ErrSafety
	}
	return map[string]any{"location": l, "display_name": name, "kind": kind, "size_bytes": size, "modified_at": fileTimestamp(mt), "changed_at": fileTimestamp(ct), "mode": fmt.Sprintf("%04o", mode&07777), "uid": uid, "gid": gid, "version": version, "filesystem_id": fs, "actions": fileActions(version)}, nil
}
func (g *Gateway) fileList(ctx context.Context, c contracts.RuntimeConfig, p fileParams, f *os.File, path string) (any, error) {
	if p.Limit == 0 {
		p.Limit = 100
	}
	if p.Limit < 1 || p.Limit > 100 {
		return nil, storage.ErrInvalid
	}
	if p.Sort != "name" && p.Sort != "size" && p.Sort != "modified" {
		return nil, storage.ErrInvalid
	}
	if p.Order != "asc" && p.Order != "desc" {
		return nil, storage.ErrInvalid
	}
	version, e := fileaccess.Version(f)
	if e != nil {
		return nil, e
	}
	owner, _ := ctx.Value(metricOwnerKey{}).(string)
	digest := scopeJSON(p.Location) + ":" + owner + ":" + p.Sort + ":" + p.Order + ":" + scopeJSON(c.Files)
	dir, e := g.Files.guard.Directory(f)
	if e != nil {
		return nil, e
	}
	defer dir.Close()
	names, e := dir.Readdirnames(4097)
	if e != nil && e != io.EOF {
		return nil, storage.ErrSafety
	}
	if len(names) > 4096 {
		return nil, fileaccess.ErrLimit
	}
	records := []map[string]any{}
	complete := true
	for _, name := range names {
		if ctx.Err() != nil {
			return nil, storage.ErrSafety
		}

		loc := p.Location
		loc.Components = append(append([]string{}, p.Location.Components...), base64.RawURLEncoding.EncodeToString([]byte(name)))
		entry, e := g.Files.guard.Open(path, loc)
		if e != nil {
			complete = false
			continue
		}
		record, e := fileRecord(entry, loc)
		if e == nil {
			record["actions"] = g.fileActionsFor(entry, loc, path)
		}
		entry.Close()
		if e != nil {
			complete = false
			continue
		}
		records = append(records, record)
	}
	after, e := fileaccess.Version(f)
	if e != nil || after != version {
		return nil, storage.ErrVersion
	}
	sort.Slice(records, func(i, j int) bool {
		a, b := records[i], records[j]
		an, bn := a["display_name"].(string), b["display_name"].(string)
		less := an < bn
		if an == bn {
			al, bl := a["location"].(fileaccess.Location), b["location"].(fileaccess.Location)
			less = al.Components[len(al.Components)-1] < bl.Components[len(bl.Components)-1]
		}
		if p.Sort == "size" {
			av, _ := a["size_bytes"].(string)
			bv, _ := b["size_bytes"].(string)
			ai, _ := strconv.ParseUint(av, 10, 64)
			bi, _ := strconv.ParseUint(bv, 10, 64)
			if ai != bi {
				less = ai < bi
			}
		} else if p.Sort == "modified" {
			av, _ := a["modified_at"].(string)
			bv, _ := b["modified_at"].(string)
			at, _ := time.Parse(time.RFC3339Nano, av)
			bt, _ := time.Parse(time.RFC3339Nano, bv)
			if !at.Equal(bt) {
				less = at.Before(bt)
			}
		}
		if p.Order == "desc" {
			return !less
		}
		return less
	})
	version = scopeJSON(records)
	cursor, e := g.position(p.Cursor, "files.list", digest)
	if e != nil {
		return nil, e
	}
	if p.Cursor != "" && cursor.Epoch != version {
		return nil, storage.ErrVersion
	}
	if cursor.Position < 0 || cursor.Position > int64(len(records)) {
		return nil, storage.ErrCursor
	}
	end := int(cursor.Position) + p.Limit
	if end > len(records) {
		end = len(records)
	}
	items := []any{}
	for _, r := range records[int(cursor.Position):end] {
		items = append(items, r)
	}
	var next any
	if end < len(records) {
		next, e = g.cursor("files.list", version, digest, int64(end))
		if e != nil {
			return nil, e
		}
	}
	out := page(items, next, version)
	out["coverage"].(map[string]any)["complete"] = complete
	return out, nil
}
func scopeJSON(v any) string {
	b, e := json.Marshal(v)
	if e != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (g *Gateway) fileTicket(ctx context.Context, name string, c contracts.RuntimeConfig, revision string, p fileParams, f *os.File) (any, error) {
	pending, e := g.pendingTransfers(ctx)
	if e != nil {
		return nil, e
	}
	g.Files.mu.Lock()
	g.Files.reapLocked()
	if g.Files.closed || g.Files.transferSlotsLocked(pending) >= 2 {
		g.Files.mu.Unlock()
		return nil, storage.ErrBusy
	}
	g.Files.preparing++
	g.Files.mu.Unlock()
	defer func() { g.Files.mu.Lock(); g.Files.preparing--; g.Files.mu.Unlock() }()
	owner, _ := ctx.Value(metricOwnerKey{}).(string)
	if owner == "" {
		return nil, storage.ErrUnauthorized
	}
	version, e := fileaccess.Version(f)
	if e != nil {
		return nil, e
	}
	if name == "files.download" && p.Expected != version {
		return nil, storage.ErrVersion
	}
	r, e := g.Files.guard.ReadFile(f)
	if e != nil {
		return nil, e
	}
	keep := false
	defer func() {
		if !keep {
			r.Close()
		}
	}()
	info, e := r.Stat()
	if e != nil || info.Size() < 0 {
		return nil, storage.ErrSafety
	}
	mode := "download"
	limit := c.Files.DownloadBytes
	if name == "files.text" {
		limit = c.Files.FullTextBytes
		if limit > 1000000 {
			limit = 1000000
		}
		if p.Mode != "full" && p.Mode != "tail" {
			return nil, storage.ErrInvalid
		}
	}
	if info.Size() > limit && !(name == "files.text" && p.Mode == "tail") {
		return nil, fileaccess.ErrLimit
	}
	ticket := &readTicket{owner: owner, revision: revision, version: version, file: r, size: info.Size(), created: time.Now(), timeUsed: time.Now()}
	var encoding any
	var next any
	var from int64
	truncated := false
	if name == "files.text" {
		mode = "text"
		if p.Mode == "full" && p.Cursor != "" {
			return nil, storage.ErrInvalid
		}
		endOffset := info.Size()
		digest := scopeJSON(p.Location) + ":" + owner + ":" + strconv.Itoa(p.Lines) + ":" + scopeJSON(c.Files)
		if p.Cursor != "" {
			position, e := g.position(p.Cursor, "files.text", digest)
			if e != nil {
				return nil, e
			}
			if position.Epoch != version || position.Position < 0 || position.Position > info.Size() {
				return nil, storage.ErrVersion
			}
			endOffset = position.Position
		}
		start := int64(0)
		if p.Mode == "tail" {
			if p.Lines != 100 && p.Lines != 500 && p.Lines != 1000 {
				return nil, storage.ErrInvalid
			}
			if endOffset > 8000000 {
				start = endOffset - 8000000
			}
			if _, e = r.Seek(start, 0); e != nil {
				return nil, storage.ErrSafety
			}
		}
		cap := limit
		if p.Mode == "tail" {
			cap = 8000000
		}
		scanLimit := cap + 1
		if p.Mode == "tail" {
			scanLimit = endOffset - start
		}
		b, e := io.ReadAll(io.LimitReader(contextFileReader{ctx, r}, scanLimit))
		if e != nil {
			return nil, fileaccess.ErrSource
		}
		if int64(len(b)) > cap {
			return nil, fileaccess.ErrLimit
		}
		if p.Mode == "tail" {
			end := len(b)
			if end > 0 && b[end-1] == '\n' {
				end--
			}
			count := 0
			index := end
			for index > 0 {
				index--
				if b[index] == '\n' {
					count++
					if count == p.Lines {
						index++
						break
					}
				}
			}
			if int64(len(b)-index) > limit {
				index = len(b) - int(limit)
				truncated = true
				for index < len(b) && !utf8.RuneStart(b[index]) {
					index++
				}
			}
			if start > 0 {
				for index < len(b) && !utf8.RuneStart(b[index]) {
					index++
				}
			}
			from = start + int64(index)
			b = b[index:]
			truncated = truncated || from > 0
		}
		if !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
			return nil, storage.ErrSafety
		}
		enc := "utf-8"
		if from == 0 && bytes.HasPrefix(b, []byte{0xef, 0xbb, 0xbf}) {
			enc = "utf-8-bom"
		}
		encoding = enc
		if p.Mode == "tail" && from > 0 {
			next, e = g.cursor("files.text", version, digest, from)
			if e != nil {
				return nil, e
			}
		}
		ticket.data = b
		ticket.size = int64(len(b))
		ticket.file = nil
	}
	after, e := fileaccess.Version(r)
	if e != nil || after != version {
		return nil, storage.ErrVersion
	}
	hash := sha256.New()
	if ticket.file != nil {
		if _, e = r.Seek(0, 0); e != nil {
			return nil, storage.ErrSafety
		}
		n, e := io.Copy(hash, io.LimitReader(contextFileReader{ctx, r}, limit+1))
		if e != nil {
			return nil, fileaccess.ErrSource
		}
		if n > limit {
			return nil, fileaccess.ErrLimit
		}
		if n != ticket.size {
			return nil, storage.ErrVersion
		}
		if _, e = r.Seek(0, 0); e != nil {
			return nil, storage.ErrSafety
		}
		after, e = fileaccess.Version(r)
		if e != nil || after != version {
			return nil, storage.ErrVersion
		}
	} else {
		hash.Write(ticket.data)
	}
	ticket.digest = hex.EncodeToString(hash.Sum(nil))
	id, e := storage.RandomID()
	if e != nil {
		return nil, e
	}
	g.Files.mu.Lock()
	defer g.Files.mu.Unlock()
	g.Files.reapLocked()
	if g.Files.closed || g.Files.transferSlotsLocked(pending) > 2 {
		return nil, storage.ErrBusy
	}
	g.Files.tickets[id] = ticket
	keep = ticket.file != nil
	return map[string]any{"transfer_id": id, "mode": mode, "file_version": version, "size_bytes": strconv.FormatInt(ticket.size, 10), "sha256": ticket.digest, "encoding": encoding, "expires_at": timestamp(ticket.created.Add(300 * time.Second)), "truncated": truncated, "byte_from": strconv.FormatInt(from, 10), "byte_to": strconv.FormatInt(from+ticket.size, 10), "next_cursor": next}, nil
}

func (g *Gateway) pendingTransfers(ctx context.Context) (map[string]bool, error) {
	rows, e := g.Store.FileRecords(ctx, "transfer")
	if e != nil {
		return nil, e
	}
	ids := map[string]bool{}
	for _, r := range rows {
		if r.State != "published" && r.State != "purged" {
			ids[r.ID] = true
		}
	}
	return ids, nil
}
func (s *fileService) transferSlotsLocked(ids map[string]bool) int {
	set := map[string]bool{}
	for id := range ids {
		set[id] = true
	}
	for id := range s.uploads {
		set[id] = true
	}
	return len(set) + len(s.tickets) + s.preparing
}
func (g *Gateway) reserveTransfer(ctx context.Context) (func(), error) {
	ids, e := g.pendingTransfers(ctx)
	if e != nil {
		return nil, e
	}
	g.Files.mu.Lock()
	defer g.Files.mu.Unlock()
	if g.Files.closed || g.Files.transferSlotsLocked(ids) >= 2 {
		return nil, storage.ErrBusy
	}
	g.Files.preparing++
	return func() { g.Files.mu.Lock(); g.Files.preparing--; g.Files.mu.Unlock() }, nil
}
func (s *fileService) reapLocked() {
	for id, t := range s.tickets {
		if !t.busy && (time.Since(t.created) >= time.Hour || time.Since(t.timeUsed) >= 300*time.Second) {
			if t.file != nil {
				t.file.Close()
			}
			delete(s.tickets, id)
		}
	}
}
func (s *fileService) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for id, t := range s.uploads {
		t.mu.Lock()
		t.closed = true
		if !t.busy {
			t.file.Close()
			t.area.Close()
		}
		t.mu.Unlock()
		delete(s.uploads, id)
	}
	for id, t := range s.tickets {
		if !t.busy {
			if t.file != nil {
				t.file.Close()
			}
			delete(s.tickets, id)
		}
	}
	s.guard.Close()
}

// Only the process that owns an active, already audited effect may tolerate
// its incomplete journal proof. After restart this marker does not exist.
func (s *fileService) beginJournal(id string) func() {
	s.mu.Lock()
	if s.inflight == nil {
		s.inflight = map[string]bool{}
	}
	s.inflight[id] = true
	s.mu.Unlock()
	return func() { s.mu.Lock(); delete(s.inflight, id); s.mu.Unlock() }
}

type contextFileReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextFileReader) Read(b []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.r.Read(b)
}

func fileTimestamp(t time.Time) any {
	if t.Year() < 1 || t.Year() > 9999 {
		return nil
	}
	return timestamp(t)
}

// One-shot activation: a stalled native lookup cannot block the monitoring
// listeners or publish a late guard. No timeout-driven worker multiplication.
func boundedFileActivation(build func() *fileService, wait time.Duration) *fileService {
	result := make(chan *fileService)
	aborted := make(chan struct{})
	defer close(aborted)
	go func() {
		s := build()
		select {
		case result <- s:
		case <-aborted:
			if s != nil {
				s.Close()
			}
		}
	}()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case s := <-result:
		return s
	case <-timer.C:
		return nil
	}
}
