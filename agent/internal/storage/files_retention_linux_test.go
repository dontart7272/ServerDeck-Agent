//go:build linux && cgo

// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestE08JournalRotationNeverEvictsUnknown(t *testing.T) {
	s, _ := testStore(t, DefaultLimits())
	ctx := context.Background()
	id, _ := RandomID()
	running(t, s, id, "system.files.cleanup", "files.mutations")
	now := time.Now()
	old := now.Add(-16 * 24 * time.Hour).UnixMicro()
	expires := now.Add(-15 * 24 * time.Hour).UnixMicro()
	ids := map[string]string{}
	for _, state := range []string{"published", "restored", "purged", "unknown", "planned", "receiving", "ready", "trashed"} {
		rid, _ := RandomID()
		ids[state] = rid
		r := FileJournalRecord{ID: rid, Kind: "transfer", Owner: "local:1000", OperationID: id, State: state, Bytes: 0, Created: old, Expires: expires, Document: json.RawMessage(`{}`)}
		if e := s.SaveFileRecord(ctx, id, r); e != nil {
			t.Fatal(e)
		}
	}
	rotate, _ := RandomID()
	running(t, s, rotate, "system.files.rotate", "files.rotate")
	if _, e := s.db.Exec("UPDATE operations SET actor='system:files' WHERE id=?", rotate); e != nil {
		t.Fatal(e)
	}
	if e := s.RotateFileRecords(ctx, rotate); e != ErrSafety {
		t.Fatal("untrusted restart clock allowed rotation", e)
	}
	s.started = now.Add(-8 * 24 * time.Hour)
	s.wallStart = now.Add(-8 * 24 * time.Hour)
	if e := s.RotateFileRecords(ctx, rotate); e != nil {
		t.Fatal(e)
	}
	rows, e := s.FileRecords(ctx, "transfer")
	if e != nil {
		t.Fatal(e)
	}
	remaining := map[string]bool{}
	for _, r := range rows {
		remaining[r.ID] = true
	}
	for state, id := range ids {
		terminal := state == "published" || state == "restored" || state == "purged"
		if remaining[id] == terminal {
			t.Fatal("wrong retention decision", state)
		}
	}
	if s.FileRetentionElapsed(ctx, 30*24*time.Hour) {
		t.Fatal("seven days treated as thirty days")
	}
	if !s.FileRetentionElapsed(ctx, time.Hour) {
		t.Fatal("monotonic lower-bound retention unavailable")
	}
}
