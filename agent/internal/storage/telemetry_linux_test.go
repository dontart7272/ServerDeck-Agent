// SPDX-License-Identifier: Apache-2.0
//go:build linux

package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTelemetryAtomicStateRotationRestartAndIsolation(t *testing.T) {
	s, path := testStore(t, DefaultLimits())
	ctx := context.Background()
	tm, e := s.OpenTelemetry(ctx, "events", 32000000)
	if e != nil {
		t.Fatal(e)
	}
	r := TelemetryRecord{Kind: "problem", ID: testOperation, Series: "resource", Segment: testDevice, Start: 1, Stop: 1, Revision: 1, Data: json.RawMessage(`{"state":"active"}`)}
	if e = tm.Update(ctx, []TelemetryRecord{r}, []TelemetryRecord{r}, nil); e != nil {
		t.Fatal(e)
	}
	_, epoch, last, e := tm.Changes(ctx, "", 0, 100)
	if e != nil || last != 1 {
		t.Fatalf("%s %d %v", epoch, last, e)
	}
	if e = tm.Prune(ctx, 2, 10); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = tm.Changes(ctx, epoch, 0, 100); e != ErrCursor {
		t.Fatalf("gap: %v", e)
	}
	rows, _, _, e := tm.Records(ctx, "problem", "", 0, 0, 10, "", 100)
	if e != nil || len(rows) != 1 {
		t.Fatalf("active lost: %v %v", rows, e)
	}
	tm.Close()
	tm, e = s.OpenTelemetry(ctx, "events", 32000000)
	if e != nil {
		t.Fatal(e)
	}
	defer tm.Close()
	rows, _, _, e = tm.Records(ctx, "problem", "", 0, 0, 10, "", 100)
	if e != nil || len(rows) != 1 {
		t.Fatal("restart lost active")
	}
	_, e = tm.db.Exec("CREATE TRIGGER reject_changes BEFORE INSERT ON changes BEGIN SELECT RAISE(ABORT,'fixture'); END")
	if e != nil {
		t.Fatal(e)
	}
	r.Revision = 2
	r.Data = json.RawMessage(`{"state":"source_unknown"}`)
	if tm.Update(ctx, []TelemetryRecord{r}, []TelemetryRecord{r}, nil) == nil {
		t.Fatal("failure hidden")
	}
	rows, _, _, e = tm.Records(ctx, "problem", "", 0, 0, 10, "", 100)
	if e != nil || string(rows[0].Data) != `{"state":"active"}` {
		t.Fatal("partial event transaction")
	}
	if _, _, e = s.Settings(ctx); e != nil {
		t.Fatal("independent DB failure damaged critical state")
	}
	for _, name := range []string{"events.db", "events.db-wal", "events.db-shm"} {
		st, e := os.Stat(filepath.Join(path, name))
		if e != nil || st.Mode().Perm()&0077 != 0 {
			t.Fatalf("permissions %s %v", name, e)
		}
	}
}

func TestTelemetryQuotaReadOnlyCorruptionAndSchema(t *testing.T) {
	s, path := testStore(t, DefaultLimits())
	ctx := context.Background()
	tm, e := s.OpenTelemetry(ctx, "history", 16000000)
	if e != nil {
		t.Fatal(e)
	}
	r := TelemetryRecord{Kind: "bucket", ID: "bucket", Series: "cpu", Segment: testDevice, Level: 15000, Start: 1, Stop: 2, Revision: 1, Data: json.RawMessage(`{"mean":1}`)}
	if _, e = tm.db.Exec("PRAGMA query_only=ON"); e != nil {
		t.Fatal(e)
	}
	if tm.Update(ctx, []TelemetryRecord{r}, nil, nil) == nil {
		t.Fatal("read-only accepted")
	}
	if _, e = tm.db.Exec("PRAGMA query_only=OFF"); e != nil {
		t.Fatal(e)
	}
	tm.budget = 65536
	if tm.Update(ctx, []TelemetryRecord{r}, nil, nil) != ErrQuota {
		t.Fatal("quota ignored")
	}
	tm.budget = 16000000
	if e = tm.Update(ctx, []TelemetryRecord{r}, nil, nil); e != nil {
		t.Fatal(e)
	}
	if _, e = tm.db.Exec("CREATE TABLE unexpected(x)"); e != nil {
		t.Fatal(e)
	}
	tm.Close()
	if reopened, e := s.OpenTelemetry(ctx, "history", 16000000); e == nil {
		reopened.Close()
		t.Fatal("schema tamper accepted")
	}
	db, e := sql.Open("sqlite3", filepath.Join(path, "history.db"))
	if e != nil {
		t.Fatal(e)
	}
	db.Exec("DROP TABLE unexpected")
	db.Close()
	if e = os.WriteFile(filepath.Join(path, "history.db"), []byte("corrupt fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	if reopened, e := s.OpenTelemetry(ctx, "history", 16000000); e == nil {
		reopened.Close()
		t.Fatal("corruption replaced")
	}
	if _, _, e = s.Settings(ctx); e != nil {
		t.Fatal("critical state affected")
	}
}

func TestTelemetryPinnedReaderCheckpointAndDeadline(t *testing.T) {
	s, path := testStore(t, DefaultLimits())
	ctx := context.Background()
	tm, e := s.OpenTelemetry(ctx, "history", 16000000)
	if e != nil {
		t.Fatal(e)
	}
	defer tm.Close()
	r := TelemetryRecord{Kind: "bucket", ID: "a", Series: "cpu", Segment: testDevice, Start: 1, Stop: 2, Revision: 1, Data: json.RawMessage(`{}`)}
	if e = tm.Update(ctx, []TelemetryRecord{r}, nil, nil); e != nil {
		t.Fatal(e)
	}
	reader, e := sql.Open("sqlite3", filepath.Join(path, "history.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer reader.Close()
	tx, e := reader.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	var n int
	if e = tx.QueryRow("SELECT count(*) FROM records").Scan(&n); e != nil {
		t.Fatal(e)
	}
	r.Revision++
	start := time.Now()
	e = tm.Update(ctx, []TelemetryRecord{r}, nil, nil)
	if time.Since(start) > 2*time.Second {
		t.Fatal("checkpoint blocked indefinitely")
	}
	if e != nil && e != ErrStorage && e != ErrQuota {
		t.Fatal(e)
	}
	short, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, _, e = tm.Records(short, "bucket", "", 0, 0, 10, "", 100); e == nil {
		t.Fatal("cancellation ignored")
	}
}
