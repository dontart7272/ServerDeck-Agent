// SPDX-License-Identifier: Apache-2.0
//go:build linux

package history

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"serverdeck.local/agent/internal/storage"
)

func historyFixture(t *testing.T) (*Engine, *storage.Telemetry) {
	t.Helper()
	b, err := os.ReadFile("../../../Документация ServerDeck/Документация ServerDeck Agent/contracts/examples/config.json")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Runtime json.RawMessage `json:"runtime_initial"`
	}
	json.Unmarshal(b, &cfg)
	s, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "state"), "11111111-1111-4111-8111-111111111111", cfg.Runtime, true, storage.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	db, err := s.OpenTelemetry(context.Background(), "history", 16000000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return NewEngine(db), db
}

func TestPersistentTiersPaginationRevisionsAndRetentionEpoch(t *testing.T) {
	e, db := historyFixture(t)
	ctx := context.Background()
	series := SeriesID("cpu", "busy_percent")
	for i := 0; i < 20; i++ {
		w := window(15*time.Second, Gauge)
		w.Series = series
		w.Segment = "22222222-2222-4222-8222-222222222222"
		w.Start = epoch.Add(time.Duration(i) * 15 * time.Second)
		b := mustAggregate(t, w, []Interval{{From: w.Start, To: w.Start.Add(w.Step), Covered: w.Step, Value: float64(i)}})
		e.buckets[bucketID(w)] = accumulated{Bucket: b, Unit: "percent", Key: "busy_percent", Resource: "cpu", Logical: "cpu:aggregate", Source: "fixture.cpu"}
		e.dirty[bucketID(w)] = true
	}
	if err := e.Flush(ctx, epoch.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	points, unit, current, _, last, step, more, err := e.Page(ctx, series, epoch, epoch.Add(time.Hour), 2, "", "")
	if err != nil || unit != "percent" || len(points) != 2 || step != 15000 || !more {
		t.Fatalf("first page %d %s %d %v %v", len(points), unit, step, more, err)
	}
	next, _, _, _, _, _, _, err := e.Page(ctx, series, epoch, epoch.Add(time.Hour), 2, last, current)
	if err != nil || len(next) != 2 || next[0].(map[string]any)["bucket_id"] == points[0].(map[string]any)["bucket_id"] {
		t.Fatal("page duplicate", err)
	}
	coarse, _, _, _, _, step, _, err := e.Page(ctx, series, epoch, epoch.Add(7*24*time.Hour), 2000, "", "")
	if err != nil || len(coarse) != 1 || step != 300000 {
		t.Fatalf("coarse %d %v", len(coarse), err)
	}
	stat := coarse[0].(map[string]any)["statistics"].(map[string]any)
	if stat["mean"] != 9.5 {
		t.Fatalf("weighted persisted statistics: %v", stat)
	}
	if err = db.Prune(ctx, epoch.Add(8*24*time.Hour).UnixMicro(), 100); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, _, _, _, err = e.Page(ctx, series, epoch, epoch.Add(time.Hour), 2, last, current); err != storage.ErrCursor {
		t.Fatalf("retention cursor did not gap: %v", err)
	}
	empty, unit, _, _, _, _, _, err := e.Page(ctx, series, epoch, epoch.Add(time.Hour), 2, "", "")
	if err != nil || len(empty) != 0 || unit != "percent" {
		t.Fatal("retention removed registry or invented zeros", err)
	}
}
