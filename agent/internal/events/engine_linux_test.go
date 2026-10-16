// SPDX-License-Identifier: Apache-2.0
//go:build linux

package events

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/metrics"
	"serverdeck.local/agent/internal/storage"
)

func eventFixture(t *testing.T) (*Engine, *storage.Telemetry, *storage.Store) {
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
	db, err := s.OpenTelemetry(context.Background(), "events", 32000000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	e, err := New(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	return e, db, s
}
func observation(base time.Time, second int, value float64, valid bool) metrics.Snapshot {
	at := contracts.Timestamp(base.Add(time.Duration(second) * time.Second))
	availability, fresh := "available", "fresh"
	if !valid {
		availability = "source_error"
		fresh = "unknown"
	}
	return metrics.Snapshot{SegmentID: "22222222-2222-4222-8222-222222222222", At: at, Blocks: []metrics.Block{{ID: "memory", Availability: availability, Metrics: []metrics.Metric{{Key: "available_percent", ResourceID: "ram", Unit: "percent", Value: value, Availability: availability, Freshness: fresh, MeasuredAt: &at}}}}}
}

func eventChanges(db *storage.Telemetry, ctx context.Context, epoch string, after int64, limit int) ([]storage.TelemetryRecord, string, int64, error) {
	rows, current, last, err := db.Changes(ctx, epoch, after, limit)
	out := []storage.TelemetryRecord{}
	for _, r := range rows {
		if r.Kind == "event" {
			out = append(out, r)
		}
	}
	return out, current, last, err
}
func TestThresholdBoundariesLossRecoveryRepeatAndRestart(t *testing.T) {
	e, db, _ := eventFixture(t)
	ctx := context.Background()
	r := storage.DefaultRules()[0]
	base := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	observe := func(second int, value float64, valid bool) {
		t.Helper()
		if err := e.Observe(ctx, []contracts.APIRule{r}, observation(base, second, value, valid), time.Duration(second)*time.Second); err != nil {
			t.Fatal(err)
		}
	}
	observe(0, 10, true)
	observe(120, 10, true)
	if len(e.Problems()) != 0 {
		t.Fatal("exact boundary triggered")
	}
	observe(121, 9, true)
	observe(240, 9, true)
	if len(e.Problems()) != 0 {
		t.Fatal("early trigger")
	}
	observe(241, 9, true)
	if len(e.Problems()) != 1 {
		t.Fatal("missing begin")
	}
	rows, epoch, last, err := eventChanges(db, ctx, "", 0, 100)
	if err != nil || len(rows) != 1 {
		t.Fatalf("begin %v %v", rows, err)
	}
	observe(250, 100, false)
	if e.Problems()[0].(map[string]any)["state"] != "source_unknown" {
		t.Fatal("source loss recovered")
	}
	observe(251, 16, true)
	observe(370, 16, true)
	if len(e.Problems()) != 1 {
		t.Fatal("early recovery")
	}
	observe(371, 16, true)
	if len(e.Problems()) != 0 {
		t.Fatal("missing recovery")
	}
	observe(400, 9, true)
	observe(520, 9, true)
	observe(4119, 9, true)
	rows, _, last, err = eventChanges(db, ctx, epoch, last, 100)
	if err != nil || len(rows) != 2 {
		t.Fatalf("unexpected repeat before hour: %d %v", len(rows), err)
	}
	observe(4120, 9, true)
	rows, _, _, err = eventChanges(db, ctx, epoch, last, 100)
	if err != nil || len(rows) != 1 || EventWire(rows[0], epoch)["kind"] != "repeat" {
		t.Fatal("repeat boundary")
	}
	if err = db.Prune(ctx, base.Add(24*time.Hour).UnixMicro(), 1); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(ctx, db)
	if err != nil || len(restarted.Problems()) != 1 {
		t.Fatalf("retention/restart lost active: %v", err)
	}
	if restarted.Problems()[0].(map[string]any)["state"] != "source_unknown" {
		t.Fatal("restart fabricated continuity")
	}
	if err = restarted.Observe(ctx, []contracts.APIRule{r}, observation(base, 5000, 16, true), 0); err != nil {
		t.Fatal(err)
	}
	if len(restarted.Problems()) != 1 {
		t.Fatal("restart continued recovery duration")
	}
}

func TestPendingBreaksOnSourceLossAndClockSegment(t *testing.T) {
	e, _, _ := eventFixture(t)
	ctx := context.Background()
	r := storage.DefaultRules()[0]
	base := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	for _, p := range []struct {
		sec   int
		valid bool
	}{{0, true}, {119, false}, {120, true}, {239, true}} {
		if err := e.Observe(ctx, []contracts.APIRule{r}, observation(base, p.sec, 9, p.valid), time.Duration(p.sec)*time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if len(e.Problems()) != 0 {
		t.Fatal("missing source interval counted")
	}
	s := observation(base, 240, 9, true)
	s.SegmentID = "33333333-3333-4333-8333-333333333333"
	if err := e.Observe(ctx, []contracts.APIRule{r}, s, 240*time.Second); err != nil {
		t.Fatal(err)
	}
	if len(e.Problems()) != 0 {
		t.Fatal("clock segment counted continuously")
	}
}
