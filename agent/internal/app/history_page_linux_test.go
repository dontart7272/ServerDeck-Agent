//go:build linux

// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"math"
	"path/filepath"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/history"
	"serverdeck.local/agent/internal/operations"
	"serverdeck.local/agent/internal/storage"
	"testing"
	"time"
)

func TestHistoryLargePageContinuationAndDurableRegistry(t *testing.T) {
	g, _, _ := newTestGateway(t)
	ctx := context.Background()
	series := history.SeriesID("fixture.cpu", "busy_percent")
	base := time.Now().UTC().Truncate(5 * time.Minute).Add(-7 * 24 * time.Hour)
	segment := newID(t)
	meta, _ := json.Marshal(map[string]string{"unit": "percent", "key": "busy_percent", "resource_id": "fixture.cpu", "logical_key": "cpu:aggregate", "source": "fixture.cpu"})
	if err := g.historyDB.Update(ctx, []storage.TelemetryRecord{{Kind: "series", ID: series, Series: series, Start: 0, Stop: math.MaxInt64, Revision: 1, Data: meta}}, nil, nil); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2010; {
		records := []storage.TelemetryRecord{}
		for j := 0; j < 16 && i < 2010; j++ {
			start := base.Add(time.Duration(i) * 5 * time.Minute)
			bucket := history.Bucket{Window: history.Window{Series: series, Segment: segment, Start: start, Step: 5 * time.Minute, Revision: 1, Kind: history.Gauge, Closed: true}, Covered: 5 * time.Minute, SampleCount: 1, WeightedSum: 300, Mean: 1, Maximum: 1, Last: 1, HasValue: true, Complete: true, LastAt: start.Add(5 * time.Minute)}
			data, _ := json.Marshal(struct {
				Bucket                               history.Bucket
				Unit, Key, Resource, Logical, Source string
			}{bucket, "percent", "busy_percent", "fixture.cpu", "cpu:aggregate", "fixture.cpu"})
			id := start.Format("20060102T150405") + ":" + series + ":" + segment + ":300000"
			records = append(records, storage.TelemetryRecord{Kind: "bucket", ID: id, Series: series, Segment: segment, Level: 300000, Start: start.UnixMicro(), Stop: start.Add(5 * time.Minute).UnixMicro(), Revision: 1, Data: data})
			i++
		}
		if err := g.historyDB.Update(ctx, records, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	// A fresh engine discovers persisted metadata without the collector's RAM.
	g.History = history.NewEngine(g.historyDB)
	registry, _, err := g.History.Registry(ctx, "busy_percent", "cpu:aggregate")
	if err != nil || len(registry) != 1 {
		t.Fatal("registry after engine restart", err)
	}
	_, token := pairDirect(t, g)
	_, other := pairDirect(t, g)
	srv, client, _ := testHTTPS(t, g, false)
	params := map[string]any{"series_ids": []string{series}, "from": base.Format(time.RFC3339Nano), "to": base.Add(7 * 24 * time.Hour).Format(time.RFC3339Nano), "max_points": 2000}
	status, raw := query(t, client, srv.URL, token, "history.get", params)
	if status != 200 || len(raw) > contracts.MaxHistoryBytes {
		t.Fatal(status, len(raw), string(raw[:min(200, len(raw))]))
	}
	if _, err = contracts.Validate(bytes.NewReader(raw), contracts.Target{Family: "api", Definition: "QueryResponse"}, contracts.MaxHistoryBytes); err != nil {
		t.Fatal(err)
	}
	data := decodeMap(t, raw)["data"].(map[string]any)
	points := data["items"].([]any)[0].(map[string]any)["points"].([]any)
	if len(points) != 2000 {
		t.Fatal("silently truncated", len(points))
	}
	params["cursor"] = data["next_cursor"]
	if status, _ = query(t, client, srv.URL, other, "history.get", params); status == 200 {
		t.Fatal("cross actor history cursor")
	}
	status, raw = query(t, client, srv.URL, token, "history.get", params)
	if status != 200 {
		t.Fatal(status, string(raw))
	}
	data = decodeMap(t, raw)["data"].(map[string]any)
	next := data["items"].([]any)[0].(map[string]any)["points"].([]any)
	if len(next) != 10 || data["next_cursor"] != nil || points[1999].(map[string]any)["bucket_id"] == next[0].(map[string]any)["bucket_id"] {
		t.Fatal("continuation missing/duplicate", len(next))
	}
}

func TestTelemetryMutationCannotBypassFailedAudit(t *testing.T) {
	g, path, _ := newTestGateway(t)
	ctx := context.Background()
	rules, err := g.Store.Rules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rule := rules[0]
	rule.DurationMs = 1
	b, _ := json.Marshal(map[string]any{"rule": rule})
	request := operations.Request{ID: newID(t), Action: "rules.put", Expected: rule.Version, Params: b}
	plan, err := g.Operations.Prepare(ctx, operations.Local(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.Plan = plan.ID
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(path, "critical.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TRIGGER e05_no_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = g.Operations.Execute(ctx, operations.Local(), request); err == nil {
		t.Fatal("rule mutation bypassed audit")
	}
	after, err := g.Store.Rules(ctx)
	if err != nil || after[0].Version != rules[0].Version || after[0].DurationMs != rules[0].DurationMs {
		t.Fatal("effect before durable intent", err)
	}
}
