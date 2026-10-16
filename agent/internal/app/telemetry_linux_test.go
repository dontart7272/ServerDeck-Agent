// SPDX-License-Identifier: Apache-2.0
//go:build linux

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/metrics"
	"serverdeck.local/agent/internal/operations"
	"serverdeck.local/agent/internal/storage"
)

func applyTelemetry(t *testing.T, g *Gateway, action, expected string, params any) storage.Operation {
	t.Helper()
	b, _ := json.Marshal(params)
	r := operations.Request{ID: newID(t), Action: action, Expected: expected, Params: b}
	plan, err := g.Operations.Prepare(context.Background(), operations.Local(), r)
	if err != nil {
		t.Fatal(err)
	}
	r.Plan = plan.ID
	o, err := g.Operations.Execute(context.Background(), operations.Local(), r)
	if err != nil {
		t.Fatal(err)
	}
	if o.State != "succeeded" {
		t.Fatalf("%s: %+v", action, o)
	}
	return o
}

func TestTelemetryHTTPRulesEventsProblemsPolicyAndAudit(t *testing.T) {
	g, _, _ := newTestGateway(t)
	_, token := pairDirect(t, g)
	_, other := pairDirect(t, g)
	srv, client, _ := testHTTPS(t, g, false)
	status, _ := query(t, client, srv.URL, "", "rules.list", map[string]any{})
	if status != 401 {
		t.Fatal("unauthorized rules", status)
	}
	status, raw := query(t, client, srv.URL, token, "rules.list", map[string]any{"limit": 2})
	if status != 200 {
		t.Fatal(status, string(raw))
	}
	data := decodeMap(t, raw)["data"].(map[string]any)
	cursor := data["next_cursor"].(string)
	status, _ = query(t, client, srv.URL, other, "rules.list", map[string]any{"limit": 2, "cursor": cursor})
	if status == 200 {
		t.Fatal("different actor continued rules page")
	}
	rules, err := g.Store.Rules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rule := rules[0]
	for _, r := range rules {
		if r.Id == "memory.available" {
			rule = r
		}
	}
	rule.DurationMs = 0
	rule.RecoveryDurationMs = 0
	applyTelemetry(t, g, "rules.put", rule.Version, map[string]any{"rule": rule})
	status, _ = query(t, client, srv.URL, token, "rules.list", map[string]any{"limit": 2, "cursor": cursor})
	if status == 200 {
		t.Fatal("changed rules silently shifted continuation")
	}
	at := time.Now().UTC()
	stamp := contracts.Timestamp(at)
	snapshot := metrics.Snapshot{SegmentID: newID(t), At: stamp, Blocks: []metrics.Block{{ID: "memory", Availability: "available", Metrics: []metrics.Metric{{Key: "available_percent", ResourceID: "ram", Unit: "percent", Value: float64(9), Availability: "available", Freshness: "fresh", MeasuredAt: &stamp}}}}}
	rules, _ = g.Store.Rules(context.Background())
	if err = g.Events.Observe(context.Background(), rules, snapshot, 0); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"events.list", "problems.list"} {
		status, raw = query(t, client, srv.URL, token, name, map[string]any{})
		if status != 200 {
			t.Fatal(name, status, string(raw))
		}
		if _, err = contracts.Validate(bytes.NewReader(raw), contracts.Target{Family: "api", Definition: "QueryResponse"}, contracts.MaxJSONBytes); err != nil {
			t.Fatal(err)
		}
		items := decodeMap(t, raw)["data"].(map[string]any)["items"].([]any)
		if len(items) == 0 {
			t.Fatal("no data", name)
		}
	}
	applyTelemetry(t, g, "config.set", "1", map[string]any{"changes": map[string]any{"history": map[string]any{"budget_bytes": 16000000, "module_share_percent": 25}}})
	status, raw = query(t, client, srv.URL, token, "config.get", map[string]any{})
	if status != 200 {
		t.Fatal(status, string(raw))
	}
	if decodeMap(t, raw)["data"].(map[string]any)["version"] != "2" {
		t.Fatal("settings revision")
	}
	entries, _, _, err := g.Store.AuditPage(context.Background(), "", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, a := range entries {
		if a.Kind == "intent" {
			seen[a.Action] = true
		}
	}
	if !seen["rules.put"] || !seen["config.set"] {
		t.Fatal("missing intent", seen)
	}
}

func TestRetentionReductionReportsObservablePendingCleanup(t *testing.T) {
	g, _, _ := newTestGateway(t)
	ctx := context.Background()
	old := time.Now().Add(-3 * 24 * time.Hour).UnixMicro()
	for i := 0; i < 64; i++ {
		id := newID(t)
		if err := g.eventsDB.Update(ctx, nil, []storage.TelemetryRecord{{Kind: "event", ID: id, Start: old, Stop: old, Revision: 1, Data: json.RawMessage(`{}`)}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	params, _ := json.Marshal(map[string]any{"changes": map[string]any{"events": map[string]any{"retention_days": 1, "budget_bytes": 32000000}}})
	request := operations.Request{ID: newID(t), Action: "config.set", Expected: "1", Params: params}
	plan, err := g.Operations.Prepare(ctx, operations.Local(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.Plan = plan.ID
	op, err := g.Operations.Execute(ctx, operations.Local(), request)
	if err != nil || op.State != "unknown" || op.Effect != "partial" || op.Code != "CLEANUP_PENDING" {
		t.Fatal("unfinished cleanup reported success", op, err)
	}
	var result struct {
		Version string
		Cleanup string `json:"cleanup_operation_id"`
	}
	if json.Unmarshal(op.Result, &result) != nil || result.Version != "2" || result.Cleanup != request.ID {
		t.Fatal("cleanup identity/new policy missing", string(op.Result))
	}
	_, version, err := g.Store.Settings(ctx)
	if err != nil || version != 2 {
		t.Fatal("new policy lost", err)
	}
	repeated, err := g.Operations.Execute(ctx, operations.Local(), request)
	if err != nil || repeated.State != "unknown" || repeated.Revision != op.Revision {
		t.Fatal("unknown cleanup blindly repeated", repeated, err)
	}
}

func TestEmptyRetentionReductionNeedsNoCleanupOperation(t *testing.T) {
	g, _, _ := newTestGateway(t)
	op := applyTelemetry(t, g, "config.set", "1", map[string]any{"changes": map[string]any{"events": map[string]any{"retention_days": 1, "budget_bytes": 32000000}}})
	var result map[string]any
	if json.Unmarshal(op.Result, &result) != nil || result["cleanup_operation_id"] != nil {
		t.Fatal("empty cleanup invented", string(op.Result))
	}
}
