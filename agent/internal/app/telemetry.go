// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"strconv"
	"time"

	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/events"
	"serverdeck.local/agent/internal/history"
	"serverdeck.local/agent/internal/operations"
	"serverdeck.local/agent/internal/storage"
)

func (g *Gateway) openTelemetry() {
	ctx := context.Background()
	b, _, err := g.Store.Settings(ctx)
	if err != nil {
		return
	}
	var runtime contracts.RuntimeConfig
	if json.Unmarshal(b, &runtime) != nil {
		return
	}
	g.historyDB, err = g.Store.OpenTelemetry(ctx, "history", runtime.History.BudgetBytes)
	if err == nil {
		g.History = history.NewEngine(g.historyDB)
	}
	g.eventsDB, err = g.Store.OpenTelemetry(ctx, "events", runtime.Events.BudgetBytes)
	if err == nil {
		g.Events, err = events.New(ctx, g.eventsDB)
		if err != nil {
			g.eventsDB.Close()
			g.eventsDB = nil
		}
	}
}
func (g *Gateway) startTelemetry() {
	ctx, cancel := context.WithCancel(context.Background())
	g.telemetryCancel = cancel
	g.telemetryDone = make(chan struct{})
	go func() {
		defer close(g.telemetryDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		start := time.Now()
		clockTrusted := true
		lastSegment := ""
		lastFlush, lastPrune := time.Now(), time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now()
				if g.Metrics == nil {
					continue
				}
				snapshot := g.Metrics.Snapshot("detail", []string{"cpu", "system", "network", "memory", "filesystems", "gpu", "security", "docker"}, nil)
				if lastSegment != "" && lastSegment != snapshot.SegmentID {
					clockTrusted = false
				}
				lastSegment = snapshot.SegmentID
				if g.History != nil {
					g.History.Observe(snapshot)
				}
				if now.Sub(lastFlush) >= 5*time.Second {
					lastFlush = now
					if g.History != nil {
						_ = g.History.Flush(ctx, now)
					}
					if g.Events != nil {
						rules, err := g.Store.Rules(ctx)
						g.Events.PolicyUnavailable(err != nil)
						if err == nil {
							_ = g.Events.Observe(ctx, rules, snapshot, time.Since(start))
						}
					}
					if now.Sub(lastPrune) >= time.Minute {
						lastPrune = now
						if g.historyDB != nil {
							_ = g.historyDB.Reclaim(ctx)
						}
						if g.eventsDB != nil {
							_ = g.eventsDB.Reclaim(ctx)
						}
						var runtime contracts.RuntimeConfig
						if b, _, err := g.Store.Settings(ctx); err == nil {
							_ = json.Unmarshal(b, &runtime)
						}
						if g.historyDB != nil && clockTrusted {
							_ = g.historyDB.Prune(ctx, now.Add(-7*24*time.Hour).UnixMicro(), 100000)
						}
						if g.eventsDB != nil {
							before := int64(0)
							if clockTrusted && runtime.Events.RetentionDays > 0 {
								before = now.Add(-time.Duration(runtime.Events.RetentionDays) * 24 * time.Hour).UnixMicro()
							}
							_ = g.eventsDB.Prune(ctx, before, 100000)
						}
					}
				}
			}
		}
	}()
}

func (g *Gateway) telemetryQuery(ctx context.Context, name string, raw []byte) (any, error) {
	if name == "history.get" {
		return g.historyQuery(ctx, raw)
	}
	var p struct {
		Cursor             string
		Limit              int
		From, To, Severity string
		ResourceID         string   `json:"resource_id"`
		MetricKey          string   `json:"metric_key"`
		LogicalKey         string   `json:"logical_key"`
		SeriesIDs          []string `json:"series_ids"`
		MaxPoints          int      `json:"max_points"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return nil, storage.ErrInvalid
	}
	if p.Limit == 0 {
		p.Limit = 100
	}
	if p.Limit < 1 || p.Limit > 100 {
		return nil, storage.ErrInvalid
	}
	owner, _ := ctx.Value(metricOwnerKey{}).(string)
	digest := scope(raw) + ":" + owner
	c, err := g.position(p.Cursor, name, digest)
	if err != nil {
		return nil, err
	}
	switch name {
	case "history.series":
		if g.History == nil {
			return nil, storage.ErrStorage
		}
		items, revision, err := g.History.Registry(ctx, p.MetricKey, p.LogicalKey)
		if err != nil {
			return nil, err
		}
		if p.Cursor != "" && (c.Epoch != g.RunID || c.Nonce != revision) {
			return nil, storage.ErrCursor
		}
		if c.Position > int64(len(items)) {
			return nil, storage.ErrCursor
		}
		end := min(int(c.Position)+p.Limit, len(items))
		var next any
		if end < len(items) {
			b, _ := json.Marshal(cursorValue{Version: 1, Agent: g.AgentID, Epoch: g.RunID, Kind: name, Scope: digest, Position: int64(end), Expires: time.Now().Add(15 * time.Minute).Unix(), Nonce: revision})
			next, err = g.Store.SignCursor(b)
		}
		return page(items[int(c.Position):end], next, revision), err
	case "rules.list":
		rules, err := g.Store.Rules(ctx)
		if err != nil {
			return nil, err
		}
		items := []any{}
		for _, r := range rules {
			items = append(items, r)
		}
		encoded, _ := json.Marshal(items)
		hash := sha256.Sum256(encoded)
		revision := hex.EncodeToString(hash[:])
		if p.Cursor != "" && (c.Epoch != g.RunID || c.Nonce != revision) {
			return nil, storage.ErrCursor
		}
		if c.Position > int64(len(items)) {
			return nil, storage.ErrCursor
		}
		end := min(int(c.Position)+p.Limit, len(items))
		var next any
		if end < len(items) {
			b, _ := json.Marshal(cursorValue{Version: 1, Agent: g.AgentID, Epoch: g.RunID, Kind: name, Scope: digest, Position: int64(end), Expires: time.Now().Add(15 * time.Minute).Unix(), Nonce: revision})
			next, err = g.Store.SignCursor(b)
		}
		return page(items[int(c.Position):end], next, revision), err
	case "problems.list":
		if g.Events == nil {
			return nil, storage.ErrStorage
		}
		items := g.Events.Problems()
		encoded, _ := json.Marshal(items)
		hash := sha256.Sum256(encoded)
		revision := hex.EncodeToString(hash[:])
		if p.Cursor != "" && c.Nonce != revision {
			return nil, storage.ErrCursor
		}
		if c.Epoch != "" && c.Epoch != g.RunID {
			return nil, storage.ErrCursor
		}
		if c.Position > int64(len(items)) {
			return nil, storage.ErrCursor
		}
		end := min(int(c.Position)+p.Limit, len(items))
		var next any
		if end < len(items) {
			b, _ := json.Marshal(cursorValue{Version: 1, Agent: g.AgentID, Epoch: g.RunID, Kind: name, Scope: digest, Position: int64(end), Expires: time.Now().Add(15 * time.Minute).Unix(), Nonce: revision})
			next, err = g.Store.SignCursor(b)
		}
		return page(items[int(c.Position):end], next, revision), err
	case "events.list":
		if g.eventsDB == nil {
			return nil, storage.ErrStorage
		}
		rows, epoch, last, err := g.eventsDB.Changes(ctx, c.Epoch, c.Position, p.Limit)
		if err != nil {
			if err == storage.ErrCursor {
				return nil, g.eventGap(ctx, name, digest)
			}
			return nil, err
		}
		items := []any{}
		for _, r := range rows {
			if r.Kind != "event" {
				continue
			}
			v := events.EventWire(r, epoch)
			if p.Severity != "" && v["severity"] != p.Severity {
				continue
			}
			if p.ResourceID != "" && v["resource_id"] != p.ResourceID {
				continue
			}
			if p.From != "" {
				t, err := time.Parse(time.RFC3339Nano, p.From)
				if err != nil {
					return nil, storage.ErrInvalid
				}
				if r.Start < t.UnixMicro() {
					continue
				}
			}
			if p.To != "" {
				t, err := time.Parse(time.RFC3339Nano, p.To)
				if err != nil {
					return nil, storage.ErrInvalid
				}
				if r.Start >= t.UnixMicro() {
					continue
				}
			}
			items = append(items, v)
		}
		var next any
		if last > c.Position {
			next, err = g.cursor(name, epoch, digest, last)
		}
		result := page(items, next, epoch+":"+strconv.FormatInt(last, 10))
		_, floor, _, boundsErr := g.eventsDB.Bounds(ctx)
		if boundsErr != nil {
			return nil, boundsErr
		}
		if floor > 0 {
			result["coverage"].(map[string]any)["complete"] = false
		}
		return result, err

	}
	return nil, storage.ErrInvalid
}

type ruleHandler struct {
	g      *Gateway
	remove bool
}
type ruleParams struct {
	Rule contracts.APIRule `json:"rule"`
	ID   string            `json:"rule_id"`
}

func (h ruleHandler) Validate(b []byte) error {
	var p ruleParams
	if json.Unmarshal(b, &p) != nil {
		return storage.ErrInvalid
	}
	if h.remove {
		if !storage.SafeLabel(p.ID) {
			return storage.ErrInvalid
		}
		return nil
	}
	return storage.ValidateRule(p.Rule)
}
func (h ruleHandler) Keys(operations.Request) ([]string, error) {
	return []string{"rules.registry"}, nil
}
func (h ruleHandler) Check(ctx context.Context, r operations.Request) error {
	rules, err := h.g.Store.Rules(ctx)
	if err != nil {
		return err
	}
	var p ruleParams
	json.Unmarshal(r.Params, &p)
	id := p.ID
	if !h.remove {
		id = p.Rule.Id
		if p.Rule.Version != r.Expected {
			return storage.ErrVersion
		}
	}
	version := "0"
	for _, v := range rules {
		if v.Id == id {
			version = v.Version
		}
	}
	if version != r.Expected {
		return storage.ErrVersion
	}
	return nil
}
func (h ruleHandler) Effect(ctx context.Context, r operations.Request) operations.Outcome {
	var p ruleParams
	json.Unmarshal(r.Params, &p)
	if h.remove {
		rules, err := h.g.Store.Rules(ctx)
		if err != nil {
			return outcomeError(err)
		}
		found := false
		for _, v := range rules {
			if v.Id == p.ID {
				p.Rule = v
				found = true
			}
		}
		if !found {
			return outcomeError(storage.ErrVersion)
		}
	}
	if err := h.g.Store.ApplyRule(ctx, r.ID, p.Rule, r.Expected, h.remove); err != nil {
		return outcomeError(err)
	}
	result := map[string]any{"rule_id": p.Rule.Id, "version": ""}
	if !h.remove {
		rules, err := h.g.Store.Rules(ctx)
		if err != nil {
			return operations.Outcome{State: "unknown", Effect: "partial", Code: "STORAGE_UNAVAILABLE"}
		}
		for _, v := range rules {
			if v.Id == p.Rule.Id {
				result["version"] = v.Version
			}
		}
	}
	if h.remove {
		result = map[string]any{"rule_id": p.ID, "deleted": true}
	}
	b, _ := json.Marshal(result)
	return operations.Outcome{State: "succeeded", Effect: "applied", Result: b}
}
