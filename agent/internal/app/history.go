// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"serverdeck.local/agent/internal/storage"
)

type historyCursor struct {
	Agent, Run, Scope, Epoch, After string
	Index                           int
	Expires                         int64
}

func (g *Gateway) historyQuery(ctx context.Context, raw []byte) (any, error) {
	if g.History == nil {
		return nil, storage.ErrStorage
	}
	var p struct {
		Series           []string `json:"series_ids"`
		From, To, Cursor string
		Max              int `json:"max_points"`
	}
	if json.Unmarshal(raw, &p) != nil || len(p.Series) < 1 || len(p.Series) > 32 || p.Max < 1 || p.Max > 2000 {
		return nil, storage.ErrInvalid
	}
	from, err := time.Parse(time.RFC3339Nano, p.From)
	if err != nil {
		return nil, storage.ErrInvalid
	}
	to, err := time.Parse(time.RFC3339Nano, p.To)
	if err != nil || !to.After(from) || to.Sub(from) > 7*24*time.Hour {
		return nil, storage.ErrInvalid
	}
	owner, _ := ctx.Value(metricOwnerKey{}).(string)
	digest := scope(raw) + ":" + owner
	c := historyCursor{Agent: g.AgentID, Run: g.RunID, Scope: digest, Expires: time.Now().Add(15 * time.Minute).Unix()}
	if p.Cursor != "" {
		b, err := g.Store.VerifyCursor(p.Cursor)
		if err != nil {
			return nil, storage.ErrCursor
		}
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&c) != nil || c.Agent != g.AgentID || c.Run != g.RunID || c.Scope != digest || c.Index < 0 || c.Index >= len(p.Series) || len(c.After) > 512 {
			return nil, storage.ErrCursor
		}
		if c.Expires <= time.Now().Unix() {
			return nil, storage.ErrCursor
		}
	}
	points, unit, epoch, revision, last, step, more, err := g.History.Page(ctx, p.Series[c.Index], from, to, p.Max, c.After, c.Epoch)
	if err != nil {
		return nil, err
	}
	coverage := historyCoverage(points, from, to)
	item := map[string]any{"series_id": p.Series[c.Index], "unit": unit, "schema": "1", "step_ms": step, "coverage": coverage, "points": points}
	c.Epoch = epoch
	c.After = last
	if !more {
		c.Index++
		c.After = ""
	}
	var next any
	if c.Index < len(p.Series) {
		b, _ := json.Marshal(c)
		next, err = g.Store.SignCursor(b)
		if err != nil {
			return nil, err
		}
	}
	return map[string]any{"items": []any{item}, "next_cursor": next, "coverage": coverage, "revision": revision}, nil
}

func historyCoverage(points []any, from, to time.Time) map[string]any {
	gaps := []any{}
	position := from
	var actualFrom, actualTo any
	segment := ""
	complete := len(points) > 0
	gap := func(a, b time.Time, reason string) {
		complete = false
		if !b.After(a) {
			return
		}
		if len(gaps) < 255 {
			gaps = append(gaps, map[string]any{"from": a.UTC().Format(time.RFC3339Nano), "to": b.UTC().Format(time.RFC3339Nano), "reason": reason})
		} else if len(gaps) == 255 {
			gaps = append(gaps, map[string]any{"from": a.UTC().Format(time.RFC3339Nano), "to": to.UTC().Format(time.RFC3339Nano), "reason": "MULTIPLE_GAPS"})
		}
	}
	for _, raw := range points {
		p := raw.(map[string]any)
		a, _ := time.Parse(time.RFC3339Nano, p["from"].(string))
		b, _ := time.Parse(time.RFC3339Nano, p["to"].(string))
		if a.Before(from) {
			a = from
		}
		if b.After(to) {
			b = to
		}
		if actualFrom == nil {
			actualFrom = a.UTC().Format(time.RFC3339Nano)
		}
		actualTo = b.UTC().Format(time.RFC3339Nano)
		if a.After(position) {
			gap(position, a, "NOT_RETAINED_OR_SOURCE_GAP")
		}
		if p["complete"] != true {
			gap(a, b, "PARTIAL_COVERAGE")
		}
		if segment != "" && segment != p["segment_id"] {
			gap(a, b, "SEGMENT_BOUNDARY")
		}
		segment = p["segment_id"].(string)
		if b.After(position) {
			position = b
		}
	}
	if position.Before(to) {
		gap(position, to, "NOT_RETAINED_OR_PENDING_PAGE")
	}
	return map[string]any{"from": actualFrom, "to": actualTo, "complete": complete, "gaps": gaps}
}
