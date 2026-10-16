// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"encoding/json"
	"serverdeck.local/agent/internal/metrics"
	"serverdeck.local/agent/internal/storage"
)

type metricOwnerKey struct{}

func withMetricOwner(ctx context.Context, owner string) context.Context {
	return context.WithValue(ctx, metricOwnerKey{}, owner)
}

type metricParams struct {
	View       string   `json:"view"`
	Blocks     []string `json:"blocks"`
	Resources  []string `json:"resource_ids"`
	Search     string   `json:"search"`
	Sort       string   `json:"sort"`
	Order      string   `json:"order"`
	Cursor     string   `json:"cursor"`
	Limit      int      `json:"limit"`
	ProcessRef string   `json:"process_ref"`
}

func (g *Gateway) metricQuery(ctx context.Context, name string, raw []byte) (any, error) {
	if g.Metrics == nil {
		return nil, metrics.ErrUnavailable
	}
	var p metricParams
	if json.Unmarshal(raw, &p) != nil {
		return nil, storage.ErrInvalid
	}
	owner, _ := ctx.Value(metricOwnerKey{}).(string)
	// Only trusted transports supply an owner. Internal callers can read current
	// observations but cannot allocate per-device pagination or cadence leases.
	switch name {
	case "snapshot.get":
		if e := metricBlocks(p.Blocks); e != nil {
			return nil, e
		}
		if p.View != "summary" && p.View != "detail" {
			return nil, storage.ErrInvalid
		}
		if p.View == "detail" && (len(p.Blocks) == 0 || hasBlock(p.Blocks, "processes")) && owner != "" {
			if e := g.Metrics.Lease(owner); e != nil {
				return nil, e
			}
		}
		return g.processSnapshot(ctx, g.Metrics.Snapshot(p.View, p.Blocks, p.Resources)), nil
	case "processes.get":
		if owner != "" {
			if e := g.Metrics.Lease(owner); e != nil {
				return nil, e
			}
		}
		process, err := g.Metrics.Process(p.ProcessRef)
		if err != nil {
			return nil, err
		}
		return g.processActions(ctx, process), nil
	case "processes.list":
		if owner == "" {
			return nil, storage.ErrUnauthorized
		}
		if e := g.Metrics.Lease(owner); e != nil {
			return nil, e
		}
		if p.Limit == 0 {
			p.Limit = 100
		}
		digest := scope(raw) + ":" + owner
		c, e := g.position(p.Cursor, name, digest)
		if e != nil {
			return nil, e
		}
		if c.Position > 4096 {
			return nil, storage.ErrCursor
		}
		items, revision, more, complete, e := g.Metrics.Processes(owner, c.Epoch, p.Search, p.Sort, p.Order, int(c.Position), p.Limit)
		if e != nil {
			return nil, e
		}
		wire := make([]any, 0, len(items))
		for _, v := range items {
			wire = append(wire, g.processActions(ctx, v))
		}
		var next any
		if more {
			next, e = g.cursor(name, revision, digest, c.Position+int64(len(items)))
			if e != nil {
				return nil, e
			}
		}
		result := page(wire, next, revision)
		result["coverage"].(map[string]any)["complete"] = complete
		return result, nil
	}
	return nil, storage.ErrInvalid
}
func hasBlock(blocks []string, name string) bool {
	for _, v := range blocks {
		if v == name {
			return true
		}
	}
	return false
}

func metricBlocks(blocks []string) error {
	for _, name := range blocks {
		switch name {
		case "system", "cpu", "memory", "network", "filesystems", "processes", "gpu", "docker", "security":
		default:
			return metrics.ErrUnavailable
		}
	}
	return nil
}
