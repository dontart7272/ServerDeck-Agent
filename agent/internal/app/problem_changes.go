// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"encoding/json"
	"strconv"

	"serverdeck.local/agent/internal/storage"
)

func (g *Gateway) problemChanges(ctx context.Context, raw []byte) (map[string]any, error) {
	if g.eventsDB == nil {
		return nil, storage.ErrStorage
	}
	var p struct {
		Cursor string
		Limit  int
	}
	if json.Unmarshal(raw, &p) != nil {
		return nil, storage.ErrInvalid
	}
	if p.Limit == 0 {
		p.Limit = 8
	}
	owner, _ := ctx.Value(metricOwnerKey{}).(string)
	digest := scope(raw) + ":" + owner
	c, err := g.position(p.Cursor, "problems.changes", digest)
	if err != nil {
		return nil, err
	}
	rows, epoch, last, err := g.eventsDB.Changes(ctx, c.Epoch, c.Position, p.Limit)
	if err != nil {
		if err == storage.ErrCursor {
			return nil, g.eventGap(ctx, "problems.changes", digest)
		}
		return nil, err
	}
	items := []any{}
	for _, r := range rows {
		if r.Kind != "problem" {
			continue
		}
		var v map[string]any
		if json.Unmarshal(r.Data, &v) != nil {
			return nil, storage.ErrStorage
		}
		items = append(items, v)
	}
	var next any
	if last > c.Position {
		next, err = g.cursor("problems.changes", epoch, digest, last)
	}
	return page(items, next, epoch+":"+strconv.FormatInt(last, 10)), err
}
