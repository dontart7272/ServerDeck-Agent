// SPDX-License-Identifier: Apache-2.0
package history

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"

	"serverdeck.local/agent/internal/storage"
)

// Registry preserves generations across restarts; logical keys aid discovery
// without combining different resource IDs/segments into one physical resource.
func (e *Engine) Registry(ctx context.Context, metric, logical string) ([]any, string, error) {
	items := []any{}
	after := ""
	seen := 0
	for {
		rows, _, _, err := e.store.Records(ctx, "series", "", 0, 0, math.MaxInt64, after, 2000)
		if err != nil {
			return nil, "", err
		}
		for _, r := range rows {
			seen++
			if seen > 4096 {
				return nil, "", storage.ErrQuota
			}
			var v map[string]string
			if json.Unmarshal(r.Data, &v) != nil {
				return nil, "", storage.ErrStorage
			}
			after = r.ID
			if metric != "" && v["key"] != metric || logical != "" && v["logical_key"] != logical {
				continue
			}
			items = append(items, map[string]any{"series_id": r.ID, "resource_id": v["resource_id"], "logical_key": v["logical_key"], "key": v["key"], "unit": v["unit"], "schema": "1", "source": v["source"]})
		}
		if len(rows) < 2000 {
			break
		}
	}
	b, _ := json.Marshal(items)
	hash := sha256.Sum256(b)
	return items, hex.EncodeToString(hash[:]), nil
}
