// SPDX-License-Identifier: Apache-2.0
package metrics

import (
	"encoding/json"
	"time"
)

// Wire records omit process-local monotonic clocks. Retain those clocks alongside
// records so nested metrics age honestly, independently of wall-clock changes.
func renderNested(raw json.RawMessage, b Block, now Stamp) (json.RawMessage, bool) {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return raw, true
	}
	partial := false
	var walk func(any)
	walk = func(value any) {
		switch node := value.(type) {
		case map[string]any:
			key, k := node["key"].(string)
			resource, r := node["resource_id"].(string)
			interval, i := node["expected_interval_ms"].(float64)
			if k && r && i {
				mono, known := b.nestedTimes[resource+"/"+key]
				if !known {
					node["freshness"] = "unknown"
				} else if now.Mono-mono >= time.Duration(3*interval)*time.Millisecond {
					node["freshness"] = "stale"
				}
				if b.Availability != "available" {
					if len(b.Metrics) > 0 {
						node["attempted_at"] = b.Metrics[0].AttemptedAt
					}
					node["availability"] = b.Availability
					node["reason"] = b.Reason
					if node["value"] != nil {
						node["freshness"] = "stale"
					}
				}
				if node["availability"] != "available" || node["freshness"] != "fresh" {
					partial = true
				}
				return
			}
			for _, child := range node {
				walk(child)
			}
		case []any:
			for _, child := range node {
				walk(child)
			}
		}
	}
	walk(value)
	out, err := json.Marshal(value)
	if err != nil {
		return raw, true
	}
	return out, partial
}
