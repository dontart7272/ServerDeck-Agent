// SPDX-License-Identifier: Apache-2.0
package app

import "strconv"

func (g *Gateway) storageInfos() []any {
	out := []any{g.storageInfo()}
	for _, kind := range []string{"history", "events"} {
		db := g.historyDB
		if kind == "events" {
			db = g.eventsDB
		}
		status := "unavailable"
		used, wal, budget, reserve := int64(0), int64(0), int64(0), int64(0)
		var reason any = "STORAGE_UNAVAILABLE"
		if db != nil {
			var failed bool
			used, wal, budget, failed = db.Health()
			reserve = db.Reserve()
			status = "ok"
			reason = nil
			if failed {
				status = "degraded"
				reason = "STORAGE_UNAVAILABLE"
			}
			if kind == "history" && g.History != nil {
				failed, lost := g.History.Health()
				if failed || lost > 0 {
					status = "degraded"
					reason = "HISTORY_GAPS_" + strconv.FormatInt(lost, 10)
				}
			}
			if kind == "events" && g.Events != nil && g.Events.Health() {
				status = "degraded"
				reason = "EVENT_COVERAGE_LOST"
			}
		}
		out = append(out, map[string]any{"kind": kind, "status": status, "used_bytes": strconv.FormatInt(used, 10), "budget_bytes": strconv.FormatInt(budget, 10), "wal_bytes": strconv.FormatInt(wal, 10), "reserve_bytes": strconv.FormatInt(reserve, 10), "reason": reason})
	}
	return out
}
