// SPDX-License-Identifier: Apache-2.0
package history

import (
	"context"
	"encoding/json"
	"math"
	"strconv"
	"time"

	"serverdeck.local/agent/internal/storage"
)

func (e *Engine) Page(ctx context.Context, series string, from, to time.Time, limit int, after, expectedEpoch string) (points []any, unit, epoch, revision, last string, step int64, more bool, err error) {
	if limit < 1 || limit > 2000 || !to.After(from) || to.Sub(from) > 7*24*time.Hour {
		err = storage.ErrInvalid
		return
	}
	step = 15000
	if to.Sub(from) > time.Hour {
		step = 60000
	}
	if to.Sub(from) > 24*time.Hour {
		step = 300000
	}
	rows, current, rev, e2 := e.store.Records(ctx, "bucket", series, step, from.UnixMicro(), to.UnixMicro(), after, limit)
	if e2 != nil {
		err = e2
		return
	}
	epoch = current
	revision = current + ":" + strconv.FormatInt(rev, 10)
	if expectedEpoch != "" && expectedEpoch != epoch {
		err = storage.ErrCursor
		return
	}
	points = []any{}
	last = after
	for _, r := range rows {
		var a accumulated
		if json.Unmarshal(r.Data, &a) != nil {
			err = storage.ErrStorage
			return
		}
		unit = a.Unit
		points = append(points, Point(a))
		last = r.ID
	}
	if len(rows) == limit {
		extra, nextEpoch, _, lookupErr := e.store.Records(ctx, "bucket", series, step, from.UnixMicro(), to.UnixMicro(), last, 1)
		if lookupErr != nil {
			err = lookupErr
			return
		}
		if nextEpoch != epoch {
			err = storage.ErrCursor
			return
		}
		more = len(extra) > 0
	}
	if unit == "" {
		meta, _, _, e2 := e.store.Records(ctx, "series", series, 0, 0, math.MaxInt64, "", 1)
		if e2 != nil {
			err = e2
			return
		}
		if len(meta) == 1 {
			var v map[string]string
			if json.Unmarshal(meta[0].Data, &v) != nil {
				err = storage.ErrStorage
				return
			}
			unit = v["unit"]
		} else {
			err = storage.ErrInvalid
		}
	}
	return
}
