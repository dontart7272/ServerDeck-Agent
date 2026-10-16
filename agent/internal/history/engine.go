// SPDX-License-Identifier: Apache-2.0
package history

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/metrics"
	"serverdeck.local/agent/internal/storage"
)

type accumulated struct {
	Bucket                    Bucket
	Unit, Key                 string
	Resource, Logical, Source string
}
type previous struct {
	metric  metrics.Metric
	segment string
}

type Engine struct {
	mu       sync.Mutex
	store    *storage.Telemetry
	previous map[string]previous
	buckets  map[string]accumulated
	dirty    map[string]bool
	failed   bool
	lost     int64
}

func NewEngine(s *storage.Telemetry) *Engine {
	return &Engine{store: s, previous: map[string]previous{}, buckets: map[string]accumulated{}, dirty: map[string]bool{}}
}
func SeriesID(resource, key string) string {
	h := sha256.Sum256([]byte(resource + "\x00" + key + "\x001"))
	return hex.EncodeToString(h[:])
}
func bucketID(w Window) string {
	return w.Start.UTC().Format("20060102T150405") + ":" + w.Series + ":" + w.Segment + ":" + strconv.FormatInt(int64(w.Step/time.Millisecond), 10)
}
func numeric(v any) (float64, uint64, bool) {
	switch n := v.(type) {
	case float64:
		return n, 0, finite(n)
	case contracts.U64:
		return float64(n), uint64(n), true
	case int64:
		return float64(n), uint64(n), n >= 0
	case uint64:
		return float64(n), n, true
	case bool:
		if n {
			return 1, 1, true
		}
		return 0, 0, true
	}
	return 0, 0, false
}
func (e *Engine) Observe(s metrics.Snapshot) {
	e.mu.Lock()
	defer e.mu.Unlock()
	seen := map[string]bool{}
	for _, block := range s.Blocks {
		if block.ID != "cpu" && block.ID != "network" && block.ID != "system" && block.ID != "gpu" {
			continue
		}
		labels := map[string]string{}
		for _, raw := range block.Records {
			var r struct {
				Type     string `json:"record_type"`
				Resource string `json:"resource_id"`
				Logical  *int   `json:"logical_id"`
				Name     string `json:"name"`
				UUID     string `json:"uuid"`
			}
			if json.Unmarshal(raw, &r) != nil {
				continue
			}
			switch r.Type {
			case "cpu_summary":
				labels[r.Resource] = "cpu:aggregate"
			case "cpu":
				if r.Logical != nil {
					labels[r.Resource] = "cpu:logical:" + strconv.Itoa(*r.Logical)
				}
			case "network_summary":
				labels[r.Resource] = "network:aggregate"
			case "gpu":
				labels[r.Resource] = "gpu:" + r.UUID
			case "network":
				labels[r.Resource] = "network:" + r.Name
			}
		}
		for _, m := range block.Metrics {
			if block.ID == "gpu" && (m.Key == "temperature_threshold_c" || m.Key == "gpu_processes_available") {
				continue
			}
			if block.ID == "system" && !strings.HasPrefix(m.Key, "load") && !strings.HasPrefix(m.Key, "psi_") {
				continue
			}
			if block.ID == "network" && m.Key == "link_load_percent" {
				continue
			}
			id := SeriesID(m.ResourceID, m.Key)
			if block.ID == "gpu" {
				id = SeriesID(m.ResourceID, m.Key+"@"+m.Source)
			}
			seen[id] = true
			p, had := e.previous[id]
			if m.Availability != "available" || m.Freshness != "fresh" || m.MeasuredAt == nil {
				delete(e.previous, id)
				continue
			}
			v, c, ok := numeric(m.Value)
			if !ok {
				delete(e.previous, id)
				continue
			}
			if had && p.metric.MeasuredAt != nil && time.Time(*p.metric.MeasuredAt).Equal(time.Time(*m.MeasuredAt)) {
				continue
			}
			if !had && len(e.previous) >= 4096 {
				e.failed = true
				e.lost++
				continue
			}
			e.previous[id] = previous{m, s.SegmentID}
			if !had || p.segment != s.SegmentID || p.metric.MeasuredAt == nil {
				continue
			}
			from, to := time.Time(*p.metric.MeasuredAt).UTC(), time.Time(*m.MeasuredAt).UTC()
			covered := m.MonotonicElapsed() - p.metric.MonotonicElapsed()
			if covered <= 0 || covered > time.Duration(3*m.Interval)*time.Millisecond || !to.After(from) || math.Abs(float64(to.Sub(from)-covered)) > float64(time.Second) {
				continue
			}
			kind := Gauge
			var delta uint64
			if block.ID == "network" && !strings.HasSuffix(m.Key, "rate") || m.Key == "throttle_events" {
				_, old, valid := numeric(p.metric.Value)
				if !valid || c < old {
					continue
				}
				kind = CounterDelta
				delta = c - old
				v = 0
			}
			// Rate is an observation over the whole measured interval. Coverage is
			// clipped at bucket edges; exact bytes belong once to the bucket in
			// which the interval ends. No fractional byte estimates are invented.
			rate := v
			if kind == CounterDelta {
				rate = float64(delta) / covered.Seconds()
			}
			intervalTo := to
			wholeCovered := covered
			for parts := 0; from.Before(intervalTo) && parts < 16; parts++ {
				start := from.Truncate(15 * time.Second)
				to = intervalTo
				if edge := start.Add(15 * time.Second); to.After(edge) {
					to = edge
				}
				covered = to.Sub(from)
				ownedDelta := uint64(0)
				ownedCovered := time.Duration(0)
				if to.Equal(intervalTo) {
					ownedDelta = delta
					ownedCovered = wholeCovered
				}
				w := Window{Series: id, Segment: s.SegmentID, Start: start, Step: 15 * time.Second, Revision: 1, Kind: kind}
				key := bucketID(w)
				a, exists := e.buckets[key]
				b, err := Aggregate(w, []Interval{{From: from, To: to, Covered: covered, Value: rate, Delta: ownedDelta, RateKnown: kind == CounterDelta, DeltaCovered: ownedCovered}})
				if err != nil {
					e.failed = true
					continue
				}
				if exists {
					if a.Bucket.Covered+b.Covered > w.Step || a.Bucket.SampleCount >= MaxInputs {
						e.failed = true
						continue
					}
					b.Covered += a.Bucket.Covered
					b.CounterCovered += a.Bucket.CounterCovered
					b.SampleCount += a.Bucket.SampleCount
					b.WeightedSum += a.Bucket.WeightedSum
					if math.MaxUint64-b.Sum < a.Bucket.Sum {
						e.failed = true
						continue
					}
					b.Sum += a.Bucket.Sum
					if a.Bucket.Maximum > b.Maximum {
						b.Maximum = a.Bucket.Maximum
					}
					b.Revision = a.Bucket.Revision + 1
					b, err = finish(b)
					if err != nil {
						e.failed = true
						continue
					}
				}
				if !exists && len(e.buckets) >= 8192 {
					e.failed = true
					e.lost++
					continue
				}
				logical := labels[m.ResourceID]
				if logical == "" {
					logical = "resource:" + m.ResourceID
				}
				e.buckets[key] = accumulated{Bucket: b, Unit: m.Unit, Key: m.Key, Resource: m.ResourceID, Logical: logical, Source: m.Source}
				e.dirty[key] = true
				from = to
			}
		}
	}
	for id := range e.previous {
		if !seen[id] {
			delete(e.previous, id)
		}
	}
}

func (e *Engine) Flush(ctx context.Context, now time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, step := range []time.Duration{time.Minute, 5 * time.Minute} {
		childStep := 15 * time.Second
		if step == 5*time.Minute {
			childStep = time.Minute
		}
		groups := map[string][]Bucket{}
		units := map[string]accumulated{}
		for _, a := range e.buckets {
			if a.Bucket.Step != childStep {
				continue
			}
			w := a.Bucket.Window
			w.Step = step
			w.Start = w.Start.Truncate(step)
			key := bucketID(w)
			groups[key] = append(groups[key], a.Bucket)
			units[key] = a
		}
		for key, children := range groups {
			sort.Slice(children, func(i, j int) bool { return children[i].Start.Before(children[j].Start) })
			w := children[0].Window
			w.Step = step
			w.Start = w.Start.Truncate(step)
			w.Closed = !now.Before(w.Start.Add(step))
			w.Revision = 1
			if old, ok := e.buckets[key]; ok {
				w.Revision = old.Bucket.Revision + 1
			}
			b, err := Rollup(w, children)
			if err != nil {
				e.failed = true
				return err
			}
			a := units[key]
			a.Bucket = b
			if _, ok := e.buckets[key]; !ok && len(e.buckets) >= 8192 {
				e.failed = true
				e.lost++
				continue
			}
			e.buckets[key] = a
			e.dirty[key] = true
		}
	}
	keys := make([]string, 0, len(e.buckets))
	for k := range e.buckets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		a := e.buckets[k]
		if !a.Bucket.Closed && !now.Before(a.Bucket.Start.Add(a.Bucket.Step)) {
			a.Bucket.Closed = true
			a.Bucket.Revision++
			a.Bucket, _ = finish(a.Bucket)
			e.buckets[k] = a
			e.dirty[k] = true
		}
	}
	records := []storage.TelemetryRecord{}
	pending := []string{}
	write := func() error {
		if len(records) == 0 {
			return nil
		}
		err := e.store.Update(ctx, records, nil, nil)
		if err != nil {
			e.failed = true
			_ = e.store.Reclaim(ctx)
			return err
		}
		for _, k := range pending {
			delete(e.dirty, k)
		}
		records = nil
		pending = nil
		return nil
	}
	for _, k := range keys {
		if !e.dirty[k] {
			continue
		}
		a := e.buckets[k]
		data, _ := json.Marshal(a)
		b := a.Bucket
		meta, _ := json.Marshal(map[string]string{"unit": a.Unit, "key": a.Key, "resource_id": a.Resource, "logical_key": a.Logical, "source": a.Source})
		records = append(records, storage.TelemetryRecord{Kind: "series", ID: b.Series, Series: b.Series, Segment: "", Start: 0, Stop: math.MaxInt64, Revision: 1, Data: meta})
		records = append(records, storage.TelemetryRecord{Kind: "bucket", ID: k, Series: b.Series, Segment: b.Segment, Level: int64(b.Step / time.Millisecond), Start: b.Start.UnixMicro(), Stop: b.Start.Add(b.Step).UnixMicro(), Revision: b.Revision, Data: data})
		pending = append(pending, k)
		if len(records) >= 32 {
			if err := write(); err != nil {
				return err
			}
		}
	}
	if err := write(); err != nil {
		return err
	}
	// Keep sufficient statistics through the active five-minute window so all
	// tiers are built from original coverage, not rounded wire means.
	for k, a := range e.buckets {
		if a.Bucket.Closed && !e.dirty[k] && !a.Bucket.Start.Add(a.Bucket.Step).After(now.Truncate(5*time.Minute)) {
			delete(e.buckets, k)
		}
	}
	e.failed = false
	return nil
}

func (e *Engine) Health() (bool, int64) { e.mu.Lock(); defer e.mu.Unlock(); return e.failed, e.lost }

func Point(a accumulated) map[string]any {
	b := a.Bucket
	stats := map[string]any{}
	if b.HasValue {
		switch {
		case b.Kind == CounterDelta:
			if b.CounterCovered > 0 {
				stats["sum"] = strconv.FormatUint(b.Sum, 10)
				stats["mean"] = b.Mean
			}
			stats["max"] = b.Maximum
		case a.Key == "temperature_c":
			stats["max"] = b.Maximum
		case a.Key == "throttled":
			stats["observed_true"] = b.Maximum > 0
			stats["last"] = b.Last
		case strings.HasPrefix(a.Key, "load"):
			stats["last"] = b.Last
		default:
			if b.Covered > 0 {
				stats["mean"] = b.Mean
			}
			if strings.HasSuffix(a.Key, "rate") || strings.HasPrefix(a.Logical, "gpu:") && (a.Key == "power_w" || a.Key == "vram_used_bytes" || a.Key == "vram_total_bytes") {
				stats["max"] = b.Maximum
			}
		}
	}
	var reason any
	if !b.Complete {
		reason = "PARTIAL_COVERAGE"
	}
	return map[string]any{"bucket_id": bucketID(b.Window), "revision": strconv.FormatInt(b.Revision, 10), "segment_id": b.Segment, "from": b.Start.UTC().Format(time.RFC3339Nano), "to": b.Start.Add(b.Step).UTC().Format(time.RFC3339Nano), "step_ms": int64(b.Step / time.Millisecond), "covered_ms": int64(b.Covered / time.Millisecond), "counter_covered_ms": int64(b.CounterCovered / time.Millisecond), "sample_count": b.SampleCount, "complete": b.Complete, "statistics": stats, "gap_reason": reason}
}

func (e *Engine) Read(ctx context.Context, series string, from, to time.Time, maxPoints int) ([]any, string, string, error) {
	if maxPoints < 1 || maxPoints > 2000 || !to.After(from) || to.Sub(from) > 7*24*time.Hour {
		return nil, "", "", storage.ErrInvalid
	}
	level := int64(15000)
	if to.Sub(from) > time.Hour {
		level = 60000
	}
	if to.Sub(from) > 24*time.Hour {
		level = 300000
	}
	rows, epoch, revision, err := e.store.Records(ctx, "bucket", series, level, from.UnixMicro(), to.UnixMicro(), "", 2000)
	if err != nil {
		return nil, "", "", err
	}
	points := []any{}
	var unit string
	for _, r := range rows {
		var a accumulated
		if json.Unmarshal(r.Data, &a) != nil {
			return nil, "", "", storage.ErrStorage
		}
		unit = a.Unit
		points = append(points, Point(a))
	}
	if unit == "" {
		meta, _, _, err := e.store.Records(ctx, "series", series, 0, 0, math.MaxInt64, "", 1)
		if err != nil {
			return nil, "", "", err
		}
		if len(meta) == 1 {
			var v map[string]string
			if json.Unmarshal(meta[0].Data, &v) != nil {
				return nil, "", "", storage.ErrStorage
			}
			unit = v["unit"]
		}
	}
	if len(points) > maxPoints {
		return nil, "", "", storage.ErrQuota
	}
	return points, unit, epoch + ":" + strconv.FormatInt(revision, 10), nil
}
