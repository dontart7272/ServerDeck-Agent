// SPDX-License-Identifier: Apache-2.0
//go:build linux && cgo

package history

import (
	"context"
	"encoding/json"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/metrics"
	"testing"
	"time"
)

func TestGPUHistoryPersistsMaxMeanAndSeparatesSource(t *testing.T) {
	e, _ := historyFixture(t)
	l, err := metrics.NewLinux()
	if err != nil {
		t.Fatal(err)
	}
	base := epoch
	resource := "gpu.fixture"
	record := json.RawMessage(`{"record_type":"gpu","resource_id":"gpu.fixture","uuid":"GPU-fixture"}`)
	for i := 0; i <= 16; i += 2 {
		stamp := metrics.Stamp{Wall: base.Add(time.Duration(i) * time.Second), Mono: time.Duration(i+1) * time.Second}
		sample, err := l.Collect("memory", stamp, 2000, "fixture")
		if err != nil {
			t.Fatal(err)
		}
		var m metrics.Metric
		for _, candidate := range sample.Block.Metrics {
			if candidate.Availability == "available" {
				m = candidate
				break
			}
		}
		if m.MeasuredAt == nil {
			t.Fatal("clock fixture missing")
		}
		m.Key = "power_w"
		m.ResourceID = resource
		m.Unit = "watt"
		m.Value = float64(i)
		m.Source = "nvml"
		m.Interval = 2000
		e.Observe(metrics.Snapshot{At: contracts.Timestamp(stamp.Wall), SegmentID: "22222222-2222-4222-8222-222222222222", Blocks: []metrics.Block{{ID: "gpu", Metrics: []metrics.Metric{m}, Records: []json.RawMessage{record}}}})
	}
	if err = e.Flush(context.Background(), base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	points, unit, _, err := e.Read(context.Background(), SeriesID(resource, "power_w@nvml"), base, base.Add(time.Minute), 100)
	if err != nil || unit != "watt" || len(points) == 0 {
		t.Fatal(unit, len(points), err)
	}
	stats := points[0].(map[string]any)["statistics"].(map[string]any)
	if stats["max"] == nil || stats["mean"] == nil {
		t.Fatal(stats)
	}
	if SeriesID(resource, "power_w@nvml") == SeriesID(resource, "power_w@nvidia-smi") {
		t.Fatal("source precision merged")
	}
}
