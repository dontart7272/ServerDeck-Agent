// SPDX-License-Identifier: Apache-2.0
//go:build linux

package events

import (
	"context"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/metrics"
	"serverdeck.local/agent/internal/storage"
	"testing"
	"time"
)

func TestGPUDeviceThresholdRequiresFreshSameResourceThreshold(t *testing.T) {
	e, _, _ := eventFixture(t)
	var rule contracts.APIRule
	for _, r := range storage.DefaultRules() {
		if r.Id == "gpu.temperature" {
			rule = r
		}
	}
	if !rule.Enabled {
		t.Fatal("new default disabled")
	}
	base := time.Now().UTC()
	observe := func(second int, threshold bool, temp float64) {
		at := contracts.Timestamp(base.Add(time.Duration(second) * time.Second))
		ms := []metrics.Metric{{Key: "temperature_c", ResourceID: "gpu.test", Unit: "celsius", Value: temp, Availability: "available", Freshness: "fresh", MeasuredAt: &at}}
		if threshold {
			ms = append(ms, metrics.Metric{Key: "temperature_threshold_c", ResourceID: "gpu.test", Unit: "celsius", Value: 80.0, Availability: "available", Freshness: "fresh", MeasuredAt: &at})
		}
		s := metrics.Snapshot{At: at, SegmentID: "22222222-2222-4222-8222-222222222222", Blocks: []metrics.Block{{ID: "gpu", Availability: "available", Metrics: ms}}}
		if err := e.Observe(context.Background(), []contracts.APIRule{rule}, s, time.Duration(second)*time.Second); err != nil {
			t.Fatal(err)
		}
	}
	observe(0, false, 99)
	observe(120, false, 99)
	if len(e.Problems()) != 0 {
		t.Fatal("invented threshold")
	}
	observe(121, true, 80)
	observe(300, true, 80)
	if len(e.Problems()) != 1 {
		t.Fatalf("device boundary not triggered: %d", len(e.Problems()))
	}
}
