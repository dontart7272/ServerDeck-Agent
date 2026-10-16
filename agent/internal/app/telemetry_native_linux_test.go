// SPDX-License-Identifier: Apache-2.0
//go:build linux

package app

import (
	"context"
	"math"
	"serverdeck.local/agent/internal/metrics"
	"testing"
	"time"
)

func TestTelemetryPersistsSharedNativeCollectionWithoutPhones(t *testing.T) {
	g, _, _ := newTestGateway(t)
	collector, err := metrics.NewLinux()
	if err != nil {
		t.Fatal(err)
	}
	g.Metrics = metrics.New(g.RunID, collector.BootID(), collector)
	g.startTelemetry()
	deadline := time.Now().Add(18 * time.Second)
	for {
		rows, _, _, err := g.historyDB.Records(context.Background(), "bucket", "", 0, 0, math.MaxInt64, "", 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("history never persisted without client")
		}
		time.Sleep(100 * time.Millisecond)
	}
	g.mu.Lock()
	phones := len(g.wsDevices)
	g.mu.Unlock()
	if phones != 0 {
		t.Fatal("fixture unexpectedly acquired a phone")
	}
}
