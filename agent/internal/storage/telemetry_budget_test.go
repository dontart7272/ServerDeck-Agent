// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestTelemetryJournalShrinkAndGrowthAreConfirmedAgainstActualState(t *testing.T) {
	s, _ := testStore(t, DefaultLimits())
	ctx := context.Background()
	db, err := s.OpenTelemetry(ctx, "events", 32000000)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	active := TelemetryRecord{Kind: "problem", ID: testOperation, Series: "fixture", Start: 0, Stop: math.MaxInt64, Revision: 1, Data: json.RawMessage(`{"state":"active"}`)}
	if err = db.Update(ctx, []TelemetryRecord{active}, nil, nil); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]string{"padding": strings.Repeat("x", 2048)})
	for i := 0; i < 800; i += 16 {
		batch := []TelemetryRecord{}
		for j := 0; j < 16; j++ {
			batch = append(batch, TelemetryRecord{Kind: "event", ID: fmt.Sprintf("event-%04d", i+j), Start: int64(i + j), Stop: int64(i + j), Revision: 1, Data: data})
		}
		if err = db.Update(ctx, nil, batch, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err = db.SetBudget(1000000); err != ErrQuota {
		t.Fatal("uncompleted journal shrink declared successful", err)
	}
	for i := 0; i < 20; i++ {
		_ = db.Reclaim(ctx)
	}
	var size int64
	if err = db.db.QueryRow("SELECT coalesce(sum(length(data)+length(id)+512),0) FROM changes").Scan(&size); err != nil || size > 1000000 {
		t.Fatal("logical quota not enforced", size, err)
	}
	rows, _, _, err := db.Records(ctx, "problem", "", 0, 0, math.MaxInt64, "", 100)
	if err != nil || len(rows) != 1 {
		t.Fatal("cleanup deleted active problem", err)
	}
	var before, after int64
	db.db.QueryRow("PRAGMA max_page_count").Scan(&before)
	if err = db.SetBudget(64000000); err != nil {
		t.Fatal(err)
	}
	db.db.QueryRow("PRAGMA max_page_count").Scan(&after)
	if after <= before {
		t.Fatal("growing budget retained old page ceiling", before, after)
	}
	_, floor, _, err := db.Bounds(ctx)
	if err != nil || floor == 0 {
		t.Fatal("rotation silently reused cursors", floor, err)
	}
}
