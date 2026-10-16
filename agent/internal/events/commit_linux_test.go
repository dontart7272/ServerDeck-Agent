// SPDX-License-Identifier: Apache-2.0
//go:build linux

package events

import (
	"context"
	"testing"
	"time"

	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/storage"
)

// The fault decorates a real SQLite commit; it does not fake database effects.
type lostCommitReply struct {
	*storage.Telemetry
	lose bool
}

func (s *lostCommitReply) Update(ctx context.Context, records, changes []storage.TelemetryRecord, deletes []string) error {
	if err := s.Telemetry.Update(ctx, records, changes, deletes); err != nil {
		return err
	}
	if s.lose {
		s.lose = false
		return storage.ErrStorage
	}
	return nil
}

func TestLostCommitReplyDoesNotDuplicateBeginOrRecovery(t *testing.T) {
	e, db, _ := eventFixture(t)
	fault := &lostCommitReply{db, true}
	e.store = fault
	ctx := context.Background()
	r := storage.DefaultRules()[0]
	r.DurationMs = 0
	r.RecoveryDurationMs = 0
	base := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	if err := e.Observe(ctx, []contracts.APIRule{r}, observation(base, 0, 9, true), 0); err == nil {
		t.Fatal("lost reply hidden")
	}
	if !e.Health() {
		t.Fatal("failure hidden independently of journal")
	}
	before, epoch, _, err := eventChanges(db, ctx, "", 0, 100)
	if err != nil || len(before) != 1 {
		t.Fatal("real begin not committed", err)
	}
	beginID := before[0].ID
	if err = e.Observe(ctx, []contracts.APIRule{r}, observation(base, 1, 9, true), time.Second); err != nil {
		t.Fatal(err)
	}
	fault.lose = true
	if err = e.Observe(ctx, []contracts.APIRule{r}, observation(base, 2, 16, true), 2*time.Second); err == nil {
		t.Fatal("recovery lost reply hidden")
	}
	if err = e.Observe(ctx, []contracts.APIRule{r}, observation(base, 3, 16, true), 3*time.Second); err != nil {
		t.Fatal(err)
	}
	if len(e.Problems()) != 0 {
		t.Fatal("recovery unresolved")
	}
	rows, _, _, err := eventChanges(db, ctx, "", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	begin, recovery, gaps := 0, 0, 0
	for _, row := range rows {
		event := EventWire(row, epoch)
		switch event["kind"] {
		case "begin":
			begin++
			if row.ID != beginID {
				t.Fatal("identity changed")
			}
		case "recovery":
			recovery++
		case "gap":
			gaps++
		}
	}
	if begin != 1 || recovery != 1 || gaps != 2 {
		t.Fatalf("duplicates or hidden coverage: begin=%d recovery=%d gaps=%d", begin, recovery, gaps)
	}
}

type failBeforeCommit struct {
	*storage.Telemetry
	remaining int
}

func (s *failBeforeCommit) Update(ctx context.Context, records, changes []storage.TelemetryRecord, deletes []string) error {
	if s.remaining > 0 {
		s.remaining--
		return storage.ErrStorage
	}
	return s.Telemetry.Update(ctx, records, changes, deletes)
}
func TestRetriedGapKeepsItsPersistedTimestampAndFilterPosition(t *testing.T) {
	e, db, _ := eventFixture(t)
	e.store = &failBeforeCommit{db, 2}
	r := storage.DefaultRules()[0]
	r.DurationMs = 0
	base := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		err := e.Observe(context.Background(), []contracts.APIRule{r}, observation(base, i, 9, true), time.Duration(i)*time.Second)
		if (i < 2) != (err != nil) {
			t.Fatal(i, err)
		}
	}
	rows, epoch, _, err := eventChanges(db, context.Background(), "", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range rows {
		wire := EventWire(row, epoch)
		if wire["kind"] == "gap" {
			at, err := time.Parse(time.RFC3339Nano, wire["observed_at"].(string))
			if err != nil || row.Start != at.UnixMicro() {
				t.Fatal("journal filter timestamp drift", row.Start, wire, err)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("missing gap")
	}
}
