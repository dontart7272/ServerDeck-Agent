// SPDX-License-Identifier: Apache-2.0
//go:build linux

package events

import (
	"context"
	"testing"
	"time"
)

func TestSSHLostCommitReplyReconcilesDurableState(t *testing.T) {
	e, db, _ := eventFixture(t)
	fault := &lostCommitReply{Telemetry: db}
	e.store = fault
	ctx := context.Background()
	base := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	for i := 1; i <= 5; i++ {
		fault.lose = i == 5
		err := e.SSHFailure(ctx, SSHObservation{Source: "inode", Address: "203.0.113.9", Position: uint64(i), At: base.Add(time.Duration(i) * time.Second), Mono: time.Duration(i) * time.Second})
		if (i == 5) != (err != nil) {
			t.Fatal(i, err)
		}
	}
	if err := e.SSHFailure(ctx, SSHObservation{Source: "inode", Address: "203.0.113.9", Position: 5, At: base.Add(6 * time.Second), Mono: 6 * time.Second}); err != nil {
		t.Fatal(err)
	}
	if len(e.Problems()) != 1 {
		t.Fatal("committed begin not reconciled")
	}
	// Reconciliation restarts continuous source coverage conservatively.
	if err := e.SSHSourceProgress(ctx, "ssh", base.Add(7*time.Second), 7*time.Second, true); err != nil {
		t.Fatal(err)
	}
	fault.lose = true
	if err := e.SSHSourceProgress(ctx, "ssh", base.Add(308*time.Second), 308*time.Second, true); err == nil {
		t.Fatal("lost recovery ack hidden")
	}
	if err := e.SSHSourceProgress(ctx, "ssh", base.Add(309*time.Second), 309*time.Second, true); err != nil {
		t.Fatal(err)
	}
	rows, _, _, err := eventChanges(db, ctx, "", 0, 100)
	if err != nil || len(rows) != 2 || len(e.Problems()) != 0 {
		t.Fatal("duplicate recovery or stale active state", len(rows), len(e.Problems()), err)
	}
}

func TestPolicyReadFailureIsVisibleWithoutJournal(t *testing.T) {
	e, _, _ := eventFixture(t)
	e.PolicyUnavailable(true)
	if !e.Health() {
		t.Fatal("policy failure hidden")
	}
	e.PolicyUnavailable(false)
	if e.Health() {
		t.Fatal("health never recovers")
	}
}
