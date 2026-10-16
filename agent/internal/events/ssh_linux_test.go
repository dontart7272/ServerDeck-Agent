// SPDX-License-Identifier: Apache-2.0
//go:build linux

package events

import (
	"context"
	"testing"
	"time"
)

func TestSSHWindowRotationDedupAddressesSourceLossAndQuietRecovery(t *testing.T) {
	e, db, _ := eventFixture(t)
	ctx := context.Background()
	base := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	for _, x := range []struct {
		source, address string
		position        uint64
		second          int
	}{{"inode-old", "203.0.113.7", 1, 0}, {"inode-old", "203.0.113.7", 2, 20}, {"inode-old", "203.0.113.7", 2, 21}, {"inode-old", "203.0.113.7", 3, 40}, {"inode-new", "203.0.113.7", 1, 60}, {"inode-new", "203.0.113.7", 2, 80}, {"inode-new", "203.0.113.8", 3, 81}} {
		if err := e.SSHFailure(ctx, SSHObservation{Source: x.source, Address: x.address, Position: x.position, At: base.Add(time.Duration(x.second) * time.Second), Mono: time.Duration(x.second) * time.Second}); err != nil {
			t.Fatal(err)
		}
	}
	if len(e.Problems()) != 1 {
		t.Fatal("cross-address grouping or rotation lost window")
	}
	rows, epoch, last, err := eventChanges(db, ctx, "", 0, 100)
	if err != nil || len(rows) != 1 || EventWire(rows[0], epoch)["count"] != "5" {
		t.Fatal("duplicate counted", rows, err)
	}
	if err = e.SSHSourceProgress(ctx, "ssh", base.Add(400*time.Second), 400*time.Second, false); err != nil {
		t.Fatal(err)
	}
	if e.Problems()[0].(map[string]any)["state"] != "source_unknown" {
		t.Fatal("loss became recovery")
	}
	if err = e.SSHSourceProgress(ctx, "ssh", base.Add(401*time.Second), 401*time.Second, true); err != nil {
		t.Fatal(err)
	}
	if len(e.Problems()) != 1 {
		t.Fatal("unknown quiet duration continued")
	}
	if err = e.SSHSourceProgress(ctx, "ssh", base.Add(700*time.Second), 700*time.Second, true); err != nil {
		t.Fatal(err)
	}
	if len(e.Problems()) != 1 {
		t.Fatal("early quiet recovery")
	}
	if err = e.SSHSourceProgress(ctx, "ssh", base.Add(701*time.Second), 701*time.Second, true); err != nil {
		t.Fatal(err)
	}
	if len(e.Problems()) != 0 {
		t.Fatal("quiet recovery absent")
	}
	rows, _, _, err = eventChanges(db, ctx, epoch, last, 100)
	if err != nil || len(rows) != 1 || EventWire(rows[0], epoch)["code"] != "SSH_WINDOW_QUIET" {
		t.Fatal("quiet event", err)
	}
	if err = e.SSHFailure(ctx, SSHObservation{Source: "inode-new", Address: "203.0.113.7", Position: 2, At: base.Add(702 * time.Second), Mono: 702 * time.Second}); err != nil {
		t.Fatal(err)
	}
	if len(e.Problems()) != 0 {
		t.Fatal("replay recreated problem")
	}
}
