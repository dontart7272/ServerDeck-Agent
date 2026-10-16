// SPDX-License-Identifier: Apache-2.0
//go:build linux

package storage

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestTelemetryCrashHelper(t *testing.T) {
	path := os.Getenv("SERVERDECK_TELEMETRY_CRASH_STATE")
	if path == "" {
		return
	}
	ctx := context.Background()
	s, err := Open(ctx, path, "", nil, false, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	db, err := s.OpenTelemetry(ctx, "events", 32000000)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for generation := 1; generation <= 10000; generation++ {
		b, _ := json.Marshal(map[string]int{"generation": generation})
		r := TelemetryRecord{Kind: "problem", ID: testOperation, Series: "fixture", Segment: testDevice, Start: 1, Stop: 9223372036854775807, Revision: int64(generation), Data: b}
		change := r
		change.Kind = "event"
		change.ID, err = RandomID()
		if err != nil {
			t.Fatal(err)
		}
		if err = db.Update(ctx, []TelemetryRecord{r}, []TelemetryRecord{change}, nil); err != nil {
			t.Fatal(err)
		}
		if generation == 1 {
			if err = os.WriteFile(filepath.Join(path, "child-ready"), []byte("ready"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestTelemetryKillDuringRealUpdatesKeepsStateAndJournalAtomic(t *testing.T) {
	for _, delay := range []time.Duration{0, 2 * time.Millisecond, 10 * time.Millisecond} {
		t.Run(delay.String(), func(t *testing.T) {
			s, path := testStore(t, DefaultLimits())
			db, err := s.OpenTelemetry(context.Background(), "events", 32000000)
			if err != nil {
				t.Fatal(err)
			}
			db.Close()
			s.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTelemetryCrashHelper$")
			cmd.Env = append(os.Environ(), "SERVERDECK_TELEMETRY_CRASH_STATE="+path)
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill() })
			for {
				if _, err = os.Stat(filepath.Join(path, "child-ready")); err == nil {
					break
				}
				if ctx.Err() != nil {
					t.Fatal("child did not start")
				}
				time.Sleep(time.Millisecond)
			}
			time.Sleep(delay)
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			reopened, err := Open(context.Background(), path, "", nil, false, DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			recovered, err := reopened.OpenTelemetry(context.Background(), "events", 32000000)
			if err != nil {
				t.Fatal(err)
			}
			defer recovered.Close()
			var state, event []byte
			if recovered.db.QueryRow("SELECT data FROM records WHERE kind='problem' AND id=?", testOperation).Scan(&state) != nil || recovered.db.QueryRow("SELECT data FROM changes WHERE kind='event' ORDER BY seq DESC LIMIT 1").Scan(&event) != nil {
				t.Fatal("committed prefix lost")
			}
			var a, b map[string]int
			if json.Unmarshal(state, &a) != nil || json.Unmarshal(event, &b) != nil || a["generation"] != b["generation"] {
				t.Fatal("state/event half transaction")
			}
		})
	}
}
