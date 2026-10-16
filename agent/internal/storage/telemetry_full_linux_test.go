// SPDX-License-Identifier: Apache-2.0
//go:build linux

package storage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestTelemetryPhysicalFullFilesystem(t *testing.T) {
	root := os.Getenv("SERVERDECK_TEST_FULL_FS")
	if root == "" {
		t.Skip("isolated bounded ext4 procedure only")
	}
	var fs syscall.Statfs_t
	if syscall.Statfs(root, &fs) != nil || uint64(fs.Blocks)*uint64(fs.Bsize) > 32000000 || uint64(fs.Blocks)*uint64(fs.Bsize) < 8000000 || fs.Type != 0xef53 || os.Geteuid() == 0 {
		t.Fatal("refusing unsafe full filesystem environment")
	}
	current, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	init, _ := os.Readlink("/proc/1/ns/mnt")
	if current == init {
		t.Fatal("mount namespace is not isolated")
	}
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(root, "state"), testInstallation, seed(t), true, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	history, err := s.OpenTelemetry(ctx, "history", 256000000)
	if err != nil {
		t.Fatal(err)
	}
	defer history.Close()
	events, err := s.OpenTelemetry(ctx, "events", 32000000)
	if err != nil {
		t.Fatal(err)
	}
	defer events.Close()
	r := TelemetryRecord{Kind: "bucket", ID: "first", Series: "fixture", Segment: testDevice, Level: 15000, Start: 1, Stop: 15000001, Revision: 1, Data: json.RawMessage(`{"mean":1}`)}
	if err = history.Update(ctx, []TelemetryRecord{r}, nil, nil); err != nil {
		t.Fatal(err)
	}
	p := TelemetryRecord{Kind: "problem", ID: testOperation, Series: "fixture", Segment: testDevice, Start: 1, Stop: 9223372036854775807, Revision: 1, Data: json.RawMessage(`{"state":"active"}`)}
	if err = events.Update(ctx, []TelemetryRecord{p}, []TelemetryRecord{p}, nil); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(root, "fill"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	full := false
	buffer := make([]byte, 65536)
	for i := 0; i < 512; i++ {
		if _, err = f.Write(buffer); err != nil {
			if errors.Is(err, syscall.ENOSPC) {
				full = true
				break
			}
			t.Fatal(err)
		}
	}
	f.Close()
	if !full {
		t.Fatal("bounded image did not reach ENOSPC")
	}
	r.ID = "second"
	r.Revision = 2
	if err = history.Update(ctx, []TelemetryRecord{r}, nil, nil); err == nil {
		t.Fatal("full history write succeeded")
	}
	_, _, _, failed := history.Health()
	if !failed {
		t.Fatal("history failure not observable")
	}
	if err = events.Update(ctx, nil, []TelemetryRecord{p}, []string{p.ID}); err == nil {
		t.Fatal("full event recovery succeeded")
	}
	rows, _, _, err := events.Records(ctx, "problem", "", 0, 0, 9223372036854775807, "", 100)
	if err != nil || len(rows) != 1 {
		t.Fatal("full storage lost active problem", err)
	}
	if _, _, err = s.Settings(ctx); err != nil {
		t.Fatal("critical settings unreadable after telemetry failure", err)
	}
}
