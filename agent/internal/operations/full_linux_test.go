// SPDX-License-Identifier: Apache-2.0
package operations

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"serverdeck.local/agent/internal/storage"
)

// Opt-in helper for a real, bounded ext4 ENOSPC test. Never fill an ordinary
// host filesystem: refuse root and any filesystem whose total size exceeds32MB.
func TestPhysicalFullFilesystem(t *testing.T) {
	root := os.Getenv("SERVERDECK_TEST_FULL_FS")
	if root == "" {
		t.Skip("requires private <=32MB ext4 mount; tools/e02-full-filesystem.sh")
	}
	var fs syscall.Statfs_t
	if os.Geteuid() == 0 || syscall.Statfs(root, &fs) != nil || uint64(fs.Type) != 0xef53 || int64(fs.Blocks)*fs.Bsize > 32000000 {
		t.Fatal("refusing unsafe ENOSPC environment")
	}
	fill := func(path string) {
		t.Helper()
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			t.Fatal(e)
		}
		defer f.Close()
		buf := make([]byte, 65536)
		for written := 0; written < 32000000; written += len(buf) {
			_, e = f.Write(buf)
			if errors.Is(e, syscall.ENOSPC) {
				return
			}
			if e != nil {
				t.Fatal(e)
			}
		}
		t.Fatal("bounded filesystem did not become full")
	}
	path := filepath.Join(root, "state-intent")
	s := openStore(t, path)
	f := &fixture{}
	svc := New(s, map[string]Handler{"fixture": f})
	r := prepared(t, svc, Local(), operationID)
	filler := filepath.Join(root, "intent-filler")
	fill(filler)
	if _, e := svc.Execute(context.Background(), Local(), r); e != storage.ErrSpace || f.effects.Load() != 0 {
		t.Fatalf("ENOSPC intent effect: %v", e)
	}
	os.Remove(filler)
	s.Close()
	path = filepath.Join(root, "state-result")
	s = openStore(t, path)
	filler = filepath.Join(root, "result-filler")
	f = &fixture{path: filepath.Join(root, "effects"), effect: func() Outcome {
		fill(filler)
		return Outcome{State: "succeeded", Effect: "applied", Result: []byte("null")}
	}}
	svc = New(s, map[string]Handler{"fixture": f})
	r = prepared(t, svc, Local(), operationID)
	o, e := svc.Execute(context.Background(), Local(), r)
	if e != storage.ErrAudit || o.Effect != "applied" || o.AuditStatus != "result_pending" || s.Health().AuditAvailable {
		t.Fatalf("ENOSPC result dishonest: %+v %v", o, e)
	}
	if _, e = svc.Execute(context.Background(), Local(), r); e != nil || f.effects.Load() != 1 {
		t.Fatal("full disk repeated effect")
	}
	os.Remove(filler)
	s.Close()
	s = openStore(t, path)
	svc = New(s, map[string]Handler{"fixture": f})
	o, e = svc.Execute(context.Background(), Local(), r)
	if e != nil || o.State != "unknown" || f.effects.Load() != 1 {
		t.Fatal("ENOSPC recovery repeated effect")
	}
}
