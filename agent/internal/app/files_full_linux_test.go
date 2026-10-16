//go:build linux && cgo

// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"serverdeck.local/agent/internal/fileaccess"
	"serverdeck.local/agent/internal/operations"
	"syscall"
	"testing"
)

func TestE08NativeFullAndReadOnlyPreserveOriginal(t *testing.T) {
	root := os.Getenv("SD_E08_ROOT")
	if root == "" {
		t.Skip("private bounded filesystem procedure")
	}
	ns, _ := os.Readlink("/proc/self/ns/mnt")
	if os.Getenv("SD_E08_OUTER_MNT") == "" || ns == os.Getenv("SD_E08_OUTER_MNT") {
		t.Fatal("not isolated")
	}
	var fs syscall.Statfs_t
	if syscall.Statfs(root, &fs) != nil || uint64(fs.Type) != 0x01021994 || uint64(fs.Blocks)*uint64(fs.Bsize) > 16000000+4096 {
		t.Fatal("unbounded/non-tmpfs fixture")
	}
	g, _, _ := newTestGateway(t)
	dir := fixtureFiles(t, g)
	g.Files.guard.EnableSharedRoots()
	// Use a fresh child of the bounded mount as the configured allowed root.
	bounded := filepath.Join(root, "negative")
	if e := os.Mkdir(bounded, 0700); e != nil {
		t.Fatal(e)
	}
	raw, revision, e := g.fileConfig(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	raw.Files.Roots[0].Path = bounded
	applyTelemetry(t, g, "config.set", revision, map[string]any{"changes": map[string]any{"files": raw.Files}})
	_ = dir
	original := []byte("original survives ENOSPC and read-only")
	if e := os.WriteFile(filepath.Join(bounded, "original"), original, 0600); e != nil {
		t.Fatal(e)
	}
	area, e := g.Files.guard.Area(bounded, g.AgentID)
	if e != nil {
		t.Fatal(e)
	}
	area.Close()
	fill, e := os.Create(filepath.Join(bounded, "filler"))
	if e != nil {
		t.Fatal(e)
	}
	if e = syscall.Statfs(root, &fs); e != nil {
		t.Fatal(e)
	}
	reserve := int64(fs.Bavail)*int64(fs.Bsize) - 8*int64(fs.Bsize)
	if reserve <= 0 {
		t.Fatal("unexpected fixture capacity")
	}
	if e = syscall.Fallocate(int(fill.Fd()), 0, 0, reserve); e != nil {
		t.Fatal(e)
	}
	parent, _ := e08Root(t, g, bounded)
	loc := fileaccess.Location{RootID: parent.RootID, Components: []string{"b3JpZ2luYWw"}}
	f, e := g.Files.guard.Open(bounded, loc)
	if e != nil {
		t.Fatal(e)
	}
	v, _ := fileaccess.Version(f)
	f.Close()
	sum := sha256.Sum256(bytes.Repeat([]byte{'x'}, 200000))
	o := runE08Operation(t, g, operations.Local(), "files.write.begin", editParams{Location: loc, Expected: v, Size: 200000, SHA: hex.EncodeToString(sum[:]), Encoding: "utf-8"})
	if o.State == "succeeded" {
		t.Fatal("full filesystem accepted staging")
	}
	if b, e := os.ReadFile(filepath.Join(bounded, "original")); e != nil || !bytes.Equal(b, original) {
		t.Fatal("ENOSPC damaged original", e)
	}
	if o.State == "unknown" {
		if e = g.Operations.ResolveLocal(t.Context(), operations.Local(), o.ID, "none"); e != nil {
			t.Fatal(e)
		}
	}
	fill.Close()
	if e = os.Remove(filepath.Join(bounded, "filler")); e != nil {
		t.Fatal(e)
	}
	if e = syscall.Mount("", root, "", syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); e != nil {
		t.Fatal(e)
	}
	defer syscall.Mount("", root, "", syscall.MS_REMOUNT, "")
	parent, v = e08Root(t, g, bounded)
	b, _ := json.Marshal(fileCreateParams{Parent: parent, Name: "cmVhZG9ubHk", Kind: "file", ParentVersion: v})
	r := operations.Request{ID: newID(t), Action: "files.create", Params: b}
	p, e := g.Operations.Prepare(t.Context(), operations.Local(), r)
	if e != nil {
		t.Fatal(e)
	}
	r.Plan = p.ID
	o, e = g.Operations.Execute(t.Context(), operations.Local(), r)
	if e != nil || o.Effect != "none" {
		t.Fatal("read-only effect", o.State, o.Effect, e)
	}
	if b, e := os.ReadFile(filepath.Join(bounded, "original")); e != nil || !bytes.Equal(b, original) {
		t.Fatal("read-only damaged original", e)
	}
}
