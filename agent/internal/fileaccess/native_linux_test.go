//go:build linux && cgo

// SPDX-License-Identifier: Apache-2.0
package fileaccess

import (
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func fixtureGuard(t *testing.T) *Guard {
	t.Helper()
	p, e := PinAbsolute("/proc")
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	g, e := New([]*os.File{p})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(g.Close)
	return g
}
func TestE08OpenTypesTraversalAndHardLinks(t *testing.T) {
	dir := t.TempDir()
	g := fixtureGuard(t)
	os.WriteFile(filepath.Join(dir, "file"), []byte("hello"), 0600)
	f, e := g.Open(dir, Location{"root", []string{base64.RawURLEncoding.EncodeToString([]byte("file"))}})
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	r, e := g.ReadFile(f)
	if e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(r)
	r.Close()
	if e != nil || string(b) != "hello" {
		t.Fatal(e)
	}
	for _, parts := range [][]string{{"..", "file"}, {"a/b"}, {""}, {"a\x00b"}, {"a\\b"}} {
		if _, e := g.Open(dir, Location{"root", parts}); e == nil {
			t.Fatal("invalid path accepted")
		}
	}
	os.Symlink("file", filepath.Join(dir, "link"))
	link, e := g.Open(dir, Location{"root", []string{base64.RawURLEncoding.EncodeToString([]byte("link"))}})
	if e != nil {
		t.Fatal(e)
	}
	defer link.Close()
	if _, e = g.ReadFile(link); e == nil {
		t.Fatal("symlink dereferenced")
	}
	syscall.Mkfifo(filepath.Join(dir, "fifo"), 0600)
	fifo, e := g.Open(dir, Location{"root", []string{base64.RawURLEncoding.EncodeToString([]byte("fifo"))}})
	if e != nil {
		t.Fatal(e)
	}
	defer fifo.Close()
	if _, e = g.ReadFile(fifo); e == nil {
		t.Fatal("FIFO read")
	}
	os.Link(filepath.Join(dir, "file"), filepath.Join(dir, "hard"))
	if _, e = g.Open(dir, Location{"root", []string{base64.RawURLEncoding.EncodeToString([]byte("hard"))}}); e == nil {
		t.Fatal("hardlink")
	}
	if _, e = g.Open("/dev/shm", Location{"root", []string{}}); e == nil {
		t.Fatal("virtual /dev filesystem exposed")
	}
}
func TestE08PinnedProtectedFilesystemSurvivesRename(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	os.Mkdir(state, 0700)
	pin, e := PinAbsolute(state)
	if e != nil {
		t.Fatal(e)
	}
	defer pin.Close()
	g, e := New([]*os.File{pin})
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	os.Rename(state, filepath.Join(dir, "renamed"))
	os.Mkdir(state, 0700)
	if _, e = g.Open(dir, Location{"root", []string{base64.RawURLEncoding.EncodeToString([]byte("renamed"))}}); !errors.Is(e, ErrSafety) {
		t.Fatal("protected FS alias allowed", e)
	}
}
func TestE08CounterexampleParentValidationIsNotProtection(t *testing.T) {
	dir := t.TempDir()
	ordinary := filepath.Join(dir, "ordinary")
	protected := filepath.Join(dir, "protected")
	os.Mkdir(ordinary, 0700)
	os.Mkdir(protected, 0700)
	os.WriteFile(filepath.Join(protected, "secret"), []byte("synthetic-secret"), 0600)
	root, e := PinAbsolute(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	old, e := nativeOpen(int(root.Fd()), "ordinary", pathOnly, true)
	if e != nil {
		t.Fatal(e)
	}
	old.Close() // naive precheck succeeded
	os.Rename(ordinary, filepath.Join(dir, "old"))
	os.Rename(protected, ordinary)
	opened, e := nativeOpen(int(root.Fd()), "ordinary/secret", pathOnly, true)
	if e != nil {
		t.Fatal(e)
	}
	defer opened.Close()
	st, e := opened.Stat()
	if e != nil || st.Size() != 16 {
		t.Fatal(st, e)
	}
	t.Log("COUNTEREXAMPLE: full openat2 beneath root can resolve a protected directory moved in after an earlier parent check")
}
func TestE08CounterexampleStatThenRenameLosesExternalEdit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	os.WriteFile(path, []byte("original"), 0600)
	p, _ := PinAbsolute(path)
	before, _ := Version(p)
	p.Close()
	os.WriteFile(filepath.Join(dir, "stage"), []byte("agent"), 0600)
	// The external writer runs after the last version check, before publication.
	os.WriteFile(path, []byte("external-new"), 0600)
	if e := os.Rename(filepath.Join(dir, "stage"), path); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(path)
	if string(b) != "agent" {
		t.Fatal("counterexample did not reproduce")
	}
	t.Log("COUNTEREXAMPLE: stat/expected version", before, "does not make rename a compare-and-swap; external edit lost")
}
func FuzzE08Location(f *testing.F) {
	f.Add("..")
	f.Add("name")
	f.Fuzz(func(t *testing.T, s string) {
		l := Location{"root", []string{s}}
		e := l.Validate()
		if e == nil && (s == "" || s == ".." || s == ".") {
			t.Fatal("unsafe component")
		}
	})
}

func TestE08ActualPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("ordinary UID procedure")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "denied")
	os.WriteFile(path, []byte("fixture"), 0000)
	g := fixtureGuard(t)
	f, e := g.Open(dir, Location{"root", []string{"ZGVuaWVk"}})
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if _, e = g.ReadFile(f); !errors.Is(e, ErrPermission) {
		t.Fatal("OS permission denial", e)
	}
}
