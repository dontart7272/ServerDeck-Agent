//go:build linux && cgo

// SPDX-License-Identifier: Apache-2.0
package fileaccess

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func sharedLocation(parts ...string) Location {
	l := Location{RootID: "test", Components: []string{}}
	for _, p := range parts {
		l.Components = append(l.Components, base64.RawURLEncoding.EncodeToString([]byte(p)))
	}
	return l
}

func TestE08PrivateMethodsCannotPublishOrPurgeOwnObject(t *testing.T) {
	g := fixtureGuard(t)
	g.EnableSharedRoots()
	root := t.TempDir()
	a, e := g.Area(root, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	id := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	f, e := a.New(id)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if _, e = f.Write([]byte("fixture-core-object")); e != nil {
		t.Fatal(e)
	}
	if e = f.Sync(); e != nil {
		t.Fatal(e)
	}
	proof, _ := IdentityProof(f)
	version, _ := Version(f)
	if e = g.Protect(f); e != nil {
		t.Fatal(e)
	}
	parent := sharedLocation()
	p, e := g.Open(root, parent)
	if e != nil {
		t.Fatal(e)
	}
	pv, _ := Version(p)
	p.Close()
	if out, e := a.Open(id, proof); e == nil {
		out.Close()
		t.Fatal("own object reopened for content")
	}
	if out, e := a.Publish(id, f, parent, "ZGVzdA", pv, ""); e == nil {
		out.Close()
		t.Fatal("own object published")
	}
	if out, e := a.Restore(id, version, parent, "ZGVzdA", pv); e == nil {
		out.Close()
		t.Fatal("own object restored")
	}
	if e = a.Purge(context.Background(), id, version); e == nil {
		t.Fatal("own object purged")
	}
	if info, e := f.Stat(); e != nil || info.Size() != 19 {
		t.Fatal("own object changed", e)
	}
}

func TestE08SharedRootProtectsOwnObjectsAndAncestors(t *testing.T) {
	root := t.TempDir()
	own := filepath.Join(root, "parent", "state")
	if e := os.MkdirAll(own, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(own, "request.key"), []byte("fixture-secret"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(filepath.Join(own, "nested"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(own, "nested", "db-copy"), []byte("fixture-own-copy"), 0600); e != nil {
		t.Fatal(e)
	}
	pin, e := PinAbsolute(own)
	if e != nil {
		t.Fatal(e)
	}
	g, e := New([]*os.File{pin})
	pin.Close()
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	g.EnableSharedRoots()
	g.ReserveName(".serverdeck-fixture")
	if f, e := g.Open(filepath.Join(own, "nested"), sharedLocation("db-copy")); e == nil {
		f.Close()
		t.Fatal("nested configured root bypassed protected ancestor")
	}
	if e := os.WriteFile(filepath.Join(root, "ordinary"), []byte("public"), 0600); e != nil {
		t.Fatal(e)
	}
	f, e := g.Open(root, sharedLocation("ordinary"))
	if e != nil {
		t.Fatal("ordinary shared filesystem data unavailable", e)
	}
	f.Close()
	for _, path := range []Location{sharedLocation("parent", "state"), sharedLocation("parent", "state", "request.key"), sharedLocation(".serverdeck-fixture")} {
		if f, e := g.Open(root, path); e == nil {
			f.Close()
			t.Fatal("protected path accepted", path)
		}
	}
	parent, e := g.Open(root, sharedLocation("parent"))
	if e != nil {
		t.Fatal(e)
	}
	version, e := Version(parent)
	if e != nil {
		t.Fatal(e)
	}
	if e = g.CanRemove(parent); !errors.Is(e, ErrProtected) {
		t.Fatal("dangerous ancestor removable", e)
	}
	parent.Close()
	r, e := g.Open(root, sharedLocation())
	if e != nil {
		t.Fatal(e)
	}
	rv, _ := Version(r)
	r.Close()
	if e = g.CheckRename(root, sharedLocation("parent"), version, sharedLocation(), "cmVuYW1lZA", rv); !errors.Is(e, ErrProtected) {
		t.Fatal("ancestor rename not refused", e)
	}
	if e = g.ValidateBindings(); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(own, own+"-moved"); e != nil {
		t.Fatal(e)
	}
	if e = g.ValidateBindings(); !errors.Is(e, ErrSafety) {
		t.Fatal("own-object maintenance violation undetected", e)
	}
}

func TestE08SharedRootsRenameAcrossUsesDestinationRoot(t *testing.T) {
	root := t.TempDir()
	own := filepath.Join(root, "state")
	source, target := filepath.Join(root, "from"), filepath.Join(root, "to")
	for _, p := range []string{own, source, target} {
		if e := os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	pin, e := PinAbsolute(own)
	if e != nil {
		t.Fatal(e)
	}
	g, e := New([]*os.File{pin})
	pin.Close()
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	g.EnableSharedRoots()
	if e = os.WriteFile(filepath.Join(source, "file"), []byte("payload"), 0600); e != nil {
		t.Fatal(e)
	}
	f, e := g.Open(source, sharedLocation("file"))
	if e != nil {
		t.Fatal(e)
	}
	v, _ := Version(f)
	f.Close()
	p, e := g.Open(target, sharedLocation())
	if e != nil {
		t.Fatal(e)
	}
	pv, _ := Version(p)
	p.Close()
	out, e := g.RenameAcross(source, target, sharedLocation("file"), v, sharedLocation(), "ZmlsZQ", pv)
	if e != nil {
		t.Fatal(e)
	}
	out.Close()
	if b, e := os.ReadFile(filepath.Join(target, "file")); e != nil || string(b) != "payload" {
		t.Fatal("wrong destination", e)
	}
	if _, e := os.Stat(filepath.Join(source, "file")); !os.IsNotExist(e) {
		t.Fatal("source remains", e)
	}
	if e = os.WriteFile(filepath.Join(source, "file"), []byte("next"), 0600); e != nil {
		t.Fatal(e)
	}
	f, e = g.Open(source, sharedLocation("file"))
	if e != nil {
		t.Fatal(e)
	}
	v, _ = Version(f)
	f.Close()
	p, e = g.Open(target, sharedLocation())
	if e != nil {
		t.Fatal(e)
	}
	pv, _ = Version(p)
	p.Close()
	if out, e = g.RenameAcross(source, target, sharedLocation("file"), v, sharedLocation(), "ZmlsZQ", pv); e == nil {
		out.Close()
		t.Fatal("occupied name overwritten")
	}
	if b, e := os.ReadFile(filepath.Join(target, "file")); e != nil || string(b) != "payload" {
		t.Fatal("occupied destination changed", e)
	}
}
