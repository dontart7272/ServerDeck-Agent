//go:build linux && cgo

// SPDX-License-Identifier: Apache-2.0
package fileaccess

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
)

type Area struct {
	dir  *os.File
	g    *Guard
	root string
	name string
}

func validOpaqueID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	_, e := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	return e == nil && strings.ToLower(s) == s
}
func (g *Guard) reserveEntry(f *os.File, hold bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.reserveEntryLocked(f, hold)
}
func (g *Guard) reserveEntryLocked(f *os.File, hold bool) error {
	st, e := metadata(f)
	if e != nil {
		return e
	}
	if g.closed {
		return ErrSafety
	}
	key := identity{uint64(st.Dev), st.Ino}
	if hold {
		if !g.reserved[key] && len(g.reserved) >= g.privateLimit {
			return ErrLimit
		}
		g.reserved[key] = true
	} else {
		delete(g.reserved, key)
	}
	return nil
}
func (g *Guard) CheckPrivateCapacity(nodes int) error {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.closed {
		return ErrSafety
	}
	if nodes < 0 || nodes > g.privateLimit-len(g.reserved) {
		return ErrLimit
	}
	return nil
}
func (g *Guard) Area(root, installation string) (*Area, error) {
	if !validOpaqueID(installation) {
		return nil, ErrSafety
	}
	r, e := g.MutationRoot(root)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	d, e := g.Directory(r)
	if e != nil {
		return nil, e
	}
	defer d.Close()
	name := ".serverdeck-" + installation
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil, ErrSafety
	}
	g.reservedNames[name] = true
	if e = syscall.Mkdirat(int(d.Fd()), name, 0700); e != nil && !errors.Is(e, syscall.EEXIST) {
		return nil, classifyMutation(e)
	}
	a, e := nativeOpen(int(d.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY, true)
	if e != nil {
		return nil, e
	}
	st, e := metadata(a)
	if e != nil || st.Mode&07777 != 0700 || st.Uid != uint32(os.Geteuid()) {
		a.Close()
		return nil, ErrSafety
	}
	if e = g.reserveEntryLocked(a, true); e != nil {
		a.Close()
		return nil, e
	}
	if d.Sync() != nil {
		a.Close()
		return nil, ErrUncertain
	}
	return &Area{a, g, root, name}, nil
}
func (a *Area) Close() error { return a.dir.Close() }
func (a *Area) Name() string { return a.name }
func (a *Area) Space(bytes int64) error {
	if bytes < 0 {
		return ErrLimit
	}
	var st syscall.Statfs_t
	if syscall.Fstatfs(int(a.dir.Fd()), &st) != nil || st.Bsize <= 0 {
		return ErrSafety
	}
	if uint64(bytes)/uint64(st.Bsize)+17 > st.Bavail {
		return ErrSpace
	}
	return nil
}
func (a *Area) New(id string) (*os.File, error) {
	if !validOpaqueID(id) {
		return nil, ErrSafety
	}
	if e := a.Space(0); e != nil {
		return nil, e
	}
	a.g.mu.Lock()
	defer a.g.mu.Unlock()
	if a.g.closed {
		return nil, ErrSafety
	}
	fd, e := syscall.Openat(int(a.dir.Fd()), id, syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_RDWR|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return nil, classifyMutation(e)
	}
	f := os.NewFile(uintptr(fd), "staging")
	if a.g.reserveEntryLocked(f, true) != nil || f.Sync() != nil || a.dir.Sync() != nil {
		f.Close()
		return nil, ErrUncertain
	}
	return f, nil
}
func (a *Area) Open(id, proof string) (*os.File, error) {
	if !validOpaqueID(id) {
		return nil, ErrSafety
	}
	entry, e := a.Entry(id)
	if e != nil {
		return nil, e
	}
	entry.Close()
	f, e := nativeOpen(int(a.dir.Fd()), id, syscall.O_RDWR|syscall.O_NONBLOCK, true)
	if e != nil {
		return nil, e
	}
	st, e := metadata(f)
	p, pe := IdentityProof(f)
	if e != nil || pe != nil || p != proof || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) {
		f.Close()
		return nil, ErrChanged
	}
	if e = a.g.reserveEntry(f, true); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func (a *Area) Entry(id string) (*os.File, error) {
	if !validOpaqueID(id) {
		return nil, ErrSafety
	}
	f, e := nativeOpen(int(a.dir.Fd()), id, pathOnly, true)
	if e != nil {
		return nil, e
	}
	if e = a.g.checkPrivate(f); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func (a *Area) Trash(source Location, expected, id string) (*os.File, error) {
	if !validOpaqueID(id) || len(source.Components) == 0 {
		return nil, ErrSafety
	}
	// Private-area destinations are deliberately inaccessible to Guard.Open.
	parent, e := parentOf(source)
	if e != nil {
		return nil, e
	}
	p, e := a.g.Open(a.root, parent)
	if e != nil {
		return nil, e
	}
	defer p.Close()
	pd, e := a.g.Directory(p)
	if e != nil {
		return nil, e
	}
	defer pd.Close()
	f, e := a.g.Open(a.root, source)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	if e = a.g.CanRemove(f); e != nil {
		return nil, e
	}
	if e = requireVersion(f, expected); e != nil {
		return nil, e
	}
	name, e := rawLeaf(source)
	if e != nil {
		return nil, e
	}
	if e = renameEntry(pd, name, a.dir, id, false); e != nil {
		return nil, e
	}
	if pd.Sync() != nil || a.dir.Sync() != nil {
		return nil, ErrUncertain
	}
	out, e := a.Entry(id)
	if e != nil {
		return nil, ErrUncertain
	}
	if e = a.g.reserveEntry(out, true); e != nil {
		out.Close()
		return nil, ErrUncertain
	}
	return out, nil
}
func (a *Area) Restore(id, expected string, parent Location, name, parentVersion string, replace ...string) (*os.File, error) {
	if !validOpaqueID(id) {
		return nil, ErrSafety
	}
	if _, e := a.Scan(context.Background(), id, 9223372036854775807); e != nil {
		return nil, e
	}
	f, e := a.Entry(id)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	if e = requireVersion(f, expected); e != nil {
		return nil, e
	}
	replacing := len(replace) == 1 && replace[0] != ""
	if len(replace) > 1 {
		return nil, ErrSafety
	}
	if !replacing {
		if e = a.g.CheckCreate(a.root, parent, name, parentVersion); e != nil {
			return nil, e
		}
	}
	p, e := a.g.Open(a.root, parent)
	if e != nil {
		return nil, e
	}
	defer p.Close()
	pd, e := a.g.Directory(p)
	if e != nil {
		return nil, e
	}
	defer pd.Close()
	l, e := Child(parent, name)
	if e != nil {
		return nil, e
	}
	leaf, e := rawLeaf(l)
	if e != nil {
		return nil, e
	}
	if e = requireVersion(p, parentVersion); e != nil {
		return nil, e
	}
	if replacing {
		existing, e := a.g.Open(a.root, l)
		if e != nil {
			return nil, e
		}
		e = requireVersion(existing, replace[0])
		existing.Close()
		if e != nil {
			return nil, e
		}
	}
	if e = renameEntry(a.dir, id, pd, leaf, replacing); e != nil {
		return nil, e
	}
	if pd.Sync() != nil || a.dir.Sync() != nil {
		return nil, ErrUncertain
	}
	if e = a.releaseTree(f); e != nil {
		return nil, ErrUncertain
	}
	out, e := a.g.Open(a.root, l)
	if e != nil {
		return nil, ErrUncertain
	}
	return out, nil
}

// The destination is resolved independently from the private area's root.
// renameat2 refuses EXDEV before moving an entry; no copy-and-delete fallback.
func (a *Area) RestoreTo(root, id, expected string, parent Location, name, parentVersion string, replace ...string) (*os.File, error) {
	scoped := *a
	scoped.root = root
	return scoped.Restore(id, expected, parent, name, parentVersion, replace...)
}

// Publication is a single same-filesystem rename. Caller must have durably
// registered/preserved the previous version before asking for replacement.
func (a *Area) Publish(id string, staged *os.File, parent Location, name, parentVersion, replaceVersion string) (*os.File, error) {
	if !validOpaqueID(id) {
		return nil, ErrSafety
	}
	if e := a.g.checkPrivate(staged); e != nil {
		return nil, e
	}
	p, e := a.g.Open(a.root, parent)
	if e != nil {
		return nil, e
	}
	defer p.Close()
	pd, e := a.g.Directory(p)
	if e != nil {
		return nil, e
	}
	defer pd.Close()
	l, e := Child(parent, name)
	if e != nil {
		return nil, e
	}
	leaf, e := rawLeaf(l)
	if e != nil {
		return nil, e
	}
	if e = requireVersion(p, parentVersion); e != nil {
		return nil, e
	}
	mode := uint32(0600)
	if replaceVersion != "" {
		old, e := a.g.Open(a.root, l)
		if e != nil {
			return nil, e
		}
		st, se := metadata(old)
		e = requireVersion(old, replaceVersion)
		defer old.Close()
		if e != nil {
			return nil, e
		}
		if se != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Uid != uint32(os.Geteuid()) && os.Geteuid() != 0 {
			return nil, ErrPermission
		}
		if st.Mode&07000 != 0 {
			return nil, ErrSafety
		}
		if n, xe := syscall.Listxattr(fdPath(old), nil); xe != nil || n != 0 {
			return nil, ErrSafety
		}
		if e = staged.Chown(int(st.Uid), int(st.Gid)); e != nil {
			return nil, ErrPermission
		}
		mode = st.Mode & 0777
	}
	if e = staged.Chmod(os.FileMode(mode)); e != nil {
		return nil, classifyMutation(e)
	}
	if staged.Sync() != nil {
		return nil, ErrUncertain
	}
	if e = renameEntry(a.dir, id, pd, leaf, replaceVersion != ""); e != nil {
		return nil, e
	}
	if pd.Sync() != nil || a.dir.Sync() != nil {
		return nil, ErrUncertain
	}
	if e = a.g.reserveEntry(staged, false); e != nil {
		return nil, ErrUncertain
	}
	out, e := a.g.Open(a.root, l)
	if e != nil {
		return nil, ErrUncertain
	}
	return out, nil
}
func (a *Area) CopyFile(ctx context.Context, source *os.File, id string, limit int64) (*os.File, int64, error) {
	st, e := source.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() < 0 || st.Size() > limit {
		return nil, 0, ErrLimit
	}
	if mode, uid, gid, _, _, se := StatFields(source); se != nil || mode&07000 != 0 || (uid != uint32(os.Geteuid()) && os.Geteuid() != 0) {
		return nil, 0, ErrPermission
	} else {
		_ = gid
	}
	if n, xe := syscall.Listxattr(fdPath(source), nil); xe != nil || n != 0 {
		return nil, 0, ErrSafety
	}
	if e = a.Space(st.Size()); e != nil {
		return nil, 0, e
	}
	reader, e := a.g.ReadFile(source)
	if e != nil {
		return nil, 0, e
	}
	defer reader.Close()
	before, e := Version(source)
	if e != nil {
		return nil, 0, e
	}
	f, e := a.New(id)
	if e != nil {
		return nil, 0, e
	}
	buf := make([]byte, 65536)
	var total int64
	for {
		if ctx.Err() != nil {
			f.Close()
			return nil, total, ErrUncertain
		}
		n, re := reader.Read(buf)
		if n > 0 {
			if int64(n) > limit-total {
				f.Close()
				return nil, total, ErrUncertain
			}
			written, we := f.Write(buf[:n])
			total += int64(written)
			if we != nil || written != n {
				f.Close()
				return nil, total, ErrUncertain
			}
		}
		if re == io.EOF {
			break
		}
		if re != nil {
			f.Close()
			return nil, total, ErrUncertain
		}
	}
	after, e := Version(source)
	if e != nil || after != before || total != st.Size() {
		f.Close()
		return nil, total, ErrUncertain
	}
	if preserveMetadata(f, source) != nil {
		f.Close()
		return nil, total, ErrUncertain
	}
	if f.Sync() != nil {
		f.Close()
		return nil, total, ErrUncertain
	}
	f.Seek(0, 0)
	return f, total, nil
}
func (a *Area) Purge(ctx context.Context, id, expected string) error {
	if !validOpaqueID(id) {
		return ErrSafety
	}
	f, e := a.Entry(id)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = requireVersion(f, expected); e != nil {
		return e
	}
	if _, e = a.Scan(ctx, id, 9223372036854775807); e != nil {
		return e
	}
	count := 0
	var remove func(*os.File, string) error
	remove = func(parent *os.File, name string) error {
		if ctx.Err() != nil || count >= 10000 {
			return ErrLimit
		}
		count++
		entry, e := nativeOpen(int(parent.Fd()), name, pathOnly, true)
		if e != nil {
			return e
		}
		defer entry.Close()
		if e = a.g.checkPrivate(entry); e != nil {
			return e
		}
		st, e := metadata(entry)
		if e != nil {
			return e
		}
		if st.Mode&syscall.S_IFMT == syscall.S_IFDIR {
			d, e := nativeOpen(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY, true)
			if e != nil {
				return e
			}
			defer d.Close()
			names, e := d.Readdirnames(10001 - count)
			if e != nil && e != io.EOF {
				return e
			}
			if len(names) > 10000-count {
				return ErrLimit
			}
			for _, child := range names {
				if child == "." || child == ".." || strings.ContainsAny(child, "/\x00") {
					return ErrSafety
				}
				if e = remove(d, child); e != nil {
					return e
				}
			}
			if e = unlinkEntry(parent, name, true); e != nil {
				return e
			}
		} else {
			if e = unlinkEntry(parent, name, false); e != nil {
				return e
			}
		}
		a.g.reserveEntry(entry, false)
		return parent.Sync()
	}
	if e = remove(a.dir, id); e != nil {
		return ErrUncertain
	}
	return nil
}
func (a *Area) Location(rootID, id string) Location {
	return Location{RootID: rootID, Components: []string{base64.RawURLEncoding.EncodeToString([]byte(a.name)), base64.RawURLEncoding.EncodeToString([]byte(id))}}
}
func fdPath(f *os.File) string { return "/proc/self/fd/" + strconv.FormatUint(uint64(f.Fd()), 10) }

func (a *Area) Allocate(f *os.File, size int64) error {
	if e := a.Space(size); e != nil {
		return e
	}
	if size > 0 {
		if e := syscall.Fallocate(int(f.Fd()), 0, 0, size); e != nil {
			return classifyMutation(e)
		}
	}
	return nil
}

func (a *Area) Proof() (string, error) { return IdentityProof(a.dir) }
func (g *Guard) OpenArea(root, installation string) (*Area, error) {
	if !validOpaqueID(installation) {
		return nil, ErrSafety
	}
	r, e := g.MutationRoot(root)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	name := ".serverdeck-" + installation
	dir, e := nativeOpen(int(r.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY, true)
	if e != nil {
		return nil, e
	}
	st, e := metadata(dir)
	if e != nil || st.Mode&07777 != 0700 || st.Uid != uint32(os.Geteuid()) {
		dir.Close()
		return nil, ErrSafety
	}
	if e = g.reserveEntry(dir, true); e != nil {
		dir.Close()
		return nil, e
	}
	return &Area{dir, g, root, name}, nil
}
func (a *Area) ProtectTree(id, proof string) error {
	if !validOpaqueID(id) {
		return ErrSafety
	}
	entry, e := a.Entry(id)
	if e != nil {
		return e
	}
	actual, e := IdentityProof(entry)
	entry.Close()
	if e != nil || actual != proof {
		return ErrChanged
	}
	count := 0
	var protect func(*os.File, string) error
	protect = func(parent *os.File, name string) error {
		if count >= 10000 {
			return ErrLimit
		}
		count++
		f, e := nativeOpen(int(parent.Fd()), name, pathOnly, true)
		if e != nil {
			return e
		}
		defer f.Close()
		if e = a.g.checkPrivate(f); e != nil {
			return e
		}
		if e = a.g.reserveEntry(f, true); e != nil {
			return e
		}
		st, e := metadata(f)
		if e != nil {
			return e
		}
		if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
			return nil
		}
		d, e := nativeOpen(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY, true)
		if e != nil {
			return e
		}
		defer d.Close()
		names, e := d.Readdirnames(10001 - count)
		if e != nil && e != io.EOF {
			return e
		}
		if len(names) > 10000-count {
			return ErrLimit
		}
		for _, child := range names {
			if e = protect(d, child); e != nil {
				return e
			}
		}
		return nil
	}
	return protect(a.dir, id)
}

func (a *Area) releaseTree(f *os.File) error {
	count := 0
	var release func(*os.File) error
	release = func(f *os.File) error {
		if count >= 10000 {
			return ErrLimit
		}
		count++
		st, e := metadata(f)
		if e != nil {
			return e
		}
		if e = a.g.reserveEntry(f, false); e != nil {
			return e
		}
		if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
			return nil
		}
		d, e := nativeOpen(int(f.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY, true)
		if e != nil {
			return e
		}
		defer d.Close()
		names, e := d.Readdirnames(10001 - count)
		if e != nil && e != io.EOF {
			return e
		}
		if len(names) > 10000-count {
			return ErrLimit
		}
		for _, name := range names {
			child, e := nativeOpen(int(d.Fd()), name, pathOnly, true)
			if e != nil {
				return e
			}
			e = release(child)
			child.Close()
			if e != nil {
				return e
			}
		}
		return nil
	}
	return release(f)
}

func CheckReplacementMeta(f *os.File) error {
	mode, uid, _, _, _, e := StatFields(f)
	if e != nil || mode&syscall.S_IFMT != syscall.S_IFREG || mode&07000 != 0 {
		return ErrSafety
	}
	if uid != uint32(os.Geteuid()) && os.Geteuid() != 0 {
		return ErrPermission
	}
	n, e := syscall.Listxattr(fdPath(f), nil)
	if e != nil || n != 0 {
		return ErrSafety
	}
	return nil
}
