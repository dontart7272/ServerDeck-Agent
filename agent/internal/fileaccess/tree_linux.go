//go:build linux && cgo

// SPDX-License-Identifier: Apache-2.0
package fileaccess

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"syscall"
)

type TreeInfo struct {
	Bytes  int64
	Digest string
	Nodes  int
	Kind   string
}

func scanTree(ctx context.Context, f *os.File, limit int64, guard *Guard, private ...bool) (TreeInfo, error) {
	out := TreeInfo{}
	hash := sha256.New()
	var walk func(*os.File, int) error
	walk = func(f *os.File, depth int) error {
		if ctx.Err() != nil || out.Nodes >= 10000 || depth > 256 {
			return ErrLimit
		}
		out.Nodes++
		if guard != nil {
			var e error
			if len(private) > 0 && private[0] {
				e = guard.checkPrivate(f)
			} else {
				e = guard.checkLocked(f)
			}
			if e != nil {
				return e
			}
		}
		st, e := metadata(f)
		if e != nil {
			return e
		}
		v, e := Version(f)
		if e != nil {
			return e
		}
		fmt.Fprintf(hash, "%s;", v)
		switch st.Mode & syscall.S_IFMT {
		case syscall.S_IFREG:
			if st.Nlink != 1 || st.Size < 0 {
				return ErrSafety
			}
			if st.Size > limit-out.Bytes {
				return ErrLimit
			}
			out.Bytes += st.Size
			if depth == 0 {
				out.Kind = "file"
			}
		case syscall.S_IFLNK:
			if st.Size < 0 || st.Size > limit-out.Bytes {
				return ErrLimit
			}
			out.Bytes += st.Size
			if depth == 0 {
				out.Kind = "symlink"
			}
		case syscall.S_IFDIR:
			if depth == 0 {
				out.Kind = "directory"
			}
			d, e := nativeOpen(int(f.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY, true)
			if e != nil {
				return e
			}
			defer d.Close()
			names, e := d.Readdirnames(10001 - out.Nodes)
			if e != nil && e != io.EOF {
				return ErrSource
			}
			if len(names) > 10000-out.Nodes {
				return ErrLimit
			}
			sort.Strings(names)
			for _, name := range names {
				fmt.Fprintf(hash, "%d:%s;", len(name), name)
				child, e := nativeOpen(int(d.Fd()), name, pathOnly, true)
				if e != nil {
					return e
				}
				e = walk(child, depth+1)
				child.Close()
				if e != nil {
					return e
				}
			}
		default:
			return ErrSafety
		}
		return nil
	}
	if e := walk(f, 0); e != nil {
		return out, e
	}
	out.Digest = hex.EncodeToString(hash.Sum(nil))
	return out, nil
}
func (g *Guard) checkPrivate(f *os.File) error {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.closed {
		return ErrSafety
	}
	return g.checkEntry(f, false)
}
func (g *Guard) checkLocked(f *os.File) error {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.closed {
		return ErrSafety
	}
	return g.check(f)
}
func (g *Guard) Scan(ctx context.Context, root string, location Location, limit int64) (TreeInfo, error) {
	f, e := g.Open(root, location)
	if e != nil {
		return TreeInfo{}, e
	}
	defer f.Close()
	return scanTree(ctx, f, limit, g)
}
func (a *Area) Scan(ctx context.Context, id string, limit int64) (TreeInfo, error) {
	f, e := a.Entry(id)
	if e != nil {
		return TreeInfo{}, e
	}
	defer f.Close()
	return scanTree(ctx, f, limit, a.g, true)
}
func FilesystemDevice(f *os.File) (string, error) {
	st, e := metadata(f)
	if e != nil {
		return "", e
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil || len(boot) > 128 {
		return "", ErrSafety
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", boot, st.Dev)))
	return hex.EncodeToString(sum[:]), nil
}
