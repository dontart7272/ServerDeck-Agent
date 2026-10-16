//go:build linux && cgo

// SPDX-License-Identifier: Apache-2.0
package fileaccess

/*
#define _GNU_SOURCE
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/xattr.h>
static int sd_link_text(int fd,char *buf,int max){int r=readlinkat(fd,"",buf,max);return r<0?-errno:r;}
static int sd_make_link(int parent,const char *name,const char *target){int r=symlinkat(target,parent,name);return r<0?-errno:0;}
static int sd_link_xattrs(const char *path){int r=llistxattr(path,NULL,0);return r<0?-errno:r;}
*/
import "C"
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"
	"unsafe"
)

func readLink(f *os.File) (string, error) {
	b := make([]byte, 4097)
	n := int(C.sd_link_text(C.int(f.Fd()), (*C.char)(unsafe.Pointer(&b[0])), C.int(len(b))))
	if n < 0 {
		return "", classifyMutation(syscall.Errno(-n))
	}
	if n > 4096 {
		return "", ErrLimit
	}
	return string(b[:n]), nil
}
func checkLinkMetadata(f *os.File) error {
	before, e := Version(f)
	if e != nil {
		return e
	}
	path, e := os.Readlink(fdPath(f))
	if e != nil || strings.HasSuffix(path, " (deleted)") {
		return ErrSafety
	}
	current, e := PinAbsolute(path)
	if e != nil {
		return ErrSafety
	}
	v, e := Version(current)
	current.Close()
	if e != nil || v != before {
		return ErrChanged
	}
	name := C.CString(path)
	n := int(C.sd_link_xattrs(name))
	C.free(unsafe.Pointer(name))
	if n != 0 {
		return ErrSafety
	}
	current, e = PinAbsolute(path)
	if e != nil {
		return ErrChanged
	}
	v, e = Version(current)
	current.Close()
	after, ae := Version(f)
	if e != nil || ae != nil || v != before || after != before {
		return ErrChanged
	}
	return nil
}
func (a *Area) CopyObject(ctx context.Context, source *os.File, id string, limit int64) (*os.File, error) {
	return a.copyObject(ctx, source, id, limit, false)
}
func (a *Area) CopyPrivateTo(ctx context.Context, id, proof string, target *Area, targetID string, limit int64) (*os.File, error) {
	f, e := a.Entry(id)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	actual, e := IdentityProof(f)
	if e != nil || actual != proof {
		return nil, ErrChanged
	}
	return target.copyObject(ctx, f, targetID, limit, true)
}
func (a *Area) copyObject(ctx context.Context, source *os.File, id string, limit int64, private bool) (*os.File, error) {
	if !validOpaqueID(id) {
		return nil, ErrSafety
	}
	count := 0
	left := limit
	var copy func(*os.File, *os.File, string, int) (*os.File, error)
	copy = func(source, parent *os.File, name string, depth int) (*os.File, error) {
		if ctx.Err() != nil || count >= 10000 || depth > 256 {
			return nil, ErrLimit
		}
		count++
		a.g.mu.RLock()
		e := a.g.checkEntry(source, !private)
		if a.g.closed {
			e = ErrSafety
		}
		a.g.mu.RUnlock()
		if e != nil {
			return nil, e
		}
		st, e := metadata(source)
		if e != nil {
			return nil, e
		}
		switch st.Mode & syscall.S_IFMT {
		case syscall.S_IFREG:
			if st.Size < 0 || st.Size > left || st.Nlink != 1 {
				return nil, ErrLimit
			}
			if e = CheckReplacementMeta(source); e != nil {
				return nil, e
			}
			if e = a.Space(st.Size); e != nil {
				return nil, e
			}
			fd, e := syscall.Openat(int(parent.Fd()), name, syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_RDWR|syscall.O_CLOEXEC, 0600)
			if e != nil {
				return nil, classifyMutation(e)
			}
			out := os.NewFile(uintptr(fd), "copy")
			if e = a.g.reserveEntry(out, true); e != nil {
				out.Close()
				return nil, e
			}
			in, e := readDescriptor(source)
			if e != nil {
				out.Close()
				return nil, e
			}
			defer in.Close()
			before, e := Version(source)
			if e != nil {
				out.Close()
				return nil, e
			}
			buffer := make([]byte, 65536)
			var copied int64
			for {
				if ctx.Err() != nil {
					out.Close()
					return nil, ErrUncertain
				}
				n, re := in.Read(buffer)
				if n > 0 {
					if int64(n) > left-copied {
						out.Close()
						return nil, ErrLimit
					}
					wn, we := out.Write(buffer[:n])
					copied += int64(wn)
					if we != nil || wn != n {
						out.Close()
						return nil, ErrUncertain
					}
				}
				if re == io.EOF {
					break
				}
				if re != nil {
					out.Close()
					return nil, ErrUncertain
				}
			}
			after, e := Version(source)
			if e != nil || after != before || copied != st.Size {
				out.Close()
				return nil, ErrChanged
			}
			left -= copied
			if preserveMetadata(out, source) != nil || out.Sync() != nil {
				out.Close()
				return nil, ErrUncertain
			}
			return out, nil
		case syscall.S_IFDIR:
			if st.Mode&07000 != 0 {
				return nil, ErrSafety
			}
			if n, e := syscall.Listxattr(fdPath(source), nil); e != nil || n != 0 {
				return nil, ErrSafety
			}
			if e = syscall.Mkdirat(int(parent.Fd()), name, 0700); e != nil {
				return nil, classifyMutation(e)
			}
			out, e := nativeOpen(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY, true)
			if e != nil {
				return nil, e
			}
			if e = a.g.reserveEntry(out, true); e != nil {
				out.Close()
				return nil, e
			}
			in, e := nativeOpen(int(source.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY, true)
			if e != nil {
				out.Close()
				return nil, e
			}
			defer in.Close()
			names, e := in.Readdirnames(10001 - count)
			if e != nil && e != io.EOF {
				out.Close()
				return nil, e
			}
			if len(names) > 10000-count {
				out.Close()
				return nil, ErrLimit
			}
			sort.Strings(names)
			for _, child := range names {
				f, e := nativeOpen(int(in.Fd()), child, pathOnly, true)
				if e != nil {
					out.Close()
					return nil, e
				}
				c, e := copy(f, out, child, depth+1)
				f.Close()
				if e != nil {
					out.Close()
					return nil, e
				}
				c.Close()
			}
			if preserveMetadata(out, source) != nil || out.Sync() != nil {
				out.Close()
				return nil, ErrUncertain
			}
			return out, nil
		case syscall.S_IFLNK:
			if e := checkLinkMetadata(source); e != nil {
				return nil, e
			}
			target, e := readLink(source)
			if e != nil {
				return nil, e
			}
			if int64(len(target)) > left {
				return nil, ErrLimit
			}
			left -= int64(len(target))
			cn, ct := C.CString(name), C.CString(target)
			r := int(C.sd_make_link(C.int(parent.Fd()), cn, ct))
			C.free(unsafe.Pointer(cn))
			C.free(unsafe.Pointer(ct))
			if r < 0 {
				return nil, classifyMutation(syscall.Errno(-r))
			}
			if e = preserveLinkMetadata(parent, name, source); e != nil {
				return nil, e
			}
			out, e := nativeOpen(int(parent.Fd()), name, pathOnly, true)
			if e != nil {
				return nil, e
			}
			if e = a.g.reserveEntry(out, true); e != nil {
				out.Close()
				return nil, e
			}
			return out, nil
		default:
			return nil, ErrSafety
		}
	}
	out, e := copy(source, a.dir, id, 0)
	if e != nil {
		return nil, e
	}
	if a.dir.Sync() != nil {
		out.Close()
		return nil, ErrUncertain
	}
	return out, nil
}
func payloadDigest(ctx context.Context, f *os.File, limit int64, guard *Guard) (string, error) {
	hash := sha256.New()
	left := limit
	nodes := 0
	var walk func(*os.File, int) error
	walk = func(f *os.File, depth int) error {
		if ctx.Err() != nil || nodes >= 10000 {
			return ErrLimit
		}
		nodes++
		if guard != nil {
			if e := guard.checkLocked(f); e != nil {
				return e
			}
		}
		st, e := metadata(f)
		if e != nil {
			return e
		}
		switch st.Mode & syscall.S_IFMT {
		case syscall.S_IFREG:
			if st.Size < 0 || st.Size > left || st.Nlink != 1 {
				return ErrLimit
			}
			before, e := Version(f)
			if e != nil {
				return e
			}
			in, e := readDescriptor(f)
			if e != nil {
				return e
			}
			defer in.Close()
			child := sha256.New()
			buffer := make([]byte, 65536)
			var size int64
			for {
				if ctx.Err() != nil {
					return ErrLimit
				}
				n, re := in.Read(buffer)
				if n > 0 {
					if int64(n) > left-size {
						return ErrLimit
					}
					size += int64(n)
					child.Write(buffer[:n])
				}
				if re == io.EOF {
					break
				}
				if re != nil {
					return ErrSource
				}
			}
			after, e := Version(f)
			if e != nil || after != before || size != st.Size {
				return ErrChanged
			}
			left -= size
			fmt.Fprintf(hash, "f:%d:%x;", size, child.Sum(nil))
		case syscall.S_IFLNK:
			target, e := readLink(f)
			if e != nil {
				return e
			}
			if int64(len(target)) > left {
				return ErrLimit
			}
			left -= int64(len(target))
			fmt.Fprintf(hash, "l:%d:", len(target))
			hash.Write([]byte(target))
		case syscall.S_IFDIR:
			d, e := nativeOpen(int(f.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY, true)
			if e != nil {
				return e
			}
			defer d.Close()
			names, e := d.Readdirnames(10001 - nodes)
			if e != nil && e != io.EOF {
				return e
			}
			if len(names) > 10000-nodes {
				return ErrLimit
			}
			sort.Strings(names)
			fmt.Fprintf(hash, "d:%d;", len(names))
			for _, name := range names {
				fmt.Fprintf(hash, "n:%d:", len(name))
				hash.Write([]byte(name))
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
		return "", e
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
func (g *Guard) PayloadDigest(ctx context.Context, root string, l Location, limit int64) (string, error) {
	f, e := g.Open(root, l)
	if e != nil {
		return "", e
	}
	defer f.Close()
	return payloadDigest(ctx, f, limit, g)
}
func (a *Area) PayloadDigest(ctx context.Context, id string, limit int64) (string, error) {
	f, e := a.Entry(id)
	if e != nil {
		return "", e
	}
	defer f.Close()
	return payloadDigest(ctx, f, limit, nil)
}
