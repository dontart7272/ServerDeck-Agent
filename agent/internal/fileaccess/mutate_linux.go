//go:build linux && cgo

// SPDX-License-Identifier: Apache-2.0
package fileaccess

/*
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/syscall.h>
#include <linux/fs.h>
#include <errno.h>
#include <stdlib.h>
static int sd_times(int fd,long long as,long an,long long ms,long mn){struct timespec t[2]={{.tv_sec=as,.tv_nsec=an},{.tv_sec=ms,.tv_nsec=mn}};int r=futimens(fd,t);return r<0?-errno:0;}
static int sd_link_times(int fd,const char *name,long long as,long an,long long ms,long mn){struct timespec t[2]={{.tv_sec=as,.tv_nsec=an},{.tv_sec=ms,.tv_nsec=mn}};int r=utimensat(fd,name,t,AT_SYMLINK_NOFOLLOW);return r<0?-errno:0;}
static int sd_unlink(int dir,const char *name,int flags){int r=unlinkat(dir,name,flags);return r<0?-errno:0;}
static int sd_rename(int oldfd,const char *oldname,int newfd,const char *newname,int replace){int r=syscall(SYS_renameat2,oldfd,oldname,newfd,newname,replace?0:RENAME_NOREPLACE);return r<0?-errno:0;}
*/
import "C"
import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Mutation failures after the first changed directory entry must not be retried
// as though no effect happened, including failed fsync or result reopening.

// The legacy profile requires a whole-filesystem root. Shared roots use the
// accepted descriptor-bound maintenance model; lexical containment after an
// external directory rename is deliberately not a promised invariant.
func (g *Guard) MutationRoot(path string) (*os.File, error) {
	f, e := g.Open(path, Location{RootID: "native", Components: []string{}})
	if e != nil {
		return nil, e
	}
	g.mu.RLock()
	shared := g.shared
	g.mu.RUnlock()
	if shared {
		return f, nil
	}
	fail := func() (*os.File, error) { f.Close(); return nil, ErrSafety }
	fdinfo, e := os.ReadFile("/proc/self/fdinfo/" + strconv.FormatUint(uint64(f.Fd()), 10))
	if e != nil || len(fdinfo) > 4096 {
		return fail()
	}
	id := ""
	for _, line := range strings.Split(string(fdinfo), "\n") {
		x := strings.Fields(line)
		if len(x) == 2 && x[0] == "mnt_id:" {
			id = x[1]
		}
	}
	m, e := os.Open("/proc/self/mountinfo")
	if e != nil {
		return fail()
	}
	b, e := io.ReadAll(io.LimitReader(m, 1000001))
	m.Close()
	if e != nil || len(b) > 1000000 {
		return fail()
	}
	actual, e := os.Readlink("/proc/self/fd/" + strconv.FormatUint(uint64(f.Fd()), 10))
	if e != nil {
		return fail()
	}
	decode := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	for _, line := range strings.Split(string(b), "\n") {
		x := strings.Fields(line)
		if len(x) > 5 && x[0] == id && x[3] == "/" && decode.Replace(x[4]) == actual {
			return f, nil
		}
	}
	return fail()
}
func Child(parent Location, name string) (Location, error) {
	p := Location{RootID: parent.RootID, Components: append(append([]string{}, parent.Components...), name)}
	if e := p.Validate(); e != nil {
		return Location{}, e
	}
	return p, nil
}
func rawLeaf(l Location) (string, error) {
	parts, e := l.Decoded()
	if e != nil || len(parts) == 0 {
		return "", ErrSafety
	}
	return parts[len(parts)-1], nil
}
func parentOf(l Location) (Location, error) {
	if e := l.Validate(); e != nil || len(l.Components) == 0 {
		return Location{}, ErrSafety
	}
	return Location{RootID: l.RootID, Components: append([]string{}, l.Components[:len(l.Components)-1]...)}, nil
}
func requireVersion(f *os.File, want string) error {
	v, e := Version(f)
	if e != nil {
		return e
	}
	if v != want {
		return ErrChanged
	}
	return nil
}

func (g *Guard) CheckCreate(root string, parent Location, name, expected string) error {
	r, e := g.MutationRoot(root)
	if e != nil {
		return e
	}
	r.Close()
	l, e := Child(parent, name)
	if e != nil {
		return e
	}
	p, e := g.Open(root, parent)
	if e != nil {
		return e
	}
	defer p.Close()
	info, e := p.Stat()
	if e != nil || !info.IsDir() {
		return ErrSafety
	}
	if e = requireVersion(p, expected); e != nil {
		return e
	}
	existing, e := g.Open(root, l)
	if e == nil {
		existing.Close()
		return ErrChanged
	}
	if !errors.Is(e, ErrMissing) {
		return e
	}
	return nil
}
func (g *Guard) Create(root string, parent Location, name, expected, kind string) (*os.File, error) {
	if kind != "file" && kind != "directory" {
		return nil, ErrSafety
	}
	if e := g.CheckCreate(root, parent, name, expected); e != nil {
		return nil, e
	}
	p, e := g.Open(root, parent)
	if e != nil {
		return nil, e
	}
	defer p.Close()
	dir, e := g.Directory(p)
	if e != nil {
		return nil, e
	}
	defer dir.Close()
	l, e := Child(parent, name)
	if e != nil {
		return nil, e
	}
	leaf, e := rawLeaf(l)
	if e != nil {
		return nil, e
	}
	// Recheck the checked directory immediately before publication.
	if e = requireVersion(p, expected); e != nil {
		return nil, e
	}
	if kind == "directory" {
		if e = syscall.Mkdirat(int(dir.Fd()), leaf, 0700); e != nil {
			return nil, classifyMutation(e)
		}
		created, err := nativeOpen(int(dir.Fd()), leaf, syscall.O_RDONLY|syscall.O_DIRECTORY, true)
		if err != nil {
			return nil, ErrUncertain
		}
		err = created.Sync()
		closeErr := created.Close()
		if err != nil || closeErr != nil {
			return nil, ErrUncertain
		}
	} else {
		fd, e := syscall.Openat(int(dir.Fd()), leaf, syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_WRONLY|syscall.O_CLOEXEC, 0600)
		if e != nil {
			return nil, classifyMutation(e)
		}
		f := os.NewFile(uintptr(fd), "created")
		e = f.Sync()
		ce := f.Close()
		if e != nil || ce != nil {
			return nil, ErrUncertain
		}
	}
	if e = dir.Sync(); e != nil {
		return nil, ErrUncertain
	}
	f, e := g.Open(root, l)
	if e != nil {
		return nil, ErrUncertain
	}
	return f, nil
}
func classifyMutation(e error) error {
	if errors.Is(e, syscall.EEXIST) || errors.Is(e, syscall.ENOTEMPTY) {
		return ErrChanged
	}
	if errors.Is(e, syscall.ENOSPC) || errors.Is(e, syscall.EDQUOT) {
		return ErrSpace
	}
	return classify(e)
}
func (g *Guard) CheckRename(root string, source Location, expected string, target Location, name, parentVersion string) error {
	return g.CheckRenameAcross(root, root, source, expected, target, name, parentVersion)
}
func (g *Guard) CheckRenameAcross(sourceRoot, targetRoot string, source Location, expected string, target Location, name, parentVersion string) error {
	r, e := g.MutationRoot(sourceRoot)
	if e != nil {
		return e
	}
	r.Close()
	if len(source.Components) == 0 {
		return ErrProtected
	}
	f, e := g.Open(sourceRoot, source)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = g.CanRemove(f); e != nil {
		return e
	}
	info, e := f.Stat()
	if e != nil {
		return e
	}
	if info.IsDir() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, e = g.Scan(ctx, sourceRoot, source, 9223372036854775807); e != nil {
			return e
		}
	}
	if e = requireVersion(f, expected); e != nil {
		return e
	}
	return g.CheckCreate(targetRoot, target, name, parentVersion)
}
func (g *Guard) Rename(root string, source Location, expected string, target Location, name, parentVersion string) (*os.File, error) {
	return g.RenameAcross(root, root, source, expected, target, name, parentVersion)
}
func (g *Guard) RenameAcross(sourceRoot, targetRoot string, source Location, expected string, target Location, name, parentVersion string) (*os.File, error) {
	if e := g.CheckRenameAcross(sourceRoot, targetRoot, source, expected, target, name, parentVersion); e != nil {
		return nil, e
	}
	sourceParent, e := parentOf(source)
	if e != nil {
		return nil, e
	}
	sp, e := g.Open(sourceRoot, sourceParent)
	if e != nil {
		return nil, e
	}
	defer sp.Close()
	tp, e := g.Open(targetRoot, target)
	if e != nil {
		return nil, e
	}
	defer tp.Close()
	sd, e := g.Directory(sp)
	if e != nil {
		return nil, e
	}
	defer sd.Close()
	td, e := g.Directory(tp)
	if e != nil {
		return nil, e
	}
	defer td.Close()
	from, e := rawLeaf(source)
	if e != nil {
		return nil, e
	}
	dst, e := Child(target, name)
	if e != nil {
		return nil, e
	}
	to, e := rawLeaf(dst)
	if e != nil {
		return nil, e
	}
	// Reopen current object immediately before publication, not the old Check FD.
	current, e := g.Open(sourceRoot, source)
	if e != nil {
		return nil, e
	}
	e = g.CanRemove(current)
	if e == nil {
		e = requireVersion(current, expected)
	}
	current.Close()
	if e != nil {
		return nil, e
	}
	if e = requireVersion(tp, parentVersion); e != nil {
		return nil, e
	}
	a, b := C.CString(from), C.CString(to)
	defer C.free(unsafe.Pointer(a))
	defer C.free(unsafe.Pointer(b))
	result := int(C.sd_rename(C.int(sd.Fd()), a, C.int(td.Fd()), b, 0))
	if result < 0 {
		return nil, classifyMutation(syscall.Errno(-result))
	}
	if sd.Sync() != nil || td.Sync() != nil {
		return nil, ErrUncertain
	}
	out, e := g.Open(targetRoot, dst)
	if e != nil {
		return nil, ErrUncertain
	}
	return out, nil
}

func renameEntry(from *os.File, name string, to *os.File, target string, replace bool) error {
	a, b := C.CString(name), C.CString(target)
	defer C.free(unsafe.Pointer(a))
	defer C.free(unsafe.Pointer(b))
	flag := 0
	if replace {
		flag = 1
	}
	result := int(C.sd_rename(C.int(from.Fd()), a, C.int(to.Fd()), b, C.int(flag)))
	if result < 0 {
		return classifyMutation(syscall.Errno(-result))
	}
	return nil
}

func unlinkEntry(dir *os.File, name string, directory bool) error {
	c := C.CString(name)
	defer C.free(unsafe.Pointer(c))
	flags := 0
	if directory {
		flags = 0x200
	}
	r := int(C.sd_unlink(C.int(dir.Fd()), c, C.int(flags)))
	if r < 0 {
		return classifyMutation(syscall.Errno(-r))
	}
	return nil
}

func preserveMetadata(out, source *os.File) error {
	st, e := metadata(source)
	if e != nil {
		return e
	}
	if e = out.Chown(int(st.Uid), int(st.Gid)); e != nil {
		return ErrPermission
	}
	if e = out.Chmod(os.FileMode(st.Mode & 0777)); e != nil {
		return ErrPermission
	}
	r := int(C.sd_times(C.int(out.Fd()), C.longlong(st.Atim.Sec), C.long(st.Atim.Nsec), C.longlong(st.Mtim.Sec), C.long(st.Mtim.Nsec)))
	if r < 0 {
		return classifyMutation(syscall.Errno(-r))
	}
	return nil
}
func preserveLinkMetadata(parent *os.File, name string, source *os.File) error {
	st, e := metadata(source)
	if e != nil {
		return e
	}
	if e = syscall.Fchownat(int(parent.Fd()), name, int(st.Uid), int(st.Gid), 0x100); e != nil {
		return ErrPermission
	}
	c := C.CString(name)
	defer C.free(unsafe.Pointer(c))
	r := int(C.sd_link_times(C.int(parent.Fd()), c, C.longlong(st.Atim.Sec), C.long(st.Atim.Nsec), C.longlong(st.Mtim.Sec), C.long(st.Mtim.Nsec)))
	if r < 0 {
		return classifyMutation(syscall.Errno(-r))
	}
	return nil
}
