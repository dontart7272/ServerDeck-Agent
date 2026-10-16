//go:build linux && cgo

// SPDX-License-Identifier: Apache-2.0
package fileaccess

/*
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/openat2.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
static int sd_open(int parent,const char *path,int flags,int xdev) {
 struct open_how h={.flags=flags|O_CLOEXEC|O_NOFOLLOW,.resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|(xdev?RESOLVE_NO_XDEV:0)};
 int r=syscall(SYS_openat2,parent,path,&h,sizeof(h));return r<0?-errno:r;
}
static int sd_read(int fd){char path[64];snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);int r=open(path,O_RDONLY|O_NONBLOCK|O_CLOEXEC);return r<0?-errno:r;}
static int sd_access(int fd,int mode){int r=syscall(SYS_faccessat2,fd,"",mode,AT_EMPTY_PATH|AT_EACCESS);return r<0?-errno:0;}
*/
import "C"
import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const pathOnly = 0x200000

func AvailableBytes(f *os.File) (int64, error) {
	var fs syscall.Statfs_t
	if syscall.Fstatfs(int(f.Fd()), &fs) != nil || fs.Bsize <= 0 || fs.Bavail > uint64((int64(^uint64(0)>>1))/fs.Bsize) {
		return 0, ErrSafety
	}
	return int64(fs.Bavail) * fs.Bsize, nil
}

func Access(f *os.File, mode int) error {
	if f == nil || mode < 0 || mode > 7 {
		return ErrSafety
	}
	r := int(C.sd_access(C.int(f.Fd()), C.int(mode)))
	if r < 0 {
		return classify(syscall.Errno(-r))
	}
	return nil
}

// Identity deliberately excludes pathname and mount ID: aliases on the same inode remain protected.
type identity struct{ dev, ino uint64 }
type ownedBinding struct {
	fd   *os.File
	path string
}
type Guard struct {
	privateLimit  int
	shared        bool
	ancestors     map[identity]bool
	bindings      []ownedBinding
	reservedNames map[string]bool
	mu            sync.RWMutex
	pins          []*os.File
	denied        map[identity]bool
	protectedFS   map[uint64]bool
	reserved      map[identity]bool
	closed        bool
}

func New(pins []*os.File) (*Guard, error) {
	if len(pins) == 0 {
		return nil, ErrSafety
	}
	g := &Guard{privateLimit: 65536, ancestors: map[identity]bool{}, reservedNames: map[string]bool{}, denied: map[identity]bool{}, protectedFS: map[uint64]bool{}, reserved: map[identity]bool{}}
	for _, f := range pins {
		if e := g.Protect(f); e != nil {
			g.Close()
			return nil, e
		}
	}
	return g, nil
}
func (g *Guard) Protect(f *os.File) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || f == nil {
		return ErrSafety
	}
	fd, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_DUPFD_CLOEXEC, 0)
	if errno != 0 {
		return ErrSafety
	}
	copy := os.NewFile(fd, "protected")
	var st syscall.Stat_t
	if syscall.Fstat(int(fd), &st) != nil {
		copy.Close()
		return ErrSafety
	}
	if g.denied[identity{uint64(st.Dev), st.Ino}] {
		copy.Close()
		return nil
	}
	if len(g.pins) >= 128 {
		copy.Close()
		return ErrSafety
	}
	path, e := os.Readlink("/proc/self/fd/" + strconv.FormatUint(uint64(copy.Fd()), 10))
	if e != nil || !filepath.IsAbs(path) || strings.HasSuffix(path, " (deleted)") {
		copy.Close()
		return ErrSafety
	}
	if e = g.addAncestorsLocked(copy, path, st.Mode&syscall.S_IFMT == syscall.S_IFDIR); e != nil {
		copy.Close()
		return e
	}
	g.bindings = append(g.bindings, ownedBinding{copy, path})
	g.protectedFS[uint64(st.Dev)] = true
	g.pins = append(g.pins, copy)
	g.denied[identity{uint64(st.Dev), st.Ino}] = true
	return nil
}
func (g *Guard) Close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.closed {
		g.closed = true
		for _, f := range g.pins {
			f.Close()
		}
		g.pins = nil
	}
}
func nativeOpen(parent int, path string, flags int, xdev bool) (*os.File, error) {
	c := C.CString(path)
	defer C.free(unsafe.Pointer(c))
	cross := 0
	if xdev {
		cross = 1
	}
	fd := int(C.sd_open(C.int(parent), c, C.int(flags), C.int(cross)))
	if fd < 0 {
		return nil, classify(syscall.Errno(-fd))
	}
	return os.NewFile(uintptr(fd), "fileaccess"), nil
}
func PinAbsolute(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || strings.ContainsRune(path, 0) {
		return nil, ErrSafety
	}
	base, e := os.Open("/")
	if e != nil {
		return nil, ErrSafety
	}
	defer base.Close()
	rel := strings.TrimPrefix(path, "/")
	if rel == "" {
		rel = "."
	}
	return nativeOpen(int(base.Fd()), rel, pathOnly, false)
}
func classify(e error) error {
	switch {
	case errors.Is(e, syscall.EACCES) || errors.Is(e, syscall.EPERM):
		return ErrPermission
	case errors.Is(e, syscall.ENOENT):
		return ErrMissing
	default:
		return ErrSafety
	}
}
func metadata(f *os.File) (syscall.Stat_t, error) {
	var st syscall.Stat_t
	if syscall.Fstat(int(f.Fd()), &st) != nil {
		return st, ErrSafety
	}
	return st, nil
}
func (g *Guard) check(f *os.File) error {
	return g.checkEntry(f, true)
}
func (g *Guard) checkEntry(f *os.File, reserved bool) error {
	st, e := metadata(f)
	if e != nil {
		return e
	}
	if g.denied[identity{uint64(st.Dev), st.Ino}] || (reserved && g.reserved[identity{uint64(st.Dev), st.Ino}]) {
		return ErrProtected
	}
	if !g.shared && g.protectedFS[uint64(st.Dev)] {
		return ErrSafety
	}
	var fs syscall.Statfs_t
	if syscall.Fstatfs(int(f.Fd()), &fs) != nil {
		return ErrSafety
	}
	// Deliberate local-filesystem profile; virtual/remote/unknown filesystems are not content sources.
	switch uint64(fs.Type) {
	case 0xef53, 0x01021994, 0x58465342, 0x9123683e:
	default:
		return ErrSafety
	}
	if st.Mode&syscall.S_IFMT == syscall.S_IFREG && st.Nlink != 1 {
		return ErrSafety
	}
	return nil
}

// Open checks each directory identity, then resolves the complete name from the
// pinned root again. No read is authorized by a lexical prefix or an old parent FD.
func (g *Guard) Open(rootPath string, l Location) (*os.File, error) {
	if e := l.Validate(); e != nil {
		return nil, e
	}
	decoded, _ := l.Decoded()
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.closed {
		return nil, ErrSafety
	}
	for _, part := range decoded {
		if g.reservedNames[part] {
			return nil, ErrProtected
		}
	}
	root, e := PinAbsolute(rootPath)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	st, e := metadata(root)
	if e != nil || st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return nil, ErrSafety
	}
	if e = g.check(root); e != nil {
		return nil, e
	}
	if e = wholeFilesystemMount(root); e != nil {
		return nil, e
	}
	if e = g.rootAllowed(root); e != nil {
		return nil, e
	}
	for i := range decoded {
		f, e := nativeOpen(int(root.Fd()), strings.Join(decoded[:i+1], "/"), pathOnly, true)
		if e != nil {
			return nil, e
		}
		e = g.check(f)
		f.Close()
		if e != nil {
			return nil, e
		}
	}
	rel := strings.Join(decoded, "/")
	if rel == "" {
		rel = "."
	}
	f, e := nativeOpen(int(root.Fd()), rel, pathOnly, true)
	if e != nil {
		return nil, e
	}
	if e = g.check(f); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}

// A configured root can itself be below a protected directory. Checking only
// its inode and its relative children would let a nested root bypass that fence.
// Caller holds g.mu.RLock; '..' is a trusted, bounded ancestor walk.
func (g *Guard) rootAllowed(root *os.File) error {
	fd, _, errno := syscall.Syscall(syscall.SYS_FCNTL, root.Fd(), syscall.F_DUPFD_CLOEXEC, 0)
	if errno != 0 {
		return ErrSafety
	}
	current := os.NewFile(fd, "root-ancestor")
	defer func() { current.Close() }()
	for i := 0; i < 256; i++ {
		st, e := metadata(current)
		if e != nil {
			return e
		}
		if g.denied[identity{uint64(st.Dev), st.Ino}] || g.reserved[identity{uint64(st.Dev), st.Ino}] {
			return ErrProtected
		}
		parentFD, e := syscall.Openat(int(current.Fd()), "..", pathOnly|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if e != nil {
			return classify(e)
		}
		parent := os.NewFile(uintptr(parentFD), "root-parent")
		pst, e := metadata(parent)
		if e != nil {
			parent.Close()
			return e
		}
		if pst.Dev == st.Dev && pst.Ino == st.Ino {
			parent.Close()
			return nil
		}
		current.Close()
		current = parent
	}
	return ErrLimit
}

// Subtree bind mounts cannot establish ancestry of their root from a dentry FD.
// Reject them rather than infer that a path spelling proves an unprotected root.
func wholeFilesystemMount(f *os.File) error {
	info, e := os.ReadFile("/proc/self/fdinfo/" + strconv.FormatUint(uint64(f.Fd()), 10))
	if e != nil || len(info) > 4096 {
		return ErrSafety
	}
	id := ""
	for _, line := range strings.Split(string(info), "\n") {
		if strings.HasPrefix(line, "mnt_id:") {
			v := strings.Fields(line)
			if len(v) == 2 {
				id = v[1]
			}
		}
	}
	mounts, e := os.Open("/proc/self/mountinfo")
	if e != nil {
		return ErrSafety
	}
	defer mounts.Close()
	b, e := io.ReadAll(io.LimitReader(mounts, 1000001))
	if e != nil || len(b) > 1000000 {
		return ErrSafety
	}
	device := ""
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 5 && fields[0] == id {
			if fields[3] != "/" {
				return ErrSafety
			}
			device = fields[2]
		}
	}
	if device == "" {
		return ErrSafety
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 5 && fields[2] == device {
			for _, virtual := range []string{"/proc", "/sys", "/dev"} {
				if fields[4] == virtual || strings.HasPrefix(fields[4], virtual+"/") {
					return ErrSafety
				}
			}
		}
	}
	return nil
}
func Version(f *os.File) (string, error) {
	st, e := metadata(f)
	if e != nil {
		return "", e
	}
	binding, e := mountBinding(f)
	if e != nil {
		return "", e
	}
	sum := sha256.Sum256([]byte(binding + ":" + fmt.Sprintf("%d:%d:%d:%d:%d:%d:%d:%d:%d:%d", st.Dev, st.Ino, st.Mode, st.Uid, st.Gid, st.Nlink, st.Size, st.Mtim.Sec, st.Mtim.Nsec, st.Ctim.Sec) + ":" + strconv.FormatInt(st.Ctim.Nsec, 10)))
	return hex.EncodeToString(sum[:]), nil
}
func (g *Guard) ReadFile(f *os.File) (*os.File, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.closed {
		return nil, ErrSafety
	}
	if e := g.check(f); e != nil {
		return nil, e
	}
	st, e := metadata(f)
	if e != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, ErrSafety
	}
	fd := int(C.sd_read(C.int(f.Fd())))
	if fd < 0 {
		return nil, classify(syscall.Errno(-fd))
	}
	r := os.NewFile(uintptr(fd), "content")
	after, e := metadata(r)
	if e != nil || after.Dev != st.Dev || after.Ino != st.Ino {
		r.Close()
		return nil, ErrChanged
	}
	return r, nil
}
func Stat(f *os.File) (os.FileInfo, error) { return f.Stat() }
func StatFields(f *os.File) (uint32, uint32, uint32, time.Time, time.Time, error) {
	st, e := metadata(f)
	return st.Mode, st.Uid, st.Gid, time.Unix(st.Mtim.Sec, st.Mtim.Nsec), time.Unix(st.Ctim.Sec, st.Ctim.Nsec), e
}

func Filesystem(f *os.File) (string, error) {
	st, e := metadata(f)
	if e != nil {
		return "", e
	}
	binding, e := mountBinding(f)
	if e != nil {
		return "", e
	}
	return "fs:" + binding + ":" + strconv.FormatUint(uint64(st.Dev), 10), nil
}
func (g *Guard) Directory(f *os.File) (*os.File, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.closed {
		return nil, ErrSafety
	}
	if e := g.check(f); e != nil {
		return nil, e
	}
	st, e := metadata(f)
	if e != nil || st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return nil, ErrSafety
	}
	r, e := nativeOpen(int(f.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY, true)
	return r, e
}

func mountBinding(f *os.File) (string, error) {
	info, e := os.ReadFile("/proc/self/fdinfo/" + strconv.FormatUint(uint64(f.Fd()), 10))
	if e != nil || len(info) > 4096 {
		return "", ErrSafety
	}
	mount := ""
	for _, line := range strings.Split(string(info), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "mnt_id:" {
			mount = fields[1]
		}
	}
	boot, e := os.Open("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return "", ErrSafety
	}
	b, e := io.ReadAll(io.LimitReader(boot, 129))
	boot.Close()
	if e != nil || len(b) > 128 || mount == "" {
		return "", ErrSafety
	}
	namespace, e := os.Readlink("/proc/self/ns/mnt")
	if e != nil {
		return "", ErrSafety
	}
	h := sha256.Sum256([]byte(strings.TrimSpace(string(b)) + ":" + namespace + ":" + mount))
	return hex.EncodeToString(h[:16]), nil
}

// Boot-bound identity proof: a pathname is only a locator. Pins prevent inode
// reuse during this process; another boot requires explicit local re-attestation.
func IdentityProof(f *os.File) (string, error) {
	st, e := metadata(f)
	if e != nil {
		return "", e
	}
	b, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil || len(b) > 128 {
		return "", ErrSafety
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(string(b)) + ":" + fmt.Sprintf("%d:%d:%d", st.Dev, st.Ino, st.Mode&syscall.S_IFMT)))
	return hex.EncodeToString(sum[:]), nil
}

func readDescriptor(f *os.File) (*os.File, error) {
	st, e := metadata(f)
	if e != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, ErrSafety
	}
	fd := int(C.sd_read(C.int(f.Fd())))
	if fd < 0 {
		return nil, classify(syscall.Errno(-fd))
	}
	out := os.NewFile(uintptr(fd), "content")
	after, e := metadata(out)
	if e != nil || after.Dev != st.Dev || after.Ino != st.Ino {
		out.Close()
		return nil, ErrChanged
	}
	return out, nil
}

func (g *Guard) addAncestorsLocked(f *os.File, path string, directory bool) error {
	start := path
	if !directory {
		start = filepath.Dir(path)
	}
	current, e := PinAbsolute(start)
	if e != nil {
		return e
	}
	defer func() {
		if current != nil {
			current.Close()
		}
	}()
	for i := 0; i < 256; i++ {
		st, e := metadata(current)
		if e != nil {
			return e
		}
		g.ancestors[identity{uint64(st.Dev), st.Ino}] = true
		// This is a trusted ancestor walk, not a client path. RESOLVE_BENEATH
		// deliberately rejects '..' escaping its starting descriptor.
		parentFD, e := syscall.Openat(int(current.Fd()), "..", pathOnly|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if e != nil {
			return e
		}
		parent := os.NewFile(uintptr(parentFD), "ancestor")
		pst, e := metadata(parent)
		if e != nil {
			parent.Close()
			return e
		}
		if pst.Dev == st.Dev && pst.Ino == st.Ino {
			parent.Close()
			return nil
		}
		current.Close()
		current = parent
	}
	return ErrLimit
}
func (g *Guard) EnableSharedRoots() { g.mu.Lock(); defer g.mu.Unlock(); g.shared = true }
func (g *Guard) ReserveName(name string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.reservedNames[name] = true
}
func (g *Guard) ValidateBindings() error {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.closed {
		return ErrSafety
	}
	for _, binding := range g.bindings {
		path, e := os.Readlink("/proc/self/fd/" + strconv.FormatUint(uint64(binding.fd.Fd()), 10))
		if e != nil || path != binding.path {
			return ErrSafety
		}
	}
	return nil
}
func (g *Guard) CanRemove(f *os.File) error {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.closed {
		return ErrSafety
	}
	if e := g.check(f); e != nil {
		return e
	}
	st, e := metadata(f)
	if e != nil {
		return e
	}
	if st.Mode&syscall.S_IFMT == syscall.S_IFDIR && g.ancestors[identity{uint64(st.Dev), st.Ino}] {
		return ErrProtected
	}
	return nil
}
