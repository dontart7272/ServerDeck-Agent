// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Pin a private directory by descriptor. Reject symlinks at every component,
// foreign ownership, writable ancestors (except root-owned sticky temp roots),
// nonlocal filesystems and hard-linked private files. Shared UID/root is not an
// isolation boundary; no syscall here changes host permissions or mounts.
func privateDir(path string, create bool) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, ErrSafety
	}
	fd, e := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrSafety
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, p := range parts {
		last := i == len(parts)-1
		next, err := syscall.Openat(fd, p, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err == syscall.ENOENT && last && create {
			err = syscall.Mkdirat(fd, p, 0700)
			if err == nil {
				err = syscall.Fsync(fd)
			}
			if err == nil {
				next, err = syscall.Openat(fd, p, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
			}
		}
		syscall.Close(fd)
		if err != nil {
			return nil, ErrSafety
		}
		fd = next
		var st syscall.Stat_t
		if syscall.Fstat(fd, &st) != nil || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || (st.Mode&0022 != 0 && !(st.Uid == 0 && st.Mode&syscall.S_ISVTX != 0 && !last)) || (last && (st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0)) {
			syscall.Close(fd)
			return nil, ErrSafety
		}
	}
	var fs syscall.Statfs_t
	if syscall.Fstatfs(fd, &fs) != nil {
		syscall.Close(fd)
		return nil, ErrSafety
	}
	// Deliberate allowlist: release support for other local FS needs its own tests.
	switch uint64(fs.Type) {
	case 0xef53, 0x01021994, 0x58465342, 0x9123683e:
	default:
		syscall.Close(fd)
		return nil, ErrSafety
	}
	return os.NewFile(uintptr(fd), path), nil
}
func privateFile(dir *os.File, name string, create bool) (*os.File, bool, error) {
	flags := syscall.O_RDWR | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	fd, e := syscall.Openat(int(dir.Fd()), name, flags, 0)
	made := false
	if e == syscall.ENOENT && create {
		fd, e = syscall.Openat(int(dir.Fd()), name, flags|syscall.O_CREAT|syscall.O_EXCL, 0600)
		made = e == nil
	}
	if e != nil {
		return nil, false, ErrSafety
	}
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 || st.Nlink != 1 {
		syscall.Close(fd)
		return nil, false, ErrSafety
	}
	return os.NewFile(uintptr(fd), name), made, nil
}
func lockFile(f *os.File) error {
	if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return ErrBusy
	}
	return nil
}
func diskFree(f *os.File) (int64, error) {
	var st syscall.Statfs_t
	if syscall.Fstatfs(int(f.Fd()), &st) != nil {
		return 0, ErrStorage
	}
	return int64(st.Bavail) * st.Bsize, nil
}
func allocated(f os.FileInfo) int64    { return f.Sys().(*syscall.Stat_t).Blocks * 512 }
func descriptorPath(f *os.File) string { return "/proc/self/fd/" + itoa(int64(f.Fd())) }
