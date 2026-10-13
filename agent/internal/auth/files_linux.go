// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"serverdeck.local/agent/internal/storage"
)

// ReadTrusted rejects writable ancestors, symlinks and file aliases. Private
// key mode is0600; public configuration/certificate may be0644 but not writable.
func ReadTrusted(path string, max int64, private bool) ([]byte, error) {
	return ReadTrustedForOwner(path, max, private, uint32(os.Geteuid()))
}
func ReadTrustedForOwner(path string, max int64, private bool, uid uint32) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 {
		return nil, storage.ErrSafety
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	fd, e := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, storage.ErrSafety
	}
	for i, p := range parts {
		last := i == len(parts)-1
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
		if !last {
			flags |= syscall.O_DIRECTORY
		}
		next, err := syscall.Openat(fd, p, flags, 0)
		syscall.Close(fd)
		if err != nil {
			return nil, storage.ErrSafety
		}
		fd = next
		var st syscall.Stat_t
		if syscall.Fstat(fd, &st) != nil || (st.Uid != 0 && st.Uid != uid) || st.Mode&0022 != 0 && !(st.Uid == 0 && st.Mode&syscall.S_ISVTX != 0 && !last) {
			syscall.Close(fd)
			return nil, storage.ErrSafety
		}
		if last && (st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Nlink != 1 || private && st.Mode&0077 != 0 || st.Size > max) {
			syscall.Close(fd)
			return nil, storage.ErrSafety
		}
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max {
		return nil, storage.ErrSafety
	}
	return b, nil
}
func PeerUID(c *net.UnixConn) (uint32, error) {
	raw, e := c.SyscallConn()
	if e != nil {
		return 0, storage.ErrSafety
	}
	var cred *syscall.Ucred
	var inner error
	e = raw.Control(func(fd uintptr) {
		cred, inner = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if e != nil || inner != nil || cred == nil {
		return 0, storage.ErrSafety
	}
	return cred.Uid, nil
}

func PrivatePeerDirectory(path string, uid uint32) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 {
		return nil, storage.ErrSafety
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	fd, e := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, storage.ErrSafety
	}
	for i, p := range parts {
		next, err := syscall.Openat(fd, p, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		syscall.Close(fd)
		if err != nil {
			return nil, storage.ErrSafety
		}
		fd = next
		var st syscall.Stat_t
		last := i == len(parts)-1
		if syscall.Fstat(fd, &st) != nil || (st.Uid != 0 && st.Uid != uid) || (st.Mode&0022 != 0 && !(st.Uid == 0 && st.Mode&syscall.S_ISVTX != 0 && !last)) || last && (st.Uid != uid || st.Mode&0077 != 0) {
			syscall.Close(fd)
			return nil, storage.ErrSafety
		}
	}
	return os.NewFile(uintptr(fd), path), nil
}
