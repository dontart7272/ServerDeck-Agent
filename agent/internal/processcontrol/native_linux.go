// SPDX-License-Identifier: Apache-2.0
//go:build linux && cgo

package processcontrol

/*
#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
static int sd_open(int pid) {int fd=syscall(SYS_pidfd_open,pid,0);return fd<0?-errno:fd;}
static int sd_send(int fd,int sig) {int r=syscall(SYS_pidfd_send_signal,fd,sig,NULL,0);return r<0?-errno:r;}
static int sd_poll(int fd,int ms) {struct pollfd p={.fd=fd,.events=POLLIN};int r=poll(&p,1,ms);if(r<0)return -errno;if(r==0)return 0;if(p.revents&(POLLIN|POLLHUP))return 1;return -EIO;}
*/
import "C"
import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"serverdeck.local/agent/internal/storage"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func bounded(path string, max int64) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max {
		return "", storage.ErrSafety
	}
	return string(b), nil
}
func statFields(pid int64) ([]string, error) {
	if pid < 1 || pid > 4194304 {
		return nil, storage.ErrInvalid
	}
	raw, e := bounded("/proc/"+strconv.FormatInt(pid, 10)+"/stat", 16384)
	if e != nil {
		return nil, e
	}
	end := strings.LastIndexByte(raw, ')')
	if end < 0 {
		return nil, storage.ErrSafety
	}
	fields := strings.Fields(raw[end+1:])
	if len(fields) < 20 {
		return nil, storage.ErrSafety
	}
	flags, e := strconv.ParseUint(fields[6], 10, 64)
	if e != nil {
		return nil, storage.ErrSafety
	}
	if fields[0] == "Z" || fields[0] == "X" {
		return nil, ErrMissing
	}
	if pid == 1 || flags&0x200000 != 0 {
		return nil, ErrProtected
	}
	return fields, nil
}
func nativeParent(pid int) (int, error) {
	f, e := statFields(int64(pid))
	if e != nil {
		return 0, e
	}
	p, e := strconv.Atoi(f[1])
	if e != nil || p < 0 {
		return 0, storage.ErrSafety
	}
	return p, nil
}
func Read(pid int64) (Identity, error) {
	var id Identity
	f, e := statFields(pid)
	if e != nil {
		return id, e
	}
	parent, e := strconv.Atoi(f[1])
	if e != nil {
		return id, storage.ErrSafety
	}
	start, e := strconv.ParseUint(f[19], 10, 64)
	if e != nil || start == 0 {
		return id, storage.ErrSafety
	}
	boot, e := bounded("/proc/sys/kernel/random/boot_id", 128)
	if e != nil {
		return id, e
	}
	boot = strings.TrimSpace(boot)
	if !storage.ValidID(boot) {
		return id, storage.ErrSafety
	}
	ns, e := os.Stat("/proc/" + strconv.FormatInt(pid, 10) + "/ns/pid")
	if e != nil {
		return id, e
	}
	st, ok := ns.Sys().(*syscall.Stat_t)
	if !ok {
		return id, storage.ErrSafety
	}
	startText, nsText := strconv.FormatUint(start, 10), strconv.FormatUint(st.Ino, 10)
	sum := sha256.Sum256([]byte(strings.Join([]string{boot, strconv.FormatInt(pid, 10), startText, nsText}, "\x00")))
	return Identity{PID: pid, Boot: boot, Start: startText, Namespace: nsText, Ref: hex.EncodeToString(sum[:16]), Parent: parent}, nil
}
func nativeProbe() error {
	// NSpid is expressed from the procfs mount's namespace downwards. A foreign
	// ancestor procfs view must never be passed to pidfd_open in our namespace.
	raw, e := bounded("/proc/self/status", 16384)
	if e != nil {
		return storage.ErrSafety
	}
	valid := false
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "NSpid:") {
			f := strings.Fields(line)
			valid = len(f) == 2 && f[1] == strconv.Itoa(os.Getpid())
		}
	}
	if !valid {
		return storage.ErrSafety
	}
	fd, e := nativeOpen(os.Getpid())
	if e != nil {
		return storage.ErrSafety
	}
	defer nativeClose(fd)
	return nativeSend(fd, 0)
}
func nativeOpen(pid int) (int, error) {
	fd := int(C.sd_open(C.int(pid)))
	if fd < 0 {
		return -1, syscall.Errno(-fd)
	}
	return fd, nil
}
func nativeClose(fd int) { syscall.Close(fd) }
func nativeSend(fd, sig int) error {
	n := int(C.sd_send(C.int(fd), C.int(sig)))
	if n < 0 {
		return syscall.Errno(-n)
	}
	return nil
}
func nativeExited(fd, ms int) (bool, error) {
	until := time.Now().Add(time.Duration(ms) * time.Millisecond)
	for {
		remaining := time.Until(until).Milliseconds()
		if remaining < 0 {
			return false, nil
		}
		n := int(C.sd_poll(C.int(fd), C.int(remaining)))
		if n >= 0 {
			return n == 1, nil
		}
		if syscall.Errno(-n) != syscall.EINTR {
			return false, syscall.Errno(-n)
		}
	}
}
func nativePermission(e error) bool {
	return errors.Is(e, syscall.EPERM) || errors.Is(e, syscall.EACCES)
}
func nativeMissing(e error) bool { return errors.Is(e, syscall.ESRCH) }
