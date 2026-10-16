// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"os"
	"syscall"
)

func duplicateProtection(f *os.File) (*os.File, error) {
	fd, _, e := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_DUPFD_CLOEXEC, 0)
	if e != 0 {
		return nil, ErrSafety
	}
	return os.NewFile(fd, "protected-state"), nil
}
