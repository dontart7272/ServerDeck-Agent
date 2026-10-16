// SPDX-License-Identifier: Apache-2.0
//go:build linux && cgo

package metrics

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type AuthObservation struct {
	Source   string
	Position uint64
	At       time.Time
	Code     string
}

type AuthFailure struct {
	Source, Address string
	Position        uint64
	At              time.Time
	Mono            time.Duration
}
type SecurityHooks struct {
	Anchor      func([]byte) (string, error)
	Observation func(context.Context, AuthObservation) error
	Load        func(context.Context, string) ([]byte, error)
	Save        func(context.Context, string, []byte) error
	Failure     func(context.Context, AuthFailure) error
	Progress    func(context.Context, time.Time, time.Duration, bool) error
}
type AdapterOptions struct {
	DockerSocket    *string
	SecuritySources string
	Security        SecurityHooks
}

func (*Linux) IntegrationSources() {}

// ConfigureAdapters must run before the shared collector starts its workers.
func (l *Linux) ConfigureAdapters(options AdapterOptions) { l.adapters = options }

type outputLimit struct {
	data  []byte
	limit int
}

func (b *outputLimit) Write(p []byte) (int, error) {
	if len(p) > b.limit-len(b.data) {
		n := b.limit - len(b.data)
		b.data = append(b.data, p[:n]...)
		return n, ErrLimit
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

// Only compiled-in read-only commands call this private function. No shell/PATH.
func trustedExecutable(path string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	for p := resolved; ; p = filepath.Dir(p) {
		st, err := os.Stat(p)
		if err != nil {
			return false
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok || sys.Uid != 0 || st.Mode().Perm()&022 != 0 {
			return false
		}
		if p == resolved && (!st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0) {
			return false
		}
		if p == "/" {
			break
		}
	}
	return true
}
func readCommand(ctx context.Context, path string, limit int, args ...string) ([]byte, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	if !trustedExecutable(path) {
		return nil, os.ErrPermission
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "HOME=/nonexistent"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 250 * time.Millisecond
	out := &outputLimit{limit: limit}
	cmd.Stdout = out
	stderr := &stderrFlag{}
	cmd.Stderr = stderr
	err := cmd.Run()
	if err == nil && stderr.seen {
		err = ErrUnavailable
	}
	return out.data, err
}
func unavailableBlock(b *Block, status, reason string) {
	b.Availability = status
	b.Reason = ptr(reason)
}
func cleanLabel(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
	return safe(s, max)
}
func adapterError(b *Block, err error, code string) error {
	if errors.Is(err, os.ErrPermission) {
		unavailableBlock(b, "permission_denied", "PERMISSION_DENIED")
	} else {
		unavailableBlock(b, "source_error", code)
	}
	return nil
}

type stderrFlag struct{ seen bool }

func (s *stderrFlag) Write(p []byte) (int, error) { s.seen = true; return len(p), nil }
