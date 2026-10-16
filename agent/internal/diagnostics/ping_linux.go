// SPDX-License-Identifier: Apache-2.0
//go:build linux

package diagnostics

import (
	"bytes"
	"context"
	"errors"
	"math"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type limited struct {
	bytes.Buffer
	max      int
	overflow bool
}

func (b *limited) Write(p []byte) (int, error) {
	if len(p) > b.max-b.Len() {
		b.overflow = true
		return 0, ErrSource
	}
	return b.Buffer.Write(p)
}
func trusted(path string) bool {
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil {
		return false
	}
	st, e := os.Stat(resolved)
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
		return false
	}
	for p := resolved; ; p = filepath.Dir(p) {
		st, e := os.Stat(p)
		if e != nil || st.Mode().Perm()&022 != 0 {
			return false
		}
		info, ok := st.Sys().(*syscall.Stat_t)
		if !ok || info.Uid != 0 {
			return false
		}
		if p == "/" {
			return true
		}
	}
}
func nativePing(ctx context.Context, ip netip.Addr) (Stats, error) {
	path := "/usr/bin/ping"
	if !trusted(path) {
		path = "/bin/ping"
	}
	if !trusted(path) {
		return Stats{}, ErrSource
	}
	family := "-4"
	if ip.Is6() {
		family = "-6"
	}
	cmd := exec.CommandContext(ctx, path, family, "-n", "-c", "5", "-w", "10", "-W", "1", ip.String())
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 250 * time.Millisecond
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	out, stderr := &limited{max: 65536}, &limited{max: 4096}
	cmd.Stdout, cmd.Stderr = out, stderr
	err := cmd.Run()
	if errors.Is(err, os.ErrPermission) || strings.Contains(strings.ToLower(stderr.String()), "operation not permitted") || strings.Contains(strings.ToLower(stderr.String()), "permission denied") {
		return Stats{}, ErrPermission
	}
	if ctx.Err() != nil || out.overflow || stderr.overflow {
		return Stats{}, ErrSource
	}
	if err != nil {
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 1 {
			return Stats{}, ErrSource
		}
	}
	return parsePing(out.String())
}

var summary = regexp.MustCompile(`(?m)^([0-9]+) packets transmitted, ([0-9]+) (?:packets )?received,.*$`)
var rtt = regexp.MustCompile(`(?m)^(?:rtt|round-trip) min/avg/max/(?:mdev|stddev) = [0-9.]+/([0-9.]+)/[0-9.]+/[0-9.]+ ms$`)

func parsePing(raw string) (Stats, error) {
	var s Stats
	if len(raw) > 65536 {
		return s, ErrSource
	}
	matches := summary.FindAllStringSubmatch(raw, -1)
	if len(matches) != 1 {
		return s, ErrSource
	}
	s.Sent, _ = strconv.Atoi(matches[0][1])
	s.Received, _ = strconv.Atoi(matches[0][2])
	if s.Sent < 1 || s.Sent > 5 || s.Received < 0 || s.Received > s.Sent {
		return Stats{}, ErrSource
	}
	if s.Received > 0 {
		matches = rtt.FindAllStringSubmatch(raw, -1)
		if len(matches) != 1 {
			return Stats{}, ErrSource
		}
		avg, e := strconv.ParseFloat(matches[0][1], 64)
		if e != nil || math.IsNaN(avg) || math.IsInf(avg, 0) || avg < 0 || avg > 10000 {
			return Stats{}, ErrSource
		}
		s.Latency = &avg
	}
	return s, nil
}
