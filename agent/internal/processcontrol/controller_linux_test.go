//go:build linux && cgo

// SPDX-License-Identifier: Apache-2.0
package processcontrol

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/storage"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func target(t *testing.T) (*exec.Cmd, contracts.APIProcess) {
	t.Helper()
	cmd := exec.Command("/bin/sleep", "60")
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	id, e := Read(int64(cmd.Process.Pid))
	if e != nil {
		t.Fatal(e)
	}
	start, _ := strconv.ParseUint(id.Start, 10, 64)
	ns, _ := strconv.ParseUint(id.Namespace, 10, 64)
	return cmd, contracts.APIProcess{Pid: id.PID, ProcessRef: id.Ref, BootId: id.Boot, StartTicks: contracts.U64(start), PidNamespace: contracts.U64(ns)}
}
func TestPidfdSignalsIdentityProtectionAndNoFallback(t *testing.T) {
	ctx := context.Background()
	c := New()
	if e := c.Available(); e != nil {
		t.Fatal("pidfd required in this Linux test", e)
	}
	cmd, p := target(t)
	if !errors.Is(c.Check(ctx, p), ErrProtected) {
		t.Fatal("Agent descendants must be protected")
	}
	c.self = 0 // Controlled child fixture only; production always protects descendants.
	bad := p
	bad.StartTicks++
	if !errors.Is(c.Check(ctx, bad), ErrChanged) {
		t.Fatal("start identity")
	}
	bad = p
	bad.BootId = "different"
	if !errors.Is(c.Check(ctx, bad), ErrChanged) {
		t.Fatal("boot identity")
	}
	bad = p
	bad.PidNamespace++
	if !errors.Is(c.Check(ctx, bad), ErrChanged) {
		t.Fatal("namespace identity")
	}
	if e := c.Protect(p.ProcessRef); e != nil {
		t.Fatal(e)
	}
	if !errors.Is(c.Check(ctx, p), ErrProtected) {
		t.Fatal("managed child")
	}
	c.Unprotect(p.ProcessRef)
	c.open = func(int) (int, error) { return -1, syscall.ENOSYS }
	if !errors.Is(c.Check(ctx, p), storage.ErrSafety) {
		t.Fatal("unsafe fallback")
	}
	if cmd.Process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("fallback changed child")
	}
	c.open = nativeOpen
	r, e := c.Signal(ctx, p, false)
	if e != nil || !r.SignalSent || !r.ExitObserved {
		t.Fatalf("TERM %+v %v", r, e)
	}
	if _, e = c.Signal(ctx, p, true); e == nil {
		t.Fatal("dead instance signalled")
	}
	for _, pid := range []int64{1, int64(os.Getpid())} {
		d := New()
		if !errors.Is(d.Check(ctx, contracts.APIProcess{Pid: pid}), ErrProtected) {
			t.Fatal("protected", pid)
		}
	}
}
func TestPinnedDeadProcessCannotSignalNewChild(t *testing.T) {
	cmd, p := target(t)
	fd, e := nativeOpen(int(p.Pid))
	if e != nil {
		t.Fatal(e)
	}
	defer nativeClose(fd)
	cmd.Process.Kill()
	cmd.Wait()
	other, _ := target(t)
	if !errors.Is(nativeSend(fd, 15), syscall.ESRCH) {
		t.Fatal("dead pidfd accepted signal")
	}
	if other.Process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("new child affected")
	}
}

func TestIgnoreTERMHelper(t *testing.T) {
	if os.Getenv("SD_E07_IGNORE") == "" {
		return
	}
	signal.Ignore(syscall.SIGTERM)
	if e := os.WriteFile(os.Getenv("SD_E07_READY"), []byte("ready"), 0600); e != nil {
		os.Exit(2)
	}
	for {
		time.Sleep(time.Hour)
	}
}
func TestTERMDoesNotEscalateKILLIsSeparate(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready")
	cmd := exec.Command(os.Args[0], "-test.run=^TestIgnoreTERMHelper$")
	cmd.Env = append(os.Environ(), "SD_E07_IGNORE=1", "SD_E07_READY="+ready)
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, e := os.Stat(ready); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("helper readiness")
		}
		time.Sleep(10 * time.Millisecond)
	}
	id, e := Read(int64(cmd.Process.Pid))
	if e != nil {
		t.Fatal(e)
	}
	start, _ := strconv.ParseUint(id.Start, 10, 64)
	ns, _ := strconv.ParseUint(id.Namespace, 10, 64)
	p := contracts.APIProcess{Pid: id.PID, ProcessRef: id.Ref, BootId: id.Boot, StartTicks: contracts.U64(start), PidNamespace: contracts.U64(ns)}
	c := New()
	c.self = 0
	r, e := c.Signal(context.Background(), p, false)
	if e != nil || !r.SignalSent || r.ExitObserved {
		t.Fatal("TERM escalated or dishonest", r, e)
	}
	r, e = c.Signal(context.Background(), p, true)
	if e != nil || !r.SignalSent || !r.ExitObserved {
		t.Fatal("separate KILL", r, e)
	}
}

// This procedure may write ns_last_pid ONLY as PID 1 in a newly-created PID
// namespace. It is never run by the default test suite or on the host namespace.
func TestIsolatedFastPIDReuse(t *testing.T) {
	if os.Getenv("SD_E07_ISOLATED_PIDNS") != "1" {
		t.Skip("explicit isolated namespace procedure")
	}
	outer := os.Getenv("SD_E07_OUTER_PIDNS")
	current, e := os.Readlink("/proc/self/ns/pid")
	if e != nil || outer == "" || outer == current || os.Getpid() != 1 {
		t.Fatal("refusing namespace mutation outside verified isolated PID namespace")
	}
	cmd, p := target(t)
	fd, e := nativeOpen(int(p.Pid))
	if e != nil {
		t.Fatal(e)
	}
	defer nativeClose(fd)
	cmd.Process.Kill()
	cmd.Wait()
	time.Sleep(30 * time.Millisecond) // Different start tick; the numeric PID is deliberately reused.
	if e = os.WriteFile("/proc/sys/kernel/ns_last_pid", []byte(strconv.FormatInt(p.Pid-1, 10)), 0600); e != nil {
		t.Fatal(e)
	}
	next, q := target(t)
	if q.Pid != p.Pid {
		t.Fatalf("PID was not reused: %d -> %d", p.Pid, q.Pid)
	}
	c := New()
	c.self = 0
	if !errors.Is(c.Check(context.Background(), p), ErrChanged) {
		t.Fatal("old reference accepted for reused PID")
	}
	if !errors.Is(nativeSend(fd, 15), syscall.ESRCH) {
		t.Fatal("old fd signalled reused PID")
	}
	if next.Process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("new instance affected")
	}
	t.Logf("PASS actual numeric PID reuse %d; old reference and pidfd rejected; new instance alive", q.Pid)
}

func TestForeignUIDHelper(t *testing.T) {
	raw := os.Getenv("SD_E07_FOREIGN_PROCESS")
	if raw == "" {
		return
	}
	if os.Geteuid() != 65534 {
		t.Fatal("fixture UID not dropped")
	}
	var p contracts.APIProcess
	if json.Unmarshal([]byte(raw), &p) != nil {
		t.Fatal("fixture")
	}
	c := New()
	if !errors.Is(c.Check(context.Background(), p), ErrPermission) {
		t.Fatal("foreign UID not denied")
	}
	if _, e := c.Signal(context.Background(), p, true); !errors.Is(e, ErrPermission) {
		t.Fatal("foreign UID signal accepted", e)
	}
}
func TestIsolatedForeignUID(t *testing.T) {
	if os.Getenv("SD_E07_ISOLATED_ROOT") != "1" {
		t.Skip("explicit isolated root procedure")
	}
	outer := os.Getenv("SD_E07_OUTER_PIDNS")
	current, e := os.Readlink("/proc/self/ns/pid")
	if e != nil || outer == "" || outer == current || os.Getpid() != 1 || os.Geteuid() != 0 {
		t.Fatal("refusing foreign UID procedure outside isolated root PID namespace")
	}
	cmd, p := target(t)
	raw, _ := json.Marshal(p)
	helper := exec.Command(os.Args[0], "-test.v", "-test.run=^TestForeignUIDHelper$")
	helper.Env = append(os.Environ(), "SD_E07_FOREIGN_PROCESS="+string(raw))
	helper.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, NoSetGroups: true}}
	if out, e := helper.CombinedOutput(); e != nil {
		t.Fatalf("foreign UID helper: %v %s", e, out)
	} else {
		t.Log(string(out))
	}
	if cmd.Process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("foreign UID fixture changed target")
	}
}

func TestPID1AgentStillProtectsItsChildren(t *testing.T) {
	c := New()
	c.self = 1
	if !errors.Is(c.protected(Identity{PID: 123, Parent: 1, Ref: "fixture"}), ErrProtected) {
		t.Fatal("PID1 Agent child protection bypass")
	}
}
