// SPDX-License-Identifier: Apache-2.0
// Package processcontrol pins a checked process instance. There is no kill(pid) fallback.
package processcontrol

import (
	"context"
	"errors"
	"os"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/storage"
	"strconv"
	"sync"
	"time"
)

var ErrProtected = errors.New("PROTECTED_OBJECT")
var ErrChanged = errors.New("OBJECT_CHANGED")
var ErrMissing = errors.New("NOT_FOUND")
var ErrPermission = errors.New("PERMISSION_DENIED")

type Identity struct {
	PID                         int64
	Boot, Start, Namespace, Ref string
	Parent                      int
}
type Result struct {
	ProcessRef   string              `json:"process_ref"`
	SignalSent   bool                `json:"signal_sent"`
	ExitObserved bool                `json:"exit_observed"`
	ObservedAt   contracts.Timestamp `json:"observed_at"`
}
type Controller struct {
	mu        sync.RWMutex
	managed   map[string]bool
	self      int
	open      func(int) (int, error)
	available error
}

func New() *Controller {
	c := &Controller{managed: map[string]bool{}, self: os.Getpid(), open: nativeOpen}
	c.available = nativeProbe()
	return c
}
func (c *Controller) Available() error { return c.available }

// Protect is for trusted managed-process lifecycle code, never for client input.
func (c *Controller) Protect(ref string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.managed) >= 256 {
		return storage.ErrQuota
	}
	c.managed[ref] = true
	return nil
}
func (c *Controller) Unprotect(ref string) { c.mu.Lock(); delete(c.managed, ref); c.mu.Unlock() }
func (c *Controller) protected(id Identity) error {
	if id.PID == 1 || int(id.PID) == c.self {
		return ErrProtected
	}
	c.mu.RLock()
	managed := c.managed[id.Ref]
	c.mu.RUnlock()
	if managed {
		return ErrProtected
	}
	parent := id.Parent
	seen := map[int]bool{}
	for count := 0; parent > 0; count++ {
		if parent == c.self {
			return ErrProtected
		}
		if parent == 1 {
			break
		}
		if count >= 64 || seen[parent] {
			return storage.ErrSafety
		}
		seen[parent] = true
		next, err := nativeParent(parent)
		if err != nil {
			return classify(err)
		}
		parent = next
	}
	return nil
}
func matches(id Identity, p contracts.APIProcess) bool {
	return id.Ref == p.ProcessRef && id.PID == p.Pid && id.Boot == p.BootId && id.Start == strconv.FormatUint(uint64(p.StartTicks), 10) && id.Namespace == strconv.FormatUint(uint64(p.PidNamespace), 10)
}
func (c *Controller) pin(ctx context.Context, p contracts.APIProcess) (int, error) {
	if err := ctx.Err(); err != nil {
		return -1, storage.ErrSafety
	}
	if p.Pid == 1 || int(p.Pid) == c.self {
		return -1, ErrProtected
	}
	if c.available != nil {
		return -1, storage.ErrSafety
	}
	before, err := Read(p.Pid)
	if err != nil {
		return -1, classify(err)
	}
	if !matches(before, p) {
		return -1, ErrChanged
	}
	if err = c.protected(before); err != nil {
		return -1, err
	}
	fd, err := c.open(int(p.Pid))
	if err != nil {
		return -1, classify(err)
	}
	fail := func(e error) (int, error) { nativeClose(fd); return -1, e }
	after, err := Read(p.Pid)
	if err != nil {
		return fail(classify(err))
	}
	if !matches(after, p) {
		return fail(ErrChanged)
	}
	if err = c.protected(after); err != nil {
		return fail(err)
	}
	if err = nativeSend(fd, 0); err != nil {
		return fail(classify(err))
	}
	return fd, nil
}
func (c *Controller) Check(ctx context.Context, p contracts.APIProcess) error {
	fd, err := c.pin(ctx, p)
	if fd >= 0 {
		nativeClose(fd)
	}
	return err
}
func (c *Controller) Signal(ctx context.Context, p contracts.APIProcess, kill bool) (Result, error) {
	result := Result{ProcessRef: p.ProcessRef, ObservedAt: contracts.Timestamp(time.Now().UTC())}
	fd, err := c.pin(ctx, p)
	if err != nil {
		return result, err
	}
	defer nativeClose(fd)
	if err = ctx.Err(); err != nil {
		return result, storage.ErrSafety
	}
	sig := 15
	if kill {
		sig = 9
	}
	if err = nativeSend(fd, sig); err != nil {
		return result, classify(err)
	}
	result.SignalSent = true
	// A successful send is final even when exit cannot be observed within the bound.
	result.ExitObserved, _ = nativeExited(fd, 1000)
	result.ObservedAt = contracts.Timestamp(time.Now().UTC())
	return result, nil
}
func classify(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrMissing) {
		return ErrMissing
	}
	if errors.Is(err, ErrProtected) {
		return ErrProtected
	}
	if errors.Is(err, os.ErrPermission) || nativePermission(err) {
		return ErrPermission
	}
	if errors.Is(err, os.ErrNotExist) || nativeMissing(err) {
		return ErrMissing
	}
	return storage.ErrSafety
}
