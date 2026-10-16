// SPDX-License-Identifier: Apache-2.0
//go:build !linux || !cgo

package processcontrol

import "serverdeck.local/agent/internal/storage"

func Read(int64) (Identity, error)        { return Identity{}, storage.ErrSafety }
func nativeParent(int) (int, error)       { return 0, storage.ErrSafety }
func nativeProbe() error                  { return storage.ErrSafety }
func nativeOpen(int) (int, error)         { return -1, storage.ErrSafety }
func nativeClose(int)                     {}
func nativeSend(int, int) error           { return storage.ErrSafety }
func nativeExited(int, int) (bool, error) { return false, storage.ErrSafety }
func nativePermission(error) bool         { return false }
func nativeMissing(error) bool            { return false }
