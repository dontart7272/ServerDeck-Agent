//go:build !linux || !cgo

// SPDX-License-Identifier: Apache-2.0
package fileaccess

import (
	"context"
	"os"
)

type Area struct{}

func (*Guard) CheckPrivateCapacity(int) error { return ErrSafety }

func (*Guard) Area(string, string) (*Area, error)              { return nil, ErrSafety }
func (*Area) Close() error                                     { return nil }
func (*Area) Name() string                                     { return "" }
func (*Area) Space(int64) error                                { return ErrSafety }
func (*Area) Allocate(*os.File, int64) error                   { return ErrSafety }
func (*Area) New(string) (*os.File, error)                     { return nil, ErrSafety }
func (*Area) Open(string, string) (*os.File, error)            { return nil, ErrSafety }
func (*Area) Entry(string) (*os.File, error)                   { return nil, ErrSafety }
func (*Area) Trash(Location, string, string) (*os.File, error) { return nil, ErrSafety }
func (*Area) Restore(string, string, Location, string, string, ...string) (*os.File, error) {
	return nil, ErrSafety
}
func (*Area) RestoreTo(string, string, string, Location, string, string, ...string) (*os.File, error) {
	return nil, ErrSafety
}
func (*Area) Publish(string, *os.File, Location, string, string, string) (*os.File, error) {
	return nil, ErrSafety
}
func (*Area) CopyFile(context.Context, *os.File, string, int64) (*os.File, int64, error) {
	return nil, 0, ErrSafety
}
func (*Area) Purge(context.Context, string, string) error { return ErrSafety }
func (*Area) Location(string, string) Location            { return Location{} }

func (*Area) Proof() (string, error)                  { return "", ErrSafety }
func (*Guard) OpenArea(string, string) (*Area, error) { return nil, ErrSafety }
func (*Area) ProtectTree(string, string) error        { return ErrSafety }

type TreeInfo struct {
	Bytes  int64
	Digest string
	Nodes  int
	Kind   string
}

func (*Guard) Scan(context.Context, string, Location, int64) (TreeInfo, error) {
	return TreeInfo{}, ErrSafety
}
func (*Area) Scan(context.Context, string, int64) (TreeInfo, error) { return TreeInfo{}, ErrSafety }
func FilesystemDevice(*os.File) (string, error)                     { return "", ErrSafety }

func CheckReplacementMeta(*os.File) error { return ErrSafety }

func (*Area) CopyObject(context.Context, *os.File, string, int64) (*os.File, error) {
	return nil, ErrSafety
}
func (*Area) CopyPrivateTo(context.Context, string, string, *Area, string, int64) (*os.File, error) {
	return nil, ErrSafety
}
func (*Guard) PayloadDigest(context.Context, string, Location, int64) (string, error) {
	return "", ErrSafety
}
func (*Area) PayloadDigest(context.Context, string, int64) (string, error) { return "", ErrSafety }
