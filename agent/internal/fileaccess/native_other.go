//go:build !linux || !cgo

// SPDX-License-Identifier: Apache-2.0
package fileaccess

import (
	"os"
	"time"
)

type Guard struct{}

func AvailableBytes(*os.File) (int64, error) { return 0, ErrSafety }

func Access(*os.File, int) error { return ErrSafety }

func New([]*os.File) (*Guard, error)                   { return nil, ErrSafety }
func (*Guard) Close()                                  {}
func (*Guard) Protect(*os.File) error                  { return ErrSafety }
func (*Guard) Open(string, Location) (*os.File, error) { return nil, ErrSafety }
func (*Guard) ReadFile(*os.File) (*os.File, error)     { return nil, ErrSafety }
func (*Guard) Directory(*os.File) (*os.File, error)    { return nil, ErrSafety }
func PinAbsolute(string) (*os.File, error)             { return nil, ErrSafety }
func Version(*os.File) (string, error)                 { return "", ErrSafety }
func Stat(*os.File) (os.FileInfo, error)               { return nil, ErrSafety }
func StatFields(*os.File) (uint32, uint32, uint32, time.Time, time.Time, error) {
	return 0, 0, 0, time.Time{}, time.Time{}, ErrSafety
}

func Filesystem(*os.File) (string, error) { return "", ErrSafety }

func IdentityProof(*os.File) (string, error) { return "", ErrSafety }

func (*Guard) EnableSharedRoots()       {}
func (*Guard) ReserveName(string)       {}
func (*Guard) ValidateBindings() error  { return ErrSafety }
func (*Guard) CanRemove(*os.File) error { return ErrSafety }
