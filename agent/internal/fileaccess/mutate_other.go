//go:build !linux || !cgo

// SPDX-License-Identifier: Apache-2.0
package fileaccess

import "os"

func (*Guard) MutationRoot(string) (*os.File, error)              { return nil, ErrSafety }
func (*Guard) CheckCreate(string, Location, string, string) error { return ErrSafety }
func (*Guard) Create(string, Location, string, string, string) (*os.File, error) {
	return nil, ErrSafety
}
func (*Guard) CheckRename(string, Location, string, Location, string, string) error { return ErrSafety }
func (*Guard) Rename(string, Location, string, Location, string, string) (*os.File, error) {
	return nil, ErrSafety
}
func (*Guard) CheckRenameAcross(string, string, Location, string, Location, string, string) error {
	return ErrSafety
}
func (*Guard) RenameAcross(string, string, Location, string, Location, string, string) (*os.File, error) {
	return nil, ErrSafety
}
