// SPDX-License-Identifier: Apache-2.0
package storage

import "os"

// Windows retains offline contract commands; critical storage is Linux-only.
func privateDir(string, bool) (*os.File, error)                  { return nil, ErrSafety }
func privateFile(*os.File, string, bool) (*os.File, bool, error) { return nil, false, ErrSafety }
func lockFile(*os.File) error                                    { return ErrSafety }
func diskFree(*os.File) (int64, error)                           { return 0, ErrSafety }
func allocated(f os.FileInfo) int64                              { return f.Size() }
func descriptorPath(*os.File) string                             { return "" }
