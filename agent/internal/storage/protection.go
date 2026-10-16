// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"os"
)

// ProtectionDirectory pins the directory actually in use, even after an external rename.
func (s *Store) ProtectionDirectory(ctx context.Context) (*os.File, error) {
	var f *os.File
	e := s.read(ctx, func(context.Context) error { var err error; f, err = duplicateProtection(s.dir); return err })
	return f, e
}
