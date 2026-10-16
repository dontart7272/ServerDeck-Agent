// SPDX-License-Identifier: Apache-2.0
package storage

import "os"

func duplicateProtection(*os.File) (*os.File, error) { return nil, ErrSafety }
