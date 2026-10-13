// SPDX-License-Identifier: Apache-2.0
package app

import (
	"io"
	"serverdeck.local/agent/internal/storage"
)

func nativeCommand(string, string, io.Writer) error              { return storage.ErrSafety }
func nativeLocalCommand(string, string, string, io.Writer) error { return storage.ErrSafety }
