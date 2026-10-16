//go:build !linux || !cgo

// SPDX-License-Identifier: Apache-2.0
package app

import (
	"serverdeck.local/agent/internal/operations"
	"serverdeck.local/agent/internal/storage"
)

func offlineFileRecovery(*storage.Store, string, string) (*operations.Service, func(), error) {
	return nil, nil, storage.ErrSafety
}
