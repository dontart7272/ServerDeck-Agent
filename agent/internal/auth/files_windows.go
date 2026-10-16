// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"net"
	"os"
	"serverdeck.local/agent/internal/storage"
)

func ReadTrusted(string, int64, bool) ([]byte, error)                 { return nil, storage.ErrSafety }
func PeerUID(*net.UnixConn) (uint32, error)                           { return 0, storage.ErrSafety }
func PrivatePeerDirectory(string, uint32) (*os.File, error)           { return nil, storage.ErrSafety }
func ReadTrustedForOwner(string, int64, bool, uint32) ([]byte, error) { return nil, storage.ErrSafety }

func ReadTrustedPinned(string, int64, bool, uint32) ([]byte, *os.File, error) {
	return nil, nil, storage.ErrSafety
}
