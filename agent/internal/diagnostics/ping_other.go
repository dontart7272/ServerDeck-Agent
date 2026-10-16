// SPDX-License-Identifier: Apache-2.0
//go:build !linux

package diagnostics

import (
	"context"
	"net/netip"
)

func nativePing(context.Context, netip.Addr) (Stats, error) { return Stats{}, ErrSource }
