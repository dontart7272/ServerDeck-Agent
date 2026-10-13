// SPDX-License-Identifier: Apache-2.0
//go:build !linux || !cgo

package metrics

type Linux struct{}

func NewLinux() (*Linux, error)                                     { return nil, ErrUnavailable }
func (*Linux) BootID() string                                       { return "" }
func (*Linux) Collect(string, Stamp, int64, string) (Sample, error) { return Sample{}, ErrUnavailable }
