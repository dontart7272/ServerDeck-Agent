//go:build linux && cgo

// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"os"
	"os/user"
	"serverdeck.local/agent/internal/fileaccess"
	"serverdeck.local/agent/internal/operations"
	"serverdeck.local/agent/internal/storage"
)

// Destructive offline recovery requires the actual bootstrap configuration;
// state-only commands cannot silently omit TLS/config/code/runtime protections.
func offlineFileRecovery(s *storage.Store, state, path string) (*operations.Service, func(), error) {
	ctx := context.Background()
	cfg, configPin, e := readNativeConfigPinned(path)
	if e != nil {
		return nil, nil, storage.ErrSafety
	}
	defer configPin.Close()
	u, e := user.Current()
	if e != nil || cfg.RuntimeUser != u.Username || cfg.Paths.State != state {
		return nil, nil, storage.ErrSafety
	}
	installation, e := s.InstallationID(ctx)
	if e != nil || installation != string(cfg.InstallationID) {
		return nil, nil, storage.ErrSafety
	}
	pins := []*os.File{configPin}
	for _, p := range []string{cfg.TLS.CertificateFile, cfg.TLS.PrivateKeyFile, cfg.Paths.Runtime} {
		f, e := fileaccess.PinAbsolute(p)
		if e != nil {
			return nil, nil, storage.ErrSafety
		}
		defer f.Close()
		pins = append(pins, f)
	}
	id, e := s.AgentID(ctx)
	if e != nil {
		return nil, nil, e
	}
	g := &Gateway{Store: s, AgentID: id}
	files := g.buildFiles(cfg, pins)
	if files == nil {
		return nil, nil, storage.ErrSafety
	}
	inventory, e := s.VerifiedInventory(ctx)
	if e != nil {
		files.Close()
		return nil, nil, storage.ErrSafety
	}
	for _, region := range inventory.Attestation.Regions {
		f, e := fileaccess.PinAbsolute(region.Path)
		if e != nil {
			files.Close()
			return nil, nil, storage.ErrSafety
		}
		proof, pe := fileaccess.IdentityProof(f)
		if pe != nil || proof != region.Proof {
			f.Close()
			files.Close()
			return nil, nil, storage.ErrSafety
		}
		e = files.guard.Protect(f)
		f.Close()
		if e != nil {
			files.Close()
			return nil, nil, storage.ErrSafety
		}
	}
	return operations.OfflineWithFileProtection(s, files.guard), files.Close, nil
}
