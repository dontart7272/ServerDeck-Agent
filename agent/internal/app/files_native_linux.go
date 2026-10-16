// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"os"
	"serverdeck.local/agent/internal/config"
	"serverdeck.local/agent/internal/fileaccess"
	"time"
)

func (g *Gateway) startFiles(cfg config.Config, pins []*os.File) {
	g.fileInit.Do(func() {
		g.Files = boundedFileActivation(func() *fileService { return g.buildFiles(cfg, pins) }, 2*time.Second)
		if g.Files != nil {
			g.startFileMaintenance()
		}
	})
}
func (g *Gateway) buildFiles(cfg config.Config, pins []*os.File) *fileService {
	state, e := g.Store.ProtectionDirectory(context.Background())
	if e != nil {
		return nil
	}
	defer state.Close()
	exe, e := os.Open("/proc/self/exe")
	if e != nil {
		return nil
	}
	defer exe.Close()
	release, e := fileaccess.PinAbsolute(cfg.Paths.Releases)
	if e != nil {
		return nil
	}
	defer release.Close()
	guard, e := fileaccess.New(append(append([]*os.File{}, pins...), state, exe, release))
	if e != nil {
		return nil
	}
	guard.EnableSharedRoots()
	guard.ReserveName(".serverdeck-" + g.AgentID)
	// The persisted baseline is explicitly unknown until a reviewed accounting
	// and identity proof exists. Do not infer completeness from an empty table.
	inventory, e := g.Store.OwnedInventory(context.Background())
	if e != nil || inventory.Baseline != "unknown" {
		guard.Close()
		return nil
	}
	return &fileService{guard: guard, tickets: map[string]*readTicket{}, reads: make(chan struct{}, 4)}
}
