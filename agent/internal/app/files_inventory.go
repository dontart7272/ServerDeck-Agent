// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"encoding/json"
	"serverdeck.local/agent/internal/fileaccess"
	"serverdeck.local/agent/internal/storage"
)

// Production derives eligibility from the current durable attestation on EVERY
// entry and stream chunk. The private bool exists only for controlled fixtures.
func (g *Gateway) filesReady(ctx context.Context) error {
	if g.Files == nil {
		return storage.ErrSafety
	}
	if g.Files.inventoryVerified {
		return nil
	}
	if e := g.Files.guard.ValidateBindings(); e != nil {
		return storage.ErrSafety
	}
	inventory, e := g.Store.VerifiedInventory(ctx)
	if e != nil {
		return storage.ErrSafety
	}
	att := inventory.Attestation
	covered := map[string]bool{}
	for _, region := range att.Regions {
		f, e := fileaccess.PinAbsolute(region.Path)
		if e != nil {
			return storage.ErrSafety
		}
		proof, e := fileaccess.IdentityProof(f)
		if e != nil || proof != region.Proof {
			f.Close()
			return storage.ErrSafety
		}
		e = g.Files.guard.Protect(f)
		f.Close()
		if e != nil {
			return storage.ErrSafety
		}
		covered[region.Path] = true
	}
	absent := map[string]bool{}
	for _, id := range att.Absent {
		absent[id] = true
	}
	for _, record := range inventory.Artifacts {
		region := record.LocationHint
		for _, binding := range att.Bindings {
			if binding.ID == record.ID {
				region = binding.Region
				break
			}
		}
		if !covered[region] && !absent[record.ID] {
			return storage.ErrSafety
		}
	}
	// Re-register private staging/trash identities after restart. Missing proof
	// never means absence; incomplete journal records keep the gate closed.
	for _, kind := range []string{"transfer", "trash"} {
		records, e := g.Store.FileRecords(ctx, kind)
		if e != nil {
			return storage.ErrSafety
		}
		for _, record := range records {
			if record.State == "published" || record.State == "purged" || record.State == "restored" {
				continue
			}
			var root, proof, areaProof string
			if kind == "transfer" {
				var spec writeSpec
				if json.Unmarshal(record.Document, &spec) != nil {
					return storage.ErrSafety
				}
				root, proof, areaProof = spec.RootPath, spec.Proof, spec.AreaProof
			} else {
				var spec trashSpec
				if json.Unmarshal(record.Document, &spec) != nil {
					return storage.ErrSafety
				}
				root, proof, areaProof = spec.RootPath, spec.Proof, spec.AreaProof
			}
			if proof == "" || areaProof == "" {
				g.Files.mu.Lock()
				active := g.Files.inflight[record.ID]
				g.Files.mu.Unlock()
				if active && record.State == "planned" {
					continue
				}
				return storage.ErrSafety
			}
			area, e := g.Files.guard.OpenArea(root, g.AgentID)
			if e != nil {
				return storage.ErrSafety
			}
			actual, e := area.Proof()
			if e != nil || actual != areaProof {
				area.Close()
				return storage.ErrSafety
			}
			e = area.ProtectTree(record.ID, proof)
			area.Close()
			if e != nil {
				return storage.ErrSafety
			}
		}
	}
	return nil
}
