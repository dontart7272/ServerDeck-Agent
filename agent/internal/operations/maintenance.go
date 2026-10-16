// SPDX-License-Identifier: Apache-2.0
package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"os"

	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/fileaccess"
	"serverdeck.local/agent/internal/storage"
)

type maintenanceParams struct {
	Destination string `json:"destination"`
	Backup      string `json:"backup,omitempty"`
}
type maintenanceHandler struct {
	store   *storage.Store
	restore bool
}

func (h maintenanceHandler) Validate(b []byte) error {
	if _, e := contracts.Parse(bytes.NewReader(b), 4096); e != nil {
		return storage.ErrInvalid
	}
	var p maintenanceParams
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || !contracts.CleanAbsolutePath(p.Destination) || len(p.Destination) > 1024 {
		return storage.ErrInvalid
	}
	if h.restore {
		if !contracts.CleanAbsolutePath(p.Backup) || len(p.Backup) > 1024 {
			return storage.ErrInvalid
		}
	} else if p.Backup != "" {
		return storage.ErrInvalid
	}
	return nil
}
func (h maintenanceHandler) Keys(Request) ([]string, error) {
	return []string{"storage.maintenance"}, nil
}
func (h maintenanceHandler) Check(_ context.Context, r Request) error {
	var p maintenanceParams
	json.Unmarshal(r.Params, &p)
	if _, e := os.Lstat(p.Destination); !os.IsNotExist(e) {
		return storage.ErrSafety
	}
	return nil
}
func (h maintenanceHandler) Effect(ctx context.Context, r Request) Outcome {
	var p maintenanceParams
	json.Unmarshal(r.Params, &p)
	var e error
	if h.restore {
		e = h.store.Restore(ctx, r.ID, p.Backup, p.Destination)
	} else {
		e = h.store.Backup(ctx, r.ID, p.Destination)
	}
	if e != nil {
		return Outcome{State: "unknown", Effect: "unknown", Code: "RECOVERY_REQUIRED"}
	}
	return Outcome{State: "succeeded", Effect: "applied", Result: []byte(`{"complete":true}`)}
}
func Offline(s *storage.Store) *Service {
	return New(s, map[string]Handler{"files.reconcile": fileReconcileHandler{s: s}, "storage.inventory.confirm": inventoryHandler{s}, "storage.backup": maintenanceHandler{store: s}, "storage.restore": maintenanceHandler{store: s, restore: true}})
}
func OfflineWithFileProtection(s *storage.Store, g *fileaccess.Guard) *Service {
	svc := Offline(s)
	svc.handlers["files.reconcile"] = fileReconcileHandler{s: s, protection: g}
	return svc
}
func MaintenanceParams(destination, backup string) []byte {
	b, _ := json.Marshal(maintenanceParams{destination, backup})
	return b
}
