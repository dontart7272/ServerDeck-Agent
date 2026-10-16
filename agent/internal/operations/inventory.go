// SPDX-License-Identifier: Apache-2.0
package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/storage"
)

type inventoryHandler struct{ s *storage.Store }

func (inventoryHandler) Validate(raw []byte) error {
	if _, e := contracts.Validate(bytes.NewReader(raw), contracts.Target{Family: "api", Definition: "InventoryConfirmationInput"}, 65536); e != nil {
		return storage.ErrInvalid
	}
	var p storage.InventoryConfirmation
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil {
		return storage.ErrInvalid
	}
	return storage.ValidateInventoryConfirmation(p)
}
func (inventoryHandler) Keys(Request) ([]string, error) {
	return []string{"storage.maintenance", "files.mutations", "settings.runtime"}, nil
}
func (inventoryHandler) Check(context.Context, Request) error { return nil }
func (h inventoryHandler) Effect(ctx context.Context, r Request) Outcome {
	var p storage.InventoryConfirmation
	json.Unmarshal(r.Params, &p)
	if e := h.s.ConfirmInventory(ctx, r.ID, p); e != nil {
		return Outcome{State: "unknown", Effect: "unknown", Code: "RECOVERY_REQUIRED", Result: []byte("null")}
	}
	return Outcome{State: "succeeded", Effect: "applied", Result: []byte(`{"inventory_attested":true}`)}
}
