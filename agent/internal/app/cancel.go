// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"context"
	"encoding/json"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/operations"
	"serverdeck.local/agent/internal/storage"
	"strconv"
)

type cancelParams struct {
	Target   string `json:"target_operation_id"`
	Expected string `json:"expected_version"`
}
type cancelHandler struct{ g *Gateway }

func (h cancelHandler) Validate(b []byte) error {
	if _, e := contracts.Parse(bytes.NewReader(b), 4096); e != nil {
		return e
	}
	var p cancelParams
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || !storage.ValidID(p.Target) || len(p.Expected) < 1 || len(p.Expected) > 256 {
		return storage.ErrInvalid
	}
	return nil
}
func (h cancelHandler) Keys(r operations.Request) ([]string, error) {
	var p cancelParams
	json.Unmarshal(r.Params, &p)
	return []string{"operations.control:" + p.Target}, nil
}
func (h cancelHandler) Check(ctx context.Context, r operations.Request) error {
	var p cancelParams
	json.Unmarshal(r.Params, &p)
	if p.Target == r.ID {
		return storage.ErrInvalid
	}
	o, e := h.g.Operations.Get(ctx, p.Target)
	if e != nil {
		return e
	}
	if strconv.FormatInt(o.Revision, 10) != p.Expected {
		return storage.ErrVersion
	}
	return nil
}
func (h cancelHandler) Effect(ctx context.Context, r operations.Request) operations.Outcome {
	var p cancelParams
	json.Unmarshal(r.Params, &p)
	v, e := strconv.ParseInt(p.Expected, 10, 64)
	if e != nil {
		return outcomeError(storage.ErrVersion)
	}
	state, e := h.g.Operations.CancelAudited(ctx, r.ID, p.Target, v, r.Credential)
	if e != nil {
		return outcomeError(e)
	}
	b, _ := json.Marshal(map[string]string{"target_operation_id": p.Target, "state": state})
	return operations.Outcome{State: "succeeded", Effect: "applied", Result: b}
}
