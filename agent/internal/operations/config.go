// SPDX-License-Identifier: Apache-2.0
package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"

	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/storage"
)

type ConfigHandler struct{ Store *storage.Store }

func (h ConfigHandler) Validate(b []byte) error {
	_, e := contracts.Validate(bytes.NewReader(b), contracts.Target{Family: "api", Definition: "ConfigChanges"}, 65536)
	return e
}
func (h ConfigHandler) Keys(Request) ([]string, error) { return []string{"settings"}, nil }
func (h ConfigHandler) merged(ctx context.Context, r Request) ([]byte, int64, error) {
	b, v, e := h.Store.Settings(ctx)
	if e != nil {
		return nil, 0, e
	}
	if r.Expected != strconv.FormatInt(v, 10) {
		return nil, 0, storage.ErrVersion
	}
	var current contracts.RuntimeConfig
	if json.Unmarshal(b, &current) != nil {
		return nil, 0, storage.ErrStorage
	}
	merged, e := contracts.ApplyRuntimeChanges(current, bytes.NewReader(r.Params))
	if e != nil {
		return nil, 0, storage.ErrInvalid
	}
	b, e = json.Marshal(merged)
	return b, v, e
}
func (h ConfigHandler) Check(ctx context.Context, r Request) error {
	_, _, e := h.merged(ctx, r)
	return e
}
func (h ConfigHandler) Effect(ctx context.Context, r Request) Outcome {
	b, v, e := h.merged(ctx, r)
	if e != nil {
		return Outcome{State: "failed", Effect: "none", Code: "VERSION_CONFLICT"}
	}
	if e = h.Store.ApplySettings(ctx, r.ID, v, b); e != nil {
		if e == storage.ErrVersion {
			return Outcome{State: "failed", Effect: "none", Code: "VERSION_CONFLICT"}
		}
		return Outcome{State: "unknown", Effect: "unknown", Code: "STORAGE_UNAVAILABLE"}
	}
	result, _ := json.Marshal(map[string]string{"version": strconv.FormatInt(v+1, 10)})
	return Outcome{State: "succeeded", Effect: "applied", Result: result}
}
