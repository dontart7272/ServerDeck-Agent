// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"time"

	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/operations"
	"serverdeck.local/agent/internal/storage"
)

type telemetryConfigHandler struct{ g *Gateway }

func (h telemetryConfigHandler) Validate(b []byte) error {
	var p struct {
		Changes json.RawMessage `json:"changes"`
	}
	if json.Unmarshal(b, &p) != nil {
		return storage.ErrInvalid
	}
	var groups map[string]json.RawMessage
	if json.Unmarshal(p.Changes, &groups) != nil || len(groups) == 0 {
		return storage.ErrInvalid
	}
	for group := range groups {
		if group != "history" && group != "events" && group != "audit" && group != "icmp" && group != "files" {
			return operations.ErrAction
		}
	}
	return nil
}
func (h telemetryConfigHandler) Keys(operations.Request) ([]string, error) {
	return []string{"settings.runtime"}, nil
}
func (h telemetryConfigHandler) prepare(ctx context.Context, r operations.Request) (contracts.RuntimeConfig, int64, error) {
	b, revision, err := h.g.Store.Settings(ctx)
	if err != nil {
		return contracts.RuntimeConfig{}, 0, err
	}
	expected, err := strconv.ParseInt(r.Expected, 10, 64)
	if err != nil || revision != expected {
		return contracts.RuntimeConfig{}, 0, storage.ErrVersion
	}
	var current contracts.RuntimeConfig
	if json.Unmarshal(b, &current) != nil {
		return current, 0, storage.ErrStorage
	}
	var p struct {
		Changes json.RawMessage `json:"changes"`
	}
	if json.Unmarshal(r.Params, &p) != nil {
		return current, 0, storage.ErrInvalid
	}
	next, err := contracts.ApplyRuntimeChanges(current, bytes.NewReader(p.Changes))
	return next, revision, err
}
func (h telemetryConfigHandler) Check(ctx context.Context, r operations.Request) error {
	_, _, err := h.prepare(ctx, r)
	return err
}
func (h telemetryConfigHandler) Effect(ctx context.Context, r operations.Request) operations.Outcome {
	next, version, err := h.prepare(ctx, r)
	if err != nil {
		return outcomeError(err)
	}
	previousBytes, _, err := h.g.Store.Settings(ctx)
	var previous contracts.RuntimeConfig
	if err != nil || json.Unmarshal(previousBytes, &previous) != nil {
		return outcomeError(storage.ErrStorage)
	}
	b, _ := json.Marshal(next)
	if err = h.g.Store.ApplySettings(ctx, r.ID, version, b); err != nil {
		return outcomeError(err)
	}
	pending := func(code string) operations.Outcome {
		result, _ := json.Marshal(map[string]any{"version": strconv.FormatInt(version+1, 10), "cleanup_operation_id": r.ID})
		return operations.Outcome{State: "unknown", Effect: "partial", Code: code, Result: result}
	}
	if h.g.historyDB != nil {
		if err = h.g.historyDB.SetBudget(next.History.BudgetBytes); err != nil {
			_ = h.g.historyDB.Reclaim(ctx)
			if err = h.g.historyDB.SetBudget(next.History.BudgetBytes); err != nil {
				return pending(err.Error())
			}
		}
	}
	if h.g.eventsDB != nil {
		if err = h.g.eventsDB.SetBudget(next.Events.BudgetBytes); err != nil {
			_ = h.g.eventsDB.Reclaim(ctx)
			if err = h.g.eventsDB.SetBudget(next.Events.BudgetBytes); err != nil {
				return pending(err.Error())
			}
		}
	}
	if next.Events.RetentionDays < previous.Events.RetentionDays {
		if h.g.eventsDB == nil {
			return pending("CLEANUP_PENDING")
		}
		before := time.Now().Add(-time.Duration(next.Events.RetentionDays) * 24 * time.Hour).UnixMicro()
		left, readErr := h.g.eventsDB.RetentionPending(ctx, before)
		if readErr != nil {
			return pending("CLEANUP_PENDING")
		}
		if left {
			if !h.g.Store.RetentionClockTrusted(ctx) {
				return pending("CLEANUP_PENDING")
			}
			if err = h.g.eventsDB.Prune(ctx, before, 100000); err != nil {
				return pending("CLEANUP_PENDING")
			}
			left, readErr = h.g.eventsDB.RetentionPending(ctx, before)
			if readErr != nil || left {
				return pending("CLEANUP_PENDING")
			}
		}
	}
	if next.Audit.RetentionDays < previous.Audit.RetentionDays {
		before := time.Now().Add(-time.Duration(next.Audit.RetentionDays) * 24 * time.Hour).UnixMicro()
		left, readErr := h.g.Store.AuditRetentionPending(ctx, before)
		if readErr != nil || left {
			return pending("CLEANUP_PENDING")
		}
	}
	result, _ := json.Marshal(map[string]any{"version": strconv.FormatInt(version+1, 10), "cleanup_operation_id": nil})
	return operations.Outcome{State: "succeeded", Effect: "applied", Result: result}
}
