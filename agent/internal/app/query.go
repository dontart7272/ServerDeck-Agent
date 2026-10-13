// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"serverdeck.local/agent/internal/auth"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/storage"
)

type cursorValue struct {
	Version                   int `json:"version"`
	Agent, Epoch, Kind, Scope string
	Position                  int64
	Expires                   int64
	Nonce                     string
}

func scope(raw []byte) string {
	var p map[string]any
	json.Unmarshal(raw, &p)
	delete(p, "cursor")
	delete(p, "limit")
	b, _ := json.Marshal(p)
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:])
}
func (g *Gateway) cursor(kind, epoch, scope string, position int64) (string, error) {
	nonce, e := auth.RandomSecret(16)
	if e != nil {
		return "", e
	}
	b, _ := json.Marshal(cursorValue{Version: 1, Agent: g.AgentID, Epoch: epoch, Kind: kind, Scope: scope, Position: position, Expires: time.Now().Add(15 * time.Minute).Unix(), Nonce: nonce})
	return g.Store.SignCursor(b)
}
func (g *Gateway) position(token, kind, scope string) (cursorValue, error) {
	if token == "" {
		return cursorValue{}, nil
	}
	b, e := g.Store.VerifyCursor(token)
	if e != nil {
		return cursorValue{}, storage.ErrCursor
	}
	if _, e = contracts.Parse(bytes.NewReader(b), 1024); e != nil {
		return cursorValue{}, storage.ErrCursor
	}
	var c cursorValue
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || c.Version != 1 || c.Agent != g.AgentID || !storage.ValidID(c.Epoch) || c.Kind != kind || c.Scope != scope || c.Position < 0 {
		return c, storage.ErrCursor
	}
	if c.Expires <= time.Now().Unix() {
		return c, errors.New("CURSOR_EXPIRED")
	}
	return c, nil
}
func coverage() map[string]any {
	return map[string]any{"from": nil, "to": nil, "complete": true, "gaps": []any{}}
}
func page(items []any, next any, revision string) map[string]any {
	return map[string]any{"items": items, "next_cursor": next, "coverage": coverage(), "revision": revision}
}

type queryParams struct {
	Cursor      string `json:"cursor"`
	Limit       int    `json:"limit"`
	State       string `json:"state"`
	OperationID string `json:"operation_id"`
	From        string `json:"from"`
	To          string `json:"to"`
}

func (g *Gateway) Query(ctx context.Context, name string, raw []byte) (any, error) {
	var p queryParams
	json.Unmarshal(raw, &p)
	if p.Limit == 0 {
		p.Limit = 100
	}
	digest := scope(raw)
	switch name {
	case "snapshot.get", "processes.list", "processes.get":
		return g.metricQuery(ctx, name, raw)
	case "agent.info":
		return g.info(), nil
	case "config.get":
		b, revision, e := g.Store.Settings(ctx)
		if e != nil {
			return nil, e
		}
		var runtimeConfig any
		if json.Unmarshal(b, &runtimeConfig) != nil {
			return nil, storage.ErrStorage
		}
		return map[string]any{"version": strconv.FormatInt(revision, 10), "runtime": runtimeConfig}, nil
	case "devices.list":
		devices, e := g.Store.Devices(ctx)
		if e != nil {
			return nil, e
		}
		// Bind pagination to a coherent registry snapshot, excluding observational last_seen.
		var registry strings.Builder
		for _, d := range devices {
			fmt.Fprintf(&registry, "%s:%d;", d.ID, d.Revision)
		}
		registryHash := sha256.Sum256([]byte(registry.String()))
		digest += hex.EncodeToString(registryHash[:])
		c, e := g.position(p.Cursor, name, digest)
		if e != nil {
			return nil, e
		}
		if c.Epoch != "" && c.Epoch != g.RunID {
			return nil, storage.ErrCursor
		}
		if c.Position > int64(len(devices)) {
			return nil, storage.ErrCursor
		}
		items := []any{}
		pos := c.Position
		for pos < int64(len(devices)) && len(items) < p.Limit {
			d := devices[pos]
			items = append(items, map[string]any{"device_id": d.ID, "name": d.Name, "version": strconv.FormatInt(d.Revision, 10), "created_at": timestamp(time.UnixMicro(d.Created)), "last_seen_at": optionalTime(d.LastSeen), "revoked_at": optionalTime(d.RevokedAt)})
			pos++
		}
		var next any
		if pos < int64(len(devices)) {
			next, e = g.cursor(name, g.RunID, digest, pos)
		}
		return page(items, next, g.RunID), e
	case "operations.list":
		c, e := g.position(p.Cursor, name, digest)
		if e != nil {
			return nil, e
		}
		changes, epoch, last, e := g.Store.OperationPage(ctx, c.Epoch, c.Position, p.Limit, p.State)
		if e != nil {
			return nil, e
		}
		items := []any{}
		for _, v := range changes {
			items = append(items, operationWire(v.Operation))
		}
		token, e := g.cursor(name, epoch, digest, last)
		if e != nil {
			return nil, e
		}
		var next any
		if last > c.Position {
			next = token
		}
		return page(items, next, epoch+":"+strconv.FormatInt(last, 10)), nil
	case "audit.list":
		c, e := g.position(p.Cursor, name, digest)
		if e != nil {
			return nil, e
		}
		entries, floor, epoch, e := g.Store.AuditPage(ctx, c.Epoch, c.Position, p.Limit)
		if e != nil {
			return nil, e
		}
		items := []any{}
		last := c.Position
		for _, a := range entries {
			last = a.Seq
			if p.OperationID != "" && p.OperationID != a.OperationID {
				continue
			}
			at := time.UnixMicro(a.At)
			if p.From != "" {
				from, _ := time.Parse(time.RFC3339Nano, p.From)
				if at.Before(from) {
					continue
				}
			}
			if p.To != "" {
				to, _ := time.Parse(time.RFC3339Nano, p.To)
				if !at.Before(to) {
					continue
				}
			}
			items = append(items, map[string]any{"epoch": epoch, "sequence": strconv.FormatInt(a.Seq, 10), "operation_id": a.OperationID, "kind": a.Kind, "initiator": initiatorWire(a.Actor), "action": a.Action, "object_ref": a.Object, "observed_at": timestamp(at), "effect_status": a.Effect, "code": a.Code})
		}
		var next any
		if len(entries) == p.Limit {
			next, e = g.cursor(name, epoch, digest, last)
		}
		result := page(items, next, epoch+":"+strconv.FormatInt(last, 10))
		if floor > 0 {
			result["coverage"].(map[string]any)["complete"] = false
		}
		return result, e
	default:
		return nil, errors.New("SOURCE_UNAVAILABLE")
	}
}
func optionalTime(v *int64) any {
	if v == nil {
		return nil
	}
	return timestamp(time.UnixMicro(*v))
}
func initiatorWire(actor string) map[string]any {
	parts := strings.SplitN(actor, ":", 2)
	if len(parts) != 2 {
		return map[string]any{"kind": "system", "id": "unknown"}
	}
	return map[string]any{"kind": parts[0], "id": parts[1]}
}
func operationWire(o storage.Operation) map[string]any {
	var result any
	if len(o.Result) != 0 {
		json.Unmarshal(o.Result, &result)
	}
	var errValue any
	if o.Code != "" && o.Code != "ADMIN_RESOLUTION" {
		code := errorCode(errors.New(o.Code))
		if code == "INVALID_REQUEST" {
			code = "STORAGE_UNAVAILABLE"
		}
		errValue = map[string]any{"code": code, "message": code, "retryable": false, "operation_id": o.ID}
	}
	var expires any
	if o.Expires > 0 {
		expires = timestamp(time.UnixMicro(o.Expires))
	}
	return map[string]any{"operation_id": o.ID, "revision": strconv.FormatInt(o.Revision, 10), "initiator": initiatorWire(o.Actor), "action": o.Action, "object_ref": "operation", "state": o.State, "phase": o.Phase, "created_at": timestamp(time.UnixMicro(o.Created)), "updated_at": timestamp(time.UnixMicro(o.Updated)), "effect_status": o.Effect, "audit_status": o.AuditStatus, "cancellable": o.State == "preparing", "progress": nil, "result": result, "error": errValue, "dedup_until": expires}
}
func (g *Gateway) storageInfo() map[string]any {
	h := g.Store.Health()
	status := "ok"
	var reason any
	if !h.Available || !h.AuditAvailable {
		status = "degraded"
		reason = "STORAGE_UNAVAILABLE"
	}
	if !h.SecurityFloorAvailable {
		status = "degraded"
		reason = "SAFETY_UNAVAILABLE"
	}
	return map[string]any{"kind": "critical", "status": status, "used_bytes": strconv.FormatInt(h.AllocatedBytes, 10), "budget_bytes": "128000000", "wal_bytes": strconv.FormatInt(h.WALBytes, 10), "reserve_bytes": "8000000", "reason": reason}
}
func (g *Gateway) info() map[string]any {
	sources := []any{}
	if g.Metrics != nil {
		sources = g.Metrics.Sources()
	}
	fingerprint := ""
	expiry := time.Now()
	if g.Certificate != nil {
		fingerprint = auth.Fingerprint(g.Certificate)
		expiry = g.Certificate.NotAfter
	}
	caps := []any{}
	for _, id := range []string{"agent.info", "devices.list", "devices.revoke", "config.get", "operations.list", "operations.cancel", "audit.list", "transport.https", "transport.wss"} {
		caps = append(caps, map[string]any{"id": id, "available": true, "reason": nil, "version": "1"})
	}
	for _, id := range []string{"history.get", "files", "modules", "events", "problems"} {
		caps = append(caps, map[string]any{"id": id, "available": false, "reason": "NOT_IMPLEMENTED", "version": "1"})
	}
	for _, id := range []string{"snapshot.get", "processes.list", "processes.get"} {
		var reason any = "NOT_IMPLEMENTED"
		if g.MetricsFailure != "" {
			reason = g.MetricsFailure
		}
		if g.Metrics != nil {
			reason = nil
		}
		caps = append(caps, map[string]any{"id": id, "available": g.Metrics != nil, "reason": reason, "version": "1"})
	}
	return map[string]any{"agent_id": g.AgentID, "agent_run_id": g.RunID, "version": "0.4.0-e04", "api_majors": []int{1}, "ipc_min": "1.0.0", "ipc_max": "1.0.0", "ui_schema": 1, "runtime": map[string]any{"user": g.RuntimeUser, "uid": os.Geteuid(), "gid": os.Getegid(), "root_warning": os.Geteuid() == 0}, "capabilities": caps, "storage": []any{g.storageInfo()}, "limits": map[string]any{"json_bytes": 1000000, "history_bytes": 4000000, "history_points": 2000, "process_page": 100, "active_operations": 4, "file_transfers": 2}, "tls": map[string]any{"fingerprint_sha256": fingerprint, "not_after": timestamp(expiry), "rotation_warning": time.Until(expiry) <= 30*24*time.Hour}, "sources": sources}
}
