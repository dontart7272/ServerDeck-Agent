// SPDX-License-Identifier: Apache-2.0
//go:build linux && cgo

package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"serverdeck.local/agent/internal/events"
	"serverdeck.local/agent/internal/metrics"
	"serverdeck.local/agent/internal/storage"
	"time"
)

func (g *Gateway) securityHooks() metrics.SecurityHooks {
	if g.Events == nil || g.eventsDB == nil {
		return metrics.SecurityHooks{}
	}
	return metrics.SecurityHooks{
		Anchor: func(raw []byte) (string, error) {
			params, _ := json.Marshal(raw)
			hash, err := g.Store.Fingerprint("system:security", "security.anchor", params, "")
			return hex.EncodeToString(hash), err
		},
		Observation: func(ctx context.Context, o metrics.AuthObservation) error {
			if (o.Code != "SSH_AUTH_SUCCESS" && o.Code != "AUTH_SOURCE_GAP") || !storage.SafeLabel(o.Source) || o.Position == 0 {
				return storage.ErrInvalid
			}
			hash := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", o.Source, o.Position, o.Code)))
			hash[6] = (hash[6] & 15) | 80
			hash[8] = (hash[8] & 63) | 128
			id := fmt.Sprintf("%x-%x-%x-%x-%x", hash[:4], hash[4:6], hash[6:8], hash[8:10], hash[10:16])
			severity := "info"
			if o.Code == "AUTH_SOURCE_GAP" {
				severity = "warning"
			}
			at := o.At.UTC().Format(time.RFC3339Nano)
			raw, _ := json.Marshal(map[string]any{"event_id": id, "problem_id": nil, "kind": "observation", "severity": severity, "resource_id": "security.ssh", "observed_at": at, "first_at": at, "last_at": at, "count": "1", "code": o.Code, "details": map[string]any{}})
			return g.eventsDB.Update(ctx, nil, []storage.TelemetryRecord{{Kind: "event", ID: id, Start: o.At.UnixMicro(), Stop: o.At.UnixMicro(), Revision: 1, Data: raw}}, nil)
		},
		Load: func(ctx context.Context, key string) ([]byte, error) {
			rows, _, _, err := g.eventsDB.Records(ctx, "cursor", key, 0, 0, math.MaxInt64, "", 1)
			if err != nil {
				return nil, err
			}
			if len(rows) == 0 {
				return nil, nil
			}
			return rows[0].Data, nil
		},
		Save: func(ctx context.Context, key string, raw []byte) error {
			var cursor struct{ Seq uint64 }
			if key != "ssh.auth" && key != "ssh.journal" || len(raw) > 4096 || json.Unmarshal(raw, &cursor) != nil || cursor.Seq < 1 || cursor.Seq > math.MaxInt64 {
				return storage.ErrInvalid
			}
			return g.eventsDB.Update(ctx, []storage.TelemetryRecord{{Kind: "cursor", ID: key, Series: key, Start: 0, Stop: math.MaxInt64, Revision: int64(cursor.Seq), Data: raw}}, nil, nil)
		},
		Failure: func(ctx context.Context, f metrics.AuthFailure) error {
			return g.Events.SSHFailure(ctx, events.SSHObservation{Source: f.Source, Stream: "ssh", Address: f.Address, Position: f.Position, At: f.At, Mono: f.Mono})
		},
		Progress: func(ctx context.Context, at time.Time, mono time.Duration, valid bool) error {
			return g.Events.SSHSourceProgress(ctx, "ssh", at, mono, valid)
		},
	}
}
