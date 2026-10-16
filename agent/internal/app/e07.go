// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/diagnostics"
	"serverdeck.local/agent/internal/metrics"
	"serverdeck.local/agent/internal/operations"
	"serverdeck.local/agent/internal/storage"
	"strconv"
	"time"
)

type processParams struct {
	Ref string `json:"process_ref"`
}
type processHandler struct {
	g    *Gateway
	kill bool
}

func (h processHandler) Validate(raw []byte) error {
	var p processParams
	if decodeStrict(raw, &p) != nil || len(p.Ref) != 32 {
		return storage.ErrInvalid
	}
	if _, e := hex.DecodeString(p.Ref); e != nil {
		return storage.ErrInvalid
	}
	return nil
}
func (h processHandler) Keys(r operations.Request) ([]string, error) {
	var p processParams
	json.Unmarshal(r.Params, &p)
	return []string{"process:" + p.Ref}, nil
}
func (h processHandler) process(r operations.Request) (contracts.APIProcess, error) {
	var p processParams
	if h.Validate(r.Params) != nil || json.Unmarshal(r.Params, &p) != nil {
		return contracts.APIProcess{}, storage.ErrInvalid
	}
	if r.Expected != "" && r.Expected != p.Ref {
		return contracts.APIProcess{}, storage.ErrVersion
	}
	if h.g.Metrics == nil {
		return contracts.APIProcess{}, storage.ErrSafety
	}
	process, e := h.g.Metrics.Process(p.Ref)
	if e != nil {
		return process, errors.New("NOT_FOUND")
	}
	return process, nil
}
func (h processHandler) Check(ctx context.Context, r operations.Request) error {
	p, e := h.process(r)
	if e != nil {
		return e
	}
	return h.g.Control.Check(ctx, p)
}
func (h processHandler) Effect(ctx context.Context, r operations.Request) operations.Outcome {
	p, e := h.process(r)
	if e != nil {
		return e07NoEffect(e)
	}
	result, e := h.g.Control.Signal(ctx, p, h.kill)
	if e != nil {
		return e07NoEffect(e)
	}
	raw, _ := json.Marshal(result)
	return operations.Outcome{State: "succeeded", Effect: "applied", Result: raw}
}

type icmpParams struct {
	Version string `json:"target_version"`
}
type icmpHandler struct{ g *Gateway }

func (h icmpHandler) Validate(raw []byte) error {
	var p icmpParams
	if decodeStrict(raw, &p) != nil || !storage.SafeLabel(p.Version) {
		return storage.ErrInvalid
	}
	return nil
}
func (h icmpHandler) Keys(operations.Request) ([]string, error) {
	return []string{"diagnostics.icmp", "settings.runtime"}, nil
}
func (g *Gateway) icmpConfig(ctx context.Context) (diagnostics.Config, error) {
	raw, revision, e := g.Store.Settings(ctx)
	if e != nil {
		return diagnostics.Config{}, e
	}
	var runtime contracts.RuntimeConfig
	if json.Unmarshal(raw, &runtime) != nil {
		return diagnostics.Config{}, storage.ErrStorage
	}
	hash := sha256.Sum256(rawICMP(runtime))
	return diagnostics.Config{Target: runtime.ICMP.Target, Background: runtime.ICMP.BackgroundEnabled, Version: g.RunID + ":" + strconv.FormatInt(revision, 10) + ":" + hex.EncodeToString(hash[:8])}, nil
}
func rawICMP(r contracts.RuntimeConfig) []byte { b, _ := json.Marshal(r.ICMP); return b }
func (h icmpHandler) Check(ctx context.Context, r operations.Request) error {
	if h.Validate(r.Params) != nil {
		return storage.ErrInvalid
	}
	c, e := h.g.icmpConfig(ctx)
	if e != nil {
		return e
	}
	var p icmpParams
	json.Unmarshal(r.Params, &p)
	if p.Version != c.Version || r.Expected != "" && r.Expected != c.Version {
		return storage.ErrVersion
	}
	if c.Target == nil {
		return storage.ErrInvalid
	}
	return nil
}
func (h icmpHandler) Effect(ctx context.Context, r operations.Request) operations.Outcome {
	if e := h.Check(ctx, r); e != nil {
		return e07NoEffect(e)
	}
	c, e := h.g.icmpConfig(ctx)
	if e != nil {
		return e07NoEffect(e)
	}
	result, e := h.g.Diagnostics.Run(ctx, c)
	if e != nil {
		return e07NoEffect(e)
	}
	raw, _ := json.Marshal(result)
	return operations.Outcome{State: "succeeded", Effect: "applied", Result: raw}
}
func (g *Gateway) startDiagnostics() {
	ctx, cancel := context.WithCancel(context.Background())
	g.diagnosticsCancel = cancel
	g.diagnosticsDone = make(chan struct{})
	go func() {
		defer close(g.diagnosticsDone)
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				g.backgroundICMP(ctx)
			}
		}
	}()
}
func (g *Gateway) backgroundICMP(ctx context.Context) {
	c, e := g.icmpConfig(ctx)
	if e != nil || !c.Background || c.Target == nil {
		return
	}
	// Periodic monitoring is enabled by audited config.set, not a new change
	// operation every minute. It shares the manual probe budget and policy.
	policy, e := g.Store.Policy(ctx)
	if e != nil {
		return
	}
	for _, denied := range policy.DenyActions {
		if denied == "diagnostics.icmp.run" {
			return
		}
	}
	_, _ = g.Diagnostics.Run(ctx, c)
}

func decodeStrict(raw []byte, out any) error {
	if _, e := contracts.Parse(bytes.NewReader(raw), 65536); e != nil {
		return storage.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return storage.ErrInvalid
	}
	if d.Decode(new(any)) != io.EOF {
		return storage.ErrInvalid
	}
	return nil
}

// These errors occur before sending a signal or admitting a probe.
func e07NoEffect(e error) operations.Outcome {
	code := errorCode(e)
	return operations.Outcome{State: "rejected", Effect: "none", Code: code}
}

// Availability is advisory; the application service repeats all checks before sending.
func (g *Gateway) processActions(ctx context.Context, p contracts.APIProcess) contracts.APIProcess {
	var reason *string
	e := g.Control.Check(ctx, p)
	if e != nil {
		code := errorCode(e)
		reason = &code
	}
	p.Actions = nil
	policy, pe := g.Store.Policy(ctx)
	for _, action := range []string{"process.term", "process.kill"} {
		r := reason
		if pe != nil {
			code := "STORAGE_UNAVAILABLE"
			r = &code
		} else {
			for _, denied := range policy.DenyActions {
				if denied == action {
					code := "POLICY_DENIED"
					r = &code
				}
			}
		}
		p.Actions = append(p.Actions, struct {
			Id        string  `json:"id"`
			Available bool    `json:"available"`
			Reason    *string `json:"reason"`
			Version   string  `json:"version"`
		}{action, r == nil, r, p.ProcessRef})
	}
	return p
}
func (g *Gateway) processSnapshot(ctx context.Context, s metrics.Snapshot) metrics.Snapshot {
	for i := range s.Blocks {
		if s.Blocks[i].ID != "processes" {
			continue
		}
		for j, raw := range s.Blocks[i].Records {
			var p contracts.APIProcess
			if json.Unmarshal(raw, &p) == nil {
				p = g.processActions(ctx, p)
				s.Blocks[i].Records[j], _ = json.Marshal(p)
			}
		}
	}
	return s
}
