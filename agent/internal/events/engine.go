// SPDX-License-Identifier: Apache-2.0
package events

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/metrics"
	"serverdeck.local/agent/internal/storage"
)

type State struct {
	PendingKind, PendingID                    string
	PendingData                               json.RawMessage
	ID, Rule, Resource, Status, Version, Code string
	Source                                    string
	Since, At                                 time.Time
	Pending, Recovery, LastRepeat             time.Duration
	HasPending, HasRecovery                   bool
}
type eventStore interface {
	Update(context.Context, []storage.TelemetryRecord, []storage.TelemetryRecord, []string) error
	Records(context.Context, string, string, int64, int64, int64, string, int) ([]storage.TelemetryRecord, string, int64, error)
	EventRules(context.Context) ([]contracts.APIRule, error)
	Reclaim(context.Context) error
}
type Engine struct {
	mu                sync.Mutex
	store             eventStore
	states            map[string]State
	failed            bool
	policyUnavailable bool
	segment           string
	ssh               map[string]sshWindow
	gapID             string
	gapData           json.RawMessage
	lostSince         time.Time
}

func New(ctx context.Context, s *storage.Telemetry) (*Engine, error) {
	e := &Engine{store: s, states: map[string]State{}}
	after := ""
	for {
		rows, _, _, err := s.Records(ctx, "problem", "", 0, math.MinInt64, math.MaxInt64, after, 100)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			var v State
			if json.Unmarshal(r.Data, &v) != nil || !storage.ValidID(v.ID) {
				return nil, storage.ErrStorage
			}
			v.Status = "source_unknown"
			v.HasPending = false
			v.HasRecovery = false
			v.LastRepeat = 0
			e.states[stateKey(v.Rule, v.Resource)] = v
			if v.Rule == "ssh.failures" {
				if e.ssh == nil {
					e.ssh = map[string]sshWindow{}
				}
				e.ssh[strings.TrimPrefix(v.Resource, "ssh:")] = sshWindow{Source: v.Source, First: v.Since, Last: v.At, Problem: v.ID}
			}
			after = r.ID
			if len(e.states) > 10000 {
				return nil, storage.ErrQuota
			}
		}
		if len(rows) < 100 {
			break
		}
	}
	return e, nil
}
func stateKey(rule, resource string) string {
	h := sha256.Sum256([]byte(rule + "\x00" + resource))
	return hex.EncodeToString(h[:])
}
func compare(op string, value, threshold float64) bool {
	switch op {
	case "lt":
		return value < threshold
	case "lte":
		return value <= threshold
	case "gt":
		return value > threshold
	case "gte":
		return value >= threshold
	}
	return false
}
func number(v any) (float64, bool) {
	switch v := v.(type) {
	case float64:
		return v, !math.IsNaN(v) && !math.IsInf(v, 0)
	case contracts.U64:
		return float64(v), true
	case uint64:
		return float64(v), true
	}
	return 0, false
}

// Observe uses caller monotonic elapsed time; pending durations never survive a
// segment change/restart or invalid observation. Lost sources cannot recover.
func (e *Engine) Observe(ctx context.Context, rules []contracts.APIRule, s metrics.Snapshot, mono time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.segment != s.SegmentID {
		for id, v := range e.states {
			v.HasPending = false
			v.HasRecovery = false
			if v.Status != "" {
				v.Status = "source_unknown"
			}
			e.states[id] = v
		}
		e.segment = s.SegmentID
	}
	seen := map[string]bool{}
	for _, rule := range rules {
		if !rule.Enabled || rule.Kind == "ssh_window" {
			continue
		}
		for _, b := range s.Blocks {
			if rule.Kind == "source_stale" {
				if b.ID == "security" {
					for _, m := range b.Metrics {
						if m.Key != "source_available" || m.Availability == "absent" || m.Availability == "unsupported" || rule.ResourceSelector != "*" && rule.ResourceSelector != m.ResourceID {
							continue
						}
						value := 1.0
						if m.Availability == "available" && m.Freshness == "fresh" {
							value = 0
						}
						effective := rule
						if m.MeasuredAt == nil {
							effective.DurationMs += 3 * m.Interval
						}
						key := stateKey(rule.Id, m.ResourceID)
						seen[key] = true
						if err := e.observe(ctx, effective, m.ResourceID, value, true, s, mono, key); err != nil {
							return err
						}
					}
					continue
				}

				if rule.ResourceSelector != "*" && rule.ResourceSelector != b.ID {
					continue
				}
				if b.Availability == "absent" || b.Availability == "unsupported" {
					continue
				}
				valid := b.Availability == "available" && len(b.Metrics) == 0
				for _, m := range b.Metrics {
					if m.Availability == "available" && m.Freshness == "fresh" {
						valid = true
					}
				}
				if b.Reason != nil && *b.Reason == "WARMING_UP" {
					continue
				}
				v := 0.0
				if !valid {
					v = 1
				}
				key := stateKey(rule.Id, b.ID)
				seen[key] = true
				effective := rule
				if b.ObservedAt == nil && b.Interval > 0 {
					effective.DurationMs += 3 * b.Interval
				}
				if err := e.observe(ctx, effective, b.ID, v, true, s, mono, key); err != nil {
					return err
				}
				continue
			}
			if strings.HasPrefix(rule.Id, "memory.") && b.ID != "memory" || strings.HasPrefix(rule.Id, "filesystem.") && b.ID != "filesystems" || strings.HasPrefix(rule.Id, "cpu.") && b.ID != "cpu" || strings.HasPrefix(rule.Id, "gpu.") && b.ID != "gpu" {
				continue
			}
			for _, m := range b.Metrics {
				value, ok := number(m.Value)
				metric := m.Key
				if metric == "available_bytes" && rule.Metric == "available_percent" {
					for _, total := range b.Metrics {
						if total.ResourceID == m.ResourceID && total.Key == "total_bytes" {
							n, valid := number(total.Value)
							if valid && n > 0 {
								value = 100 * value / n
								metric = "available_percent"
							} else {
								ok = false
							}
						}
					}
				}
				if metric == "inodes_available" && rule.Metric == "inodes_available_percent" {
					for _, total := range b.Metrics {
						if total.ResourceID == m.ResourceID && total.Key == "inodes_total" {
							n, valid := number(total.Value)
							if valid && n > 0 {
								value = 100 * value / n
								metric = "inodes_available_percent"
							} else {
								ok = false
							}
						}
					}
				}
				if metric != rule.Metric || (rule.ResourceSelector != "*" && rule.ResourceSelector != m.ResourceID) {
					continue
				}
				effectiveRule := rule
				if rule.Kind == "device_threshold" && b.ID != "gpu" {
					continue
				}
				if rule.Kind == "device_threshold" && (rule.Threshold == nil || rule.RecoveryThreshold == nil) {
					var threshold *float64
					for _, candidate := range b.Metrics {
						if candidate.ResourceID == m.ResourceID && candidate.Key == "temperature_threshold_c" && candidate.Availability == "available" && candidate.Freshness == "fresh" {
							if value, valid := number(candidate.Value); valid && value > 0 {
								threshold = &value
							}
						}
					}
					if threshold == nil {
						continue
					}
					if effectiveRule.Threshold == nil {
						effectiveRule.Threshold = threshold
						effectiveRule.Comparison = "gte"
					}
					if effectiveRule.RecoveryThreshold == nil {
						effectiveRule.RecoveryThreshold = threshold
						effectiveRule.RecoveryComparison = "lt"
					}
				}
				key := stateKey(rule.Id, m.ResourceID)
				seen[key] = true
				valid := ok && m.Availability == "available" && m.Freshness == "fresh"
				if err := e.observe(ctx, effectiveRule, m.ResourceID, value, valid, s, mono, key); err != nil {
					return err
				}
			}
		}
	}
	for key, v := range e.states {
		if v.Rule == "ssh.failures" {
			continue
		}
		if seen[key] {
			continue
		}
		if v.PendingKind != "" {
			if err := e.persist(ctx, key, v, v.PendingKind, s); err != nil {
				return err
			}
			var exists bool
			v, exists = e.states[key]
			if !exists {
				continue
			}
		}
		if v.Status == "" {
			delete(e.states, key)
			continue
		}
		v.Status = "source_unknown"
		v.HasPending = false
		v.HasRecovery = false
		if err := e.persist(ctx, key, v, "", s); err != nil {
			return err
		}
	}
	return nil
}
func (e *Engine) observe(ctx context.Context, r contracts.APIRule, resource string, value float64, valid bool, s metrics.Snapshot, mono time.Duration, key string) error {
	v := e.states[key]
	if v.PendingKind != "" {
		if err := e.persist(ctx, key, v, v.PendingKind, s); err != nil {
			return err
		}
		v = e.states[key]
	}
	if v.Version != r.Version {
		v.HasPending = false
		v.HasRecovery = false
		v.Version = r.Version
	}
	if v.ID == "" {
		if len(e.states) >= 10000 {
			e.failed = true
			return storage.ErrQuota
		}
		id, err := storage.RandomID()
		if err != nil {
			return err
		}
		v.ID = id
		v.Rule = r.Id
		v.Resource = resource
		v.Code = "THRESHOLD"
	}
	wall := time.Time(s.At)
	if !valid {
		v.HasPending = false
		v.HasRecovery = false
		if v.Status != "" {
			v.Status = "source_unknown"
			return e.persist(ctx, key, v, "", s)
		}
		delete(e.states, key)
		return nil
	}
	trigger, recover := false, false
	if r.Kind == "source_stale" {
		trigger = value == 1
		recover = value == 0
		v.Code = "SOURCE_UNAVAILABLE"
	} else {
		if r.Threshold != nil {
			trigger = compare(r.Comparison, value, *r.Threshold)
		}
		if r.RecoveryThreshold != nil {
			recover = compare(r.RecoveryComparison, value, *r.RecoveryThreshold)
		}
	}
	if v.Status == "" {
		if !trigger {
			delete(e.states, key)
			return nil
		}
		if !v.HasPending {
			v.HasPending = true
			v.Pending = mono
		}
		if mono-v.Pending >= time.Duration(r.DurationMs)*time.Millisecond {
			v.Status = "active"
			v.Since = wall
			v.At = wall
			v.LastRepeat = mono
			v.HasPending = false
			return e.persist(ctx, key, v, "begin", s)
		}
		e.states[key] = v
		return nil
	}
	if recover {
		if !v.HasRecovery {
			v.HasRecovery = true
			v.Recovery = mono
		}
		if mono-v.Recovery >= time.Duration(r.RecoveryDurationMs)*time.Millisecond {
			v.At = wall
			return e.persist(ctx, key, v, "recovery", s)
		}
	} else {
		v.HasRecovery = false
	}
	v.Status = "active"
	v.At = wall
	if mono-v.LastRepeat >= time.Duration(r.RepeatMs)*time.Millisecond {
		v.LastRepeat = mono
		return e.persist(ctx, key, v, "repeat", s)
	}
	return e.persist(ctx, key, v, "", s)
}
func (e *Engine) persist(ctx context.Context, key string, v State, kind string, s metrics.Snapshot) error {
	changes := []storage.TelemetryRecord{}
	deletes := []string{}
	if kind != "" {
		if v.PendingKind != kind || !storage.ValidID(v.PendingID) {
			id, err := storage.RandomID()
			if err != nil {
				return err
			}
			v.PendingID = id
			v.PendingKind = kind
			wire := map[string]any{"event_id": id, "problem_id": v.ID, "kind": kind, "severity": "warning", "resource_id": v.Resource, "observed_at": time.Time(s.At).UTC().Format(time.RFC3339Nano), "first_at": v.Since.UTC().Format(time.RFC3339Nano), "last_at": time.Time(s.At).UTC().Format(time.RFC3339Nano), "count": "1", "code": v.Code, "details": map[string]any{"rule_id": v.Rule, "rule_version": v.Version}}
			v.PendingData, _ = json.Marshal(wire)
		}
		var payload struct {
			Observed string `json:"observed_at"`
		}
		if json.Unmarshal(v.PendingData, &payload) != nil {
			return storage.ErrStorage
		}
		at, err := time.Parse(time.RFC3339Nano, payload.Observed)
		if err != nil {
			return storage.ErrStorage
		}
		changes = append(changes, storage.TelemetryRecord{Kind: "event", ID: v.PendingID, Series: v.Resource, Start: at.UnixMicro(), Stop: at.UnixMicro(), Revision: 1, Data: v.PendingData})
	}
	saved := v
	saved.PendingKind = ""
	saved.PendingID = ""
	saved.PendingData = nil
	b, _ := json.Marshal(saved)
	revision := time.Time(s.At).UnixMicro()
	if revision < 1 {
		revision = 1
	}
	records := []storage.TelemetryRecord{{Kind: "problem", ID: v.ID, Series: v.Resource, Segment: s.SegmentID, Start: v.Since.UnixMicro(), Stop: math.MaxInt64, Revision: revision, Data: b}}
	if e.failed {
		if e.gapID == "" {
			id, err := storage.RandomID()
			if err != nil {
				return err
			}
			e.gapID = id
			since := e.lostSince
			if since.IsZero() {
				since = time.Time(s.At)
			}
			e.gapData, _ = json.Marshal(map[string]any{"event_id": id, "problem_id": nil, "kind": "gap", "severity": "warning", "resource_id": "agent.events", "observed_at": time.Time(s.At).UTC().Format(time.RFC3339Nano), "first_at": since.UTC().Format(time.RFC3339Nano), "last_at": time.Time(s.At).UTC().Format(time.RFC3339Nano), "count": "1", "code": "EVENT_COVERAGE_UNKNOWN", "details": map[string]any{}})
		}
		var gap struct {
			Observed string `json:"observed_at"`
		}
		if json.Unmarshal(e.gapData, &gap) != nil {
			return storage.ErrStorage
		}
		gapAt, err := time.Parse(time.RFC3339Nano, gap.Observed)
		if err != nil {
			return storage.ErrStorage
		}
		changes = append([]storage.TelemetryRecord{{Kind: "event", ID: e.gapID, Start: gapAt.UnixMicro(), Stop: gapAt.UnixMicro(), Revision: 1, Data: e.gapData}}, changes...)
	}
	if kind == "recovery" {
		records = nil
		deletes = append(deletes, v.ID)
	}
	problemWire := map[string]any{"problem_id": v.ID, "rule_id": v.Rule, "resource_id": v.Resource, "state": v.Status, "since": v.Since.UTC().Format(time.RFC3339Nano), "observed_at": v.At.UTC().Format(time.RFC3339Nano), "severity": "warning", "code": v.Code}
	if kind == "recovery" {
		problemWire = map[string]any{"problem_id": v.ID, "removed": true, "observed_at": time.Time(s.At).UTC().Format(time.RFC3339Nano)}
	}
	problemData, _ := json.Marshal(problemWire)
	changes = append(changes, storage.TelemetryRecord{Kind: "problem", ID: v.ID, Start: time.Time(s.At).UnixMicro(), Stop: time.Time(s.At).UnixMicro(), Revision: 1, Data: problemData})
	if err := e.store.Update(ctx, records, changes, deletes); err != nil {
		e.failed = true
		if errors.Is(err, storage.ErrQuota) {
			_ = e.store.Reclaim(ctx)
		}
		if e.lostSince.IsZero() {
			e.lostSince = time.Time(s.At)
		}
		v.Status = "source_unknown"
		e.states[key] = v
		return err
	}
	if kind == "recovery" {
		delete(e.states, key)
	} else {
		e.states[key] = saved
	}
	e.failed = false
	e.gapID = ""
	e.gapData = nil
	e.lostSince = time.Time{}
	return nil
}
func (e *Engine) Problems() []any {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := []any{}
	keys := []string{}
	for k := range e.states {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := e.states[k]
		if v.Status == "" {
			continue
		}
		out = append(out, map[string]any{"problem_id": v.ID, "rule_id": v.Rule, "resource_id": v.Resource, "state": v.Status, "since": v.Since.UTC().Format(time.RFC3339Nano), "observed_at": v.At.UTC().Format(time.RFC3339Nano), "severity": "warning", "code": v.Code})
	}
	return out
}
func (e *Engine) Health() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.failed || e.policyUnavailable
}

// PolicyUnavailable is independent of the ability to append diagnostics.
func (e *Engine) PolicyUnavailable(unavailable bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policyUnavailable = unavailable
	if unavailable {
		for key, state := range e.states {
			state.Status = "source_unknown"
			state.HasPending, state.HasRecovery = false, false
			e.states[key] = state
		}
	}
}

func EventWire(r storage.TelemetryRecord, epoch string) map[string]any {
	var v map[string]any
	json.Unmarshal(r.Data, &v)
	v["epoch"] = epoch
	v["sequence"] = strconv.FormatInt(r.Revision, 10)
	return v
}
