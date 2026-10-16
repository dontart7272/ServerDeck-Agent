// SPDX-License-Identifier: Apache-2.0
package events

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/netip"
	"strconv"
	"time"

	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/metrics"
	"serverdeck.local/agent/internal/storage"
)

// SSHObservation is input from a recognized source adapter, never arbitrary log
// text. Source includes its boot/inode generation; Position increases within it.
type SSHObservation struct {
	Source, Address string
	Stream          string
	Position        uint64
	At              time.Time
	Mono            time.Duration
}
type sshWindow struct {
	Source                       string
	QuietSince                   time.Duration
	HasQuiet                     bool
	Times                        []time.Duration
	First, Last                  time.Time
	Problem                      string
	LastRepeat                   time.Duration
	Span                         time.Duration
	Version                      string
	CoverageSince, RecoverySince time.Duration
	HasCoverage, HasRecovery     bool
}

func (e *Engine) SSHFailure(ctx context.Context, in SSHObservation) error {
	rules, readErr := e.store.EventRules(ctx)
	if readErr != nil {
		return readErr
	}
	enabled := false
	threshold := 5
	span := 5 * time.Minute
	repeat := time.Hour
	version := ""
	selector := "*"
	for _, r := range rules {
		if r.Id == "ssh.failures" && r.Kind == "ssh_window" {
			enabled = r.Enabled
			version = r.Version
			selector = r.ResourceSelector
			if r.Threshold != nil {
				threshold = int(*r.Threshold)
			}
			if r.DurationMs > 0 {
				span = time.Duration(r.DurationMs) * time.Millisecond
			}
			repeat = time.Duration(r.RepeatMs) * time.Millisecond
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	address, err := netip.ParseAddr(in.Address)
	if err != nil || !storage.SafeLabel(in.Source) || in.Position == 0 || in.Position > math.MaxInt64 || in.Mono < 0 {
		return storage.ErrInvalid
	}
	stream := in.Stream
	if stream == "" {
		stream = "ssh"
	}
	if !storage.SafeLabel(stream) {
		return storage.ErrInvalid
	}
	h := sha256.Sum256([]byte(stream + ":" + address.Unmap().String()))
	key := hex.EncodeToString(h[:])
	enabled = enabled && (selector == "*" || selector == "ssh:"+key)
	rows, _, _, err := e.store.Records(ctx, "offset", in.Source, 0, 0, 9223372036854775807, "", 1)
	if err != nil {
		return err
	}
	var previous struct{ Position uint64 }
	if len(rows) > 0 {
		if json.Unmarshal(rows[0].Data, &previous) != nil {
			return storage.ErrStorage
		}
		if in.Position <= previous.Position {
			return e.reconcileSSH(ctx, key, stream)
		}
	}
	if !enabled {
		b, _ := json.Marshal(struct{ Position uint64 }{in.Position})
		return e.store.Update(ctx, []storage.TelemetryRecord{{Kind: "offset", ID: in.Source, Series: in.Source, Start: 0, Stop: math.MaxInt64, Revision: int64(in.Position), Data: b}}, nil, nil)
	}
	if e.ssh == nil {
		e.ssh = map[string]sshWindow{}
	}
	window := e.ssh[key]
	if window.Version != version {
		window.Times = nil
		window.HasCoverage = false
		window.HasRecovery = false
		window.Version = version
	}
	if !window.HasCoverage {
		window.CoverageSince = in.Mono
		window.HasCoverage = true
	}
	window.Source = stream
	window.Span = span
	window.QuietSince = in.Mono
	window.HasQuiet = true
	if _, ok := e.ssh[key]; !ok && len(e.ssh) >= 4096 {
		e.failed = true
		return storage.ErrQuota
	}
	retained := []time.Duration{}
	for _, at := range window.Times {
		if in.Mono-at < span && in.Mono >= at {
			retained = append(retained, at)
		}
	}
	if len(retained) == 0 && window.Problem == "" {
		window.First = in.At
	}
	retained = append(retained, in.Mono)
	if len(retained) > 4096 {
		e.failed = true
		return storage.ErrQuota
	}
	window.Times = retained
	if window.First.IsZero() {
		window.First = in.At
	}
	window.Last = in.At
	offset, _ := json.Marshal(struct{ Position uint64 }{in.Position})
	records := []storage.TelemetryRecord{{Kind: "offset", ID: in.Source, Series: in.Source, Start: 0, Stop: 9223372036854775807, Revision: int64(in.Position), Data: offset}}
	changes := []storage.TelemetryRecord{}
	var observed *State
	if len(retained) >= threshold {
		kind := ""
		if window.Problem == "" {
			window.Problem, err = storage.RandomID()
			if err != nil {
				return err
			}
			kind = "begin"
		} else if in.Mono-window.LastRepeat >= repeat {
			kind = "repeat"
		}
		if kind != "" {
			window.LastRepeat = in.Mono
		}
		state := State{ID: window.Problem, Rule: "ssh.failures", Resource: "ssh:" + key, Status: "active", Version: version, Code: "SSH_AUTH_FAILURES", Since: window.First, At: in.At, LastRepeat: in.Mono, Source: stream}
		observed = &state
		b, _ := json.Marshal(state)
		records = append(records, storage.TelemetryRecord{Kind: "problem", ID: state.ID, Series: state.Resource, Start: in.At.UnixMicro(), Stop: 9223372036854775807, Revision: 1, Data: b})
		if kind != "" {
			id, err := storage.RandomID()
			if err != nil {
				return err
			}
			data, _ := json.Marshal(map[string]any{"event_id": id, "problem_id": state.ID, "kind": kind, "severity": "warning", "resource_id": state.Resource, "observed_at": in.At.UTC().Format(time.RFC3339Nano), "first_at": window.First.UTC().Format(time.RFC3339Nano), "last_at": in.At.UTC().Format(time.RFC3339Nano), "count": strconv.Itoa(len(retained)), "code": "SSH_AUTH_FAILURES", "details": map[string]any{"rule_id": "ssh.failures", "rule_version": version}})
			changes = append(changes, storage.TelemetryRecord{Kind: "event", ID: id, Start: in.At.UnixMicro(), Stop: in.At.UnixMicro(), Revision: 1, Data: data})
		}
		problem, _ := json.Marshal(map[string]any{"problem_id": state.ID, "rule_id": state.Rule, "resource_id": state.Resource, "state": state.Status, "since": state.Since.UTC().Format(time.RFC3339Nano), "observed_at": state.At.UTC().Format(time.RFC3339Nano), "severity": "warning", "code": state.Code})
		changes = append(changes, storage.TelemetryRecord{Kind: "problem", ID: state.ID, Start: in.At.UnixMicro(), Stop: in.At.UnixMicro(), Revision: 1, Data: problem})
	}
	if err = e.store.Update(ctx, records, changes, nil); err != nil {
		e.failed = true
		return err
	}
	e.ssh[key] = window
	if observed != nil {
		e.states[stateKey(observed.Rule, observed.Resource)] = *observed
	}
	e.failed = false
	return nil
}

// SSHSourceProgress reports a successfully parsed continuous source window,
// including quiet periods. Missing/rotated-unrecognized input is valid=false.
// A quiet source is not proof that the host is secure.
func (e *Engine) SSHSourceProgress(ctx context.Context, source string, at time.Time, mono time.Duration, valid bool) error {
	rules, err := e.store.EventRules(ctx)
	if err != nil {
		return err
	}
	rule := contracts.APIRule{}
	for _, r := range rules {
		if r.Id == "ssh.failures" {
			rule = r
		}
	}
	valid = valid && rule.Enabled
	e.mu.Lock()
	defer e.mu.Unlock()
	for key, w := range e.ssh {
		if w.Source != source {
			continue
		}
		if w.Version != rule.Version {
			w.Version = rule.Version
			w.Times = nil
			w.HasQuiet = false
			w.HasCoverage = false
			w.HasRecovery = false
			w.Span = time.Duration(rule.DurationMs) * time.Millisecond
		}
		span := w.Span
		if span <= 0 {
			span = 5 * time.Minute
		}
		if w.Problem == "" {
			if len(w.Times) == 0 || mono-w.Times[len(w.Times)-1] >= span {
				delete(e.ssh, key)
			}
			continue
		}
		stateKey := stateKey("ssh.failures", "ssh:"+key)
		v, ok := e.states[stateKey]
		if !ok {
			continue
		}
		// A prior recovery may have committed even though its acknowledgment was
		// lost. Reconcile durable truth before allocating another event ID.
		rows, _, _, readErr := e.store.Records(ctx, "problem", v.Resource, 0, 0, math.MaxInt64, "", 1)
		if readErr != nil {
			e.failed = true
			return readErr
		}
		if len(rows) == 0 {
			delete(e.states, stateKey)
			delete(e.ssh, key)
			continue
		}
		if !valid || rule.ResourceSelector != "*" && rule.ResourceSelector != v.Resource {
			w.HasQuiet = false
			v.Status = "source_unknown"
			e.ssh[key] = w
			e.states[stateKey] = v
			w.HasCoverage = false
			w.HasRecovery = false
			e.ssh[key] = w
			if err := e.persist(ctx, stateKey, v, "", metrics.Snapshot{At: contracts.Timestamp(at)}); err != nil {
				return err
			}
			continue
		}
		if !w.HasCoverage {
			w.HasCoverage = true
			w.CoverageSince = mono
			w.HasRecovery = false
		}
		if !w.HasQuiet {
			w.HasQuiet = true
			w.QuietSince = mono
			e.ssh[key] = w
			continue
		}
		count := 0
		for _, observed := range w.Times {
			if mono >= observed && mono-observed < span {
				count++
			}
		}
		threshold := 1.0
		if rule.RecoveryThreshold != nil {
			threshold = *rule.RecoveryThreshold
		}
		comparison := rule.RecoveryComparison
		if comparison == "" {
			comparison = "lt"
		}
		if mono < w.CoverageSince || mono-w.CoverageSince < span || !compare(comparison, float64(count), threshold) {
			w.HasRecovery = false
			e.ssh[key] = w
			continue
		}
		if !w.HasRecovery {
			w.HasRecovery = true
			w.RecoverySince = mono
		}
		e.ssh[key] = w
		if mono-w.RecoverySince < time.Duration(rule.RecoveryDurationMs)*time.Millisecond {
			continue
		}
		id, err := storage.RandomID()
		if err != nil {
			return err
		}
		data, _ := json.Marshal(map[string]any{"event_id": id, "problem_id": v.ID, "kind": "recovery", "severity": "warning", "resource_id": v.Resource, "observed_at": at.UTC().Format(time.RFC3339Nano), "first_at": v.Since.UTC().Format(time.RFC3339Nano), "last_at": at.UTC().Format(time.RFC3339Nano), "count": "1", "code": "SSH_WINDOW_QUIET", "details": map[string]any{"rule_id": "ssh.failures"}})
		removed, _ := json.Marshal(map[string]any{"problem_id": v.ID, "removed": true, "observed_at": at.UTC().Format(time.RFC3339Nano)})
		if err = e.store.Update(ctx, nil, []storage.TelemetryRecord{{Kind: "event", ID: id, Start: at.UnixMicro(), Stop: at.UnixMicro(), Revision: 1, Data: data}, {Kind: "problem", ID: v.ID, Start: at.UnixMicro(), Stop: at.UnixMicro(), Revision: 1, Data: removed}}, []string{v.ID}); err != nil {
			e.failed = true
			return err
		}
		delete(e.states, stateKey)
		delete(e.ssh, key)
	}
	return nil
}

// Caller holds e.mu. Source offsets and active state share the same SQLite
// transaction, so a duplicate offset proves which state actually committed.
func (e *Engine) reconcileSSH(ctx context.Context, key, stream string) error {
	rows, _, _, err := e.store.Records(ctx, "problem", "ssh:"+key, 0, 0, math.MaxInt64, "", 1)
	if err != nil {
		e.failed = true
		return err
	}
	if len(rows) > 0 {
		var s State
		if json.Unmarshal(rows[0].Data, &s) != nil {
			e.failed = true
			return storage.ErrStorage
		}
		e.states[stateKey(s.Rule, s.Resource)] = s
		if e.ssh == nil {
			e.ssh = map[string]sshWindow{}
		}
		w := e.ssh[key]
		w.Problem, w.Source, w.First, w.Version = s.ID, stream, s.Since, s.Version
		w.HasCoverage, w.HasRecovery = false, false
		e.ssh[key] = w
	}
	e.failed = false
	return nil
}
