// SPDX-License-Identifier: Apache-2.0
package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"serverdeck.local/agent/internal/contracts"
	"sort"
	"strings"
	"sync"
	"time"
)

type job struct {
	stamp    Stamp
	interval int64
	segment  string
}
type result struct {
	name   string
	job    job
	sample Sample
	err    error
}
type source struct {
	jobs      chan job
	busy      bool
	started   time.Duration
	due       time.Duration
	block     Block
	attempted contracts.Timestamp
}
type processView struct {
	id       string
	expires  time.Duration
	segment  string
	items    []contracts.APIProcess
	complete bool
	mono     time.Duration
}
type Engine struct {
	mu                           sync.Mutex
	run, boot, segment, revision string
	collector                    Collector
	sources                      map[string]*source
	results                      chan result
	cancel                       context.CancelFunc
	done                         chan struct{}
	clock                        func() Stamp
	last                         Stamp
	leases                       map[string]time.Duration
	views                        map[string][]processView
	processes                    []contracts.APIProcess
	processComplete              bool
	processRevision              string
	processMono                  time.Duration
}

// New starts exactly one worker for each source. A blocked native call occupies
// that worker; timeout cannot create another worker or stop the syscall.
func New(run, boot string, c Collector) *Engine {
	start := time.Now()
	return newEngine(run, boot, c, func() Stamp { n := time.Now(); return Stamp{n, n.Sub(start)} })
}
func newEngine(run, boot string, c Collector, clock func() Stamp) *Engine {
	ctx, cancel := context.WithCancel(context.Background())
	e := &Engine{run: run, boot: boot, segment: id(), revision: id(), collector: c, results: make(chan result, 6), cancel: cancel, done: make(chan struct{}), clock: clock, sources: map[string]*source{}, leases: map[string]time.Duration{}, views: map[string][]processView{}}
	for _, name := range []string{"system", "cpu", "memory", "network", "filesystems", "processes"} {
		src := &source{jobs: make(chan job, 1), block: Block{ID: name, Mode: "periodic", Interval: interval(name, false), Metrics: []Metric{}, Records: []json.RawMessage{}, Availability: "source_error", Reason: ptr("WARMING_UP")}}
		e.sources[name] = src
		go func(name string, src *source) {
			for {
				select {
				case <-ctx.Done():
					return
				case j := <-src.jobs:
					if ctx.Err() != nil {
						return
					}
					s, err := safeCollect(c, name, j)
					select {
					case e.results <- result{name, j, s, err}:
					case <-ctx.Done():
						return
					}
				}
			}
		}(name, src)
	}
	go e.loop(ctx)
	return e
}
func safeCollect(c Collector, name string, j job) (s Sample, err error) {
	defer func() {
		if recover() != nil {
			err = ErrUnavailable
		}
	}()
	return c.Collect(name, j.stamp, j.interval, j.segment)
}
func interval(name string, active bool) int64 {
	switch name {
	case "system":
		return 60000
	case "filesystems":
		return 15000
	case "processes":
		if !active {
			return 5000
		}
	}
	return 2000
}
func (e *Engine) loop(ctx context.Context) {
	defer close(e.done)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	e.schedule(e.clock())
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			e.schedule(e.clock())
		case r := <-e.results:
			e.accept(r)
		}
	}
}
func (e *Engine) schedule(now Stamp) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.last.Wall.IsZero() {
		drift := now.Wall.Sub(e.last.Wall) - (now.Mono - e.last.Mono)
		if drift > time.Second || drift < -time.Second || now.Wall.Before(e.last.Wall) {
			e.segment = id()
			e.views = map[string][]processView{}
			e.processes = nil
			e.processRevision = ""
			for _, s := range e.sources {
				s.due = now.Mono
				s.block = Block{ID: s.block.ID, Mode: "periodic", Interval: s.block.Interval, Metrics: []Metric{}, Records: []json.RawMessage{}, Availability: "source_error", Reason: ptr("CLOCK_CHANGED")}
			}
		}
	}
	e.last = now
	for key, expiry := range e.leases {
		if expiry <= now.Mono {
			delete(e.leases, key)
		}
	}
	for key, views := range e.views {
		var keep []processView
		for _, v := range views {
			if v.expires > now.Mono {
				keep = append(keep, v)
			}
		}
		if len(keep) == 0 {
			delete(e.views, key)
		} else {
			e.views[key] = keep
		}
	}
	active := len(e.leases) > 0
	for name, s := range e.sources {
		ms := interval(name, active)
		if name == "processes" && ms < s.block.Interval && s.due > now.Mono+2*time.Second {
			s.due = now.Mono + 2*time.Second
		}
		if s.busy {
			if now.Mono-s.started >= time.Duration(ms)*time.Millisecond {
				s.block.Availability = "source_error"
				s.block.Reason = ptr("SOURCE_TIMEOUT")
				for i := range s.block.Metrics {
					m := &s.block.Metrics[i]
					m.Availability = "source_error"
					m.Reason = s.block.Reason
					m.AttemptedAt = s.attempted
					if m.Value != nil {
						m.Freshness = "stale"
					}
				}
			}
			continue
		}
		if now.Mono < s.due {
			continue
		}
		s.busy = true
		s.started = now.Mono
		s.attempted = contracts.Timestamp(now.Wall.UTC())
		for i := range s.block.Metrics {
			s.block.Metrics[i].AttemptedAt = s.attempted
		}
		s.due = now.Mono + time.Duration(ms)*time.Millisecond
		s.jobs <- job{now, ms, e.segment}
	}
}
func (e *Engine) accept(r result) {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.sources[r.name]
	s.busy = false
	if r.job.segment != e.segment {
		s.due = 0
		return
	}
	s.attempted = contracts.Timestamp(r.job.stamp.Wall.UTC())
	if r.err != nil {
		s.block.Availability = "source_error"
		s.block.Reason = ptr("SOURCE_ERROR")
		if errors.Is(r.err, errPermission) {
			s.block.Availability = "permission_denied"
			s.block.Reason = ptr("PERMISSION_DENIED")
		}
		for i := range s.block.Metrics {
			m := &s.block.Metrics[i]
			m.Availability = s.block.Availability
			m.Reason = s.block.Reason
			m.AttemptedAt = contracts.Timestamp(r.job.stamp.Wall.UTC())
			if m.Value != nil {
				m.Freshness = "stale"
			}
		}
	} else {
		// Retain last-good values for individual optional fields, without changing
		// their measurement timestamps or claiming a successful derivative baseline.
		old := map[string]Metric{}
		for _, m := range s.block.Metrics {
			old[m.ResourceID+"/"+m.Key] = m
		}
		for i, m := range r.sample.Block.Metrics {
			if m.Value == nil {
				if p, ok := old[m.ResourceID+"/"+m.Key]; ok && p.Value != nil {
					m.Value = p.Value
					m.MeasuredAt = p.MeasuredAt
					m.measuredMono = p.measuredMono
					m.Freshness = "stale"
					r.sample.Block.Metrics[i] = m
				}
			}
		}
		s.block = r.sample.Block
		if r.name == "processes" {
			e.processes = r.sample.Processes
			e.processComplete = s.block.Reason == nil
			e.processRevision = id()
			e.processMono = r.job.stamp.Mono
		}
	}
	e.revision = id()
}

// Lease only changes the shared process cadence. It never starts a collector.
// At most 64 trusted consumers, each automatically expires after ten seconds.
func (e *Engine) Lease(owner string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.leases[owner]; !ok && len(e.leases) >= 64 {
		return ErrLimit
	}
	e.leases[owner] = e.clock().Mono + 10*time.Second
	return nil
}
func (e *Engine) Release(owner string) { e.mu.Lock(); delete(e.leases, owner); e.mu.Unlock() }
func (e *Engine) Close()               { e.cancel(); <-e.done }
func contains(xs []string, s string) bool {
	for _, v := range xs {
		if v == s {
			return true
		}
	}
	return false
}
func (e *Engine) Snapshot(view string, blocks, resources []string) Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.clock()
	out := Snapshot{e.revision, e.run, e.boot, e.segment, contracts.Timestamp(now.Wall.UTC()), []Block{}, false}
	for _, name := range []string{"system", "cpu", "memory", "network", "filesystems", "processes"} {
		if len(blocks) > 0 && !contains(blocks, name) {
			continue
		}
		s := e.sources[name]
		b := s.block
		if b.ObservedAt != nil {
			v := *b.ObservedAt
			b.ObservedAt = &v
		}
		if b.Reason != nil {
			b.Reason = ptr(*b.Reason)
		}
		b.Metrics = append([]Metric{}, b.Metrics...)
		b.Records = make([]json.RawMessage, len(s.block.Records))
		for i, r := range s.block.Records {
			b.Records[i] = append(json.RawMessage{}, r...)
		}
		for i := range b.Metrics {
			m := &b.Metrics[i]
			if m.MeasuredAt != nil {
				v := *m.MeasuredAt
				m.MeasuredAt = &v
			}
			if m.Reason != nil {
				m.Reason = ptr(*m.Reason)
			}
			if m.MeasuredAt != nil && now.Mono-m.measuredMono >= time.Duration(3*m.Interval)*time.Millisecond {
				m.Freshness = "stale"
			}
			if m.Availability != "available" || m.Freshness != "fresh" {
				out.Partial = true
			}
		}
		if name == "processes" {
			b.Records = []json.RawMessage{}
			items := sortProcesses(e.processes, "", "cpu", "desc")
			limit := 100
			if view == "summary" {
				limit = 10
			}
			for i, p := range items {
				if len(resources) > 0 && !contains(resources, p.ProcessRef) {
					continue
				}
				if len(b.Records) >= limit {
					b.Reason = ptr("PAGE_REQUIRED")
					break
				}
				_ = i
				rendered := e.renderProcesses([]contracts.APIProcess{p}, e.processMono, now)[0]
				for _, m := range rendered.Metrics {
					if m.Availability != "available" || m.Freshness != "fresh" {
						out.Partial = true
					}
				}
				record(&b, rendered)
			}
		}
		if len(resources) > 0 {
			ms := []Metric{}
			for _, m := range b.Metrics {
				if contains(resources, m.ResourceID) {
					ms = append(ms, m)
				}
			}
			b.Metrics = ms
			rs := []json.RawMessage{}
			for _, r := range b.Records {
				var v struct {
					Resource string `json:"resource_id"`
					Process  string `json:"process_ref"`
				}
				_ = json.Unmarshal(r, &v)
				if contains(resources, v.Resource) || contains(resources, v.Process) {
					rs = append(rs, r)
				}
			}
			b.Records = rs
		}
		if b.Availability != "available" || b.Reason != nil {
			out.Partial = true
		}
		out.Blocks = append(out.Blocks, b)
	}
	return out
}
func sortProcesses(items []contracts.APIProcess, search, by, order string) []contracts.APIProcess {
	out := []contracts.APIProcess{}
	for _, p := range items {
		if strings.Contains(strings.ToLower(p.Name), strings.ToLower(search)) {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		cmp := 0
		switch by {
		case "name":
			cmp = strings.Compare(a.Name, b.Name)
		case "cpu", "rss":
			key := "cpu_percent"
			if by == "rss" {
				key = "rss_bytes"
			}
			av, aok := processNumber(a, key)
			bv, bok := processNumber(b, key)
			if aok != bok {
				return aok
			}
			if av < bv {
				cmp = -1
			} else if av > bv {
				cmp = 1
			}
		default:
			if a.Pid < b.Pid {
				cmp = -1
			} else if a.Pid > b.Pid {
				cmp = 1
			}
		}
		if cmp == 0 {
			return a.ProcessRef < b.ProcessRef
		}
		if order == "desc" {
			return cmp > 0
		}
		return cmp < 0
	})
	return out
}
func processNumber(p contracts.APIProcess, key string) (float64, bool) {
	for _, m := range p.Metrics {
		if m.Key == key && m.Value != nil && m.Freshness == "fresh" && m.Availability == "available" {
			var n float64
			if json.Unmarshal(*m.Value, &n) == nil {
				return n, true
			}
			var u contracts.U64
			if json.Unmarshal(*m.Value, &u) == nil {
				return float64(u), true
			}
		}
	}
	return 0, false
}

// Pages hold shared immutable process slices, not per-client copies. Two
// snapshots per trusted owner, max 64 owners. Sort/filter always precede slicing.
func (e *Engine) Processes(owner, revision, search, by, order string, offset, limit int) ([]contracts.APIProcess, string, bool, bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if limit < 1 || limit > 100 || offset < 0 {
		return nil, "", false, false, ErrLimit
	}
	now := e.clock()
	var v processView
	if revision == "" {
		if e.processRevision == "" {
			return nil, "", false, false, ErrUnavailable
		}
		if _, ok := e.views[owner]; !ok && len(e.views) >= 64 {
			return nil, "", false, false, ErrLimit
		}
		unique := map[string]bool{}
		for _, vs := range e.views {
			for _, v := range vs {
				if v.expires > now.Mono {
					unique[v.id] = true
				}
			}
		}
		if !unique[e.processRevision] && len(unique) >= 32 {
			return nil, "", false, false, ErrLimit
		}
		v = processView{e.processRevision, now.Mono + 30*time.Second, e.segment, e.processes, e.processComplete, e.processMono}
		vs := e.views[owner]
		if len(vs) == 0 || vs[len(vs)-1].id != v.id {
			vs = append(vs, v)
			if len(vs) > 2 {
				vs = vs[len(vs)-2:]
			}
			e.views[owner] = vs
		}
	} else {
		for _, p := range e.views[owner] {
			if p.id == revision && p.segment == e.segment && p.expires > now.Mono {
				v = p
				break
			}
		}
		if v.id == "" {
			return nil, "", false, false, ErrExpired
		}
	}
	items := sortProcesses(v.items, search, by, order)
	if offset > len(items) {
		return nil, "", false, false, ErrExpired
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	return e.renderProcesses(items[offset:end], v.mono, now), v.id, end < len(items), v.complete, nil
}
func (e *Engine) Process(ref string) (contracts.APIProcess, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, p := range e.processes {
		if p.ProcessRef == ref {
			return e.renderProcesses([]contracts.APIProcess{p}, e.processMono, e.clock())[0], nil
		}
	}
	return contracts.APIProcess{}, ErrUnavailable
}

func (e *Engine) Sources() []any {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := []any{}
	for _, name := range []string{"system", "cpu", "memory", "network", "filesystems", "processes"} {
		b := e.sources[name].block
		out = append(out, map[string]any{"id": "linux." + name, "available": b.Availability == "available", "reason": b.Reason, "version": "1"})
	}
	return out
}

func (e *Engine) renderProcesses(items []contracts.APIProcess, mono time.Duration, now Stamp) []contracts.APIProcess {
	out := append([]contracts.APIProcess{}, items...)
	for i := range out {
		clone := func(p *string) *string {
			if p == nil {
				return nil
			}
			return ptr(*p)
		}
		out[i].ParentRef = clone(out[i].ParentRef)
		out[i].SystemdUnit = clone(out[i].SystemdUnit)
		out[i].ContainerId = clone(out[i].ContainerId)
		out[i].Cgroup = clone(out[i].Cgroup)
		out[i].Metrics = append([]contracts.APIMetric{}, out[i].Metrics...)
		for j := range out[i].Metrics {
			m := &out[i].Metrics[j]
			m.Reason = clone(m.Reason)
			if m.MeasuredAt != nil {
				v := *m.MeasuredAt
				m.MeasuredAt = &v
			}
			if m.ExpectedIntervalMs != nil {
				v := *m.ExpectedIntervalMs
				m.ExpectedIntervalMs = &v
			}
			if m.Value != nil {
				value := append(json.RawMessage{}, (*m.Value)...)
				m.Value = &value
			}
			if e.sources["processes"].block.Availability != "available" {
				m.Availability = e.sources["processes"].block.Availability
				m.Reason = clone(e.sources["processes"].block.Reason)
				m.AttemptedAt = e.sources["processes"].attempted
				if m.MeasuredAt != nil {
					m.Freshness = "stale"
				}
			}
			if m.MeasuredAt != nil && m.ExpectedIntervalMs != nil && now.Mono-mono >= time.Duration(3**m.ExpectedIntervalMs)*time.Millisecond {
				m.Freshness = "stale"
			}
		}
	}
	return out
}
