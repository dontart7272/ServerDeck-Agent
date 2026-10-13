// SPDX-License-Identifier: Apache-2.0
package metrics

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"serverdeck.local/agent/internal/contracts"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testBoot = "11111111-1111-4111-8111-111111111111"

func manual(now *Stamp) *Engine {
	e := &Engine{run: testBoot, boot: testBoot, segment: id(), revision: id(), sources: map[string]*source{}, clock: func() Stamp { return *now }, leases: map[string]time.Duration{}, views: map[string][]processView{}}
	for _, name := range []string{"system", "cpu", "memory", "network", "filesystems", "processes"} {
		e.sources[name] = &source{jobs: make(chan job, 1), block: block(name, *now, interval(name, false))}
	}
	return e
}
func stamp() Stamp { return Stamp{time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC), 0} }
func metricBlock(name string, now Stamp, value any, availability, reason string) Block {
	b := block(name, now, interval(name, false))
	measure(&b, "used_bytes", "ram", "byte", value, availability, reason, now)
	return b
}
func TestLastGoodPermissionFailureStaleAndClockSegment(t *testing.T) {
	now := stamp()
	e := manual(&now)
	b := metricBlock("memory", now, contracts.U64(42), "available", "")
	e.accept(result{"memory", job{now, 2000, e.segment}, Sample{Block: b}, nil})
	now.Mono = 2 * time.Second
	now.Wall = now.Wall.Add(2 * time.Second)
	e.accept(result{"memory", job{now, 2000, e.segment}, Sample{}, os.ErrPermission})
	out := e.Snapshot("detail", []string{"memory"}, nil)
	m := out.Blocks[0].Metrics[0]
	if m.Value != contracts.U64(42) || m.Freshness != "stale" || m.Availability != "permission_denied" || time.Time(*m.MeasuredAt).Equal(now.Wall) || !out.Partial {
		t.Fatal("lost last-good semantics", m)
	}
	// No raw error content enters the wire representation.
	raw, _ := json.Marshal(out)
	if bytes.Contains(raw, []byte("permission denied")) {
		t.Fatal("raw OS diagnostic leaked")
	}
	old := e.segment
	e.last = now
	now.Mono += time.Second
	now.Wall = now.Wall.Add(-time.Hour)
	e.schedule(now)
	if e.segment == old || len(e.sources["memory"].block.Metrics) != 0 {
		t.Fatal("clock segment did not invalidate old data")
	}
	e.accept(result{"memory", job{stamp(), 2000, old}, Sample{Block: b}, nil})
	if len(e.sources["memory"].block.Metrics) != 0 {
		t.Fatal("old in-flight result crossed segment")
	}
}
func TestStaleThresholdUsesMonotonicAndReadDoesNotRefresh(t *testing.T) {
	now := stamp()
	e := manual(&now)
	b := metricBlock("memory", now, contracts.U64(0), "available", "")
	e.accept(result{"memory", job{now, 2000, e.segment}, Sample{Block: b}, nil})
	for _, c := range []struct {
		at   time.Duration
		want string
	}{{5999 * time.Millisecond, "fresh"}, {6 * time.Second, "stale"}} {
		now.Mono = c.at
		now.Wall = now.Wall.Add(time.Millisecond)
		out := e.Snapshot("detail", []string{"memory"}, nil)
		m := out.Blocks[0].Metrics[0]
		if m.Freshness != c.want || m.Value != contracts.U64(0) || !time.Time(*m.MeasuredAt).Equal(stamp().Wall) {
			t.Fatal("freshness/valid zero", m)
		}
	}
}
func TestCadencesLeaseExpiryAndHungSourceBound(t *testing.T) {
	now := stamp()
	e := manual(&now)
	e.schedule(now)
	for name, s := range e.sources {
		j := <-s.jobs
		if j.interval != interval(name, false) {
			t.Fatal("wrong startup interval")
		}
		if name != "cpu" {
			e.accept(result{name, j, Sample{Block: block(name, now, j.interval)}, nil})
		}
	}
	for i := 0; i < 64; i++ {
		if err := e.Lease(string(rune(i + 1))); err != nil {
			t.Fatal(err)
		}
	}
	if !errors.Is(e.Lease("overflow"), ErrLimit) {
		t.Fatal("unbounded leases")
	}
	now.Mono = 2 * time.Second
	now.Wall = now.Wall.Add(2 * time.Second)
	e.schedule(now)
	if !e.sources["cpu"].busy || len(e.sources["cpu"].jobs) != 0 || e.sources["cpu"].block.Reason == nil {
		t.Fatal("hung source duplicated")
	}
	// Activation shortens the next process deadline to at most two seconds.
	now.Mono = 4 * time.Second
	now.Wall = now.Wall.Add(2 * time.Second)
	e.schedule(now)
	j := <-e.sources["processes"].jobs
	if j.interval != 2000 {
		t.Fatal("active cadence")
	}
	e.accept(result{"processes", j, Sample{Block: block("processes", now, j.interval)}, nil})
	now.Mono = 11 * time.Second
	now.Wall = now.Wall.Add(7 * time.Second)
	e.schedule(now)
	if len(e.leases) != 0 {
		t.Fatal("leases never expire")
	}
	if j := <-e.sources["processes"].jobs; j.interval != 5000 {
		t.Fatal("lease expiry did not restore five-second collection")
	}
	if interval("system", false) != 60000 || interval("filesystems", false) != 15000 || interval("processes", false) != 5000 {
		t.Fatal("cadence registry")
	}
}
func process(name, reference string, pid int64, cpu float64) contracts.APIProcess {
	now := stamp()
	b := block("processes", now, 5000)
	measure(&b, "cpu_percent", reference, "percent", cpu, "available", "", now)
	return contracts.APIProcess{Name: name, ProcessRef: reference, Pid: pid, Metrics: []contracts.APIMetric{wireMetric(b.Metrics[0])}}
}
func TestProcessPagesFilterSortTieIdentityTTLAndBounds(t *testing.T) {
	now := stamp()
	e := manual(&now)
	e.processRevision = id()
	e.processComplete = true
	e.processes = []contracts.APIProcess{process("worker", "c", 3, 100), process("other", "d", 4, 999), process("worker", "a", 1, 200), process("worker", "b", 2, 200)}
	first, rev, more, complete, err := e.Processes("deviceA", "", "worker", "cpu", "desc", 0, 1)
	if err != nil || first[0].ProcessRef != "a" || !more || !complete {
		t.Fatal(first, err)
	}
	e.processes = []contracts.APIProcess{process("new", "new", 1, 0)}
	e.processRevision = id()
	next, _, _, _, err := e.Processes("deviceA", rev, "worker", "cpu", "desc", 1, 1)
	if err != nil || next[0].ProcessRef != "b" {
		t.Fatal("page no longer stable", err)
	}
	if _, _, _, _, err = e.Processes("deviceB", rev, "worker", "cpu", "desc", 1, 1); !errors.Is(err, ErrExpired) {
		t.Fatal("cross-actor continuation")
	}
	if _, err = e.Process("a"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("stale process reference resolved to reused PID")
	}
	if _, _, _, _, err = e.Processes("deviceA", "", "", "pid", "asc", 0, 101); !errors.Is(err, ErrLimit) {
		t.Fatal("page limit")
	}
	now.Mono = 30 * time.Second
	if _, _, _, _, err = e.Processes("deviceA", rev, "worker", "cpu", "desc", 1, 1); !errors.Is(err, ErrExpired) {
		t.Fatal("TTL boundary")
	}
}

type counted struct {
	calls   [6]atomic.Int64
	blocked chan struct{}
}

func (c *counted) Collect(name string, s Stamp, ms int64, _ string) (Sample, error) {
	i := map[string]int{"system": 0, "cpu": 1, "memory": 2, "network": 3, "filesystems": 4, "processes": 5}[name]
	c.calls[i].Add(1)
	if name == "cpu" {
		<-c.blocked
		return Sample{}, errors.New("secret driver diagnostic")
	}
	return Sample{Block: block(name, s, ms)}, nil
}
func wait(t *testing.T, p func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !p() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func TestSharedCollectionNoClientsManyReadersAndNativeHang(t *testing.T) {
	c := &counted{blocked: make(chan struct{})}
	e := New(testBoot, testBoot, c)
	defer e.Close()
	defer close(c.blocked)
	wait(t, func() bool { return c.calls[2].Load() == 1 })
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				e.Snapshot("summary", nil, nil)
			}
		}()
	}
	wg.Wait()
	if c.calls[1].Load() != 1 || c.calls[2].Load() != 1 {
		t.Fatal("client reads multiplied collection")
	}
	wait(t, func() bool { return c.calls[2].Load() >= 2 })
	if c.calls[1].Load() != 1 {
		t.Fatal("hung collector multiplied")
	}
	out := e.Snapshot("detail", []string{"cpu", "memory"}, nil)
	if !out.Partial || out.Blocks[0].Availability != "source_error" || out.Blocks[1].Availability != "available" {
		t.Fatal("source isolation", out)
	}
}
func TestSnapshotWireContract(t *testing.T) {
	now := stamp()
	e := manual(&now)
	e.sources["memory"].block = metricBlock("memory", now, contracts.U64(0), "available", "")
	var out bytes.Buffer
	if err := contracts.Encode(&out, contracts.Target{Family: "api", Definition: "Snapshot"}, e.Snapshot("detail", nil, nil), contracts.MaxJSONBytes); err != nil {
		t.Fatal(err)
	}
}

func TestTwoProcessSnapshotsPerOwnerAndGlobalRetentionBound(t *testing.T) {
	now := stamp()
	e := manual(&now)
	e.processes = []contracts.APIProcess{process("worker", "a", 1, 1)}
	revs := []string{}
	for i := 0; i < 3; i++ {
		e.processRevision = id()
		_, rev, _, _, err := e.Processes("one", "", "", "pid", "asc", 0, 1)
		if err != nil {
			t.Fatal(err)
		}
		revs = append(revs, rev)
	}
	if _, _, _, _, err := e.Processes("one", revs[0], "", "pid", "asc", 0, 1); !errors.Is(err, ErrExpired) {
		t.Fatal("more than two retained snapshots")
	}
	for i := 0; i < 30; i++ {
		e.processRevision = id()
		if _, _, _, _, err := e.Processes(string(rune('b'+i)), "", "", "pid", "asc", 0, 1); err != nil {
			t.Fatal(err)
		}
	}
	e.processRevision = id()
	if _, _, _, _, err := e.Processes("overflow", "", "", "pid", "asc", 0, 1); !errors.Is(err, ErrLimit) {
		t.Fatal("unbounded retained generations")
	}
}

func TestScheduledIntervalsHaveExactBoundaries(t *testing.T) {
	for _, name := range []string{"system", "cpu", "memory", "network", "filesystems", "processes"} {
		t.Run(name, func(t *testing.T) {
			now := stamp()
			e := manual(&now)
			src := e.sources[name]
			e.sources = map[string]*source{name: src}
			e.schedule(now)
			j := <-src.jobs
			e.accept(result{name, j, Sample{Block: block(name, now, j.interval)}, nil})
			now.Mono = time.Duration(j.interval)*time.Millisecond - time.Nanosecond
			now.Wall = stamp().Wall.Add(now.Mono)
			e.schedule(now)
			if len(src.jobs) != 0 {
				t.Fatal("early collection")
			}
			now.Mono++
			now.Wall = stamp().Wall.Add(now.Mono)
			e.schedule(now)
			if len(src.jobs) != 1 {
				t.Fatal("missed scheduled boundary")
			}
		})
	}
}

func TestProcessFailureUpdatesAttemptWithoutRefreshingMeasurement(t *testing.T) {
	now := stamp()
	e := manual(&now)
	e.processes = []contracts.APIProcess{process("worker", "a", 1, 100)}
	e.processRevision = id()
	now.Wall = now.Wall.Add(5 * time.Second)
	now.Mono = 5 * time.Second
	e.accept(result{"processes", job{now, 5000, e.segment}, Sample{}, os.ErrPermission})
	p, err := e.Process("a")
	if err != nil {
		t.Fatal(err)
	}
	m := p.Metrics[0]
	if m.AttemptedAt != contracts.Timestamp(now.Wall) || time.Time(*m.MeasuredAt) != stamp().Wall || m.Availability != "permission_denied" || m.Freshness != "stale" {
		t.Fatal("process source failure timestamps", m)
	}
	*m.Reason = "CALLER_MUTATION"
	if *e.sources["processes"].block.Reason == "CALLER_MUTATION" {
		t.Fatal("returned reason mutated shared source")
	}
}

func TestPageRetentionDoesNotThrottleNormalThirtySecondWindow(t *testing.T) {
	now := stamp()
	e := manual(&now)
	e.processes = []contracts.APIProcess{process("worker", "a", 1, 100)}
	for i := 0; i < 16; i++ {
		e.processRevision = id()
		now.Mono = time.Duration(i) * 2 * time.Second
		now.Wall = stamp().Wall.Add(now.Mono)
		if _, _, _, _, err := e.Processes("phone-"+strconv.Itoa(i), "", "", "pid", "asc", 0, 1); err != nil {
			t.Fatal("normal shared cadence/TTL exhausted generations", i, err)
		}
	}
}
