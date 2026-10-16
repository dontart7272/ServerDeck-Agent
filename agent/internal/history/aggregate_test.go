// SPDX-License-Identifier: Apache-2.0
package history

import (
	"math"
	"reflect"
	"sync"
	"testing"
	"time"
)

var epoch = time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)

func window(step time.Duration, kind Kind) Window {
	return Window{Series: "cpu.busy", Segment: "run-1", Start: epoch, Step: step, Revision: 1, Kind: kind, Closed: true}
}

func interval(start, end int, value float64) Interval {
	return Interval{From: epoch.Add(time.Duration(start) * time.Second), To: epoch.Add(time.Duration(end) * time.Second), Covered: time.Duration(end-start) * time.Second, Value: value}
}

func mustAggregate(t *testing.T, w Window, in []Interval) Bucket {
	t.Helper()
	b, err := Aggregate(w, in)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestWeightedCoverageAndTiers(t *testing.T) {
	w := window(15*time.Second, Gauge)
	a := mustAggregate(t, w, []Interval{interval(0, 2, 10), interval(2, 10, 30)})
	if a.Mean != 26 || a.Maximum != 30 || a.Last != 30 || a.Covered != 10*time.Second || a.Complete {
		t.Fatalf("bad partial: %+v", a)
	}
	w.Start = epoch.Add(15 * time.Second)
	b := mustAggregate(t, w, []Interval{interval(15, 20, 2)})
	minute, err := Rollup(window(time.Minute, Gauge), []Bucket{a, b})
	if err != nil || minute.Mean != 18 || minute.Covered != 15*time.Second || minute.SampleCount != 3 || minute.Last != 2 || minute.Maximum != 30 || minute.Complete {
		t.Fatalf("weighted rollup: %+v %v", minute, err)
	}
	five, err := Rollup(window(5*time.Minute, Gauge), []Bucket{minute})
	if err != nil || five.Mean != minute.Mean || five.Covered != minute.Covered || five.SampleCount != 3 {
		t.Fatalf("5m rollup: %+v %v", five, err)
	}
}

func TestCounterExactSumRatesAndOverflow(t *testing.T) {
	w := window(15*time.Second, CounterDelta)
	a := interval(0, 2, 0)
	a.Delta = 100
	b := interval(3, 8, 0)
	b.Delta = 10
	x := mustAggregate(t, w, []Interval{a, b})
	if x.Sum != 110 || x.Mean != 110.0/7 || x.Maximum != 50 || x.Last != 2 || x.Covered != 7*time.Second {
		t.Fatalf("rates: %+v", x)
	}
	a.Delta = (1 << 53) + 1
	x = mustAggregate(t, w, []Interval{a})
	w.Start = epoch.Add(15 * time.Second)
	b = interval(15, 16, 0)
	b.Delta = 3
	y := mustAggregate(t, w, []Interval{b})
	z, err := Rollup(window(time.Minute, CounterDelta), []Bucket{x, y})
	if err != nil || z.Sum != (1<<53)+4 {
		t.Fatalf("precision lost: %+v %v", z, err)
	}
	a.Delta = math.MaxUint64
	b = interval(3, 4, 0)
	b.Delta = 1
	if _, err = Aggregate(window(15*time.Second, CounterDelta), []Interval{a, b}); err != ErrInput {
		t.Fatal("sum overflow accepted")
	}
	x = mustAggregate(t, window(15*time.Second, CounterDelta), []Interval{a})
	if _, err = Rollup(window(time.Minute, CounterDelta), []Bucket{x, y}); err != ErrInput {
		t.Fatal("rollup overflow accepted")
	}
}

func TestMissingZeroAndPartialRevision(t *testing.T) {
	w := window(15*time.Second, Gauge)
	empty := mustAggregate(t, w, nil)
	if empty.HasValue || empty.Complete || empty.Covered != 0 {
		t.Fatal("missing became zero")
	}
	w.Closed = false
	partial := mustAggregate(t, w, []Interval{interval(0, 15, 0)})
	if !partial.HasValue || partial.Complete {
		t.Fatal("open zero window")
	}
	w.Closed = true
	w.Revision = 2
	closed := mustAggregate(t, w, []Interval{interval(0, 15, 0)})
	if !closed.Complete || closed.Revision <= partial.Revision || closed.Start != partial.Start || closed.Segment != partial.Segment {
		t.Fatal("partial replacement identity")
	}
}

func TestBoundaryObservationPreservesMaximumWithoutInventingTraffic(t *testing.T) {
	w := window(15*time.Second, CounterDelta)
	point := Interval{From: epoch.Add(time.Second), To: epoch.Add(time.Second), Value: 100, ObservationOnly: true}
	b := mustAggregate(t, w, []Interval{point})
	if b.Covered != 0 || b.Sum != 0 || !b.HasValue || b.Maximum != 100 || b.Complete {
		t.Fatalf("invented boundary traffic: %+v", b)
	}
	parent, err := Rollup(window(time.Minute, CounterDelta), []Bucket{b})
	if err != nil || parent.Maximum != 100 || parent.Covered != 0 || parent.Sum != 0 {
		t.Fatal(parent, err)
	}
	if _, err = Aggregate(w, []Interval{point, point}); err != ErrInput {
		t.Fatal("duplicate observation")
	}
	point.Value = -1
	if _, err = Aggregate(w, []Interval{point}); err != ErrInput {
		t.Fatal("negative rate")
	}
}

func TestRejectAmbiguousInput(t *testing.T) {
	base := window(15*time.Second, Gauge)
	for name, change := range map[string]func(*Window){
		"unaligned": func(w *Window) { w.Start = w.Start.Add(time.Nanosecond) },
		"tier":      func(w *Window) { w.Step = 2 * time.Second },
		"series":    func(w *Window) { w.Series = "" },
		"segment":   func(w *Window) { w.Segment = "" },
		"revision":  func(w *Window) { w.Revision = 0 },
		"kind":      func(w *Window) { w.Kind = 0 },
		"zero time": func(w *Window) { w.Start = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			w := base
			change(&w)
			if _, e := Aggregate(w, nil); e != ErrInput {
				t.Fatal("accepted")
			}
		})
	}
	for name, in := range map[string][]Interval{
		"before": {interval(-1, 1, 1)}, "outside": {interval(14, 16, 1)}, "empty": {interval(1, 1, 1)},
		"overlap": {interval(0, 5, 1), interval(4, 6, 2)}, "duplicate": {interval(0, 5, 1), interval(0, 5, 1)},
		"out of order": {interval(5, 6, 1), interval(0, 1, 1)}, "nan": {interval(0, 1, math.NaN())},
		"infinite": {interval(0, 1, math.Inf(1))}, "weighted overflow": {interval(0, 15, math.MaxFloat64)},
	} {
		t.Run(name, func(t *testing.T) {
			if b, e := Aggregate(base, in); e != ErrInput || !reflect.DeepEqual(b, Bucket{}) {
				t.Fatal("not atomic rejection")
			}
		})
	}
	in := interval(0, 1, 1)
	in.Covered = 2 * time.Second
	if _, e := Aggregate(base, []Interval{in}); e != ErrInput {
		t.Fatal("inflated coverage")
	}
	in.Covered = 0
	if _, e := Aggregate(base, []Interval{in}); e != ErrInput {
		t.Fatal("zero coverage")
	}
	in = interval(0, 1, 1)
	in.Delta = 1
	if _, e := Aggregate(base, []Interval{in}); e != ErrInput {
		t.Fatal("mixed semantics")
	}
	if _, e := Aggregate(window(15*time.Second, CounterDelta), []Interval{interval(0, 1, 1)}); e != ErrInput {
		t.Fatal("counter value accepted")
	}
	if _, e := Aggregate(base, make([]Interval, MaxInputs+1)); e != ErrInput {
		t.Fatal("unbounded input")
	}
}

func TestRollupRejectsSegmentsDuplicatesAndForgery(t *testing.T) {
	w := window(time.Minute, Gauge)
	a := mustAggregate(t, window(15*time.Second, Gauge), []Interval{interval(0, 15, 1)})
	for name, mutate := range map[string]func(*Bucket){
		"clock jump": func(b *Bucket) { b.Segment = "run-2" }, "series": func(b *Bucket) { b.Series = "other" },
		"wrong tier": func(b *Bucket) { b.Step = time.Minute }, "negative coverage": func(b *Bucket) { b.Covered = -1 },
		"inflated coverage": func(b *Bucket) { b.Covered = time.Minute }, "bad count": func(b *Bucket) { b.SampleCount = MaxInputs + 1 },
		"not observed": func(b *Bucket) { b.HasValue = false }, "nan": func(b *Bucket) { b.WeightedSum = math.NaN() },
		"last outside": func(b *Bucket) { b.LastAt = epoch.Add(time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			b := a
			mutate(&b)
			if _, e := Rollup(w, []Bucket{b}); e != ErrInput {
				t.Fatal("accepted")
			}
		})
	}
	if _, e := Rollup(w, []Bucket{a, a}); e != ErrInput {
		t.Fatal("duplicate accepted")
	}
	if _, e := Rollup(window(15*time.Second, Gauge), nil); e != ErrInput {
		t.Fatal("no child tier")
	}
	if _, e := Rollup(w, make([]Bucket, MaxInputs+1)); e != ErrInput {
		t.Fatal("unbounded children")
	}
}

func TestPureConcurrentAggregation(t *testing.T) {
	in := []Interval{interval(0, 10, 7)}
	original := append([]Interval(nil), in...)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Go(func() {
			for j := 0; j < 100; j++ {
				b, e := Aggregate(window(15*time.Second, Gauge), in)
				if e != nil || b.Mean != 7 {
					t.Error("unstable")
				}
			}
		})
	}
	wg.Wait()
	if !reflect.DeepEqual(in, original) {
		t.Fatal("mutated input")
	}
}

func FuzzWeightedRollup(f *testing.F) {
	f.Add(uint16(10), uint16(80), uint8(2), uint8(8))
	f.Fuzz(func(t *testing.T, x, y uint16, c1, c2 uint8) {
		d1, d2 := int(c1%15)+1, int(c2%15)+1
		v1, v2 := float64(x)/10, float64(y)/10
		a := mustAggregate(t, window(15*time.Second, Gauge), []Interval{interval(0, d1, v1)})
		w := window(15*time.Second, Gauge)
		w.Start = epoch.Add(15 * time.Second)
		b := mustAggregate(t, w, []Interval{interval(15, 15+d2, v2)})
		got, e := Rollup(window(time.Minute, Gauge), []Bucket{a, b})
		want := (v1*float64(d1) + v2*float64(d2)) / float64(d1+d2)
		if e != nil || math.Abs(got.Mean-want) > 1e-9 || got.Covered != time.Duration(d1+d2)*time.Second {
			t.Fatalf("%+v %v expected %v", got, e, want)
		}
	})
}

func TestCrossingCounterKeepsExactDeltaAndFullRateDenominator(t *testing.T) {
	a := window(15*time.Second, CounterDelta)
	left := mustAggregate(t, a, []Interval{{From: epoch.Add(14 * time.Second), To: epoch.Add(15 * time.Second), Covered: time.Second, Value: 100, RateKnown: true}})
	a.Start = epoch.Add(15 * time.Second)
	right := mustAggregate(t, a, []Interval{{From: epoch.Add(15 * time.Second), To: epoch.Add(19 * time.Second), Covered: 4 * time.Second, Delta: 500, Value: 100, RateKnown: true, DeltaCovered: 5 * time.Second}})
	if left.Sum != 0 || right.Sum != 500 || right.Mean != 100 || right.CounterCovered != 5*time.Second || right.Complete {
		t.Fatalf("boundary %+v %+v", left, right)
	}
	parent, err := Rollup(window(time.Minute, CounterDelta), []Bucket{left, right})
	if err != nil || parent.Sum != 500 || parent.Mean != 100 || parent.Covered != 5*time.Second || parent.CounterCovered != 5*time.Second {
		t.Fatal(parent, err)
	}
}
