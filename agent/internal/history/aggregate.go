// SPDX-License-Identifier: Apache-2.0
// Package history provides bounded aggregation primitives, independent of storage and transport.
package history

import (
	"errors"
	"math"
	"time"
)

const MaxInputs = 4096

type Kind uint8

const (
	Gauge Kind = iota + 1
	CounterDelta
)

var ErrInput = errors.New("HISTORY_INVALID_INPUT")

// Window identifies an aligned UTC window within exactly one series and segment.
// Revision is allocated by the caller; these pure functions do not persist it.
type Window struct {
	Series, Segment string
	Start           time.Time
	Step            time.Duration
	Revision        int64
	Kind            Kind
	Closed          bool
}

// Interval is an already validated observation interval wholly inside a window.
// Covered is valid monotonic elapsed time, never inferred from UTC alone.
// Delta is an exact increment, not a cumulative counter. Reset/wrap detection,
// boundary splitting and series authorization belong to the future ingestion layer.
type Interval struct {
	From, To time.Time
	Covered  time.Duration
	Value    float64
	Delta    uint64
	// RateKnown carries the observed interval rate independently of end-attributed bytes.
	RateKnown    bool
	DeltaCovered time.Duration
	// ObservationOnly preserves a boundary observation/max without assigning
	// an unknown fraction of its interval's counter increment to either window.
	ObservationOnly bool
}

// Bucket retains sufficient statistics for lossless weighted rollup. The sum of
// counter increments remains uint64; only rate calculation converts to float64.
// This internal type is deliberately not the public API Point contract.
type Bucket struct {
	Window
	Covered        time.Duration
	CounterCovered time.Duration
	SampleCount    int64
	WeightedSum    float64
	Mean           float64
	Maximum        float64
	Last           float64
	Sum            uint64
	HasValue       bool
	Complete       bool
	LastAt         time.Time
}

func validWindow(w Window) bool {
	return len(w.Series) > 0 && len(w.Series) <= 256 && len(w.Segment) > 0 && len(w.Segment) <= 128 &&
		w.Revision > 0 && (w.Kind == Gauge || w.Kind == CounterDelta) &&
		(w.Step == 15*time.Second || w.Step == time.Minute || w.Step == 5*time.Minute) &&
		w.Start.Year() >= 1970 && w.Start.Year() <= 9998 && w.Start.Equal(w.Start.Truncate(w.Step))
}

func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

// Aggregate accepts chronological non-overlapping intervals. Missing intervals
// remain missing: they contribute neither zero values nor coverage. Empty input
// yields HasValue=false, rather than an observed zero. Inputs are never mutated.
func Aggregate(w Window, inputs []Interval) (Bucket, error) {
	if !validWindow(w) || len(inputs) > MaxInputs {
		return Bucket{}, ErrInput
	}
	b := Bucket{Window: w}
	end, previous := w.Start.Add(w.Step), w.Start
	for _, in := range inputs {
		pointOnly := in.ObservationOnly && in.From.Equal(in.To) && in.Covered == 0 && in.Delta == 0
		if pointOnly && (!in.To.Before(end) || (b.SampleCount > 0 && !in.To.After(previous)) || (w.Kind == CounterDelta && in.Value < 0)) {
			return Bucket{}, ErrInput
		}
		if in.From.Before(previous) || (!pointOnly && !in.To.After(in.From)) || in.To.After(end) ||
			(!pointOnly && (in.Covered <= 0 || in.Covered > in.To.Sub(in.From))) || !finite(in.Value) || in.RateKnown && (w.Kind != CounterDelta || in.Value < 0) ||
			(w.Kind == CounterDelta && !pointOnly && !in.RateKnown && in.Value != 0) || (w.Kind == Gauge && in.Delta != 0) || in.ObservationOnly && !pointOnly {
			return Bucket{}, ErrInput
		}
		value := in.Value
		if w.Kind == CounterDelta && !pointOnly {
			if math.MaxUint64-b.Sum < in.Delta {
				return Bucket{}, ErrInput
			}
			b.Sum += in.Delta
			if !in.RateKnown {
				value = float64(in.Delta) / in.Covered.Seconds()
			}
			if in.RateKnown {
				if in.DeltaCovered < 0 || in.DeltaCovered > time.Minute || in.DeltaCovered == 0 && in.Delta != 0 {
					return Bucket{}, ErrInput
				}
				b.CounterCovered += in.DeltaCovered
			} else {
				b.CounterCovered += in.Covered
			}
		} else if !pointOnly {
			b.WeightedSum += value * in.Covered.Seconds()
		}
		if !b.HasValue || value > b.Maximum {
			b.Maximum = value
		}
		b.HasValue, b.Last, b.LastAt = true, value, in.To
		b.Covered += in.Covered
		b.SampleCount++
		previous = in.To
	}
	return finish(b)
}

func finish(b Bucket) (Bucket, error) {
	if b.HasValue && b.Covered > 0 {
		if b.Kind == CounterDelta {
			if b.CounterCovered > 0 {
				b.Mean = float64(b.Sum) / b.CounterCovered.Seconds()
			}
		} else {
			b.Mean = b.WeightedSum / b.Covered.Seconds()
		}
	}
	if !finite(b.WeightedSum) || !finite(b.Mean) || !finite(b.Maximum) || !finite(b.Last) {
		return Bucket{}, ErrInput
	}
	b.Complete = b.Closed && b.Covered == b.Step && (b.Kind != CounterDelta || b.CounterCovered == b.Covered)
	return b, nil
}

// Rollup only accepts the next tier (15s -> 1m -> 5m). It does not average
// averages, interpolate gaps, mix segments or count duplicate windows. Children
// must originate from this package; no persisted/untrusted bucket decoder exists.
func Rollup(w Window, children []Bucket) (Bucket, error) {
	if !validWindow(w) || len(children) > MaxInputs || w.Step == 15*time.Second {
		return Bucket{}, ErrInput
	}
	childStep := 15 * time.Second
	if w.Step == 5*time.Minute {
		childStep = time.Minute
	}
	b := Bucket{Window: w}
	previous, end := w.Start, w.Start.Add(w.Step)
	for _, c := range children {
		if !validWindow(c.Window) || c.Series != w.Series || c.Segment != w.Segment || c.Kind != w.Kind ||
			c.Step != childStep || c.Start.Before(previous) || c.Start.Add(c.Step).After(end) ||
			c.Covered < 0 || c.Covered > c.Step || c.SampleCount < 0 || c.SampleCount > MaxInputs ||
			c.HasValue != (c.SampleCount > 0) ||
			(c.Covered == 0 && (c.Sum != 0 || c.WeightedSum != 0)) ||
			(!c.HasValue && (c.Covered != 0 || c.SampleCount != 0 || c.Sum != 0 || c.WeightedSum != 0)) ||
			(c.HasValue && (c.LastAt.Before(c.Start) || c.LastAt.After(c.Start.Add(c.Step)))) ||
			!finite(c.WeightedSum) || !finite(c.Maximum) || !finite(c.Last) ||
			(w.Kind == Gauge && c.Sum != 0) ||
			math.MaxUint64-b.Sum < c.Sum || b.SampleCount+c.SampleCount > MaxInputs {
			return Bucket{}, ErrInput
		}
		b.Covered += c.Covered
		b.CounterCovered += c.CounterCovered
		b.SampleCount += c.SampleCount
		b.WeightedSum += c.WeightedSum
		b.Sum += c.Sum
		if c.HasValue {
			if !b.HasValue || c.Maximum > b.Maximum {
				b.Maximum = c.Maximum
			}
			b.HasValue, b.Last, b.LastAt = true, c.Last, c.LastAt
		}
		previous = c.Start.Add(c.Step)
	}
	return finish(b)
}
