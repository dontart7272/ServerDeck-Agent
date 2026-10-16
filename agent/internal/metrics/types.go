// SPDX-License-Identifier: Apache-2.0
// Package metrics owns shared, read-only observations. It never performs server actions.
package metrics

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"time"

	"serverdeck.local/agent/internal/contracts"
)

const MaxRecords = 4096

var ErrUnavailable = errors.New("SOURCE_UNAVAILABLE")
var ErrExpired = errors.New("CURSOR_EXPIRED")
var ErrLimit = errors.New("LIMIT_EXCEEDED")
var errPermission = os.ErrPermission

type Metric struct {
	measuredMono time.Duration
	Key          string               `json:"key"`
	ResourceID   string               `json:"resource_id"`
	SeriesSchema string               `json:"series_schema"`
	Unit         string               `json:"unit"`
	Value        any                  `json:"value"`
	Availability string               `json:"availability"`
	Freshness    string               `json:"freshness"`
	MeasuredAt   *contracts.Timestamp `json:"measured_at"`
	AttemptedAt  contracts.Timestamp  `json:"attempted_at"`
	Interval     int64                `json:"expected_interval_ms"`
	Source       string               `json:"source"`
	Reason       *string              `json:"reason"`
}

// MonotonicElapsed is process-local observation time, not a wall-clock duration.
// It is intentionally absent from JSON and must not be restored across runs.
func (m Metric) MonotonicElapsed() time.Duration { return m.measuredMono }

type Block struct {
	nestedTimes  map[string]time.Duration
	ID           string               `json:"block_id"`
	Mode         string               `json:"collection_mode"`
	ObservedAt   *contracts.Timestamp `json:"observed_at"`
	Interval     int64                `json:"expected_interval_ms"`
	Metrics      []Metric             `json:"metrics"`
	Records      []json.RawMessage    `json:"records"`
	Availability string               `json:"availability"`
	Reason       *string              `json:"reason"`
}
type Snapshot struct {
	ID        string              `json:"snapshot_id"`
	RunID     string              `json:"agent_run_id"`
	BootID    string              `json:"boot_id"`
	SegmentID string              `json:"segment_id"`
	At        contracts.Timestamp `json:"captured_at"`
	Blocks    []Block             `json:"blocks"`
	Partial   bool                `json:"partial"`
}
type Stamp struct {
	Wall time.Time
	Mono time.Duration
}
type Sample struct {
	Block     Block
	Processes []contracts.APIProcess
}
type Collector interface {
	Collect(string, Stamp, int64, string) (Sample, error)
}

func id() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic("METRICS_ENTROPY_UNAVAILABLE")
	}
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	s := hex.EncodeToString(b[:])
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}
func ptr(s string) *string                { return &s }
func at(t time.Time) *contracts.Timestamp { v := contracts.Timestamp(t.UTC()); return &v }
func block(name string, s Stamp, interval int64) Block {
	return Block{ID: name, Mode: "periodic", ObservedAt: at(s.Wall), Interval: interval, Metrics: []Metric{}, Records: []json.RawMessage{}, Availability: "available"}
}
func measure(b *Block, key, resource, unit string, value any, availability, reason string, s Stamp) {
	if v, ok := value.(float64); ok && (math.IsNaN(v) || math.IsInf(v, 0)) {
		value = nil
		availability = "source_error"
		reason = "INVALID_SAMPLE"
	}
	m := Metric{Key: key, ResourceID: resource, SeriesSchema: "1", Unit: unit, Value: value, Availability: availability, Freshness: "unknown", AttemptedAt: contracts.Timestamp(s.Wall.UTC()), Interval: b.Interval, Source: "linux." + b.ID}
	if availability == "available" {
		m.measuredMono = s.Mono
		m.Freshness = "fresh"
		m.MeasuredAt = at(s.Wall)
	}
	if reason != "" {
		m.Reason = ptr(reason)
	}
	b.Metrics = append(b.Metrics, m)
}
func record(b *Block, v any) {
	if b.nestedTimes == nil {
		b.nestedTimes = map[string]time.Duration{}
	}
	var capture func(any)
	capture = func(value any) {
		switch n := value.(type) {
		case []Metric:
			for _, m := range n {
				b.nestedTimes[m.ResourceID+"/"+m.Key] = m.measuredMono
			}
		case map[string]any:
			for _, child := range n {
				capture(child)
			}
		case []any:
			for _, child := range n {
				capture(child)
			}
		}
	}
	capture(v)

	data, e := json.Marshal(v)
	if e == nil {
		b.Records = append(b.Records, data)
	}
}
func wireMetric(m Metric) contracts.APIMetric {
	data, _ := json.Marshal(m)
	var out contracts.APIMetric
	_ = json.Unmarshal(data, &out)
	return out
}
