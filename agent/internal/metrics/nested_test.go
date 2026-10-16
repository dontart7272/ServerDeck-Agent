// SPDX-License-Identifier: Apache-2.0
package metrics

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNestedMetricUsesMonotonicAgeAndSourceFailure(t *testing.T) {
	stamp := Stamp{Wall: time.Now().UTC(), Mono: time.Second}
	b := block("gpu", stamp, 2000)
	nested := block("gpu", stamp, 2000)
	measure(&nested, "vram_used_bytes", "gpu.process", "byte", "42", "available", "", stamp)
	record(&b, map[string]any{"record_type": "gpu", "processes": []any{map[string]any{"metrics": nested.Metrics}}})
	for _, test := range []struct {
		mono   time.Duration
		status string
		stale  bool
	}{{2 * time.Second, "available", false}, {7 * time.Second, "available", true}, {2 * time.Second, "permission_denied", true}} {
		b.Availability = test.status
		now := Stamp{Wall: stamp.Wall.Add(-time.Hour), Mono: test.mono}
		raw, partial := renderNested(b.Records[0], b, now)
		var value map[string]any
		json.Unmarshal(raw, &value)
		m := value["processes"].([]any)[0].(map[string]any)["metrics"].([]any)[0].(map[string]any)
		if (m["freshness"] == "stale") != test.stale || partial != test.stale || m["value"] != "42" || m["availability"] != test.status {
			t.Fatal(m, partial, test)
		}
	}
}

type nestedIntegrationFixture struct{}

func (nestedIntegrationFixture) IntegrationSources() {}
func (nestedIntegrationFixture) Collect(string, Stamp, int64, string) (Sample, error) {
	return Sample{}, nil
}
func TestSnapshotAgesNestedMetricsAndMarksPartial(t *testing.T) {
	now := stamp()
	now.Mono = time.Second
	e := manual(&now)
	e.collector = nestedIntegrationFixture{}
	b := block("gpu", now, 2000)
	m := block("gpu", now, 2000)
	measure(&m, "vram_used_bytes", "gpu.process", "byte", "42", "available", "", now)
	record(&b, map[string]any{"processes": []any{map[string]any{"metrics": m.Metrics}}})
	e.sources["gpu"] = &source{block: b}
	now.Mono = 7 * time.Second
	now.Wall = now.Wall.Add(-time.Hour)
	snapshot := e.Snapshot("detail", []string{"gpu"}, nil)
	if !snapshot.Partial || len(snapshot.Blocks) != 1 {
		t.Fatal(snapshot)
	}
	var out map[string]any
	json.Unmarshal(snapshot.Blocks[0].Records[0], &out)
	metric := out["processes"].([]any)[0].(map[string]any)["metrics"].([]any)[0].(map[string]any)
	if metric["freshness"] != "stale" || metric["value"] != "42" {
		t.Fatal(metric)
	}
}
