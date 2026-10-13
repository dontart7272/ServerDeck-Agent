// SPDX-License-Identifier: Apache-2.0
package contracts

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const sourceDir = "../../.."

func TestTypedRoundtrip(t *testing.T) {
	b, e := os.ReadFile(filepath.Join(docsContracts(), "examples", "query.json"))
	if e != nil {
		t.Fatal(e)
	}
	target := Target{"api", "QueryRequest"}
	v, e := Decode[APIQueryRequestHistoryGet](bytes.NewReader(b), target, MaxJSONBytes)
	if e != nil {
		t.Fatal(e)
	}
	if len(v.Params.SeriesIds) != 1 || v.Params.MaxPoints != 2000 {
		t.Fatal("typed parameters lost")
	}
	var out bytes.Buffer
	if e := Encode(&out, target, v, MaxJSONBytes); e != nil {
		t.Fatal(e)
	}
	if _, e := Decode[APIQueryRequestHistoryGet](&out, target, MaxJSONBytes); e != nil {
		t.Fatal(e)
	}
	reversed := strings.Replace(string(b), "2026-10-12T01:00:00Z", "2026-10-12T00:00:00Z", 1)
	if _, e := Validate(strings.NewReader(reversed), target, MaxJSONBytes); e == nil {
		t.Fatal("empty history range accepted")
	}
	calendar := strings.Replace(string(b), "2026-10-12T00:00:00Z", "2026-02-30T00:00:00Z", 1)
	if _, e := Validate(strings.NewReader(calendar), target, MaxJSONBytes); e == nil {
		t.Fatal("bad calendar date accepted")
	}
}

func docsContracts() string {
	return filepath.Join(sourceDir, "Документация ServerDeck", "Документация ServerDeck Agent", "contracts")
}

func TestConcurrentValidation(t *testing.T) {
	b, e := os.ReadFile(filepath.Join(docsContracts(), "examples", "ipc.json"))
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 4; n++ {
				if _, e := Validate(bytes.NewReader(b), Target{"ipc", "Request"}, MaxJSONBytes); e != nil {
					t.Error(e)
				}
			}
		}()
	}
	wg.Wait()
	bad := strings.Replace(string(b), `"sequence": "1"`, `"sequence": "18446744073709551616"`, 1)
	if bad == string(b) {
		t.Fatal("fixture mutation not applied")
	}
	if _, e := Validate(strings.NewReader(bad), Target{"ipc", "Request"}, MaxJSONBytes); e == nil {
		t.Fatal("schema-bound U64 overflow accepted")
	}
}
func TestEmbeddedSchemasMatchSource(t *testing.T) {
	for _, family := range []string{"api", "ipc", "module", "ui", "config", "release"} {
		a, e := schemas.ReadFile("schemas/" + family + ".schema.json")
		if e != nil {
			t.Fatal(e)
		}
		b, e := os.ReadFile(filepath.Join(docsContracts(), family+".schema.json"))
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("schema drift: %s (run tools/sync-contracts.ps1)", family)
		}
		if _, e := schemaFor(Target{Family: family}); e != nil {
			t.Fatalf("compile %s: %v", family, e)
		}
		var root struct {
			Definitions map[string]json.RawMessage `json:"definitions"`
		}
		if json.Unmarshal(a, &root) != nil {
			t.Fatal("schema JSON")
		}
		for name := range root.Definitions {
			if _, e := schemaFor(Target{family, name}); e != nil {
				t.Errorf("compile %s/%s: %v", family, name, e)
			}
		}
	}
}
func TestExamples(t *testing.T) {
	targets := map[string]Target{"config": {"config", ""}, "query": {"api", "QueryRequest"}, "operation": {"api", "OperationRequest"}, "module": {"module", ""}, "ipc": {"ipc", "Request"}, "ui": {"ui", "Ui"}, "release": {"release", ""}, "ipc-response": {"ipc", "Response"}, "error": {"api", "ErrorEnvelope"}, "operation-state": {"api", "Operation"}, "snapshot-response": {"api", "QueryResponse"}}
	targets["wss-client"] = Target{"api", "WssClientMessage"}
	targets["wss-server"] = Target{"api", "WssServerMessage"}
	for name, target := range targets {
		t.Run(name, func(t *testing.T) {
			b, e := os.ReadFile(filepath.Join(docsContracts(), "examples", name+".json"))
			if e != nil {
				t.Fatal(e)
			}
			if _, e := Validate(bytes.NewReader(b), target, MaxJSONBytes); e != nil {
				t.Fatalf("positive fixture: %v", e)
			}
			var v map[string]any
			if json.Unmarshal(b, &v) != nil {
				t.Fatal("fixture")
			}
			v["unexpected_field"] = true
			bad, _ := json.Marshal(v)
			if _, e := Validate(bytes.NewReader(bad), target, MaxJSONBytes); e == nil {
				t.Fatal("unknown field accepted")
			}
		})
	}
}
func TestDirectionAndSemantics(t *testing.T) {
	if _, e := Validate(strings.NewReader(`{}`), Target{"api", ""}, MaxJSONBytes); e == nil {
		t.Fatal("family root permitted")
	}
	for _, tc := range []struct{ def, input string }{
		{"Process", `{}`},
		{"QueryRequest", `{"schema_version":"1.0","request_id":"11111111-1111-4111-8111-111111111111","query":"shell.exec","params":{}}`},
	} {
		if _, e := Validate(strings.NewReader(tc.input), Target{"api", tc.def}, MaxJSONBytes); e == nil {
			t.Fatal("bad input accepted")
		}
	}
	for _, s := range []string{`"18446744073709551616"`, `"2026-02-30T00:00:00Z"`, `"Lg"`} {
		// Exercise semantic formats with the same annotations as the real schemas.
		var v any
		if json.Unmarshal([]byte(s), &v) != nil {
			t.Fatal("fixture")
		}
		if validU64(v) && validComponent(v) {
			t.Fatal("bad semantic value accepted")
		}
	}
}
