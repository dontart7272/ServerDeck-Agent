// SPDX-License-Identifier: Apache-2.0
package contracts

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// Construct minimal structural fixtures for every discriminated request branch.
// These prove codec coverage, not operation authorization or system semantics.
func sample(t *testing.T, s map[string]any, root map[string]any, depth int) any {
	t.Helper()
	if depth > 80 {
		t.Fatal("recursive fixture schema")
	}
	if r, ok := s["$ref"].(string); ok {
		return sample(t, root["definitions"].(map[string]any)[strings.TrimPrefix(r, "#/definitions/")].(map[string]any), root, depth+1)
	}
	if v, ok := s["const"]; ok {
		return v
	}
	if v, ok := s["enum"].([]any); ok {
		return v[0]
	}
	for _, key := range []string{"oneOf", "anyOf"} {
		if v, ok := s[key].([]any); ok {
			return sample(t, v[0].(map[string]any), root, depth+1)
		}
	}
	switch s["type"] {
	case "object":
		v := map[string]any{}
		props, _ := s["properties"].(map[string]any)
		req, _ := s["required"].([]any)
		for _, key := range req {
			k := key.(string)
			v[k] = sample(t, props[k].(map[string]any), root, depth+1)
		}
		if len(v) == 0 {
			if min, _ := s["minProperties"].(float64); min > 0 {
				for k, p := range props {
					v[k] = sample(t, p.(map[string]any), root, depth+1)
					break
				}
			}
		}
		return v
	case "array":
		n, _ := s["minItems"].(float64)
		v := []any{}
		for i := 0; i < int(n); i++ {
			v = append(v, sample(t, s["items"].(map[string]any), root, depth+1))
		}
		return v
	case "integer", "number":
		if n, ok := s["minimum"]; ok {
			return n
		}
		return 0
	case "boolean":
		return false
	case "null":
		return nil
	case "string":
		p, _ := s["pattern"].(string)
		switch p {
		case "^(0|[1-9][0-9]{0,19})$":
			return "0"
		case "^/":
			return "/fixture"
		case "^(|/.*)$":
			return ""
		case "^[0-7]{4}$":
			return "0600"
		case "^[0-9]+\\.[0-9]+\\.[0-9]+(?:-[0-9A-Za-z.-]+)?$":
			return "1.0.0"
		case "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,9})?Z$":
			return "2026-10-12T00:00:00Z"
		case "^[0-9a-f-]{36}$", "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$":
			return "11111111-1111-4111-8111-111111111111"
		case "^[0-9a-f]{64}$":
			return strings.Repeat("0", 64)
		case "^[A-Za-z0-9_-]+$":
			return "YQ"
		case "^[a-z0-9][a-z0-9.-]*\\.[a-z0-9][a-z0-9.-]*$":
			return "example.module"
		}
		n, _ := s["minLength"].(float64)
		if n < 1 {
			n = 1
		}
		return strings.Repeat("a", int(n))
	}
	t.Fatalf("unhandled fixture schema: %v", s)
	return nil
}
func TestRequestCatalogBranches(t *testing.T) {
	for _, tc := range []struct{ family, def string }{{"api", "QueryRequest"}, {"api", "PrepareRequest"}, {"api", "OperationRequest"}, {"ipc", "Request"}} {
		b, _ := schemas.ReadFile("schemas/" + tc.family + ".schema.json")
		var root map[string]any
		if json.Unmarshal(b, &root) != nil {
			t.Fatal("schema")
		}
		def := root["definitions"].(map[string]any)[tc.def].(map[string]any)
		variants, _ := def["oneOf"].([]any)
		if variants == nil {
			variants = def["anyOf"].([]any)
		}
		if len(variants) == 0 {
			t.Fatal("no request variants")
		}
		for i, branch := range variants {
			t.Run(tc.family+"/"+tc.def+"/"+string(rune('A'+i)), func(t *testing.T) {
				v := sample(t, branch.(map[string]any), root, 0)
				if m := v.(map[string]any); m["query"] == "history.get" {
					m["params"].(map[string]any)["to"] = "2026-10-12T01:00:00Z"
				}
				b, _ := json.Marshal(v)
				if _, e := Validate(bytes.NewReader(b), Target{tc.family, tc.def}, MaxJSONBytes); e != nil {
					t.Fatalf("positive branch %d: %v", i, e)
				}
				m := v.(map[string]any)
				m["params"].(map[string]any)["unexpected_parameter"] = true
				b, _ = json.Marshal(v)
				if _, e := Validate(bytes.NewReader(b), Target{tc.family, tc.def}, MaxJSONBytes); e == nil {
					t.Fatal("unknown nested parameter accepted")
				}
			})
		}
	}
}
