// SPDX-License-Identifier: Apache-2.0
package contracts

import (
	"encoding/json"
	"strconv"
	"testing"
)

func TestDataSchemaSubset(t *testing.T) {
	for _, s := range []string{
		`{"type":"object","properties":{"x":{"type":"string","maxLength":80}},"required":["x"],"additionalProperties":false}`,
		`{"type":"array","maxItems":100,"items":{"type":"integer","minimum":0,"maximum":10}}`,
		`{"type":"object","properties":{"x":{"$ref":"#/definitions/Value"}},"additionalProperties":false,"definitions":{"Value":{"type":"string","maxLength":80}}}`,
	} {
		var m map[string]any
		json.Unmarshal([]byte(s), &m)
		if e := ValidateDataSchema(m); e != nil {
			t.Fatal(e)
		}
	}
	for _, s := range []string{
		`{"$ref":"https://example.invalid/schema.json"}`,
		`{"type":"string"}`,
		`{"type":"string","maxLength":4097}`,
		`{"type":"string","maxLength":80,"pattern":"(a+)+"}`,
		`{"type":"array","items":{"type":"boolean"}}`,
		`{"type":"object","properties":{},"additionalProperties":true}`,
		`{"type":"object","properties":{"x":{"$ref":"#/definitions/Value"}},"additionalProperties":false,"definitions":{"Value":{"$ref":"#/definitions/Value"}}}`,
		`{"oneOf":[{"type":"boolean"},{"type":"boolean"}]}`,
		`{"type":"integer","minimum":0}`,
	} {
		var m map[string]any
		json.Unmarshal([]byte(s), &m)
		if ValidateDataSchema(m) == nil {
			t.Fatal("unsafe/unbounded schema accepted")
		}
	}
}

// Every schema-bearing sibling must be inspected even when another keyword
// already bounds the set of possible data values. const/enum values are data.
func TestDataSchemaSiblingGuards(t *testing.T) {
	wrappers := map[string]string{
		"const": `"const":{}`,
		"enum":  `"enum":[{}]`,
		"oneOf": `"oneOf":[{"type":"object","properties":{"kind":{"const":"a"}},"required":["kind"],"additionalProperties":false},{"type":"object","properties":{"kind":{"const":"b"}},"required":["kind"],"additionalProperties":false}]`,
	}
	siblings := map[string]string{
		"properties-pattern":           `"properties":{"x":{"type":"string","maxLength":80,"pattern":"a+"}}`,
		"items-format":                 `"items":{"type":"string","maxLength":80,"format":"custom"}`,
		"additionalProperties-remote":  `"additionalProperties":{"$ref":"https://example.invalid/schema.json"}`,
		"additionalProperties-pattern": `"additionalProperties":{"type":"string","maxLength":80,"pattern":"a+"}`,
		"properties-recursive":         `"properties":{"x":{"$ref":"#"}}`,
		"properties-unbounded":         `"properties":{"x":{"type":"string"}}`,
		"items-unbounded":              `"items":{"type":"array","items":{"type":"boolean"}}`,
		"unused-definitions":           `"definitions":{"Unused":{"type":"string","pattern":"a+"}}`,
	}
	for wrapper, prefix := range wrappers {
		for sibling, suffix := range siblings {
			t.Run(wrapper+"/"+sibling, func(t *testing.T) {
				var schema map[string]any
				if err := json.Unmarshal([]byte("{"+prefix+","+suffix+"}"), &schema); err != nil {
					t.Fatal(err)
				}
				if err := ValidateDataSchema(schema); err == nil {
					t.Fatal("forbidden sibling schema accepted")
				}
			})
		}
		// A valid sibling must not be rejected merely for being a sibling.
		var schema map[string]any
		json.Unmarshal([]byte("{"+prefix+`,"properties":{"x":{"type":"string","maxLength":80}}}`), &schema)
		if err := ValidateDataSchema(schema); err != nil {
			t.Fatalf("%s: bounded sibling rejected: %v", wrapper, err)
		}
	}
	for _, input := range []string{
		`{"const":{"pattern":"literal data","items":{"$ref":"#"}}}`,
		`{"enum":[{"format":"literal data"}]}`,
	} {
		var schema map[string]any
		json.Unmarshal([]byte(input), &schema)
		if err := ValidateDataSchema(schema); err != nil {
			t.Fatal("constant data mistaken for schema", err)
		}
	}
}

func TestDataSchemaSiblingDepth(t *testing.T) {
	var node any = map[string]any{"type": "boolean"}
	for i := 0; i < 16; i++ {
		node = map[string]any{"const": map[string]any{}, "properties": map[string]any{"x": node}}
	}
	if err := ValidateDataSchema(node.(map[string]any)); err != ErrLimit {
		t.Fatalf("hidden depth must hit shared limit: %v", err)
	}
}
func TestUIDeclarationLimits(t *testing.T) {
	leaf := map[string]any{"node_id": "same", "type": "text", "label_key": "test"}
	v := map[string]any{"screens": []any{map[string]any{"screen_id": "main", "root": map[string]any{"node_id": "root", "type": "column", "children": []any{leaf, leaf}}}}}
	if validateUI(v) == nil {
		t.Fatal("duplicate node IDs accepted")
	}
}

func TestUITotalAndDepth(t *testing.T) {
	makeUI := func(node map[string]any) any {
		return map[string]any{"screens": []any{map[string]any{"screen_id": "main", "root": node}}}
	}
	root := map[string]any{"node_id": "root", "children": []any{}}
	children := []any{}
	for i := 0; i < 511; i++ {
		children = append(children, map[string]any{"node_id": strconv.Itoa(i)})
	}
	root["children"] = children
	if e := validateUI(makeUI(root)); e != nil {
		t.Fatal("512 nodes rejected")
	}
	root["children"] = append(children, map[string]any{"node_id": "extra"})
	if e := validateUI(makeUI(root)); e != ErrLimit {
		t.Fatal("513 nodes accepted")
	}
	node := map[string]any{"node_id": "leaf"}
	for i := 0; i < 16; i++ {
		node = map[string]any{"node_id": strconv.Itoa(i), "children": []any{node}}
	}
	if e := validateUI(makeUI(node)); e != ErrLimit {
		t.Fatal("depth17 accepted")
	}
}
