// SPDX-License-Identifier: Apache-2.0
package contracts

import (
	"encoding/json"
	"strconv"
	"strings"
)

// ValidateDataSchema checks the finite declarative subset for module data.
// No regex, custom format, remote load or executable validator is permitted.
func ValidateDataSchema(root map[string]any) error {
	b, e := json.Marshal(root)
	if e != nil || len(b) > 256000 {
		return ErrLimit
	}
	allowed := map[string]bool{}
	for _, k := range strings.Fields("$schema $ref definitions title description type properties required additionalProperties enum const items minItems maxItems minLength maxLength minimum maximum oneOf") {
		allowed[k] = true
	}
	var walk func(map[string]any, int, map[string]bool) error
	visits := 0
	walk = func(s map[string]any, depth int, refs map[string]bool) error {
		visits++
		if visits > 10000 {
			return ErrLimit
		}
		if depth > 16 {
			return ErrLimit
		}
		for k := range s {
			if !allowed[k] {
				return ErrSchema
			}
		}
		if defs, ok := s["definitions"].(map[string]any); ok {
			for name, v := range defs {
				child, ok := v.(map[string]any)
				if !ok {
					return ErrSchema
				}
				next := map[string]bool{"#/definitions/" + name: true}
				if e := walk(child, depth+1, next); e != nil {
					return e
				}
			}
		}
		if ref, ok := s["$ref"].(string); ok {
			if !strings.HasPrefix(ref, "#/definitions/") || refs[ref] {
				return ErrSchema
			}
			for key := range s {
				if key != "$ref" && key != "definitions" && key != "$schema" && key != "title" && key != "description" {
					return ErrSchema
				}
			}
			name := strings.TrimPrefix(ref, "#/definitions/")
			if strings.Contains(name, "/") || strings.Contains(name, "~") {
				return ErrSchema
			}
			defs, _ := root["definitions"].(map[string]any)
			target, ok := defs[name].(map[string]any)
			if !ok {
				return ErrSchema
			}
			refs[ref] = true
			e := walk(target, depth+1, refs)
			delete(refs, ref)
			return e
		}
		// Inspect every schema-bearing sibling before a finite const/enum/oneOf
		// can return. The compiler processes these siblings too; skipping them
		// would bypass the keyword, reference and complexity restrictions.
		if value, exists := s["properties"]; exists {
			props, ok := value.(map[string]any)
			if !ok || len(props) > 128 {
				return ErrSchema
			}
			for _, value := range props {
				child, ok := value.(map[string]any)
				if !ok {
					return ErrSchema
				}
				if e := walk(child, depth+1, refs); e != nil {
					return e
				}
			}
		}
		if value, exists := s["items"]; exists {
			child, ok := value.(map[string]any)
			if !ok {
				return ErrSchema
			}
			if e := walk(child, depth+1, refs); e != nil {
				return e
			}
		}
		if child, ok := s["additionalProperties"].(map[string]any); ok {
			if e := walk(child, depth+1, refs); e != nil {
				return e
			}
		}
		if variants, ok := s["oneOf"].([]any); ok {
			if len(variants) < 2 || len(variants) > 32 {
				return ErrSchema
			}
			// Find a common required string const with unique values in all branches.
			first, ok := variants[0].(map[string]any)
			if !ok {
				return ErrSchema
			}
			props, _ := first["properties"].(map[string]any)
			discriminated := false
			for key := range props {
				seen := map[string]bool{}
				valid := true
				for _, v := range variants {
					m, ok := v.(map[string]any)
					if !ok {
						valid = false
						break
					}
					p, _ := m["properties"].(map[string]any)
					field, _ := p[key].(map[string]any)
					tag, ok := field["const"].(string)
					required := false
					if req, ok := m["required"].([]any); ok {
						for _, k := range req {
							if k == key {
								required = true
							}
						}
					}
					if !ok || seen[tag] || !required {
						valid = false
						break
					}
					seen[tag] = true
				}
				if valid {
					discriminated = true
					break
				}
			}
			if !discriminated {
				return ErrSchema
			}
			for _, v := range variants {
				m, ok := v.(map[string]any)
				if !ok {
					return ErrSchema
				}
				if e := walk(m, depth+1, refs); e != nil {
					return e
				}
			}
			return nil
		}
		kind, _ := s["type"].(string)
		// Constants and enums are finite even without a type declaration.
		if _, ok := s["const"]; ok {
			return nil
		}
		if values, ok := s["enum"].([]any); ok {
			if len(values) < 1 || len(values) > 128 {
				return ErrSchema
			}
			return nil
		}
		switch kind {
		case "object":
			if s["additionalProperties"] != false {
				return ErrSchema
			}
			if _, ok := s["properties"].(map[string]any); !ok {
				return ErrSchema
			}
		case "array":
			if !boundedNumber(s["maxItems"], 0, 4096) {
				return ErrSchema
			}
			if _, ok := s["items"].(map[string]any); !ok {
				return ErrSchema
			}
		case "string":
			if !boundedNumber(s["maxLength"], 0, 4096) {
				return ErrSchema
			}
		case "number", "integer":
			if s["minimum"] == nil || s["maximum"] == nil {
				return ErrSchema
			}
		case "boolean", "null":
		default:
			return ErrSchema
		}
		return nil
	}
	if e := walk(root, 1, map[string]bool{}); e != nil {
		return e
	}
	// Compiler also rejects malformed keyword values, inverted bounds, etc.
	b, e = json.Marshal(root)
	if e != nil {
		return ErrSchema
	}
	if _, e := compileDeclaration(b); e != nil {
		return ErrSchema
	}
	return nil
}
func boundedNumber(v any, min, max float64) bool {
	var n float64
	switch x := v.(type) {
	case float64:
		n = x
	case json.Number:
		var e error
		n, e = strconv.ParseFloat(string(x), 64)
		if e != nil {
			return false
		}
	case int:
		n = float64(x)
	default:
		return false
	}
	return n >= min && n <= max && n == float64(int64(n))
}

func validateModule(v any) error {
	root, ok := v.(map[string]any)
	if !ok {
		return ErrSchema
	}
	total := 0
	for _, kind := range []string{"reads", "actions"} {
		seen := map[string]bool{}
		decls, _ := root[kind].([]any)
		for _, d := range decls {
			m := d.(map[string]any)
			id := m["id"].(string)
			if seen[id] {
				return ErrSchema
			}
			seen[id] = true
			for _, key := range []string{"params_schema", "result_schema"} {
				s := m[key].(map[string]any)
				b, _ := json.Marshal(s)
				total += len(b)
				if total > 256000 {
					return ErrLimit
				}
				if e := ValidateDataSchema(s); e != nil {
					return e
				}
			}
		}
	}
	seen := map[string]bool{}
	deps, _ := root["dependencies"].([]any)
	for _, d := range deps {
		id := d.(map[string]any)["module_id"].(string)
		if seen[id] || id == root["module_id"] {
			return ErrSchema
		}
		seen[id] = true
	}
	return nil
}
func validateUI(v any) error {
	root, ok := v.(map[string]any)
	if !ok {
		return ErrSchema
	}
	seen := map[string]bool{}
	count := 0
	var walk func(map[string]any, int) error
	walk = func(node map[string]any, depth int) error {
		count++
		if depth > 16 || count > 512 {
			return ErrLimit
		}
		id := node["node_id"].(string)
		if seen[id] {
			return ErrSchema
		}
		seen[id] = true
		children, _ := node["children"].([]any)
		for _, v := range children {
			if e := walk(v.(map[string]any), depth+1); e != nil {
				return e
			}
		}
		return nil
	}
	screens, _ := root["screens"].([]any)
	screenIDs := map[string]bool{}
	for _, s := range screens {
		m := s.(map[string]any)
		id := m["screen_id"].(string)
		if screenIDs[id] {
			return ErrSchema
		}
		screenIDs[id] = true
		if e := walk(m["root"].(map[string]any), 1); e != nil {
			return e
		}
	}
	return nil
}
