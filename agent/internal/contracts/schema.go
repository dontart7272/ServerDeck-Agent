// SPDX-License-Identifier: Apache-2.0
package contracts

import (
	"bytes"
	"embed"
	"encoding/json"
	"io"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

//go:embed schemas/*.json
var schemas embed.FS

type Target struct {
	Family     string
	Definition string
}

var compiled sync.Map
var compileMu sync.Mutex

func compileDeclaration(b []byte) (*jsonschema.Schema, error) {
	c := jsonschema.NewCompiler()
	c.Draft = jsonschema.Draft7
	c.LoadURL = func(string) (io.ReadCloser, error) { return nil, ErrSchema }
	if e := c.AddResource("declaration.json", bytes.NewReader(b)); e != nil {
		return nil, e
	}
	return c.Compile("declaration.json")
}

func schemaFor(t Target) (*jsonschema.Schema, error) {
	if !strings.Contains("|api|ipc|module|ui|config|release|", "|"+t.Family+"|") || t.Family == "" {
		return nil, ErrSchema
	}
	if s, ok := compiled.Load(t); ok {
		return s.(*jsonschema.Schema), nil
	}
	compileMu.Lock()
	defer compileMu.Unlock()
	if s, ok := compiled.Load(t); ok {
		return s.(*jsonschema.Schema), nil
	}
	b, e := schemas.ReadFile("schemas/" + t.Family + ".schema.json")
	if e != nil {
		return nil, ErrSchema
	}
	var root map[string]any
	if json.Unmarshal(b, &root) != nil {
		return nil, ErrSchema
	}
	if t.Definition != "" {
		defs, ok := root["definitions"].(map[string]any)
		if !ok {
			return nil, ErrSchema
		}
		if _, ok := defs[t.Definition]; !ok {
			return nil, ErrSchema
		}
		root = map[string]any{"$schema": root["$schema"], "definitions": defs, "$ref": "#/definitions/" + t.Definition}
		b, e = json.Marshal(root)
		if e != nil {
			return nil, ErrSchema
		}
	}
	addSemanticFormats(root)
	b, e = json.Marshal(root)
	if e != nil {
		return nil, ErrSchema
	}
	c := jsonschema.NewCompiler()
	c.Draft = jsonschema.Draft7
	c.AssertFormat = true
	c.Formats["date-time"] = validTimestamp
	c.Formats["serverdeck-u64"] = validU64
	c.Formats["serverdeck-component"] = validComponent
	c.Formats["serverdeck-os-uuid"] = validOSUUID
	c.LoadURL = func(string) (io.ReadCloser, error) { return nil, ErrSchema }
	if c.AddResource("schema.json", bytes.NewReader(b)) != nil {
		return nil, ErrSchema
	}
	s, e := c.Compile("schema.json")
	if e != nil {
		return nil, ErrSchema
	}
	compiled.Store(t, s)
	return s, nil
}

// Validate requires an explicit direction/type for API, IPC and UI. Passing
// their family root could accept a response at a request endpoint.
func Validate(r io.Reader, t Target, limit int64) (json.RawMessage, error) {
	if (t.Family == "api" || t.Family == "ipc" || t.Family == "ui") && t.Definition == "" {
		return nil, ErrSchema
	}
	// The aggregate is for schema documentation only, never a wire boundary.
	if t.Family == "api" && t.Definition == "WssMessage" {
		return nil, ErrSchema
	}
	v, e := Parse(r, limit)
	if e != nil {
		return nil, e
	}
	s, e := schemaFor(t)
	if e != nil {
		return nil, e
	}
	if s.Validate(v) != nil {
		return nil, ErrSchema
	}
	if t.Family == "api" {
		switch t.Definition {
		case "Runtime", "ConfigChanges":
			if e := validateRuntimeValue(v); e != nil {
				return nil, e
			}
		case "PrepareRequest", "OperationRequest":
			m := v.(map[string]any)
			if m["action"] == "config.set" {
				if e := validateRuntimeValue(m["params"].(map[string]any)["changes"]); e != nil {
					return nil, e
				}
			}
		case "WssClientMessage":
			if e := validateWssClient(v.(map[string]any)); e != nil {
				return nil, e
			}
		}
	}
	if t.Family == "api" && t.Definition == "QueryRequest" {
		if e := validateQuery(v); e != nil {
			return nil, e
		}
	}
	if t.Family == "module" && t.Definition == "" {
		if e := validateModule(v); e != nil {
			return nil, e
		}
	}
	if t.Family == "ui" && t.Definition == "Ui" {
		if e := validateUI(v); e != nil {
			return nil, e
		}
	}
	b, e := json.Marshal(v)
	if e != nil {
		return nil, ErrInvalid
	}
	return b, nil
}

// Decode validates the complete discriminated shape before exposing a type.
func Decode[T any](r io.Reader, t Target, limit int64) (T, error) {
	var v T
	b, e := Validate(r, t, limit)
	if e != nil {
		return v, e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil {
		return v, ErrSchema
	}
	return v, nil
}

func Encode(w io.Writer, t Target, v any, limit int64) error {
	if e := guardEncode(v, limit); e != nil {
		return e
	}
	b, e := json.Marshal(v)
	if e != nil {
		return ErrInvalid
	}
	b, e = Validate(bytes.NewReader(b), t, limit)
	if e != nil {
		return e
	}
	n, e := w.Write(b)
	if e == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return e
}
