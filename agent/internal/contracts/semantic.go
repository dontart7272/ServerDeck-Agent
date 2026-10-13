// SPDX-License-Identifier: Apache-2.0
package contracts

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

// Annotate only matching schema nodes, never arbitrary user-supplied data keys.
// date-time is already declared in the source and AssertFormat checks calendars.
func addSemanticFormats(v any) {
	switch x := v.(type) {
	case map[string]any:
		switch x["pattern"] {
		case "^(0|[1-9][0-9]{0,19})$":
			x["format"] = "serverdeck-u64"
		case "^[A-Za-z0-9_-]+$":
			x["format"] = "serverdeck-component"
		case "^[0-9a-f-]{36}$":
			x["format"] = "serverdeck-os-uuid"
		}
		for _, child := range x {
			addSemanticFormats(child)
		}
	case []any:
		for _, child := range x {
			addSemanticFormats(child)
		}
	}
}
func validU64(v any) bool {
	s, ok := v.(string)
	if !ok {
		return true
	}
	b, _ := json.Marshal(s)
	var n U64
	return n.UnmarshalJSON(b) == nil
}
func validComponent(v any) bool {
	s, ok := v.(string)
	if !ok {
		return true
	}
	return (Location{Components: []string{s}}).Validate() == nil
}

var osUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func validOSUUID(v any) bool { s, ok := v.(string); return !ok || osUUID.MatchString(s) }

func validTimestamp(v any) bool {
	s, ok := v.(string)
	if !ok {
		return true
	}
	if !strings.HasSuffix(s, "Z") {
		return false
	}
	_, e := time.Parse(time.RFC3339Nano, s)
	return e == nil
}

func validateQuery(v any) error {
	m := v.(map[string]any)
	if m["query"] == "history.get" {
		p := m["params"].(map[string]any)
		from, e := time.Parse(time.RFC3339Nano, p["from"].(string))
		if e != nil {
			return ErrInvalid
		}
		to, e := time.Parse(time.RFC3339Nano, p["to"].(string))
		if e != nil || !from.Before(to) {
			return ErrInvalid
		}
	}
	return nil
}

func validateTimeRange(p map[string]any) error {
	from, hasFrom := p["from"].(string)
	to, hasTo := p["to"].(string)
	if hasFrom && hasTo {
		start, e := time.Parse(time.RFC3339Nano, from)
		if e != nil {
			return ErrInvalid
		}
		end, e := time.Parse(time.RFC3339Nano, to)
		if e != nil || !start.Before(end) {
			return ErrInvalid
		}
	}
	return nil
}
