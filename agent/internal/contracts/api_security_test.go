// SPDX-License-Identifier: Apache-2.0
package contracts

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func checkAPI(t *testing.T, definition string, value any, good bool) {
	t.Helper()
	b, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	_, e = Validate(bytes.NewReader(b), Target{"api", definition}, MaxJSONBytes)
	if (e == nil) != good {
		t.Fatalf("%s: expected accepted=%v, got %v", definition, good, e)
	}
}

func TestWssDirectionAndTopics(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	subscribe := func(subs ...any) any {
		return map[string]any{"schema_version": "1.0", "request_id": id, "type": "subscribe", "subscriptions": subs}
	}
	sub := func(topic string, params any) map[string]any {
		return map[string]any{"id": "s", "topic": topic, "params": params}
	}
	valid := subscribe(sub("snapshot", map[string]any{"view": "summary"}))
	checkAPI(t, "WssClientMessage", valid, true)
	checkAPI(t, "WssServerMessage", valid, false)
	checkAPI(t, "WssMessage", valid, false)
	for _, topic := range []string{"events", "operations", "problems", "storage"} {
		checkAPI(t, "WssClientMessage", subscribe(sub(topic, map[string]any{})), true)
	}
	for _, bad := range []any{
		subscribe(sub("snapshot", true)),
		subscribe(sub("snapshot", map[string]any{"view": "unknown"})),
		subscribe(sub("storage", map[string]any{"unexpected": true})),
		subscribe(sub("operations", map[string]any{"state": "invented"})),
		subscribe(sub("events", map[string]any{"from": "2026-10-13T01:00:00Z", "to": "2026-10-13T00:00:00Z"})),
		subscribe(sub("snapshot", map[string]any{"view": "summary"}), sub("storage", map[string]any{})),
	} {
		checkAPI(t, "WssClientMessage", bad, false)
	}
	withAfter := sub("snapshot", map[string]any{"view": "summary"})
	withAfter["after"] = "cursor"
	checkAPI(t, "WssClientMessage", subscribe(withAfter), false)
	withAfter = sub("events", map[string]any{})
	withAfter["after"] = "cursor"
	checkAPI(t, "WssClientMessage", subscribe(withAfter), true)
	for _, count := range []int{16, 17} {
		subs := make([]any, count)
		for i := range subs {
			s := sub("storage", map[string]any{})
			s["id"] = string(rune('a' + i))
			subs[i] = s
		}
		checkAPI(t, "WssClientMessage", subscribe(subs...), count == 16)
	}
	heartbeat := map[string]any{"schema_version": "1.0", "type": "heartbeat", "server_time": "2026-10-13T00:00:00Z"}
	checkAPI(t, "WssServerMessage", heartbeat, true)
	checkAPI(t, "WssClientMessage", heartbeat, false)
	ack := map[string]any{"schema_version": "1.0", "type": "ack", "subscription_id": "s", "cursor": "c"}
	checkAPI(t, "WssClientMessage", ack, true)
	checkAPI(t, "WssServerMessage", ack, false)

	// Exercise each server change topic and reject records from another topic.
	b, e := schemas.ReadFile("schemas/api.schema.json")
	if e != nil {
		t.Fatal(e)
	}
	var root map[string]any
	if json.Unmarshal(b, &root) != nil {
		t.Fatal("schema")
	}
	defs := root["definitions"].(map[string]any)
	for _, name := range []string{"WssChangesEvents", "WssChangesOperations", "WssChangesProblems", "WssChangesStorage"} {
		value := sample(t, defs[name].(map[string]any), root, 0).(map[string]any)
		item := defs[name].(map[string]any)["properties"].(map[string]any)["data"].(map[string]any)["items"].(map[string]any)
		value["data"] = []any{sample(t, item, root, 0)}
		checkAPI(t, "WssServerMessage", value, true)
		if value["topic"] == "storage" {
			value["topic"] = "events"
		} else {
			value["topic"] = "storage"
		}
		checkAPI(t, "WssServerMessage", value, false)
	}
}

func runtimeFixture(t *testing.T) RuntimeConfig {
	t.Helper()
	b, e := os.ReadFile(filepath.Join(docsContracts(), "examples", "config.json"))
	if e != nil {
		t.Fatal(e)
	}
	var cfg struct {
		Runtime RuntimeConfig `json:"runtime_initial"`
	}
	if json.Unmarshal(b, &cfg) != nil {
		t.Fatal("fixture")
	}
	return cfg.Runtime
}

func TestRuntimeAPISharedSemantics(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	for _, target := range []string{"-c", "https://example.com", "a b", "0.0.0.0", "224.0.0.1", "ff02::1", "fe80::1%eth0", "127.0.0.1", "2001:db8::1", "example.com."} {
		good := target == "127.0.0.1" || target == "2001:db8::1" || target == "example.com."
		changes := map[string]any{"icmp": map[string]any{"target": target, "background_enabled": true}}
		checkAPI(t, "ConfigChanges", changes, good)
		for _, def := range []string{"PrepareRequest", "OperationRequest"} {
			request := map[string]any{"schema_version": "1.0", "request_id": id, "operation_id": id, "action": "config.set", "expected_version": "v", "params": map[string]any{"changes": changes}}
			if def == "OperationRequest" {
				request["plan_id"] = strings.Repeat("a", 22)
			}
			checkAPI(t, def, request, good)
		}
	}
	checkAPI(t, "ConfigChanges", map[string]any{"icmp": map[string]any{"target": nil, "background_enabled": true}}, false)
	for _, mutate := range []func(*RuntimeConfig){
		func(r *RuntimeConfig) { r.Files.FullTextBytes = 1000; r.Files.EditBytes = 2000 },
		func(r *RuntimeConfig) { r.Files.Roots[0].Path = "/tmp/../etc" },
		func(r *RuntimeConfig) { r.Files.Roots = append(r.Files.Roots, r.Files.Roots[0]) },
		func(r *RuntimeConfig) {
			x := r.Files.Roots[0]
			x.RootID = "22222222-2222-4222-8222-222222222222"
			r.Files.Roots = append(r.Files.Roots, x)
		},
	} {
		r := runtimeFixture(t)
		mutate(&r)
		checkAPI(t, "Runtime", r, false)
		checkAPI(t, "ConfigChanges", map[string]any{"files": r.Files}, false)
	}
}

func TestApplyRuntimeChanges(t *testing.T) {
	original := runtimeFixture(t)
	before, _ := json.Marshal(original)
	updated, e := ApplyRuntimeChanges(original, strings.NewReader(`{"icmp":{"target":"example.com","background_enabled":true}}`))
	if e != nil || updated.ICMP.Target == nil || *updated.ICMP.Target != "example.com" {
		t.Fatal("merge", e)
	}
	if updated.Files.FullTextBytes != original.Files.FullTextBytes {
		t.Fatal("untouched group lost")
	}
	updated.Files.Roots[0].Path = "/different"
	after, _ := json.Marshal(original)
	if !bytes.Equal(before, after) {
		t.Fatal("merge mutated original snapshot")
	}
	for _, patch := range []string{`{}`, `{"icmp":{"target":"-c","background_enabled":true}}`, `{"icmp":{"target":null}}`, `{"runtime_user":"root"}`} {
		if _, e := ApplyRuntimeChanges(original, strings.NewReader(patch)); e == nil {
			t.Fatal("invalid patch accepted")
		}
	}
	bad := runtimeFixture(t)
	bad.ICMP.BackgroundEnabled = true
	bad.ICMP.Target = nil
	if _, e := ApplyRuntimeChanges(bad, strings.NewReader(`{"icmp":{"target":"example.com","background_enabled":true}}`)); e == nil {
		t.Fatal("invalid current snapshot silently accepted")
	}
}
