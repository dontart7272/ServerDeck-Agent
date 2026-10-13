// SPDX-License-Identifier: Apache-2.0
package config

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func fixture(t *testing.T) map[string]any {
	t.Helper()
	b, e := os.ReadFile("../../../Документация ServerDeck/Документация ServerDeck Agent/contracts/examples/config.json")
	if e != nil {
		t.Fatal(e)
	}
	var v map[string]any
	if json.Unmarshal(b, &v) != nil {
		t.Fatal("fixture")
	}
	return v
}
func branch(v map[string]any, key string) map[string]any { return v[key].(map[string]any) }
func TestConfig(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"unknown", func(v map[string]any) { v["sudo"] = true }},
		{"version", func(v map[string]any) { v["config_version"] = 2 }},
		{"port", func(v map[string]any) { branch(v, "transport")["port"] = 65536 }},
		{"nonlocal", func(v map[string]any) { branch(v, "transport")["listen_addresses"] = []string{"0.0.0.0"} }},
		{"hostname-listener", func(v map[string]any) { branch(v, "transport")["listen_addresses"] = []string{"localhost"} }},
		{"broad-cidr", func(v map[string]any) { branch(v, "transport")["allowed_cidrs"] = []string{"0.0.0.0/0"} }},
		{"noncanonical-cidr", func(v map[string]any) { branch(v, "transport")["allowed_cidrs"] = []string{"127.0.0.1/8"} }},
		{"relative-path", func(v map[string]any) { branch(v, "paths")["state"] = "../data" }},
		{"dot-path", func(v map[string]any) { branch(v, "paths")["state"] = "/a/../b" }},
		{"overlap", func(v map[string]any) { branch(v, "paths")["state"] = "/run/serverdeck/state" }},
		{"edit-over-full", func(v map[string]any) { branch(branch(v, "runtime_initial"), "files")["full_text_bytes"] = 1000 }},
		{"history-over-bound", func(v map[string]any) { branch(branch(v, "runtime_initial"), "history")["budget_bytes"] = 16000000001 }},
		{"icmp-missing", func(v map[string]any) { branch(branch(v, "runtime_initial"), "icmp")["background_enabled"] = true }},
		{"icmp-url", func(v map[string]any) { branch(branch(v, "runtime_initial"), "icmp")["target"] = "https://example.com" }},
		{"icmp-flag", func(v map[string]any) { branch(branch(v, "runtime_initial"), "icmp")["target"] = "-c" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := fixture(t)
			tc.mutate(v)
			b, _ := json.Marshal(v)
			if _, e := Load(bytes.NewReader(b)); e == nil {
				t.Fatal("bad configuration accepted")
			}
		})
	}
	v := fixture(t)
	b, _ := json.Marshal(v)
	if _, e := Load(bytes.NewReader(b)); e != nil {
		t.Fatal(e)
	}
	for _, target := range []string{"example.com", "2001:db8::1", "127.0.0.1"} {
		branch(branch(v, "runtime_initial"), "icmp")["target"] = target
		b, _ := json.Marshal(v)
		if _, e := Load(bytes.NewReader(b)); e != nil {
			t.Fatal(e)
		}
	}
}
