// SPDX-License-Identifier: Apache-2.0
//go:build linux && cgo

package metrics

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDockerUnixNegotiationWorkingSetAndReadOnly(t *testing.T) {
	directory, err := os.MkdirTemp("", "docker-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	path := filepath.Join(directory, "d.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	var sample atomic.Uint64
	var mode atomic.Int32
	id := strings.Repeat("a", 64)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("mutation: %s", r.Method)
			http.Error(w, "", 405)
			return
		}
		switch mode.Load() {
		case 1:
			http.Error(w, "DO_NOT_EXPOSE", 403)
			return
		case 2:
			http.Redirect(w, r, "http://example.invalid/", 302)
			return
		case 3:
			w.Write([]byte(strings.Repeat("x", 2000001)))
			return
		}
		var out any
		switch r.URL.Path {
		case "/version":
			out = map[string]any{"Version": "test", "ApiVersion": "1.99", "MinAPIVersion": "1.40"}
		case "/v1.56/containers/json":
			out = []any{map[string]any{"Id": id, "Names": []string{"/demo"}, "State": "running", "Labels": map[string]string{"secret": "DO_NOT_EXPOSE", "com.docker.compose.project": "demo"}}}
		case "/v1.56/containers/" + id + "/json":
			out = map[string]any{"State": map[string]any{"Health": map[string]string{"Status": "healthy"}}, "Config": map[string]any{"Env": []string{"PASSWORD=DO_NOT_EXPOSE"}}}
		case "/v1.56/containers/" + id + "/stats":
			n := sample.Add(1)
			out = map[string]any{"cpu_stats": map[string]any{"cpu_usage": map[string]uint64{"total_usage": n * 10}, "system_cpu_usage": n * 100, "online_cpus": 2}, "memory_stats": map[string]any{"usage": 100, "limit": 1000, "stats": map[string]int{"inactive_file": 20}}}
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(out)
	})}
	go server.Serve(listener)
	defer server.Close()
	l, err := NewLinux()
	if err != nil {
		t.Fatal(err)
	}
	l.ConfigureAdapters(AdapterOptions{DockerSocket: &path})
	for i := 1; i <= 2; i++ {
		s := Stamp{Wall: time.Now(), Mono: time.Duration(i) * time.Second}
		b := block("docker", s, 15000)
		if err := l.collectDocker(&b, s); err != nil {
			t.Fatal(err)
		}
		validateAdapterBlock(t, b)
		raw, _ := json.Marshal(b)
		if strings.Contains(string(raw), "DO_NOT_EXPOSE") {
			t.Fatal("secret leaked")
		}
		found := false
		for _, record := range b.Records {
			data, _ := json.Marshal(record)
			if strings.Contains(string(data), `"memory_used_bytes"`) && strings.Contains(string(data), `"80"`) {
				found = true
			}
		}
		if !found {
			t.Fatalf("working set absent: %s", raw)
		}
	}
	for _, test := range []struct {
		mode   int32
		status string
	}{{1, "permission_denied"}, {2, "source_error"}, {3, "source_error"}} {
		mode.Store(test.mode)
		stamp := Stamp{Wall: time.Now(), Mono: 3 * time.Second}
		b := block("docker", stamp, 15000)
		if err := l.collectDocker(&b, stamp); err != nil || b.Availability != test.status {
			t.Fatal(test, b.Availability, err)
		}
	}
	client, tr, err := dockerClient(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.CloseIdleConnections()
	_ = client
}
func TestDockerVersionBoundaries(t *testing.T) {
	for _, v := range []string{"1.39", "2.56", "bad", "1.-1"} {
		if _, err := dockerVersion(v, "1.24"); err == nil {
			t.Fatal(v)
		}
	}
	if _, err := dockerVersion("1.60", "1.57"); err == nil {
		t.Fatal("incompatible min")
	}
	if v, err := dockerVersion("1.41", "1.24"); err != nil || v != "1.41" {
		t.Fatal(v, err)
	}
}
