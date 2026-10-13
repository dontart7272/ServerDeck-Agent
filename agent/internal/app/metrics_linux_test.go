// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"github.com/coder/websocket"
	"net/http"
	"path/filepath"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/metrics"
	"serverdeck.local/agent/internal/operations"
	"strings"
	"testing"
	"time"
)

func TestMetricsHTTPSPagesScopeWSSAndRevocation(t *testing.T) {
	g, _, _ := newTestGateway(t)
	collector, err := metrics.NewLinux()
	if err != nil {
		t.Fatal(err)
	}
	g.Metrics = metrics.New(g.RunID, collector.BootID(), collector)
	device, token := pairDirect(t, g)
	_, other := pairDirect(t, g)
	srv, client, _ := testHTTPS(t, g, false)
	params := map[string]any{"view": "detail", "blocks": []string{"cpu", "memory", "network", "filesystems", "processes", "system"}}
	status, _ := query(t, client, srv.URL, "", "snapshot.get", params)
	if status != 401 {
		t.Fatal("unauthenticated metrics", status)
	}
	status, _ = query(t, client, srv.URL, token, "snapshot.get", map[string]any{"view": "detail", "blocks": []string{"unregistered-source"}})
	if status == 200 {
		t.Fatal("unknown block turned into a complete empty snapshot")
	}
	// Wait for startup collection without making a request trigger sampling.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if time.Now().After(deadline) {
			break
		}
		// Use current process lookup to avoid allocating pagination snapshots.
		snapshot := g.Metrics.Snapshot("summary", []string{"processes"}, nil)
		if len(snapshot.Blocks[0].Records) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	status, raw := query(t, client, srv.URL, token, "snapshot.get", params)
	if status != 200 {
		t.Fatal("snapshot HTTP", status, string(raw))
	}
	if _, err := contracts.Validate(bytes.NewReader(raw), contracts.Target{Family: "api", Definition: "QueryResponse"}, contracts.MaxJSONBytes); err != nil {
		t.Fatal(err)
	}
	pp := map[string]any{"sort": "pid", "order": "asc", "limit": 1}
	status, raw = query(t, client, srv.URL, token, "processes.list", pp)
	if status != 200 {
		t.Fatal("process page", status, string(raw))
	}
	data := decodeMap(t, raw)["data"].(map[string]any)
	revision := data["revision"]
	cursor, _ := data["next_cursor"].(string)
	if cursor == "" {
		t.Fatal("expected multiple native processes")
	}
	pp["cursor"] = cursor
	status, _ = query(t, client, srv.URL, other, "processes.list", pp)
	if status == 200 {
		t.Fatal("cursor crossed trusted initiator")
	}
	status, raw = query(t, client, srv.URL, token, "processes.list", pp)
	if status != 200 || decodeMap(t, raw)["data"].(map[string]any)["revision"] != revision {
		t.Fatal("stable continuation", status)
	}
	pp["sort"] = "name"
	status, _ = query(t, client, srv.URL, token, "processes.list", pp)
	if status == 200 {
		t.Fatal("cursor crossed sort")
	}
	conn, _, err := websocket.Dial(context.Background(), "wss"+strings.TrimPrefix(srv.URL, "https")+"/api/v1/stream", &websocket.DialOptions{HTTPClient: client, HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}}, Subprotocols: []string{"serverdeck.v1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	subscribe, _ := json.Marshal(map[string]any{"schema_version": "1.0", "request_id": newID(t), "type": "subscribe", "subscriptions": []any{map[string]any{"id": "metrics", "topic": "snapshot", "params": map[string]any{"view": "detail", "blocks": []string{"memory"}}}}})
	if err = conn.Write(ctx, websocket.MessageText, subscribe); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_, raw, err := conn.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		value := decodeMap(t, raw)
		if i == 0 {
			if value["type"] != "subscribed" {
				t.Fatal("subscription", string(raw))
			}
			continue
		}
		if value["type"] != "snapshot" || value["cursor"] != nil {
			t.Fatal("snapshot incorrectly requires ack", string(raw))
		}
		if _, err := contracts.Validate(bytes.NewReader(raw), contracts.Target{Family: "api", Definition: "WssServerMessage"}, contracts.MaxJSONBytes); err != nil {
			t.Fatal(err)
		}
	}
	// Revocation from the existing guarded application service must still stop
	// a live snapshot connection, before another observation can be delivered.
	revokeDirect(t, g, operations.Local(), device)
	_, _, err = conn.Read(ctx)
	if websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatal("revocation", err)
	}
}

func TestMetricReadContinuesAfterAuditFailure(t *testing.T) {
	g, path, _ := newTestGateway(t)
	_, token := pairDirect(t, g)
	collector, err := metrics.NewLinux()
	if err != nil {
		t.Fatal(err)
	}
	g.Metrics = metrics.New(g.RunID, collector.BootID(), collector)
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(path, "critical.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TRIGGER e04_audit_failure BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = g.Issue(context.Background(), operations.Local()); err == nil {
		t.Fatal("mutation bypassed failed audit")
	}
	if g.Store.Health().AuditAvailable {
		t.Fatal("failed audit hidden")
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(g.Metrics.Snapshot("summary", []string{"memory"}, nil).Blocks[0].Metrics) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("memory collection stalled")
		}
		time.Sleep(10 * time.Millisecond)
	}
	srv, client, _ := testHTTPS(t, g, false)
	status, raw := query(t, client, srv.URL, token, "snapshot.get", map[string]any{"view": "summary", "blocks": []string{"memory"}})
	if status != 200 {
		t.Fatal("monitoring stopped after audit failure", status, string(raw))
	}
	if g.Store.Health().AuditAvailable {
		t.Fatal("observation cleared audit failure")
	}
}
