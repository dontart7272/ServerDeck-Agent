// SPDX-License-Identifier: Apache-2.0
//go:build linux

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/metrics"
	"serverdeck.local/agent/internal/storage"
)

func TestTelemetryWSSResumeProblemRemovalAndGap(t *testing.T) {
	g, _, _ := newTestGateway(t)
	_, token := pairDirect(t, g)
	srv, client, _ := testHTTPS(t, g, false)
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()
	r := storage.DefaultRules()[0]
	r.DurationMs = 0
	r.RecoveryDurationMs = 0
	at := contracts.Timestamp(time.Now().UTC())
	snapshot := metrics.Snapshot{At: at, SegmentID: newID(t), Blocks: []metrics.Block{{ID: "memory", Availability: "available", Metrics: []metrics.Metric{{Key: "available_percent", ResourceID: "ram", Value: float64(9), Availability: "available", Freshness: "fresh", MeasuredAt: &at}}}}}
	if err := g.Events.Observe(ctx, []contracts.APIRule{r}, snapshot, 0); err != nil {
		t.Fatal(err)
	}
	dial := func() *websocket.Conn {
		t.Helper()
		conn, _, err := websocket.Dial(ctx, "wss"+strings.TrimPrefix(srv.URL, "https")+"/api/v1/stream", &websocket.DialOptions{HTTPClient: client, HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}}, Subprotocols: []string{"serverdeck.v1"}})
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}
	write := func(conn *websocket.Conn, v any) {
		t.Helper()
		b, _ := json.Marshal(v)
		if err := conn.Write(ctx, websocket.MessageText, b); err != nil {
			t.Fatal(err)
		}
	}
	subscribe := func(conn *websocket.Conn, topic, after string) {
		t.Helper()
		sub := map[string]any{"id": topic, "topic": topic, "params": map[string]any{}}
		if after != "" {
			sub["after"] = after
		}
		write(conn, map[string]any{"schema_version": "1.0", "request_id": newID(t), "type": "subscribe", "subscriptions": []any{sub}})
	}
	read := func(conn *websocket.Conn) map[string]any {
		t.Helper()
		_, b, err := conn.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = contracts.Validate(bytes.NewReader(b), contracts.Target{Family: "api", Definition: "WssServerMessage"}, contracts.MaxJSONBytes); err != nil {
			t.Fatal(err, string(b))
		}
		return decodeMap(t, b)
	}
	first := dial()
	subscribe(first, "events", "")
	if read(first)["type"] != "subscribed" {
		t.Fatal("subscribe")
	}
	begin := read(first)
	if begin["topic"] != "events" || begin["data"].([]any)[0].(map[string]any)["kind"] != "begin" {
		t.Fatal(begin)
	}
	cursor := begin["cursor"].(string)
	first.CloseNow()
	second := dial()
	defer second.CloseNow()
	subscribe(second, "events", cursor)
	if read(second)["type"] != "subscribed" {
		t.Fatal("resume")
	}
	snapshot.At = contracts.Timestamp(time.Time(at).Add(time.Second))
	snapshot.Blocks[0].Metrics[0].Value = float64(16)
	if err := g.Events.Observe(ctx, []contracts.APIRule{r}, snapshot, time.Second); err != nil {
		t.Fatal(err)
	}
	recovery := read(second)
	if recovery["topic"] != "events" || len(recovery["data"].([]any)) != 1 || recovery["data"].([]any)[0].(map[string]any)["kind"] != "recovery" {
		t.Fatal("resume repeated begin or lost recovery", recovery)
	}
	write(second, map[string]any{"schema_version": "1.0", "type": "ack", "subscription_id": "events", "cursor": recovery["cursor"]})
	subscribe(second, "problems", "")
	if read(second)["type"] != "subscribed" {
		t.Fatal("problems subscribe")
	}
	changes := read(second)
	items := changes["data"].([]any)
	if changes["topic"] != "problems" || len(items) != 2 || items[1].(map[string]any)["removed"] != true {
		t.Fatal("problem tombstone", changes)
	}
	if err := g.eventsDB.Prune(ctx, time.Now().Add(24*time.Hour).UnixMicro(), 1); err != nil {
		t.Fatal(err)
	}
	status, raw := query(t, client, srv.URL, token, "events.list", map[string]any{"cursor": cursor})
	if status == 200 || !strings.Contains(string(raw), "CURSOR_GAP") {
		t.Fatal("stale cursor", status, string(raw))
	}
}
