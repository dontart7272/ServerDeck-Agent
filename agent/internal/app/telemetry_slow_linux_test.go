//go:build linux

// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"encoding/json"
	"github.com/coder/websocket"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestTelemetrySlowConsumerClosesWithoutDeletingState(t *testing.T) {
	g, _, _ := newTestGateway(t)
	_, token := pairDirect(t, g)
	srv, client, _ := testHTTPS(t, g, false)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "wss"+strings.TrimPrefix(srv.URL, "https")+"/api/v1/stream", &websocket.DialOptions{HTTPClient: client, HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}}, Subprotocols: []string{"serverdeck.v1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	payload, _ := json.Marshal(map[string]any{"schema_version": "1.0", "request_id": newID(t), "type": "subscribe", "subscriptions": []any{map[string]any{"id": "storage", "topic": "storage", "params": map[string]any{}}}})
	if err = conn.Write(ctx, websocket.MessageText, payload); err != nil {
		t.Fatal(err)
	}
	changes := 0
	for {
		_, raw, readErr := conn.Read(ctx)
		if readErr != nil {
			if websocket.CloseStatus(readErr) != websocket.StatusTryAgainLater {
				t.Fatal("expected ACK_TIMEOUT 1013", readErr)
			}
			break
		}
		var msg map[string]any
		json.Unmarshal(raw, &msg)
		if msg["type"] == "changes" {
			changes++
		}
	}
	if changes != 1 {
		t.Fatal("unacknowledged updates accumulated", changes)
	}
	if _, err = g.Store.AgentID(context.Background()); err != nil {
		t.Fatal("slow client affected critical state", err)
	}
}
