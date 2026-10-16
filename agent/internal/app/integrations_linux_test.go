// SPDX-License-Identifier: Apache-2.0
//go:build linux && cgo

package app

import (
	"context"
	"serverdeck.local/agent/internal/metrics"
	"strings"
	"testing"
	"time"
)

func TestSecurityHooksPersistCursorAndDeduplicateInfoOnRealSQLite(t *testing.T) {
	g, _, _ := newTestGateway(t)
	h := g.securityHooks()
	ctx := context.Background()
	raw := []byte(`{"Seq":1,"Version":1}`)
	if err := h.Save(ctx, "ssh.auth", raw); err != nil {
		t.Fatal(err)
	}
	got, err := h.Load(ctx, "ssh.auth")
	if err != nil || string(got) != string(raw) {
		t.Fatal(string(got), err)
	}
	a, err := h.Anchor([]byte("DO_NOT_EXPOSE_RAW_LOG"))
	if err != nil || len(a) != 64 || strings.Contains(a, "RAW") {
		t.Fatal(a, err)
	}
	b, err := h.Anchor([]byte("DO_NOT_EXPOSE_RAW_LOG"))
	if err != nil || a != b {
		t.Fatal("unstable anchor")
	}
	observation := metrics.AuthObservation{Source: "11111111-1111-4111-8111-111111111111", Position: 123, At: time.Now().UTC(), Code: "SSH_AUTH_SUCCESS"}
	for i := 0; i < 2; i++ {
		if err = h.Observation(ctx, observation); err != nil {
			t.Fatal(err)
		}
	}
	rows, _, _, err := g.eventsDB.Changes(ctx, "", 0, 100)
	if err != nil || len(rows) != 1 {
		t.Fatal(len(rows), err)
	}
	if !strings.Contains(string(rows[0].Data), `"severity":"info"`) {
		t.Fatal(string(rows[0].Data))
	}
}
