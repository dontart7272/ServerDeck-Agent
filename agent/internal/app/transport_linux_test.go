// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/operations"
	"serverdeck.local/agent/internal/storage"
)

func TestAuditFailureCannotPairOrRevokeAndObservationKeepsFailureVisible(t *testing.T) {
	for _, phase := range []string{"issue", "pair", "revoke"} {
		t.Run(phase, func(t *testing.T) {
			g, path, _ := newTestGateway(t)
			ctx := context.Background()
			id, token := pairDirect(t, g)
			code, e := g.Issue(ctx, operations.Local())
			if e != nil {
				t.Fatal(e)
			}
			db, e := sql.Open("sqlite3", "file:"+filepath.Join(path, "critical.db")+"?_busy_timeout=1000")
			if e != nil {
				t.Fatal(e)
			}
			defer db.Close()
			if _, e = db.Exec(`CREATE TRIGGER test_audit_failure BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'fixture'); END`); e != nil {
				t.Fatal(e)
			}
			switch phase {
			case "issue":
				if _, e = g.Issue(ctx, operations.Local()); e == nil {
					t.Fatal("code returned without audit")
				}
			case "pair":
				r := pairRequest(t, code)
				if _, e = g.Pair(ctx, r); e == nil {
					t.Fatal("token returned without audit")
				}
			case "revoke":
				params, _ := json.Marshal(map[string]string{"device_id": id, "expected_version": "1"})
				r := operations.Request{ID: newID(t), Action: "devices.revoke", Params: params}
				p, e := g.Operations.Prepare(ctx, operations.Local(), r)
				if e != nil {
					t.Fatal(e)
				}
				r.Plan = p.ID
				if o, e := g.Operations.Execute(ctx, operations.Local(), r); e == nil && o.State == "succeeded" {
					t.Fatal("revocation bypassed audit")
				}
			}
			devices, e := g.Store.Devices(ctx)
			if e != nil || len(devices) != 1 || devices[0].RevokedAt != nil {
				t.Fatal("effect before audited intent")
			}
			if _, e = g.Auth.Authenticate(ctx, token); e != nil {
				t.Fatal("monitoring credential lost")
			}
			if g.Store.Health().AuditAvailable {
				t.Fatal("last_seen hid failed audit")
			}
			if _, e = db.Exec("DROP TRIGGER test_audit_failure"); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestHTTPPreparedRevokeIdempotencyVersionsAndInitiator(t *testing.T) {
	g, _, _ := newTestGateway(t)
	target, token := pairDirect(t, g)
	actorID, operator := pairDirect(t, g)
	srv, c, _ := testHTTPS(t, g, false)
	op := newID(t)
	params := map[string]any{"device_id": target, "expected_version": "1"}
	prep := map[string]any{"schema_version": "1.0", "request_id": newID(t), "operation_id": op, "action": "devices.revoke", "params": params}
	status, b := request(t, c, srv.URL+"/api/v1/prepare", operator, prep)
	if status != 200 {
		t.Fatalf("prepare %d", status)
	}
	plan := decodeMap(t, b)["plan_id"]
	exec := map[string]any{"schema_version": "1.0", "request_id": newID(t), "operation_id": op, "action": "devices.revoke", "params": params, "plan_id": plan}
	status, b = request(t, c, srv.URL+"/api/v1/operations", operator, exec)
	if status != 202 {
		t.Fatalf("execute %d", status)
	}
	saved := decodeMap(t, b)
	if saved["state"] != "succeeded" || saved["initiator"].(map[string]any)["id"] != actorID {
		t.Fatal("incorrect outcome/initiator")
	}
	status, b = request(t, c, srv.URL+"/api/v1/operations", operator, exec)
	if status != 202 || decodeMap(t, b)["revision"] != saved["revision"] {
		t.Fatal("repeat changed operation")
	}
	params["expected_version"] = "2"
	status, _ = request(t, c, srv.URL+"/api/v1/operations", operator, exec)
	if status != 409 {
		t.Fatalf("changed idempotent request %d", status)
	}
	if status, _ = query(t, c, srv.URL, token, "agent.info", map[string]any{}); status != 401 {
		t.Fatal("revoked token accepted")
	}
	prep["operation_id"] = newID(t)
	status, _ = request(t, c, srv.URL+"/api/v1/prepare", operator, prep)
	if status != 409 {
		t.Fatalf("stale version %d", status)
	}
}

func TestWSSBoundsDuplicateSubscriptionsCrossAckAndOrigin(t *testing.T) {
	g, _, _ := newTestGateway(t)
	_, token := pairDirect(t, g)
	srv, _, conf := testHTTPS(t, g, false)
	tr := &http.Transport{TLSClientConfig: conf}
	defer tr.CloseIdleConnections()
	dial := func(header http.Header) (*websocket.Conn, *http.Response, error) {
		return websocket.Dial(context.Background(), "wss"+strings.TrimPrefix(srv.URL, "https")+"/api/v1/stream", &websocket.DialOptions{HTTPClient: &http.Client{Transport: tr, Timeout: 3 * time.Second}, HTTPHeader: header, Subprotocols: []string{"serverdeck.v1"}})
	}
	headers := func() http.Header { return http.Header{"Authorization": []string{"Bearer " + token}} }
	h := headers()
	h.Set("Origin", "https://hostile.invalid")
	if ws, _, e := dial(h); e == nil {
		ws.CloseNow()
		t.Fatal("browser origin accepted")
	}
	a, _, e := dial(headers())
	if e != nil {
		t.Fatal(e)
	}
	defer a.CloseNow()
	b, _, e := dial(headers())
	if e != nil {
		t.Fatal(e)
	}
	defer b.CloseNow()
	if ws, _, e := dial(headers()); e == nil {
		ws.CloseNow()
		t.Fatal("third WSS accepted")
	}
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	subscriptions := []any{map[string]any{"id": "s", "topic": "storage", "params": map[string]any{}}}
	send := func(ws *websocket.Conn, subs []any) {
		data, _ := json.Marshal(map[string]any{"schema_version": "1.0", "request_id": newID(t), "type": "subscribe", "subscriptions": subs})
		if e := ws.Write(ctx, websocket.MessageText, data); e != nil {
			t.Fatal(e)
		}
	}
	send(a, subscriptions)
	_, _, e = a.Read(ctx)
	if e != nil {
		t.Fatal(e)
	}
	_, data, e := a.Read(ctx)
	if e != nil {
		t.Fatal(e)
	}
	cursor := decodeMap(t, data)["cursor"]
	send(b, subscriptions)
	_, _, e = b.Read(ctx)
	if e != nil {
		t.Fatal(e)
	}
	_, _, e = b.Read(ctx)
	if e != nil {
		t.Fatal(e)
	}
	// Both snapshots may share position/scope but the exact pending cursor is
	// session-bound by subscription state. A foreign subscription ID is refused.
	ack, _ := json.Marshal(map[string]any{"schema_version": "1.0", "type": "ack", "subscription_id": "s", "cursor": cursor})
	b.Write(ctx, websocket.MessageText, ack)
	_, _, _ = b.Read(ctx)
	_, _, e = b.Read(ctx)
	if websocket.CloseStatus(e) != websocket.StatusPolicyViolation {
		t.Fatal("cross session ACK accepted")
	}
	send(a, subscriptions)
	_, _, _ = a.Read(ctx)
	_, _, e = a.Read(ctx)
	if websocket.CloseStatus(e) != websocket.StatusPolicyViolation {
		t.Fatal("duplicate subscription accepted")
	}
}

func TestRateBoundsAndCursorScopeTamper(t *testing.T) {
	l := newLimiter()
	now := time.Now()
	l.now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		if !l.allow("unauth:one", 2, 5) {
			t.Fatal("burst")
		}
	}
	if !l.blocked("unauth:one") || l.allow("unauth:one", 2, 5) {
		t.Fatal("flood allowed")
	}
	now = now.Add(500 * time.Millisecond)
	if l.blocked("unauth:one") || !l.allow("unauth:one", 2, 5) {
		t.Fatal("refill")
	}
	l = newLimiter()
	for i := 0; i < 1024; i++ {
		if !l.allow(fmt.Sprintf("unauth:%d", i), 2, 5) {
			t.Fatal("IP capacity")
		}
	}
	if l.allow("pair:extra", .2, 3) {
		t.Fatal("IP table unbounded")
	}
	g, _, _ := newTestGateway(t)
	pairDirect(t, g)
	pairDirect(t, g)
	first, e := g.Query(context.Background(), "devices.list", []byte(`{"limit":1}`))
	if e != nil {
		t.Fatal(e)
	}
	cursor := first.(map[string]any)["next_cursor"].(string)
	params, _ := json.Marshal(map[string]any{"cursor": cursor, "limit": 1})
	if _, e = g.Query(context.Background(), "devices.list", params); e != nil {
		t.Fatal(e)
	}
	changed := cursor[:len(cursor)-1] + "!"
	if _, e = g.position(changed, "devices.list", scope([]byte(`{}`))); !errors.Is(e, storage.ErrCursor) {
		t.Fatal("tampered cursor accepted")
	}
	if _, e = g.position(cursor, "operations.list", scope([]byte(`{}`))); !errors.Is(e, storage.ErrCursor) {
		t.Fatal("wrong kind accepted")
	}
	devices, _ := g.Store.Devices(context.Background())
	revokeDirect(t, g, operations.Local(), devices[0].ID)
	if _, e = g.Query(context.Background(), "devices.list", params); !errors.Is(e, storage.ErrCursor) {
		t.Fatal("stale registry page accepted")
	}
}

// Handler-only error checks do not stand in for the real TLS tests above.
func TestMalformedHeadersAndPairingFlood(t *testing.T) {
	g, _, _ := newTestGateway(t)
	srv, c, _ := testHTTPS(t, g, false)
	for i := 0; i < 4; i++ {
		status, b := request(t, c, srv.URL+"/api/v1/pair", "", map[string]any{"schema_version": "1.0", "request_id": newID(t), "pairing_id": newID(t), "pairing_code": strings.Repeat("A", 22), "device_name": "phone"})
		if i < 3 && status != 401 || i == 3 && status != 429 {
			t.Fatalf("pairing flood %d: %d", i, status)
		}
		if bytes.Contains(b, []byte(strings.Repeat("A", 22))) {
			t.Fatal("error echoed secret")
		}
	}
	r := httptest.NewRequest("POST", "https://localhost/api/v1/query", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.TLS = nil
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("plaintext accepted")
	}
}

func TestFloorPublicationFailurePreservesCommittedRevocation(t *testing.T) {
	g, path, _ := newTestGateway(t)
	id, token := pairDirect(t, g)
	ctx := context.Background()
	if e := os.Mkdir(filepath.Join(path, "security-floor.next"), 0700); e != nil {
		t.Fatal(e)
	}
	params, _ := json.Marshal(map[string]string{"device_id": id, "expected_version": "1"})
	r := operations.Request{ID: newID(t), Action: "devices.revoke", Params: params}
	p, e := g.Operations.Prepare(ctx, operations.Local(), r)
	if e != nil {
		t.Fatal(e)
	}
	r.Plan = p.ID
	o, e := g.Operations.Execute(ctx, operations.Local(), r)
	if e != nil || o.State != "unknown" || o.Effect != "partial" || o.Code != "SAFETY_UNAVAILABLE" {
		t.Fatalf("dishonest publication failure: %v %s %s", e, o.State, o.Effect)
	}
	if _, e = g.Auth.Authenticate(ctx, token); !errors.Is(e, storage.ErrUnauthorized) {
		t.Fatal("revocation undone on publication failure")
	}
	if g.Store.Health().SecurityFloorAvailable {
		t.Fatal("floor failure invisible")
	}
	repeat, e := g.Operations.Execute(ctx, operations.Local(), r)
	if e != nil || repeat.Revision != o.Revision {
		t.Fatal("unknown mutation retried")
	}
}

func TestRetiredRegistryBoundDoesNotResurrectPrunedToken(t *testing.T) {
	g, path, _ := newTestGateway(t)
	ctx := context.Background()
	var first string
	for i := 0; i < 34; i++ {
		if i > 0 {
			g.Auth.Close()
			next, e := NewGateway(g.Store, g.Certificate, "fixture")
			if e != nil {
				t.Fatal(e)
			}
			g = next
		}
		id, token := pairDirect(t, g)
		if i == 0 {
			first = token
		}
		revokeDirect(t, g, operations.Local(), id)
	}
	defer g.Close()
	devices, e := g.Store.Devices(ctx)
	if e != nil || len(devices) != 32 {
		t.Fatal("retired registry not bounded")
	}
	if _, e = g.Auth.Authenticate(ctx, first); !errors.Is(e, storage.ErrUnauthorized) {
		t.Fatal("pruned identity active")
	}
	// Earlier restore test covers old snapshots. Here the authenticated floor
	// itself must not retain an unbounded tombstone list.
	if b, e := os.ReadFile(filepath.Join(path, "security-floor.json")); e != nil || len(b) > 65536 {
		t.Fatal("floor exceeds bound")
	}
}

func TestHTTPCancellationHasTypedAuditedTooLateResult(t *testing.T) {
	g, _, _ := newTestGateway(t)
	_, token := pairDirect(t, g)
	entries, _, e := g.Store.Audit(context.Background(), 0, 100)
	if e != nil {
		t.Fatal(e)
	}
	target, e := g.Store.Lookup(context.Background(), entries[0].OperationID)
	if e != nil {
		t.Fatal(e)
	}
	srv, c, _ := testHTTPS(t, g, false)
	op := newID(t)
	params := map[string]any{"target_operation_id": target.ID, "expected_version": fmt.Sprint(target.Revision)}
	payload := map[string]any{"schema_version": "1.0", "request_id": newID(t), "operation_id": op, "action": "operations.cancel", "params": params}
	status, b := request(t, c, srv.URL+"/api/v1/prepare", token, payload)
	if status != 200 {
		t.Fatalf("prepare cancellation %d", status)
	}
	payload["plan_id"] = decodeMap(t, b)["plan_id"]
	status, b = request(t, c, srv.URL+"/api/v1/operations", token, payload)
	if status != 202 {
		t.Fatalf("cancel %d", status)
	}
	result := decodeMap(t, b)
	if result["state"] != "succeeded" || result["result"].(map[string]any)["state"] != "too_late" {
		t.Fatal("terminal operation falsely cancelled")
	}
	unchanged, e := g.Store.Lookup(context.Background(), target.ID)
	if e != nil || unchanged.Revision != target.Revision {
		t.Fatal("late cancel changed terminal target")
	}
}

func TestDifferentPairingCodesCannotOverwriteSamePendingRequest(t *testing.T) {
	g, _, _ := newTestGateway(t)
	ctx := context.Background()
	a, e := g.Issue(ctx, operations.Local())
	if e != nil {
		t.Fatal(e)
	}
	b, e := g.Issue(ctx, operations.Local())
	if e != nil {
		t.Fatal(e)
	}
	id := newID(t)
	// Pin the exact interleaving deterministically before exercising real
	// concurrent requests: the first valid proof already owns this RAM slot.
	proof, e := g.Auth.VerifyCode(ctx, a.ID, a.Secret)
	if e != nil {
		t.Fatal(e)
	}
	g.mu.Lock()
	g.pairs[id] = pendingPair{proof: proof}
	g.pairIDs[a.ID] = true
	g.mu.Unlock()
	blocked := contracts.APIPairRequest{SchemaVersion: "1.0", RequestId: id, PairingId: b.ID, PairingCode: b.Secret, DeviceName: "blocked"}
	if _, e = g.Pair(ctx, blocked); e == nil {
		t.Fatal("reserved request overwritten")
	}
	g.mu.Lock()
	unchanged := g.pairs[id].proof.ID() == a.ID
	delete(g.pairs, id)
	delete(g.pairIDs, a.ID)
	g.mu.Unlock()
	if !unchanged {
		t.Fatal("pending proof replaced")
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan map[string]any, 2)
	for _, r := range []contracts.APIPairRequest{{SchemaVersion: "1.0", RequestId: id, PairingId: a.ID, PairingCode: a.Secret, DeviceName: "one"}, {SchemaVersion: "1.0", RequestId: id, PairingId: b.ID, PairingCode: b.Secret, DeviceName: "two"}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if value, e := g.Pair(ctx, r); e == nil {
				results <- value
			}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	wins := 0
	for result := range results {
		wins++
		c, e := g.Auth.Authenticate(ctx, result["token"].(string))
		if e != nil || c.ID() != result["device_id"] {
			t.Fatal("pairing response not bound to committed credential")
		}
	}
	devices, e := g.Store.Devices(ctx)
	if e != nil || wins != 1 || len(devices) != 1 {
		t.Fatal("duplicate or mismatched pending request")
	}
}
