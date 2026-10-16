//go:build linux && cgo

// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/diagnostics"
	"serverdeck.local/agent/internal/metrics"
	"serverdeck.local/agent/internal/operations"
	"serverdeck.local/agent/internal/storage"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestE07ConfigProbeReplayVersionAndAudit(t *testing.T) {
	g, path, _ := newTestGateway(t)
	ctx := context.Background()
	_, rev, e := g.Store.Settings(ctx)
	if e != nil {
		t.Fatal(e)
	}
	_ = rev
	// Read-only default, then an audited, versioned shared setting.
	c, e := g.icmpConfig(ctx)
	if e != nil || c.Target != nil || g.Diagnostics.Last(c).Status != "not_configured" {
		t.Fatal(c, e)
	}
	config, e := g.Query(ctx, "config.get", []byte(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(config)
	var value map[string]any
	json.Unmarshal(b, &value)
	version := value["version"].(string)
	applyTelemetry(t, g, "config.set", version, map[string]any{"changes": map[string]any{"icmp": map[string]any{"target": "127.0.0.1", "background_enabled": false}}})
	c, e = g.icmpConfig(ctx)
	if e != nil || c.Target == nil {
		t.Fatal(c, e)
	}
	params, _ := json.Marshal(icmpParams{c.Version})
	r := operations.Request{ID: newID(t), Action: "diagnostics.icmp.run", Params: params, Expected: c.Version}
	plan, e := g.Operations.Prepare(ctx, operations.Local(), r)
	if e != nil {
		t.Fatal(e)
	}
	r.Plan = plan.ID
	db, e := sql.Open("sqlite3", "file:"+filepath.Join(path, "critical.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if _, e = db.Exec(`CREATE TRIGGER e07_no_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'fixture'); END`); e != nil {
		t.Fatal(e)
	}
	if _, e = g.Operations.Execute(ctx, operations.Local(), r); e == nil {
		t.Fatal("audit bypass")
	}
	if g.Diagnostics.Last(c).ObservedAt != nil {
		t.Fatal("probe before intent")
	}
	if _, e = db.Exec(`DROP TRIGGER e07_no_audit`); e != nil {
		t.Fatal(e)
	}
	result, e := g.Operations.Execute(ctx, operations.Local(), r)
	if e != nil || result.State != "succeeded" {
		t.Fatal(result, e)
	}
	var observed diagnostics.Result
	if json.Unmarshal(result.Result, &observed) != nil || observed.Status != "available" || observed.Sent != 5 {
		t.Fatal(string(result.Result))
	}
	replay, e := g.Operations.Execute(ctx, operations.Local(), r)
	if e != nil || string(replay.Result) != string(result.Result) {
		t.Fatal("replay", replay, e)
	}
	other := r
	other.Params = []byte(`{"target_version":"different"}`)
	if _, e = g.Operations.Execute(ctx, operations.Local(), other); e == nil {
		t.Fatal("changed idempotency accepted")
	}
	stale := r
	stale.ID = newID(t)
	stale.Plan = ""
	stale.Params = []byte(`{"target_version":"different"}`)
	if _, e = g.Operations.Prepare(ctx, operations.Local(), stale); e != storage.ErrVersion {
		t.Fatal("version", e)
	}
}

func TestE07RealSignalAuditLossReplayAndRecovery(t *testing.T) {
	g, path, seed := newTestGateway(t)
	ctx := context.Background()
	// An isolated helper creates a test target outside the Agent process tree.
	out, e := exec.Command("/usr/bin/python3", "-c", `import subprocess; p=subprocess.Popen(["/bin/sleep","60"],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True); print(p.pid)`).Output()
	if e != nil {
		t.Fatal(e)
	}
	pid, e := strconv.Atoi(strings.TrimSpace(string(out)))
	if e != nil {
		t.Fatal(e)
	}

	collector, e := metrics.NewLinux()
	if e != nil {
		t.Fatal(e)
	}
	g.Metrics = metrics.New(g.RunID, collector.BootID(), collector)
	deadline := time.Now().Add(5 * time.Second)
	var ref string
	for ref == "" {
		snapshot := g.Metrics.Snapshot("detail", []string{"processes"}, nil)
		for _, block := range snapshot.Blocks {
			for _, raw := range block.Records {
				var p struct {
					Pid int    `json:"pid"`
					Ref string `json:"process_ref"`
				}
				json.Unmarshal(raw, &p)
				if p.Pid == pid {
					ref = p.Ref
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("target not collected")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Cleanup also checks instance identity and uses pidfd, never a stale raw PID.
	captured, e := g.Metrics.Process(ref)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _, _ = g.Control.Signal(context.Background(), captured, true) })
	params, _ := json.Marshal(processParams{ref})
	r := operations.Request{ID: newID(t), Action: "process.term", Expected: ref, Params: params}
	plan, e := g.Operations.Prepare(ctx, operations.Local(), r)
	if e != nil {
		t.Fatal(e)
	}
	r.Plan = plan.ID
	// A TERM plan cannot authorize KILL.
	changed := r
	changed.Action = "process.kill"
	if _, e = g.Operations.Execute(ctx, operations.Local(), changed); e == nil {
		t.Fatal("TERM plan used for KILL")
	}
	db, e := sql.Open("sqlite3", "file:"+filepath.Join(path, "critical.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if _, e = db.Exec(`CREATE TRIGGER e07_intent_failure BEFORE INSERT ON audit WHEN NEW.kind='intent' BEGIN SELECT RAISE(ABORT,'fixture'); END`); e != nil {
		t.Fatal(e)
	}
	if _, e = g.Operations.Execute(ctx, operations.Local(), r); e == nil {
		t.Fatal("signal bypassed audit")
	}
	if syscall.Kill(pid, 0) != nil {
		t.Fatal("effect before audit")
	}
	db.Exec(`DROP TRIGGER e07_intent_failure`)
	if _, e = db.Exec(`CREATE TRIGGER e07_result_failure BEFORE INSERT ON audit WHEN NEW.kind='result' BEGIN SELECT RAISE(ABORT,'fixture'); END`); e != nil {
		t.Fatal(e)
	}
	result, e := g.Operations.Execute(ctx, operations.Local(), r)
	if e == nil || result.State != "succeeded" || result.AuditStatus != "result_pending" {
		t.Fatal("dishonest outcome", result, e)
	}
	var signal struct {
		Sent bool `json:"signal_sent"`
	}
	if json.Unmarshal(result.Result, &signal) != nil || !signal.Sent {
		t.Fatal(string(result.Result))
	}
	// Idempotent replay returns memory-held outcome without rechecking a dead target.
	replay, e := g.Operations.Execute(ctx, operations.Local(), r)
	if e != nil || string(replay.Result) != string(result.Result) {
		t.Fatal("lost response replay", replay, e)
	}
	db.Exec(`DROP TRIGGER e07_result_failure`)
	g.Store.Close()
	reopened, e := storage.Open(ctx, path, "", seed, false, storage.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	recovered, e := reopened.Lookup(ctx, r.ID)
	if e != nil || recovered.State != "unknown" {
		t.Fatal("restart must not repeat", recovered, e)
	}
}

func TestE07StrictParamsPlansAndQueryContract(t *testing.T) {
	g, _, _ := newTestGateway(t)
	for _, raw := range []string{`{"process_ref":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pid":1}`, `{"process_ref":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","process_ref":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`, `{"process_ref":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} {}`} {
		if (processHandler{g: g}).Validate([]byte(raw)) == nil {
			t.Fatal("invalid process params", raw)
		}
	}
	ctx := context.Background()
	_, token := pairDirect(t, g)
	srv, client, _ := testHTTPS(t, g, false)
	status, _ := query(t, client, srv.URL, "", "diagnostics.icmp", map[string]any{})
	if status != 401 {
		t.Fatal("unauthorized diagnostics")
	}
	status, raw := query(t, client, srv.URL, token, "diagnostics.icmp", map[string]any{})
	if status != 200 {
		t.Fatal(status, string(raw))
	}
	if _, e := contracts.Validate(strings.NewReader(string(raw)), contracts.Target{Family: "api", Definition: "QueryResponse"}, contracts.MaxJSONBytes); e != nil {
		t.Fatal("wire", e)
	}
	_ = ctx
}

func TestE07ExplicitBackgroundContinuesWithoutAuditSpam(t *testing.T) {
	g, path, _ := newTestGateway(t)
	ctx := context.Background()
	config, e := g.Query(ctx, "config.get", []byte(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	version := config.(map[string]any)["version"].(string)
	applyTelemetry(t, g, "config.set", version, map[string]any{"changes": map[string]any{"icmp": map[string]any{"target": "127.0.0.1", "background_enabled": true}}})
	c, e := g.icmpConfig(ctx)
	if e != nil || !c.Background {
		t.Fatal(c, e)
	}
	db, e := sql.Open("sqlite3", "file:"+filepath.Join(path, "critical.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	var before, after int
	if e = db.QueryRow("SELECT count(*) FROM audit").Scan(&before); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec(`CREATE TRIGGER e07_background_no_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'fixture'); END`); e != nil {
		t.Fatal(e)
	}
	if _, e = g.Issue(ctx, operations.Local()); e == nil {
		t.Fatal("fixture audit did not fail")
	}
	g.backgroundICMP(ctx)
	observed := g.Diagnostics.Last(c)
	if observed.Status != "available" || observed.Sent != 5 {
		t.Fatal("monitor stopped with audit", observed)
	}
	if e = db.QueryRow("SELECT count(*) FROM audit").Scan(&after); e != nil || after != before {
		t.Fatal("background audit spam", before, after, e)
	}
	if g.Store.Health().AuditAvailable {
		t.Fatal("monitor masked audit failure")
	}
}
