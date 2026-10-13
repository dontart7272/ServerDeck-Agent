// SPDX-License-Identifier: Apache-2.0
package operations

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"serverdeck.local/agent/internal/storage"
)

const installation = "11111111-1111-4111-8111-111111111111"
const operationID = "22222222-2222-4222-8222-222222222222"

func initial(t *testing.T) []byte {
	t.Helper()
	b, e := os.ReadFile("../../../Документация ServerDeck/Документация ServerDeck Agent/contracts/examples/config.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Runtime json.RawMessage `json:"runtime_initial"`
	}
	json.Unmarshal(b, &v)
	return v.Runtime
}
func openStore(t *testing.T, path string) *storage.Store {
	t.Helper()
	s, e := storage.Open(context.Background(), path, installation, initial(t), true, storage.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func database(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, e := sql.Open("sqlite3", "file:"+filepath.Join(path, "critical.db")+"?_busy_timeout=1000")
	if e != nil {
		t.Fatal(e)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return db
}

type fixture struct {
	path    string
	checks  atomic.Int32
	effects atomic.Int32
	check   func(int32) error
	effect  func() Outcome
}

func (f *fixture) Validate(b []byte) error {
	if !json.Valid(b) {
		return storage.ErrInvalid
	}
	return nil
}
func (f *fixture) Keys(r Request) ([]string, error) { return []string{"fixture.object"}, nil }
func (f *fixture) Check(context.Context, Request) error {
	n := f.checks.Add(1)
	if f.check != nil {
		return f.check(n)
	}
	return nil
}
func (f *fixture) Effect(context.Context, Request) Outcome {
	f.effects.Add(1)
	if f.path != "" {
		file, e := os.OpenFile(f.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if e != nil {
			return Outcome{State: "unknown", Effect: "unknown", Code: "RECOVERY_REQUIRED"}
		}
		file.Write([]byte("x"))
		file.Sync()
		file.Close()
	}
	if f.effect != nil {
		return f.effect()
	}
	return Outcome{State: "succeeded", Effect: "applied", Result: []byte(`{"complete":true}`)}
}
func prepared(t *testing.T, svc *Service, a Initiator, id string) Request {
	t.Helper()
	r := Request{ID: id, Action: "fixture", Params: []byte(`{"secret":"never-audit-this"}`)}
	p, e := svc.Prepare(context.Background(), a, r)
	if e != nil {
		t.Fatal(e)
	}
	r.Plan = p.ID
	return r
}
func TestIntentFailureHasNoEffect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	s := openStore(t, path)
	f := &fixture{}
	svc := New(s, map[string]Handler{"fixture": f})
	r := prepared(t, svc, Local(), operationID)
	db := database(t, path)
	if _, e := db.Exec(`CREATE TRIGGER deny_intent BEFORE INSERT ON audit WHEN NEW.kind='intent' BEGIN SELECT RAISE(ABORT,'token password secret'); END`); e != nil {
		t.Fatal(e)
	}
	_, e := svc.Execute(context.Background(), Local(), r)
	if e == nil || f.effects.Load() != 0 || s.Health().AuditAvailable {
		t.Fatalf("effect before audit: %v", e)
	}
	if bytes.Contains([]byte(e.Error()), []byte("password")) {
		t.Fatal("raw SQLite error escaped")
	}
}
func TestResultFailureNoDuplicateAndRestartUnknown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	s := openStore(t, path)
	f := &fixture{path: filepath.Join(filepath.Dir(path), "effects")}
	svc := New(s, map[string]Handler{"fixture": f})
	r := prepared(t, svc, Local(), operationID)
	db := database(t, path)
	if _, e := db.Exec(`CREATE TRIGGER deny_result BEFORE INSERT ON audit WHEN NEW.kind='result' BEGIN SELECT RAISE(ABORT,'private diagnostic'); END`); e != nil {
		t.Fatal(e)
	}
	o, e := svc.Execute(context.Background(), Local(), r)
	if e != storage.ErrAudit || o.State != "succeeded" || o.Effect != "applied" || o.AuditStatus != "result_pending" {
		t.Fatalf("dishonest known effect: %+v %v", o, e)
	}
	if _, e = svc.Execute(context.Background(), Local(), r); e != nil || f.effects.Load() != 1 {
		t.Fatal("duplicate effect")
	}
	var raw string
	db.QueryRow("SELECT group_concat(actor||action||object||code,';') FROM audit").Scan(&raw)
	if bytes.Contains([]byte(raw), []byte("never-audit-this")) {
		t.Fatal("secret in audit")
	}
	db.Exec("DROP TRIGGER deny_result")
	db.Close()
	s.Close()
	s = openStore(t, path)
	svc = New(s, map[string]Handler{"fixture": f})
	o, e = svc.Execute(context.Background(), Local(), r)
	if e != nil || o.State != "unknown" || f.effects.Load() != 1 {
		t.Fatal("restart replayed effect")
	}
	other := prepared(t, svc, Local(), "44444444-4444-4444-8444-444444444444")
	if _, e = svc.Execute(context.Background(), Local(), other); e != storage.ErrBusy {
		t.Fatalf("unknown didn't retain object lock: %v", e)
	}
}
func TestConcurrentRepeatIdentityAndExternalVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	s := openStore(t, path)
	f := &fixture{}
	svc := New(s, map[string]Handler{"fixture": f})
	a := Initiator{id: "device:fixtureA"}
	r := prepared(t, svc, a, operationID)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := svc.Execute(context.Background(), a, r); errs <- e }()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil && e != storage.ErrBusy {
			t.Fatal(e)
		}
	}
	if f.effects.Load() != 1 {
		t.Fatal("concurrent duplicate")
	}
	if _, e := svc.Execute(context.Background(), a, r); e != nil {
		t.Fatal("retained replay failed")
	}
	if _, e := svc.Execute(context.Background(), Initiator{id: "device:fixtureB"}, r); e != storage.ErrConflict {
		t.Fatal("initiator substitution")
	}
	r.Params = []byte(`{"secret":"changed"}`)
	if _, e := svc.Execute(context.Background(), a, r); e != storage.ErrConflict {
		t.Fatal("parameter substitution")
	}
	changed := atomic.Bool{}
	f.check = func(n int32) error {
		if changed.Load() {
			return storage.ErrVersion
		}
		return nil
	}
	r = prepared(t, svc, a, "44444444-4444-4444-8444-444444444444")
	changed.Store(true)
	if _, e := svc.Execute(context.Background(), a, r); e != storage.ErrVersion || f.effects.Load() != 1 {
		t.Fatal("external version change missed")
	}
}
func TestCancellationBeforeEffect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	s := openStore(t, path)
	entered := make(chan struct{})
	proceed := make(chan struct{})
	f := &fixture{check: func(n int32) error {
		if n == 3 {
			close(entered)
			<-proceed
		}
		return nil
	}}
	svc := New(s, map[string]Handler{"fixture": f})
	r := prepared(t, svc, Local(), operationID)
	done := make(chan storage.Operation)
	go func() { o, _ := svc.Execute(context.Background(), Local(), r); done <- o }()
	<-entered
	if e := svc.Cancel(Local(), operationID); e != nil {
		t.Fatal(e)
	}
	close(proceed)
	o := <-done
	if o.State != "cancelled" || o.Effect != "none" || f.effects.Load() != 0 {
		t.Fatal("cancelled effect occurred")
	}
	if e := svc.Cancel(Local(), operationID); !errors.Is(e, ErrCancel) {
		t.Fatal("terminal cancellation accepted")
	}
}

func TestDisconnectAfterIntentDoesNotCancel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	s := openStore(t, path)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &fixture{check: func(n int32) error {
		if n == 3 {
			cancel()
		}
		return nil
	}}
	svc := New(s, map[string]Handler{"fixture": f})
	r := prepared(t, svc, Local(), operationID)
	o, e := svc.Execute(ctx, Local(), r)
	if e != nil || o.State != "succeeded" || f.effects.Load() != 1 {
		t.Fatalf("disconnect cancelled accepted operation: %+v %v", o, e)
	}
}

func TestAuditedCancellationRequiresDurableControlAndCanWinBeforeEffect(t *testing.T) {
	s := openStore(t, filepath.Join(t.TempDir(), "state"))
	f := &fixture{}
	entered, release := make(chan struct{}), make(chan struct{})
	f.check = func(n int32) error {
		if n == 3 {
			close(entered)
			<-release
		}
		return nil
	}
	svc := New(s, map[string]Handler{"fixture": f})
	r := prepared(t, svc, Local(), operationID)
	finished := make(chan storage.Operation, 1)
	go func() { o, _ := svc.Execute(context.Background(), Local(), r); finished <- o }()
	<-entered
	control := "44444444-4444-4444-8444-444444444444"
	if _, e := svc.CancelAudited(context.Background(), control, operationID, 1, nil); e == nil {
		close(release)
		t.Fatal("cancel bypassed durable intent")
	}
	mac, e := s.Fingerprint("local:0", "operations.cancel", []byte(`{}`), "")
	if e != nil {
		close(release)
		t.Fatal(e)
	}
	if _, _, e = s.Intent(context.Background(), storage.Operation{ID: control, Actor: "local:0", Action: "operations.cancel", MAC: mac}, []string{"operations.control"}); e != nil {
		close(release)
		t.Fatal(e)
	}
	if e = s.MarkRunning(context.Background(), control); e != nil {
		close(release)
		t.Fatal(e)
	}
	if state, e := svc.CancelAudited(context.Background(), control, operationID, 1, nil); e != nil || state != "cancelled" {
		close(release)
		t.Fatal("audited cancel did not win", e)
	}
	close(release)
	o := <-finished
	if o.State != "cancelled" || f.effects.Load() != 0 {
		t.Fatal("cancelled operation produced effect")
	}
	if e = s.Finish(context.Background(), control, "succeeded", "applied", "", []byte(`{"target_operation_id":"22222222-2222-4222-8222-222222222222","state":"cancelled"}`)); e != nil {
		t.Fatal(e)
	}
}
func TestRealConfigCAS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	s := openStore(t, path)
	svc := New(s, map[string]Handler{"config.set": ConfigHandler{s}})
	r := Request{ID: operationID, Action: "config.set", Expected: "1", Params: []byte(`{"audit":{"retention_days":30,"budget_bytes":64000000}}`)}
	p, e := svc.Prepare(context.Background(), Local(), r)
	if e != nil {
		t.Fatal(e)
	}
	r.Plan = p.ID
	o, e := svc.Execute(context.Background(), Local(), r)
	if e != nil || o.State != "succeeded" {
		t.Fatalf("config operation: %v %+v", e, o)
	}
	_, v, e := s.Settings(context.Background())
	if e != nil || v != 2 {
		t.Fatal("CAS not saved")
	}
	r.ID = "44444444-4444-4444-8444-444444444444"
	if _, e = svc.Prepare(context.Background(), Local(), r); e != storage.ErrVersion {
		t.Fatal("stale settings accepted")
	}
	if e = s.ApplySettings(context.Background(), r.ID, 2, initial(t)); e != storage.ErrSafety {
		t.Fatal("audit bypass accepted")
	}
}
func TestQueueBoundsParallelismAndFairness(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	s := openStore(t, path)
	svc := New(s, nil)
	ctx := context.Background()
	releases := []func(){}
	for i := 0; i < 4; i++ {
		r, e := svc.wait(ctx, "device:busy", []string{fmt.Sprintf("object:%d", i)}, false)
		if e != nil {
			t.Fatal(e)
		}
		releases = append(releases, r)
	}
	got := make(chan string, 3)
	fin := make(chan struct{})
	var wg sync.WaitGroup
	for _, actor := range []string{"device:A", "device:A", "device:B"} {
		wg.Add(1)
		go func(a string) {
			defer wg.Done()
			r, e := svc.wait(ctx, a, []string{"shared"}, false)
			if e != nil {
				t.Error(e)
				return
			}
			got <- a
			<-fin
			r()
		}(actor)
	}
	deadline := time.Now().Add(time.Second)
	for {
		svc.mu.Lock()
		n := len(svc.queue)
		svc.mu.Unlock()
		if n == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("queue not entered")
		}
		time.Sleep(time.Millisecond)
	}
	for _, r := range releases {
		r()
	}
	first := <-got
	fin <- struct{}{}
	second := <-got
	if first == second {
		t.Fatalf("ready actor starved: %s then %s", first, second)
	}
	fin <- struct{}{}
	<-got
	fin <- struct{}{}
	wg.Wait()
	svc.mu.Lock()
	if svc.active != 0 || len(svc.queue) != 0 {
		t.Fatal("slots leaked")
	}
	svc.mu.Unlock()
}
func TestCrashChild(t *testing.T) {
	stage := os.Getenv("SERVERDECK_CRASH_STAGE")
	if stage == "" {
		return
	}
	path := os.Getenv("SERVERDECK_CRASH_STATE")
	s := openStore(t, path)
	f := &fixture{path: filepath.Join(filepath.Dir(path), "effects")}
	f.check = func(n int32) error {
		if (stage == "before_intent" && n == 2) || (stage == "after_intent" && n == 3) {
			os.Exit(83)
		}
		return nil
	}
	f.effect = func() Outcome {
		if stage == "after_effect" {
			os.Exit(83)
		}
		return Outcome{State: "succeeded", Effect: "applied", Result: []byte("null")}
	}
	if stage == "before_effect" {
		f.effect = nil
		f.check = func(n int32) error { return nil }
		f.effect = func() Outcome { os.Exit(83); return Outcome{} }
		f.path = ""
	}
	svc := New(s, map[string]Handler{"fixture": f})
	r := prepared(t, svc, Local(), operationID)
	if _, e := svc.Execute(context.Background(), Local(), r); e != nil {
		t.Fatal(e)
	}
	if stage == "after_result" {
		os.Exit(83)
	}
}
func TestCrashRecoveryRealProcess(t *testing.T) {
	for _, stage := range []string{"before_intent", "after_intent", "before_effect", "after_effect", "after_result"} {
		t.Run(stage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state")
			cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$")
			cmd.Env = append(os.Environ(), "SERVERDECK_CRASH_STAGE="+stage, "SERVERDECK_CRASH_STATE="+path)
			b, e := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(e, &exit) || exit.ExitCode() != 83 {
				t.Fatalf("child %v %s", e, b)
			}
			s := openStore(t, path)
			f := &fixture{path: filepath.Join(filepath.Dir(path), "effects")}
			svc := New(s, map[string]Handler{"fixture": f})
			o, e := svc.Get(context.Background(), operationID)
			if stage == "before_intent" {
				if e != storage.ErrNotFound {
					t.Fatal("pre-intent operation appeared")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			want := "unknown"
			if stage == "after_result" {
				want = "succeeded"
			}
			if o.State != want {
				t.Fatalf("recovery %s want %s", o.State, want)
			}
			r := Request{ID: operationID, Action: "fixture", Params: []byte(`{"secret":"never-audit-this"}`)}
			if _, e = svc.Execute(context.Background(), Local(), r); e != nil || f.effects.Load() != 0 {
				t.Fatal("crash replayed effect")
			}
			effects, _ := os.ReadFile(f.path)
			n := 0
			if stage == "after_effect" || stage == "after_result" {
				n = 1
			}
			if len(effects) != n {
				t.Fatalf("effects=%d want %d", len(effects), n)
			}
		})
	}
}
