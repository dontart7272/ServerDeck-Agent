//go:build linux && cgo

// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/fileaccess"
	"serverdeck.local/agent/internal/operations"
	"serverdeck.local/agent/internal/storage"
	"sync"
	"testing"
	"time"
)

func runE08Operation(t *testing.T, g *Gateway, actor operations.Initiator, action string, params any) storage.Operation {
	t.Helper()
	b, _ := json.Marshal(params)
	r := operations.Request{ID: newID(t), Action: action, Params: b}
	p, e := g.Operations.Prepare(context.Background(), actor, r)
	if e != nil {
		t.Fatal(action, "prepare", e)
	}
	r.Plan = p.ID
	o, e := g.Operations.Execute(context.Background(), actor, r)
	if e != nil {
		t.Fatal(action, "execute", o.State, e)
	}
	return o
}
func e08Root(t *testing.T, g *Gateway, root string) (fileaccess.Location, string) {
	t.Helper()
	raw, _, e := g.Store.Settings(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	var c contracts.RuntimeConfig
	json.Unmarshal(raw, &c)
	l := fileaccess.Location{RootID: string(c.Files.Roots[0].RootID), Components: []string{}}
	f, e := g.Files.guard.Open(root, l)
	if e != nil {
		t.Fatal(e)
	}
	v, e := fileaccess.Version(f)
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	return l, v
}
func TestE08FileAuditBeforeEffectAndResultReplay(t *testing.T) {
	g, path, _ := newTestGateway(t)
	root := fixtureFiles(t, g)
	g.Files.guard.EnableSharedRoots()
	ctx := context.Background()
	parent, v := e08Root(t, g, root)
	b, _ := json.Marshal(fileCreateParams{Parent: parent, Name: "YXVkaXQ", Kind: "file", ParentVersion: v})
	r := operations.Request{ID: newID(t), Action: "files.create", Params: b}
	p, e := g.Operations.Prepare(ctx, operations.Local(), r)
	if e != nil {
		t.Fatal(e)
	}
	r.Plan = p.ID
	db, e := sql.Open("sqlite3", "file:"+filepath.Join(path, "critical.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if _, e = db.Exec(`CREATE TRIGGER e08_intent BEFORE INSERT ON audit WHEN NEW.kind='intent' BEGIN SELECT RAISE(ABORT,'fixture'); END`); e != nil {
		t.Fatal(e)
	}
	if _, e = g.Operations.Execute(ctx, operations.Local(), r); e == nil {
		t.Fatal("effect bypassed audit")
	}
	if _, e = os.Stat(filepath.Join(root, "audit")); !os.IsNotExist(e) {
		t.Fatal("file created without intent")
	}
	db.Exec(`DROP TRIGGER e08_intent`)
	if _, e = db.Exec(`CREATE TRIGGER e08_result BEFORE INSERT ON audit WHEN NEW.kind='result' BEGIN SELECT RAISE(ABORT,'fixture'); END`); e != nil {
		t.Fatal(e)
	}
	o, e := g.Operations.Execute(ctx, operations.Local(), r)
	if e == nil || o.State != "succeeded" || o.AuditStatus != "result_pending" {
		t.Fatal("dishonest file result", o.State, o.AuditStatus, e)
	}
	f, e := g.Files.guard.Open(root, fileaccess.Location{RootID: parent.RootID, Components: []string{"YXVkaXQ"}})
	if e != nil {
		t.Fatal(e)
	}
	proof, _ := fileaccess.IdentityProof(f)
	f.Close()
	replay, e := g.Operations.Execute(ctx, operations.Local(), r)
	if e != nil || replay.Revision != o.Revision {
		t.Fatal("replay", e)
	}
	f, e = g.Files.guard.Open(root, fileaccess.Location{RootID: parent.RootID, Components: []string{"YXVkaXQ"}})
	if e != nil {
		t.Fatal(e)
	}
	after, _ := fileaccess.IdentityProof(f)
	f.Close()
	if after != proof {
		t.Fatal("file effect repeated")
	}
	db.Exec(`DROP TRIGGER e08_result`)
}

func TestE08UploadRecoveryAndAuditedExpiry(t *testing.T) {
	g, path, _ := newTestGateway(t)
	root := fixtureFiles(t, g)
	g.Files.guard.EnableSharedRoots()
	ctx := context.Background()
	_, token := pairDirect(t, g)
	credential, e := g.Auth.Authenticate(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	actor := operations.Device(credential)
	srv, client, _ := testHTTPS(t, g, false)
	payload := []byte("recoverable staged bytes")
	sum := sha256.Sum256(payload)
	parent, v := e08Root(t, g, root)
	begin := runE08Operation(t, g, actor, "files.upload.begin", uploadParams{Parent: parent, Name: "cmVjb3Zlcg", ParentVersion: v, Size: int64(len(payload)), SHA: hex.EncodeToString(sum[:]), Conflict: "fail"})
	ticket := decodeMap(t, begin.Result)
	req, _ := http.NewRequest("PUT", srv.URL+"/api/v1/transfers/"+ticket["transfer_id"].(string)+"/content", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")
	res, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal(res.Status)
	}
	db, e := sql.Open("sqlite3", "file:"+filepath.Join(path, "critical.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if _, e = db.Exec(`CREATE TRIGGER e08_commit_result BEFORE UPDATE ON file_journal WHEN NEW.state='published' BEGIN SELECT RAISE(ABORT,'fixture'); END`); e != nil {
		t.Fatal(e)
	}
	commit := runE08Operation(t, g, actor, "files.transfer.commit", commitParams{ID: begin.ID, SHA: hex.EncodeToString(sum[:]), Size: int64(len(payload)), Expected: ticket["file_version"].(string)})
	if commit.State != "unknown" {
		t.Fatal("post-publication failure lost uncertainty", commit.State)
	}
	if b, e := os.ReadFile(filepath.Join(root, "recover")); e != nil || !bytes.Equal(b, payload) {
		t.Fatal("publication missing", e)
	}
	db.Exec(`DROP TRIGGER e08_commit_result`)
	row, _, e := g.transferRecord(ctx, begin.ID)
	if e != nil || row.State != "unknown" {
		t.Fatal(e, row.State)
	}
	offline := operations.Offline(g.Store)
	params, _ := json.Marshal(map[string]any{"record_id": row.ID, "expected_version": storage.FileRecordVersion(row), "state": "published"})
	r := operations.Request{ID: newID(t), Action: "files.reconcile", Params: params}
	p, e := offline.Prepare(ctx, operations.Local(), r)
	if e != nil {
		t.Fatal(e)
	}
	r.Plan = p.ID
	out, e := offline.Execute(ctx, operations.Local(), r)
	if e != nil || out.State != "succeeded" {
		t.Fatal("journal recovery", out, e)
	}
	if o, _ := g.Store.Lookup(ctx, commit.ID); o.State != "unknown" {
		t.Fatal("journal observation silently resolved uncertain effect")
	}
	if e = g.Operations.ResolveLocal(ctx, operations.Local(), commit.ID, "applied"); e != nil {
		t.Fatal(e)
	}
	location := fileaccess.Location{RootID: parent.RootID, Components: []string{"cmVjb3Zlcg"}}
	f, e := g.Files.guard.Open(root, location)
	if e != nil {
		t.Fatal(e)
	}
	version, _ := fileaccess.Version(f)
	f.Close()
	trash := runE08Operation(t, g, actor, "files.trash", trashParams{Location: location, Expected: version})
	trashID := decodeMap(t, trash.Result)["trash_id"].(string)
	g.Files.mu.Lock()
	g.Files.deadlines[trashID] = time.Now().Add(-time.Second)
	g.Files.mu.Unlock()
	g.sweepFiles(ctx)
	tr, _, e := g.trashRecord(ctx, trashID)
	if e != nil || tr.State != "purged" {
		t.Fatal("expiry did not use audited purge", e, tr.State)
	}
	var intents int
	if e = db.QueryRow("SELECT count(*) FROM audit WHERE action='system.trash.expire' AND kind='intent'").Scan(&intents); e != nil || intents != 1 {
		t.Fatal("expiry audit", intents, e)
	}
	g.sweepFiles(ctx)
	var after int
	db.QueryRow("SELECT count(*) FROM audit WHERE action='system.trash.expire' AND kind='intent'").Scan(&after)
	if after != intents {
		t.Fatal("expiry replay spam")
	}
}

func TestE08ParallelCreateHasOneWinnerAndPreservesVersion(t *testing.T) {
	g, _, _ := newTestGateway(t)
	root := fixtureFiles(t, g)
	g.Files.guard.EnableSharedRoots()
	ctx := context.Background()
	parent, v := e08Root(t, g, root)
	requests := []operations.Request{}
	for i := 0; i < 8; i++ {
		b, _ := json.Marshal(fileCreateParams{Parent: parent, Name: "c2hhcmVk", Kind: "file", ParentVersion: v})
		r := operations.Request{ID: newID(t), Action: "files.create", Params: b}
		p, e := g.Operations.Prepare(ctx, operations.Local(), r)
		if e != nil {
			t.Fatal(e)
		}
		r.Plan = p.ID
		requests = append(requests, r)
	}
	type observed struct {
		o storage.Operation
		e error
	}
	results := make(chan observed, len(requests))
	var wg sync.WaitGroup
	for _, r := range requests {
		wg.Add(1)
		go func(r operations.Request) {
			defer wg.Done()
			o, e := g.Operations.Execute(ctx, operations.Local(), r)
			results <- observed{o, e}
		}(r)
	}
	wg.Wait()
	close(results)
	winners := 0
	for result := range results {
		o := result.o
		if o.ID == "" {
			if !errors.Is(result.e, storage.ErrVersion) && !errors.Is(result.e, storage.ErrBusy) && !errors.Is(result.e, fileaccess.ErrChanged) {
				t.Fatal("unexpected concurrent refusal", result.e)
			}
			continue
		}
		if o.State == "succeeded" {
			winners++
		} else if o.Effect != "none" {
			t.Fatal("conflict claims effect", o.State, o.Effect)
		}
	}
	if winners != 1 {
		t.Fatal("concurrent winners", winners)
	}
	if b, e := os.ReadFile(filepath.Join(root, "shared")); e != nil || len(b) != 0 {
		t.Fatal(e)
	}
}

func TestE08AbortedUploadCleanupAndTwoTransferLimit(t *testing.T) {
	g, _, _ := newTestGateway(t)
	root := fixtureFiles(t, g)
	g.Files.guard.EnableSharedRoots()
	ctx := context.Background()
	_, token := pairDirect(t, g)
	c, e := g.Auth.Authenticate(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	actor := operations.Device(c)
	srv, client, _ := testHTTPS(t, g, false)
	payload := []byte("declared payload")
	sum := sha256.Sum256(payload)
	tickets := []storage.Operation{}
	for _, name := range []string{"Zmlyc3Q", "c2Vjb25k"} {
		parent, v := e08Root(t, g, root)
		tickets = append(tickets, runE08Operation(t, g, actor, "files.upload.begin", uploadParams{Parent: parent, Name: name, ParentVersion: v, Size: int64(len(payload)), SHA: hex.EncodeToString(sum[:]), Conflict: "fail"}))
	}
	parent, v := e08Root(t, g, root)
	b, _ := json.Marshal(uploadParams{Parent: parent, Name: "dGhpcmQ", ParentVersion: v, Size: int64(len(payload)), SHA: hex.EncodeToString(sum[:]), Conflict: "fail"})
	if _, e = g.Operations.Prepare(ctx, actor, operations.Request{ID: newID(t), Action: "files.upload.begin", Params: b}); !errors.Is(e, storage.ErrBusy) {
		t.Fatal("third transfer admitted", e)
	}
	bad := append(append([]byte{}, payload...), byte('x'))
	req, _ := http.NewRequest("PUT", srv.URL+"/api/v1/transfers/"+tickets[0].ID+"/content", bytes.NewReader(bad))
	req.ContentLength = -1
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")
	res, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode == 200 {
		t.Fatal("excess input accepted")
	}
	row, _, e := g.transferRecord(ctx, tickets[0].ID)
	if e != nil || row.State != "receiving" {
		t.Fatal("missing Content-Length changed staging state", row.State, e)
	}
	controlled := httptest.NewRequest("PUT", "http://local/api/v1/transfers/"+tickets[0].ID+"/content", bytes.NewReader(bad))
	controlled.ContentLength = int64(len(payload))
	controlled.Header.Set("Content-Type", "application/octet-stream")
	recorder := &e08DeadlineRecorder{httptest.NewRecorder()}
	g.fileReceive(recorder, controlled, actor.ID(), func(ctx context.Context) error { return g.Store.CheckCredential(ctx, c) }, ctx, &c)
	row, spec, e := g.transferRecord(ctx, tickets[0].ID)
	if e != nil || row.State != "failed" || recorder.Code == 200 {
		t.Fatal("abort state", row.State, e)
	}
	a, e := g.Files.guard.OpenArea(root, g.AgentID)
	if e != nil {
		t.Fatal(e)
	}
	f, e := a.Entry(row.ID)
	if e != nil {
		t.Fatal(e)
	}
	info, _ := f.Stat()
	f.Close()
	a.Close()
	if info.Size() > spec.Size {
		t.Fatal("excess bytes persisted")
	}
	retryRequest, _ := http.NewRequest("PUT", srv.URL+"/api/v1/transfers/"+tickets[0].ID+"/content", bytes.NewReader(payload))
	retryRequest.Header.Set("Authorization", "Bearer "+token)
	retryRequest.Header.Set("Content-Type", "application/octet-stream")
	retryResponse, e := client.Do(retryRequest)
	if e != nil {
		t.Fatal(e)
	}
	retryResponse.Body.Close()
	if retryResponse.StatusCode != 200 {
		t.Fatal("upload restart from beginning", retryResponse.Status)
	}
	row, _, e = g.transferRecord(ctx, tickets[0].ID)
	if e != nil || row.State != "ready" {
		t.Fatal("retry did not verify complete content", row.State, e)
	}
	failedRequest, _ := http.NewRequest("PUT", srv.URL+"/api/v1/transfers/"+tickets[1].ID+"/content", bytes.NewReader(bytes.Repeat([]byte{'x'}, len(payload))))
	failedRequest.Header.Set("Authorization", "Bearer "+token)
	failedRequest.Header.Set("Content-Type", "application/octet-stream")
	failedResponse, e := client.Do(failedRequest)
	if e != nil {
		t.Fatal(e)
	}
	failedResponse.Body.Close()
	if failedResponse.StatusCode == 200 {
		t.Fatal("wrong digest accepted")
	}
	g.Files.mu.Lock()
	g.Files.deadlines[row.ID] = time.Now().Add(-time.Second)
	g.Files.deadlines[tickets[1].ID] = time.Now().Add(-time.Second)
	g.Files.mu.Unlock()
	g.sweepFiles(ctx)
	row, _, e = g.transferRecord(ctx, row.ID)
	if e != nil || row.State != "purged" {
		t.Fatal("aborted staging not cleaned", row.State, e)
	}
	second, _, e := g.transferRecord(ctx, tickets[1].ID)
	if e != nil || second.State != "purged" {
		t.Fatal("failed staging not cleaned", second.State, e)
	}
	if _, e = os.Stat(filepath.Join(root, "first")); !os.IsNotExist(e) {
		t.Fatal("aborted transfer published a target")
	}
}

type e08DeadlineRecorder struct{ *httptest.ResponseRecorder }

func (*e08DeadlineRecorder) SetReadDeadline(time.Time) error  { return nil }
func (*e08DeadlineRecorder) SetWriteDeadline(time.Time) error { return nil }
