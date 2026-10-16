//go:build linux && cgo

// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"serverdeck.local/agent/internal/config"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/fileaccess"
	"serverdeck.local/agent/internal/operations"
	"serverdeck.local/agent/internal/storage"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func fixtureFiles(t *testing.T, g *Gateway) string {
	t.Helper()
	pin, e := fileaccess.PinAbsolute("/proc")
	if e != nil {
		t.Fatal(e)
	}
	defer pin.Close()
	guard, e := fileaccess.New([]*os.File{pin})
	if e != nil {
		t.Fatal(e)
	}
	// Directed transport fixture: synthetic protected inode on another FS. Actual
	// bootstrap/state/key protection is exercised separately by native/isolated tests.
	g.Files = &fileService{inventoryVerified: true, guard: guard, tickets: map[string]*readTicket{}, reads: make(chan struct{}, 4)}
	dir := t.TempDir()
	raw, _, _ := g.Store.Settings(context.Background())
	var c contracts.RuntimeConfig
	json.Unmarshal(raw, &c)
	cfg, _ := g.Query(context.Background(), "config.get", []byte(`{}`))
	c.Files.Roots[0].Path = dir
	applyTelemetry(t, g, "config.set", cfg.(map[string]any)["version"].(string), map[string]any{"changes": map[string]any{"files": c.Files}})
	return dir
}
func TestE08ReadTicketsHTTPContractsOwnersAndVersion(t *testing.T) {
	g, _, _ := newTestGateway(t)
	dir := fixtureFiles(t, g)
	os.WriteFile(filepath.Join(dir, "hello"), []byte("\xef\xbb\xbfhello\r\n"), 0600)
	raw, _, _ := g.Store.Settings(context.Background())
	var c contracts.RuntimeConfig
	json.Unmarshal(raw, &c)
	_, token := pairDirect(t, g)
	_, other := pairDirect(t, g)
	srv, client, _ := testHTTPS(t, g, false)
	location := fileaccess.Location{RootID: string(c.Files.Roots[0].RootID), Components: []string{"aGVsbG8"}}
	for _, name := range []string{"files.roots", "files.list", "files.stat", "files.text"} {
		params := map[string]any{}
		if name != "files.roots" {
			params["location"] = location
		}
		if name == "files.list" {
			loc := location
			loc.Components = []string{}
			params["location"] = loc
			params["sort"] = "name"
			params["order"] = "asc"
		}
		if name == "files.text" {
			params["mode"] = "full"
		}
		status, b := query(t, client, srv.URL, token, name, params)
		if status != 200 {
			t.Fatal(name, status, string(b))
		}
		if _, e := contracts.Validate(bytes.NewReader(b), contracts.Target{Family: "api", Definition: "QueryResponse"}, contracts.MaxJSONBytes); e != nil {
			t.Fatal(name, e)
		}
		if name == "files.text" {
			data := decodeMap(t, b)["data"].(map[string]any)
			id := data["transfer_id"].(string)
			request, _ := http.NewRequest("GET", srv.URL+"/api/v1/transfers/"+id+"/content", nil)
			request.Header.Set("Authorization", "Bearer "+other)
			response, e := client.Do(request)
			if e != nil {
				t.Fatal(e)
			}
			response.Body.Close()
			if response.StatusCode != 401 {
				t.Fatal("foreign ticket", response.StatusCode)
			}
			request, _ = http.NewRequest("GET", srv.URL+"/api/v1/transfers/"+id+"/content", nil)
			request.Header.Set("Authorization", "Bearer "+token)
			response, e = client.Do(request)
			if e != nil {
				t.Fatal(e)
			}
			content, e := io.ReadAll(response.Body)
			response.Body.Close()
			if e != nil || response.StatusCode != 200 || string(content) != "\xef\xbb\xbfhello\r\n" || response.Trailer.Get("ServerDeck-Transfer-Status") != "complete" {
				t.Fatal(response.StatusCode, e, string(content), response.Trailer)
			}
		}
	}
	status, b := query(t, client, srv.URL, token, "files.stat", map[string]any{"location": location})
	if status != 200 {
		t.Fatal(string(b))
	}
	version := decodeMap(t, b)["data"].(map[string]any)["version"].(string)
	status, b = query(t, client, srv.URL, token, "files.download", map[string]any{"location": location, "expected_version": version})
	if status != 200 {
		t.Fatal(string(b))
	}
	id := decodeMap(t, b)["data"].(map[string]any)["transfer_id"].(string)
	os.WriteFile(filepath.Join(dir, "hello"), []byte("changed"), 0600)
	request, _ := http.NewRequest("GET", srv.URL+"/api/v1/transfers/"+id+"/content", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, e := client.Do(request)
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 409 {
		t.Fatal("stale download", response.StatusCode)
	}
}
func TestE08BoundsTailBinaryAndMutationAuditGate(t *testing.T) {
	g, _, _ := newTestGateway(t)
	dir := fixtureFiles(t, g)
	raw, _, _ := g.Store.Settings(context.Background())
	var c contracts.RuntimeConfig
	json.Unmarshal(raw, &c)
	loc := fileaccess.Location{RootID: string(c.Files.Roots[0].RootID), Components: []string{"bG9n"}}
	ctx := withMetricOwner(context.Background(), operations.Local().ID())
	os.WriteFile(filepath.Join(dir, "log"), []byte(strings.Repeat("line\n", 1100)), 0600)
	params, _ := json.Marshal(map[string]any{"location": loc, "mode": "tail", "lines": 100})
	v, e := g.Query(ctx, "files.text", params)
	if e != nil {
		t.Fatal(e)
	}
	ticket := v.(map[string]any)
	if ticket["size_bytes"] != "500" || ticket["truncated"] != true {
		t.Fatal(ticket)
	}
	os.WriteFile(filepath.Join(dir, "log"), []byte{0xff, 0, 1}, 0600)
	if _, e = g.Query(ctx, "files.text", params); e == nil {
		t.Fatal("binary text accepted")
	}
	gateParams, _ := json.Marshal(fileCreateParams{Parent: fileaccess.Location{RootID: loc.RootID, Components: []string{}}, Name: "YmxvY2tlZA", Kind: "file", ParentVersion: "fixture-version"})
	r := operations.Request{ID: newID(t), Action: "files.create", Params: gateParams}
	if _, e = g.Operations.Prepare(ctx, operations.Local(), r); errorCode(e) != "SAFETY_UNAVAILABLE" {
		t.Fatal("mutation gate", e)
	}
	if len(g.Files.tickets) != 1 {
		t.Fatal("failed text leaked slots")
	}
}

func TestE08NativeSeparateFilesystem(t *testing.T) {
	root := os.Getenv("SD_E08_ROOT")
	if root == "" {
		t.Skip("explicit private mount namespace procedure")
	}
	if os.Getenv("SD_E08_OUTER_MNT") == "" {
		t.Fatal("missing namespace guard")
	}
	current, e := os.Readlink("/proc/self/ns/mnt")
	if e != nil || current == os.Getenv("SD_E08_OUTER_MNT") {
		t.Fatal("not isolated")
	}
	g, _, _ := newTestGateway(t)
	own := t.TempDir()
	os.WriteFile(filepath.Join(own, "config"), []byte("fixture"), 0600)
	pin, e := os.Open(filepath.Join(own, "config"))
	if e != nil {
		t.Fatal(e)
	}
	defer pin.Close()
	var cfg config.Config
	cfg.Paths.Releases = own
	g.startFiles(cfg, []*os.File{pin})
	if g.Files == nil {
		t.Fatal("guard activation")
	}
	// Exercise the real production gate through explicit audited local accounting.
	confirmation, _ := json.Marshal(storage.InventoryConfirmation{KnownRegions: []string{}, Absent: []string{}})
	confirmationRequest := operations.Request{ID: newID(t), Action: "storage.inventory.confirm", Params: confirmation}
	offline := operations.OfflineWithFileProtection(g.Store, g.Files.guard)
	confirmationPlan, e := offline.Prepare(context.Background(), operations.Local(), confirmationRequest)
	if e != nil {
		t.Fatal(e)
	}
	confirmationRequest.Plan = confirmationPlan.ID
	confirmed, e := offline.Execute(context.Background(), operations.Local(), confirmationRequest)
	if e != nil || confirmed.State != "succeeded" {
		t.Fatal("inventory confirmation", confirmed.State, e)
	}
	if g.Files.inventoryVerified || g.filesReady(context.Background()) != nil {
		t.Fatal("production gate was bypassed or not attested")
	}

	raw, _, _ := g.Store.Settings(context.Background())
	var c contracts.RuntimeConfig
	json.Unmarshal(raw, &c)
	currentConfig, _ := g.Query(context.Background(), "config.get", []byte(`{}`))
	c.Files.Roots[0].Path = root
	applyTelemetry(t, g, "config.set", currentConfig.(map[string]any)["version"].(string), map[string]any{"changes": map[string]any{"files": c.Files}})

	// Actual audited create/rename effects on the accepted whole-filesystem profile.
	parent := fileaccess.Location{RootID: string(c.Files.Roots[0].RootID), Components: []string{}}
	dirFD, e := g.Files.guard.Open(root, parent)
	if e != nil {
		t.Fatal(e)
	}
	parentVersion, e := fileaccess.Version(dirFD)
	dirFD.Close()
	if e != nil {
		t.Fatal(e)
	}
	createParams, _ := json.Marshal(fileCreateParams{Parent: parent, Name: "Y3JlYXRlZA", Kind: "file", ParentVersion: parentVersion})
	mutationRequest := operations.Request{ID: newID(t), Action: "files.create", Params: createParams}
	plan, e := g.Operations.Prepare(context.Background(), operations.Local(), mutationRequest)
	if e != nil {
		t.Fatal("create prepare", e)
	}
	mutationRequest.Plan = plan.ID
	result, e := g.Operations.Execute(context.Background(), operations.Local(), mutationRequest)
	if e != nil || result.State != "succeeded" {
		t.Fatal("create", result.State, result.Code, e)
	}
	replay, e := g.Operations.Execute(context.Background(), operations.Local(), mutationRequest)
	if e != nil || replay.Revision != result.Revision {
		t.Fatal("create replay", e)
	}
	created := decodeMap(t, result.Result)
	source := fileaccess.Location{RootID: parent.RootID, Components: []string{"Y3JlYXRlZA"}}
	dirFD, _ = g.Files.guard.Open(root, parent)
	parentVersion, _ = fileaccess.Version(dirFD)
	dirFD.Close()
	renameParams, _ := json.Marshal(fileRenameParams{Location: source, Expected: created["version"].(string), Target: parent, Name: "cmVuYW1lZA", ParentVersion: parentVersion})
	mutationRequest = operations.Request{ID: newID(t), Action: "files.rename", Params: renameParams}
	plan, e = g.Operations.Prepare(context.Background(), operations.Local(), mutationRequest)
	if e != nil {
		t.Fatal("rename prepare", e)
	}
	mutationRequest.Plan = plan.ID
	result, e = g.Operations.Execute(context.Background(), operations.Local(), mutationRequest)
	if e != nil || result.State != "succeeded" {
		t.Fatal("rename", result.State, result.Code, e)
	}
	if _, e = os.Stat(filepath.Join(root, "renamed")); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(root, "created")); !os.IsNotExist(e) {
		t.Fatal("rename left source")
	}
	// Actual streamed upload remains private until a separate audited commit.
	uploadBody := []byte("staged-data")
	uploadSHA := sha256.Sum256(uploadBody)
	_, uploadToken := pairDirect(t, g)
	credential, e := g.Auth.Authenticate(context.Background(), uploadToken)
	if e != nil {
		t.Fatal(e)
	}
	dirFD, _ = g.Files.guard.Open(root, parent)
	parentVersion, _ = fileaccess.Version(dirFD)
	dirFD.Close()
	uploadRaw, _ := json.Marshal(uploadParams{Parent: parent, Name: "dXBsb2FkZWQ", ParentVersion: parentVersion, Size: int64(len(uploadBody)), SHA: hex.EncodeToString(uploadSHA[:]), Conflict: "fail"})
	uploadRequest := operations.Request{ID: newID(t), Action: "files.upload.begin", Params: uploadRaw}
	uploadPlan, e := g.Operations.Prepare(context.Background(), operations.Device(credential), uploadRequest)
	if e != nil {
		t.Fatal("upload prepare", e)
	}
	uploadRequest.Plan = uploadPlan.ID
	uploadResult, e := g.Operations.Execute(context.Background(), operations.Device(credential), uploadRequest)
	if e != nil || uploadResult.State != "succeeded" {
		t.Fatal("upload begin", uploadResult.State, uploadResult.Code, e)
	}
	uploadTicket := decodeMap(t, uploadResult.Result)
	if _, e = os.Stat(filepath.Join(root, "uploaded")); !os.IsNotExist(e) {
		t.Fatal("begin published target")
	}
	uploadServer, uploadClient, _ := testHTTPS(t, g, false)
	uploadHTTP, _ := http.NewRequest("PUT", uploadServer.URL+"/api/v1/transfers/"+uploadRequest.ID+"/content", bytes.NewReader(uploadBody))
	uploadHTTP.Header.Set("Authorization", "Bearer "+uploadToken)
	uploadHTTP.Header.Set("Content-Type", "application/octet-stream")
	uploadResponse, e := uploadClient.Do(uploadHTTP)
	if e != nil {
		t.Fatal(e)
	}
	uploadReply, _ := io.ReadAll(uploadResponse.Body)
	uploadResponse.Body.Close()
	if uploadResponse.StatusCode != 200 {
		t.Fatal("upload content", uploadResponse.StatusCode, string(uploadReply))
	}
	if _, e = os.Stat(filepath.Join(root, "uploaded")); !os.IsNotExist(e) {
		t.Fatal("PUT published target")
	}
	commitRaw, _ := json.Marshal(commitParams{ID: uploadRequest.ID, SHA: hex.EncodeToString(uploadSHA[:]), Size: int64(len(uploadBody)), Expected: uploadTicket["file_version"].(string)})
	commitRequest := operations.Request{ID: newID(t), Action: "files.transfer.commit", Params: commitRaw}
	commitPlan, e := g.Operations.Prepare(context.Background(), operations.Device(credential), commitRequest)
	if e != nil {
		t.Fatal("commit prepare", e)
	}
	commitRequest.Plan = commitPlan.ID
	committed, e := g.Operations.Execute(context.Background(), operations.Device(credential), commitRequest)
	if e != nil || committed.State != "succeeded" {
		t.Fatal("commit", committed.State, committed.Code, e)
	}
	uploaded, e := os.ReadFile(filepath.Join(root, "uploaded"))
	if e != nil || !bytes.Equal(uploaded, uploadBody) {
		t.Fatal("published bytes", e)
	}
	// Trash, occupied-name refusal, restore and explicit irreversible purge.
	uploadedLocation := mustChild(parent, "dXBsb2FkZWQ")
	trashed := runFileOperation(t, g, operations.Device(credential), "files.trash", trashParams{Location: uploadedLocation, Expected: decodeMap(t, committed.Result)["version"].(string)})
	trashData := decodeMap(t, trashed.Result)
	trashID, trashVersion := trashData["trash_id"].(string), trashData["version"].(string)
	listed, e := g.Query(withMetricOwner(context.Background(), operations.Device(credential).ID()), "trash.list", []byte(`{}`))
	if e != nil {
		t.Fatal("trash list", e)
	}
	listedJSON, _ := json.Marshal(listed)
	// Validate through the real response envelope as well as direct data.
	if len(listedJSON) == 0 {
		t.Fatal("empty trash result")
	}
	os.WriteFile(filepath.Join(root, "occupied"), []byte("foreign"), 0600)
	dirFD, _ = g.Files.guard.Open(root, parent)
	parentVersion, _ = fileaccess.Version(dirFD)
	dirFD.Close()
	occupiedParams, _ := json.Marshal(restoreParams{ID: trashID, Expected: trashVersion, Parent: parent, Name: "b2NjdXBpZWQ", ParentVersion: parentVersion, Conflict: "fail"})
	if _, e = g.Operations.Prepare(context.Background(), operations.Device(credential), operations.Request{ID: newID(t), Action: "trash.restore", Params: occupiedParams}); errorCode(e) != "OBJECT_CHANGED" {
		t.Fatal("occupied restore accepted", e)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "occupied")); string(b) != "foreign" {
		t.Fatal("occupied target changed")
	}
	restored := runFileOperation(t, g, operations.Device(credential), "trash.restore", restoreParams{ID: trashID, Expected: trashVersion, Parent: parent, Name: "cmVzdG9yZWQtdXBsb2Fk", ParentVersion: parentVersion, Conflict: "fail"})
	restoredData := decodeMap(t, restored.Result)["file"].(map[string]any)
	retrash := runFileOperation(t, g, operations.Device(credential), "files.trash", trashParams{Location: mustChild(parent, "cmVzdG9yZWQtdXBsb2Fk"), Expected: restoredData["version"].(string)})
	purgeData := decodeMap(t, retrash.Result)
	runFileOperation(t, g, operations.Device(credential), "trash.purge", purgeParams{ID: purgeData["trash_id"].(string), Expected: purgeData["version"].(string)})
	// Cross-filesystem directory move copies/verifies first, then trashes source.
	if second := os.Getenv("SD_E08_ROOT2"); second != "" {
		raw, _, _ = g.Store.Settings(context.Background())
		json.Unmarshal(raw, &c)
		secondID := newID(t)
		c.Files.Roots = append(c.Files.Roots, contracts.RuntimeRoot{RootID: contracts.UUID(secondID), Path: second})
		currentConfig, _ = g.Query(context.Background(), "config.get", []byte(`{}`))
		applyTelemetry(t, g, "config.set", currentConfig.(map[string]any)["version"].(string), map[string]any{"changes": map[string]any{"files": c.Files}})
		os.Mkdir(filepath.Join(root, "tree"), 0700)
		os.WriteFile(filepath.Join(root, "tree", "payload"), []byte("directory-payload"), 0640)
		os.Symlink("payload", filepath.Join(root, "tree", "link"))
		src := mustChild(parent, base64.RawURLEncoding.EncodeToString([]byte("tree")))
		srcFD, _ := g.Files.guard.Open(root, src)
		srcVersion, _ := fileaccess.Version(srcFD)
		srcFD.Close()
		targetParent := fileaccess.Location{RootID: secondID, Components: []string{}}
		targetFD, _ := g.Files.guard.Open(second, targetParent)
		targetVersion, _ := fileaccess.Version(targetFD)
		targetFD.Close()
		moved := runFileOperation(t, g, operations.Device(credential), "files.move", fileRenameParams{Location: src, Expected: srcVersion, Target: targetParent, Name: base64.RawURLEncoding.EncodeToString([]byte("moved-tree")), ParentVersion: targetVersion})
		if decodeMap(t, moved.Result)["source_status"] != "trashed" {
			t.Fatal("cross-FS source not trashed")
		}
		if b, e := os.ReadFile(filepath.Join(second, "moved-tree", "payload")); e != nil || string(b) != "directory-payload" {
			t.Fatal("cross-FS bytes", e)
		}
		if link, e := os.Readlink(filepath.Join(second, "moved-tree", "link")); e != nil || link != "payload" {
			t.Fatal("symlink object was not copied", e)
		}
		if _, e := os.Stat(filepath.Join(root, "tree")); !os.IsNotExist(e) {
			t.Fatal("cross-FS source path remains")
		}
		trashID := decodeMap(t, moved.Result)["trash_id"].(string)
		_, trashMeta, e := g.trashRecord(context.Background(), trashID)
		if e != nil {
			t.Fatal(e)
		}
		targetFD, e = g.Files.guard.Open(second, targetParent)
		if e != nil {
			t.Fatal(e)
		}
		targetVersion, _ = fileaccess.Version(targetFD)
		targetFD.Close()
		restored := runFileOperation(t, g, operations.Device(credential), "trash.restore", restoreParams{ID: trashID, Expected: trashMeta.Version, Parent: targetParent, Name: base64.RawURLEncoding.EncodeToString([]byte("restored-cross-tree")), ParentVersion: targetVersion, Conflict: "fail"})
		if restored.State != "succeeded" {
			t.Fatal("cross-FS restore", restored.State, restored.Code)
		}
		if b, e := os.ReadFile(filepath.Join(second, "restored-cross-tree", "payload")); e != nil || string(b) != "directory-payload" {
			t.Fatal("cross restore bytes", e)
		}
		row, _, e := g.trashRecord(context.Background(), trashID)
		if e != nil || row.State != "restored" {
			t.Fatal("cross restore source state", row.State, e)
		}
		stateFD, e := g.Store.ProtectionDirectory(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		db, e := sql.Open("sqlite3", "file:/proc/self/fd/"+strconv.FormatUint(uint64(stateFD.Fd()), 10)+"/critical.db")
		if e != nil {
			t.Fatal(e)
		}
		defer db.Close()
		defer stateFD.Close()
		for _, phase := range []string{"copy", "verify", "publish", "source_trash"} {
			name := "failure-" + phase
			os.WriteFile(filepath.Join(root, name), []byte("source-retained"), 0600)
			src := mustChild(parent, base64.RawURLEncoding.EncodeToString([]byte(name)))
			sf, e := g.Files.guard.Open(root, src)
			if e != nil {
				t.Fatal(e)
			}
			sv, _ := fileaccess.Version(sf)
			sf.Close()
			tf, e := g.Files.guard.Open(second, targetParent)
			if e != nil {
				t.Fatal(e)
			}
			tv, _ := fileaccess.Version(tf)
			tf.Close()
			params, _ := json.Marshal(fileRenameParams{Location: src, Expected: sv, Target: targetParent, Name: base64.RawURLEncoding.EncodeToString([]byte(name)), ParentVersion: tv})
			request := operations.Request{ID: newID(t), Action: "files.move", Params: params}
			plan, e := g.Operations.Prepare(context.Background(), operations.Device(credential), request)
			if e != nil {
				t.Fatal(e)
			}
			request.Plan = plan.ID
			if _, e = db.Exec("CREATE TRIGGER e08_phase BEFORE UPDATE ON operations WHEN NEW.phase='" + phase + "' BEGIN SELECT RAISE(ABORT,'fixture'); END"); e != nil {
				t.Fatal(e)
			}
			out, e := g.Operations.Execute(context.Background(), operations.Device(credential), request)
			db.Exec("DROP TRIGGER e08_phase")
			if e != nil || out.State != "unknown" {
				t.Fatal("phase failure", phase, out.State, e)
			}
			if b, e := os.ReadFile(filepath.Join(root, name)); e != nil || string(b) != "source-retained" {
				t.Fatal("phase lost source", phase, e)
			}
			_, targetErr := os.Stat(filepath.Join(second, name))
			if (phase == "source_trash") != (targetErr == nil) {
				t.Fatal("phase publication", phase, targetErr)
			}
			if phase != "source_trash" {
				record, spec, e := g.transferRecord(context.Background(), out.ID)
				if e != nil {
					t.Fatal(e)
				}
				disposition := "purged"
				observed := ""
				if spec.Proof != "" {
					disposition = "discard"
					observed = spec.Proof
				}
				recoveryInput := map[string]any{"record_id": record.ID, "expected_version": storage.FileRecordVersion(record), "state": disposition}
				if observed != "" {
					recoveryInput["observed_proof"] = observed
				}
				input, _ := json.Marshal(recoveryInput)
				offline := operations.OfflineWithFileProtection(g.Store, g.Files.guard)
				recovery := operations.Request{ID: newID(t), Action: "files.reconcile", Params: input}
				p, e := offline.Prepare(context.Background(), operations.Local(), recovery)
				if e != nil {
					t.Fatal(e)
				}
				recovery.Plan = p.ID
				resolved, e := offline.Execute(context.Background(), operations.Local(), recovery)
				if e != nil || resolved.State != "succeeded" {
					t.Fatal("phase stage rollback", phase, resolved, e)
				}
			}
			effect := "none"
			if phase == "source_trash" {
				effect = "applied"
			}
			if e = g.Operations.ResolveLocal(context.Background(), operations.Local(), out.ID, effect); e != nil {
				t.Fatal(e)
			}
		}
	}
	// Shared roots use the explicitly accepted descriptor-bound profile.
	os.Mkdir(filepath.Join(root, "subroot"), 0700)
	if f, e := g.Files.guard.MutationRoot(filepath.Join(root, "subroot")); e == nil {
		f.Close()
	} else {
		t.Fatal("shared subroot unavailable", e)
	}
	os.WriteFile(filepath.Join(root, "safe"), []byte("independent-filesystem"), 0600)
	loc := fileaccess.Location{RootID: string(c.Files.Roots[0].RootID), Components: []string{"c2FmZQ"}}
	params, _ := json.Marshal(map[string]any{"location": loc})
	if _, e = g.Query(context.Background(), "files.stat", params); e != nil {
		t.Fatal("separate filesystem unavailable", e)
	}
	// A genuine whole-filesystem bind alias is rejected if it is a subtree root.
	if _, e = g.Files.guard.Open(own, fileaccess.Location{RootID: loc.RootID, Components: []string{}}); e == nil {
		t.Fatal("own filesystem readable")
	}
	nested := filepath.Join(root, "nested")
	os.Mkdir(nested, 0700)
	if e = syscall.Mount(own, nested, "", syscall.MS_BIND, ""); e != nil {
		t.Fatal(e)
	}
	defer syscall.Unmount(nested, 0)
	if _, e = g.Files.guard.Open(root, fileaccess.Location{RootID: loc.RootID, Components: []string{"bmVzdGVk"}}); e == nil {
		t.Fatal("nested bind mount crossed")
	}
	_, token := pairDirect(t, g)
	srv, client, _ := testHTTPS(t, g, false)
	status, b := query(t, client, srv.URL, token, "files.stat", map[string]any{"location": loc})
	if status != 200 {
		t.Fatal(status, string(b))
	}
	version := decodeMap(t, b)["data"].(map[string]any)["version"].(string)
	status, b = query(t, client, srv.URL, token, "files.download", map[string]any{"location": loc, "expected_version": version})
	if status != 200 {
		t.Fatal(status, string(b))
	}
	id := decodeMap(t, b)["data"].(map[string]any)["transfer_id"].(string)
	request, _ := http.NewRequest("GET", srv.URL+"/api/v1/transfers/"+id+"/content", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, e := client.Do(request)
	if e != nil {
		t.Fatal(e)
	}
	contents, e := io.ReadAll(response.Body)
	response.Body.Close()
	if e != nil || string(contents) != "independent-filesystem" || response.Trailer.Get("ServerDeck-Transfer-Status") != "complete" {
		t.Fatal("native download", e, string(contents), response.Trailer)
	}
	t.Log("PASS actual native protection rejects own FS and permits separately mounted temporary data FS")
}

type e08Writer struct {
	*httptest.ResponseRecorder
	once  sync.Once
	after func()
}

func (w *e08Writer) Write(b []byte) (int, error) {
	n, e := w.ResponseRecorder.Write(b)
	w.once.Do(w.after)
	return n, e
}
func TestE08StreamRevocationAndConcurrentSourceEdit(t *testing.T) {
	for _, kind := range []string{"revoke", "external-write"} {
		t.Run(kind, func(t *testing.T) {
			g, _, _ := newTestGateway(t)
			dir := fixtureFiles(t, g)
			path := filepath.Join(dir, "file")
			os.WriteFile(path, bytes.Repeat([]byte("x"), 256000), 0600)
			device, token := pairDirect(t, g)
			credential, e := g.Auth.Authenticate(context.Background(), token)
			if e != nil {
				t.Fatal(e)
			}
			session, e := g.Auth.Session(credential)
			if e != nil {
				t.Fatal(e)
			}
			defer session.Close()
			raw, _, _ := g.Store.Settings(context.Background())
			var c contracts.RuntimeConfig
			json.Unmarshal(raw, &c)
			location := fileaccess.Location{RootID: string(c.Files.Roots[0].RootID), Components: []string{"ZmlsZQ"}}
			ctx := withMetricOwner(context.Background(), "device:"+device)
			params, _ := json.Marshal(map[string]any{"location": location})
			record, e := g.Query(ctx, "files.stat", params)
			if e != nil {
				t.Fatal(e)
			}
			version := record.(map[string]any)["version"]
			params, _ = json.Marshal(map[string]any{"location": location, "expected_version": version})
			prepared, e := g.Query(ctx, "files.download", params)
			if e != nil {
				t.Fatal(e)
			}
			id := prepared.(map[string]any)["transfer_id"].(string)
			writer := &e08Writer{ResponseRecorder: httptest.NewRecorder(), after: func() {
				if kind == "revoke" {
					revokeDirect(t, g, operations.Local(), device)
				} else {
					if e := os.WriteFile(path, []byte("externally-changed"), 0600); e != nil {
						t.Fatal(e)
					}
				}
			}}
			request := httptest.NewRequest("GET", "https://localhost/api/v1/transfers/"+id+"/content", nil)
			g.fileContent(writer, request, session)
			result := writer.Result()
			defer result.Body.Close()
			status := result.Trailer.Get("ServerDeck-Transfer-Status")
			if kind == "revoke" && status != "UNAUTHORIZED" {
				t.Fatal("revoked stream", status)
			}
			if kind == "external-write" && status != "OBJECT_CHANGED" {
				t.Fatal("changed stream", status)
			}
			if writer.Body.Len() >= 256000 {
				t.Fatal("entire stream sent despite interruption")
			}
		})
	}
}
func TestE08TicketBoundsExpiryAndEarlierTailCursor(t *testing.T) {
	g, _, _ := newTestGateway(t)
	dir := fixtureFiles(t, g)
	raw, _, _ := g.Store.Settings(context.Background())
	var c contracts.RuntimeConfig
	json.Unmarshal(raw, &c)
	location := fileaccess.Location{RootID: string(c.Files.Roots[0].RootID), Components: []string{"bG9n"}}
	ctx := withMetricOwner(context.Background(), "local:fixture")
	os.WriteFile(filepath.Join(dir, "log"), []byte(strings.Repeat("line\n", 1100)), 0600)
	params, _ := json.Marshal(map[string]any{"location": location, "mode": "tail", "lines": 100})
	first, e := g.Query(ctx, "files.text", params)
	if e != nil {
		t.Fatal(e)
	}
	a := first.(map[string]any)
	params, _ = json.Marshal(map[string]any{"location": location, "mode": "tail", "lines": 100, "cursor": a["next_cursor"]})
	second, e := g.Query(ctx, "files.text", params)
	if e != nil {
		t.Fatal(e)
	}
	b := second.(map[string]any)
	if a["byte_from"] != "5000" || b["byte_from"] != "4500" || b["byte_to"] != "5000" {
		t.Fatal(a, b)
	}
	if _, e = g.Query(ctx, "files.text", params); e != storage.ErrBusy {
		t.Fatal("transfer slot limit", e)
	}
	g.Files.mu.Lock()
	for _, ticket := range g.Files.tickets {
		ticket.timeUsed = time.Now().Add(-301 * time.Second)
	}
	g.Files.mu.Unlock()
	if _, e = g.Query(ctx, "files.text", params); e != nil {
		t.Fatal("expired slots not reclaimed", e)
	}
	os.WriteFile(filepath.Join(dir, "log"), bytes.Repeat([]byte("x"), 1000001), 0600)
	params, _ = json.Marshal(map[string]any{"location": location, "mode": "full"})
	if _, e = g.Query(ctx, "files.text", params); e != fileaccess.ErrLimit {
		t.Fatal("actual byte size limit", e)
	}
}

func (w *e08Writer) SetWriteDeadline(time.Time) error { return nil }

func TestE08LateNativeActivationCannotPublishAfterTimeout(t *testing.T) {
	pin, e := fileaccess.PinAbsolute("/proc")
	if e != nil {
		t.Fatal(e)
	}
	defer pin.Close()
	guard, e := fileaccess.New([]*os.File{pin})
	if e != nil {
		t.Fatal(e)
	}
	defer guard.Close()
	blocked := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	build := func() *fileService {
		close(blocked)
		<-release
		defer close(done)
		return &fileService{guard: guard, tickets: map[string]*readTicket{}, reads: make(chan struct{}, 4)}
	}
	if boundedFileActivation(build, 10*time.Millisecond) != nil {
		t.Fatal("stalled activation published")
	}
	<-blocked
	close(release)
	<-done
	deadline := time.Now().Add(time.Second)
	root := t.TempDir()
	for {
		f, e := guard.Open(root, fileaccess.Location{RootID: "fixture", Components: []string{}})
		if f != nil {
			f.Close()
		}
		if e != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("late guard leaked")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestE08UnregisteredRestoredStateNeverExposesKey(t *testing.T) {
	root := os.Getenv("SD_E08_ROOT")
	if root == "" {
		t.Skip("explicit private mount namespace procedure")
	}
	current, e := os.Readlink("/proc/self/ns/mnt")
	if e != nil || os.Getenv("SD_E08_OUTER_MNT") == "" || current == os.Getenv("SD_E08_OUTER_MNT") {
		t.Fatal("not isolated")
	}
	g, _, _ := newTestGateway(t)
	own := t.TempDir()
	os.WriteFile(filepath.Join(own, "config"), []byte("fixture"), 0600)
	pin, e := os.Open(filepath.Join(own, "config"))
	if e != nil {
		t.Fatal(e)
	}
	defer pin.Close()
	var cfg config.Config
	cfg.Paths.Releases = own
	g.startFiles(cfg, []*os.File{pin})
	if g.Files == nil {
		t.Fatal("guard activation")
	}
	maintenance := operations.Offline(g.Store)
	ctx := context.Background()
	backup := filepath.Join(own, "backup")
	restored := filepath.Join(root, "restored")
	for _, step := range []struct{ action, destination, backup string }{{"storage.backup", backup, ""}, {"storage.restore", restored, backup}} {
		r := operations.Request{ID: newID(t), Action: step.action, Params: operations.MaintenanceParams(step.destination, step.backup)}
		plan, e := maintenance.Prepare(ctx, operations.Local(), r)
		if e != nil {
			t.Fatal(e)
		}
		r.Plan = plan.ID
		result, e := maintenance.Execute(ctx, operations.Local(), r)
		if e != nil || result.State != "succeeded" {
			t.Fatal("maintenance fixture", result.State, e)
		}
	}
	inventory, e := g.Store.OwnedInventory(ctx)
	if e != nil || len(inventory.Artifacts) != 2 || inventory.Baseline != "unknown" {
		t.Fatal("owned receipts missing", e)
	}
	// A separate live-state FD alone does not cover a restored sibling tree.
	location := fileaccess.Location{RootID: "fixture", Components: []string{"cmVzdG9yZWQ", "cmVxdWVzdC5rZXk"}}
	f, e := g.Files.guard.Open(root, location)
	if e != nil {
		t.Fatal("counterexample not exercised", e)
	}
	info, e := f.Stat()
	f.Close()
	if e != nil || info.Size() != 32 {
		t.Fatal("fixture key metadata", e)
	}
	raw, _, _ := g.Store.Settings(ctx)
	var c contracts.RuntimeConfig
	json.Unmarshal(raw, &c)
	currentConfig, _ := g.Query(ctx, "config.get", []byte(`{}`))
	c.Files.Roots[0].Path = root
	applyTelemetry(t, g, "config.set", currentConfig.(map[string]any)["version"].(string), map[string]any{"changes": map[string]any{"files": c.Files}})
	location.RootID = string(c.Files.Roots[0].RootID)
	params, _ := json.Marshal(map[string]any{"location": location, "mode": "full"})
	if _, e = g.Query(withMetricOwner(ctx, operations.Local().ID()), "files.text", params); e != storage.ErrSafety {
		t.Fatal("unregistered own restored key exposed", e)
	}
	confirmation, _ := json.Marshal(storage.InventoryConfirmation{KnownRegions: []string{}, Absent: []string{}})
	r := operations.Request{ID: newID(t), Action: "storage.inventory.confirm", Params: confirmation}
	p, e := maintenance.Prepare(ctx, operations.Local(), r)
	if e != nil {
		t.Fatal(e)
	}
	r.Plan = p.ID
	attested, e := maintenance.Execute(ctx, operations.Local(), r)
	if e != nil || attested.State != "succeeded" || g.filesReady(ctx) != nil {
		t.Fatal("complete inventory did not safely activate", e)
	}
	if _, e = g.Query(withMetricOwner(ctx, operations.Local().ID()), "files.text", params); e == nil {
		t.Fatal("accounted own key exposed")
	}
	plain := filepath.Join(root, "ordinary-confirmed")
	if e = os.WriteFile(plain, []byte("ordinary-data"), 0600); e != nil {
		t.Fatal(e)
	}
	ordinary := fileaccess.Location{RootID: location.RootID, Components: []string{base64.RawURLEncoding.EncodeToString([]byte("ordinary-confirmed"))}}
	plainParams, _ := json.Marshal(map[string]any{"location": ordinary, "mode": "full"})
	if _, e = g.Query(withMetricOwner(ctx, operations.Local().ID()), "files.text", plainParams); e != nil {
		t.Fatal("shared filesystem ordinary data blocked", e)
	}
	hard := filepath.Join(root, "key-hard-alias")
	if e = os.Link(filepath.Join(restored, "request.key"), hard); e != nil {
		t.Fatal(e)
	}
	defer os.Remove(hard)
	if f, e := g.Files.guard.Open(root, fileaccess.Location{RootID: location.RootID, Components: []string{base64.RawURLEncoding.EncodeToString([]byte("key-hard-alias"))}}); e == nil {
		f.Close()
		t.Fatal("own key hard alias exposed")
	}
	alias := filepath.Join(root, "whole-fs-alias")
	if e = os.Mkdir(alias, 0700); e != nil {
		t.Fatal(e)
	}
	if e = syscall.Mount(root, alias, "", syscall.MS_BIND, ""); e != nil {
		t.Fatal(e)
	}
	defer syscall.Unmount(alias, 0)
	if f, e := g.Files.guard.Open(alias, location); e == nil {
		f.Close()
		t.Fatal("owned key exposed through full-filesystem bind alias")
	}
	t.Log("PASS actual backup/restore created a separate own-key tree; live read refused without complete inventory; key bytes were never returned or logged")
}

func runFileOperation(t *testing.T, g *Gateway, actor operations.Initiator, action string, params any) storage.Operation {
	t.Helper()
	raw, e := json.Marshal(params)
	if e != nil {
		t.Fatal(e)
	}
	r := operations.Request{ID: newID(t), Action: action, Params: raw}
	plan, e := g.Operations.Prepare(context.Background(), actor, r)
	if e != nil {
		t.Fatal(action, "prepare", e)
	}
	r.Plan = plan.ID
	out, e := g.Operations.Execute(context.Background(), actor, r)
	if e != nil || out.State != "succeeded" {
		t.Fatal(action, "execute", out.State, out.Code, e)
	}
	return out
}
