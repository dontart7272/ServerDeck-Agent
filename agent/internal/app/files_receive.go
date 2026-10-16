// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"serverdeck.local/agent/internal/storage"
	"strings"
	"time"
)

func (g *Gateway) fileReceive(w http.ResponseWriter, r *http.Request, owner string, check func(context.Context) error, lifetime context.Context, credential *storage.Credential) {
	if g.filesReady(r.Context()) != nil {
		g.fail(w, "", storage.ErrSafety, "")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/transfers/"), "/")
	if r.Method != "PUT" || len(parts) != 2 || parts[1] != "content" || !storage.ValidID(parts[0]) || r.Header.Get("Range") != "" || r.Header.Get("Content-Type") != "application/octet-stream" || r.Header.Get("Content-Encoding") != "" {
		g.fail(w, "", storage.ErrInvalid, "")
		return
	}
	g.Files.mu.Lock()
	t := g.Files.uploads[parts[0]]
	g.Files.mu.Unlock()
	if t == nil {
		g.fail(w, "", storage.ErrNotFound, "")
		return
	}
	begin, e := g.Store.Lookup(r.Context(), t.record.OperationID)
	if e != nil || begin.State != "succeeded" {
		g.fail(w, "", storage.ErrSafety, "")
		return
	}
	t.mu.Lock()
	if t.record.Owner != owner {
		t.mu.Unlock()
		g.fail(w, "", storage.ErrUnauthorized, "")
		return
	}
	if !t.closed && !t.busy && t.record.State == "ready" && time.Since(t.used) < 300*time.Second && time.Now().UnixMicro() < t.record.Expires {
		spec := t.spec
		id := t.record.ID
		t.mu.Unlock()
		if r.ContentLength < 0 || r.ContentLength != spec.Size {
			g.fail(w, "", storage.ErrInvalid, "")
			return
		}
		_, revision, e := g.fileConfig(r.Context())
		if e != nil || revision != spec.Revision || check(r.Context()) != nil {
			g.fail(w, "", storage.ErrPolicy, "")
			return
		}
		row, _, e := g.transferRecord(r.Context(), id)
		if e != nil || row.State != "ready" {
			g.fail(w, "", storage.ErrVersion, "")
			return
		}
		g.replyTransferReceipt(w, id, spec.Size, spec.SHA)
		return
	}
	if t.closed || t.busy || (t.record.State != "receiving" && t.record.State != "failed") || time.Since(t.used) >= 300*time.Second || time.Now().UnixMicro() >= t.record.Expires {
		t.mu.Unlock()
		g.fail(w, "", storage.ErrBusy, "")
		return
	}
	if r.ContentLength < 0 || r.ContentLength != t.spec.Size {
		t.mu.Unlock()
		g.fail(w, "", storage.ErrInvalid, "")
		return
	}
	t.busy = true
	retry := t.record.State == "failed"
	t.mu.Unlock()
	defer func() {
		t.mu.Lock()
		t.busy = false
		t.used = time.Now()
		if t.closed {
			t.file.Close()
			t.area.Close()
		}
		t.mu.Unlock()
	}()
	controller := http.NewResponseController(w)
	deadline := func() time.Time {
		end := time.UnixMicro(t.record.Expires)
		idle := time.Now().Add(300 * time.Second)
		if idle.Before(end) {
			return idle
		}
		return end
	}
	if e := controller.SetReadDeadline(deadline()); e != nil {
		g.fail(w, "", storage.ErrSafety, "")
		return
	}
	if e := controller.SetWriteDeadline(deadline()); e != nil {
		g.fail(w, "", storage.ErrSafety, "")
		return
	}
	done := make(chan struct{})
	stop := context.AfterFunc(lifetime, func() {
		defer close(done)
		_ = controller.SetWriteDeadline(time.Now())
		_ = controller.SetReadDeadline(time.Now())
		_ = r.Body.Close()
	})
	defer func() {
		if !stop() {
			<-done
		}
	}()
	fail := func(e error) {
		t.mu.Lock()
		from := t.record.State
		t.record.State = "failed"
		doc, _ := json.Marshal(t.spec)
		t.mu.Unlock()
		_ = g.Store.TransferProgress(context.Background(), t.record.ID, owner, from, "failed", doc, nil)
		g.fail(w, "", e, t.record.OperationID)
	}
	if e := check(r.Context()); e != nil {
		fail(e)
		return
	}
	if retry {
		doc, _ := json.Marshal(t.spec)
		if e := g.Store.TransferProgress(r.Context(), t.record.ID, owner, "failed", "receiving", doc, credential); e != nil {
			g.fail(w, "", e, t.record.OperationID)
			return
		}
		t.mu.Lock()
		t.record.State = "receiving"
		t.mu.Unlock()
		if e := t.file.Truncate(0); e != nil {
			fail(storage.ErrStorage)
			return
		}
		if _, e := t.file.Seek(0, 0); e != nil {
			fail(storage.ErrStorage)
			return
		}
		if e := t.area.Allocate(t.file, t.spec.Size); e != nil {
			fail(e)
			return
		}
	}
	_, revision, e := g.fileConfig(r.Context())
	if e != nil || revision != t.spec.Revision {
		fail(storage.ErrVersion)
		return
	}
	if _, e = t.file.Seek(0, 0); e != nil {
		fail(storage.ErrSafety)
		return
	}
	hash := sha256.New()
	buf := make([]byte, 64000)
	var received int64
	for {
		if check(r.Context()) != nil || r.Context().Err() != nil || lifetime.Err() != nil {
			fail(storage.ErrUnauthorized)
			return
		}
		_, current, e := g.fileConfig(r.Context())
		if e != nil || current != t.spec.Revision || g.filesReady(r.Context()) != nil {
			fail(storage.ErrPolicy)
			return
		}
		if e = controller.SetReadDeadline(deadline()); e != nil {
			fail(storage.ErrSafety)
			return
		}
		want := int64(len(buf))
		if left := t.spec.Size - received + 1; left < want {
			want = left
		}
		if e = controller.SetWriteDeadline(deadline()); e != nil {
			fail(storage.ErrSafety)
			return
		}
		n, re := r.Body.Read(buf[:want])
		if int64(n) > t.spec.Size-received {
			fail(storage.ErrQuota)
			return
		}
		if n > 0 {
			written, we := t.file.Write(buf[:n])
			if we != nil || written != n {
				fail(storage.ErrStorage)
				return
			}
			hash.Write(buf[:n])
			received += int64(n)
			t.mu.Lock()
			t.used = time.Now()
			t.mu.Unlock()
		}
		if re == io.EOF {
			break
		}
		if re != nil {
			fail(storage.ErrStorage)
			return
		}
		if n == 0 {
			fail(storage.ErrStorage)
			return
		}
	}
	if received != t.spec.Size || hex.EncodeToString(hash.Sum(nil)) != t.spec.SHA {
		fail(storage.ErrVersion)
		return
	}
	if e = t.file.Sync(); e != nil {
		fail(storage.ErrStorage)
		return
	}
	if check(r.Context()) != nil {
		fail(storage.ErrUnauthorized)
		return
	}
	_, current, e := g.fileConfig(r.Context())
	if e != nil || current != t.spec.Revision || g.filesReady(r.Context()) != nil {
		fail(storage.ErrPolicy)
		return
	}
	doc, _ := json.Marshal(t.spec)
	if e = g.Store.TransferProgress(r.Context(), t.record.ID, owner, "receiving", "ready", doc, credential); e != nil {
		fail(e)
		return
	}
	t.mu.Lock()
	t.record.State = "ready"
	t.mu.Unlock()
	g.replyTransferReceipt(w, t.record.ID, received, t.spec.SHA)
}

func (g *Gateway) replyTransferReceipt(w http.ResponseWriter, id string, size int64, digest string) {
	g.reply(w, 200, "TransferReceipt", map[string]any{"schema_version": "1.0", "transfer_id": id, "received_bytes": size, "sha256": digest, "ready": true})
}
