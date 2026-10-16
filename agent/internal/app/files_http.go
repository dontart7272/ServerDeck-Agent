// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"serverdeck.local/agent/internal/auth"
	"serverdeck.local/agent/internal/fileaccess"
	"serverdeck.local/agent/internal/storage"
	"strconv"
	"strings"
	"time"
)

func (g *Gateway) fileContent(w http.ResponseWriter, r *http.Request, session *auth.Session) {
	owner := "device:" + session.Credential.ID()
	if r.Method == "PUT" {
		g.fileReceive(w, r, owner, session.Check, session.Context, &session.Credential)
		return
	}
	g.fileContentOwned(w, r, owner, session.Check, session.Context)
}
func (g *Gateway) fileContentOwned(w http.ResponseWriter, r *http.Request, owner string, check func(context.Context) error, lifetime context.Context) {
	if g.filesReady(r.Context()) != nil {
		g.fail(w, "", storage.ErrSafety, "")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/transfers/")
	parts := strings.Split(path, "/")
	if r.Header.Get("Range") != "" || r.Method != "GET" || len(parts) != 2 || parts[1] != "content" || !storage.ValidID(parts[0]) {
		g.fail(w, "", storage.ErrInvalid, "")
		return
	}
	s := g.Files
	s.mu.Lock()
	s.reapLocked()
	t := s.tickets[parts[0]]
	if t == nil || t.owner != owner {
		s.mu.Unlock()
		g.fail(w, "", storage.ErrUnauthorized, "")
		return
	}
	if t.busy || s.closed {
		s.mu.Unlock()
		g.fail(w, "", storage.ErrBusy, "")
		return
	}
	t.busy = true
	t.timeUsed = time.Now()
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.tickets, parts[0])
		if t.file != nil {
			t.file.Close()
		}
		s.mu.Unlock()
	}()
	_, revision, e := g.fileConfig(r.Context())
	if e != nil || revision != t.revision {
		g.fail(w, "", storage.ErrVersion, "")
		return
	}
	if e = check(r.Context()); e != nil {
		g.fail(w, "", e, "")
		return
	}
	var input io.Reader = bytes.NewReader(t.data)
	if t.file != nil {
		v, e := fileaccess.Version(t.file)
		if e != nil || v != t.version {
			g.fail(w, "", storage.ErrVersion, "")
			return
		}
		if _, e = t.file.Seek(0, 0); e != nil {
			g.fail(w, "", storage.ErrSafety, "")
			return
		}
		input = t.file
	}
	controller := http.NewResponseController(w)
	deadline := func() time.Time {
		d := time.Now().Add(300 * time.Second)
		end := t.created.Add(time.Hour)
		if end.Before(d) {
			d = end
		}
		return d
	}
	if e := controller.SetWriteDeadline(deadline()); e != nil {
		g.fail(w, "", storage.ErrSafety, "")
		return
	}
	cancelled := make(chan struct{})
	stop := context.AfterFunc(lifetime, func() { defer close(cancelled); _ = controller.SetWriteDeadline(time.Now()) })
	defer func() {
		if !stop() {
			<-cancelled
		}
	}()
	// No Content-Length: HTTP chunked trailers carry the final consistency outcome.
	// Exact expected length/digest are bound into the previously validated ticket.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-ServerDeck-Size", strconv.FormatInt(t.size, 10))
	w.Header().Set("X-ServerDeck-SHA256", t.digest)
	w.Header().Set("Trailer", "ServerDeck-Transfer-Status")
	w.WriteHeader(200)
	status := "complete"
	hash := sha256.New()
	buf := make([]byte, 64000)
	left := t.size
	for left > 0 {
		if r.Context().Err() != nil || check(r.Context()) != nil || lifetime.Err() != nil {
			status = "UNAUTHORIZED"
			break
		}
		_, currentRevision, policyErr := g.fileConfig(r.Context())
		if policyErr != nil || currentRevision != t.revision || g.filesReady(r.Context()) != nil {
			status = "POLICY_DENIED"
			break
		}
		want := int64(len(buf))
		if left < want {
			want = left
		}
		n, e := input.Read(buf[:want])
		if n > 0 {
			hash.Write(buf[:n])
			if e := controller.SetWriteDeadline(deadline()); e != nil {
				status = "SOURCE_UNAVAILABLE"
				break
			}
			written, err := w.Write(buf[:n])
			if err != nil || written != n {
				status = "SOURCE_UNAVAILABLE"
				break
			}
			left -= int64(n)
		}
		if e != nil {
			if e == io.EOF && left == 0 {
				break
			}
			status = "OBJECT_CHANGED"
			break
		}
		if n == 0 {
			status = "SOURCE_UNAVAILABLE"
			break
		}
	}
	if left != 0 || hex.EncodeToString(hash.Sum(nil)) != t.digest {
		if status == "complete" {
			status = "OBJECT_CHANGED"
		}
	}
	if t.file != nil {
		v, e := fileaccess.Version(t.file)
		if e != nil || v != t.version {
			status = "OBJECT_CHANGED"
		}
	}
	if check(r.Context()) != nil {
		status = "UNAUTHORIZED"
	}
	w.Header().Set("ServerDeck-Transfer-Status", status)
}
