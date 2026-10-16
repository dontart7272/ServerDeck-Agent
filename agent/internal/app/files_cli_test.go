// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestE08LocalDownloadNeverAcceptsPartialOrForgedCompletion(t *testing.T) {
	payload := "checked bytes"
	sum := sha256.Sum256([]byte(payload))
	p := localTransferParams{ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Size: int64(len(payload)), SHA: hex.EncodeToString(sum[:])}
	for _, tc := range []struct {
		name, body, status, digest string
		ok                         bool
	}{
		{"complete", payload, "complete", p.SHA, true},
		{"truncated", payload[:4], "complete", p.SHA, false},
		{"missing trailer", payload, "", p.SHA, false},
		{"changed", payload, "OBJECT_CHANGED", p.SHA, false},
		{"extra", payload + "x", "complete", p.SHA, false},
		{"corrupt", strings.Repeat("x", len(payload)), "complete", p.SHA, false},
		{"header digest", payload, "complete", strings.Repeat("0", 64), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := &http.Response{StatusCode: 200, Header: make(http.Header), Trailer: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.body))}
			res.Header.Set("Content-Type", "application/octet-stream")
			res.Header.Set("X-ServerDeck-Size", "13")
			res.Header.Set("X-ServerDeck-SHA256", tc.digest)
			res.Trailer.Set("ServerDeck-Transfer-Status", tc.status)
			var out bytes.Buffer
			e := receiveLocalDownload(res, p, &out)
			if (e == nil) != tc.ok {
				t.Fatal(e)
			}
		})
	}
}

func TestE08ArrayVersionsBindEveryElement(t *testing.T) {
	if scopeJSON([]string{"a", "v1"}) == scopeJSON([]string{"a", "v2"}) || scopeJSON([]string{}) == scopeJSON([]string{"a"}) {
		t.Fatal("array version loses contents")
	}
	if scopeJSON(map[string]any{"b": 2, "a": 1}) != scopeJSON(map[string]any{"a": 1, "b": 2}) {
		t.Fatal("map version is not canonical")
	}
}
