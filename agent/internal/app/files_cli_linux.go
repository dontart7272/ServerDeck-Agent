//go:build linux && cgo

// SPDX-License-Identifier: Apache-2.0
package app

import (
	"encoding/json"
	"io"
	"net/http"
	"serverdeck.local/agent/internal/config"
	"serverdeck.local/agent/internal/storage"
	"time"
)

func localTransfer(cfg config.Config, action string, raw []byte, input io.Reader, out io.Writer) error {
	p, e := parseLocalTransfer(raw)
	if e != nil {
		return e
	}
	return withLocalClient(cfg, time.Hour, func(client *http.Client) error {
		method := "GET"
		var body io.Reader
		if action == "upload" {
			method = "PUT"
			body = io.LimitReader(input, p.Size+1)
		}
		req, e := http.NewRequest(method, "http://local/local/v1/transfers/"+p.ID+"/content", body)
		if e != nil {
			return storage.ErrInvalid
		}
		if method == "PUT" {
			req.Header.Set("Content-Type", "application/octet-stream")
			req.ContentLength = p.Size
			if p.Size == 0 {
				var extra [1]byte
				n, e := io.ReadFull(input, extra[:])
				if n != 0 || e != io.EOF {
					return storage.ErrInvalid
				}
				req.Body = http.NoBody
			}
		}
		res, e := client.Do(req)
		if e != nil {
			return storage.ErrSafety
		}
		if method == "GET" {
			return receiveLocalDownload(res, p, out)
		}
		defer res.Body.Close()
		b, e := io.ReadAll(io.LimitReader(res.Body, 4097))
		var receipt struct {
			SchemaVersion string `json:"schema_version"`
			ID            string `json:"transfer_id"`
			Size          int64  `json:"received_bytes"`
			SHA           string `json:"sha256"`
			Ready         bool   `json:"ready"`
		}
		if e != nil || len(b) > 4096 || res.StatusCode != 200 || decodeStrict(b, &receipt) != nil || receipt.SchemaVersion != "1.0" || receipt.ID != p.ID || receipt.Size != p.Size || receipt.SHA != p.SHA || !receipt.Ready {
			return storage.ErrSafety
		}
		return json.NewEncoder(out).Encode(receipt)
	})
}
