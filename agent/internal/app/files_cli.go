// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"

	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/storage"
)

type localTransferParams struct {
	ID   string `json:"transfer_id"`
	Size int64  `json:"size_bytes"`
	SHA  string `json:"sha256"`
}

func parseLocalTransfer(raw []byte) (localTransferParams, error) {
	var p localTransferParams
	if _, e := contracts.Validate(bytes.NewReader(raw), contracts.Target{Family: "api", Definition: "LocalTransferInput"}, 65536); e != nil {
		return p, storage.ErrInvalid
	}
	if decodeStrict(raw, &p) != nil || !storage.ValidID(p.ID) || p.Size < 0 || p.Size > 1000000000 || !validDigest(p.SHA) {
		return p, storage.ErrInvalid
	}
	return p, nil
}

// stdout may already contain a prefix on failure. Success requires all three
// independently checked signals: exact bytes, digest, and completion trailer.
func receiveLocalDownload(res *http.Response, p localTransferParams, out io.Writer) error {
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "application/octet-stream" || res.Header.Get("X-ServerDeck-Size") != strconv.FormatInt(p.Size, 10) || res.Header.Get("X-ServerDeck-SHA256") != p.SHA {
		return storage.ErrSafety
	}
	hash := sha256.New()
	n, e := io.CopyN(io.MultiWriter(out, hash), res.Body, p.Size)
	var extra [1]byte
	count, end := io.ReadFull(res.Body, extra[:])
	if e != nil || n != p.Size || count != 0 || end != io.EOF || hex.EncodeToString(hash.Sum(nil)) != p.SHA || res.Trailer.Get("ServerDeck-Transfer-Status") != "complete" {
		return storage.ErrSafety
	}
	return nil
}
