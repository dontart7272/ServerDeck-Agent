// SPDX-License-Identifier: Apache-2.0
package contracts

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
)

type RPCRequestEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// ReadFrame consumes one frame only; framing grants no authority or peer trust.
func ReadFrame(r io.Reader, t Target) (json.RawMessage, error) {
	if t.Family != "ipc" {
		return nil, ErrSchema
	}
	var header [4]byte
	if _, e := io.ReadFull(r, header[:]); e != nil {
		return nil, ErrInvalid
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > MaxJSONBytes {
		return nil, ErrLimit
	}
	b := make([]byte, int(n))
	if _, e := io.ReadFull(r, b); e != nil {
		return nil, ErrInvalid
	}
	return Validate(bytes.NewReader(b), t, MaxJSONBytes)
}
func WriteFrame(w io.Writer, t Target, v any) error {
	if t.Family != "ipc" {
		return ErrSchema
	}
	var b bytes.Buffer
	if e := Encode(&b, t, v, MaxJSONBytes); e != nil {
		return e
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(b.Len()))
	// io.Copy handles partial writes and never ignores an io.ErrShortWrite.
	if _, e := io.Copy(w, bytes.NewReader(header[:])); e != nil {
		return e
	}
	_, e := io.Copy(w, &b)
	return e
}

// ReadResponse binds one response to a locally pending RPC. The caller chooses
// resultDefinition from its own method registry, never from the peer's claim.
// Peer authentication, pending lifecycle and operation receipts belong to E09.
func ReadResponse(r io.Reader, pendingID, resultDefinition string) (json.RawMessage, error) {
	switch resultDefinition {
	case "Welcome", "Receipt", "Operation", "CollectResult", "ReadResult", "OperationPlan", "Accepted", "CancelResult", "ShutdownResult", "HeartbeatResult":
	default:
		return nil, ErrSchema
	}
	if pendingID == "" || len(pendingID) > 64 {
		return nil, ErrInvalid
	}
	b, e := ReadFrame(r, Target{"ipc", "Response"})
	if e != nil {
		return nil, e
	}
	var envelope struct {
		ID     *string         `json:"id"`
		Result json.RawMessage `json:"result"`
	}
	if json.Unmarshal(b, &envelope) != nil || envelope.ID == nil || *envelope.ID != pendingID {
		return nil, ErrInvalid
	}
	if len(envelope.Result) > 0 {
		if _, e := Validate(bytes.NewReader(envelope.Result), Target{"ipc", resultDefinition}, MaxJSONBytes); e != nil {
			return nil, e
		}
	}
	return b, nil
}
