// SPDX-License-Identifier: Apache-2.0
package contracts

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

type UUID string
type Version string
type U64 uint64
type Timestamp time.Time

func (u *U64) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) != nil || s == "" || (len(s) > 1 && s[0] == '0') {
		return ErrInvalid
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return ErrInvalid
		}
	}
	n, e := strconv.ParseUint(s, 10, 64)
	if e != nil {
		return ErrInvalid
	}
	*u = U64(n)
	return nil
}
func (u U64) MarshalJSON() ([]byte, error) { return json.Marshal(strconv.FormatUint(uint64(u), 10)) }
func (t *Timestamp) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) != nil || !strings.HasSuffix(s, "Z") {
		return ErrInvalid
	}
	v, e := time.Parse(time.RFC3339Nano, s)
	if e != nil {
		return ErrInvalid
	}
	*t = Timestamp(v)
	return nil
}
func (t Timestamp) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(t).UTC().Format(time.RFC3339Nano))
}

type Location struct {
	RootID     UUID     `json:"root_id"`
	Components []string `json:"components"`
}

func (l Location) Validate() error {
	for _, s := range l.Components {
		b, e := base64.RawURLEncoding.Strict().DecodeString(s)
		if e != nil || len(b) < 1 || len(b) > 255 || base64.RawURLEncoding.EncodeToString(b) != s || strings.ContainsAny(string(b), "/\x00") || string(b) == "." || string(b) == ".." {
			return ErrInvalid
		}
	}
	return nil
}

// Params and results are discriminated by the selected embedded schema. They
// are never accepted as arbitrary commands or executable module definitions.
type QueryRequest struct {
	SchemaVersion string          `json:"schema_version"`
	RequestID     UUID            `json:"request_id"`
	Query         string          `json:"query"`
	Params        json.RawMessage `json:"params"`
}
type OperationRequest struct {
	SchemaVersion   string          `json:"schema_version"`
	RequestID       UUID            `json:"request_id"`
	OperationID     UUID            `json:"operation_id"`
	Action          string          `json:"action"`
	Params          json.RawMessage `json:"params"`
	PlanID          string          `json:"plan_id"`
	ExpectedVersion *Version        `json:"expected_version,omitempty"`
}
type PrepareRequest struct {
	SchemaVersion   string          `json:"schema_version"`
	RequestID       UUID            `json:"request_id"`
	OperationID     UUID            `json:"operation_id"`
	Action          string          `json:"action"`
	Params          json.RawMessage `json:"params"`
	ExpectedVersion *Version        `json:"expected_version,omitempty"`
}
type OperationState string

const (
	Preparing OperationState = "preparing"
	Running   OperationState = "running"
	Succeeded OperationState = "succeeded"
	Rejected  OperationState = "rejected"
	Failed    OperationState = "failed"
	Cancelled OperationState = "cancelled"
	Unknown   OperationState = "unknown"
)
