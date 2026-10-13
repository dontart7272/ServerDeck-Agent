// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"errors"
	"regexp"
	"time"
)

var (
	ErrStorage  = errors.New("STORAGE_UNAVAILABLE")
	ErrAudit    = errors.New("AUDIT_UNAVAILABLE")
	ErrSpace    = errors.New("NO_SPACE")
	ErrQuota    = errors.New("QUOTA_EXCEEDED")
	ErrBusy     = errors.New("BUSY")
	ErrVersion  = errors.New("VERSION_CONFLICT")
	ErrConflict = errors.New("IDEMPOTENCY_CONFLICT")
	ErrNotFound = errors.New("OPERATION_NOT_FOUND")
	ErrSafety   = errors.New("SAFETY_UNAVAILABLE")
	ErrSchema   = errors.New("INCOMPATIBLE_VERSION")
	ErrInvalid  = errors.New("INVALID_REQUEST")
	ErrCursor   = errors.New("CURSOR_GAP")
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var safePattern = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,128}$`)

func ValidID(s string) bool   { return uuidPattern.MatchString(s) }
func SafeLabel(s string) bool { return safePattern.MatchString(s) }

type Operation struct {
	ID          string      `json:"operation_id"`
	Actor       string      `json:"initiator"`
	Action      string      `json:"action"`
	State       string      `json:"state"`
	Phase       string      `json:"phase"`
	Effect      string      `json:"effect_status"`
	AuditStatus string      `json:"audit_status"`
	Code        string      `json:"code"`
	Result      []byte      `json:"-"`
	Revision    int64       `json:"revision"`
	Created     int64       `json:"created_us"`
	Updated     int64       `json:"updated_us"`
	Expires     int64       `json:"dedup_until_us"`
	MAC         []byte      `json:"-"`
	Credential  *Credential `json:"-"`
}

func (o Operation) Terminal() bool {
	return o.State == "succeeded" || o.State == "failed" || o.State == "rejected" || o.State == "cancelled"
}

type Limits struct {
	StateBytes    int64
	AuditBytes    int64
	AuditDays     int
	Operations    int
	WALBytes      int64
	PhysicalBytes int64
}

func DefaultLimits() Limits { return Limits{64000000, 64000000, 30, 10000, 8000000, 128000000} }

type Health struct {
	Available              bool   `json:"available"`
	AuditAvailable         bool   `json:"audit_available"`
	SecurityFloorAvailable bool   `json:"security_floor_available"`
	Failures               uint64 `json:"failures"`
	Code                   string `json:"code"`
	AllocatedBytes         int64  `json:"allocated_bytes"`
	WALBytes               int64  `json:"wal_bytes"`
	TemporalExpiry         bool   `json:"temporal_expiry"`
}
type AuditEntry struct {
	Seq                                                    int64
	OperationID, Actor, Action, Object, Kind, Code, Effect string
	At                                                     int64
}

const readerTimeout = time.Second
