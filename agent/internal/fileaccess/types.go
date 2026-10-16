// SPDX-License-Identifier: Apache-2.0
// Package fileaccess implements descriptor-bound reads. Mutations require an explicitly safe filesystem profile.
package fileaccess

import (
	"encoding/base64"
	"errors"
	"serverdeck.local/agent/internal/contracts"
)

var ErrUncertain = errors.New("RECOVERY_REQUIRED")
var ErrSafety = errors.New("SAFETY_UNAVAILABLE")
var ErrProtected = errors.New("PROTECTED_OBJECT")
var ErrChanged = errors.New("OBJECT_CHANGED")
var ErrPermission = errors.New("PERMISSION_DENIED")
var ErrMissing = errors.New("NOT_FOUND")
var ErrSpace = errors.New("NO_SPACE")
var ErrLimit = errors.New("LIMIT_EXCEEDED")
var ErrSource = errors.New("SOURCE_UNAVAILABLE")

type Location struct {
	RootID     string   `json:"root_id"`
	Components []string `json:"components"`
}

func (l Location) Validate() error {
	if l.RootID == "" || l.Components == nil || len(l.Components) > 256 {
		return ErrSafety
	}
	if (contracts.Location{RootID: contracts.UUID(l.RootID), Components: l.Components}).Validate() != nil {
		return ErrSafety
	}
	total := 0
	for _, s := range l.Components {
		b, _ := base64.RawURLEncoding.Strict().DecodeString(s)
		total += len(b) + 1
	}
	if total > 4096 {
		return ErrLimit
	}
	return nil
}
func (l Location) Decoded() ([]string, error) {
	if e := l.Validate(); e != nil {
		return nil, e
	}
	parts := make([]string, len(l.Components))
	for i, s := range l.Components {
		b, _ := base64.RawURLEncoding.Strict().DecodeString(s)
		parts[i] = string(b)
	}
	return parts, nil
}
