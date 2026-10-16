// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"context"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/operations"
	"serverdeck.local/agent/internal/storage"
)

// A rejected gate is deliberately NOT an implemented file mutation.
type fileMutationGate struct{}

func (fileMutationGate) Validate(raw []byte) error {
	if _, e := contracts.Parse(bytes.NewReader(raw), 65536); e != nil {
		return storage.ErrInvalid
	}
	return nil
}
func (fileMutationGate) Keys(operations.Request) ([]string, error) {
	return []string{"files.safety-gate"}, nil
}
func (fileMutationGate) Check(context.Context, operations.Request) error { return storage.ErrSafety }
func (fileMutationGate) Effect(context.Context, operations.Request) operations.Outcome {
	return operations.Outcome{State: "rejected", Effect: "none", Code: "SAFETY_UNAVAILABLE"}
}
