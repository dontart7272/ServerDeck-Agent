// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/fileaccess"
	"serverdeck.local/agent/internal/operations"
	"serverdeck.local/agent/internal/storage"
)

type fileCreateParams struct {
	Parent        fileaccess.Location `json:"parent"`
	Name          string              `json:"name"`
	Kind          string              `json:"kind"`
	ParentVersion string              `json:"parent_version"`
}
type fileRenameParams struct {
	Location      fileaccess.Location `json:"location"`
	Expected      string              `json:"expected_version"`
	Target        fileaccess.Location `json:"target_parent"`
	Name          string              `json:"target_name"`
	ParentVersion string              `json:"target_parent_version"`
}
type fileMutationHandler struct {
	g      *Gateway
	rename bool
}

func (h fileMutationHandler) Validate(raw []byte) error {
	if h.rename {
		var p fileRenameParams
		if decodeStrict(raw, &p) != nil || p.Location.Validate() != nil || p.Target.Validate() != nil || len(p.Location.Components) == 0 || p.Expected == "" || p.ParentVersion == "" {
			return storage.ErrInvalid
		}
		if _, e := fileaccessChild(p.Target, p.Name); e != nil {
			return storage.ErrInvalid
		}
		return nil
	}
	var p fileCreateParams
	if decodeStrict(raw, &p) != nil || p.Parent.Validate() != nil || p.ParentVersion == "" || (p.Kind != "file" && p.Kind != "directory") {
		return storage.ErrInvalid
	}
	if _, e := fileaccessChild(p.Parent, p.Name); e != nil {
		return storage.ErrInvalid
	}
	return nil
}

// Both policy and filesystem mutations use the common durable lock registry.
func (h fileMutationHandler) Keys(operations.Request) ([]string, error) {
	return []string{"files.mutations", "settings.runtime"}, nil
}
func fileaccessChild(parent fileaccess.Location, name string) (fileaccess.Location, error) {
	l := fileaccess.Location{RootID: parent.RootID, Components: append(append([]string{}, parent.Components...), name)}
	return l, l.Validate()
}
func (h fileMutationHandler) Check(ctx context.Context, r operations.Request) error {
	if h.g.filesReady(ctx) != nil {
		return storage.ErrSafety
	}
	c, _, e := h.g.fileConfig(ctx)
	if e != nil {
		return e
	}
	if h.rename {
		var p fileRenameParams
		json.Unmarshal(r.Params, &p)
		root, e := rootPath(c, p.Location.RootID)
		if e != nil {
			return e
		}
		targetRoot, e := rootPath(c, p.Target.RootID)
		if e != nil {
			return e
		}
		return h.g.Files.guard.CheckRenameAcross(root, targetRoot, p.Location, p.Expected, p.Target, p.Name, p.ParentVersion)
	}
	var p fileCreateParams
	json.Unmarshal(r.Params, &p)
	root, e := rootPath(c, p.Parent.RootID)
	if e != nil {
		return e
	}
	return h.g.Files.guard.CheckCreate(root, p.Parent, p.Name, p.ParentVersion)
}
func (h fileMutationHandler) Effect(ctx context.Context, r operations.Request) operations.Outcome {
	if e := h.Check(ctx, r); e != nil {
		return fileMutationOutcome(nil, e, false)
	}
	c, _, e := h.g.fileConfig(ctx)
	if e != nil {
		return fileMutationOutcome(nil, e, false)
	}
	if r.Credential != nil {
		if e = h.g.Store.CheckCredential(ctx, *r.Credential); e != nil {
			return fileMutationOutcome(nil, e, false)
		}
	}
	var out *os.File
	var location fileaccess.Location
	if h.rename {
		var p fileRenameParams
		json.Unmarshal(r.Params, &p)
		root, _ := rootPath(c, p.Location.RootID)
		targetRoot, _ := rootPath(c, p.Target.RootID)
		out, e = h.g.Files.guard.RenameAcross(root, targetRoot, p.Location, p.Expected, p.Target, p.Name, p.ParentVersion)
		location, _ = fileaccessChild(p.Target, p.Name)
	} else {
		var p fileCreateParams
		json.Unmarshal(r.Params, &p)
		root, _ := rootPath(c, p.Parent.RootID)
		out, e = h.g.Files.guard.Create(root, p.Parent, p.Name, p.ParentVersion, p.Kind)
		location, _ = fileaccessChild(p.Parent, p.Name)
	}
	if e != nil {
		return fileMutationOutcome(nil, e, errors.Is(e, fileaccess.ErrUncertain))
	}
	defer out.Close()
	record, e := h.g.presentFile(ctx, out, location)
	if e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	b, e := json.Marshal(record)
	if e != nil {
		return fileMutationOutcome(nil, e, true)
	}
	if _, e = contracts.Validate(bytes.NewReader(b), contracts.Target{Family: "api", Definition: "File"}, contracts.MaxJSONBytes); e != nil {
		return fileMutationOutcome(nil, storage.ErrSafety, true)
	}
	return fileMutationOutcome(b, nil, false)
}
func fileMutationOutcome(result []byte, e error, uncertain bool) operations.Outcome {
	if uncertain {
		return operations.Outcome{State: "unknown", Effect: "unknown", Code: "RECOVERY_REQUIRED", Result: []byte("null")}
	}
	if e != nil {
		return operations.Outcome{State: "failed", Effect: "none", Code: errorCode(e), Result: []byte("null")}
	}
	return operations.Outcome{State: "succeeded", Effect: "applied", Result: result}
}
