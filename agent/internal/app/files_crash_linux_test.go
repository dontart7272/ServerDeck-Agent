//go:build linux && cgo

// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"serverdeck.local/agent/internal/fileaccess"
	"serverdeck.local/agent/internal/operations"
	"serverdeck.local/agent/internal/storage"
	"testing"
)

type crashFileHandler struct {
	h     fileMutationHandler
	phase string
}

func (h crashFileHandler) Validate(b []byte) error                     { return h.h.Validate(b) }
func (h crashFileHandler) Keys(r operations.Request) ([]string, error) { return h.h.Keys(r) }
func (h crashFileHandler) Check(c context.Context, r operations.Request) error {
	return h.h.Check(c, r)
}
func (h crashFileHandler) Effect(c context.Context, r operations.Request) operations.Outcome {
	if h.phase == "after-intent" {
		os.Exit(70)
	}
	o := h.h.Effect(c, r)
	if o.State != "succeeded" {
		os.Exit(71)
	}
	os.Exit(70)
	return o
}
func TestE08CrashEffectChild(t *testing.T) {
	state := os.Getenv("SD_E08_CRASH_STATE")
	if state == "" {
		t.Skip("subprocess fixture")
	}
	if os.Getenv("SD_E08_CRASH_ROOT") == "" {
		t.Fatal("missing temporary root")
	}
	s, e := storage.Open(context.Background(), state, "", nil, false, storage.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	g, e := NewGateway(s, nil, "fixture")
	if e != nil {
		t.Fatal(e)
	}
	pin, e := fileaccess.PinAbsolute("/proc")
	if e != nil {
		t.Fatal(e)
	}
	guard, e := fileaccess.New([]*os.File{pin})
	pin.Close()
	if e != nil {
		t.Fatal(e)
	}
	guard.EnableSharedRoots()
	g.Files = &fileService{inventoryVerified: true, guard: guard, tickets: map[string]*readTicket{}, reads: make(chan struct{}, 4)}
	svc, e := operations.NewAuthorized(s, map[string]operations.Handler{"files.create": crashFileHandler{fileMutationHandler{g, false}, os.Getenv("SD_E08_CRASH_PHASE")}}, g.authorize)
	if e != nil {
		t.Fatal(e)
	}
	r := operations.Request{ID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", Action: "files.create", Params: []byte(os.Getenv("SD_E08_CRASH_PARAMS"))}
	p, e := svc.Prepare(context.Background(), operations.Local(), r)
	if e != nil {
		t.Fatal(e)
	}
	r.Plan = p.ID
	if os.Getenv("SD_E08_CRASH_PHASE") == "before-intent" {
		os.Exit(70)
	}
	_, e = svc.Execute(context.Background(), operations.Local(), r)
	t.Fatal("child did not crash", e)
}
func TestE08CrashNeverAutomaticallyRepeatsFileEffect(t *testing.T) {
	for _, phase := range []string{"before-intent", "after-intent", "after-effect"} {
		t.Run(phase, func(t *testing.T) {
			g, state, _ := newTestGateway(t)
			root := fixtureFiles(t, g)
			g.Files.guard.EnableSharedRoots()
			parent, v := e08Root(t, g, root)
			params, _ := json.Marshal(fileCreateParams{Parent: parent, Name: "Y3Jhc2g", Kind: "file", ParentVersion: v})
			g.Close()
			g.Store.Close()
			cmd := exec.Command(os.Args[0], "-test.run=^TestE08CrashEffectChild$")
			cmd.Env = append(os.Environ(), "SD_E08_CRASH_STATE="+state, "SD_E08_CRASH_ROOT="+root, "SD_E08_CRASH_PHASE="+phase, "SD_E08_CRASH_PARAMS="+string(params))
			output, e := cmd.CombinedOutput()
			ee, ok := e.(*exec.ExitError)
			if !ok || ee.ExitCode() != 70 {
				t.Fatal("unexpected child exit", e, string(output))
			}
			s, e := storage.Open(context.Background(), state, "", nil, false, storage.DefaultLimits())
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			o, e := s.Lookup(context.Background(), "cccccccc-cccc-4ccc-8ccc-cccccccccccc")
			if phase == "before-intent" {
				if e != storage.ErrNotFound {
					t.Fatal("operation before intent", e)
				}
			} else if e != nil || o.State != "unknown" {
				t.Fatal("restart lost uncertainty", o.State, e)
			}
			file := filepath.Join(root, "crash")
			_, statErr := os.Stat(file)
			if phase == "after-effect" {
				if statErr != nil {
					t.Fatal(statErr)
				}
			} else if !os.IsNotExist(statErr) {
				t.Fatal("unexpected effect", statErr)
			}
			if phase != "before-intent" {
				svc, e := operations.NewAuthorized(s, map[string]operations.Handler{"files.create": fileMutationHandler{g, false}}, nil)
				if e != nil {
					t.Fatal(e)
				}
				replay, e := svc.Execute(context.Background(), operations.Local(), operations.Request{ID: o.ID, Action: "files.create", Params: params})
				if e != nil || replay.State != "unknown" {
					t.Fatal("crash replay", replay.State, e)
				}
			}
		})
	}
}
