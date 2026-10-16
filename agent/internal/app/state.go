// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"

	"serverdeck.local/agent/internal/auth"
	"serverdeck.local/agent/internal/config"
	"serverdeck.local/agent/internal/fileaccess"
	"serverdeck.local/agent/internal/operations"
	"serverdeck.local/agent/internal/storage"
)

func stateCommand(args []string, out, errOut io.Writer) (int, bool) {
	if len(args) == 0 {
		return 0, false
	}
	switch args[0] {
	case "state-init", "state-status", "state-files", "state-file-reconcile", "state-inventory", "state-inventory-confirm", "state-operation", "state-backup", "state-restore", "state-resolve":
	default:
		return 0, false
	}
	fail := func(e error) (int, bool) { fmt.Fprintln(errOut, e); return 1, true }
	if len(args) < 2 {
		return fail(storage.ErrInvalid)
	}
	ctx := context.Background()
	var seed []byte
	var installation string
	create := args[0] == "state-init"
	if create {
		if len(args) != 3 {
			return fail(storage.ErrInvalid)
		}
		f, e := os.Open(args[2])
		if e != nil {
			return fail(storage.ErrInvalid)
		}
		c, e := config.Load(f)
		f.Close()
		if e != nil {
			return fail(storage.ErrInvalid)
		}
		current, e := user.Current()
		if e != nil || c.RuntimeUser != current.Username || c.Paths.State != args[1] {
			return fail(storage.ErrSafety)
		}
		installation = string(c.InstallationID)
		seed, _ = json.Marshal(c.RuntimeInitial)
	} else if ((args[0] == "state-status" || args[0] == "state-inventory" || args[0] == "state-files") && len(args) != 2) || (args[0] == "state-operation" && len(args) != 3) || ((args[0] == "state-backup" || args[0] == "state-inventory-confirm") && (len(args) != 5 || args[4] != "--confirm")) || ((args[0] == "state-restore" || args[0] == "state-file-reconcile") && (len(args) != 6 || args[5] != "--confirm")) || (args[0] == "state-resolve" && (len(args) != 5 || args[4] != "--confirm")) {
		return fail(storage.ErrInvalid)
	}
	s, e := storage.Open(ctx, args[1], installation, seed, create, storage.DefaultLimits())
	if e != nil {
		return fail(e)
	}
	defer s.Close()
	svc := operations.Offline(s)
	if args[0] == "state-file-reconcile" {
		var closeProtection func()
		svc, closeProtection, e = offlineFileRecovery(s, args[1], args[2])
		if e != nil {
			return fail(e)
		}
		defer closeProtection()
	}
	switch args[0] {
	case "state-init":
		fmt.Fprintln(out, "OK: critical schema v5; existing settings preserved")
	case "state-status":
		json.NewEncoder(out).Encode(s.Health())
	case "state-files":
		items := []any{}
		for _, kind := range []string{"transfer", "trash"} {
			rows, e := s.FileRecords(ctx, kind)
			if e != nil {
				return fail(e)
			}
			for _, r := range rows {
				item := map[string]any{"record": r, "version": storage.FileRecordVersion(r), "private_object_proof": nil}
				var spec struct{ RootPath string }
				if json.Unmarshal(r.Document, &spec) == nil {
					id, _ := s.AgentID(ctx)
					path := spec.RootPath + "/.serverdeck-" + id + "/" + r.ID
					f, e := fileaccess.PinAbsolute(path)
					if e == nil {
						proof, e := fileaccess.IdentityProof(f)
						f.Close()
						if e == nil {
							item["private_object_proof"] = proof
						}
					}
				}
				items = append(items, item)
			}
		}
		json.NewEncoder(out).Encode(map[string]any{"items": items})
	case "state-inventory":
		i, e := s.OwnedInventory(ctx)
		if e != nil {
			return fail(e)
		}
		json.NewEncoder(out).Encode(i)
	case "state-operation":
		o, e := svc.Get(ctx, args[2])
		if e != nil {
			return fail(e)
		}
		json.NewEncoder(out).Encode(o)
	case "state-resolve":
		if e := svc.ResolveLocal(ctx, operations.Local(), args[2], args[3]); e != nil {
			return fail(e)
		}
		o, e := svc.Get(ctx, args[2])
		if e != nil {
			return fail(e)
		}
		json.NewEncoder(out).Encode(o)
	case "state-backup", "state-restore", "state-inventory-confirm", "state-file-reconcile":
		action := "storage.backup"
		id := args[3]
		params := operations.MaintenanceParams(args[2], "")
		if args[0] == "state-restore" {
			action = "storage.restore"
			id = args[4]
			params = operations.MaintenanceParams(args[3], args[2])
		}
		if args[0] == "state-inventory-confirm" || args[0] == "state-file-reconcile" {
			action = "storage.inventory.confirm"
			if args[0] == "state-file-reconcile" {
				action = "files.reconcile"
				id = args[4]
			}
			input := args[2]
			if args[0] == "state-file-reconcile" {
				input = args[3]
			}
			params, e = auth.ReadTrusted(input, 65536, false)
			if e != nil {
				return fail(e)
			}
		}
		r := operations.Request{ID: id, Action: action, Params: params}
		a := operations.Local()
		// Retry lookup precedes preparing a new plan/destination existence check.
		if o, e := svc.Get(ctx, id); e == nil {
			mac, e := s.Fingerprint(a.ID(), action, params, "")
			if e != nil || !storage.Matches(o, a.ID(), action, mac) {
				return fail(storage.ErrConflict)
			}
			json.NewEncoder(out).Encode(o)
			return 0, true
		} else if e != storage.ErrNotFound {
			return fail(e)
		}
		p, e := svc.Prepare(ctx, a, r)
		if e != nil {
			return fail(e)
		}
		r.Plan = p.ID
		o, e := svc.Execute(ctx, a, r)
		if o.ID != "" {
			json.NewEncoder(out).Encode(o)
		}
		if e != nil {
			return fail(e)
		}
	}
	return 0, true
}
