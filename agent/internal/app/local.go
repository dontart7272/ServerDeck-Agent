// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"serverdeck.local/agent/internal/auth"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/operations"
	"serverdeck.local/agent/internal/storage"
)

type localPeerKey struct{}

// Local transport supplies the OS peer; no request field chooses an actor.
func (g *Gateway) localHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	uid, ok := r.Context().Value(localPeerKey{}).(uint32)
	if !ok {
		g.fail(w, "", storage.ErrUnauthorized, "")
		return
	}
	a := operations.LocalPeer(uid)
	if a.ID() == "" {
		g.fail(w, "", storage.ErrUnauthorized, "")
		return
	}
	if r.URL.RawQuery != "" || r.Header.Get("Origin") != "" || len(r.RequestURI) > 2048 {
		g.fail(w, "", storage.ErrInvalid, "")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/local/v1/transfers/") {
		request := r.Clone(r.Context())
		request.URL.Path = "/api/v1/transfers/" + strings.TrimPrefix(r.URL.Path, "/local/v1/transfers/")
		check := func(ctx context.Context) error {
			if ctx.Err() != nil {
				return storage.ErrUnauthorized
			}
			return nil
		}
		if r.Method == "PUT" {
			g.fileReceive(w, request, a.ID(), check, r.Context(), nil)
		} else {
			g.fileContentOwned(w, request, a.ID(), check, r.Context())
		}
		return
	}
	if r.URL.Path == "/local/v1/pairing" && r.Method == "POST" {
		b, e := readJSON(w, r)
		if e != nil {
			g.fail(w, "", e, "")
			return
		}
		if string(bytes.TrimSpace(b)) != "{}" {
			g.fail(w, "", storage.ErrInvalid, "")
			return
		}
		c, e := g.Issue(r.Context(), a)
		if e != nil {
			g.fail(w, "", e, "")
			return
		}
		// Explicit SSH/local stdout is the sole place that returns this secret.
		value := map[string]any{"agent_id": g.AgentID, "port": g.Port, "api_majors": []int{1}, "fingerprint_sha256": auth.Fingerprint(g.Certificate), "certificate_expires_at": timestamp(g.Certificate.NotAfter), "san_dns": g.Certificate.DNSNames, "san_ips": g.Certificate.IPAddresses, "pairing_id": c.ID, "pairing_code": c.Secret, "expires_at": timestamp(c.Expires)}
		g.replyLocal(w, value)
		return
	}
	if r.URL.Path == "/local/v1/query" && r.Method == "POST" {
		b, e := readJSON(w, r)
		if e != nil {
			g.fail(w, "", e, "")
			return
		}
		q, e := contracts.Decode[contracts.QueryRequest](bytes.NewReader(b), contracts.Target{Family: "api", Definition: "QueryRequest"}, contracts.MaxJSONBytes)
		if e != nil {
			g.fail(w, "", e, "")
			return
		}
		data, e := g.Query(withMetricOwner(r.Context(), a.ID()), q.Query, q.Params)
		if e != nil {
			g.fail(w, string(q.RequestID), e, "")
			return
		}
		g.reply(w, 200, "QueryResponse", map[string]any{"schema_version": "1.0", "request_id": q.RequestID, "agent_id": g.AgentID, "served_at": timestamp(time.Now()), "query": q.Query, "data": data})
		return
	}
	if r.URL.Path == "/local/v1/prepare" && r.Method == "POST" {
		b, e := readJSON(w, r)
		if e != nil {
			g.fail(w, "", e, "")
			return
		}
		q, e := contracts.Decode[contracts.PrepareRequest](bytes.NewReader(b), contracts.Target{Family: "api", Definition: "PrepareRequest"}, contracts.MaxJSONBytes)
		if e != nil {
			g.fail(w, "", e, "")
			return
		}
		p, e := g.Operations.Prepare(r.Context(), a, operationRequest(q.OperationID, q.Action, q.Params, q.ExpectedVersion, ""))
		if e != nil {
			g.fail(w, string(q.RequestID), e, string(q.OperationID))
			return
		}
		g.reply(w, 200, "PrepareResult", g.prepareWire(q, p))
		return
	}
	if r.URL.Path == "/local/v1/operations" && r.Method == "POST" {
		b, e := readJSON(w, r)
		if e != nil {
			g.fail(w, "", e, "")
			return
		}
		q, e := contracts.Decode[contracts.OperationRequest](bytes.NewReader(b), contracts.Target{Family: "api", Definition: "OperationRequest"}, contracts.MaxJSONBytes)
		if e != nil {
			g.fail(w, "", e, "")
			return
		}
		o, e := g.Operations.Execute(r.Context(), a, operationRequest(q.OperationID, q.Action, q.Params, q.ExpectedVersion, q.PlanID))
		if o.ID == "" {
			g.fail(w, string(q.RequestID), e, string(q.OperationID))
			return
		}
		g.reply(w, 202, "Operation", operationWire(o))
		return
	}
	g.fail(w, "", storage.ErrInvalid, "")
}
func (g *Gateway) prepareWire(q contracts.PrepareRequest, p operations.Plan) map[string]any {
	versions := []any{}
	var v revokeParams
	if q.Action == "devices.revoke" && json.Unmarshal(q.Params, &v) == nil {
		versions = append(versions, map[string]any{"object_ref": "device:" + v.DeviceID, "version": v.Expected})
	}
	addVersion := func(ref, version string) {
		if version != "" {
			versions = append(versions, map[string]any{"object_ref": ref, "version": version})
		}
	}
	// References are opaque hashes; plans never expose path bytes or file content.
	var fields map[string]json.RawMessage
	if len(q.Action) >= 5 && (q.Action[:5] == "files" || q.Action[:5] == "trash") && json.Unmarshal(q.Params, &fields) == nil {
		for _, pair := range [][2]string{{"location", "expected_version"}, {"parent", "parent_version"}, {"target_parent", "target_parent_version"}} {
			var version string
			if json.Unmarshal(fields[pair[1]], &version) == nil && fields[pair[0]] != nil {
				var object any
				if json.Unmarshal(fields[pair[0]], &object) == nil {
					addVersion("file:"+scopeJSON(object), version)
				}
			}
		}
		for _, key := range []string{"trash_id", "transfer_id"} {
			var id, version string
			if json.Unmarshal(fields[key], &id) == nil && json.Unmarshal(fields["expected_version"], &version) == nil {
				addVersion(key+":"+id, version)
			}
		}
	}
	code, description := "REVOKE_DEVICE", "Confirm revocation of this device access"
	switch q.Action {
	case "files.create":
		code, description = "CREATE_FILE_OBJECT", "Create a new object only if its name is unoccupied"
	case "files.rename", "files.move":
		code, description = "MOVE_FILE_OBJECT", "Move the checked object; external directory changes can leave an uncertain outcome"
	case "files.write.begin", "files.upload.begin":
		code, description = "RESERVE_FILE_TRANSFER", "Reserve private staging space; this does not publish the target file"
	case "files.transfer.commit":
		code, description = "PUBLISH_FILE_TRANSFER", "Publish verified content atomically; preserve a replaced version in trash"
	case "files.trash":
		code, description = "TRASH_FILE_OBJECT", "Move the checked object to the private trash on its filesystem"
	case "trash.restore":
		code, description = "RESTORE_TRASH_OBJECT", "Restore the checked trash entry; an occupied name requires an explicit versioned replacement"
	case "trash.purge":
		code, description = "PURGE_TRASH_OBJECT", "Permanently delete this trash entry and its contents; recovery is not guaranteed"
	}
	if q.Action == "config.set" {
		code = "CHANGE_RETENTION_POLICY"
		description = "Confirm policy change; reducing budget or retention may permanently remove history and completed journals"
		if q.ExpectedVersion != nil {
			versions = append(versions, map[string]any{"object_ref": "settings.runtime", "version": string(*q.ExpectedVersion)})
		}
	}
	if q.Action == "config.set" {
		var config struct {
			Changes map[string]json.RawMessage `json:"changes"`
		}
		if json.Unmarshal(q.Params, &config) == nil && len(config.Changes) == 1 && config.Changes["icmp"] != nil {
			code = "CONFIGURE_ICMP"
			description = "Change the shared ICMP target and explicit background monitoring setting"
		}
	}
	if q.Action == "config.set" {
		var cfg struct {
			Changes map[string]json.RawMessage `json:"changes"`
		}
		json.Unmarshal(q.Params, &cfg)
		if len(cfg.Changes) == 1 && cfg.Changes["files"] != nil {
			code = "CONFIGURE_FILES"
			description = "Change common roots and byte limits; root / preserves all fixed protections and unsafe filesystem profiles remain unavailable"
		}
	}
	if q.Action == "rules.put" || q.Action == "rules.delete" {
		code = "CHANGE_EVENT_RULE"
		description = "Confirm versioned change of server event evaluation policy"
		if q.ExpectedVersion != nil {
			versions = append(versions, map[string]any{"object_ref": "rules.registry", "version": string(*q.ExpectedVersion)})
		}
	}
	if q.Action == "operations.cancel" {
		var c cancelParams
		json.Unmarshal(q.Params, &c)
		versions = append(versions, map[string]any{"object_ref": "operation:" + c.Target, "version": c.Expected})
		code = "CANCEL_OPERATION"
		description = "Request cancellation only before the effect phase"
	}
	if q.Action == "process.term" || q.Action == "process.kill" {
		var process processParams
		json.Unmarshal(q.Params, &process)
		versions = append(versions, map[string]any{"object_ref": "process:" + process.Ref, "version": process.Ref})
		code = "SEND_SIGTERM"
		description = "Send SIGTERM to this exact process instance; exit is not guaranteed"
		if q.Action == "process.kill" {
			code = "SEND_SIGKILL"
			description = "Send SIGKILL to this exact process instance; unsaved data may be lost"
		}
	}
	if q.Action == "diagnostics.icmp.run" {
		var probe icmpParams
		json.Unmarshal(q.Params, &probe)
		versions = append(versions, map[string]any{"object_ref": "diagnostics.icmp", "version": probe.Version})
		code = "RUN_ICMP"
		description = "Send at most five ICMP probes to the configured target within ten seconds"
	}
	return map[string]any{"schema_version": "1.0", "request_id": q.RequestID, "agent_id": g.AgentID, "served_at": timestamp(time.Now()), "operation_id": q.OperationID, "plan_id": p.ID, "expires_at": timestamp(p.Expires), "object_versions": versions, "consequences": []any{map[string]any{"code": code, "description": description, "irreversible": q.Action == "devices.revoke" || q.Action == "trash.purge" || (q.Action == "config.set" && code != "CONFIGURE_ICMP" && code != "CONFIGURE_FILES") || q.Action == "process.term" || q.Action == "process.kill"}}}
}
func (g *Gateway) replyLocal(w http.ResponseWriter, v any) {
	b, e := json.Marshal(v)
	if e != nil || len(b) > contracts.MaxJSONBytes {
		g.fail(w, "", storage.ErrInvalid, "")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(b)
}
