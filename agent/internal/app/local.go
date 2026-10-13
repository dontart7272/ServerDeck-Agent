// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"encoding/json"
	"net/http"
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
	code, description := "REVOKE_DEVICE", "Confirm revocation of this device access"
	if q.Action == "operations.cancel" {
		var c cancelParams
		json.Unmarshal(q.Params, &c)
		versions = append(versions, map[string]any{"object_ref": "operation:" + c.Target, "version": c.Expected})
		code = "CANCEL_OPERATION"
		description = "Request cancellation only before the effect phase"
	}
	return map[string]any{"schema_version": "1.0", "request_id": q.RequestID, "agent_id": g.AgentID, "served_at": timestamp(time.Now()), "operation_id": q.OperationID, "plan_id": p.ID, "expires_at": timestamp(p.Expires), "object_versions": versions, "consequences": []any{map[string]any{"code": code, "description": description, "irreversible": q.Action == "devices.revoke"}}}
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
