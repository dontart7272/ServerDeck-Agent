// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"serverdeck.local/agent/internal/auth"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/metrics"
	"serverdeck.local/agent/internal/operations"
	"serverdeck.local/agent/internal/storage"
)

type pendingPair struct {
	proof    storage.PairProof
	hash     [32]byte
	id, name string
}
type Gateway struct {
	Store                       *storage.Store
	Auth                        *auth.Manager
	Operations                  *operations.Service
	Metrics                     *metrics.Engine
	MetricsFailure              string
	AgentID, RunID, RuntimeUser string
	Certificate                 *x509.Certificate
	mu                          sync.Mutex
	pairs                       map[string]pendingPair
	pairIDs                     map[string]bool
	issues                      map[string]auth.Code
	limiter                     *limiter
	Port                        int
	wsTotal                     int
	wsDevices                   map[string]int
	connections                 map[net.Conn]*connectionInfo
}

func NewGateway(s *storage.Store, cert *x509.Certificate, user string) (*Gateway, error) {
	id, e := s.AgentID(context.Background())
	if e != nil {
		return nil, e
	}
	run, e := storage.RandomID()
	if e != nil {
		return nil, e
	}
	g := &Gateway{Store: s, Auth: auth.New(s), AgentID: id, RunID: run, RuntimeUser: user, Certificate: cert, pairs: map[string]pendingPair{}, pairIDs: map[string]bool{}, issues: map[string]auth.Code{}, limiter: newLimiter(), wsDevices: map[string]int{}, connections: map[net.Conn]*connectionInfo{}}
	g.Operations, e = operations.NewAuthorized(s, map[string]operations.Handler{"pairing.issue": issueHandler{g}, "devices.pair": pairHandler{g}, "devices.revoke": revokeHandler{g}, "operations.cancel": cancelHandler{g}}, g.authorize)
	if e != nil {
		return nil, e
	}
	return g, nil
}
func (g *Gateway) Close() {
	if g.Metrics != nil {
		g.Metrics.Close()
	}
	g.Auth.Close()
	g.mu.Lock()
	var list []net.Conn
	for c := range g.connections {
		list = append(list, c)
	}
	g.mu.Unlock()
	for _, c := range list {
		c.Close()
		g.closeConnection(c)
	}
}
func (g *Gateway) authorize(ctx context.Context, a operations.Initiator, r operations.Request) error {
	if c := a.Credential(); c != nil {
		if e := g.Store.CheckCredential(ctx, *c); e != nil {
			return e
		}
	} else if strings.HasPrefix(a.ID(), "local:") {
		if a.ID() != operations.Local().ID() && a.ID() != "local:0" {
			return storage.ErrUnauthorized
		}
	} else if a.ID() == "system:pairing" && r.Action == "devices.pair" {
		g.mu.Lock()
		_, ok := g.pairs[r.ID]
		g.mu.Unlock()
		if !ok {
			return storage.ErrUnauthorized
		}
	} else {
		return storage.ErrUnauthorized
	}
	policy, e := g.Store.Policy(ctx)
	if e != nil {
		return e
	}
	for _, v := range policy.DenyActions {
		if v == r.Action {
			return storage.ErrPolicy
		}
	}
	return nil
}
func (g *Gateway) Issue(ctx context.Context, a operations.Initiator) (auth.Code, error) {
	if !strings.HasPrefix(a.ID(), "local:") {
		return auth.Code{}, storage.ErrUnauthorized
	}
	c, e := g.Auth.NewCode()
	if e != nil {
		return c, e
	}
	id, e := storage.RandomID()
	if e != nil {
		g.Auth.DiscardCode(c.ID)
		return auth.Code{}, e
	}
	g.mu.Lock()
	g.issues[id] = c
	g.mu.Unlock()
	defer func() { g.mu.Lock(); delete(g.issues, id); g.mu.Unlock() }()
	params, _ := json.Marshal(map[string]string{"pairing_id": c.ID})
	r := operations.Request{ID: id, Action: "pairing.issue", Params: params}
	p, e := g.Operations.Prepare(ctx, a, r)
	if e == nil {
		r.Plan = p.ID
		var o storage.Operation
		o, e = g.Operations.Execute(ctx, a, r)
		if e == nil && o.State != "succeeded" {
			e = storage.ErrAudit
		}
	}
	if e != nil {
		g.Auth.DiscardCode(c.ID)
		return auth.Code{}, e
	}
	return c, nil
}
func (g *Gateway) Pair(ctx context.Context, r contracts.APIPairRequest) (map[string]any, error) {
	if !storage.ValidDeviceName(r.DeviceName) {
		return nil, storage.ErrInvalid
	}
	proof, e := g.Auth.VerifyCode(ctx, string(r.PairingId), r.PairingCode)
	if e != nil {
		_ = g.Store.Rejection(ctx, storage.Operation{ID: string(r.RequestId), Actor: "system:pairing", Action: "devices.pair"}, "PAIRING_REJECTED")
		return nil, auth.ErrPairing
	}
	id, e := storage.RandomID()
	if e != nil {
		return nil, e
	}
	token, e := auth.RandomSecret(32)
	if e != nil {
		return nil, e
	}
	hash, e := auth.Digest(token, 32)
	if e != nil {
		return nil, e
	}
	g.mu.Lock()
	_, requestReserved := g.pairs[string(r.RequestId)]
	if g.pairIDs[proof.ID()] || requestReserved || len(g.pairs) >= 3 {
		g.mu.Unlock()
		return nil, auth.ErrPairing
	}
	g.pairIDs[proof.ID()] = true
	g.pairs[string(r.RequestId)] = pendingPair{proof, hash, id, r.DeviceName}
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		delete(g.pairIDs, proof.ID())
		delete(g.pairs, string(r.RequestId))
		g.mu.Unlock()
		g.Auth.DiscardCode(proof.ID())
	}()
	params, _ := json.Marshal(map[string]string{"pairing_id": proof.ID(), "device_id": id, "device_name": r.DeviceName})
	request := operations.Request{ID: string(r.RequestId), Action: "devices.pair", Params: params}
	actor := operations.PairingInitiator()
	plan, e := g.Operations.Prepare(ctx, actor, request)
	if e != nil {
		return nil, e
	}
	request.Plan = plan.ID
	o, e := g.Operations.Execute(ctx, actor, request)
	if e != nil {
		return nil, e
	}
	if o.State != "succeeded" {
		return nil, auth.ErrPairing
	}
	return map[string]any{"schema_version": "1.0", "request_id": r.RequestId, "agent_id": g.AgentID, "served_at": timestamp(time.Now()), "device_id": id, "token": token, "api_majors": []int{1}, "created_at": timestamp(time.UnixMicro(o.Updated))}, nil
}

type issueHandler struct{ g *Gateway }

func (h issueHandler) Validate(b []byte) error {
	if len(b) > 256 || !json.Valid(b) {
		return storage.ErrInvalid
	}
	return nil
}
func (h issueHandler) Keys(operations.Request) ([]string, error) {
	return []string{"devices.registry"}, nil
}
func (h issueHandler) Check(_ context.Context, r operations.Request) error {
	h.g.mu.Lock()
	defer h.g.mu.Unlock()
	if _, ok := h.g.issues[r.ID]; !ok {
		return storage.ErrSafety
	}
	return nil
}
func (h issueHandler) Effect(ctx context.Context, r operations.Request) operations.Outcome {
	h.g.mu.Lock()
	c, ok := h.g.issues[r.ID]
	h.g.mu.Unlock()
	if !ok {
		return operations.Outcome{State: "failed", Effect: "none", Code: "INVALID_REQUEST"}
	}
	if e := h.g.Store.CreatePairCode(ctx, r.ID, c.ID, c.Hash, c.Expires); e != nil {
		return outcomeError(e)
	}
	result, _ := json.Marshal(map[string]any{"pairing_id": c.ID, "expires_at": timestamp(c.Expires)})
	return operations.Outcome{State: "succeeded", Effect: "applied", Result: result}
}

type pairHandler struct{ g *Gateway }

func (h pairHandler) Validate(b []byte) error {
	if len(b) > 1024 || !json.Valid(b) {
		return storage.ErrInvalid
	}
	return nil
}
func (h pairHandler) Keys(operations.Request) ([]string, error) {
	return []string{"devices.registry"}, nil
}
func (h pairHandler) Check(_ context.Context, r operations.Request) error {
	h.g.mu.Lock()
	defer h.g.mu.Unlock()
	if _, ok := h.g.pairs[r.ID]; !ok {
		return auth.ErrPairing
	}
	return nil
}
func (h pairHandler) Effect(ctx context.Context, r operations.Request) operations.Outcome {
	h.g.mu.Lock()
	p, ok := h.g.pairs[r.ID]
	h.g.mu.Unlock()
	if !ok {
		return outcomeError(storage.ErrUnauthorized)
	}
	if e := h.g.Store.PairDevice(ctx, r.ID, p.id, p.name, p.hash, p.proof); e != nil {
		return outcomeError(e)
	}
	result, _ := json.Marshal(map[string]any{"device_id": p.id, "created_at": timestamp(time.Now())})
	return operations.Outcome{State: "succeeded", Effect: "applied", Result: result}
}

type revokeParams struct {
	DeviceID string `json:"device_id"`
	Expected string `json:"expected_version"`
}
type revokeHandler struct{ g *Gateway }

func (h revokeHandler) Validate(b []byte) error {
	if _, e := contracts.Parse(bytes.NewReader(b), 4096); e != nil {
		return e
	}
	var r revokeParams
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || !storage.ValidID(r.DeviceID) || len(r.Expected) < 1 || len(r.Expected) > 256 {
		return storage.ErrInvalid
	}
	return nil
}
func (h revokeHandler) Keys(operations.Request) ([]string, error) {
	return []string{"devices.registry"}, nil
}
func (h revokeHandler) Check(ctx context.Context, r operations.Request) error {
	var p revokeParams
	if json.Unmarshal(r.Params, &p) != nil {
		return storage.ErrInvalid
	}
	devices, e := h.g.Store.Devices(ctx)
	if e != nil {
		return e
	}
	for _, d := range devices {
		if d.ID == p.DeviceID {
			if d.RevokedAt != nil || strconv.FormatInt(d.Revision, 10) != p.Expected {
				return storage.ErrVersion
			}
			return nil
		}
	}
	return storage.ErrNotFound
}
func (h revokeHandler) Effect(ctx context.Context, r operations.Request) operations.Outcome {
	var p revokeParams
	json.Unmarshal(r.Params, &p)
	version, e := strconv.ParseInt(p.Expected, 10, 64)
	if e != nil {
		return outcomeError(storage.ErrVersion)
	}
	if e = h.g.Store.RevokeDevice(ctx, r.ID, p.DeviceID, version, r.Credential); e != nil {
		if errors.Is(e, storage.ErrSecurityPublish) {
			h.g.Auth.Revoked(p.DeviceID)
		}
		return outcomeError(e)
	}
	h.g.Auth.Revoked(p.DeviceID)
	result, _ := json.Marshal(map[string]any{"device_id": p.DeviceID, "revoked_at": timestamp(time.Now())})
	return operations.Outcome{State: "succeeded", Effect: "applied", Result: result}
}
func outcomeError(e error) operations.Outcome {
	if errors.Is(e, storage.ErrSecurityPublish) {
		return operations.Outcome{State: "unknown", Effect: "partial", Code: "SAFETY_UNAVAILABLE"}
	}
	if errors.Is(e, storage.ErrUnauthorized) || errors.Is(e, storage.ErrVersion) || errors.Is(e, storage.ErrQuota) {
		return operations.Outcome{State: "rejected", Effect: "none", Code: e.Error()}
	}
	return operations.Outcome{State: "unknown", Effect: "unknown", Code: "STORAGE_UNAVAILABLE"}
}
func timestamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
