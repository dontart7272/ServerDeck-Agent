// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"serverdeck.local/agent/internal/auth"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/operations"
	"serverdeck.local/agent/internal/storage"
)

type connectionKey struct{}
type connectionInfo struct {
	mu      sync.Mutex
	session *auth.Session
	conn    net.Conn
}

func (g *Gateway) HTTPServer(config *tls.Config) *http.Server {
	return &http.Server{Handler: g, TLSConfig: config, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 11904, TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}, ErrorLog: log.New(io.Discard, "", 0), ConnContext: func(ctx context.Context, c net.Conn) context.Context {
		info := &connectionInfo{conn: c}
		g.mu.Lock()
		full := len(g.connections) >= 64
		if !full {
			g.connections[c] = info
		}
		g.mu.Unlock()
		if full {
			c.Close()
		}
		return context.WithValue(ctx, connectionKey{}, info)
	}, ConnState: func(c net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			g.closeConnection(c)
		}
	}}
}

// HTTP ConnState has no context argument. Attach cancellation to a wrapped
// listener connection, and use response-local leases for handler-only tests.
func (g *Gateway) closeConnection(c net.Conn) {
	g.mu.Lock()
	info := g.connections[c]
	delete(g.connections, c)
	g.mu.Unlock()
	if info != nil {
		info.mu.Lock()
		if info.session != nil {
			info.session.Close()
		}
		info.mu.Unlock()
	}
}
func (g *Gateway) requestSession(r *http.Request, c storage.Credential) (*auth.Session, func(), error) {
	if info, ok := r.Context().Value(connectionKey{}).(*connectionInfo); ok {
		info.mu.Lock()
		defer info.mu.Unlock()
		if info.session != nil && info.session.Credential.ID() != c.ID() {
			info.session.Close()
			info.session = nil
		}
		if info.session == nil {
			var e error
			info.session, e = g.Auth.Session(c)
			if e != nil {
				return nil, nil, e
			}
		}
		return info.session, func() {}, nil
	}
	session, e := g.Auth.Session(c)
	if e != nil {
		return nil, nil, e
	}
	return session, session.Close, nil
}
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fallback := "00000000-0000-4000-8000-000000000000"
	if r.TLS == nil || r.TLS.Version < tls.VersionTLS12 {
		g.fail(w, fallback, storage.ErrUnauthorized, "")
		return
	}
	headerBytes := len(r.Method) + len(r.RequestURI) + len(r.Proto) + 6 + len(r.Host) + 8
	for k, v := range r.Header {
		for _, s := range v {
			headerBytes += len(k) + len(s) + 4
		}
	}
	if headerBytes > 16000 || len(r.RequestURI) > 2048 || r.URL.RawQuery != "" || r.Header.Get("Cookie") != "" {
		g.fail(w, fallback, storage.ErrInvalid, "")
		return
	}
	if r.Header.Get("Origin") != "" {
		g.fail(w, fallback, storage.ErrPolicy, "")
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/v1/") {
		g.fail(w, fallback, storage.ErrSchema, "")
		return
	}
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		g.fail(w, fallback, storage.ErrInvalid, "")
		return
	}
	ip, e := netip.ParseAddr(host)
	if e != nil {
		g.fail(w, fallback, storage.ErrInvalid, "")
		return
	}
	ip = ip.Unmap()
	if r.URL.Path == "/api/v1/pair" {
		if !g.limiter.allow("unauth:"+ip.String(), 2, 5) || !g.limiter.allow("pair-global", 1, 3) || !g.limiter.allow("pair:"+ip.String(), .2, 3) {
			g.fail(w, fallback, auth.ErrRate, "")
			return
		}
		if r.Method != "POST" {
			g.fail(w, fallback, storage.ErrInvalid, "")
			return
		}
		body, e := readJSON(w, r)
		if e != nil {
			g.fail(w, fallback, e, "")
			return
		}
		req, e := contracts.Decode[contracts.APIPairRequest](bytes.NewReader(body), contracts.Target{Family: "api", Definition: "PairRequest"}, contracts.MaxJSONBytes)
		if e != nil {
			g.fail(w, fallback, e, "")
			return
		}
		result, e := g.Pair(r.Context(), req)
		if e != nil {
			g.fail(w, req.RequestId, e, "")
			return
		}
		g.reply(w, 201, "PairResult", result)
		return
	}
	authorization := r.Header.Values("Authorization")
	if len(authorization) != 1 || !strings.HasPrefix(authorization[0], "Bearer ") {
		if !g.limiter.allow("unauth:"+ip.String(), 2, 5) {
			g.fail(w, fallback, auth.ErrRate, "")
		} else {
			g.fail(w, fallback, storage.ErrUnauthorized, "")
		}
		return
	}
	if g.limiter.blocked("unauth:" + ip.String()) {
		g.fail(w, fallback, auth.ErrRate, "")
		return
	}
	credential, e := g.Auth.Authenticate(r.Context(), strings.TrimPrefix(authorization[0], "Bearer "))
	if e != nil {
		g.limiter.allow("unauth:"+ip.String(), 2, 5)
		g.fail(w, fallback, e, "")
		return
	}
	if !g.limiter.allow("device:"+credential.ID(), 20, 40) {
		g.fail(w, fallback, auth.ErrRate, "")
		return
	}
	session, release, e := g.requestSession(r, credential)
	if e != nil {
		g.fail(w, fallback, e, "")
		return
	}
	defer release()
	actor := operations.Device(credential)
	if r.URL.Path == "/api/v1/stream" {
		if r.Method != "GET" {
			g.fail(w, fallback, storage.ErrInvalid, "")
			return
		}
		g.websocket(w, r, session)
		return
	}
	if r.URL.Path == "/api/v1/query" && r.Method == "POST" {
		body, e := readJSON(w, r)
		if e != nil {
			g.fail(w, fallback, e, "")
			return
		}
		req, e := contracts.Decode[contracts.QueryRequest](bytes.NewReader(body), contracts.Target{Family: "api", Definition: "QueryRequest"}, contracts.MaxJSONBytes)
		if e != nil {
			g.fail(w, fallback, e, "")
			return
		}
		data, e := g.Query(withMetricOwner(r.Context(), "device:"+session.Credential.ID()), req.Query, req.Params)
		if e != nil {
			g.fail(w, string(req.RequestID), e, "")
			return
		}
		if e = session.Check(r.Context()); e != nil {
			g.fail(w, string(req.RequestID), e, "")
			return
		}
		g.reply(w, 200, "QueryResponse", map[string]any{"schema_version": "1.0", "request_id": req.RequestID, "agent_id": g.AgentID, "served_at": timestamp(time.Now()), "query": req.Query, "data": data})
		return
	}
	if r.URL.Path == "/api/v1/prepare" && r.Method == "POST" {
		body, e := readJSON(w, r)
		if e != nil {
			g.fail(w, fallback, e, "")
			return
		}
		req, e := contracts.Decode[contracts.PrepareRequest](bytes.NewReader(body), contracts.Target{Family: "api", Definition: "PrepareRequest"}, contracts.MaxJSONBytes)
		if e != nil {
			g.fail(w, fallback, e, "")
			return
		}
		request := operationRequest(req.OperationID, req.Action, req.Params, req.ExpectedVersion, "")
		plan, e := g.Operations.Prepare(r.Context(), actor, request)
		if e != nil {
			g.fail(w, string(req.RequestID), e, string(req.OperationID))
			return
		}
		g.reply(w, 200, "PrepareResult", g.prepareWire(req, plan))
		return
	}
	if r.URL.Path == "/api/v1/operations" && r.Method == "POST" {
		body, e := readJSON(w, r)
		if e != nil {
			g.fail(w, fallback, e, "")
			return
		}
		req, e := contracts.Decode[contracts.OperationRequest](bytes.NewReader(body), contracts.Target{Family: "api", Definition: "OperationRequest"}, contracts.MaxJSONBytes)
		if e != nil {
			g.fail(w, fallback, e, "")
			return
		}
		o, e := g.Operations.Execute(r.Context(), actor, operationRequest(req.OperationID, req.Action, req.Params, req.ExpectedVersion, req.PlanID))
		if o.ID != "" {
			g.reply(w, 202, "Operation", operationWire(o))
			return
		}
		g.fail(w, string(req.RequestID), e, string(req.OperationID))
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/operations/") && r.Method == "GET" {
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/operations/")
		o, e := g.Operations.Get(r.Context(), id)
		if e != nil {
			g.fail(w, fallback, e, id)
			return
		}
		if e = session.Check(r.Context()); e != nil {
			g.fail(w, fallback, e, id)
			return
		}
		g.reply(w, 200, "Operation", operationWire(o))
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/transfers/") || strings.HasPrefix(r.URL.Path, "/api/v1/ui/") {
		g.fail(w, fallback, errors.New("SOURCE_UNAVAILABLE"), "")
		return
	}
	g.fail(w, fallback, storage.ErrInvalid, "")
}
func operationRequest(id contracts.UUID, action string, params []byte, expected *contracts.Version, plan string) operations.Request {
	r := operations.Request{ID: string(id), Action: action, Params: params, Plan: plan}
	if expected != nil {
		r.Expected = string(*expected)
	}
	return r
}
func readJSON(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	media, params, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || media != "application/json" || r.Header.Get("Content-Encoding") != "" || len(params) > 1 || params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8") {
		return nil, storage.ErrInvalid
	}
	if r.ContentLength > contracts.MaxJSONBytes {
		return nil, contracts.ErrLimit
	}
	body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, contracts.MaxJSONBytes))
	if e != nil {
		return nil, contracts.ErrLimit
	}
	return body, nil
}
func (g *Gateway) reply(w http.ResponseWriter, status int, definition string, value any) {
	var b bytes.Buffer
	if e := contracts.Encode(&b, contracts.Target{Family: "api", Definition: definition}, value, contracts.MaxJSONBytes); e != nil {
		g.fail(w, "00000000-0000-4000-8000-000000000000", errors.New("INTERNAL_ERROR"), "")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b.Bytes())
}
func errorCode(e error) string {
	if e == nil {
		return "INTERNAL_ERROR"
	}
	switch e.Error() {
	case "UNAUTHORIZED", "PAIRING_REJECTED", "POLICY_DENIED", "VERSION_CONFLICT", "IDEMPOTENCY_CONFLICT", "CURSOR_GAP", "CURSOR_EXPIRED", "BUSY", "PLAN_EXPIRED", "LIMIT_EXCEEDED", "INCOMPATIBLE_VERSION", "RATE_LIMITED", "AUDIT_UNAVAILABLE", "STORAGE_UNAVAILABLE", "SOURCE_UNAVAILABLE", "NO_SPACE", "QUOTA_EXCEEDED", "SAFETY_UNAVAILABLE", "UNSUPPORTED_ACTION", "UNSUPPORTED_QUERY", "INTERNAL_ERROR", "OPERATION_NOT_FOUND":
		return e.Error()
	}
	if errors.Is(e, contracts.ErrLimit) {
		return "LIMIT_EXCEEDED"
	}
	return "INVALID_REQUEST"
}
func (g *Gateway) fail(w http.ResponseWriter, request string, e error, operation string) {
	code := errorCode(e)
	status := 400
	switch code {
	case "UNAUTHORIZED", "PAIRING_REJECTED":
		status = 401
	case "POLICY_DENIED":
		status = 403
	case "OPERATION_NOT_FOUND":
		status = 404
	case "VERSION_CONFLICT", "IDEMPOTENCY_CONFLICT", "CURSOR_GAP", "BUSY", "PLAN_EXPIRED":
		status = 409
	case "CURSOR_EXPIRED":
		status = 410
	case "LIMIT_EXCEEDED":
		status = 413
	case "INCOMPATIBLE_VERSION", "SAFETY_UNAVAILABLE":
		status = 422
	case "RATE_LIMITED":
		status = 429
		w.Header().Set("Retry-After", "1")
	case "AUDIT_UNAVAILABLE", "STORAGE_UNAVAILABLE", "SOURCE_UNAVAILABLE":
		status = 503
	case "NO_SPACE", "QUOTA_EXCEEDED":
		status = 507
	case "INTERNAL_ERROR":
		status = 500
	}
	if !storage.ValidID(request) {
		request = "00000000-0000-4000-8000-000000000000"
	}
	errValue := map[string]any{"code": code, "message": code, "retryable": code == "RATE_LIMITED" || code == "BUSY"}
	if storage.ValidID(operation) {
		errValue["operation_id"] = operation
	}
	value := map[string]any{"schema_version": "1.0", "request_id": request, "agent_id": g.AgentID, "served_at": timestamp(time.Now()), "error": errValue}
	var b bytes.Buffer
	if contracts.Encode(&b, contracts.Target{Family: "api", Definition: "ErrorEnvelope"}, value, contracts.MaxJSONBytes) != nil {
		http.Error(w, "INTERNAL_ERROR", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b.Bytes())
}
