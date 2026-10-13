// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"serverdeck.local/agent/internal/auth"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/storage"
)

type subscription struct {
	ID, Topic      string
	Params         json.RawMessage
	After, Pending string
	PendingBytes   int
	Sent           time.Time
	Counter        int64
}

func (g *Gateway) websocket(w http.ResponseWriter, r *http.Request, session *auth.Session) {
	if r.Header.Get("Sec-WebSocket-Protocol") != "serverdeck.v1" {
		g.fail(w, "", storage.ErrInvalid, "")
		return
	}
	g.mu.Lock()
	if g.wsTotal >= 16 || g.wsDevices[session.Credential.ID()] >= 2 {
		g.mu.Unlock()
		g.fail(w, "", storage.ErrQuota, "")
		return
	}
	g.wsTotal++
	g.wsDevices[session.Credential.ID()]++
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		g.wsTotal--
		g.wsDevices[session.Credential.ID()]--
		if g.wsDevices[session.Credential.ID()] == 0 {
			delete(g.wsDevices, session.Credential.ID())
		}
		g.mu.Unlock()
		session.Close()
		if info, ok := r.Context().Value(connectionKey{}).(*connectionInfo); ok {
			g.closeConnection(info.conn)
		}
	}()
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Time{})
	_ = controller.SetWriteDeadline(time.Time{})
	control := func(context.Context, []byte) bool {
		if !g.limiter.allow("device:"+session.Credential.ID(), 20, 40) {
			session.Close()
			return false
		}
		return true
	}
	conn, e := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"serverdeck.v1"}, CompressionMode: websocket.CompressionDisabled, OnPingReceived: control, OnPongReceived: func(ctx context.Context, p []byte) { control(ctx, p) }})
	if e != nil {
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(contracts.MaxJSONBytes)
	// Keep the reader alive for the close handshake. Canceling a coder Read
	// directly tears down TCP before a 1008 frame can be sent on revocation.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	incoming := make(chan []byte)
	readError := make(chan error, 1)
	go func() {
		for {
			kind, data, e := conn.Read(ctx)
			if e != nil {
				readError <- e
				return
			}
			if kind != websocket.MessageText {
				readError <- storage.ErrInvalid
				return
			}
			select {
			case incoming <- data:
			case <-ctx.Done():
				return
			}
		}
	}()
	subscriptions := map[string]*subscription{}
	connectionID, err := storage.RandomID()
	if err != nil {
		return
	}
	leaseOwner := "wss:" + session.Credential.ID() + ":" + connectionID
	defer func() {
		if g.Metrics != nil {
			g.Metrics.Release(leaseOwner)
		}
	}()
	pendingBytes := 0
	check := time.NewTicker(time.Second)
	defer check.Stop()
	updates := time.NewTicker(time.Second)
	updateCount := 0
	defer updates.Stop()
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()
	sendError := func(id string, err error) {
		kind := "error"
		if errorCode(err) == "CURSOR_GAP" {
			kind = "gap"
		}
		_ = g.sendWSS(conn, session, map[string]any{"schema_version": "1.0", "subscription_id": id, "server_time": timestamp(time.Now()), "type": kind, "error": map[string]any{"code": errorCode(err), "message": errorCode(err), "retryable": false}})
	}
	emit := func(s *subscription) error {
		if s.Topic == "snapshot" {
			var p metricParams
			if json.Unmarshal(s.Params, &p) != nil {
				return storage.ErrInvalid
			}
			if e := metricBlocks(p.Blocks); e != nil {
				return e
			}
			if p.View == "detail" && (len(p.Blocks) == 0 || hasBlock(p.Blocks, "processes")) {
				if e := g.Metrics.Lease(leaseOwner); e != nil {
					return e
				}
			}
			period := 5 * time.Second
			if p.View == "detail" {
				period = 2 * time.Second
			}
			if !s.Sent.IsZero() && time.Since(s.Sent) < period {
				return nil
			}
			value := g.Metrics.Snapshot(p.View, p.Blocks, p.Resources)
			if e := g.sendWSS(conn, session, map[string]any{"schema_version": "1.0", "subscription_id": s.ID, "server_time": timestamp(time.Now()), "type": "snapshot", "data": value}); e != nil {
				return e
			}
			s.Sent = time.Now()
			return nil
		}
		if s.Pending != "" {
			return nil
		}
		var data []any
		var cursor string
		var e error
		if s.Topic == "storage" {
			s.Counter++
			data = []any{g.storageInfo()}
			cursor, e = g.cursor("storage", g.RunID, scope(s.Params), s.Counter)
		} else {
			var p map[string]any
			json.Unmarshal(s.Params, &p)
			p["limit"] = 8
			if s.After != "" {
				p["cursor"] = s.After
			}
			raw, _ := json.Marshal(p)
			value, err := g.Query(ctx, "operations.list", raw)
			if err != nil {
				return err
			}
			page := value.(map[string]any)
			data = page["items"].([]any)
			cursor, _ = page["next_cursor"].(string)
			if cursor == "" {
				return nil
			}
		}
		if e != nil {
			return e
		}
		value := map[string]any{"schema_version": "1.0", "subscription_id": s.ID, "server_time": timestamp(time.Now()), "type": "changes", "topic": s.Topic, "data": data, "cursor": cursor}
		var encoded bytes.Buffer
		if e = contracts.Encode(&encoded, contracts.Target{Family: "api", Definition: "WssServerMessage"}, value, contracts.MaxJSONBytes); e != nil {
			return e
		}
		if pendingBytes+encoded.Len() > 4000000 {
			return storage.ErrQuota
		}
		if e = g.sendWSSBytes(conn, session, encoded.Bytes()); e != nil {
			return e
		}
		s.Pending = cursor
		s.PendingBytes = encoded.Len()
		pendingBytes += encoded.Len()
		s.Sent = time.Now()
		return nil
	}
	for {
		select {
		case <-session.Context.Done():
			_ = conn.Close(websocket.StatusPolicyViolation, "UNAUTHORIZED")
			return
		case <-readError:
			if session.Context.Err() != nil {
				_ = conn.Close(websocket.StatusPolicyViolation, "UNAUTHORIZED")
			}
			return
		case <-check.C:
			if e = session.Check(ctx); e != nil {
				_ = conn.Close(websocket.StatusPolicyViolation, "UNAUTHORIZED")
				return
			}
			for _, s := range subscriptions {
				if s.Pending != "" && time.Since(s.Sent) > 30*time.Second {
					_ = conn.Close(websocket.StatusTryAgainLater, "ACK_TIMEOUT")
					return
				}
			}
		case <-ping.C:
			pingCtx, stop := context.WithTimeout(ctx, 10*time.Second)
			e = conn.Ping(pingCtx)
			stop()
			if e != nil {
				return
			}
		case <-updates.C:
			updateCount++
			for _, s := range subscriptions {
				if s.Topic != "snapshot" && updateCount%5 != 0 {
					continue
				}
				if e = emit(s); e != nil {
					sendError(s.ID, e)
					_ = conn.Close(websocket.StatusTryAgainLater, "RESUME_REQUIRED")
					return
				}
			}
		case data := <-incoming:
			if e = session.Check(ctx); e != nil {
				_ = conn.Close(websocket.StatusPolicyViolation, "UNAUTHORIZED")
				return
			}
			if !g.limiter.allow("device:"+session.Credential.ID(), 20, 40) {
				_ = conn.Close(websocket.StatusTryAgainLater, "RATE_LIMITED")
				return
			}
			raw, e := contracts.Validate(bytes.NewReader(data), contracts.Target{Family: "api", Definition: "WssClientMessage"}, contracts.MaxJSONBytes)
			if e != nil {
				sendError("session", e)
				_ = conn.Close(websocket.StatusPolicyViolation, "INVALID_REQUEST")
				return
			}
			var message struct {
				Type, SubscriptionID, Cursor string
				Subscriptions                []struct {
					ID, Topic string
					Params    json.RawMessage
					After     string
				}
			}
			var fields map[string]json.RawMessage
			json.Unmarshal(raw, &fields)
			json.Unmarshal(fields["type"], &message.Type)
			json.Unmarshal(fields["subscription_id"], &message.SubscriptionID)
			json.Unmarshal(fields["cursor"], &message.Cursor)
			json.Unmarshal(fields["subscriptions"], &message.Subscriptions)
			if message.Type == "ack" {
				s := subscriptions[message.SubscriptionID]
				if s == nil || s.Pending == "" || s.Pending != message.Cursor {
					sendError(message.SubscriptionID, storage.ErrInvalid)
					_ = conn.Close(websocket.StatusPolicyViolation, "INVALID_ACK")
					return
				}
				s.After = s.Pending
				s.Pending = ""
				pendingBytes -= s.PendingBytes
				s.PendingBytes = 0
				if s.Topic == "operations" {
					if e = emit(s); e != nil {
						sendError(s.ID, e)
					}
				}
				continue
			}
			if len(subscriptions)+len(message.Subscriptions) > 16 {
				sendError("session", contracts.ErrLimit)
				_ = conn.Close(websocket.StatusPolicyViolation, "LIMIT_EXCEEDED")
				return
			}
			batchIDs := map[string]bool{}
			for _, v := range message.Subscriptions {
				if subscriptions[v.ID] != nil || batchIDs[v.ID] {
					sendError(v.ID, storage.ErrInvalid)
					_ = conn.Close(websocket.StatusPolicyViolation, "DUPLICATE_SUBSCRIPTION")
					return
				}
				batchIDs[v.ID] = true
			}
			for _, v := range message.Subscriptions {
				if v.Topic != "operations" && v.Topic != "storage" && (v.Topic != "snapshot" || g.Metrics == nil) {
					sendError(v.ID, errors.New("SOURCE_UNAVAILABLE"))
					continue
				}
				s := &subscription{ID: v.ID, Topic: v.Topic, Params: v.Params, After: v.After}
				if v.After != "" {
					kind := "operations.list"
					if v.Topic == "storage" {
						kind = "storage"
					}
					c, err := g.position(v.After, kind, scope(v.Params))
					if err != nil || v.Topic == "storage" && c.Epoch != g.RunID {
						if err == nil {
							err = storage.ErrCursor
						}
						sendError(v.ID, err)
						continue
					}
					s.Counter = c.Position
				}
				subscriptions[v.ID] = s
				var start any
				if v.After != "" {
					start = v.After
				}
				if e = g.sendWSS(conn, session, map[string]any{"schema_version": "1.0", "type": "subscribed", "subscription_id": v.ID, "server_time": timestamp(time.Now()), "cursor": start}); e != nil {
					return
				}
				if e = emit(s); e != nil {
					sendError(s.ID, e)
					delete(subscriptions, s.ID)
				}
			}
		}
	}
}
func (g *Gateway) sendWSS(c *websocket.Conn, s *auth.Session, value any) error {
	var b bytes.Buffer
	if e := contracts.Encode(&b, contracts.Target{Family: "api", Definition: "WssServerMessage"}, value, contracts.MaxJSONBytes); e != nil {
		return e
	}
	return g.sendWSSBytes(c, s, b.Bytes())
}
func (g *Gateway) sendWSSBytes(c *websocket.Conn, s *auth.Session, b []byte) error {
	ctx, cancel := context.WithTimeout(s.Context, 10*time.Second)
	defer cancel()
	writer, e := c.Writer(ctx, websocket.MessageText)
	if e != nil {
		return e
	}
	closed := false
	defer func() {
		if !closed {
			_ = c.CloseNow()
		}
	}()
	for len(b) > 0 {
		if e = s.Check(ctx); e != nil {
			return e
		}
		n := len(b)
		if n > 64000 {
			n = 64000
		}
		if _, e = writer.Write(b[:n]); e != nil {
			return e
		}
		b = b[n:]
	}
	e = writer.Close()
	closed = true
	return e
}
