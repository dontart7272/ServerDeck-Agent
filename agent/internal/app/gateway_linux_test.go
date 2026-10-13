// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"serverdeck.local/agent/internal/auth"
	"serverdeck.local/agent/internal/config"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/operations"
	"serverdeck.local/agent/internal/storage"
)

func newID(t *testing.T) string {
	t.Helper()
	s, e := storage.RandomID()
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func testCertificate(t *testing.T, expired bool) (tls.Certificate, *x509.Certificate, []byte, []byte) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	end := time.Now().Add(24 * time.Hour)
	if expired {
		end = time.Now().Add(-time.Hour)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "loopback test"}, NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: end, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	pk, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	cp := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kp := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})
	cert, e := tls.X509KeyPair(cp, kp)
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	cert.Leaf = leaf
	return cert, leaf, cp, kp
}
func newTestGateway(t *testing.T) (*Gateway, string, []byte) {
	t.Helper()
	b, e := os.ReadFile("../../../Документация ServerDeck/Документация ServerDeck Agent/contracts/examples/config.json")
	if e != nil {
		t.Fatal(e)
	}
	var c config.Config
	if json.Unmarshal(b, &c) != nil {
		t.Fatal("fixture")
	}
	seed, _ := json.Marshal(c.RuntimeInitial)
	path := filepath.Join(t.TempDir(), "state")
	s, e := storage.Open(context.Background(), path, string(c.InstallationID), seed, true, storage.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	_, leaf, _, _ := testCertificate(t, false)
	g, e := NewGateway(s, leaf, "fixture")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { g.Close(); s.Close() })
	return g, path, seed
}
func pairDirect(t *testing.T, g *Gateway) (string, string) {
	t.Helper()
	c, e := g.Issue(context.Background(), operations.Local())
	if e != nil {
		t.Fatal(e)
	}
	r := contracts.APIPairRequest{SchemaVersion: "1.0", RequestId: newID(t), PairingId: c.ID, PairingCode: c.Secret, DeviceName: "test phone"}
	result, e := g.Pair(context.Background(), r)
	if e != nil {
		t.Fatal(e)
	}
	return result["device_id"].(string), result["token"].(string)
}
func pairRequest(t *testing.T, c auth.Code) contracts.APIPairRequest {
	return contracts.APIPairRequest{SchemaVersion: "1.0", RequestId: newID(t), PairingId: c.ID, PairingCode: c.Secret, DeviceName: "phone"}
}
func testHTTPS(t *testing.T, g *Gateway, expired bool) (*httptest.Server, *http.Client, *tls.Config) {
	t.Helper()
	cert, leaf, _, _ := testCertificate(t, expired)
	g.Certificate = leaf
	server := httptest.NewUnstartedServer(g)
	server.Config = g.HTTPServer(auth.ServerTLS(cert))
	server.TLS = server.Config.TLSConfig
	server.StartTLS()
	conf, e := auth.PinnedTLS(leaf, "127.0.0.1", auth.Fingerprint(leaf))
	if e != nil {
		t.Fatal(e)
	}
	tr := &http.Transport{TLSClientConfig: conf, MaxIdleConnsPerHost: 8}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	t.Cleanup(func() { tr.CloseIdleConnections(); g.Close(); server.Close() })
	return server, client, conf
}
func request(t *testing.T, c *http.Client, url, token string, v any) (int, []byte) {
	t.Helper()
	var b []byte
	switch x := v.(type) {
	case []byte:
		b = x
	default:
		b, _ = json.Marshal(v)
	}
	r, e := http.NewRequest("POST", url, bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	res, e := c.Do(r)
	if e != nil {
		t.Fatal("HTTPS request failed", e)
	}
	defer res.Body.Close()
	body, e := io.ReadAll(io.LimitReader(res.Body, contracts.MaxJSONBytes+1))
	if e != nil {
		t.Fatal(e)
	}
	return res.StatusCode, body
}
func query(t *testing.T, c *http.Client, url, token, name string, params any) (int, []byte) {
	return request(t, c, url+"/api/v1/query", token, map[string]any{"schema_version": "1.0", "request_id": newID(t), "query": name, "params": params})
}
func decodeMap(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var v map[string]any
	if json.Unmarshal(b, &v) != nil {
		t.Fatal("invalid JSON")
	}
	return v
}

func TestPairingAtomicReplayAttemptsRestartAndSecrets(t *testing.T) {
	g, path, _ := newTestGateway(t)
	ctx := context.Background()
	c, e := g.Issue(ctx, operations.Local())
	if e != nil {
		t.Fatal(e)
	}
	r := contracts.APIPairRequest{SchemaVersion: "1.0", RequestId: newID(t), PairingId: c.ID, PairingCode: c.Secret, DeviceName: "first"}
	value, e := g.Pair(ctx, r)
	if e != nil {
		t.Fatal(e)
	}
	token := value["token"].(string)
	id := value["device_id"].(string)
	if _, e = g.Auth.Authenticate(ctx, token); e != nil {
		t.Fatal("token not committed")
	}
	if _, e = g.Pair(ctx, r); !errors.Is(e, auth.ErrPairing) {
		t.Fatal("replay returned credential")
	}
	c2, e := g.Issue(ctx, operations.Local())
	if e != nil {
		t.Fatal(e)
	}
	bad, _ := auth.RandomSecret(16)
	for i := 0; i < 5; i++ {
		if _, e = g.Auth.VerifyCode(ctx, c2.ID, bad); !errors.Is(e, auth.ErrPairing) {
			t.Fatal("wrong code")
		}
	}
	if _, e = g.Auth.VerifyCode(ctx, c2.ID, c2.Secret); !errors.Is(e, auth.ErrPairing) {
		t.Fatal("attempt budget bypass")
	}
	code3, e := g.Issue(ctx, operations.Local())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = g.Issue(ctx, operations.Local()); !errors.Is(e, auth.ErrRate) {
		t.Fatal("issue rate bypass")
	}
	entries, _, e := g.Store.Audit(ctx, 0, 100)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(entries)
	for _, secret := range []string{token, c.Secret, c2.Secret, code3.Secret} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatal("secret in audit")
		}
	}
	for _, a := range entries {
		o, e := g.Store.Lookup(ctx, a.OperationID)
		if e == nil && (bytes.Contains(o.Result, []byte(token)) || bytes.Contains(o.Result, []byte(c.Secret))) {
			t.Fatal("secret in operation result")
		}
	}
	g.Close()
	g.Store.Close()
	s, e := storage.Open(ctx, path, "", nil, false, storage.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	_, leaf, _, _ := testCertificate(t, false)
	next, e := NewGateway(s, leaf, "fixture")
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	credential, e := next.Auth.Authenticate(ctx, token)
	if e != nil || credential.ID() != id {
		t.Fatal("restart revoked existing phone")
	}
	if _, e = next.Auth.VerifyCode(ctx, code3.ID, code3.Secret); !errors.Is(e, auth.ErrPairing) {
		t.Fatal("code survived restart")
	}
	if next.AgentID != g.AgentID {
		t.Fatal("agent identity changed")
	}
}

func TestHTTPSGuardsAndTypedQueries(t *testing.T) {
	g, _, _ := newTestGateway(t)
	id, token := pairDirect(t, g)
	srv, c, _ := testHTTPS(t, g, false)
	for _, name := range []string{"agent.info", "devices.list", "config.get", "operations.list", "audit.list"} {
		status, b := query(t, c, srv.URL, token, name, map[string]any{})
		if status != 200 {
			t.Fatalf("query %s status %d", name, status)
		}
		if _, e := contracts.Validate(bytes.NewReader(b), contracts.Target{Family: "api", Definition: "QueryResponse"}, contracts.MaxJSONBytes); e != nil {
			t.Fatalf("query %s invalid response: %v", name, e)
		}
	}
	for _, path := range []string{"/api/v1/query", "/api/v1/stream", "/api/v1/transfers/x", "/api/v1/ui/x", "/api/v1/operations/" + newID(t)} {
		status, _ := request(t, c, srv.URL+path, "", map[string]any{})
		if status != 401 {
			t.Fatalf("unauthenticated %s: %d", path, status)
		}
	}
	// Native devices cannot choose identity in a valid request envelope.
	g.limiter = newLimiter()
	status, _ := query(t, c, srv.URL, token, "agent.info", map[string]any{"device_id": id})
	if status != 400 {
		t.Fatal("spoofed identity accepted")
	}
	for _, body := range [][]byte{[]byte(`{"schema_version":"1.0","schema_version":"1.0"}`), []byte(strings.Repeat(" ", contracts.MaxJSONBytes+1)), []byte{0xff}} {
		status, _ = request(t, c, srv.URL+"/api/v1/query", token, body)
		if status != 400 && status != 413 {
			t.Fatalf("invalid body status %d", status)
		}
	}
	for _, header := range []string{"Origin", "Cookie", "Content-Encoding"} {
		r, _ := http.NewRequest("POST", srv.URL+"/api/v1/query", strings.NewReader("{}"))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(header, "untrusted")
		res, e := c.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
		if res.StatusCode < 400 {
			t.Fatal("unsafe header accepted")
		}
	}
	status, _ = query(t, c, srv.URL, token, "snapshot.get", map[string]any{"sections": []string{"cpu"}})
	if status < 400 {
		t.Fatal("future collector advertised as implemented")
	}
	status, _ = request(t, c, srv.URL+"/api/v1/shell", token, map[string]any{"command": "true"})
	if status < 400 {
		t.Fatal("shell endpoint exists")
	}
}

func TestTLSRejectsWrongPinSANExpiryAndOldProtocol(t *testing.T) {
	g, _, _ := newTestGateway(t)
	srv, _, conf := testHTTPS(t, g, false)
	for _, kind := range []string{"pin", "san", "old"} {
		cfg := conf.Clone()
		switch kind {
		case "pin":
			cfg, _ = auth.PinnedTLS(g.Certificate, "127.0.0.1", strings.Repeat("00", 32))
		case "san":
			cfg.ServerName = "wrong.invalid"
		case "old":
			cfg.MinVersion = tls.VersionTLS10
			cfg.MaxVersion = tls.VersionTLS11
		}
		tr := &http.Transport{TLSClientConfig: cfg}
		_, e := (&http.Client{Transport: tr, Timeout: 3 * time.Second}).Get(srv.URL + "/api/v1/query")
		tr.CloseIdleConnections()
		if e == nil {
			t.Fatalf("TLS accepted %s", kind)
		}
	}
	expired, _, cp, kp := testCertificate(t, true)
	_ = expired
	if _, _, e := auth.Certificate(cp, kp); !errors.Is(e, auth.ErrTLS) {
		t.Fatal("expired server certificate accepted")
	}
	g2, _, _ := newTestGateway(t)
	s2, c2, _ := testHTTPS(t, g2, true)
	if _, e := c2.Get(s2.URL + "/api/v1/query"); e == nil {
		t.Fatal("expired pinned certificate accepted")
	}
}

func revokeDirect(t *testing.T, g *Gateway, actor operations.Initiator, id string) storage.Operation {
	t.Helper()
	params, _ := json.Marshal(map[string]string{"device_id": id, "expected_version": "1"})
	r := operations.Request{ID: newID(t), Action: "devices.revoke", Params: params}
	p, e := g.Operations.Prepare(context.Background(), actor, r)
	if e != nil {
		t.Fatal(e)
	}
	r.Plan = p.ID
	o, e := g.Operations.Execute(context.Background(), actor, r)
	if e != nil || o.State != "succeeded" {
		t.Fatalf("revoke failed: %v %s", e, o.State)
	}
	return o
}

func TestRevocationClosesWSSAndPreventsReplayAfterRestore(t *testing.T) {
	g, _, _ := newTestGateway(t)
	id, token := pairDirect(t, g)
	_, keeper := pairDirect(t, g)
	ctx := context.Background()
	backup := filepath.Join(t.TempDir(), "backup")
	svc := operations.Offline(g.Store)
	r := operations.Request{ID: newID(t), Action: "storage.backup"}
	r.Params, _ = json.Marshal(map[string]string{"destination": backup})
	p, e := svc.Prepare(ctx, operations.Local(), r)
	if e != nil {
		t.Fatal(e)
	}
	r.Plan = p.ID
	if o, e := svc.Execute(ctx, operations.Local(), r); e != nil || o.State != "succeeded" {
		t.Fatal("backup failed", e)
	}
	srv, client, conf := testHTTPS(t, g, false)
	tr := &http.Transport{TLSClientConfig: conf}
	defer tr.CloseIdleConnections()
	ws, _, e := websocket.Dial(ctx, "wss"+strings.TrimPrefix(srv.URL, "https")+"/api/v1/stream", &websocket.DialOptions{HTTPClient: &http.Client{Transport: tr}, HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}}, Subprotocols: []string{"serverdeck.v1"}})
	if e != nil {
		t.Fatal("WSS upgrade failed", e)
	}
	defer ws.CloseNow()
	msg := []byte(`{"schema_version":"1.0","request_id":"11111111-1111-4111-8111-111111111111","type":"subscribe","subscriptions":[{"id":"ops","topic":"operations","params":{}}]}`)
	if e = ws.Write(ctx, websocket.MessageText, msg); e != nil {
		t.Fatal(e)
	}
	read, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for i := 0; i < 2; i++ {
		_, b, e := ws.Read(read)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = contracts.Validate(bytes.NewReader(b), contracts.Target{Family: "api", Definition: "WssServerMessage"}, contracts.MaxJSONBytes); e != nil {
			t.Fatal(e)
		}
	}
	cred, e := g.Auth.Authenticate(ctx, keeper)
	if e != nil {
		t.Fatal(e)
	}
	revokeDirect(t, g, operations.Device(cred), id)
	_, _, e = ws.Read(read)
	if e == nil || websocket.CloseStatus(e) != websocket.StatusPolicyViolation {
		t.Fatalf("revoked WSS not closed 1008: %v", e)
	}
	if status, _ := query(t, client, srv.URL, token, "agent.info", map[string]any{}); status != 401 {
		t.Fatal("revoked HTTP token accepted")
	}
	target := filepath.Join(t.TempDir(), "restored")
	r = operations.Request{ID: newID(t), Action: "storage.restore", Params: operations.MaintenanceParams(target, backup)}
	p, e = svc.Prepare(ctx, operations.Local(), r)
	if e != nil {
		t.Fatal(e)
	}
	r.Plan = p.ID
	if o, e := svc.Execute(ctx, operations.Local(), r); e != nil || o.State != "succeeded" {
		t.Fatal("restore failed", e)
	}
	restored, e := storage.Open(ctx, target, "", nil, false, storage.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	h, _ := auth.Digest(token, 32)
	if _, e = restored.Authenticate(ctx, h); !errors.Is(e, storage.ErrUnauthorized) {
		t.Fatal("backup resurrected revoked access")
	}
	h, _ = auth.Digest(keeper, 32)
	if _, e = restored.Authenticate(ctx, h); e != nil {
		t.Fatal("restore lost active credential")
	}
}

func TestConcurrentPairingHasOneWinner(t *testing.T) {
	g, _, _ := newTestGateway(t)
	c, e := g.Issue(context.Background(), operations.Local())
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := contracts.APIPairRequest{SchemaVersion: "1.0", RequestId: newID(t), PairingId: c.ID, PairingCode: c.Secret, DeviceName: "phone"}
			if _, e := g.Pair(context.Background(), r); e == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("pair winners %d", wins)
	}
	devices, e := g.Store.Devices(context.Background())
	if e != nil || len(devices) != 1 {
		t.Fatal("duplicate device")
	}
}

func TestUnixPeerCLIAndPathProtection(t *testing.T) {
	g, _, _ := newTestGateway(t)
	path := filepath.Join(t.TempDir(), "run")
	if e := os.Mkdir(path, 0700); e != nil {
		t.Fatal(e)
	}
	l, dir, e := listenLocal(path)
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	srv := g.adminServer()
	go srv.Serve(l)
	defer srv.Close()
	u, e := user.Current()
	if e != nil {
		t.Fatal(e)
	}
	var cfg config.Config
	cfg.RuntimeUser = u.Username
	cfg.Paths.Runtime = path
	var out bytes.Buffer
	if e = localIssue(cfg, &out); e != nil {
		t.Fatal(e)
	}
	v := decodeMap(t, out.Bytes())
	if len(v["pairing_code"].(string)) != 22 || len(v["fingerprint_sha256"].(string)) != 64 {
		t.Fatal("bootstrap fields")
	}
	if _, e = auth.PrivatePeerDirectory(path, uint32(os.Geteuid()+1)); e == nil {
		t.Fatal("wrong socket owner accepted")
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if os.Symlink(path, alias) != nil {
		t.Fatal("symlink fixture")
	}
	if _, e = auth.PrivatePeerDirectory(alias, uint32(os.Geteuid())); e == nil {
		t.Fatal("symlink accepted")
	}
	key := filepath.Join(t.TempDir(), "key")
	if os.WriteFile(key, []byte("fixture"), 0644) != nil {
		t.Fatal("fixture")
	}
	if _, e = auth.ReadTrusted(key, 100, true); e == nil {
		t.Fatal("public key permissions accepted")
	}
	os.Chmod(key, 0600)
	if _, e = auth.ReadTrusted(key, 100, true); e != nil {
		t.Fatal(e)
	}
}
