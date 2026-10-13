// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"serverdeck.local/agent/internal/auth"
	"serverdeck.local/agent/internal/config"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestNativeProcessHelper(t *testing.T) {
	path := os.Getenv("SERVERDECK_E03_NATIVE_CONFIG")
	if path == "" {
		return
	}
	os.Exit(Run("serverdeck-agent", []string{"serve", "--config", path}, io.Discard, io.Discard))
}

func TestNativeServeCLIShutdownAndPortConflict(t *testing.T) {
	g, state, _ := newTestGateway(t)
	g.Close()
	g.Store.Close()
	base := filepath.Dir(state)
	raw, e := os.ReadFile("../../../Документация ServerDeck/Документация ServerDeck Agent/contracts/examples/config.json")
	if e != nil {
		t.Fatal(e)
	}
	var cfg config.Config
	json.Unmarshal(raw, &cfg)
	u, _ := user.Current()
	cfg.RuntimeUser = u.Username
	cfg.Paths.State = state
	cfg.Paths.Runtime = filepath.Join(base, "run")
	cfg.Paths.Releases = filepath.Join(base, "releases")
	os.Mkdir(cfg.Paths.Runtime, 0700)
	os.Mkdir(cfg.Paths.Releases, 0700)
	_, leaf, cp, kp := testCertificate(t, false)
	cfg.TLS.CertificateFile = filepath.Join(base, "cert.pem")
	cfg.TLS.PrivateKeyFile = filepath.Join(base, "key.pem")
	os.WriteFile(cfg.TLS.CertificateFile, cp, 0600)
	os.WriteFile(cfg.TLS.PrivateKeyFile, kp, 0600)
	reserve, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	cfg.Transport.ListenAddresses = []string{"127.0.0.1", "::1"}
	cfg.Transport.AllowedCIDRs = []string{"127.0.0.0/8", "::1/128"}
	cfg.Transport.Port = port
	cfgPath := filepath.Join(base, "config.json")
	data, _ := json.Marshal(cfg)
	os.WriteFile(cfgPath, data, 0600)
	var output bytes.Buffer
	if e = nativeCommand("serverdeck-agent", cfgPath, &output); e == nil || e.Error() != "PORT_IN_USE" {
		reserve.Close()
		t.Fatal("occupied port not diagnosed", e)
	}
	reserve.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestNativeProcessHelper$")
	cmd.Env = append(os.Environ(), "SERVERDECK_E03_NATIVE_CONFIG="+cfgPath)
	if binary := os.Getenv("SERVERDECK_E03_AGENT_BINARY"); binary != "" {
		cmd = exec.Command(binary, "serve", "--config", cfgPath)
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { cmd.Process.Kill() })
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, e = os.Stat(filepath.Join(cfg.Paths.Runtime, "admin.sock")); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native startup timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
	ctl := func(args []string) int {
		if binary := os.Getenv("SERVERDECK_E03_CTL_BINARY"); binary != "" {
			c := exec.Command(binary, args...)
			c.Stdout = &output
			c.Stderr = io.Discard
			if c.Run() != nil {
				return 1
			}
			return 0
		}
		return Run("serverdeckctl", args, &output, io.Discard)
	}
	if code := ctl([]string{"pairing-issue", "--config", cfgPath}); code != 0 {
		t.Fatal("local CLI pairing failed")
	}
	bootstrap := decodeMap(t, output.Bytes())
	conf, _ := auth.PinnedTLS(leaf, "127.0.0.1", auth.Fingerprint(leaf))
	tr := &http.Transport{TLSClientConfig: conf}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	url := "https://127.0.0.1:" + strconv.Itoa(port)
	status, b := request(t, client, url+"/api/v1/pair", "", map[string]any{"schema_version": "1.0", "request_id": newID(t), "pairing_id": bootstrap["pairing_id"], "pairing_code": bootstrap["pairing_code"], "device_name": "native smoke"})
	if status != 201 {
		t.Fatalf("pair %d", status)
	}
	token := decodeMap(t, b)["token"].(string)
	if status, _ = query(t, client, url, token, "agent.info", map[string]any{}); status != 200 {
		t.Fatalf("info %d", status)
	}
	v6conf, _ := auth.PinnedTLS(leaf, "::1", auth.Fingerprint(leaf))
	v6transport := &http.Transport{TLSClientConfig: v6conf}
	defer v6transport.CloseIdleConnections()
	if status, _ = query(t, &http.Client{Transport: v6transport, Timeout: 3 * time.Second}, "https://[::1]:"+strconv.Itoa(port), token, "agent.info", map[string]any{}); status != 200 {
		t.Fatal("dual-family native port failed")
	}
	q, _ := json.Marshal(map[string]any{"schema_version": "1.0", "request_id": newID(t), "query": "devices.list", "params": map[string]any{}})
	qp := filepath.Join(base, "query.json")
	os.WriteFile(qp, q, 0600)
	output.Reset()
	if code := ctl([]string{"local", "--config", cfgPath, "query", qp}); code != 0 {
		t.Fatal("local query CLI failed")
	}
	q, _ = json.Marshal(map[string]any{"schema_version": "1.0", "request_id": newID(t), "query": "snapshot.get", "params": map[string]any{"view": "summary", "blocks": []string{"memory", "cpu"}}})
	if e = os.WriteFile(qp, q, 0600); e != nil {
		t.Fatal(e)
	}
	output.Reset()
	if code := ctl([]string{"local", "--config", cfgPath, "query", qp}); code != 0 {
		t.Fatal("native snapshot CLI failed")
	}
	if decodeMap(t, output.Bytes())["query"] != "snapshot.get" {
		t.Fatal("native snapshot response")
	}
	if cmd.Process.Signal(syscall.SIGTERM) != nil {
		t.Fatal("stop signal")
	}
	select {
	case e = <-done:
		if e != nil {
			t.Fatal("unclean service shutdown", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown timed out")
	}
	if _, e = os.Lstat(filepath.Join(cfg.Paths.Runtime, "admin.sock")); !os.IsNotExist(e) {
		t.Fatal("socket not removed")
	}
}

func TestIPv6TLSLoopback(t *testing.T) {
	l, e := net.Listen("tcp6", "[::1]:0")
	if e != nil {
		t.Fatal("required WSL IPv6 loopback unavailable", e)
	}
	g, _, _ := newTestGateway(t)
	_, token := pairDirect(t, g)
	cert, leaf, _, _ := testCertificate(t, false)
	srv := httptest.NewUnstartedServer(g)
	srv.Listener.Close()
	srv.Listener = l
	srv.Config = g.HTTPServer(auth.ServerTLS(cert))
	srv.TLS = srv.Config.TLSConfig
	srv.StartTLS()
	defer srv.Close()
	conf, _ := auth.PinnedTLS(leaf, "::1", auth.Fingerprint(leaf))
	tr := &http.Transport{TLSClientConfig: conf}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	if status, _ := query(t, client, srv.URL, token, "agent.info", map[string]any{}); status != 200 {
		t.Fatal("IPv6 query failed")
	}
}
