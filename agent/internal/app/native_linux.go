// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"serverdeck.local/agent/internal/auth"
	"serverdeck.local/agent/internal/config"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/metrics"
	"serverdeck.local/agent/internal/storage"
)

func nativeCommand(name, path string, out io.Writer) error {
	cfg, e := readNativeConfig(path)
	if e != nil {
		return storage.ErrInvalid
	}
	if name == "serverdeckctl" {
		return localIssue(cfg, out)
	}
	u, e := user.Current()
	if e != nil || u.Username != cfg.RuntimeUser {
		return storage.ErrSafety
	}
	certPEM, e := auth.ReadTrusted(cfg.TLS.CertificateFile, 65536, false)
	if e != nil {
		return e
	}
	keyPEM, e := auth.ReadTrusted(cfg.TLS.PrivateKeyFile, 65536, true)
	if e != nil {
		return e
	}
	cert, leaf, e := auth.Certificate(certPEM, keyPEM)
	if e != nil {
		return e
	}
	for _, s := range cfg.Transport.ListenAddresses {
		ip := netip.MustParseAddr(s)
		if !ip.IsUnspecified() && leaf.VerifyHostname(s) != nil {
			return auth.ErrTLS
		}
	}
	seed, _ := json.Marshal(cfg.RuntimeInitial)
	store, e := storage.Open(context.Background(), cfg.Paths.State, string(cfg.InstallationID), seed, false, storage.DefaultLimits())
	if e != nil {
		return e
	}
	defer store.Close()
	g, e := NewGateway(store, leaf, cfg.RuntimeUser)
	if e != nil {
		return e
	}
	defer g.Close()
	g.Port = cfg.Transport.Port
	local, dir, e := listenLocal(cfg.Paths.Runtime)
	if e != nil {
		return e
	}
	defer dir.Close()
	defer local.Close()
	admin := g.adminServer()
	listeners := []net.Listener{}
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()
	for _, s := range cfg.Transport.ListenAddresses {
		network := "tcp6"
		if netip.MustParseAddr(s).Is4() {
			network = "tcp4"
		}
		l, e := net.Listen(network, net.JoinHostPort(s, strconv.Itoa(cfg.Transport.Port)))
		if e != nil {
			if errors.Is(e, syscall.EADDRINUSE) {
				return errors.New("PORT_IN_USE")
			}
			return storage.ErrSafety
		}
		listeners = append(listeners, l)
	}
	servers := []*http.Server{admin}
	collector, e := metrics.NewLinux()
	if e != nil {
		g.MetricsFailure = "SOURCE_UNAVAILABLE"
	} else {
		g.Metrics = metrics.New(g.RunID, collector.BootID(), collector)
	}
	results := make(chan error, len(listeners)+1)
	go func() { results <- admin.Serve(local) }()
	for _, l := range listeners {
		srv := g.HTTPServer(auth.ServerTLS(cert))
		srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			ip, parse := netip.ParseAddr(host)
			allowed := err == nil && parse == nil && cfg.Transport.Mode == "external"
			if err == nil && parse == nil {
				for _, cidr := range cfg.Transport.AllowedCIDRs {
					if netip.MustParsePrefix(cidr).Contains(ip.Unmap()) {
						allowed = true
						break
					}
				}
			}
			if !allowed {
				g.fail(w, "", storage.ErrPolicy, "")
				return
			}
			g.ServeHTTP(w, r)
		})
		servers = append(servers, srv)
		go func() { results <- srv.Serve(tls.NewListener(l, srv.TLSConfig)) }()
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-results:
	}
	g.Close()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(shutdown)
		_ = s.Close()
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return storage.ErrSafety
	}
	return nil
}

func (g *Gateway) adminServer() *http.Server {
	return &http.Server{Handler: http.HandlerFunc(g.localHandler), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 11904, ErrorLog: log.New(io.Discard, "", 0), ConnContext: func(ctx context.Context, c net.Conn) context.Context {
		u, ok := c.(*net.UnixConn)
		if !ok {
			c.Close()
			return ctx
		}
		uid, e := auth.PeerUID(u)
		if e != nil || uid != 0 && uid != uint32(os.Geteuid()) {
			c.Close()
			return ctx
		}
		g.mu.Lock()
		full := len(g.connections) >= 64
		if !full {
			g.connections[c] = &connectionInfo{conn: c}
		}
		g.mu.Unlock()
		if full {
			c.Close()
			return ctx
		}
		return context.WithValue(ctx, localPeerKey{}, uid)
	}, ConnState: func(c net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			g.closeConnection(c)
		}
	}}
}

func listenLocal(path string) (*net.UnixListener, *os.File, error) {
	dir, e := storage.PrivateDirectory(path, false)
	if e != nil {
		return nil, nil, e
	}
	fail := func() (*net.UnixListener, *os.File, error) { dir.Close(); return nil, nil, storage.ErrSafety }
	socket := "/proc/self/fd/" + strconv.FormatUint(uint64(dir.Fd()), 10) + "/admin.sock"
	if info, e := os.Lstat(socket); e == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 || st.Uid != uint32(os.Geteuid()) {
			return fail()
		}
		c, err := net.DialTimeout("unix", socket, 100*time.Millisecond)
		if err == nil {
			c.Close()
			return fail()
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return fail()
		}
		again, err := os.Lstat(socket)
		if err != nil || !os.SameFile(info, again) || os.Remove(socket) != nil {
			return fail()
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return fail()
	}
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if e != nil {
		return fail()
	}
	if os.Chmod(socket, 0600) != nil {
		l.Close()
		return fail()
	}
	return l, dir, nil
}

func localIssue(cfg config.Config, out io.Writer) error {
	return localRequest(cfg, "pairing", []byte("{}"), out)
}
func nativeLocalCommand(path, action, input string, out io.Writer) error {
	cfg, e := readNativeConfig(path)
	if e != nil {
		return storage.ErrInvalid
	}
	body, e := auth.ReadTrusted(input, contracts.MaxJSONBytes, false)
	if e != nil {
		return e
	}
	var definition, route string
	switch action {
	case "query":
		definition = "QueryRequest"
		route = "query"
	case "prepare":
		definition = "PrepareRequest"
		route = "prepare"
	case "execute":
		definition = "OperationRequest"
		route = "operations"
	default:
		return storage.ErrInvalid
	}
	if _, e = contracts.Validate(bytes.NewReader(body), contracts.Target{Family: "api", Definition: definition}, contracts.MaxJSONBytes); e != nil {
		return storage.ErrInvalid
	}
	return localRequest(cfg, route, body, out)
}
func localRequest(cfg config.Config, route string, body []byte, out io.Writer) error {
	expected, e := user.Lookup(cfg.RuntimeUser)
	if e != nil {
		return storage.ErrSafety
	}
	uid, e := strconv.ParseUint(expected.Uid, 10, 32)
	if e != nil {
		return storage.ErrSafety
	}
	// Verify every ancestor and the final private directory against the expected
	// service UID; the connected peer is checked independently with SO_PEERCRED.
	dir, e := auth.PrivatePeerDirectory(cfg.Paths.Runtime, uint32(uid))
	if e != nil {
		return e
	}
	defer dir.Close()
	path := "/proc/self/fd/" + strconv.FormatUint(uint64(dir.Fd()), 10) + "/admin.sock"
	info, e := os.Lstat(path)
	if e != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		return storage.ErrSafety
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(uid) {
		return storage.ErrSafety
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		c, e := d.DialContext(ctx, "unix", path)
		if e != nil {
			return nil, storage.ErrSafety
		}
		u, ok := c.(*net.UnixConn)
		if !ok {
			c.Close()
			return nil, storage.ErrSafety
		}
		peer, e := auth.PeerUID(u)
		if e != nil || peer != uint32(uid) {
			c.Close()
			return nil, storage.ErrUnauthorized
		}
		return c, nil
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest("POST", "http://local/local/v1/"+route, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res, e := client.Do(req)
	if e != nil {
		return storage.ErrSafety
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, contracts.MaxJSONBytes+1))
	if e != nil || len(b) > contracts.MaxJSONBytes || res.StatusCode != 200 && res.StatusCode != 202 || !json.Valid(b) {
		return storage.ErrSafety
	}
	_, e = out.Write(append(b, '\n'))
	return e
}

func readNativeConfig(path string) (cfg config.Config, err error) {
	owner := uint32(os.Geteuid())
	if os.Geteuid() == 0 {
		info, e := os.Lstat(path)
		if e != nil {
			return cfg, storage.ErrSafety
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return cfg, storage.ErrSafety
		}
		owner = st.Uid
	}
	b, e := auth.ReadTrustedForOwner(path, contracts.MaxJSONBytes, false, owner)
	if e != nil {
		return cfg, e
	}
	cfg, e = config.Load(bytes.NewReader(b))
	if e != nil {
		return cfg, storage.ErrInvalid
	}
	u, e := user.Lookup(cfg.RuntimeUser)
	if e != nil {
		return cfg, storage.ErrSafety
	}
	uid, e := strconv.ParseUint(u.Uid, 10, 32)
	if e != nil || owner != 0 && owner != uint32(uid) {
		return cfg, storage.ErrSafety
	}
	return cfg, nil
}
