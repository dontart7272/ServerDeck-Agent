//go:build linux

// SPDX-License-Identifier: Apache-2.0
package diagnostics

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"serverdeck.local/agent/internal/storage"
	"strings"
	"testing"
	"time"
)

func TestPingParserBoundaries(t *testing.T) {
	valid := "5 packets transmitted, 5 received, 0% packet loss, time 4000ms\nrtt min/avg/max/mdev = 0.01/0.02/0.03/0.01 ms\n"
	for _, raw := range []string{"", strings.Repeat("x", 65537), "6 packets transmitted, 0 received, 100% packet loss\n", "1 packets transmitted, 2 received, loss\n", valid + valid, "5 packets transmitted, 5 received, loss\n"} {
		if _, e := parsePing(raw); e == nil {
			t.Fatal("invalid accepted")
		}
	}
	s, e := parsePing(valid)
	if e != nil || s.Sent != 5 || s.Received != 5 || *s.Latency != 0.02 {
		t.Fatal(s, e)
	}
	s, e = parsePing("5 packets transmitted, 0 received, 100% packet loss, time 4000ms\n")
	if e != nil || s.Latency != nil {
		t.Fatal("loss", s, e)
	}
}
func TestManagerBudgetIdentityDNSAndFailure(t *testing.T) {
	m := New()
	defer m.Close()
	now := time.Now()
	m.now = func() time.Time { return now }
	calls := 0
	m.resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	m.runner = func(ctx context.Context, ip netip.Addr) (Stats, error) {
		calls++
		if ip.String() != "127.0.0.1" {
			t.Fatal("unexpected DNS selection")
		}
		return Stats{Sent: 5}, nil
	}
	target := "localhost"
	c := Config{Target: &target, Version: "v1"}
	r, e := m.Run(context.Background(), c)
	if e != nil || r.Status != "available" || *r.Loss != 100 || calls != 1 {
		t.Fatal(r, e)
	}
	if _, e = m.Run(context.Background(), c); !errors.Is(e, ErrRate) {
		t.Fatal("rate", e)
	}
	now = now.Add(180 * time.Second)
	if m.Last(c).Status != "stale" {
		t.Fatal("stale")
	}
	c.Version = "v2"
	if m.Last(c).ObservedAt != nil {
		t.Fatal("mixed identity")
	}
	m.runner = func(context.Context, netip.Addr) (Stats, error) { return Stats{}, ErrPermission }
	r, e = m.Run(context.Background(), c)
	if e != nil || r.Status != "permission_denied" {
		t.Fatal(r, e)
	}
	for _, s := range []string{"-c 500", "localhost;touch /tmp/no", "https://host", "a\nxxx", "::", "224.0.0.1"} {
		c.Target = &s
		if _, e = m.Run(context.Background(), c); !errors.Is(e, storage.ErrInvalid) {
			t.Fatal("unsafe target", s, e)
		}
	}
}
func TestManagerConcurrentClose(t *testing.T) {
	m := New()
	target := "127.0.0.1"
	c := Config{Target: &target, Version: "v"}
	entered := make(chan struct{})
	done := make(chan struct{})
	m.runner = func(ctx context.Context, _ netip.Addr) (Stats, error) {
		close(entered)
		<-ctx.Done()
		return Stats{}, ErrSource
	}
	go func() { m.Run(context.Background(), c); close(done) }()
	<-entered
	if _, e := m.Run(context.Background(), c); !errors.Is(e, storage.ErrBusy) {
		t.Fatal(e)
	}
	m.Close()
	<-done
	if _, e := m.Run(context.Background(), c); !errors.Is(e, ErrSource) {
		t.Fatal("closed", e)
	}
}
func TestNativeLoopbackIPv4IPv6(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "::1"} {
		t.Run(address, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			s, e := nativePing(ctx, netip.MustParseAddr(address))
			if e != nil || s.Sent != 5 || s.Received != 5 || s.Latency == nil {
				t.Fatalf("native loopback %+v %v", s, e)
			}
		})
	}
}
func FuzzPingSummary(f *testing.F) {
	f.Add("5 packets transmitted, 0 received, 100% packet loss\n")
	f.Fuzz(func(t *testing.T, s string) {
		v, e := parsePing(s)
		if e == nil && (v.Sent < 1 || v.Sent > 5 || v.Received < 0 || v.Received > v.Sent) {
			t.Fatal(v)
		}
	})
}

func TestDeadlineDNSFailureAndNativeCancellation(t *testing.T) {
	m := New()
	defer m.Close()
	target := "localhost"
	config := Config{Target: &target, Version: "v"}
	m.resolve = func(ctx context.Context, _ string) ([]netip.Addr, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 10*time.Second {
			t.Fatal("DNS outside budget")
		}
		return nil, ErrSource
	}
	r, e := m.Run(context.Background(), config)
	if e != nil || r.Status != "source_error" || r.ResolvedIP != nil {
		t.Fatal(r, e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, e = nativePing(ctx, netip.MustParseAddr("127.0.0.1")); e == nil {
		t.Fatal("cancelled probe successful")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("child cleanup unbounded")
	}
	if trusted("/tmp") || trusted("/nonexistent/serverdeck-ping") {
		t.Fatal("untrusted executable accepted")
	}
}

func TestIsolatedPingPermissionDenied(t *testing.T) {
	if os.Getenv("SD_E07_PING_DENIED") != "1" {
		t.Skip("explicit capability-drop namespace procedure")
	}
	ns, e := os.Readlink("/proc/self/ns/pid")
	outer := os.Getenv("SD_E07_OUTER_PIDNS")
	if e != nil || outer == "" || outer == ns || os.Getpid() != 1 {
		t.Fatal("not isolated")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, e = nativePing(ctx, netip.MustParseAddr("127.0.0.1")); !errors.Is(e, ErrPermission) {
		t.Fatal("expected real permission refusal", e)
	}
}
