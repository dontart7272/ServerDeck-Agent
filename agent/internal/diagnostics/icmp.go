// SPDX-License-Identifier: Apache-2.0
package diagnostics

import (
	"context"
	"errors"
	"math"
	"net"
	"net/netip"
	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/storage"
	"sort"
	"sync"
	"time"
)

var ErrRate = errors.New("RATE_LIMITED")
var ErrPermission = errors.New("PERMISSION_DENIED")
var ErrSource = errors.New("SOURCE_UNAVAILABLE")

type Config struct {
	Target     *string
	Version    string
	Background bool
}
type Result struct {
	Target     *string              `json:"target"`
	Version    string               `json:"target_version"`
	Background bool                 `json:"background_enabled"`
	ObservedAt *contracts.Timestamp `json:"observed_at"`
	ResolvedIP *string              `json:"resolved_ip"`
	Sent       int                  `json:"packets_sent"`
	Received   int                  `json:"packets_received"`
	Latency    *float64             `json:"latency_ms"`
	Loss       *float64             `json:"loss_percent"`
	Status     string               `json:"status"`
}
type Stats struct {
	Sent, Received int
	Latency        *float64
}
type Manager struct {
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closing   bool
	lastAt    time.Time
	mu        sync.Mutex
	busy      bool
	lastStart time.Time
	last      Result
	runner    func(context.Context, netip.Addr) (Stats, error)
	resolve   func(context.Context, string) ([]netip.Addr, error)
	now       func() time.Time
}

func New() *Manager {
	resolver := &net.Resolver{PreferGo: true, StrictErrors: true}
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{ctx: ctx, cancel: cancel, runner: nativePing, resolve: func(ctx context.Context, target string) ([]netip.Addr, error) {
		return resolver.LookupNetIP(ctx, "ip", target)
	}, now: time.Now}
}
func initial(c Config) Result {
	status := "source_error"
	if c.Target == nil {
		status = "not_configured"
	}
	var target *string
	if c.Target != nil {
		copy := *c.Target
		target = &copy
	}
	return Result{Target: target, Version: c.Version, Background: c.Background, Status: status}
}
func (m *Manager) Last(c Config) Result {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.last.Version != c.Version {
		return initial(c)
	}
	r := m.last
	if r.ObservedAt != nil && m.now().Sub(m.lastAt) >= 180*time.Second {
		r.Status = "stale"
	}
	return r
}
func (m *Manager) Run(ctx context.Context, c Config) (Result, error) {
	result := initial(c)
	if c.Target == nil {
		return result, storage.ErrInvalid
	}
	if !contracts.ValidICMPTarget(*c.Target) {
		return result, storage.ErrInvalid
	}
	m.mu.Lock()
	if m.closing {
		m.mu.Unlock()
		return result, ErrSource
	}
	if m.busy {
		m.mu.Unlock()
		return result, storage.ErrBusy
	}
	now := m.now()
	if !m.lastStart.IsZero() && now.Sub(m.lastStart) < 15*time.Second {
		m.mu.Unlock()
		return result, ErrRate
	}
	m.wg.Add(1)
	m.busy = true
	m.lastStart = now
	m.mu.Unlock()
	defer func() { m.mu.Lock(); m.busy = false; m.mu.Unlock(); m.wg.Done() }()
	caller := ctx
	ctx, cancel := context.WithTimeout(m.ctx, 10*time.Second)
	stop := context.AfterFunc(caller, cancel)
	defer stop()
	defer cancel()
	ip, err := netip.ParseAddr(*c.Target)
	if err != nil {
		var addresses []netip.Addr
		addresses, err = m.resolve(ctx, *c.Target)
		if len(addresses) > 128 {
			err = ErrSource
		}
		if err == nil {
			sort.Slice(addresses, func(i, j int) bool {
				if addresses[i].Is4() != addresses[j].Is4() {
					return addresses[i].Is4()
				}
				return addresses[i].Less(addresses[j])
			})
			found := false
			for _, candidate := range addresses {
				if validIP(candidate) {
					ip = candidate
					found = true
					break
				}
			}
			if !found {
				err = ErrSource
			}
		}
	}
	if err == nil && validIP(ip) {
		address := ip.Unmap().String()
		result.ResolvedIP = &address
		stats, e := m.runner(ctx, ip.Unmap())
		err = e
		if err == nil && (stats.Sent < 1 || stats.Sent > 5 || stats.Received < 0 || stats.Received > stats.Sent || stats.Latency != nil && (math.IsNaN(*stats.Latency) || math.IsInf(*stats.Latency, 0) || *stats.Latency < 0 || *stats.Latency > 10000)) {
			stats = Stats{}
			err = ErrSource
		}
		result.Sent, result.Received, result.Latency = stats.Sent, stats.Received, stats.Latency
		if err == nil && stats.Sent > 0 {
			loss := 100 * float64(stats.Sent-stats.Received) / float64(stats.Sent)
			result.Loss = &loss
			result.Status = "available"
		}
	} else if err == nil {
		err = ErrSource
	}
	if err != nil {
		result.Status = "source_error"
		if errors.Is(err, ErrPermission) {
			result.Status = "permission_denied"
		}
	}
	at := contracts.Timestamp(m.now().UTC())
	result.ObservedAt = &at
	m.mu.Lock()
	m.lastAt = m.now()
	m.last = result
	m.mu.Unlock()
	return result, nil
}
func validIP(ip netip.Addr) bool {
	return ip.IsValid() && ip.Zone() == "" && !ip.IsUnspecified() && !ip.IsMulticast()
}

func (m *Manager) Close() { m.mu.Lock(); m.closing = true; m.cancel(); m.mu.Unlock(); m.wg.Wait() }
