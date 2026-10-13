// SPDX-License-Identifier: Apache-2.0
package app

import (
	"strings"
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	at     time.Time
	rate   float64
	burst  float64
}
type limiter struct {
	mu      sync.Mutex
	buckets map[string]bucket
	now     func() time.Time
}

func newLimiter() *limiter { return &limiter{buckets: map[string]bucket{}, now: time.Now} }
func (l *limiter) allow(key string, rate, burst float64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for k, b := range l.buckets {
		if now.Sub(b.at) > 10*time.Minute {
			delete(l.buckets, k)
		}
	}
	b, ok := l.buckets[key]
	if !ok {
		// Pairing and unauthenticated requests share at most 1024 IP identities.
		ips := map[string]bool{}
		for k := range l.buckets {
			if strings.HasPrefix(k, "unauth:") {
				ips[strings.TrimPrefix(k, "unauth:")] = true
			}
			if strings.HasPrefix(k, "pair:") {
				ips[strings.TrimPrefix(k, "pair:")] = true
			}
		}
		ip := strings.TrimPrefix(strings.TrimPrefix(key, "unauth:"), "pair:")
		if ((strings.HasPrefix(key, "unauth:") || strings.HasPrefix(key, "pair:")) && !ips[ip] && len(ips) >= 1024) || len(l.buckets) >= 2113 {
			return false
		}
		b = bucket{burst, now, rate, burst}
	}
	elapsed := now.Sub(b.at).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	b.tokens += elapsed * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.at = now
	allowed := b.tokens >= 1
	if allowed {
		b.tokens--
	}
	l.buckets[key] = b
	return allowed
}

// blocked inspects an exhausted unauthenticated bucket before token verification.
func (l *limiter) blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		return false
	}
	return b.tokens+l.now().Sub(b.at).Seconds()*b.rate < 1
}
