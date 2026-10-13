// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"serverdeck.local/agent/internal/storage"
)

var ErrPairing = errors.New("PAIRING_REJECTED")
var ErrRate = errors.New("RATE_LIMITED")

type issued struct {
	hash     [32]byte
	until    time.Time
	attempts int
}
type Code struct {
	ID, Secret string
	Expires    time.Time
	Hash       [32]byte
}
type Manager struct {
	Store    *storage.Store
	mu       sync.Mutex
	codes    map[string]issued
	issues   []time.Time
	sessions map[string]map[*Session]bool
	observed map[string]time.Time
	now      func() time.Time
}
type Session struct {
	Credential storage.Credential
	Context    context.Context
	cancel     context.CancelFunc
	manager    *Manager
	once       sync.Once
}

func New(s *storage.Store) *Manager {
	return &Manager{Store: s, codes: map[string]issued{}, sessions: map[string]map[*Session]bool{}, observed: map[string]time.Time{}, now: time.Now}
}
func RandomSecret(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, e := rand.Read(b); e != nil {
		return "", storage.ErrSafety
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func Digest(secret string, size int) ([32]byte, error) {
	b, e := base64.RawURLEncoding.Strict().DecodeString(secret)
	if e != nil || len(b) != size || base64.RawURLEncoding.EncodeToString(b) != secret {
		return [32]byte{}, storage.ErrUnauthorized
	}
	return sha256.Sum256(b), nil
}
func (m *Manager) NewCode() (Code, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for id, c := range m.codes {
		if !now.Before(c.until) {
			delete(m.codes, id)
		}
	}
	recent := m.issues[:0]
	for _, v := range m.issues {
		if now.Sub(v) < time.Minute {
			recent = append(recent, v)
		}
	}
	m.issues = recent
	if len(m.issues) >= 3 {
		return Code{}, ErrRate
	}
	if len(m.codes) >= 3 {
		return Code{}, storage.ErrQuota
	}
	id, e := storage.RandomID()
	if e != nil {
		return Code{}, e
	}
	secret, e := RandomSecret(16)
	if e != nil {
		return Code{}, e
	}
	hash, e := Digest(secret, 16)
	if e != nil {
		return Code{}, e
	}
	// Reserve the bounded slot before durable creation. Failed issuance cannot
	// leak an active secret; stale reservations expire monotonically.
	c := Code{id, secret, now.Add(300 * time.Second), hash}
	m.codes[id] = issued{hash, c.Expires, 0}
	m.issues = append(m.issues, now)
	return c, nil
}
func (m *Manager) DiscardCode(id string) { m.mu.Lock(); delete(m.codes, id); m.mu.Unlock() }
func (m *Manager) VerifyCode(ctx context.Context, id, secret string) (storage.PairProof, error) {
	hash, e := Digest(secret, 16)
	m.mu.Lock()
	c, exists := m.codes[id]
	valid := exists && m.now().Before(c.until) && m.now().UTC().Before(c.until.UTC()) && c.attempts < 5 && e == nil && subtle.ConstantTimeCompare(hash[:], c.hash[:]) == 1
	if !valid && exists {
		c.attempts++
		if c.attempts >= 5 || !m.now().Before(c.until) {
			delete(m.codes, id)
		} else {
			m.codes[id] = c
		}
	}
	m.mu.Unlock()
	if !valid {
		if exists {
			_ = m.Store.FailedPairAttempt(ctx, id)
		}
		return storage.PairProof{}, ErrPairing
	}
	proof, e := m.Store.CheckPairCode(ctx, id, hash)
	if e != nil {
		return storage.PairProof{}, ErrPairing
	}
	return proof, nil
}
func (m *Manager) Authenticate(ctx context.Context, token string) (storage.Credential, error) {
	hash, e := Digest(token, 32)
	if e != nil {
		return storage.Credential{}, storage.ErrUnauthorized
	}
	c, e := m.Store.Authenticate(ctx, hash)
	if e != nil {
		return c, e
	}
	m.mu.Lock()
	now := m.now()
	previous, seen := m.observed[c.ID()]
	observe := !seen || now.Sub(previous) >= time.Minute
	if observe {
		if !seen && len(m.observed) >= 32 {
			for id := range m.observed {
				delete(m.observed, id)
				break
			}
		}
		m.observed[c.ID()] = now
	}
	m.mu.Unlock()
	if observe {
		_ = m.Store.ObserveDevice(ctx, c.ID(), now.UTC().UnixMicro())
	}
	return c, nil
}
func (m *Manager) Session(c storage.Credential) (*Session, error) {
	if c.ID() == "" {
		return nil, storage.ErrUnauthorized
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	total := 0
	for _, v := range m.sessions {
		total += len(v)
	}
	set := m.sessions[c.ID()]
	if len(set) >= 8 || total >= 64 {
		return nil, storage.ErrQuota
	}
	if set == nil {
		set = map[*Session]bool{}
		m.sessions[c.ID()] = set
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Session{Credential: c, Context: ctx, cancel: cancel, manager: m}
	set[s] = true
	return s, nil
}
func (s *Session) Close() {
	s.once.Do(func() {
		s.cancel()
		m := s.manager
		m.mu.Lock()
		delete(m.sessions[s.Credential.ID()], s)
		if len(m.sessions[s.Credential.ID()]) == 0 {
			delete(m.sessions, s.Credential.ID())
		}
		m.mu.Unlock()
	})
}
func (s *Session) Check(ctx context.Context) error {
	if s.Context.Err() != nil {
		return storage.ErrUnauthorized
	}
	return s.manager.Store.CheckCredential(ctx, s.Credential)
}
func (m *Manager) Revoked(id string) {
	m.mu.Lock()
	var set []*Session
	for s := range m.sessions[id] {
		set = append(set, s)
	}
	m.mu.Unlock()
	for _, s := range set {
		s.Close()
	}
}
func (m *Manager) Close() {
	m.mu.Lock()
	var sessions []*Session
	for _, set := range m.sessions {
		for s := range set {
			sessions = append(sessions, s)
		}
	}
	m.codes = map[string]issued{}
	m.mu.Unlock()
	for _, s := range sessions {
		s.Close()
	}
}
