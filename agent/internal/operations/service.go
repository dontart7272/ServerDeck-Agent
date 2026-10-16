// SPDX-License-Identifier: Apache-2.0
package operations

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"serverdeck.local/agent/internal/storage"
)

var ErrPlan = errors.New("PLAN_EXPIRED")
var ErrAction = errors.New("UNSUPPORTED_ACTION")
var ErrCancel = errors.New("CANCELLATION_UNAVAILABLE")

type Initiator struct {
	id         string
	credential *storage.Credential
}

// No device ID can be supplied by CLI arguments. E03 must create a trusted
// transport adapter; shared UID/root remains trusted by the host threat model.
func Local() Initiator { return Initiator{id: "local:" + strconv.Itoa(os.Geteuid())} }
func Device(c storage.Credential) Initiator {
	if !storage.ValidID(c.ID()) {
		return Initiator{}
	}
	return Initiator{id: "device:" + c.ID(), credential: &c}
}
func LocalPeer(uid uint32) Initiator {
	if uid != 0 && uid != uint32(os.Geteuid()) {
		return Initiator{}
	}
	return Initiator{id: "local:" + strconv.FormatUint(uint64(uid), 10)}
}
func PairingInitiator() Initiator         { return Initiator{id: "system:pairing"} }
func FileMaintenanceInitiator() Initiator { return Initiator{id: "system:files"} }
func (a Initiator) ID() string            { return a.id }

type Request struct {
	ID, Action, Expected, Plan string
	Actor                      string
	Params                     []byte
	Credential                 *storage.Credential
}
type Plan struct {
	ID      string
	Expires time.Time
	Objects []string
}
type Outcome struct {
	State, Effect, Code string
	Result              []byte
}

// Implementations are compiled application adapters, never client callbacks.
// Check must read the actual object. For external resources it must use an
// atomic version-aware primitive at Effect, not assume an internal mutex helps.
type Handler interface {
	Validate([]byte) error
	Keys(Request) ([]string, error)
	Check(context.Context, Request) error
	Effect(context.Context, Request) Outcome
}
type savedPlan struct {
	actor   string
	request Request
	mac     []byte
	plan    Plan
}
type job struct {
	actor   string
	keys    []string
	ready   chan struct{}
	granted bool
}
type execution struct {
	actor string
	phase atomic.Int32
}
type Service struct {
	store       *storage.Store
	handlers    map[string]Handler
	mu          sync.Mutex
	plans       map[string]savedPlan
	pending     map[string]storage.Operation
	running     map[string]*execution
	queue       []*job
	active      int
	held        map[string]bool
	lastActor   string
	maintenance bool
	guard       func(context.Context, Initiator, Request) error
	limit       int
}

func New(s *storage.Store, handlers map[string]Handler) *Service {
	h := make(map[string]Handler, len(handlers))
	for k, v := range handlers {
		h[k] = v
	}
	return &Service{store: s, handlers: h, plans: map[string]savedPlan{}, pending: map[string]storage.Operation{}, running: map[string]*execution{}, held: map[string]bool{}, limit: 4}
}
func NewAuthorized(s *storage.Store, h map[string]Handler, guard func(context.Context, Initiator, Request) error) (*Service, error) {
	p, e := s.Policy(context.Background())
	if e != nil {
		return nil, e
	}
	v := New(s, h)
	v.guard = guard
	v.limit = p.MaxChanges
	return v, nil
}
func (s *Service) authorized(ctx context.Context, a Initiator, r Request) error {
	if s.guard != nil {
		return s.guard(ctx, a, r)
	}
	return nil
}
func (a Initiator) Credential() *storage.Credential { return a.credential }
func (s *Service) fingerprint(a Initiator, r Request) ([]byte, error) {
	if !storage.ValidID(r.ID) || a.id == "" {
		return nil, storage.ErrInvalid
	}
	return s.store.Fingerprint(a.id, r.Action, r.Params, r.Expected)
}
func (s *Service) reject(ctx context.Context, a Initiator, r Request, e error) error {
	code := "INVALID_REQUEST"
	switch e.Error() {
	case "PROTECTED_OBJECT", "OBJECT_CHANGED", "NOT_FOUND", "PERMISSION_DENIED":
		code = e.Error()
	}
	for _, x := range []error{storage.ErrVersion, storage.ErrConflict, storage.ErrBusy, ErrPlan, ErrAction, storage.ErrSafety} {
		if errors.Is(e, x) {
			code = x.Error()
		}
	}
	if err := s.store.Rejection(ctx, storage.Operation{ID: r.ID, Actor: a.id, Action: r.Action}, code); err != nil {
		return storage.ErrAudit
	}
	return e
}
func (s *Service) Prepare(ctx context.Context, a Initiator, r Request) (Plan, error) {
	r.Actor = a.ID()
	r.Credential = a.credential
	if e := s.authorized(ctx, a, r); e != nil {
		return Plan{}, e
	}
	mac, e := s.fingerprint(a, r)
	if e != nil {
		return Plan{}, e
	}
	h := s.handlers[r.Action]
	if h == nil {
		return Plan{}, s.reject(ctx, a, r, ErrAction)
	}
	if e = h.Validate(r.Params); e != nil {
		return Plan{}, s.reject(ctx, a, r, storage.ErrInvalid)
	}
	keys, e := h.Keys(r)
	if e != nil {
		return Plan{}, s.reject(ctx, a, r, e)
	}
	keys, e = validKeys(keys)
	if e != nil {
		return Plan{}, s.reject(ctx, a, r, e)
	}
	if e = h.Check(ctx, r); e != nil {
		return Plan{}, s.reject(ctx, a, r, e)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.maintenance {
		return Plan{}, storage.ErrBusy
	}
	now := time.Now()
	count := 0
	for k, p := range s.plans {
		if !now.Before(p.plan.Expires) {
			delete(s.plans, k)
		} else if p.actor == a.id {
			count++
		}
	}
	if len(s.plans) >= 128 || count >= 8 {
		return Plan{}, storage.ErrQuota
	}
	token := make([]byte, 16)
	if _, e = rand.Read(token); e != nil {
		return Plan{}, storage.ErrSafety
	}
	p := Plan{base64.RawURLEncoding.EncodeToString(token), now.Add(120 * time.Second), keys}
	r.Params = append([]byte(nil), r.Params...)
	s.plans[p.ID] = savedPlan{a.id, r, mac, p}
	return p, nil
}
func validKeys(keys []string) ([]string, error) {
	keys = append([]string(nil), keys...)
	sort.Strings(keys)
	if len(keys) < 1 || len(keys) > 16 {
		return nil, storage.ErrInvalid
	}
	for i, k := range keys {
		if !storage.SafeLabel(k) || (i > 0 && keys[i-1] == k) {
			return nil, storage.ErrInvalid
		}
	}
	return keys, nil
}
func (s *Service) Get(ctx context.Context, id string) (storage.Operation, error) {
	s.mu.Lock()
	o, ok := s.pending[id]
	s.mu.Unlock()
	if ok {
		o.Result = append([]byte(nil), o.Result...)
		o.MAC = append([]byte(nil), o.MAC...)
		return o, nil
	}
	return s.store.Lookup(ctx, id)
}
func (s *Service) Execute(ctx context.Context, a Initiator, r Request) (storage.Operation, error) {
	r.Actor = a.ID()
	r.Credential = a.credential
	if e := s.authorized(ctx, a, r); e != nil {
		return storage.Operation{}, e
	}
	mac, e := s.fingerprint(a, r)
	if e != nil {
		return storage.Operation{}, e
	}
	if prior, e := s.Get(ctx, r.ID); e == nil {
		if !storage.Matches(prior, a.id, r.Action, mac) {
			return storage.Operation{}, s.reject(ctx, a, r, storage.ErrConflict)
		}
		return prior, nil
	} else if !errors.Is(e, storage.ErrNotFound) {
		return storage.Operation{}, e
	}
	h := s.handlers[r.Action]
	if h == nil {
		return storage.Operation{}, s.reject(ctx, a, r, ErrAction)
	}
	if e = h.Validate(r.Params); e != nil {
		return storage.Operation{}, s.reject(ctx, a, r, storage.ErrInvalid)
	}
	s.mu.Lock()
	p, ok := s.plans[r.Plan]
	maint := s.maintenance
	s.mu.Unlock()
	if maint {
		return storage.Operation{}, storage.ErrBusy
	}
	if !ok || p.actor != a.id || p.request.ID != r.ID || !storage.Matches(storage.Operation{Actor: p.actor, Action: p.request.Action, MAC: p.mac}, a.id, r.Action, mac) || !time.Now().Before(p.plan.Expires) {
		return storage.Operation{}, s.reject(ctx, a, r, ErrPlan)
	}
	maintenanceAction := r.Action == "storage.backup" || r.Action == "storage.restore"
	release, e := s.wait(ctx, a.id, p.plan.Objects, maintenanceAction)
	if e != nil {
		return storage.Operation{}, s.reject(context.Background(), a, r, e)
	}
	defer release()
	if e = s.authorized(ctx, a, r); e != nil {
		return storage.Operation{}, e
	}
	r.Credential = a.credential
	// Recheck after queue/locks; another concurrent request may have completed.
	if prior, e := s.Get(ctx, r.ID); e == nil {
		if !storage.Matches(prior, a.id, r.Action, mac) {
			return storage.Operation{}, s.reject(ctx, a, r, storage.ErrConflict)
		}
		return prior, nil
	} else if !errors.Is(e, storage.ErrNotFound) {
		return storage.Operation{}, e
	}
	if !time.Now().Before(p.plan.Expires) {
		return storage.Operation{}, s.reject(ctx, a, r, ErrPlan)
	}
	if e = h.Check(ctx, r); e != nil {
		return storage.Operation{}, s.reject(ctx, a, r, e)
	}
	if e = s.authorized(ctx, a, r); e != nil {
		return storage.Operation{}, e
	}
	o := storage.Operation{ID: r.ID, Actor: a.id, Action: r.Action, MAC: mac, Credential: a.credential}
	prior, replay, e := s.store.Intent(ctx, o, p.plan.Objects)
	if e != nil {
		return storage.Operation{}, e
	}
	if replay {
		return prior, nil
	}
	x := &execution{actor: a.id}
	s.mu.Lock()
	s.running[r.ID] = x
	delete(s.plans, r.Plan)
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.running, r.ID); s.mu.Unlock() }()
	// From intent onwards use independent bounded DB contexts. Disconnect does
	// not undo the operation. Cancellation can win only before the effect phase.
	out := Outcome{State: "cancelled", Effect: "none", Code: "CANCELLED", Result: []byte("null")}
	// The request context no longer controls execution after durable intent.
	// Only an explicit Cancel may win the transition into the effect phase.
	{
		if e = h.Check(context.Background(), r); e != nil {
			out = Outcome{State: "rejected", Effect: "none", Code: checkedErrorCode(e), Result: []byte("null")}
		} else if !x.phase.CompareAndSwap(0, 2) {
			out = Outcome{State: "cancelled", Effect: "none", Code: "CANCELLED", Result: []byte("null")}
		} else if e = s.store.MarkRunningAuthorized(context.Background(), r.ID, a.credential); e != nil {
			if errors.Is(e, storage.ErrUnauthorized) {
				if s.store.Finish(context.Background(), r.ID, "rejected", "none", "UNAUTHORIZED", []byte("null")) == nil {
					return s.store.Lookup(context.Background(), r.ID)
				}
			}
			o, _ = s.store.Lookup(context.Background(), r.ID)
			o.AuditStatus = "result_pending"
			o.Code = "AUDIT_UNAVAILABLE"
			s.remember(o)
			return o, storage.ErrAudit
		} else {
			out = effect(h, r)
		}
	}
	if out.Result == nil {
		out.Result = []byte("null")
	}
	if e = s.store.Finish(context.Background(), r.ID, out.State, out.Effect, out.Code, out.Result); e != nil {
		o, _ = s.store.Lookup(context.Background(), r.ID)
		o.State = out.State
		o.Effect = out.Effect
		o.Result = append([]byte(nil), out.Result...)
		o.Code = out.Code
		o.AuditStatus = "result_pending"
		s.remember(o)
		return o, storage.ErrAudit
	}
	return s.store.Lookup(context.Background(), r.ID)
}
func effect(h Handler, r Request) (out Outcome) {
	out = Outcome{State: "unknown", Effect: "unknown", Code: "RECOVERY_REQUIRED", Result: []byte("null")}
	defer func() {
		if recover() != nil {
			out = Outcome{State: "unknown", Effect: "unknown", Code: "RECOVERY_REQUIRED", Result: []byte("null")}
		}
	}()
	return h.Effect(context.Background(), r)
}
func (s *Service) remember(o storage.Operation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) < 10000 {
		s.pending[o.ID] = o
	}
}
func (s *Service) Cancel(a Initiator, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	x := s.running[id]
	if x == nil || x.actor != a.id || !x.phase.CompareAndSwap(0, 1) {
		return ErrCancel
	}
	return nil
}

// All authenticated operators have the same control rights. Unlike Cancel's
// offline test hook this entry requires a durable audited control operation.
func (s *Service) CancelAudited(ctx context.Context, control, id string, expected int64, c *storage.Credential) (string, error) {
	if e := s.store.CancellationAuthority(ctx, control, id, expected, c); e != nil {
		return "", e
	}
	s.mu.Lock()
	x := s.running[id]
	won := x != nil && x.phase.CompareAndSwap(0, 1)
	s.mu.Unlock()
	if won {
		return "cancelled", nil
	}
	o, e := s.store.Lookup(ctx, id)
	if e != nil {
		return "", e
	}
	if o.State == "unknown" {
		return "unknown", nil
	}
	return "too_late", nil
}
func (s *Service) ResolveLocal(ctx context.Context, a Initiator, id, effect string) error {
	if a.id != Local().id {
		return storage.ErrSafety
	}
	return s.Maintenance(func() error {
		if e := s.store.Resolve(ctx, id, a.id, effect); e != nil {
			return e
		}
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return nil
	})
}

func (s *Service) dispatch() {
	for s.active < s.limit {
		candidate := -1
		seen := map[string]bool{}
		for i, j := range s.queue {
			if seen[j.actor] {
				continue
			}
			seen[j.actor] = true
			blocked := false
			for _, k := range j.keys {
				if s.held[k] {
					blocked = true
					break
				}
			}
			if blocked {
				continue
			}
			candidate = i
			break
		}
		if candidate < 0 {
			return
		}
		j := s.queue[candidate]
		s.queue = append(s.queue[:candidate], s.queue[candidate+1:]...)
		// Move this actor's remaining FIFO behind the other actors. Merely picking
		// a different actor than last would starve a third continuously ready actor.
		others := make([]*job, 0, len(s.queue))
		same := make([]*job, 0, len(s.queue))
		for _, q := range s.queue {
			if q.actor == j.actor {
				same = append(same, q)
			} else {
				others = append(others, q)
			}
		}
		s.queue = append(others, same...)
		s.active++
		s.lastActor = j.actor
		j.granted = true
		for _, k := range j.keys {
			s.held[k] = true
		}
		close(j.ready)
	}
}
func (s *Service) wait(ctx context.Context, actor string, keys []string, maintenanceAction bool) (func(), error) {
	s.mu.Lock()
	if s.maintenance {
		s.mu.Unlock()
		return nil, storage.ErrBusy
	}
	n := 0
	for _, j := range s.queue {
		if j.actor == actor {
			n++
		}
	}
	if len(s.queue) >= 32 || n >= 8 {
		s.mu.Unlock()
		return nil, storage.ErrBusy
	}
	if maintenanceAction {
		if s.active != 0 || len(s.queue) != 0 {
			s.mu.Unlock()
			return nil, storage.ErrBusy
		}
		s.maintenance = true
	}
	j := &job{actor: actor, keys: keys, ready: make(chan struct{})}
	s.queue = append(s.queue, j)
	s.dispatch()
	s.mu.Unlock()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	release := func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.active--
		if maintenanceAction {
			s.maintenance = false
		}
		for _, k := range keys {
			delete(s.held, k)
		}
		s.dispatch()
	}
	select {
	case <-j.ready:
		return release, nil
	case <-ctx.Done():
	case <-timer.C:
	}
	s.mu.Lock()
	granted := j.granted
	if !granted {
		for i, v := range s.queue {
			if v == j {
				s.queue = append(s.queue[:i], s.queue[i+1:]...)
				break
			}
		}
	}
	s.mu.Unlock()
	if granted {
		release()
	}
	return nil, storage.ErrBusy
}

// Maintenance is a barrier, not an audit bypass. Unknown persisted operations
// stay in backups. Live effects/queued work must finish before backup/restore.
func (s *Service) Maintenance(fn func() error) error {
	s.mu.Lock()
	if s.maintenance || s.active != 0 || len(s.queue) != 0 {
		s.mu.Unlock()
		return storage.ErrBusy
	}
	s.maintenance = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.maintenance = false; s.mu.Unlock() }()
	return fn()
}

func checkedErrorCode(e error) string {
	switch e.Error() {
	case "PERMISSION_DENIED", "PROTECTED_OBJECT", "OBJECT_CHANGED", "NOT_FOUND", "SAFETY_UNAVAILABLE", "VERSION_CONFLICT", "STORAGE_UNAVAILABLE", "AUDIT_UNAVAILABLE", "SOURCE_UNAVAILABLE", "INVALID_REQUEST", "LIMIT_EXCEEDED", "QUOTA_EXCEEDED", "BUSY", "RATE_LIMITED":
		return e.Error()
	}
	return "SAFETY_UNAVAILABLE"
}
