// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"errors"
	"sort"
	"time"
)

const operationColumns = "id,actor,action,params_hmac,state,phase,effect,audit_status,code,result,revision,created,updated,expires"

type scanner interface{ Scan(...any) error }

func scanOperation(r scanner) (o Operation, e error) {
	e = r.Scan(&o.ID, &o.Actor, &o.Action, &o.MAC, &o.State, &o.Phase, &o.Effect, &o.AuditStatus, &o.Code, &o.Result, &o.Revision, &o.Created, &o.Updated, &o.Expires)
	if errors.Is(e, sql.ErrNoRows) {
		e = ErrNotFound
	}
	return
}
func (s *Store) Lookup(ctx context.Context, id string) (o Operation, e error) {
	if !ValidID(id) {
		return o, ErrInvalid
	}
	e = s.read(ctx, func(ctx context.Context) error {
		var err error
		o, err = scanOperation(s.db.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM operations WHERE id=?", id))
		return err
	})
	return
}
func Matches(o Operation, actor, action string, mac []byte) bool {
	return o.Actor == actor && o.Action == action && hmac.Equal(o.MAC, mac)
}

// Intent atomically persists the operation, safe audit and durable conflict
// ownership. Parameters/content are never stored, only their keyed fingerprint.
func (s *Store) Intent(ctx context.Context, o Operation, keys []string) (existing Operation, replay bool, err error) {
	if !ValidID(o.ID) || !SafeLabel(o.Actor) || !SafeLabel(o.Action) || len(o.MAC) != 32 || len(keys) < 1 || len(keys) > 16 {
		return existing, false, ErrInvalid
	}
	keys = append([]string(nil), keys...)
	sort.Strings(keys)
	for i, k := range keys {
		if !SafeLabel(k) || (i > 0 && keys[i-1] == k) {
			return existing, false, ErrInvalid
		}
	}
	err = s.write(ctx, func(tx *sql.Tx) error {
		if e := credentialCheck(ctx, tx, o.Credential); e != nil {
			return e
		}
		prior, e := scanOperation(tx.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM operations WHERE id=?", o.ID))
		if e == nil {
			if !Matches(prior, o.Actor, o.Action, o.MAC) {
				return ErrConflict
			}
			existing = prior
			replay = true
			return nil
		}
		if !errors.Is(e, ErrNotFound) {
			return e
		}
		if e = s.rotate(tx, time.Now()); e != nil {
			return e
		}
		var count int
		var used int64
		if e = tx.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(bytes),0) FROM operations").Scan(&count, &used); e != nil {
			return e
		}
		if count >= s.limits.Operations || used+32768 > s.limits.StateBytes {
			return ErrQuota
		}
		now := time.Now().UTC().UnixMicro()
		if _, e = tx.ExecContext(ctx, `INSERT INTO operations VALUES(?,?,?,?,'preparing','intent','none','durable','',?,1,?,?,0,32768)`, o.ID, o.Actor, o.Action, o.MAC, []byte("null"), now, now); e != nil {
			return e
		}
		for _, k := range keys {
			var held string
			e = tx.QueryRowContext(ctx, "SELECT operation_id FROM object_locks WHERE object_key=?", k).Scan(&held)
			if e == nil {
				return ErrBusy
			}
			if !errors.Is(e, sql.ErrNoRows) {
				return e
			}
			if _, e = tx.ExecContext(ctx, "INSERT INTO object_locks VALUES(?,?)", k, o.ID); e != nil {
				return e
			}
		}
		if e = s.audit(tx, o, keys[0], "intent", "", "none", now); e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, "INSERT INTO operation_changes(operation_id,revision) VALUES(?,1)", o.ID)
		return e
	})
	return
}
func (s *Store) MarkRunning(ctx context.Context, id string) error {
	return s.MarkRunningAuthorized(ctx, id, nil)
}
func (s *Store) MarkRunningAuthorized(ctx context.Context, id string, c *Credential) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		if e := credentialCheck(ctx, tx, c); e != nil {
			return e
		}
		r, e := tx.ExecContext(ctx, "UPDATE operations SET state='running',phase='effect',effect='unknown',revision=revision+1,updated=? WHERE id=? AND state='preparing' AND revision<9223372036854775807", time.Now().UTC().UnixMicro(), id)
		if e != nil {
			return e
		}
		n, e := r.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrSafety
		}
		return s.change(tx, id)
	})
}

// Finish never frees object ownership for unknown. No reconciler automatically
// dispatches effects: a domain-specific proof is required to finish later.
func (s *Store) Finish(ctx context.Context, id, state, effect, code string, result []byte) error {
	if !ValidID(id) || len(result) > 16384 || !safeCode(code) {
		return ErrInvalid
	}
	terminal := state == "succeeded" || state == "failed" || state == "rejected" || state == "cancelled"
	if !terminal && state != "unknown" {
		return ErrInvalid
	}
	if (state == "succeeded" && effect != "applied") || ((state == "cancelled" || state == "rejected") && effect != "none") || (state == "unknown" && effect != "unknown" && effect != "partial") || (effect != "none" && effect != "applied" && effect != "partial" && effect != "unknown") {
		return ErrInvalid
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		o, e := scanOperation(tx.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM operations WHERE id=?", id))
		if e != nil {
			return e
		}
		if o.Terminal() {
			return ErrSafety
		}
		if o.Revision == 9223372036854775807 {
			return ErrQuota
		}
		now := time.Now().UTC().UnixMicro()
		expiry := int64(0)
		phase := "reconcile_required"
		if terminal {
			expiry = now + int64(7*24*time.Hour/time.Microsecond)
			phase = "complete"
		}
		if _, e = tx.ExecContext(ctx, "UPDATE operations SET state=?,phase=?,effect=?,audit_status='durable',code=?,result=?,revision=revision+1,updated=?,expires=? WHERE id=? AND revision<9223372036854775807", state, phase, effect, code, result, now, expiry, id); e != nil {
			return e
		}
		if terminal {
			if _, e = tx.ExecContext(ctx, "DELETE FROM object_locks WHERE operation_id=?", id); e != nil {
				return e
			}
		}
		if e = s.audit(tx, o, "operation", "result", code, effect, now); e != nil {
			return e
		}
		return s.change(tx, id)
	})
}
func safeCode(s string) bool {
	if len(s) > 64 {
		return false
	}
	for _, c := range s {
		if c != '_' && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}
func (s *Store) change(tx *sql.Tx, id string) error {
	if _, e := tx.Exec("DELETE FROM operation_changes WHERE operation_id=?", id); e != nil {
		return e
	}
	_, e := tx.Exec("INSERT INTO operation_changes(operation_id,revision) SELECT id,revision FROM operations WHERE id=?", id)
	return e
}
func (s *Store) audit(tx *sql.Tx, o Operation, object, kind, code, effect string, now int64) error {
	if e := s.rotateAudit(tx, now, 2048); e != nil {
		return e
	}
	_, e := tx.Exec(`INSERT INTO audit(operation_id,actor,action,object,kind,code,effect,at,bytes) VALUES(?,?,?,?,?,?,?,?,2048)`, o.ID, o.Actor, o.Action, object, kind, code, effect, now)
	return e
}

// Rejections are bounded/safe and do not create an intent or invoke an effect.
func (s *Store) Rejection(ctx context.Context, o Operation, code string) error {
	if !ValidID(o.ID) || !SafeLabel(o.Actor) || !SafeLabel(o.Action) || !safeCode(code) {
		return ErrInvalid
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		return s.audit(tx, o, "operation", "rejection", code, "none", time.Now().UTC().UnixMicro())
	})
}
func (s *Store) trustworthyClock(now time.Time) bool {
	elapsed := time.Since(s.started)
	delta := now.Sub(s.wallStart) - elapsed
	if delta > time.Second || delta < -time.Second {
		s.expiryTrusted = false
		return false
	}
	// A restart cannot prove how much time elapsed while offline. Wait a full
	// retention interval in this run before using persisted wall deadlines.
	return s.expiryTrusted || elapsed >= 7*24*time.Hour
}
func (s *Store) rotate(tx *sql.Tx, now time.Time) error {
	trusted := s.trustworthyClock(now)
	s.healthMu.Lock()
	s.health.TemporalExpiry = trusted
	s.healthMu.Unlock()
	if trusted {
		if _, e := tx.Exec(`UPDATE storage_meta SET operation_floor=max(operation_floor,coalesce((SELECT max(seq) FROM operation_changes WHERE operation_id IN (SELECT id FROM operations WHERE state IN ('succeeded','failed','rejected','cancelled') AND expires>0 AND expires<=? ORDER BY expires LIMIT 256)),0)) WHERE singleton=1`, now.UTC().UnixMicro()); e != nil {
			return e
		}
		if _, e := tx.Exec(`DELETE FROM operations WHERE id IN (SELECT id FROM operations WHERE state IN ('succeeded','failed','rejected','cancelled') AND expires>0 AND expires<=? ORDER BY expires LIMIT 256)`, now.UTC().UnixMicro()); e != nil {
			return e
		}
	}
	return s.rotateAudit(tx, now.UTC().UnixMicro(), 0)
}
func (s *Store) rotateAudit(tx *sql.Tx, now, reserve int64) error {
	var total int64
	if e := tx.QueryRow("SELECT coalesce(sum(bytes),0) FROM audit").Scan(&total); e != nil {
		return e
	}
	var floor int64
	if time.Since(s.started) >= time.Duration(s.limits.AuditDays)*24*time.Hour && s.trustworthyClock(time.Now()) {
		if e := tx.QueryRow("SELECT coalesce(max(seq),0) FROM audit WHERE at<?", now-int64(time.Duration(s.limits.AuditDays)*24*time.Hour/time.Microsecond)).Scan(&floor); e != nil {
			return e
		}
		if _, e := tx.Exec("DELETE FROM audit WHERE seq<=?", floor); e != nil {
			return e
		}
		if e := tx.QueryRow("SELECT coalesce(sum(bytes),0) FROM audit").Scan(&total); e != nil {
			return e
		}
	}
	for total+reserve > s.limits.AuditBytes {
		var seq int64
		if e := tx.QueryRow("SELECT coalesce(max(seq),0) FROM (SELECT seq FROM audit ORDER BY seq LIMIT 256)").Scan(&seq); e != nil {
			return e
		}
		if seq == 0 {
			return ErrQuota
		}
		if _, e := tx.Exec("DELETE FROM audit WHERE seq<=?", seq); e != nil {
			return e
		}
		if seq > floor {
			floor = seq
		}
		if e := tx.QueryRow("SELECT coalesce(sum(bytes),0) FROM audit").Scan(&total); e != nil {
			return e
		}
	}
	if floor > 0 {
		_, e := tx.Exec("UPDATE storage_meta SET audit_floor=max(audit_floor,?) WHERE singleton=1", floor)
		return e
	}
	return nil
}
func (s *Store) Rotate(ctx context.Context) error {
	return s.write(ctx, func(tx *sql.Tx) error { return s.rotate(tx, time.Now()) })
}
func (s *Store) Audit(ctx context.Context, after int64, limit int) (entries []AuditEntry, floor int64, err error) {
	entries, floor, _, err = s.AuditPage(ctx, "", after, limit)
	return
}

// E03 cursors must bind this epoch; restore creates a fresh namespace so a
// cursor from the original branch cannot silently skip a reused sequence.
func (s *Store) AuditPage(ctx context.Context, expectedEpoch string, after int64, limit int) (entries []AuditEntry, floor int64, epoch string, err error) {
	if after < 0 || limit < 1 || limit > 100 {
		return nil, 0, "", ErrInvalid
	}
	err = s.read(ctx, func(ctx context.Context) error {
		if e := s.db.QueryRowContext(ctx, "SELECT audit_floor,epoch FROM storage_meta WHERE singleton=1").Scan(&floor, &epoch); e != nil {
			return e
		}
		if expectedEpoch != "" && expectedEpoch != epoch {
			return ErrCursor
		}
		if after != 0 && after < floor {
			return ErrCursor
		}
		rows, e := s.db.QueryContext(ctx, "SELECT seq,operation_id,actor,action,object,kind,code,effect,at FROM audit WHERE seq>? ORDER BY seq LIMIT ?", after, limit)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var a AuditEntry
			if e = rows.Scan(&a.Seq, &a.OperationID, &a.Actor, &a.Action, &a.Object, &a.Kind, &a.Code, &a.Effect, &a.At); e != nil {
				return e
			}
			entries = append(entries, a)
		}
		return rows.Err()
	})
	return
}
