// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"database/sql"
	"time"
)

// Administrative resolution records a local operator's explicit observation;
// it is not an automatic proof of effect and never dispatches an effect.
func (s *Store) Resolve(ctx context.Context, id, resolver, effect string) error {
	if !ValidID(id) || !SafeLabel(resolver) || (effect != "applied" && effect != "none") {
		return ErrInvalid
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		o, e := scanOperation(tx.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM operations WHERE id=?", id))
		if e != nil {
			return e
		}
		if o.State != "unknown" {
			return ErrSafety
		}
		if o.Revision == 9223372036854775807 {
			return ErrQuota
		}
		now := time.Now().UTC().UnixMicro()
		actor := o
		actor.Actor = resolver
		if e = s.audit(tx, actor, "operation", "gap", "ADMIN_RESOLUTION", effect, now); e != nil {
			return e
		}
		state := "failed"
		if effect == "applied" {
			state = "succeeded"
		}
		if _, e = tx.ExecContext(ctx, "UPDATE operations SET state=?,phase='admin_resolved',effect=?,code='ADMIN_RESOLUTION',audit_status='durable',revision=revision+1,updated=?,expires=? WHERE id=? AND revision<9223372036854775807", state, effect, now, now+int64(7*24*time.Hour/time.Microsecond), id); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, "DELETE FROM object_locks WHERE operation_id=?", id); e != nil {
			return e
		}
		return s.change(tx, id)
	})
}
