// SPDX-License-Identifier: Apache-2.0
package storage

import "context"

// Cancellation authority is an already audited running control operation.
func (s *Store) CancellationAuthority(ctx context.Context, control, target string, expected int64, c *Credential) error {
	return s.read(ctx, func(ctx context.Context) error {
		if e := credentialCheck(ctx, s.db, c); e != nil {
			return e
		}
		if e := requireRunning(ctx, s.db, control, "operations.cancel"); e != nil {
			return e
		}
		var revision int64
		if e := s.db.QueryRowContext(ctx, "SELECT revision FROM operations WHERE id=?", target).Scan(&revision); e != nil {
			return ErrNotFound
		}
		if revision != expected {
			return ErrVersion
		}
		return nil
	})
}
