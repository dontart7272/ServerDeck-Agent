// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"database/sql"
	"time"
)

// Reclaim performs bounded maintenance on owned telemetry only. Active problems,
// offsets, identity and critical state cannot be selected by these statements.
func (t *Telemetry) Reclaim(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.capacity {
		return ErrQuota
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	for batch := 0; batch < 8; batch++ {
		var busy, log, done int
		if t.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &done) != nil {
			return ErrStorage
		}
		if busy != 0 {
			return ErrBusy
		}
		used, _, err := t.usage()
		if err != nil {
			return err
		}
		var freePages, pages, maxPages int64
		if t.db.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&freePages) != nil || t.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages) != nil || t.db.QueryRowContext(ctx, "PRAGMA max_page_count").Scan(&maxPages) != nil {
			return ErrStorage
		}
		journalFits := true
		if t.name == "events" {
			var size int64
			if t.db.QueryRowContext(ctx, "SELECT coalesce(sum(length(data)+length(id)+512),0) FROM changes").Scan(&size) != nil {
				return ErrStorage
			}
			journalFits = size <= t.journalBudget
		}
		if journalFits && used+t.reserve+1000000 < t.budget && (freePages >= 256 || maxPages-pages >= 256) {
			t.capacity = false
			t.failed = false
			return nil
		}
		free, err := diskFree(t.owner.dir)
		if err != nil || free < 3000000 {
			return ErrSpace
		}
		tx, err := t.db.BeginTx(ctx, nil)
		if err != nil {
			return ErrStorage
		}
		var result sql.Result
		if t.name == "history" {
			result, err = tx.ExecContext(ctx, `DELETE FROM records WHERE rowid IN (SELECT a.rowid FROM records a WHERE kind='bucket' AND a.rowid<(SELECT max(b.rowid) FROM records b WHERE b.kind='bucket' AND b.series=a.series AND b.level=a.level) ORDER BY a.rowid LIMIT 8)`)
		} else {
			result, err = tx.ExecContext(ctx, "DELETE FROM changes WHERE seq IN (SELECT seq FROM changes ORDER BY seq LIMIT 8)")
		}
		if err != nil {
			tx.Rollback()
			return ErrStorage
		}
		n, err := result.RowsAffected()
		if err != nil {
			tx.Rollback()
			return ErrStorage
		}
		if n == 0 {
			tx.Rollback()
			return ErrQuota
		}
		if t.name == "history" {
			epoch, e := RandomID()
			if e != nil {
				tx.Rollback()
				return e
			}
			_, err = tx.ExecContext(ctx, "UPDATE meta SET epoch=?,revision=revision+1", epoch)
		} else {
			_, err = tx.ExecContext(ctx, "UPDATE meta SET floor=max(floor,coalesce((SELECT min(seq)-1 FROM changes),coalesce((SELECT seq FROM sqlite_sequence WHERE name='changes'),0))),revision=revision+1")
		}
		if err != nil {
			tx.Rollback()
			return ErrStorage
		}
		if tx.Commit() != nil {
			return ErrStorage
		}
		rows, err := t.db.QueryContext(ctx, "PRAGMA incremental_vacuum(128)")
		if err != nil {
			return ErrStorage
		}
		for rows.Next() {
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return ErrStorage
		}
	}
	return nil
}
