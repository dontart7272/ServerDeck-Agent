// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"serverdeck.local/agent/internal/contracts"
	"serverdeck.local/agent/internal/metrics"
)

//go:embed migrations/003.sql
var rulesMigration string

func migrateRulesAfterAuth(ctx context.Context, db *sql.DB) error {
	if e := migrateAuthDB(ctx, db); e != nil {
		return e
	}
	return migrateRulesDB(ctx, db)
}

func rotateRuleEpochDB(ctx context.Context, db *sql.DB) error {
	epoch, err := RandomID()
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return ErrStorage
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "UPDATE rule_versions SET epoch=?,next_revision=2", epoch); err != nil {
		return ErrStorage
	}
	if _, err = tx.ExecContext(ctx, "UPDATE rules SET revision=1"); err != nil {
		return ErrStorage
	}
	if tx.Commit() != nil {
		return ErrStorage
	}
	return nil
}

func migrateRulesDB(ctx context.Context, db *sql.DB) error {
	var version int
	if db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version) != nil {
		return ErrSchema
	}
	if version == 3 || version == 4 || version == 5 {
		return nil
	}
	if version != 2 {
		return ErrSchema
	}
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		return ErrStorage
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, rulesMigration); e != nil {
		return ErrStorage
	}
	h := sha256.Sum256([]byte(rulesMigration))
	if _, e = tx.ExecContext(ctx, "INSERT INTO schema_migrations VALUES(3,?,?,?)", hex.EncodeToString(h[:]), "development-E05", time.Now().UnixMicro()); e != nil {
		return ErrStorage
	}
	for _, r := range DefaultRules() {
		b, _ := json.Marshal(r)
		if _, e = tx.ExecContext(ctx, "INSERT INTO rules VALUES(?,1,?)", r.Id, b); e != nil {
			return ErrStorage
		}
	}
	epoch, e := RandomID()
	if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE rule_versions SET epoch=?", epoch); e != nil {
		return ErrStorage
	}
	return tx.Commit()
}

func DefaultRules() []contracts.APIRule {
	low, high := 10.0, 15.0
	out := []contracts.APIRule{}
	for _, p := range []struct {
		id, metric string
		duration   int64
	}{{"memory.available", "available_percent", 120000}, {"filesystem.available", "available_percent", 300000}, {"filesystem.inodes_available", "inodes_available_percent", 300000}} {
		out = append(out, contracts.APIRule{Id: p.id, Version: "1", Enabled: true, Kind: "threshold", ResourceSelector: "*", Metric: p.metric, Unit: "percent", Comparison: "lt", Threshold: &low, DurationMs: p.duration, RecoveryComparison: "gt", RecoveryThreshold: &high, RecoveryDurationMs: p.duration, RepeatMs: 3600000})
	}
	for _, p := range []struct{ id, metric, unit, kind string }{{"cpu.busy", "busy_percent", "percent", "threshold"}, {"gpu.utilization", "utilization_percent", "percent", "threshold"}, {"gpu.temperature", "temperature_c", "celsius", "device_threshold"}, {"source.unavailable", "source_stale", "bool", "source_stale"}, {"ssh.failures", "ssh_failures", "count", "ssh_window"}} {
		enabled := p.kind == "source_stale" || p.kind == "ssh_window" || p.kind == "device_threshold"
		rule := contracts.APIRule{Id: p.id, Version: "1", Enabled: enabled, Kind: p.kind, ResourceSelector: "*", Metric: p.metric, Unit: p.unit, Comparison: "gt", RecoveryComparison: "lt", RepeatMs: 3600000}
		if p.kind == "ssh_window" {
			five, one := 5.0, 1.0
			rule.Threshold = &five
			rule.RecoveryThreshold = &one
			rule.Comparison = "gte"
			rule.DurationMs = 300000
		}
		out = append(out, rule)
	}
	return out
}

func (s *Store) Rules(ctx context.Context) ([]contracts.APIRule, error) {
	out := []contracts.APIRule{}
	e := s.read(ctx, func(ctx context.Context) error {
		var epoch string
		if s.db.QueryRowContext(ctx, "SELECT epoch FROM rule_versions").Scan(&epoch) != nil || !ValidID(epoch) {
			return ErrStorage
		}
		rows, e := s.db.QueryContext(ctx, "SELECT revision,document FROM rules ORDER BY id LIMIT 256")
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var b []byte
			var rev int64
			if e = rows.Scan(&rev, &b); e != nil {
				return e
			}
			var r contracts.APIRule
			if json.Unmarshal(b, &r) != nil {
				return ErrStorage
			}
			r.Version = epoch + ":" + strconv.FormatInt(rev, 10)
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, e
}

func ValidateRule(r contracts.APIRule) error {
	b, _ := json.Marshal(r)
	if _, e := contracts.Validate(bytes.NewReader(b), contracts.Target{Family: "api", Definition: "Rule"}, 4096); e != nil {
		return ErrInvalid
	}
	if !SafeLabel(r.Id) {
		return ErrInvalid
	}
	units := map[string]string{"available_percent": "percent", "inodes_available_percent": "percent", "busy_percent": "percent", "utilization_percent": "percent", "temperature_c": "celsius", "source_stale": "bool", "ssh_failures": "count", "used_percent": "percent", "swap_used_percent": "percent", "frequency_hz": "hertz", "psi_some_percent": "percent", "psi_full_percent": "percent"}
	unit, registered := metrics.UnitForKey(r.Metric)
	if !registered {
		unit = units[r.Metric]
	}
	if unit == "" || unit != r.Unit {
		return ErrInvalid
	}
	if r.Kind == "threshold" && r.Enabled && (r.Threshold == nil || r.RecoveryThreshold == nil) {
		return ErrInvalid
	}
	if r.Kind == "ssh_window" {
		if r.Id != "ssh.failures" {
			return ErrInvalid
		}
		if r.Threshold != nil && (*r.Threshold < 1 || *r.Threshold > 4096 || *r.Threshold != float64(int64(*r.Threshold))) {
			return ErrInvalid
		}
	}
	if r.Kind == "device_threshold" && (r.Metric != "temperature_c" || r.Unit != "celsius") {
		return ErrInvalid
	}
	if r.Kind == "source_stale" && (r.Metric != "source_stale" || r.Unit != "bool") {
		return ErrInvalid
	}
	if r.Kind == "ssh_window" && (r.Metric != "ssh_failures" || r.Unit != "count") {
		return ErrInvalid
	}
	return nil
}

func (s *Store) ApplyRule(ctx context.Context, operationID string, r contracts.APIRule, expected string, remove bool) error {
	if ValidateRule(r) != nil {
		return ErrInvalid
	}
	namespace, number, hasNamespace := strings.Cut(expected, ":")
	if expected == "0" {
		number = "0"
		namespace = ""
		hasNamespace = true
	}
	if !hasNamespace {
		return ErrVersion
	}
	version, e := strconv.ParseInt(number, 10, 64)
	if e != nil || version < 0 {
		return ErrVersion
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		var epoch string
		if tx.QueryRowContext(ctx, "SELECT epoch FROM rule_versions").Scan(&epoch) != nil {
			return ErrStorage
		}
		if version > 0 && namespace != epoch {
			return ErrVersion
		}
		var action, state string
		if tx.QueryRowContext(ctx, "SELECT action,state FROM operations WHERE id=?", operationID).Scan(&action, &state) != nil || state != "running" || (remove && action != "rules.delete") || (!remove && action != "rules.put") {
			return ErrSafety
		}
		var current int64
		err := tx.QueryRowContext(ctx, "SELECT revision FROM rules WHERE id=?", r.Id).Scan(&current)
		if err != nil && err != sql.ErrNoRows {
			return ErrStorage
		}
		if current != version {
			return ErrVersion
		}
		if remove {
			_, e := tx.ExecContext(ctx, "DELETE FROM rules WHERE id=?", r.Id)
			return e
		}
		var count int
		if tx.QueryRowContext(ctx, "SELECT count(*) FROM rules").Scan(&count) != nil {
			return ErrStorage
		}
		if current == 0 && count >= 256 {
			return ErrQuota
		}
		var next int64
		if tx.QueryRowContext(ctx, "SELECT next_revision FROM rule_versions").Scan(&next) != nil {
			return ErrQuota
		}
		if next == 9223372036854775807 {
			epoch, e = RandomID()
			if e != nil {
				return e
			}
			if _, e = tx.ExecContext(ctx, "UPDATE rule_versions SET epoch=?,next_revision=2", epoch); e != nil {
				return ErrStorage
			}
			if _, e = tx.ExecContext(ctx, "UPDATE rules SET revision=1"); e != nil {
				return ErrStorage
			}
			next = 2
		}
		r.Version = epoch + ":" + strconv.FormatInt(next, 10)
		b, _ := json.Marshal(r)
		if _, e := tx.ExecContext(ctx, "INSERT INTO rules VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,document=excluded.document", r.Id, next, b); e != nil {
			return e
		}
		_, e := tx.ExecContext(ctx, "UPDATE rule_versions SET next_revision=next_revision+1")
		return e
	})
}
