// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

//go:embed migrations/002.sql
var authMigration string
var ErrUnauthorized = fmt.Errorf("UNAUTHORIZED")
var ErrPolicy = fmt.Errorf("POLICY_DENIED")

// The registry commit is durable but publication of its rollback authority is
// incomplete. Callers must not report no effect or reapply the mutation.
var ErrSecurityPublish = errors.New("SECURITY_FLOOR_UNAVAILABLE")

func RandomID() (string, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return "", ErrSafety
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// Credential cannot be constructed from a client-supplied device ID.
type Credential struct {
	id       string
	verifier [32]byte
}

func (c Credential) ID() string { return c.id }

type Device struct {
	ID        string `json:"device_id"`
	Name      string `json:"name"`
	Created   int64  `json:"created_us"`
	LastSeen  *int64 `json:"last_seen_us"`
	RevokedAt *int64 `json:"revoked_at_us"`
	Revision  int64  `json:"revision"`
}

func (s *Store) migrateAuth(ctx context.Context) error { return migrateAuthDB(ctx, s.db) }
func migrateAuthDB(ctx context.Context, db *sql.DB) error {
	var v int
	if db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v) != nil {
		return ErrSchema
	}
	if v == 2 {
		return nil
	}
	if v != 1 {
		return ErrSchema
	}
	id, e := RandomID()
	if e != nil {
		return e
	}
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		return ErrStorage
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, authMigration); e != nil {
		return ErrStorage
	}
	hash := sha256.Sum256([]byte(authMigration))
	if _, e = tx.ExecContext(ctx, "INSERT INTO schema_migrations VALUES(2,?,?,?)", hex.EncodeToString(hash[:]), "development-E03", time.Now().UTC().UnixMicro()); e != nil {
		return ErrStorage
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO auth_meta VALUES(1,?)", id); e != nil {
		return ErrStorage
	}
	if e = tx.Commit(); e != nil {
		return ErrStorage
	}
	return nil
}
func (s *Store) AgentID(ctx context.Context) (string, error) {
	var id string
	e := s.read(ctx, func(ctx context.Context) error {
		return s.db.QueryRowContext(ctx, "SELECT agent_id FROM auth_meta WHERE singleton=1").Scan(&id)
	})
	if e != nil {
		return "", e
	}
	if !ValidID(id) {
		return "", ErrSafety
	}
	return id, nil
}
func (s *Store) Authenticate(ctx context.Context, hash [32]byte) (c Credential, err error) {
	err = s.read(ctx, func(ctx context.Context) error {
		rows, e := s.db.QueryContext(ctx, "SELECT id,token_hash FROM devices WHERE revoked=0 LIMIT 33")
		if e != nil {
			return e
		}
		defer rows.Close()
		count := 0
		for rows.Next() {
			count++
			var id string
			var h []byte
			if e = rows.Scan(&id, &h); e != nil {
				return e
			}
			if len(h) == 32 && subtle.ConstantTimeCompare(h, hash[:]) == 1 && ValidID(id) {
				c = Credential{id, hash}
			}
		}
		if rows.Err() != nil {
			return rows.Err()
		}
		if count > 32 {
			return ErrSafety
		}
		if c.id == "" {
			return ErrUnauthorized
		}
		return nil
	})
	return
}
func credentialCheck(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, c *Credential) error {
	if c == nil {
		return nil
	}
	if !ValidID(c.id) {
		return ErrUnauthorized
	}
	var h []byte
	var revoked int
	if q.QueryRowContext(ctx, "SELECT token_hash,revoked FROM devices WHERE id=?", c.id).Scan(&h, &revoked) != nil || revoked != 0 || len(h) != 32 || subtle.ConstantTimeCompare(h, c.verifier[:]) != 1 {
		return ErrUnauthorized
	}
	return nil
}
func (s *Store) CheckCredential(ctx context.Context, c Credential) error {
	return s.read(ctx, func(ctx context.Context) error { return credentialCheck(ctx, s.db, &c) })
}
func (s *Store) Devices(ctx context.Context) (devices []Device, err error) {
	err = s.read(ctx, func(ctx context.Context) error {
		rows, e := s.db.QueryContext(ctx, "SELECT id,name,created,last_seen,revoked_at,revision FROM devices ORDER BY created,id LIMIT 65")
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var d Device
			if e = rows.Scan(&d.ID, &d.Name, &d.Created, &d.LastSeen, &d.RevokedAt, &d.Revision); e != nil {
				return e
			}
			devices = append(devices, d)
		}
		if len(devices) > 64 {
			return ErrSafety
		}
		return rows.Err()
	})
	return
}
func (s *Store) Policy(ctx context.Context) (p Policy, e error) {
	e = s.read(ctx, func(ctx context.Context) error { f, err := floorFromDB(ctx, s.db); p = f.Policy; return err })
	return
}

type PairProof struct {
	id   string
	hash [32]byte
}

func (p PairProof) ID() string { return p.id }
func (s *Store) CreatePairCode(ctx context.Context, operationID, id string, hash [32]byte, expires time.Time) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		if !ValidID(id) || expires.Before(time.Now()) || expires.After(time.Now().Add(301*time.Second)) {
			return ErrInvalid
		}
		if e := requireRunning(ctx, tx, operationID, "pairing.issue"); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "DELETE FROM pairing_codes WHERE consumed=1 OR expires<=?", time.Now().UTC().UnixMicro()); e != nil {
			return e
		}
		var count int
		if tx.QueryRowContext(ctx, "SELECT count(*) FROM pairing_codes").Scan(&count) != nil {
			return ErrStorage
		}
		if count >= 3 {
			return ErrQuota
		}
		_, e := tx.ExecContext(ctx, "INSERT INTO pairing_codes(id,code_hash,expires) VALUES(?,?,?)", id, hash[:], expires.UTC().UnixMicro())
		return e
	})
}
func (s *Store) CheckPairCode(ctx context.Context, id string, hash [32]byte) (proof PairProof, e error) {
	e = s.read(ctx, func(ctx context.Context) error {
		var stored []byte
		var attempts, consumed int
		var expires int64
		if s.db.QueryRowContext(ctx, "SELECT code_hash,attempts,expires,consumed FROM pairing_codes WHERE id=?", id).Scan(&stored, &attempts, &expires, &consumed) != nil || consumed != 0 || attempts >= 5 || expires <= time.Now().UTC().UnixMicro() || len(stored) != 32 || subtle.ConstantTimeCompare(stored, hash[:]) != 1 {
			return ErrUnauthorized
		}
		proof = PairProof{id, hash}
		return nil
	})
	return
}
func (s *Store) FailedPairAttempt(ctx context.Context, id string) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		if _, e := tx.ExecContext(ctx, "UPDATE pairing_codes SET attempts=attempts+1 WHERE id=? AND attempts<5 AND consumed=0", id); e != nil {
			return e
		}
		_, e := tx.ExecContext(ctx, "DELETE FROM pairing_codes WHERE attempts>=5")
		return e
	})
}
func ValidDeviceName(name string) bool {
	return utf8.ValidString(name) && utf8.RuneCountInString(name) >= 1 && utf8.RuneCountInString(name) <= 80 && !strings.ContainsAny(name, "\x00\r\n")
}
func (s *Store) PairDevice(ctx context.Context, operationID, id, name string, hash [32]byte, proof PairProof) error {
	if !ValidID(id) || !ValidDeviceName(name) {
		return ErrInvalid
	}
	e := s.write(ctx, func(tx *sql.Tx) error {
		if e := requireRunning(ctx, tx, operationID, "devices.pair"); e != nil {
			return e
		}
		var n int
		if tx.QueryRowContext(ctx, "SELECT count(*) FROM devices WHERE revoked=0").Scan(&n) != nil {
			return ErrStorage
		}
		if n >= 32 {
			return ErrQuota
		}
		r, e := tx.ExecContext(ctx, "UPDATE pairing_codes SET consumed=1 WHERE id=? AND code_hash=? AND attempts<5 AND consumed=0 AND expires>?", proof.id, proof.hash[:], time.Now().UTC().UnixMicro())
		if e != nil {
			return e
		}
		affected, e := r.RowsAffected()
		if e != nil || affected != 1 {
			return ErrUnauthorized
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO devices(id,token_hash,name,created) VALUES(?,?,?,?)", id, hash[:], name, time.Now().UTC().UnixMicro()); e != nil {
			return e
		}
		r, e = tx.ExecContext(ctx, "UPDATE identity SET security_generation=security_generation+1 WHERE singleton=1 AND security_generation<9223372036854775807")
		if e != nil {
			return e
		}
		n64, e := r.RowsAffected()
		if e != nil {
			return e
		}
		if n64 != 1 {
			return ErrQuota
		}
		return nil
	})
	if e != nil {
		return e
	}
	if s.publishAuthFloor(ctx) != nil {
		return ErrSecurityPublish
	}
	return nil
}
func (s *Store) RevokeDevice(ctx context.Context, operationID, id string, expected int64, credential *Credential) error {
	e := s.write(ctx, func(tx *sql.Tx) error {
		if e := requireRunning(ctx, tx, operationID, "devices.revoke"); e != nil {
			return e
		}
		if e := credentialCheck(ctx, tx, credential); e != nil {
			return e
		}
		now := time.Now().UTC().UnixMicro()
		r, e := tx.ExecContext(ctx, "UPDATE devices SET revoked=1,token_hash=NULL,revoked_at=?,revision=revision+1 WHERE id=? AND revision=? AND revision<9223372036854775807 AND revoked=0", now, id, expected)
		if e != nil {
			return e
		}
		n, e := r.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrVersion
		}
		r, e = tx.ExecContext(ctx, "UPDATE identity SET security_generation=security_generation+1 WHERE singleton=1 AND security_generation<9223372036854775807")
		if e != nil {
			return e
		}
		n, e = r.RowsAffected()
		if e != nil || n != 1 {
			return ErrQuota
		}
		// Retired identities are not authentication authority. Restore replaces the
		// full current registry; old deleted identities can never become active.
		_, e = tx.ExecContext(ctx, "DELETE FROM devices WHERE revoked=1 AND id NOT IN (SELECT id FROM devices WHERE revoked=1 ORDER BY revoked_at DESC,id LIMIT 32)")
		return e
	})
	if e != nil {
		return e
	}
	if s.publishAuthFloor(ctx) != nil {
		return ErrSecurityPublish
	}
	return nil
}
func (s *Store) publishAuthFloor(ctx context.Context) (err error) {
	ctx, cancel := context.WithTimeout(ctx, readerTimeout)
	defer cancel()
	defer func() { s.healthMu.Lock(); s.health.SecurityFloorAvailable = err == nil; s.healthMu.Unlock() }()
	release, e := s.acquire(ctx)
	if e != nil {
		return e
	}
	defer release()
	if e = s.admission(ctx); e != nil {
		return s.failure(e)
	}
	if _, e = s.exportFloor(ctx); e != nil {
		return s.failure(e)
	}
	return nil
}
func (s *Store) ObserveDevice(ctx context.Context, id string, at int64) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, "UPDATE devices SET last_seen=? WHERE id=? AND revoked=0 AND (last_seen IS NULL OR last_seen<?)", at, id, at-int64(time.Minute/time.Microsecond))
		return e
	})
}
