// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"strings"
)

func (s *Store) SignCursor(payload []byte) (string, error) {
	if len(payload) > 1024 {
		return "", ErrInvalid
	}
	h := hmac.New(sha256.New, s.key)
	h.Write([]byte("serverdeck-cursor-v1\x00"))
	h.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}
func (s *Store) VerifyCursor(cursor string) ([]byte, error) {
	if len(cursor) > 2048 {
		return nil, ErrInvalid
	}
	parts := strings.Split(cursor, ".")
	if len(parts) != 2 {
		return nil, ErrInvalid
	}
	payload, e := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if e != nil || len(payload) > 1024 {
		return nil, ErrInvalid
	}
	mac, e := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if e != nil {
		return nil, ErrInvalid
	}
	expected, e := s.SignCursor(payload)
	if e != nil {
		return nil, e
	}
	want, _ := base64.RawURLEncoding.DecodeString(strings.Split(expected, ".")[1])
	if !hmac.Equal(mac, want) {
		return nil, ErrInvalid
	}
	return payload, nil
}

type OperationChange struct {
	Sequence  int64
	Operation Operation
}

func (s *Store) OperationPage(ctx context.Context, epoch string, after int64, limit int, state string) (changes []OperationChange, currentEpoch string, last int64, err error) {
	if after < 0 || limit < 1 || limit > 100 {
		return nil, "", 0, ErrInvalid
	}
	err = s.read(ctx, func(ctx context.Context) error {
		var floor int64
		if e := s.db.QueryRowContext(ctx, "SELECT epoch,operation_floor FROM storage_meta WHERE singleton=1").Scan(&currentEpoch, &floor); e != nil {
			return e
		}
		if epoch != "" && epoch != currentEpoch {
			return ErrCursor
		}
		if epoch != "" && after < floor {
			return ErrCursor
		}
		var latest int64
		if e := s.db.QueryRowContext(ctx, "SELECT coalesce(max(seq),0) FROM operation_changes").Scan(&latest); e != nil {
			return e
		}
		if after > latest && after != 0 {
			return ErrCursor
		}
		rows, e := s.db.QueryContext(ctx, "SELECT seq,operation_id FROM operation_changes WHERE seq>? ORDER BY seq LIMIT ?", after, limit)
		if e != nil {
			return e
		}
		type changeID struct {
			seq int64
			id  string
		}
		var ids []changeID
		for rows.Next() {
			var item changeID
			if e = rows.Scan(&item.seq, &item.id); e != nil {
				rows.Close()
				return e
			}
			ids = append(ids, item)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		last = after
		for _, item := range ids {
			last = item.seq
			o, e := scanOperation(s.db.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM operations WHERE id=?", item.id))
			if e != nil {
				return e
			}
			if state == "" || o.State == state {
				changes = append(changes, OperationChange{item.seq, o})
			}
		}
		return nil
	})
	return
}
func PrivateDirectory(path string, create bool) (*os.File, error) { return privateDir(path, create) }
