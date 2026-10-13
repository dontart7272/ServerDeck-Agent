// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"serverdeck.local/agent/internal/storage"
	"testing"
	"time"
)

func TestMonotonicPairingExpirySlotsAndTokenBoundaries(t *testing.T) {
	b, e := os.ReadFile("../../../Документация ServerDeck/Документация ServerDeck Agent/contracts/examples/config.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Runtime json.RawMessage `json:"runtime_initial"`
	}
	json.Unmarshal(b, &v)
	s, e := storage.Open(context.Background(), filepath.Join(t.TempDir(), "state"), "11111111-1111-4111-8111-111111111111", v.Runtime, true, storage.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	m := New(s)
	defer m.Close()
	now := time.Now()
	m.now = func() time.Time { return now }
	first, e := m.NewCode()
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		if _, e = m.NewCode(); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = m.NewCode(); !errors.Is(e, ErrRate) {
		t.Fatal("unbounded issue rate")
	}
	now = now.Add(300 * time.Second)
	if _, e = m.VerifyCode(context.Background(), first.ID, first.Secret); !errors.Is(e, ErrPairing) {
		t.Fatal("expiry boundary accepted")
	}
	if _, e = m.NewCode(); e != nil {
		t.Fatal("expired slots not released")
	}
	for _, secret := range []string{"", " ", "abc", first.Secret + "=", first.Secret + "\n"} {
		if _, e = Digest(secret, 16); e == nil {
			t.Fatal("noncanonical secret accepted")
		}
	}
	if e = s.CheckCredential(context.Background(), storage.Credential{}); !errors.Is(e, storage.ErrUnauthorized) {
		t.Fatal("zero credential accepted")
	}
}
