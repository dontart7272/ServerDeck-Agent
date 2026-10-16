// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"strings"
	"testing"
)

func TestRuleRevisionNamespacePreventsDeleteRecreateAndOverflowABA(t *testing.T) {
	s, _ := testStore(t, DefaultLimits())
	ctx := context.Background()
	rules, err := s.Rules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rule := rules[0]
	old := rule.Version
	change := func(remove bool, expected string) {
		t.Helper()
		id, err := RandomID()
		if err != nil {
			t.Fatal(err)
		}
		action := "rules.put"
		if remove {
			action = "rules.delete"
		}
		running(t, s, id, action, "rules.registry")
		if err = s.ApplyRule(ctx, id, rule, expected, remove); err != nil {
			t.Fatal(err)
		}
		if err = s.Finish(ctx, id, "succeeded", "applied", "", []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	change(true, old)
	change(false, "0")
	recreated, err := s.Rules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if recreated[0].Version == old {
		t.Fatal("delete/recreate ABA")
	}
	rule = recreated[0]
	if _, err = s.db.Exec("UPDATE rule_versions SET next_revision=9223372036854775807"); err != nil {
		t.Fatal(err)
	}
	prior := rule.Version
	change(false, prior)
	rolled, err := s.Rules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	before, _, _ := strings.Cut(prior, ":")
	after, _, _ := strings.Cut(rolled[0].Version, ":")
	if before == after {
		t.Fatal("overflow reused namespace")
	}
	if err = rotateRuleEpochDB(ctx, s.db); err != nil {
		t.Fatal(err)
	}
	restored, err := s.Rules(ctx)
	if err != nil || restored[0].Version == rolled[0].Version {
		t.Fatal("restore reused old version", err)
	}
	id, _ := RandomID()
	running(t, s, id, "rules.put", "rules.registry")
	if err = s.ApplyRule(ctx, id, restored[0], prior, false); err != ErrVersion {
		t.Fatal("stale version accepted", err)
	}
}
