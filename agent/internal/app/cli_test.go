// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"strings"
	"testing"
)

func TestOfflineCommands(t *testing.T) {
	for _, args := range [][]string{nil, {"serve"}, {"sudo"}, {"operations", "execute"}} {
		var out, err bytes.Buffer
		if Run("serverdeck-agent", args, &out, &err) != 2 || out.Len() != 0 {
			t.Fatal("unfinished service must not start")
		}
	}
	var out, err bytes.Buffer
	if Run("serverdeckctl", []string{"version"}, &out, &err) != 0 || !strings.Contains(out.String(), "E04") {
		t.Fatal("version")
	}
	out.Reset()
	if Run("serverdeckctl", []string{"validate-config", "missing-secret-path"}, &out, &err) != 1 || strings.Contains(err.String(), "missing-secret-path") {
		t.Fatal("error leaks input")
	}
}
func TestSQLiteVersion(t *testing.T) {
	s, e := sqliteInfo()
	if e != nil {
		t.Fatal(e)
	}
	if !strings.HasPrefix(s, "sqlite_version=3.53.4 sqlite_source_id=") {
		t.Fatalf("unexpected SQLite: %s", s)
	}
	t.Log(s)
}
