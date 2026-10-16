// SPDX-License-Identifier: Apache-2.0
package contracts

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestE05CacheAndProblemRemovalFixtures(t *testing.T) {
	for _, tc := range []struct{ name, definition string }{
		{"history-response.json", "QueryResponse"},
		{"history-response-updated.json", "QueryResponse"},
		{"wss-problem-removed.json", "WssServerMessage"},
	} {
		b, err := os.ReadFile(filepath.Join(docsContracts(), "examples", tc.name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = Validate(bytes.NewReader(b), Target{"api", tc.definition}, MaxHistoryBytes); err != nil {
			t.Fatal(tc.name, err)
		}
	}
}
