// SPDX-License-Identifier: Apache-2.0
package operations

import (
	"errors"
	"serverdeck.local/agent/internal/storage"
	"testing"
)

func TestPostIntentPreflightErrorRemainsTyped(t *testing.T) {
	for _, e := range []error{storage.ErrStorage, storage.ErrAudit, storage.ErrVersion, storage.ErrInvalid, storage.ErrBusy, storage.ErrQuota, errors.New("PROTECTED_OBJECT"), errors.New("PERMISSION_DENIED")} {
		if code := checkedErrorCode(e); code != e.Error() {
			t.Fatalf("%s misclassified as %s", e, code)
		}
	}
	if checkedErrorCode(errors.New("fixture private detail")) != "SAFETY_UNAVAILABLE" {
		t.Fatal("unknown preflight detail leaked")
	}
}
