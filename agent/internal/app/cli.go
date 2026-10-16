// SPDX-License-Identifier: Apache-2.0
package app

import (
	"fmt"
	"io"
	"os"
	"runtime"

	"serverdeck.local/agent/internal/config"
	"serverdeck.local/agent/internal/contracts"
)

// Run selects finite offline commands or an explicitly configured Linux service.
// Only implemented adapters are registered with the guarded application service.
func Run(name string, args []string, out, errOut io.Writer) int {
	if name == "serverdeckctl" && len(args) == 5 && args[0] == "local" && args[1] == "--config" {
		if e := nativeLocalCommand(args[2], args[3], args[4], out); e != nil {
			fmt.Fprintln(errOut, e)
			return 1
		}
		return 0
	}
	if len(args) == 3 && args[1] == "--config" && ((name == "serverdeck-agent" && args[0] == "serve") || (name == "serverdeckctl" && args[0] == "pairing-issue")) {
		if e := nativeCommand(name, args[2], out); e != nil {
			fmt.Fprintln(errOut, e)
			return 1
		}
		return 0
	}
	if name == "serverdeckctl" {
		if code, handled := stateCommand(args, out, errOut); handled {
			return code
		}
	}
	if len(args) == 1 && args[0] == "version" {
		fmt.Fprintf(out, "%s development E08 api=1 schema=1.0 ipc=1 %s %s/%s\n", name, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return 0
	}
	if len(args) == 1 && args[0] == "sqlite-info" {
		s, e := sqliteInfo()
		if e != nil {
			fmt.Fprintln(errOut, "NATIVE_DEPENDENCY_UNAVAILABLE")
			return 1
		}
		fmt.Fprintln(out, s)
		return 0
	}
	if len(args) == 2 && args[0] == "validate-config" {
		f, e := os.Open(args[1])
		if e != nil {
			fmt.Fprintln(errOut, "CONFIG_READ_FAILED")
			return 1
		}
		defer f.Close()
		if _, e = config.Load(f); e != nil {
			fmt.Fprintln(errOut, e)
			return 1
		}
		fmt.Fprintln(out, "OK: structure and pure semantics; Linux filesystem/credentials/TLS preflight NOT performed")
		return 0
	}
	if len(args) == 4 && args[0] == "check-contract" {
		t := contracts.Target{Family: args[1], Definition: args[2]}
		if t.Definition == "-" {
			t.Definition = ""
		}
		f, e := os.Open(args[3])
		if e != nil {
			fmt.Fprintln(errOut, "INPUT_READ_FAILED")
			return 1
		}
		defer f.Close()
		if _, e = contracts.Validate(f, t, contracts.MaxJSONBytes); e != nil {
			fmt.Fprintln(errOut, e)
			return 1
		}
		fmt.Fprintln(out, "OK: contract shape; authorization, signatures and effects NOT verified")
		return 0
	}
	fmt.Fprintf(errOut, "Usage: %s version | sqlite-info | validate-config FILE | check-contract FAMILY DEFINITION_OR_DASH FILE\nserverdeck-agent serve --config FILE\nserverdeckctl pairing-issue --config FILE\nserverdeckctl local --config FILE query|prepare|execute INPUT_JSON | download|upload TRANSFER_JSON (upload reads stdin; download writes stdout)\nserverdeckctl: state-files STATE | state-file-reconcile STATE CONFIG INPUT_JSON ID --confirm | state-inventory-confirm STATE INPUT_JSON ID --confirm | state-init STATE CONFIG | state-status STATE | state-inventory STATE | state-operation STATE ID | state-backup STATE DEST ID --confirm | state-restore STATE BACKUP DEST ID --confirm | state-resolve STATE ID applied|none --confirm\n", name)
	return 2
}
