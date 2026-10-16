// SPDX-License-Identifier: Apache-2.0
//go:build linux && cgo

package metrics

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"os"
	"path/filepath"
	"serverdeck.local/agent/internal/contracts"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSMIProfileUnitsUnsupportedIdentityAndMalformed(t *testing.T) {
	stamp := Stamp{time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC), time.Second}
	input := []byte("GPU-11111111-1111-4111-8111-111111111111, Test GPU, 550.1, 0000:01:00.0, 42, 11, 100, 20, 70, 123.5, N/A\n")
	b, err := parseSMI(input, stamp, 2000)
	if err != nil || len(b.Records) != 1 {
		t.Fatal(err)
	}
	validateAdapterBlock(t, b)
	values := map[string]Metric{}
	for _, m := range b.Metrics {
		values[m.Key] = m
	}
	if values["vram_used_bytes"].Value != "20971520" || values["power_w"].Value != 123.5 || values["fan_percent"].Availability != "unsupported" || values["fan_percent"].Value != nil {
		t.Fatal("wrong units/zero substitution", values)
	}
	var record struct {
		UUID     string
		Resource string `json:"resource_id"`
	}
	json.Unmarshal(b.Records[0], &record)
	if record.Resource == "0" || record.UUID == "" {
		t.Fatal("index identity")
	}
	for _, bad := range []string{strings.Replace(string(input), "42,", "NaN,", 1), strings.Replace(string(input), "42,", "101,", 1), strings.Replace(string(input), "100,", "-1,", 1), string(input) + string(input), "bad,row"} {
		if _, err := parseSMI([]byte(bad), stamp, 2000); err == nil {
			t.Fatal("malformed SMI accepted", bad)
		}
	}
	for code, want := range map[nvml.Return]string{nvml.ERROR_NO_PERMISSION: "permission_denied", nvml.ERROR_NOT_SUPPORTED: "unsupported", nvml.ERROR_LIBRARY_NOT_FOUND: "source_error", nvml.ERROR_DRIVER_NOT_LOADED: "source_error"} {
		status, _ := nvmlStatus(code)
		if status != want {
			t.Fatal(code, status)
		}
	}
}

func TestAuthFileRotationCopyTruncateAndLostCursorAck(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "var/log/auth.log")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, nil, 0600)
	durable := map[string][]byte{}
	dedup := map[string]bool{}
	effects := 0
	loseAck := false
	failureBeforeCommit := false
	hooks := SecurityHooks{
		Load: func(_ context.Context, key string) ([]byte, error) { return append([]byte{}, durable[key]...), nil },
		Save: func(_ context.Context, key string, b []byte) error {
			if failureBeforeCommit {
				failureBeforeCommit = false
				return ErrUnavailable
			}
			durable[key] = append([]byte{}, b...)
			if loseAck {
				loseAck = false
				return ErrUnavailable
			}
			return nil
		},
		Failure: func(_ context.Context, f AuthFailure) error {
			key := f.Source + ":" + strconv.FormatUint(f.Position, 10)
			if !dedup[key] {
				dedup[key] = true
				effects++
			}
			return nil
		},
		Observation: func(context.Context, AuthObservation) error { return nil },
		Progress:    func(context.Context, time.Time, time.Duration, bool) error { return nil },
	}
	l := &Linux{root: root, adapters: AdapterOptions{Security: hooks}}
	base := time.Date(2026, 10, 15, 0, 0, 0, 0, time.Local)
	observe := func(seconds int) (bool, error) {
		_, valid, err := l.authFile(context.Background(), Stamp{base.Add(time.Duration(seconds) * time.Second), time.Duration(seconds+60) * time.Second})
		return valid, err
	}
	if _, err := observe(0); err != nil {
		t.Fatal(err)
	}
	appendLine := func(path string, second int) {
		t.Helper()
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		_, err = f.WriteString(base.Add(time.Duration(second)*time.Second).Format(time.RFC3339) + " host sshd[123]: Failed password for fixture from 203.0.113.7 port 2222 ssh2\n")
		if err != nil {
			t.Fatal(err)
		}
	}
	appendLine(path, 1)
	loseAck = true
	if _, err := observe(2); err == nil {
		t.Fatal("lost ack hidden")
	}
	if _, err := observe(3); err != nil || effects != 1 {
		t.Fatal("duplicate after acknowledged cursor loss", effects, err)
	}
	// Drain renamed inode first, then enroll the replacement before its first effect.
	appendLine(path, 4)
	os.Rename(path, path+".1")
	appendLine(path, 5)
	if _, err := observe(6); err != nil {
		t.Fatal(err)
	}
	loseAck = true
	if _, err := observe(7); err == nil {
		t.Fatal("reset ack loss hidden")
	}
	if _, err := observe(8); err != nil || effects != 3 {
		t.Fatal("new generation was not durable before effect", effects, err)
	}
	// Truncate/rewrite old offsets: anchor detects a new physical stream.
	os.WriteFile(path, nil, 0600)
	appendLine(path, 9)
	failureBeforeCommit = true
	if _, err := observe(10); err == nil {
		t.Fatal("generation intent failure hidden")
	}
	if effects != 3 {
		t.Fatal("effect preceded durable generation")
	}
	if _, err := observe(11); err != nil || effects != 4 {
		t.Fatal(effects, err)
	}
	// Reopening resumes persisted cursor instead of importing the same failures.
	l = &Linux{root: root, adapters: AdapterOptions{Security: hooks}}
	if _, err := observe(12); err != nil || effects != 4 {
		t.Fatal("restart duplicate", effects, err)
	}
	os.WriteFile(path, []byte("Oct 15 00:00:13 host sshd[1]: unsupported authentication provider\n"), 0600)
	valid, err := observe(14)
	if err != nil || valid {
		t.Fatal("unknown format became quiet coverage", valid, err)
	}
}

func TestOpenSSHProfileDoesNotDoubleCountPAMOrExposeUsers(t *testing.T) {
	now := time.Date(2026, 10, 15, 1, 0, 0, 0, time.FixedZone("test", 3*3600))
	kind, addr, at, ok := parseAuthLine("Oct 15 01:00:00 host sshd[77]: Failed password for invalid user sensitive-value from ::ffff:203.0.113.9 port 22 ssh2", now)
	if !ok || kind != "failure" || addr != "203.0.113.9" || !at.Equal(now) {
		t.Fatal("local time/IP profile", kind, addr, at, ok)
	}
	kind, _, ok = parseSSHMessage("pam_unix(sshd:auth): authentication failure; rhost=203.0.113.9")
	if !ok || kind != "" {
		t.Fatal("PAM duplicated explicit failure")
	}
	kind, _, ok = parseSSHMessage("Accepted publickey for sensitive-value from 2001:db8::1 port 2222 ssh2: ED25519 SHA256:fixture")
	if !ok || kind != "success" {
		t.Fatal("success not recognized")
	}
	if _, _, ok = parseSSHMessage("Failed password for user from not-an-address port 22 ssh2"); ok {
		t.Fatal("malformed address accepted")
	}
	if _, err := parseJails([]byte("Jail list: --evil")); err == nil {
		t.Fatal("option-shaped jail accepted")
	}
	if jails, err := parseJails([]byte("Status\n`- Jail list: sshd, nginx-http-auth\n")); err != nil || len(jails) != 2 {
		t.Fatal(jails, err)
	}

}

func FuzzSSHProfile(f *testing.F) {
	for _, s := range []string{"Failed password for invalid user test from 192.0.2.1 port 22 ssh2", "Accepted publickey for test from 2001:db8::1 port 65535 ssh2", "pam_unix(sshd:auth): authentication failure", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		kind, address, known := parseSSHMessage(s)
		if kind != "" && (!known || address == "") {
			t.Fatal("invalid accepted classification")
		}
	})
}

func TestFail2banUnknownOrIncompleteListCannotClaimCoverage(t *testing.T) {
	good := []byte("Status for the jail: sshd\n|- Currently banned: 2\n`- Banned IP list: 192.0.2.1 2001:db8::1\n")
	n, ips, err := parseBanList(good)
	if err != nil || n != "2" || len(ips) != 2 {
		t.Fatal(n, ips, err)
	}
	for _, raw := range []string{"Currently banned: 0", "Banned IP list:", "Currently banned: 1\nBanned IP list:", "Currently banned: 1\nBanned IP list: not-ip", "Currently banned: 2\nBanned IP list: 192.0.2.1 192.0.2.1"} {
		if _, _, err := parseBanList([]byte(raw)); err == nil {
			t.Fatal("incomplete accepted")
		}
	}
}
func TestJournalRecoveryProbeRequiresTrustedMetadata(t *testing.T) {
	good := []byte(`{"__CURSOR":"opaque","_UID":"0","_COMM":"sshd","_BOOT_ID":"11111111111111111111111111111111"}`)
	if cursor, ok := journalTailCursor(good); !ok || cursor != "opaque" {
		t.Fatal(cursor, ok)
	}
	for _, raw := range []string{"{}", strings.Replace(string(good), `"0"`, `"1000"`, 1), strings.Replace(string(good), `"sshd"`, `"other"`, 1), string(good) + string(good)} {
		if _, ok := journalTailCursor([]byte(raw)); ok {
			t.Fatal("untrusted probe accepted")
		}
	}
}

func validateAdapterBlock(t *testing.T, b Block) {
	t.Helper()
	id := "11111111-1111-4111-8111-111111111111"
	s := Snapshot{ID: id, RunID: id, BootID: id, SegmentID: id, At: contracts.Timestamp(time.Now().UTC()), Blocks: []Block{b}, Partial: true}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = contracts.Validate(bytes.NewReader(raw), contracts.Target{Family: "api", Definition: "Snapshot"}, 1000000); err != nil {
		t.Fatal("adapter violates snapshot contract", err)
	}
}
func TestSecurityObservationsMatchExistingContract(t *testing.T) {
	stamp := Stamp{Wall: time.Now().UTC(), Mono: time.Second}
	b := block("security", stamp, 15000)
	record(&b, map[string]any{"record_type": "security", "resource_id": "security", "coverage": "partial", "observations": []any{securityObservation("fail2ban", "FAIL2BAN_BAN_VISIBLE", stamp.Wall, "jail=sshd address=192.0.2.1"), securityObservation("ssh_login", "SSH_AUTH_SUCCESS", stamp.Wall, "Successful SSH authentication observed")}})
	validateAdapterBlock(t, b)
}

type deniedNVML struct {
	nvml.Interface
	uuidDenied bool
}

func (deniedNVML) DeviceGetCount() (int, nvml.Return)             { return 1, nvml.SUCCESS }
func (deniedNVML) SystemGetDriverVersion() (string, nvml.Return)  { return "fixture", nvml.SUCCESS }
func (deniedNVML) SystemGetCudaDriverVersion() (int, nvml.Return) { return 0, nvml.ERROR_NOT_SUPPORTED }
func (d deniedNVML) DeviceGetHandleByIndex(int) (nvml.Device, nvml.Return) {
	if d.uuidDenied {
		return deniedUUID{}, nvml.SUCCESS
	}
	return nil, nvml.ERROR_NO_PERMISSION
}

type deniedUUID struct{ nvml.Device }

func (deniedUUID) GetUUID() (string, nvml.Return) { return "", nvml.ERROR_NO_PERMISSION }
func TestNVMLIdentityPermissionIsNotGenericError(t *testing.T) {
	for _, uuidDenied := range []bool{false, true} {
		l := &Linux{gpu: &gpuAdapter{lib: deniedNVML{uuidDenied: uuidDenied}, init: nvml.SUCCESS, started: true}}
		stamp := Stamp{Wall: time.Now().UTC(), Mono: time.Second}
		b := block("gpu", stamp, 2000)
		if err := l.collectGPU(&b, stamp); err != nil || b.Availability != "permission_denied" || b.Reason == nil || *b.Reason != "NVML_NO_PERMISSION" {
			t.Fatal(b, err)
		}
		validateAdapterBlock(t, b)
	}
}
