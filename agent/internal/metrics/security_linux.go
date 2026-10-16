// SPDX-License-Identifier: Apache-2.0
//go:build linux && cgo

package metrics

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type authCursor struct {
	Version                 int
	Since                   string
	Dev, Ino                uint64
	Offset                  int64
	Anchor, Source, Journal string
	Seq                     uint64
	Partial                 bool
	Initialized             bool
}
type securityAdapter struct {
	cursor authCursor
	last   Stamp
}

var authPrefix = regexp.MustCompile(`^(\S+\s+\d+\s+\d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\S+)\s+\S+\s+sshd\[\d+\]: (.+)$`)
var authResult = regexp.MustCompile(`^(Failed|Accepted) (password|publickey|keyboard-interactive/pam) for (?:invalid user )?[^\s]+ from (\S+) port ([0-9]+)(?: ssh2.*)?$`)

// ParseOpenSSH accepts only explicit OpenSSH authentication results. PAM companion
// lines never count a second failure. Unsupported sshd messages lose coverage.
func parseSSHMessage(message string) (kind, address string, recognized bool) {
	if len(message) > 4096 {
		return "", "", false
	}
	match := authResult.FindStringSubmatch(message)
	if match != nil {
		ip, err := netip.ParseAddr(match[3])
		port, e := strconv.Atoi(match[4])
		if err != nil || e != nil || port < 1 || port > 65535 {
			return "", "", false
		}
		kind = "failure"
		if match[1] == "Accepted" {
			kind = "success"
		}
		return kind, ip.Unmap().String(), true
	}
	for _, prefix := range []string{"pam_unix(sshd:", "Connection closed by ", "Disconnected from ", "Received disconnect from ", "Connection reset by ", "Server listening on ", "Received signal ", "Invalid user ", "User child is on pid ", "Starting session:", "Close session:", "Failed none for ", "Did not receive identification string from ", "error: kex_exchange_identification:", "kex_exchange_identification:"} {
		if strings.HasPrefix(message, prefix) {
			return "", "", true
		}
	}
	return "", "", false
}
func parseAuthLine(line string, now time.Time) (string, string, time.Time, bool) {
	match := authPrefix.FindStringSubmatch(line)
	if match == nil {
		if strings.Contains(line, "sshd[") {
			return "", "", time.Time{}, false
		}
		return "", "", time.Time{}, true
	}
	at, err := time.Parse(time.RFC3339Nano, match[1])
	if err != nil {
		best := time.Duration(1<<63 - 1)
		for _, year := range []int{now.Year() - 1, now.Year(), now.Year() + 1} {
			candidate, e := time.ParseInLocation("2006 Jan 2 15:04:05", fmt.Sprintf("%d %s", year, match[1]), now.Location())
			if e != nil {
				continue
			}
			distance := now.Sub(candidate)
			if distance < 0 {
				distance = -distance
			}
			if distance < best {
				best = distance
				at = candidate
				err = nil
			}
		}
	}
	if err != nil || now.Sub(at) > 7*24*time.Hour || at.After(now.Add(time.Second)) {
		return "", "", time.Time{}, false
	}
	kind, address, known := parseSSHMessage(match[2])
	return kind, address, at, known
}
func cursorAnchor(file *os.File, offset int64, anchor func([]byte) (string, error)) (string, error) {
	start := max(int64(0), offset-8192)
	raw := make([]byte, offset-start)
	if _, err := file.ReadAt(raw, start); err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if anchor != nil {
		return anchor(raw)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func openAuth(path string) (*os.File, *syscall.Stat_t, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, nil, ErrUnavailable
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		f.Close()
		return nil, nil, ErrUnavailable
	}
	return f, stat, nil
}
func (l *Linux) authFile(ctx context.Context, s Stamp) ([]any, bool, error) {
	hooks := l.adapters.Security
	if hooks.Load == nil || hooks.Save == nil || hooks.Failure == nil || hooks.Progress == nil {
		return nil, false, ErrUnavailable
	}
	if l.security == nil {
		l.security = &securityAdapter{}
	}
	a := l.security
	{
		raw, err := hooks.Load(ctx, "ssh.auth")
		if err != nil {
			return nil, false, err
		}
		if len(raw) == 0 && a.cursor.Initialized {
			return nil, false, ErrUnavailable
		}
		if len(raw) > 0 && (len(raw) > 4096 || json.Unmarshal(raw, &a.cursor) != nil || a.cursor.Offset < 0 || len(a.cursor.Source) > 128 || a.cursor.Seq > 9223372036854775806 || a.cursor.Version != 1 || !a.cursor.Initialized || a.cursor.Seq == 0) {
			return nil, false, ErrUnavailable
		}
	}
	cursor := a.cursor
	path := l.path("/var/log/auth.log")
	file, stat, err := openAuth(path)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	valid := true
	reset := false
	if a.last.Mono > 0 && (s.Mono < a.last.Mono || absDuration(s.Wall.Sub(a.last.Wall)-(s.Mono-a.last.Mono)) > time.Second) {
		valid = false
	}
	a.last = s
	if !cursor.Initialized {
		// First enrollment starts at EOF: it must not manufacture a burst from old logins.
		cursor = authCursor{Version: 1, Dev: uint64(stat.Dev), Ino: stat.Ino, Offset: stat.Size, Source: id(), Seq: 1, Initialized: true}
		if cursor.Offset > 0 {
			var last [1]byte
			if _, e := file.ReadAt(last[:], cursor.Offset-1); e != nil {
				return nil, false, e
			}
			cursor.Partial = last[0] != '\n'
		}
		anchor, err := cursorAnchor(file, cursor.Offset, hooks.Anchor)
		if err != nil {
			return nil, false, err
		}
		cursor.Anchor = anchor
		raw, _ := json.Marshal(cursor)
		if err = hooks.Save(ctx, "ssh.auth", raw); err != nil {
			return nil, false, err
		}
		a.cursor = cursor
		if err = hooks.Progress(ctx, s.Wall, s.Mono, false); err != nil {
			return nil, false, err
		}
		return []any{}, false, nil
	}
	if cursor.Dev != uint64(stat.Dev) || cursor.Ino != stat.Ino {
		rotated, old, openErr := openAuth(l.path("/var/log/auth.log.1"))
		if openErr == nil && uint64(old.Dev) == cursor.Dev && old.Ino == cursor.Ino && old.Size > cursor.Offset {
			defer rotated.Close()
			file = rotated
			stat = old
		} else {
			if rotated != nil {
				rotated.Close()
			}
			if openErr != nil || old == nil || uint64(old.Dev) != cursor.Dev || old.Ino != cursor.Ino || old.Size != cursor.Offset {
				valid = false
			}
			reset = true
			cursor.Dev, cursor.Ino, cursor.Offset, cursor.Anchor, cursor.Source = uint64(stat.Dev), stat.Ino, 0, "", id()
		}
	}
	if cursor.Offset > stat.Size {
		reset = true
		cursor.Offset = 0
		cursor.Anchor = ""
		cursor.Source = id()
		valid = false
	}
	if cursor.Anchor != "" {
		anchor, err := cursorAnchor(file, cursor.Offset, hooks.Anchor)
		if err != nil {
			return nil, false, err
		}
		if anchor != cursor.Anchor {
			reset = true
			cursor.Offset = 0
			cursor.Source = id()
			valid = false
		}
	}
	if reset {
		if cursor.Seq >= 9223372036854775806 {
			return nil, false, ErrLimit
		}
		cursor.Seq++
		cursor.Anchor = ""
		raw, _ := json.Marshal(cursor)
		if err = hooks.Save(ctx, "ssh.auth", raw); err != nil {
			return nil, false, err
		}
		a.cursor = cursor
	}
	reader := bufio.NewReaderSize(io.NewSectionReader(file, cursor.Offset, 1048576), 8192)
	observations := []any{}
	processed := 0
	hitEOF := false
	for processed < 256 && ctx.Err() == nil {
		line, err := reader.ReadString('\n')
		if err != nil {
			hitEOF = errors.Is(err, io.EOF)
			if len(line) > 0 {
				valid = false
			}
			break
		}
		if len(line) > 8192 {
			return nil, false, ErrLimit
		}
		cursor.Offset += int64(len(line))
		processed++
		if cursor.Partial {
			cursor.Partial = false
			valid = false
			continue
		}
		kind, address, at, recognized := parseAuthLine(strings.TrimSuffix(line, "\n"), s.Wall.In(time.Local))
		if !recognized {
			valid = false
			continue
		}
		if kind == "failure" {
			age := s.Wall.Sub(at)
			if age < 0 || age > 5*time.Minute || age > s.Mono {
				valid = false
				continue
			}
			if err = hooks.Failure(ctx, AuthFailure{Source: cursor.Source, Address: address, Position: uint64(cursor.Offset), At: at, Mono: s.Mono - age}); err != nil {
				return nil, false, err
			}
		} else if kind == "success" {
			if hooks.Observation == nil {
				valid = false
			} else if err = hooks.Observation(ctx, AuthObservation{Source: cursor.Source, Position: uint64(cursor.Offset), At: at, Code: "SSH_AUTH_SUCCESS"}); err != nil {
				return nil, false, err
			}
			observations = append(observations, securityObservation("ssh_login", "SSH_AUTH_SUCCESS", at, "Successful SSH authentication observed"))
		}
	}
	if !hitEOF {
		valid = false
	}
	if cursor.Seq >= 9223372036854775806 {
		return nil, false, ErrLimit
	}
	cursor.Seq++
	anchor, err := cursorAnchor(file, cursor.Offset, hooks.Anchor)
	if err != nil {
		return nil, false, err
	}
	cursor.Anchor = anchor
	raw, _ := json.Marshal(cursor)
	if err = hooks.Save(ctx, "ssh.auth", raw); err != nil {
		return nil, false, err
	}
	a.cursor = cursor
	if err = hooks.Progress(ctx, s.Wall, s.Mono, valid); err != nil {
		return nil, false, err
	}
	return observations, valid, nil
}
func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
func securityObservation(kind, code string, at time.Time, summary string) any {
	return map[string]any{"kind": kind, "code": code, "observed_at": at.UTC().Format(time.RFC3339Nano), "summary": cleanLabel(summary, 512)}
}
func (l *Linux) collectSecurity(b *Block, s Stamp) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	observations := []any{}
	// The tables-only firewall profile cannot establish complete host coverage.
	complete := false
	available := 0
	osRelease, _ := l.read("/etc/os-release", 16384)
	supported := strings.Contains(osRelease, "ID=ubuntu") && strings.Contains(osRelease, `VERSION_ID="22.04"`) || strings.Contains(osRelease, "ID=debian") && (strings.Contains(osRelease, `VERSION_ID="11"`) || strings.Contains(osRelease, `VERSION_ID="12"`))
	if !supported {
		unavailableBlock(b, "unsupported", "SECURITY_OS_PROFILE_UNSUPPORTED")
		record(b, map[string]any{"record_type": "security", "resource_id": "security", "coverage": "unavailable", "observations": observations})
		return nil
	}
	auth, valid, err := l.authFile(ctx, s)
	if err != nil && os.IsNotExist(err) {
		auth, valid, err = l.authJournal(ctx, s)
	}
	status, reason := "available", ""
	if err != nil {
		status, reason = "source_error", "AUTH_SOURCE_UNAVAILABLE"
		if os.IsPermission(err) {
			status, reason = "permission_denied", "AUTH_PERMISSION_DENIED"
		}
		complete = false
		if l.adapters.Security.Progress != nil {
			_ = l.adapters.Security.Progress(ctx, s.Wall, s.Mono, false)
		}
	} else {
		available++
		observations = append(observations, auth...)
		if !valid {
			complete = false
			reason = "AUTH_COVERAGE_PARTIAL"
		}
	}
	if !valid && status == "available" {
		status = "source_error"
	}
	measure(b, "source_available", "security.ssh", "bool", func() any {
		if status != "available" {
			return nil
		}
		return true
	}(), status, reason, s)
	// Read-only nftables profile. Seeing an empty tables list is not proof that
	// another firewall backend is disabled, so coverage remains explicitly partial.
	raw, firewallErr := readCommand(ctx, "/usr/sbin/nft", 262144, "--json", "list", "tables")
	var tables struct{ Nftables []json.RawMessage }
	if firewallErr == nil && json.Unmarshal(raw, &tables) == nil && tables.Nftables != nil {
		available++
		observations = append(observations, securityObservation("firewall", "NFTABLES_VISIBLE", s.Wall, "nftables tables visible; rule effectiveness not inferred"))
	} else {
		complete = false
		if firewallErr == nil {
			firewallErr = ErrUnavailable
		}
	}
	sessions, sessionsErr := l.sshSessions(ctx, s)
	observations = append(observations, sessions...)
	if sessionsErr == nil {
		available++

	} else {
		complete = false
	}
	bans, bansErr := l.fail2ban(ctx, s)
	observations = append(observations, bans...)
	if bansErr == nil {
		available++

	} else {
		complete = false
	}

	for _, component := range []struct {
		id  string
		err error
	}{{"security.firewall", firewallErr}, {"security.sessions", sessionsErr}, {"security.fail2ban", bansErr}} {
		status, reason := "available", ""
		var value any = true
		if component.err != nil {
			value = nil
			status, reason = "source_error", "SECURITY_COMPONENT_UNAVAILABLE"
			if os.IsNotExist(component.err) {
				status, reason = "absent", "SECURITY_COMPONENT_NOT_INSTALLED"
			}
			if os.IsPermission(component.err) {
				status, reason = "permission_denied", "SECURITY_COMPONENT_PERMISSION_DENIED"
			}
		}
		measure(b, "source_available", component.id, "bool", value, status, reason, s)
	}
	coverage := "complete"
	if !complete {
		coverage = "partial"
		b.Reason = ptr("SECURITY_COVERAGE_PARTIAL")
	}
	if available == 0 {
		coverage = "unavailable"
		unavailableBlock(b, "source_error", "SECURITY_SOURCES_UNAVAILABLE")
	}
	record(b, map[string]any{"record_type": "security", "resource_id": "security", "coverage": coverage, "observations": observations})
	return nil
}
func (l *Linux) sshSessions(ctx context.Context, s Stamp) ([]any, error) {
	raw, err := readCommand(ctx, "/usr/bin/loginctl", 65536, "list-sessions", "--no-legend", "--no-pager")
	if err != nil {
		return nil, err
	}
	result := []any{}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) > 128 {
		return nil, ErrLimit
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		id := fields[0]
		if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`).MatchString(id) {
			return nil, ErrUnavailable
		}
		raw, err = readCommand(ctx, "/usr/bin/loginctl", 4096, "show-session", id, "--property=Remote", "--property=Service", "--property=State")
		if err != nil {
			return result, err
		}
		values := map[string]string{}
		for _, line := range strings.Split(string(raw), "\n") {
			k, v, ok := strings.Cut(line, "=")
			if ok {
				values[k] = v
			}
		}
		if values["Service"] == "sshd" && values["Remote"] == "yes" {
			result = append(result, securityObservation("ssh_session", "SSH_SESSION_VISIBLE", s.Wall, "SSH session "+id+" state="+values["State"]))
		}
	}
	return result, nil
}

var jailName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

func parseJails(raw []byte) ([]string, error) {
	if len(raw) > 65536 {
		return nil, ErrLimit
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if i := strings.Index(line, "Jail list:"); i >= 0 {
			names := strings.TrimSpace(line[i+len("Jail list:"):])
			if names == "" {
				return []string{}, nil
			}
			out := strings.Split(names, ",")
			if len(out) > 64 {
				return nil, ErrLimit
			}
			for i, n := range out {
				out[i] = strings.TrimSpace(n)
				if !jailName.MatchString(out[i]) {
					return nil, ErrUnavailable
				}
			}
			return out, nil
		}
	}
	return nil, ErrUnavailable
}
func (l *Linux) fail2ban(ctx context.Context, s Stamp) ([]any, error) {
	raw, err := readCommand(ctx, "/usr/bin/fail2ban-client", 65536, "status")
	if err != nil {
		return nil, err
	}
	jails, err := parseJails(raw)
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, jail := range jails {
		raw, err = readCommand(ctx, "/usr/bin/fail2ban-client", 65536, "status", jail)
		if err != nil {
			return out, err
		}
		banned, ips, err := parseBanList(raw)
		if err != nil {
			return out, err
		}
		for _, ip := range ips {
			if len(out) >= 512 {
				return out, ErrLimit
			}
			out = append(out, securityObservation("fail2ban", "FAIL2BAN_BAN_VISIBLE", s.Wall, "jail="+jail+" address="+ip))
		}
		out = append(out, securityObservation("fail2ban", "FAIL2BAN_JAIL_VISIBLE", s.Wall, "jail="+jail+" currently_banned="+banned))
	}
	return out, nil
}

// Journal profile is a fallback only: cursors are opaque, never interpreted as
// offsets. Output is bounded; truncated batches never establish quiet coverage.
func (l *Linux) authJournal(ctx context.Context, s Stamp) ([]any, bool, error) {
	hooks := l.adapters.Security
	if hooks.Load == nil || hooks.Save == nil || hooks.Failure == nil || hooks.Progress == nil {
		return nil, false, ErrUnavailable
	}
	var cursor authCursor
	raw, err := hooks.Load(ctx, "ssh.journal")
	if err != nil {
		return nil, false, err
	}
	if len(raw) > 4096 || len(raw) > 0 && json.Unmarshal(raw, &cursor) != nil {
		return nil, false, ErrUnavailable
	}
	if !cursor.Initialized {
		cursor.Version = 1
		cursor.Since = "@" + strconv.FormatInt(s.Wall.Unix(), 10)
	}
	if len(raw) > 0 && (cursor.Version != 1 || cursor.Seq == 0 || cursor.Seq > 9223372036854775806) {
		return nil, false, ErrUnavailable
	}
	args := []string{"--system", "--quiet", "--no-pager", "--output=json", "--no-tail", "--output-fields=__CURSOR,__REALTIME_TIMESTAMP,_BOOT_ID,_UID,_COMM,MESSAGE", "_COMM=sshd", "_UID=0"}
	if !cursor.Initialized {
		args = append(args, "--since="+cursor.Since)
	} else if cursor.Journal != "" {
		args = append(args, "--after-cursor="+cursor.Journal)
	} else {
		args = append(args, "--since="+cursor.Since)
	}
	raw, runErr := readCommand(ctx, "/usr/bin/journalctl", 1048576, args...)
	if runErr != nil && len(raw) == 0 {
		if cursor.Journal != "" && hooks.Observation != nil && ctx.Err() == nil {
			// Reset only after a separate successful bounded read proves journal access.
			probe, e := readCommand(ctx, "/usr/bin/journalctl", 65536, "--system", "--quiet", "--no-pager", "--output=json", "--lines=1", "--output-fields=__CURSOR,_BOOT_ID,_UID,_COMM", "_COMM=sshd", "_UID=0")
			latest, ok := journalTailCursor(probe)
			if e == nil && ok && latest != cursor.Journal && cursor.Seq < 9223372036854775806 {
				source := ref("ssh.journal.gap", cursor.Journal)
				position := cursor.Seq + 1
				if e = hooks.Observation(ctx, AuthObservation{Source: source, Position: position, At: s.Wall, Code: "AUTH_SOURCE_GAP"}); e != nil {
					return nil, false, e
				}
				cursor.Journal = latest
				cursor.Seq = position
				cursor.Initialized = true
				saved, _ := json.Marshal(cursor)
				if e = hooks.Save(ctx, "ssh.journal", saved); e != nil {
					return nil, false, e
				}
				if e = hooks.Progress(ctx, s.Wall, s.Mono, false); e != nil {
					return nil, false, e
				}
				return []any{}, false, nil
			}
		}
		return nil, false, runErr
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 8192), 65536)
	observations := []any{}
	valid := runErr == nil
	count := 0
	for scanner.Scan() {
		if count >= 256 {
			valid = false
			break
		}
		count++
		var entry struct {
			Cursor  string `json:"__CURSOR"`
			Micro   string `json:"__REALTIME_TIMESTAMP"`
			Boot    string `json:"_BOOT_ID"`
			UID     string `json:"_UID"`
			Comm    string `json:"_COMM"`
			Message string `json:"MESSAGE"`
		}
		if json.Unmarshal(scanner.Bytes(), &entry) != nil || entry.UID != "0" || entry.Comm != "sshd" || len(entry.Cursor) > 2048 || entry.Cursor == "" {
			valid = false
			continue
		}
		if cursor.Seq >= 9223372036854775806 {
			return nil, false, ErrLimit
		}
		cursor.Seq++
		micro, e := strconv.ParseInt(entry.Micro, 10, 64)
		if e != nil || micro < 0 {
			valid = false
			continue
		}
		at := time.UnixMicro(micro)
		kind, address, known := parseSSHMessage(entry.Message)
		if !known {
			valid = false
		}
		if kind == "failure" {
			age := s.Wall.Sub(at)
			if age < 0 || age > 5*time.Minute || age > s.Mono {
				valid = false
			} else {
				if err = hooks.Failure(ctx, AuthFailure{Source: ref("ssh.journal", entry.Boot), Address: address, Position: cursor.Seq, At: at, Mono: s.Mono - age}); err != nil {
					return nil, false, err
				}
			}
		} else if kind == "success" {
			if hooks.Observation == nil {
				valid = false
			} else if err = hooks.Observation(ctx, AuthObservation{Source: ref("ssh.journal", entry.Boot), Position: cursor.Seq, At: at, Code: "SSH_AUTH_SUCCESS"}); err != nil {
				return nil, false, err
			}
			observations = append(observations, securityObservation("ssh_login", "SSH_AUTH_SUCCESS", at, "Successful SSH authentication observed"))
		}
		cursor.Journal = entry.Cursor
	}
	if scanner.Err() != nil {
		valid = false
	}
	cursor.Initialized = true
	if cursor.Seq >= 9223372036854775806 {
		return nil, false, ErrLimit
	}
	cursor.Seq++
	encoded, _ := json.Marshal(cursor)
	if err = hooks.Save(ctx, "ssh.journal", encoded); err != nil {
		return nil, false, err
	}
	if err = hooks.Progress(ctx, s.Wall, s.Mono, valid); err != nil {
		return nil, false, err
	}
	return observations, valid, nil
}

// A bounded tail probe is accepted only with trusted sshd metadata and one cursor.
func journalTailCursor(raw []byte) (string, bool) {
	if len(raw) == 0 || len(raw) > 65536 {
		return "", false
	}
	var entry struct {
		Cursor string `json:"__CURSOR"`
		UID    string `json:"_UID"`
		Comm   string `json:"_COMM"`
		Boot   string `json:"_BOOT_ID"`
	}
	if json.Unmarshal(raw, &entry) != nil || entry.UID != "0" || entry.Comm != "sshd" || len(entry.Boot) != 32 || entry.Cursor == "" || len(entry.Cursor) > 2048 {
		return "", false
	}
	return entry.Cursor, true
}

func parseBanList(raw []byte) (string, []string, error) {
	if len(raw) > 65536 {
		return "", nil, ErrLimit
	}
	banned := ""
	ips := []string{}
	listSeen := false
	seen := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		if i := strings.Index(line, "Currently banned:"); i >= 0 {
			n, e := strconv.ParseUint(strings.TrimSpace(line[i+len("Currently banned:"):]), 10, 64)
			if e != nil {
				return "", nil, ErrUnavailable
			}
			banned = strconv.FormatUint(n, 10)
		}
		if i := strings.Index(line, "Banned IP list:"); i >= 0 {
			if listSeen {
				return "", nil, ErrUnavailable
			}
			listSeen = true
			for _, v := range strings.Fields(line[i+len("Banned IP list:"):]) {
				ip, e := netip.ParseAddr(v)
				if e != nil || len(ips) >= 512 {
					return "", nil, ErrUnavailable
				}
				address := ip.Unmap().String()
				if seen[address] {
					return "", nil, ErrUnavailable
				}
				seen[address] = true
				ips = append(ips, address)
			}
		}
	}
	if banned == "" || !listSeen || banned != strconv.Itoa(len(ips)) {
		return "", nil, ErrUnavailable
	}
	return banned, ips, nil
}
