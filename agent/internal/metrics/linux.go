// SPDX-License-Identifier: Apache-2.0
//go:build linux && cgo

package metrics

/*
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <unistd.h>
static long serverdeck_clock_ticks(void) { return sysconf(_SC_CLK_TCK); }
*/
import "C"

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"serverdeck.local/agent/internal/contracts"
)

type baseline struct {
	counters     []uint64
	mono         time.Duration
	segment, ref string
	cpus         int
}
type Linux struct {
	adapters                               AdapterOptions
	gpu                                    *gpuAdapter
	docker                                 *dockerAdapter
	security                               *securityAdapter
	root, boot                             string
	hz                                     uint64
	cpu, network, process                  map[string]baseline
	fs                                     map[string]string
	cpuSegment, netSegment, processSegment string
	fsSegment                              string
	readOverride                           func(string, int64) (string, error)
	namespaceOverride                      func(string) (uint64, error)
	fsPending                              map[string]chan fsResult
	fsSlots                                chan struct{}
	statOverride                           func(string, *syscall.Statfs_t) error
	cpuModel                               string
	cpuStaticUntil                         time.Duration
	cpuStaticAt                            contracts.Timestamp
	cpuTopology                            map[string]string
	netStaticUntil                         time.Duration
	netStaticAt                            contracts.Timestamp
	netDNS, netRoutes                      []string
	netMetadata                            map[string]networkMetadata
	netMetadataPartial                     bool
}

func NewLinux() (*Linux, error) { return linuxAt("/") }
func linuxAt(root string) (*Linux, error) {
	l := &Linux{root: root, hz: uint64(C.serverdeck_clock_ticks()), cpu: map[string]baseline{}, network: map[string]baseline{}, process: map[string]baseline{}, fs: map[string]string{}, fsPending: map[string]chan fsResult{}, fsSlots: make(chan struct{}, 4), netMetadata: map[string]networkMetadata{}}
	boot, e := l.read("/proc/sys/kernel/random/boot_id", 128)
	if e != nil || len(strings.TrimSpace(boot)) != 36 || l.hz == 0 || l.hz > 100000 {
		return nil, ErrUnavailable
	}
	l.boot = strings.TrimSpace(boot)
	return l, nil
}
func (l *Linux) BootID() string       { return l.boot }
func (l *Linux) path(p string) string { return filepath.Join(l.root, p) }
func (l *Linux) read(p string, limit int64) (string, error) {
	if l.readOverride != nil {
		return l.readOverride(p, limit)
	}
	f, e := os.Open(l.path(p))
	if e != nil {
		return "", e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil {
		return "", e
	}
	if int64(len(b)) > limit || !utf8.Valid(b) || strings.ContainsRune(string(b), 0) {
		return "", ErrLimit
	}
	return string(b), nil
}
func (l *Linux) text(p string, limit int64) string {
	s, _ := l.read(p, limit)
	return strings.TrimSpace(s)
}
func safe(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}
func ref(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:16])
}
func num(s string) (uint64, error) { return strconv.ParseUint(s, 10, 64) }
func multiply(a, b uint64) (uint64, bool) {
	if b != 0 && a > math.MaxUint64/b {
		return 0, false
	}
	return a * b, true
}
func (l *Linux) Collect(name string, s Stamp, ms int64, segment string) (Sample, error) {
	b := block(name, s, ms)
	var err error
	var ps []contracts.APIProcess
	switch name {
	case "gpu":
		err = l.collectGPU(&b, s)
	case "docker":
		err = l.collectDocker(&b, s)
	case "security":
		err = l.collectSecurity(&b, s)
	case "cpu":
		err = l.collectCPU(&b, s, segment)
	case "memory":
		err = l.collectMemory(&b, s)
	case "system":
		err = l.collectSystem(&b, s)
	case "network":
		err = l.collectNetwork(&b, s, segment)
	case "filesystems":
		if l.fsSegment != segment {
			l.fsPending = map[string]chan fsResult{}
			l.fsSegment = segment
		}
		err = l.collectFS(&b, s)
	case "processes":
		ps, err = l.collectProcesses(&b, s, segment)
	default:
		err = ErrUnavailable
	}
	return Sample{b, ps}, err
}

// ParseCPU excludes guest/guest_nice: Linux already counts them in user/nice.
func ParseCPU(text string) (map[string][]uint64, error) {
	out := map[string][]uint64{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || !strings.HasPrefix(f[0], "cpu") {
			continue
		}
		if len(f) < 9 {
			return nil, ErrUnavailable
		}
		if f[0] != "cpu" {
			v, e := strconv.Atoi(strings.TrimPrefix(f[0], "cpu"))
			if e != nil || v < 0 || v > 1048576 {
				return nil, ErrUnavailable
			}
		}
		if len(out) >= 257 {
			return nil, ErrLimit
		}
		values := make([]uint64, 8)
		for i := range values {
			n, e := num(f[i+1])
			if e != nil {
				return nil, ErrUnavailable
			}
			values[i] = n
		}
		if _, ok := out[f[0]]; ok {
			return nil, ErrUnavailable
		}
		out[f[0]] = values
	}
	if len(out) == 0 {
		return nil, ErrUnavailable
	}
	return out, nil
}
func CPUPercent(old, now []uint64) ([]float64, bool) {
	if len(old) != 8 || len(now) != 8 {
		return nil, false
	}
	delta := make([]float64, 8)
	total := float64(0)
	for i, n := range now {
		if n < old[i] {
			return nil, false
		}
		delta[i] = float64(n - old[i])
		total += delta[i]
	}
	if total <= 0 {
		return nil, false
	}
	out := make([]float64, 9)
	for i := range delta {
		out[i+1] = 100 * delta[i] / total
	}
	out[0] = 100 * (total - delta[3] - delta[4]) / total
	return out, true
}
func (l *Linux) collectCPU(b *Block, s Stamp, segment string) error {
	text, e := l.read("/proc/stat", 1000000)
	if e != nil {
		return e
	}
	now, e := ParseCPU(text)
	if e != nil {
		return e
	}
	if l.cpuSegment != segment {
		l.cpu = map[string]baseline{}
		l.cpuSegment = segment
		l.cpuStaticUntil = 0
	}
	keys := []string{}
	for k := range now {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	next := map[string]baseline{}
	model := ""
	if s.Mono >= l.cpuStaticUntil {
		cpuinfo, _ := l.read("/proc/cpuinfo", 1000000)
		for _, line := range strings.Split(cpuinfo, "\n") {
			if strings.HasPrefix(line, "model name") || strings.HasPrefix(line, "Hardware") {
				_, model, _ = strings.Cut(line, ":")
				model = strings.TrimSpace(model)
				break
			}
		}
		l.cpuModel = safe(model, 256)
		l.cpuStaticUntil = s.Mono + 60*time.Second
		l.cpuStaticAt = contracts.Timestamp(s.Wall.UTC())
		l.cpuTopology = map[string]string{}
	}
	model = l.cpuModel
	if model == "" {
		b.Reason = ptr("STATIC_FIELDS_UNAVAILABLE")
	}
	for _, k := range keys {
		old, exists := l.cpu[k]
		identity := old.ref
		if !exists {
			identity = ref(l.boot, k, id())
		}
		values, valid := CPUPercent(old.counters, now[k])
		if exists && !valid {
			for i, n := range now[k] {
				if n < old.counters[i] {
					identity = ref(l.boot, k, id())
					break
				}
			}
		}
		next[k] = baseline{counters: now[k], mono: s.Mono, segment: segment, ref: identity}
		names := []string{"busy_percent", "user_percent", "nice_percent", "system_percent", "idle_percent", "iowait_percent", "irq_percent", "softirq_percent", "steal_percent"}
		for i, key := range names {
			var v any
			availability, reason := "source_error", "BASELINE_REQUIRED"
			if valid {
				v = values[i]
				availability = "available"
				reason = ""
			}
			measure(b, key, identity, "percent", v, availability, reason, s)
		}
		if k != "cpu" {
			logical, _ := strconv.Atoi(strings.TrimPrefix(k, "cpu"))
			topology := l.cpuTopology[k]
			if topology == "" {
				topology = l.text("/sys/devices/system/cpu/"+k+"/topology/physical_package_id", 64) + ":" + l.text("/sys/devices/system/cpu/"+k+"/topology/core_id", 64)
				l.cpuTopology[k] = topology
			}
			record(b, map[string]any{"record_type": "cpu", "resource_id": identity, "logical_id": logical, "model": safe(model, 256), "topology": topology, "observed_at": l.cpuStaticAt})
			throttleText, throttleErr := l.read("/sys/devices/system/cpu/"+k+"/thermal_throttle/core_throttle_count", 64)
			throttle, parse := num(strings.TrimSpace(throttleText))
			if throttleErr == nil && parse == nil {
				measure(b, "throttle_events", identity, "count", contracts.U64(throttle), "available", "", s)
			} else {
				availability, reason := sourceFailure(throttleErr)
				measure(b, "throttle_events", identity, "count", nil, availability, reason, s)
			}
			v, err := l.read("/sys/devices/system/cpu/"+k+"/cpufreq/scaling_cur_freq", 64)
			hz, parse := num(strings.TrimSpace(v))
			h, ok := multiply(hz, 1000)
			if err == nil && parse == nil && ok {
				measure(b, "frequency_hz", identity, "hertz", contracts.U64(h), "available", "", s)
			} else {
				availability, reason := sourceFailure(err)
				measure(b, "frequency_hz", identity, "hertz", nil, availability, reason, s)
			}
		} else {
			var count any
			if len(now) > 1 {
				count = len(now) - 1
			}
			record(b, map[string]any{"record_type": "cpu_summary", "resource_id": identity, "logical_cpu_count": count})
			load, err := l.read("/proc/loadavg", 1024)
			f := strings.Fields(load)
			for i, key := range []string{"load1", "load5", "load15"} {
				var value any
				availability, reason := "source_error", "INVALID_SAMPLE"
				if err == nil && len(f) >= 3 {
					n, parse := strconv.ParseFloat(f[i], 64)
					if parse == nil && n >= 0 {
						value = n
						availability = "available"
						reason = ""
					}
				}
				measure(b, key, identity, "count", value, availability, reason, s)
			}
			pressure, err := l.read("/proc/pressure/cpu", 4096)
			for _, kind := range []string{"some", "full"} {
				if kind == "full" {
					measure(b, "psi_full_percent", identity, "percent", nil, "unsupported", "SYSTEM_CPU_FULL_UNDEFINED", s)
					continue
				}
				var value any
				availability, reason := sourceFailure(err)
				for _, line := range strings.Split(pressure, "\n") {
					f := strings.Fields(line)
					if len(f) > 1 && f[0] == kind {
						for _, v := range f[1:] {
							if strings.HasPrefix(v, "avg10=") {
								n, parse := strconv.ParseFloat(strings.TrimPrefix(v, "avg10="), 64)
								if parse == nil && n >= 0 && n <= 100 {
									value = n
									availability = "available"
									reason = ""
								}
							}
						}
					}
				}
				measure(b, "psi_"+kind+"_percent", identity, "percent", value, availability, reason, s)
			}
			value, availability, reason := l.cpuTemperature()
			measure(b, "temperature_c", identity, "celsius", value, availability, reason, s)
			// Event counters do not prove that throttling is active now.
			measure(b, "throttled", identity, "bool", nil, "unsupported", "CURRENT_STATE_UNSUPPORTED", s)
		}
	}
	l.cpu = next
	for k := range l.cpuTopology {
		if _, exists := next[k]; !exists {
			delete(l.cpuTopology, k)
		}
	}
	return nil
}
func sourceFailure(e error) (string, string) {
	if errors.Is(e, errStatTimeout) {
		return "source_error", "SOURCE_TIMEOUT"
	}
	if errors.Is(e, errStatBusy) {
		return "source_error", "SOURCE_BUSY"
	}
	if errors.Is(e, os.ErrPermission) {
		return "permission_denied", "PERMISSION_DENIED"
	}
	if errors.Is(e, os.ErrNotExist) {
		return "unsupported", "SOURCE_ABSENT"
	}
	return "source_error", "INVALID_SAMPLE"
}
func ParseMemory(text string) (map[string]uint64, error) {
	m := map[string]uint64{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "MemTotal:", "MemAvailable:", "MemFree:", "SwapTotal:", "SwapFree:":
			if len(f) != 3 || f[2] != "kB" {
				return nil, ErrUnavailable
			}
			n, e := num(f[1])
			v, ok := multiply(n, 1024)
			if e != nil || !ok {
				return nil, ErrUnavailable
			}
			if _, exists := m[f[0]]; exists {
				return nil, ErrUnavailable
			}
			m[f[0]] = v
		}
	}
	return m, nil
}
func (l *Linux) collectMemory(b *Block, s Stamp) error {
	text, e := l.read("/proc/meminfo", 65536)
	if e != nil {
		return e
	}
	m, e := ParseMemory(text)
	if e != nil {
		return e
	}
	identity := ref(l.boot, "memory")
	for key, field := range map[string]string{"total_bytes": "MemTotal:", "available_bytes": "MemAvailable:", "free_bytes": "MemFree:", "swap_total_bytes": "SwapTotal:"} {
		if v, ok := m[field]; ok {
			measure(b, key, identity, "byte", contracts.U64(v), "available", "", s)
		} else {
			measure(b, key, identity, "byte", nil, "source_error", "FIELD_ABSENT", s)
		}
	}
	for _, group := range []struct{ total, available, bytes, percent string }{{"MemTotal:", "MemAvailable:", "used_bytes", "used_percent"}, {"SwapTotal:", "SwapFree:", "swap_used_bytes", "swap_used_percent"}} {
		total, tok := m[group.total]
		available, aok := m[group.available]
		var used any
		availability, reason := "source_error", "INVALID_SAMPLE"
		if tok && aok && available <= total {
			used = contracts.U64(total - available)
			availability = "available"
			reason = ""
		}
		measure(b, group.bytes, identity, "byte", used, availability, reason, s)
		var percent any
		if availability == "available" && total > 0 {
			percent = 100 * float64(total-available) / float64(total)
		} else if total == 0 && tok {
			availability = "absent"
			reason = "ZERO_CAPACITY"
		}
		measure(b, group.percent, identity, "percent", percent, availability, reason, s)
	}
	return nil
}
func (l *Linux) collectSystem(b *Block, s Stamp) error {
	uptime, e := l.read("/proc/uptime", 1024)
	if e != nil {
		return e
	}
	f := strings.Fields(uptime)
	if len(f) < 1 {
		return ErrUnavailable
	}
	up, e := strconv.ParseFloat(f[0], 64)
	if e != nil || up < 0 || math.IsNaN(up) || math.IsInf(up, 0) {
		return ErrUnavailable
	}
	osName := l.text("/etc/os-release", 65536)
	for _, line := range strings.Split(osName, "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			osName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
			break
		}
	}
	machine := l.text("/etc/machine-id", 128)
	var machineID any
	if machine != "" {
		machineID = safe(machine, 128)
	}
	zone := l.text("/etc/timezone", 256)
	if zone == "" {
		name, offset := s.Wall.In(time.Local).Zone()
		zone = fmt.Sprintf("%s offset_seconds=%d", name, offset)
	}
	host, kernel := l.text("/proc/sys/kernel/hostname", 1024), l.text("/proc/sys/kernel/osrelease", 1024)
	if host == "" || kernel == "" || osName == "" || machineID == nil {
		b.Reason = ptr("LIMITED_VISIBILITY")
	}
	record(b, map[string]any{"record_type": "system", "resource_id": ref(l.boot, "system"), "hostname": safe(host, 256), "machine_id": machineID, "os": safe(osName, 256), "kernel": safe(kernel, 256), "architecture": runtime.GOARCH, "timezone": safe(zone, 128), "uptime_seconds": up})
	return nil
}

type processStat struct {
	pid, parent              int
	name, state              string
	user, system, start, rss uint64
	threads                  int64
}

func parseProcess(text string) (processStat, error) {
	var p processStat
	open := strings.IndexByte(text, '(')
	close := strings.LastIndexByte(text, ')')
	if open < 1 || close <= open {
		return p, ErrUnavailable
	}
	pid, e := strconv.Atoi(strings.TrimSpace(text[:open]))
	if e != nil || pid < 1 || pid > 4194304 {
		return p, ErrUnavailable
	}
	f := strings.Fields(text[close+1:])
	if len(f) < 22 {
		return p, ErrUnavailable
	}
	p.pid = pid
	p.name = safe(text[open+1:close], 256)
	p.state = f[0]
	if len(p.state) != 1 {
		return p, ErrUnavailable
	}
	p.parent, e = strconv.Atoi(f[1])
	if e != nil || p.parent < 0 {
		return p, ErrUnavailable
	}
	for index, target := range map[int]*uint64{11: &p.user, 12: &p.system, 19: &p.start, 21: &p.rss} {
		v, err := num(f[index])
		if err != nil {
			return p, ErrUnavailable
		}
		*target = v
	}
	p.threads, e = strconv.ParseInt(f[17], 10, 64)
	if e != nil || p.threads < 0 || p.threads > 10000000 {
		return p, ErrUnavailable
	}
	return p, nil
}
func (l *Linux) namespace(path string) (uint64, error) {
	if l.namespaceOverride != nil {
		return l.namespaceOverride(path)
	}
	info, e := os.Stat(l.path(path))
	if e != nil {
		return 0, e
	}
	v, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, ErrUnavailable
	}
	return v.Ino, nil
}
func (l *Linux) collectProcesses(b *Block, s Stamp, segment string) ([]contracts.APIProcess, error) {
	dir, e := os.Open(l.path("/proc"))
	if e != nil {
		return nil, e
	}
	defer dir.Close()
	names, e := dir.Readdirnames(65537)
	if e != nil && e != io.EOF {
		return nil, e
	}
	if len(names) > 65536 {
		return nil, ErrLimit
	}
	sort.Strings(names)
	if l.processSegment != segment {
		l.process = map[string]baseline{}
		l.processSegment = segment
	}
	statText, e := l.read("/proc/stat", 1000000)
	if e != nil {
		return nil, e
	}
	cpus, e := ParseCPU(statText)
	if e != nil {
		return nil, e
	}
	count := len(cpus) - 1
	if count < 1 {
		return nil, ErrUnavailable
	}
	next := map[string]baseline{}
	items := []contracts.APIProcess{}
	limited := false
	wireBytes := 0
	uptimeText, uptimeErr := l.read("/proc/uptime", 1024)
	upFields := strings.Fields(uptimeText)
	up := float64(0)
	if uptimeErr == nil && len(upFields) > 0 {
		up, uptimeErr = strconv.ParseFloat(upFields[0], 64)
	} else {
		uptimeErr = ErrUnavailable
	}
	parentIDs := map[int]string{}
	parents := map[int]int{}
	for _, name := range names {
		pid, parse := strconv.Atoi(name)
		if parse != nil || pid < 1 || pid > 4194304 {
			continue
		}
		if len(items) >= MaxRecords {
			limited = true
			break
		}
		base := "/proc/" + name
		before, err := l.read(base+"/stat", 16384)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				limited = true
			}
			continue
		}
		p, err := parseProcess(before)
		if err != nil || p.pid != pid {
			limited = true
			continue
		}
		ns, err := l.namespace(base + "/ns/pid")
		if err != nil {
			limited = true
			continue
		}
		status, err := l.read(base+"/status", 65536)
		if err != nil {
			limited = true
			continue
		}
		var uid int64 = -1
		for _, line := range strings.Split(status, "\n") {
			if strings.HasPrefix(line, "Uid:") {
				f := strings.Fields(line)
				if len(f) >= 2 {
					parsed, err := strconv.ParseInt(f[1], 10, 64)
					if err == nil {
						uid = parsed
					}
				}
				break
			}
		}
		if uid < 0 || uid > 4294967295 {
			limited = true
			continue
		}
		cgroup, groupErr := l.read(base+"/cgroup", 16384)
		after, err := l.read(base+"/stat", 16384)
		if err != nil {
			continue
		}
		again, err := parseProcess(after)
		nsAfter, nsErr := l.namespace(base + "/ns/pid")
		if err != nil || nsErr != nil || again.start != p.start || again.pid != p.pid || nsAfter != ns {
			limited = true
			continue
		}
		identity := ref(l.boot, name, strconv.FormatUint(p.start, 10), strconv.FormatUint(ns, 10))
		old, ok := l.process[identity]
		total, valid := multiply(1, p.user)
		if math.MaxUint64-p.user < p.system {
			valid = false
		} else {
			total = p.user + p.system
		}
		next[identity] = baseline{counters: []uint64{total}, mono: s.Mono, segment: segment, ref: identity, cpus: count}
		temp := block("processes", s, b.Interval)
		var cpu any
		var host any
		availability, reason := "source_error", "BASELINE_REQUIRED"
		if valid && ok && total >= old.counters[0] && s.Mono > old.mono {
			v := 100 * float64(total-old.counters[0]) / float64(l.hz) / (s.Mono - old.mono).Seconds()
			cpu = v
			availability = "available"
			reason = ""
			if old.cpus == count {
				host = v / float64(count)
			}
		}
		measure(&temp, "cpu_percent", identity, "percent", cpu, availability, reason, s)
		var age any
		ageAvailability, ageReason := "source_error", "INVALID_SAMPLE"
		if uptimeErr == nil && up >= float64(p.start)/float64(l.hz) {
			age = up - float64(p.start)/float64(l.hz)
			ageAvailability = "available"
			ageReason = ""
		}
		measure(&temp, "uptime_seconds", identity, "second", age, ageAvailability, ageReason, s)
		ha, hr := availability, reason
		if host == nil {
			ha = "source_error"
			hr = "BASELINE_REQUIRED"
		}
		measure(&temp, "cpu_host_percent", identity, "percent", host, ha, hr, s)
		rss, valid := multiply(p.rss, uint64(os.Getpagesize()))
		if valid {
			measure(&temp, "rss_bytes", identity, "byte", contracts.U64(rss), "available", "", s)
		} else {
			measure(&temp, "rss_bytes", identity, "byte", nil, "source_error", "INVALID_SAMPLE", s)
		}
		item := contracts.APIProcess{ProcessRef: identity, BootId: l.boot, Pid: int64(pid), StartTicks: contracts.U64(p.start), PidNamespace: contracts.U64(ns), Name: p.name, Uid: uid, State: p.state, ObservedAt: contracts.Timestamp(s.Wall.UTC()), Threads: p.threads, Visibility: "complete", Metrics: []contracts.APIMetric{}}
		item.Actions = make([]struct {
			Id        string  `json:"id"`
			Available bool    `json:"available"`
			Reason    *string `json:"reason"`
			Version   string  `json:"version"`
		}, 0)
		for _, m := range temp.Metrics {
			item.Metrics = append(item.Metrics, wireMetric(m))
		}
		if groupErr == nil {
			for _, line := range strings.Split(cgroup, "\n") {
				parts := strings.SplitN(line, ":", 3)
				if len(parts) == 3 {
					item.Cgroup = ptr(safe(parts[2], 1024))
					for _, part := range strings.Split(parts[2], "/") {
						if strings.HasSuffix(part, ".service") {
							item.SystemdUnit = ptr(safe(part, 256))
						}
					}
					break
				}
			}
		} else {
			item.Visibility = "limited"
		}
		encoded, encodeErr := json.Marshal(item)
		if encodeErr != nil || wireBytes+len(encoded) > 4000000 {
			limited = true
			break
		}
		wireBytes += len(encoded)
		items = append(items, item)
		parentIDs[pid] = identity
		parents[pid] = p.parent
	}
	for i := range items {
		if parent := parentIDs[parents[int(items[i].Pid)]]; parent != "" {
			items[i].ParentRef = ptr(parent)
		}
	}
	if limited {
		b.Reason = ptr("LIMITED_VISIBILITY")
		for i := range items {
			items[i].Visibility = "limited"
		}
	}
	l.process = next
	return items, nil
}

// Interface counters are tied to the network namespace, ifindex and a bounded
// observed generation. Deletion or any counter rollback starts a new identity.
func (l *Linux) collectNetwork(b *Block, s Stamp, segment string) error {
	text, e := l.read("/proc/net/dev", 1000000)
	if e != nil {
		return e
	}
	ns, e := l.namespace("/proc/self/ns/net")
	if e != nil {
		return e
	}
	if l.netSegment != segment {
		l.network = map[string]baseline{}
		l.netSegment = segment
		l.netStaticUntil = 0
		l.netMetadata = map[string]networkMetadata{}
	}
	interfaces, e := net.Interfaces()
	if e != nil {
		return e
	}
	index := map[string]net.Interface{}
	for _, n := range interfaces {
		index[n.Name] = n
	}
	next := map[string]baseline{}
	included := []string{}
	sumRX, sumTX := float64(0), float64(0)
	allValid := true
	if s.Mono >= l.netStaticUntil {
		l.netStaticAt = contracts.Timestamp(s.Wall.UTC())
		l.netMetadata = map[string]networkMetadata{}
		l.netDNS = []string{}
		l.netRoutes = []string{}
		l.netMetadataPartial = false
		dnsText, err := l.read("/etc/resolv.conf", 65536)
		if err != nil {
			l.netMetadataPartial = true
		}
		for _, line := range strings.Split(dnsText, "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == "nameserver" && net.ParseIP(f[1]) != nil {
				if len(l.netDNS) >= 64 {
					l.netMetadataPartial = true
					break
				}
				l.netDNS = append(l.netDNS, f[1])
			}
		}
		for _, version := range []string{"ipv4", "ipv6"} {
			path := "/proc/net/route"
			if version == "ipv6" {
				path = "/proc/net/ipv6_route"
			}
			text, err := l.read(path, 65536)
			if err != nil {
				l.netMetadataPartial = true
				continue
			}
			for i, line := range strings.Split(text, "\n") {
				f := strings.Fields(line)
				if len(f) == 0 || (version == "ipv4" && i == 0) {
					continue
				}
				if len(l.netRoutes) >= 256 {
					l.netMetadataPartial = true
					break
				}
				if version == "ipv4" && len(f) >= 11 {
					l.netRoutes = append(l.netRoutes, safe(f[0]+" ipv4 "+strings.Join(f[1:], " "), 512))
				} else if version == "ipv6" && len(f) >= 10 {
					l.netRoutes = append(l.netRoutes, safe(f[len(f)-1]+" ipv6 "+strings.Join(f[:len(f)-1], " "), 512))
				} else {
					l.netMetadataPartial = true
				}
			}
		}
		l.netStaticUntil = s.Mono + 60*time.Second
	}
	if l.netMetadataPartial {
		b.Reason = ptr("LIMITED_VISIBILITY")
	}
	dns, routes := l.netDNS, l.netRoutes
	for _, line := range strings.Split(text, "\n") {
		name, values, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		n, found := index[name]
		if !found {
			b.Reason = ptr("RESOURCE_CHANGED")
			continue
		}
		f := strings.Fields(values)
		if len(f) != 16 {
			return ErrUnavailable
		}
		counters := make([]uint64, 6)
		for i, field := range []int{0, 8, 2, 10, 3, 11} {
			v, err := num(f[field])
			if err != nil {
				return ErrUnavailable
			}
			counters[i] = v
		}
		key := fmt.Sprintf("%d:%d:%s", ns, n.Index, name)
		old, exists := l.network[key]
		valid := exists && s.Mono > old.mono
		for i, v := range counters {
			if exists && v < old.counters[i] {
				valid = false
				exists = false
				break
			}
		}
		identity := old.ref
		if !exists {
			identity = ref(l.boot, key, id())
		}
		next[key] = baseline{counters: counters, mono: s.Mono, segment: segment, ref: identity}
		for i, key := range []string{"rx_bytes", "tx_bytes", "rx_errors", "tx_errors", "rx_dropped", "tx_dropped"} {
			unit := "count"
			if i < 2 {
				unit = "byte"
			}
			measure(b, key, identity, unit, contracts.U64(counters[i]), "available", "", s)
		}
		rx, tx := float64(0), float64(0)
		for i, key := range []string{"rx_rate", "tx_rate"} {
			var value any
			availability, reason := "source_error", "BASELINE_REQUIRED"
			if valid {
				rate := float64(counters[i]-old.counters[i]) / (s.Mono - old.mono).Seconds()
				value = rate
				if i == 0 {
					rx = rate
				} else {
					tx = rate
				}
				availability = "available"
				reason = ""
			}
			measure(b, key, identity, "byte_per_second", value, availability, reason, s)
		}
		if n.Flags&net.FlagLoopback == 0 {
			included = append(included, identity)
			if valid {
				sumRX += rx
				sumTX += tx
			} else {
				allValid = false
			}
		}
		metadata, found := l.netMetadata[key]
		if !found || s.Mono >= metadata.until {
			addresses := []string{}
			a, err := n.Addrs()
			if err == nil {
				for _, v := range a {
					if len(addresses) < 128 {
						addresses = append(addresses, safe(v.String(), 128))
					}
				}
			} else {
				b.Reason = ptr("LIMITED_VISIBILITY")
			}
			speedText, speedErr := l.read("/sys/class/net/"+name+"/speed", 64)
			speed, parse := num(strings.TrimSpace(speedText))
			bps, speedOK := multiply(speed, 1000000)
			speedOK = speedOK && speedErr == nil && parse == nil && bps > 0
			var link any
			if speedOK {
				link = contracts.U64(bps)
			}
			var duplex any
			d := l.text("/sys/class/net/"+name+"/duplex", 64)
			if d == "half" || d == "full" {
				duplex = d
			}
			kind := "unknown"
			if n.Flags&net.FlagLoopback != 0 {
				kind = "loopback"
			} else if _, err := os.Stat(l.path("/sys/devices/virtual/net/" + name)); err == nil {
				kind = "virtual"
			} else if _, err := os.Stat(l.path("/sys/class/net/" + name + "/device")); err == nil {
				kind = "physical"
			}
			rs := []string{}
			for _, r := range routes {
				fields := strings.Fields(r)
				if len(fields) > 0 && fields[0] == name {
					rs = append(rs, r)
				}
			}
			metadata.record = map[string]any{"record_type": "network", "resource_id": identity, "name": safe(name, 256), "interface_type": kind, "addresses": addresses, "mtu": n.MTU, "routes": rs, "dns": dns, "duplex": duplex, "link_bps": link, "observed_at": l.netStaticAt, "operstate": safe(l.text("/sys/class/net/"+name+"/operstate", 64), 32)}
			metadata.bps = bps
			metadata.speedOK = speedOK
			metadata.until = s.Mono + 60*time.Second
			l.netMetadata[key] = metadata
		}
		metadata.record["resource_id"] = identity
		record(b, metadata.record)
		bps, speedOK := metadata.bps, metadata.speedOK
		var load any
		availability, reason := "unsupported", "LINK_SPEED_UNAVAILABLE"
		if valid && speedOK {
			load = 100 * 8 * math.Max(rx, tx) / float64(bps)
			availability = "available"
			reason = ""
		}
		measure(b, "link_load_percent", identity, "percent", load, availability, reason, s)

		if len(next) >= 256 {
			b.Reason = ptr("RESOURCE_LIMIT")
			break
		}
	}
	l.network = next
	for key := range l.netMetadata {
		if _, exists := next[key]; !exists {
			delete(l.netMetadata, key)
		}
	}
	sort.Strings(included)
	aggregate := ref(l.boot, "network-summary", strings.Join(included, ","))
	record(b, map[string]any{"record_type": "network_summary", "resource_id": aggregate, "included_resource_ids": included, "warning": "BRIDGE_VETH_DOUBLE_COUNT_POSSIBLE"})
	for key, value := range map[string]float64{"rx_rate": sumRX, "tx_rate": sumTX} {
		availability, reason := "available", ""
		var v any = value
		if !allValid || len(included) == 0 {
			availability = "source_error"
			reason = "BASELINE_REQUIRED"
			v = nil
		}
		measure(b, key, aggregate, "byte_per_second", v, availability, reason, s)
	}
	return nil
}
func unescapeMount(s string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			if i+3 >= len(s) {
				return "", ErrUnavailable
			}
			code := s[i+1 : i+4]
			switch code {
			case "040":
				out.WriteByte(' ')
			case "011":
				out.WriteByte('\t')
			case "012":
				out.WriteByte('\n')
			case "134":
				out.WriteByte('\\')
			default:
				return "", ErrUnavailable
			}
			i += 3
		} else {
			out.WriteByte(s[i])
		}
	}
	return out.String(), nil
}
func (l *Linux) collectFS(b *Block, s Stamp) error {
	text, e := l.read("/proc/self/mountinfo", 1000000)
	if e != nil {
		return e
	}
	ns, e := l.namespace("/proc/self/ns/mnt")
	if e != nil {
		return e
	}
	lines := strings.Split(text, "\n")
	sort.SliceStable(lines, func(i, j int) bool {
		a := strings.Fields(lines[i])
		bb := strings.Fields(lines[j])
		return len(a) > 4 && a[4] == "/" && (len(bb) <= 4 || bb[4] != "/")
	})
	next := map[string]string{}
	for _, line := range lines {
		if line == "" {
			continue
		}
		left, right, ok := strings.Cut(line, " - ")
		a, tail := strings.Fields(left), strings.Fields(right)
		if !ok || len(a) < 6 || len(tail) < 3 {
			return ErrUnavailable
		}
		mount, err := unescapeMount(a[4])
		if err != nil {
			return err
		}
		typ := tail[0]
		if mount != "/" && contains([]string{"proc", "sysfs", "devpts", "tmpfs", "cgroup", "cgroup2", "securityfs", "debugfs", "tracefs", "pstore", "mqueue", "hugetlbfs", "configfs", "fusectl", "autofs", "binfmt_misc", "rpc_pipefs", "nsfs", "overlay", "squashfs"}, typ) {
			continue
		}
		source, err := unescapeMount(tail[1])
		if err != nil {
			return err
		}
		if strings.Contains(source, "@") {
			source = "REDACTED_SOURCE"
			b.Reason = ptr("SOURCE_REDACTED")
		}
		key := fmt.Sprintf("%d:%s:%s:%s:%s", ns, a[0], a[2], mount, source)
		identity := l.fs[key]
		if identity == "" {
			identity = ref(l.boot, key, id())
		}
		next[key] = identity
		st, observed, statErr := l.fsStat(key, l.path(mount), s)
		if errors.Is(statErr, errHiddenMount) {
			delete(next, key)
			continue
		}
		record(b, map[string]any{"record_type": "filesystem", "resource_id": identity, "mountpoint": safe(mount, 4096), "source": safe(source, 4096), "filesystem_type": safe(typ, 80), "readonly": contains(strings.Split(a[5], ","), "ro")})
		err = statErr
		metricStamp := s
		if statErr == nil {
			metricStamp = observed
		}
		availability, reason := "available", ""
		if err != nil {
			availability, reason = sourceFailure(err)
			b.Reason = ptr("PARTIAL_SOURCE_FAILURE")
		}
		bytes := map[string]uint64{}
		valid := err == nil && st.Bsize > 0 && st.Frsize > 0 && st.Bfree <= st.Blocks && st.Bavail <= st.Bfree && st.Ffree <= st.Files
		if valid {
			for k, blocks := range map[string]uint64{"total_bytes": st.Blocks, "used_bytes": st.Blocks - st.Bfree, "available_bytes": st.Bavail, "reserved_bytes": st.Bfree - st.Bavail} {
				v, ok := multiply(blocks, uint64(st.Frsize))
				if !ok {
					valid = false
				}
				bytes[k] = v
			}
		}
		if err == nil && !valid {
			availability = "source_error"
			reason = "INVALID_SAMPLE"
		}
		for _, key := range []string{"total_bytes", "used_bytes", "available_bytes", "reserved_bytes"} {
			var value any
			if valid {
				value = contracts.U64(bytes[key])
			}
			measure(b, key, identity, "byte", value, availability, reason, metricStamp)
		}
		for key, v := range map[string]uint64{"inodes_total": st.Files, "inodes_available": st.Ffree} {
			var value any
			if valid {
				value = contracts.U64(v)
			}
			measure(b, key, identity, "count", value, availability, reason, metricStamp)
		}
		var percent any
		pa, pr := availability, reason
		denominator := float64(bytes["used_bytes"]) + float64(bytes["available_bytes"])
		if valid && denominator > 0 {
			percent = 100 * float64(bytes["used_bytes"]) / denominator
		} else if valid {
			pa = "absent"
			pr = "ZERO_CAPACITY"
		}
		measure(b, "used_percent", identity, "percent", percent, pa, pr, metricStamp)
		percent = nil
		pa, pr = availability, reason
		if valid && st.Files > 0 {
			percent = 100 * float64(st.Files-st.Ffree) / float64(st.Files)
		} else if valid {
			pa = "absent"
			pr = "ZERO_CAPACITY"
		}
		measure(b, "inodes_used_percent", identity, "percent", percent, pa, pr, metricStamp)
		if len(next) >= 256 {
			b.Reason = ptr("RESOURCE_LIMIT")
			break
		}
	}
	after, err := l.read("/proc/self/mountinfo", 1000000)
	if err != nil {
		return err
	}
	if after != text {
		return ErrUnavailable
	}
	l.fs = next
	for key := range l.fsPending {
		if _, exists := next[key]; !exists {
			delete(l.fsPending, key)
		}
	}
	return nil
}

// Compile-time assertions also keep accidental imports of command execution out
// of the collector. No subprocess, cmdline, environ, signal or write operation.
var _ Collector = (*Linux)(nil)

var errStatTimeout = errors.New("SOURCE_TIMEOUT")
var errStatBusy = errors.New("SOURCE_BUSY")
var errHiddenMount = errors.New("RESOURCE_CHANGED")

type fsResult struct {
	stat  syscall.Statfs_t
	stamp Stamp
	err   error
}

// Native statfs calls keep one of four slots until they really exit. A timeout
// cannot release a slot or create another native call for the same mount.
func (l *Linux) fsStat(key, path string, s Stamp) (syscall.Statfs_t, Stamp, error) {
	ch := l.fsPending[key]
	if ch == nil {
		select {
		case l.fsSlots <- struct{}{}:
		default:
			return syscall.Statfs_t{}, s, errStatBusy
		}
		ch = make(chan fsResult, 1)
		l.fsPending[key] = ch
		native := func(path string, st *syscall.Statfs_t) error { return l.boundStatfs(key, path, st) }
		if l.statOverride != nil {
			native = l.statOverride
		}
		started := time.Now()
		go func() {
			defer func() { <-l.fsSlots }()
			var st syscall.Statfs_t
			err := native(path, &st)
			elapsed := time.Since(started)
			ch <- fsResult{st, Stamp{s.Wall.Add(elapsed), s.Mono + elapsed}, err}
		}()
	}
	timer := time.NewTimer(10 * time.Millisecond)
	defer timer.Stop()
	select {
	case result := <-ch:
		delete(l.fsPending, key)
		return result.stat, result.stamp, result.err
	case <-timer.C:
		return syscall.Statfs_t{}, s, errStatTimeout
	}
}

// Pin the observed mount before reading its capacity. A pathname statfs could
// instead read an overmount while attaching values to a hidden mount ID.
func (l *Linux) boundStatfs(key, path string, st *syscall.Statfs_t) error {
	parts := strings.SplitN(key, ":", 3)
	if len(parts) != 3 {
		return ErrUnavailable
	}
	expected, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || expected == 0 {
		return ErrUnavailable
	}
	fd, err := syscall.Open(path, int(C.O_PATH)|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	info, err := l.read("/proc/self/fdinfo/"+strconv.Itoa(fd), 4096)
	if err != nil {
		return err
	}
	actual, err := mountID(info)
	if err != nil {
		return err
	}
	if actual != expected {
		return errHiddenMount
	}
	return syscall.Fstatfs(fd, st)
}
func mountID(info string) (uint64, error) {
	for _, line := range strings.Split(info, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "mnt_id:" {
			id, err := strconv.ParseUint(f[1], 10, 64)
			if err != nil || id == 0 {
				return 0, ErrUnavailable
			}
			return id, nil
		}
	}
	return 0, ErrUnavailable
}

// Only explicitly identified CPU thermal zones are used. Other sensors are not
// guessed to measure the CPU. The maximum of valid CPU zones is the aggregate.
func (l *Linux) cpuTemperature() (any, string, string) {
	dir, err := os.Open(l.path("/sys/class/thermal"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return l.hwmonTemperature()
		}
		a, r := sourceFailure(err)
		return nil, a, r
	}
	defer dir.Close()
	names, err := dir.Readdirnames(257)
	if err != nil && err != io.EOF {
		return nil, "source_error", "SOURCE_ERROR"
	}
	if len(names) > 256 {
		return nil, "source_error", "RESOURCE_LIMIT"
	}
	var temperature any
	availability, reason := "unsupported", "SUPPORTED_SENSOR_UNAVAILABLE"
	maximum := math.Inf(-1)
	for _, name := range names {
		if !strings.HasPrefix(name, "thermal_zone") {
			continue
		}
		kind, e := l.read("/sys/class/thermal/"+name+"/type", 128)
		if e != nil {
			if errors.Is(e, os.ErrPermission) {
				availability = "permission_denied"
				reason = "PERMISSION_DENIED"
			}
			continue
		}
		if !contains([]string{"x86_pkg_temp", "cpu-thermal", "cpu_thermal"}, strings.TrimSpace(kind)) {
			continue
		}
		text, e := l.read("/sys/class/thermal/"+name+"/temp", 64)
		v, parse := strconv.ParseInt(strings.TrimSpace(text), 10, 64)
		if e != nil {
			availability, reason = sourceFailure(e)
			continue
		}
		if parse != nil || v < -273150 || v > 1000000 {
			availability = "source_error"
			reason = "INVALID_SAMPLE"
			continue
		}
		value := float64(v) / 1000
		if value > maximum {
			maximum = value
			temperature = value
		}
	}
	if temperature != nil {
		return temperature, "available", ""
	}
	if value, a, r := l.hwmonTemperature(); value != nil || a == "permission_denied" || a == "source_error" {
		return value, a, r
	}
	return nil, availability, reason
}

// hwmon profiles distinguish measured Tdie from AMD's control-temperature
// offset (Tctl). An unrecognized label is not silently called CPU temperature.
func (l *Linux) hwmonTemperature() (any, string, string) {
	dir, err := os.Open(l.path("/sys/class/hwmon"))
	if err != nil {
		a, r := sourceFailure(err)
		return nil, a, r
	}
	defer dir.Close()
	names, err := dir.Readdirnames(65)
	if err != nil && err != io.EOF {
		return nil, "source_error", "SOURCE_ERROR"
	}
	if len(names) > 64 {
		return nil, "source_error", "RESOURCE_LIMIT"
	}
	maximum := math.Inf(-1)
	var value any
	availability, reason := "unsupported", "SUPPORTED_SENSOR_UNAVAILABLE"
	for _, name := range names {
		if !strings.HasPrefix(name, "hwmon") {
			continue
		}
		base := "/sys/class/hwmon/" + name
		driver := l.text(base+"/name", 128)
		if driver != "coretemp" && driver != "k10temp" {
			continue
		}
		entries, e := os.Open(l.path(base))
		if e != nil {
			availability, reason = sourceFailure(e)
			continue
		}
		files, e := entries.Readdirnames(1025)
		entries.Close()
		if e != nil && e != io.EOF {
			availability, reason = sourceFailure(e)
			continue
		}
		if len(files) > 1024 {
			return nil, "source_error", "RESOURCE_LIMIT"
		}
		sensors := 0
		for _, file := range files {
			if !strings.HasPrefix(file, "temp") || !strings.HasSuffix(file, "_input") {
				continue
			}
			index := strings.TrimSuffix(strings.TrimPrefix(file, "temp"), "_input")
			if _, e := strconv.ParseUint(index, 10, 16); e != nil {
				continue
			}
			sensors++
			if sensors > 128 {
				return nil, "source_error", "RESOURCE_LIMIT"
			}
			prefix := strings.TrimSuffix(file, "_input")
			label := l.text(base+"/"+prefix+"_label", 128)
			if driver == "k10temp" && label != "Tdie" {
				continue
			}
			if driver == "coretemp" && !strings.HasPrefix(label, "Package id ") && !strings.HasPrefix(label, "Core ") {
				continue
			}
			fault := l.text(base+"/"+prefix+"_fault", 64)
			if fault != "" && fault != "0" {
				availability = "source_error"
				reason = "SENSOR_FAULT"
				continue
			}
			text, e := l.read(base+"/"+file, 64)
			if e != nil {
				availability, reason = sourceFailure(e)
				continue
			}
			v, e := strconv.ParseInt(strings.TrimSpace(text), 10, 64)
			if e != nil || v < -273150 || v > 1000000 {
				availability = "source_error"
				reason = "INVALID_SAMPLE"
				continue
			}
			temperature := float64(v) / 1000
			if temperature > maximum {
				maximum = temperature
				value = temperature
			}
		}
	}
	if value != nil {
		return value, "available", ""
	}
	return nil, availability, reason
}

type networkMetadata struct {
	record  map[string]any
	bps     uint64
	speedOK bool
	until   time.Duration
}
