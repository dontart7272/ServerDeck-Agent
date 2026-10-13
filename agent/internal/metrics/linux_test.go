// SPDX-License-Identifier: Apache-2.0
//go:build linux && cgo

package metrics

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"serverdeck.local/agent/internal/contracts"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func fixture(t *testing.T) *Linux {
	t.Helper()
	root := t.TempDir()
	p := filepath.Join(root, "proc/sys/kernel/random")
	if e := os.MkdirAll(p, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(p, "boot_id"), []byte(testBoot), 0600); e != nil {
		t.Fatal(e)
	}
	l, e := linuxAt(root)
	if e != nil {
		t.Fatal(e)
	}
	return l
}
func put(t *testing.T, l *Linux, path, text string) {
	t.Helper()
	p := l.path(path)
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(p, []byte(text), 0600); e != nil {
		t.Fatal(e)
	}
}
func TestCPUFormulaGuestResetZeroAndHotplug(t *testing.T) {
	a, e := ParseCPU("cpu 100 20 30 400 50 6 7 8 99 88\ncpu0 100 20 30 400 50 6 7 8 99 88\n")
	if e != nil {
		t.Fatal(e)
	}
	b, e := ParseCPU("cpu 110 20 40 420 60 6 7 18 100 99\n")
	if e != nil {
		t.Fatal(e)
	}
	v, ok := CPUPercent(a["cpu"], b["cpu"])
	if !ok || v[0] != 50 || v[1] != 100.0/6 {
		t.Fatal(v)
	}
	if _, ok = CPUPercent(b["cpu"], a["cpu"]); ok {
		t.Fatal("negative derivative")
	}
	if _, ok = CPUPercent(a["cpu"], a["cpu"]); ok {
		t.Fatal("zero denominator")
	}
	for _, text := range []string{"cpu 1 2", "cpu0 -1 0 0 0 0 0 0 0", "cpu 0 0 0 0 0 0 0 0\ncpu 0 0 0 0 0 0 0 0"} {
		if _, e := ParseCPU(text); e == nil {
			t.Fatal("accepted invalid", text)
		}
	}
	l := fixture(t)
	now := stamp()
	put(t, l, "/proc/stat", "cpu 100 0 0 100 0 0 0 0\ncpu0 100 0 0 100 0 0 0 0\n")
	first, _ := l.Collect("cpu", now, 2000, "one")
	var old string
	for _, m := range first.Block.Metrics {
		if m.Key == "busy_percent" {
			old = m.ResourceID
			break
		}
	}
	if first.Block.Metrics[0].Value != nil {
		t.Fatal("first sample substituted zero")
	}
	put(t, l, "/proc/stat", "cpu 1 0 0 1 0 0 0 0\n")
	now.Mono = time.Second
	reset, _ := l.Collect("cpu", now, 2000, "one")
	if reset.Block.Metrics[0].Value != nil || reset.Block.Metrics[0].ResourceID == old {
		t.Fatal("reset reused identity")
	}
	put(t, l, "/proc/stat", "cpu 2 0 0 2 0 0 0 0\ncpu0 2 0 0 2 0 0 0 0\n")
	hotplug, _ := l.Collect("cpu", now, 2000, "one")
	if len(hotplug.Block.Records) != 2 {
		t.Fatal("hotplug did not reappear")
	}
}
func TestMemoryNoFreeFallbackNoSwapAndOverflow(t *testing.T) {
	l := fixture(t)
	now := stamp()
	put(t, l, "/proc/meminfo", "MemTotal: 100 kB\nMemFree: 20 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n")
	sample, err := l.Collect("memory", now, 2000, "x")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range sample.Block.Metrics {
		if m.Key == "used_bytes" && m.Value != nil {
			t.Fatal("MemFree substituted for MemAvailable")
		}
		if m.Key == "swap_used_percent" && (m.Value != nil || m.Availability != "absent") {
			t.Fatal("no swap status", m)
		}
	}
	put(t, l, "/proc/meminfo", "MemTotal: 100 kB\nMemAvailable: 40 kB\nMemFree: 20 kB\n")
	sample, _ = l.Collect("memory", now, 2000, "x")
	for _, m := range sample.Block.Metrics {
		if m.Key == "used_bytes" && m.Value != contracts.U64(60*1024) {
			t.Fatal("RAM formula", m)
		}
	}
	for _, text := range []string{"MemTotal: 18446744073709551615 kB", "MemTotal: -1 kB", "MemTotal: 1 MB", "MemTotal: 1 kB\nMemTotal: 2 kB"} {
		if _, err := ParseMemory(text); err == nil {
			t.Fatal("accepted bad memory", text)
		}
	}
}
func TestProcessParserNameParenthesesMissingFieldsAndReuse(t *testing.T) {
	text := "123 (name ) tricky) R 1 0 0 0 0 0 0 0 0 0 10 5 0 0 0 0 2 0 100 9999 3 0"
	p, err := parseProcess(text)
	if err != nil || p.name != "name ) tricky" || p.user != 10 || p.system != 5 || p.start != 100 || p.rss != 3 || p.threads != 2 {
		t.Fatal(p, err)
	}
	for _, text := range []string{"1 (a) R", "0 (a) R", "123 invalid", "123 (a) R 1 0 0 0 0 0 0 0 0 0 -1"} {
		if _, err := parseProcess(text); err == nil {
			t.Fatal("bad process")
		}
	}
	if ref(testBoot, "123", "100", "1") == ref(testBoot, "123", "101", "1") || ref(testBoot, "123", "100", "1") == ref(testBoot, "123", "100", "2") {
		t.Fatal("reused PID identity")
	}
}
func TestNativeLinuxReadOnlySourcesAndContracts(t *testing.T) {
	l, err := NewLinux()
	if err != nil {
		t.Fatal(err)
	}
	now := stamp()
	now.Wall = time.Now()
	for _, name := range []string{"system", "cpu", "memory", "network", "filesystems", "processes"} {
		sample, e := l.Collect(name, now, interval(name, false), "fixture")
		if e != nil {
			t.Fatal(name, e)
		}
		if sample.Block.ID != name || sample.Block.Availability != "available" {
			t.Fatal(name, "block status")
		}
		for _, p := range sample.Processes {
			var out bytes.Buffer
			if e := contracts.Encode(&out, contracts.Target{Family: "api", Definition: "Process"}, p, contracts.MaxJSONBytes); e != nil {
				t.Fatal(name, "process wire", e)
			}
			if p.Pid == int64(os.Getpid()) && p.StartTicks == 0 {
				t.Fatal("self identity missing")
			}
		}
		snap := Snapshot{id(), testBoot, l.BootID(), id(), contracts.Timestamp(now.Wall.UTC()), []Block{sample.Block}, true}
		var out bytes.Buffer
		if e := contracts.Encode(&out, contracts.Target{Family: "api", Definition: "Snapshot"}, snap, contracts.MaxJSONBytes); e != nil {
			t.Fatal(name, "snapshot wire", e)
		}
		raw, _ := json.Marshal(sample)
		if strings.Contains(string(raw), "cmdline") || strings.Contains(string(raw), "environ") {
			t.Fatal("secret source")
		}
		t.Log(name, "metrics", len(sample.Block.Metrics), "records", len(sample.Block.Records), "processes", len(sample.Processes), "wire bytes", out.Len())
	}
	t.Log("UID", os.Geteuid(), "CLK_TCK", l.hz, "page size", os.Getpagesize(), "PID", strconv.Itoa(os.Getpid()))
}
func TestMountEscapesAndBoundedReads(t *testing.T) {
	v, e := unescapeMount("/with\\040space\\134slash")
	if e != nil || v != "/with space\\slash" {
		t.Fatal(v, e)
	}
	for _, v := range []string{"/bad\\", "/bad\\000", "/bad\\999"} {
		if _, e := unescapeMount(v); e == nil {
			t.Fatal("bad escape")
		}
	}
	l := fixture(t)
	put(t, l, "/proc/example", strings.Repeat("x", 129))
	if _, e := l.read("/proc/example", 128); e != ErrLimit {
		t.Fatal("unbounded read")
	}
}

func TestProcessCollectionDetectsReuseDuringReadAndPermission(t *testing.T) {
	l := fixture(t)
	put(t, l, "/proc/123/stat", "")
	stable := "123 (worker) R 1 0 0 0 0 0 0 0 0 0 10 5 0 0 0 0 2 0 100 9999 3 0"
	reads := 0
	changed := false
	denied := false
	l.namespaceOverride = func(string) (uint64, error) { return 1234, nil }
	l.readOverride = func(path string, _ int64) (string, error) {
		switch path {
		case "/proc/stat":
			return "cpu 100 0 0 100 0 0 0 0\ncpu0 100 0 0 100 0 0 0 0\n", nil
		case "/proc/uptime":
			return "100.0 0", nil
		case "/proc/123/stat":
			reads++
			if changed && reads%2 == 0 {
				return strings.Replace(stable, "100 9999", "101 9999", 1), nil
			}
			return stable, nil
		case "/proc/123/status":
			if denied {
				return "", os.ErrPermission
			}
			return "Uid:\t1000 1000 1000 1000\n", nil
		case "/proc/123/cgroup":
			return "0::/test.slice/test.service\n", nil
		}
		return "", os.ErrNotExist
	}
	now := stamp()
	first, e := l.Collect("processes", now, 5000, "one")
	if e != nil || len(first.Processes) != 1 {
		t.Fatal(first, e)
	}
	if first.Processes[0].Uid != 1000 || first.Processes[0].Metrics[0].Value != nil {
		t.Fatal("first process sample")
	}
	l.hz = 100
	now.Mono = 2 * time.Second
	stable = strings.Replace(stable, "10 5 0 0", "410 5 0 0", 1)
	second, e := l.Collect("processes", now, 2000, "one")
	if e != nil || len(second.Processes) != 1 {
		t.Fatal(e)
	}
	var cpu float64
	_ = json.Unmarshal(*second.Processes[0].Metrics[0].Value, &cpu)
	if cpu != 200 {
		t.Fatal("CPU process percent incorrectly clamped", cpu)
	}
	changed = true
	next, e := l.Collect("processes", now, 5000, "one")
	if e != nil || len(next.Processes) != 0 || next.Block.Reason == nil {
		t.Fatal("PID reused between stat reads", next, e)
	}
	changed = false
	denied = true
	next, e = l.Collect("processes", now, 5000, "one")
	if e != nil || len(next.Processes) != 0 || next.Block.Reason == nil {
		t.Fatal("hidden processes became complete empty list")
	}
}

func TestRecognizedCPUTemperatureAndOtherSensorNotGuessed(t *testing.T) {
	l := fixture(t)
	put(t, l, "/sys/class/thermal/thermal_zone0/type", "acpitz")
	put(t, l, "/sys/class/thermal/thermal_zone0/temp", "80000")
	if v, a, _ := l.cpuTemperature(); v != nil || a != "unsupported" {
		t.Fatal("guessed CPU sensor")
	}
	put(t, l, "/sys/class/thermal/thermal_zone1/type", "x86_pkg_temp")
	put(t, l, "/sys/class/thermal/thermal_zone1/temp", "42500")
	if v, a, _ := l.cpuTemperature(); v != 42.5 || a != "available" {
		t.Fatal(v, a)
	}
	put(t, l, "/sys/class/thermal/thermal_zone1/temp", "invalid")
	if v, a, _ := l.cpuTemperature(); v != nil || a != "source_error" {
		t.Fatal("invalid temperature", v, a)
	}
}

func TestHungStatfsDoesNotMultiplyOrHideOtherMounts(t *testing.T) {
	l := fixture(t)
	blocked := make(chan struct{})
	defer close(blocked)
	var calls atomic.Int64
	l.statOverride = func(path string, st *syscall.Statfs_t) error {
		calls.Add(1)
		if path == "hung" {
			<-blocked
		}
		st.Blocks = 100
		st.Bfree = 40
		st.Bavail = 30
		st.Bsize = 4096
		st.Frsize = 4096
		st.Files = 100
		st.Ffree = 80
		return nil
	}
	now := stamp()
	for i := 0; i < 5; i++ {
		if _, _, err := l.fsStat("hung", "hung", now); err != errStatTimeout {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("repeated a hung native call", calls.Load())
	}
	if stat, _, err := l.fsStat("root", "root", now); err != nil || stat.Blocks != 100 {
		t.Fatal("unrelated filesystem unavailable", err)
	}
	if calls.Load() != 2 {
		t.Fatal("unexpected native calls")
	}
}

func TestNetworkResetChangesIdentityAndDoesNotProduceNegativeRate(t *testing.T) {
	l := fixture(t)
	l.namespaceOverride = func(string) (uint64, error) { return 1, nil }
	// The OS supplies a real interface identity; counter input alone is synthetic.
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) == 0 {
		t.Fatal("no native interface fixture", err)
	}
	name := interfaces[0].Name
	data := func(rx, tx string) string {
		return "Inter-| Receive | Transmit\n face |bytes|bytes\n" + name + ": " + rx + " 0 0 0 0 0 0 0 " + tx + " 0 0 0 0 0 0 0\n"
	}
	now := stamp()
	put(t, l, "/proc/net/dev", data("100", "200"))
	one, e := l.Collect("network", now, 2000, "one")
	if e != nil {
		t.Fatal(e)
	}
	now.Mono = 2 * time.Second
	put(t, l, "/proc/net/dev", data("200", "400"))
	two, e := l.Collect("network", now, 2000, "one")
	if e != nil {
		t.Fatal(e)
	}
	if one.Block.Metrics[0].ResourceID != two.Block.Metrics[0].ResourceID {
		t.Fatal("normal sample changed identity")
	}
	for _, m := range two.Block.Metrics {
		if m.Key == "rx_rate" && m.ResourceID == two.Block.Metrics[0].ResourceID && m.Value != float64(50) {
			t.Fatal("network rate", m)
		}
	}
	now.Mono = 4 * time.Second
	put(t, l, "/proc/net/dev", data("1", "2"))
	three, e := l.Collect("network", now, 2000, "one")
	if e != nil {
		t.Fatal(e)
	}
	if three.Block.Metrics[0].ResourceID == two.Block.Metrics[0].ResourceID {
		t.Fatal("reset identity unchanged")
	}
	for _, m := range three.Block.Metrics {
		if m.Key == "rx_rate" && m.Value != nil {
			t.Fatal("negative/reset rate became valid")
		}
	}
}

func TestFilesystemReservedSpaceRootOverlayAndPerMountDenial(t *testing.T) {
	l := fixture(t)
	l.namespaceOverride = func(string) (uint64, error) { return 1, nil }
	put(t, l, "/proc/self/mountinfo", "1 0 0:1 / / rw - overlay overlay rw\n2 1 0:2 / /proc rw - proc proc rw\n3 1 8:3 / /bad rw - ext4 /dev/bad rw\n")
	l.statOverride = func(path string, st *syscall.Statfs_t) error {
		if strings.HasSuffix(path, "/bad") {
			return os.ErrPermission
		}
		st.Blocks = 100
		st.Bfree = 40
		st.Bavail = 30
		st.Bsize = 4096
		st.Frsize = 4096
		st.Files = 100
		st.Ffree = 80
		return nil
	}
	sample, err := l.Collect("filesystems", stamp(), 15000, "one")
	if err != nil {
		t.Fatal(err)
	}
	if len(sample.Block.Records) != 2 {
		t.Fatal("root overlay missing or pseudo filesystem visible", len(sample.Block.Records))
	}
	first := sample.Block.Metrics[0].ResourceID
	for _, m := range sample.Block.Metrics {
		if m.ResourceID != first {
			if m.Availability != "permission_denied" || m.Value != nil {
				t.Fatal("per-mount denial", m)
			}
			continue
		}
		if m.Key == "reserved_bytes" && m.Value != contracts.U64(10*4096) {
			t.Fatal("reserved space", m)
		}
		if m.Key == "used_percent" && m.Value != 100*float64(60)/90 {
			t.Fatal("reserved blocks included in denominator", m)
		}
	}
	if sample.Block.Reason == nil {
		t.Fatal("partial filesystem failure invisible")
	}
}

func TestHwmonProfileRejectsControlTemperatureOffset(t *testing.T) {
	l := fixture(t)
	put(t, l, "/sys/class/hwmon/hwmon0/name", "k10temp")
	put(t, l, "/sys/class/hwmon/hwmon0/temp1_label", "Tctl")
	put(t, l, "/sys/class/hwmon/hwmon0/temp1_input", "70000")
	if v, _, _ := l.cpuTemperature(); v != nil {
		t.Fatal("Tctl offset advertised as measured die temperature")
	}
	put(t, l, "/sys/class/hwmon/hwmon0/temp2_label", "Tdie")
	put(t, l, "/sys/class/hwmon/hwmon0/temp2_input", "50000")
	if v, a, _ := l.cpuTemperature(); v != float64(50) || a != "available" {
		t.Fatal(v, a)
	}
	put(t, l, "/sys/class/hwmon/hwmon1/name", "coretemp")
	put(t, l, "/sys/class/hwmon/hwmon1/temp1_label", "Package id 0")
	put(t, l, "/sys/class/hwmon/hwmon1/temp1_input", "75000")
	if v, a, _ := l.cpuTemperature(); v != float64(75) || a != "available" {
		t.Fatal("coretemp profile", v, a)
	}
}

func TestFilesystemNativeSlotLimit(t *testing.T) {
	l := fixture(t)
	blocked := make(chan struct{})
	defer close(blocked)
	var calls atomic.Int64
	l.statOverride = func(string, *syscall.Statfs_t) error { calls.Add(1); <-blocked; return nil }
	for _, key := range []string{"a", "b", "c", "d"} {
		if _, _, err := l.fsStat(key, key, stamp()); err != errStatTimeout {
			t.Fatal(err)
		}
	}
	if _, _, err := l.fsStat("fifth", "fifth", stamp()); err != errStatBusy {
		t.Fatal("native slot bound", err)
	}
	if calls.Load() != 4 {
		t.Fatal("too many native statfs calls", calls.Load())
	}
}

func TestRealTemporaryFilePermissionDoesNotBecomeZero(t *testing.T) {
	l := fixture(t)
	put(t, l, "/proc/meminfo", "MemTotal: 100 kB\nMemAvailable: 40 kB\nMemFree: 10 kB\n")
	if err := os.Chmod(l.path("/proc/meminfo"), 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(l.path("/proc/meminfo"), 0600)
	sample, err := l.Collect("memory", stamp(), 2000, "one")
	if os.Geteuid() != 0 {
		if !errors.Is(err, os.ErrPermission) || len(sample.Block.Metrics) != 0 {
			t.Fatal("actual permission denial", err)
		}
	} else {
		if err != nil {
			t.Fatal("root fixture unexpectedly denied", err)
		}
	}
}

func TestSystemCPUFullPSIZeroIsUndefinedNotAvailable(t *testing.T) {
	l := fixture(t)
	put(t, l, "/proc/stat", "cpu 100 0 0 100 0 0 0 0\ncpu0 100 0 0 100 0 0 0 0\n")
	put(t, l, "/proc/pressure/cpu", "some avg10=12.50 avg60=1.00 avg300=0.50 total=100\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
	sample, err := l.Collect("cpu", stamp(), 2000, "one")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range sample.Block.Metrics {
		if m.Key == "psi_full_percent" && (m.Value != nil || m.Availability != "unsupported" || m.Reason == nil || *m.Reason != "SYSTEM_CPU_FULL_UNDEFINED") {
			t.Fatal("undefined CPU full presented as zero", m)
		}
		if m.Key == "psi_some_percent" && (m.Value != float64(12.5) || m.Availability != "available") {
			t.Fatal("valid CPU some lost", m)
		}
	}
}

func TestNativeFilesystemDescriptorBindsExpectedMount(t *testing.T) {
	l, err := NewLinux()
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	text, err := l.read("/proc/self/fdinfo/"+strconv.FormatUint(uint64(f.Fd()), 10), 4096)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	expected, err := mountID(text)
	if err != nil {
		t.Fatal(err)
	}
	var st syscall.Statfs_t
	key := "1:" + strconv.FormatUint(expected, 10) + ":fixture"
	if err := l.boundStatfs(key, path, &st); err != nil || st.Bsize <= 0 {
		t.Fatal("native pinned mount", err)
	}
	if err := l.boundStatfs("1:"+strconv.FormatUint(expected+1, 10)+":fixture", path, &st); !errors.Is(err, errHiddenMount) {
		t.Fatal("wrong mount accepted", err)
	}
	for _, text := range []string{"", "mnt_id: 0", "mnt_id: -1", "mnt_id: invalid"} {
		if _, err := mountID(text); err == nil {
			t.Fatal("invalid fd mount ID")
		}
	}
}
