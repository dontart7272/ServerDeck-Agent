// SPDX-License-Identifier: Apache-2.0
//go:build linux && cgo

package metrics

import (
	"context"
	"encoding/csv"
	"fmt"
	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type gpuStatic struct {
	at        Stamp
	name      string
	pci       any
	threshold uint32
	code      nvml.Return
}
type gpuAdapter struct {
	static       map[string]gpuStatic
	driver, cuda any
	staticAt     time.Duration
	lib          nvml.Interface
	init         nvml.Return
	started      bool
}

func nvmlStatus(code nvml.Return) (string, string) {
	switch code {
	case nvml.SUCCESS:
		return "available", ""
	case nvml.ERROR_NOT_SUPPORTED, nvml.ERROR_FUNCTION_NOT_FOUND:
		return "unsupported", "NVML_NOT_SUPPORTED"
	case nvml.ERROR_NO_PERMISSION:
		return "permission_denied", "NVML_NO_PERMISSION"
	case nvml.ERROR_LIBRARY_NOT_FOUND:
		return "source_error", "NVML_LIBRARY_MISSING"
	case nvml.ERROR_DRIVER_NOT_LOADED:
		return "source_error", "NVIDIA_DRIVER_NOT_LOADED"
	case nvml.ERROR_LIB_RM_VERSION_MISMATCH:
		return "source_error", "NVIDIA_DRIVER_LIBRARY_MISMATCH"
	case nvml.ERROR_GPU_IS_LOST:
		return "source_error", "GPU_LOST"
	default:
		return "source_error", "NVML_ERROR"
	}
}
func gpuMetric(b *Block, s Stamp, resource, key, unit, source string, value any, code nvml.Return) {
	status, reason := nvmlStatus(code)
	if code != nvml.SUCCESS {
		value = nil
	}
	measure(b, key, resource, unit, value, status, reason, s)
	b.Metrics[len(b.Metrics)-1].Source = source
}
func (l *Linux) collectGPU(b *Block, s Stamp) error {
	if l.gpu == nil {
		l.gpu = &gpuAdapter{init: nvml.ERROR_LIBRARY_NOT_FOUND}
	}
	g := l.gpu
	if g.static == nil {
		g.static = map[string]gpuStatic{}
	}
	if !g.started {
		g.started = true
		for _, path := range []string{"/usr/lib/x86_64-linux-gnu/libnvidia-ml.so.1", "/usr/lib/aarch64-linux-gnu/libnvidia-ml.so.1", "/usr/lib64/libnvidia-ml.so.1", "/usr/lib/wsl/lib/libnvidia-ml.so.1"} {
			if trustedLibrary(path) {
				g.lib = nvml.New(nvml.WithLibraryPath(path))
				g.init = g.lib.Init()
				break
			}
		}
	}
	if g.init != nvml.SUCCESS {
		if l.smi(b, s) {
			return nil
		}
		status, reason := nvmlStatus(g.init)
		if g.init == nvml.ERROR_LIBRARY_NOT_FOUND && !l.nvidiaPresent() {
			if _, err := os.Stat(l.path("/dev/dxg")); err == nil {
				status, reason = "unsupported", "WSL_GPU_UNVERIFIED"
			} else {
				status, reason = "absent", "GPU_ABSENT"
			}
		}
		unavailableBlock(b, status, reason)
		return nil
	}
	count, code := g.lib.DeviceGetCount()
	if code != nvml.SUCCESS {
		status, reason := nvmlStatus(code)
		unavailableBlock(b, status, reason)
		return nil
	}
	if count == 0 {
		unavailableBlock(b, "absent", "GPU_ABSENT")
		return nil
	}
	if count > 32 {
		count = 32
		b.Reason = ptr("GPU_LIMIT")
	}
	if g.staticAt == 0 || s.Mono-g.staticAt >= 60*time.Second {
		driver, code := g.lib.SystemGetDriverVersion()
		g.driver = nil
		if code == nvml.SUCCESS {
			g.driver = cleanLabel(driver, 80)
		}
		cuda, code := g.lib.SystemGetCudaDriverVersion()
		g.cuda = nil
		if code == nvml.SUCCESS && cuda > 0 {
			g.cuda = fmt.Sprintf("%d.%d", cuda/1000, (cuda%1000)/10)
		}
		g.staticAt = s.Mono
	}
	driverValue, cudaValue := g.driver, g.cuda
	seenDevices := map[string]bool{}
	processCount := 0
	denied := 0
	for i := 0; i < count; i++ {
		device, code := g.lib.DeviceGetHandleByIndex(i)
		if code != nvml.SUCCESS {
			if code == nvml.ERROR_NO_PERMISSION {
				denied++
			}
			b.Reason = ptr("GPU_HANDLE_UNAVAILABLE")
			continue
		}
		uuid, code := device.GetUUID()
		if code != nvml.SUCCESS || len(uuid) > 128 || !strings.HasPrefix(uuid, "GPU-") {
			if code == nvml.ERROR_NO_PERMISSION {
				denied++
			}
			b.Reason = ptr("GPU_UUID_UNAVAILABLE")
			continue
		}
		resource := ref("gpu", uuid, "1")
		seenDevices[uuid] = true
		static, exists := g.static[uuid]
		if !exists || s.Mono-static.at.Mono >= 60*time.Second {
			static = gpuStatic{at: s}
			name, nameCode := device.GetName()
			if nameCode == nvml.SUCCESS {
				static.name = cleanLabel(name, 256)
			}
			pci, pciCode := device.GetPciInfo()
			if pciCode == nvml.SUCCESS {
				raw := []byte{}
				for _, c := range pci.BusId {
					if c == 0 {
						break
					}
					raw = append(raw, byte(c))
				}
				static.pci = cleanLabel(string(raw), 128)
			}
			static.threshold, static.code = device.GetTemperatureThreshold(nvml.TEMPERATURE_THRESHOLD_SLOWDOWN)
			g.static[uuid] = static
		}
		name, pciValue := static.name, static.pci
		utilization, code := device.GetUtilizationRates()
		gpuMetric(b, s, resource, "utilization_percent", "percent", "nvml", float64(utilization.Gpu), code)
		gpuMetric(b, s, resource, "memory_utilization_percent", "percent", "nvml", float64(utilization.Memory), code)
		memory, code := device.GetMemoryInfo()
		gpuMetric(b, s, resource, "vram_total_bytes", "byte", "nvml", strconv.FormatUint(memory.Total, 10), code)
		gpuMetric(b, s, resource, "vram_used_bytes", "byte", "nvml", strconv.FormatUint(memory.Used, 10), code)
		temp, code := device.GetTemperature(nvml.TEMPERATURE_GPU)
		gpuMetric(b, s, resource, "temperature_c", "celsius", "nvml", float64(temp), code)
		gpuMetric(b, static.at, resource, "temperature_threshold_c", "celsius", "nvml", float64(static.threshold), static.code)
		b.Metrics[len(b.Metrics)-1].Interval = 60000
		power, code := device.GetPowerUsage()
		gpuMetric(b, s, resource, "power_w", "watt", "nvml", float64(power)/1000, code)
		fan, code := device.GetFanSpeed()
		gpuMetric(b, s, resource, "fan_percent", "percent", "nvml", float64(fan), code)
		reasons, code := device.GetCurrentClocksThrottleReasons()
		gpuMetric(b, s, resource, "throttled", "bool", "nvml", reasons & ^uint64(nvml.ClocksThrottleReasonGpuIdle) != 0, code)
		compute, cc := device.GetComputeRunningProcesses()
		graphics, gc := device.GetGraphicsRunningProcesses()
		processes := []any{}
		seen := map[uint32]bool{}
		for _, list := range [][]nvml.ProcessInfo{compute, graphics} {
			for _, p := range list {
				if p.Pid == 0 || p.Pid > 4194304 || seen[p.Pid] {
					continue
				}
				if len(processes) >= 128 || processCount >= 512 {
					b.Reason = ptr("GPU_PROCESS_LIMIT")
					break
				}
				processCount++
				seen[p.Pid] = true
				mb := block("gpu", s, b.Interval)
				status := nvml.SUCCESS
				if p.UsedGpuMemory == math.MaxUint64 {
					status = nvml.ERROR_NOT_SUPPORTED
				}
				gpuMetric(&mb, s, ref(resource, strconv.FormatUint(uint64(p.Pid), 10)), "vram_used_bytes", "byte", "nvml", strconv.FormatUint(p.UsedGpuMemory, 10), status)
				processes = append(processes, map[string]any{"process_ref": nil, "pid": p.Pid, "metrics": mb.Metrics})
			}
		}
		pc := nvml.SUCCESS
		if cc != nvml.SUCCESS {
			pc = cc
		}
		if gc != nvml.SUCCESS {
			pc = gc
		}
		gpuMetric(b, s, resource, "gpu_processes_available", "bool", "nvml", pc == nvml.SUCCESS, pc)
		record(b, map[string]any{"record_type": "gpu", "resource_id": resource, "uuid": uuid, "name": cleanLabel(name, 256), "driver": driverValue, "cuda": cudaValue, "pcie": pciValue, "processes": processes})
	}
	for uuid := range g.static {
		if !seenDevices[uuid] {
			delete(g.static, uuid)
		}
	}
	if len(b.Records) == 0 {
		if denied == count {
			unavailableBlock(b, "permission_denied", "NVML_NO_PERMISSION")
		} else {
			unavailableBlock(b, "source_error", "GPU_IDENTITY_UNAVAILABLE")
		}
	}
	return nil
}
func trustedLibrary(path string) bool {
	// Reuse ownership checks without requiring execute permission on a .so.
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	st, err := os.Stat(resolved)
	if err != nil || !st.Mode().IsRegular() {
		return false
	}
	for p := resolved; ; p = filepath.Dir(p) {
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm()&022 != 0 {
			return false
		}
		if sys, ok := st.Sys().(*syscall.Stat_t); !ok || sys.Uid != 0 {
			return false
		}
		if p == "/" {
			break
		}
	}
	return true
}
func (l *Linux) nvidiaPresent() bool {
	entries, err := os.ReadDir(l.path("/sys/bus/pci/devices"))
	if err != nil {
		return true
	}
	if len(entries) > 4096 {
		return true
	}
	for _, entry := range entries {
		vendor, err := l.read("/sys/bus/pci/devices/"+entry.Name()+"/vendor", 64)
		if err == nil && strings.TrimSpace(vendor) == "0x10de" {
			return true
		}
	}
	return false
}
func (l *Linux) smi(b *Block, s Stamp) bool {
	for _, path := range []string{"/usr/bin/nvidia-smi", "/usr/lib/wsl/lib/nvidia-smi"} {
		if !trustedExecutable(path) {
			continue
		}
		raw, err := readCommand(context.Background(), path, 262144, "--query-gpu=uuid,name,driver_version,pci.bus_id,utilization.gpu,utilization.memory,memory.total,memory.used,temperature.gpu,power.draw,fan.speed", "--format=csv,noheader,nounits")
		if err != nil {
			continue
		}
		parsed, err := parseSMI(raw, s, b.Interval)
		if err != nil {
			continue
		}
		*b = parsed
		b.Reason = ptr("NVML_UNAVAILABLE_SMI_FALLBACK")
		return true
	}
	return false
}
func parseSMI(raw []byte, s Stamp, ms int64) (Block, error) {
	b := block("gpu", s, ms)
	rows, err := csv.NewReader(strings.NewReader(string(raw))).ReadAll()
	if err != nil || len(rows) > 32 || len(rows) == 0 {
		return b, ErrUnavailable
	}
	fields := []struct {
		key, unit string
		scale     float64
	}{{"utilization_percent", "percent", 1}, {"memory_utilization_percent", "percent", 1}, {"vram_total_bytes", "byte", 1048576}, {"vram_used_bytes", "byte", 1048576}, {"temperature_c", "celsius", 1}, {"power_w", "watt", 1}, {"fan_percent", "percent", 1}}
	seen := map[string]bool{}
	for _, row := range rows {
		if len(row) != 11 {
			return b, ErrUnavailable
		}
		for i := range row {
			row[i] = strings.TrimSpace(row[i])
		}
		if !strings.HasPrefix(row[0], "GPU-") || len(row[0]) > 128 || seen[row[0]] {
			return b, ErrUnavailable
		}
		seen[row[0]] = true
		resource := ref("gpu", row[0], "1")
		record(&b, map[string]any{"record_type": "gpu", "resource_id": resource, "uuid": row[0], "name": cleanLabel(row[1], 256), "driver": cleanLabel(row[2], 80), "cuda": nil, "pcie": cleanLabel(row[3], 128), "processes": []any{}})
		for i, f := range fields {
			value, err := strconv.ParseFloat(row[i+4], 64)
			code := nvml.SUCCESS
			var v any = value * f.scale
			if row[i+4] == "N/A" || row[i+4] == "[Not Supported]" {
				code = nvml.ERROR_NOT_SUPPORTED
			} else if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || f.unit == "percent" && value > 100 || value*f.scale >= float64(math.MaxUint64) {
				return b, ErrUnavailable
			}
			if f.unit == "byte" && code == nvml.SUCCESS {
				v = strconv.FormatUint(uint64(value*f.scale), 10)
			}
			gpuMetric(&b, s, resource, f.key, f.unit, "nvidia-smi", v, code)
		}
		for _, missing := range []struct{ key, unit string }{{"throttled", "bool"}, {"temperature_threshold_c", "celsius"}, {"gpu_processes_available", "bool"}} {
			gpuMetric(&b, s, resource, missing.key, missing.unit, "nvidia-smi", nil, nvml.ERROR_NOT_SUPPORTED)
		}
	}
	return b, nil
}
