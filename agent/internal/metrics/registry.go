// SPDX-License-Identifier: Apache-2.0
package metrics

// UnitForKey is the built-in v1 registry. Additional module schemas are not
// admitted by guessing a unit from a client supplied key.
func UnitForKey(key string) (string, bool) {
	groups := map[string][]string{
		"percent":         {"busy_percent", "user_percent", "nice_percent", "system_percent", "iowait_percent", "steal_percent", "idle_percent", "irq_percent", "softirq_percent", "psi_some_percent", "psi_full_percent", "used_percent", "swap_used_percent", "inodes_used_percent", "link_load_percent", "utilization_percent", "memory_utilization_percent", "fan_percent", "cpu_percent", "cpu_host_percent"},
		"byte":            {"total_bytes", "available_bytes", "free_bytes", "used_bytes", "reserved_bytes", "swap_total_bytes", "swap_used_bytes", "rx_bytes", "tx_bytes", "vram_total_bytes", "vram_used_bytes", "rss_bytes", "memory_used_bytes", "memory_limit_bytes"},
		"count":           {"load1", "load5", "load15", "throttle_events", "inodes_total", "inodes_available", "rx_errors", "tx_errors", "rx_dropped", "tx_dropped", "container_count", "running_container_count", "problem_container_count"},
		"byte_per_second": {"rx_rate", "tx_rate"}, "hertz": {"frequency_hz"}, "celsius": {"temperature_c", "temperature_threshold_c"}, "watt": {"power_w"}, "bool": {"throttled", "gpu_processes_available", "source_available"}, "second": {"uptime_seconds"},
	}
	for unit, keys := range groups {
		for _, candidate := range keys {
			if candidate == key {
				return unit, true
			}
		}
	}
	return "", false
}
