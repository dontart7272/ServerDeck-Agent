// SPDX-License-Identifier: Apache-2.0
//go:build linux && cgo

package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var dockerID = regexp.MustCompile(`^[0-9a-f]{64}$`)

type containerEntry struct {
	ID     string
	Names  []string
	State  string
	Labels map[string]string
}
type dockerCached struct {
	metrics       []Metric
	health        any
	total, system uint64
	mono          time.Duration
}
type dockerAdapter struct {
	cache map[string]dockerCached
	next  int
}
type dockerHTTPError int

func (e dockerHTTPError) Error() string { return "DOCKER_HTTP_ERROR" }
func apiNumber(s string) (int, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 2 || parts[0] != "1" {
		return 0, false
	}
	n, err := strconv.Atoi(parts[1])
	return n, err == nil && n >= 0 && n < 1000
}
func dockerVersion(server, minVersion string) (string, error) {
	maximum, ok := apiNumber(server)
	minimum, valid := apiNumber(minVersion)
	if !ok || !valid || maximum < 40 || minimum > 56 || minimum > maximum {
		return "", ErrUnavailable
	}
	return "1." + strconv.Itoa(min(maximum, 56)), nil
}
func dockerClient(ctx context.Context, path string) (*http.Client, *http.Transport, error) {
	before, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	if before.Mode()&os.ModeSocket == 0 {
		return nil, nil, ErrUnavailable
	}
	owner, ok := before.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, nil, ErrUnavailable
	}
	tr := &http.Transport{MaxResponseHeaderBytes: 16384, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, ResponseHeaderTimeout: time.Second, DisableCompression: true}
	tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", path)
		if err != nil {
			return nil, err
		}
		after, err := os.Stat(path)
		if err != nil || !os.SameFile(before, after) {
			conn.Close()
			return nil, ErrUnavailable
		}
		unix, ok := conn.(*net.UnixConn)
		if !ok {
			conn.Close()
			return nil, ErrUnavailable
		}
		raw, err := unix.SyscallConn()
		if err != nil {
			conn.Close()
			return nil, err
		}
		var cred *syscall.Ucred
		var peerErr error
		err = raw.Control(func(fd uintptr) {
			cred, peerErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		})
		if err != nil || peerErr != nil || cred == nil || cred.Uid != owner.Uid {
			conn.Close()
			return nil, os.ErrPermission
		}
		return conn, nil
	}
	return &http.Client{Transport: tr, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, tr, nil
}
func dockerGet(ctx context.Context, client *http.Client, path string, out any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return ErrUnavailable
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return dockerHTTPError(response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 2000001))
	if err != nil {
		return err
	}
	if len(raw) > 2000000 {
		return ErrLimit
	}
	if json.Unmarshal(raw, out) != nil {
		return ErrUnavailable
	}
	return nil
}
func (l *Linux) collectDocker(b *Block, s Stamp) error {
	path := l.path("/var/run/docker.sock")
	explicit := l.adapters.DockerSocket != nil
	if explicit {
		path = *l.adapters.DockerSocket
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, tr, err := dockerClient(ctx, path)
	if err != nil {
		if os.IsNotExist(err) && !explicit {
			installed := false
			for _, marker := range []string{"/usr/bin/dockerd", "/usr/sbin/dockerd", "/etc/docker", "/lib/systemd/system/docker.service", "/snap/docker"} {
				if _, e := os.Stat(l.path(marker)); e == nil {
					installed = true
				}
			}
			if !installed {
				unavailableBlock(b, "absent", "DOCKER_NOT_INSTALLED")
				return nil
			}
		}
		return adapterError(b, err, "DOCKER_DAEMON_UNAVAILABLE")
	}
	defer tr.CloseIdleConnections()
	var version struct{ Version, ApiVersion, MinAPIVersion string }
	if err = dockerGet(ctx, client, "/version", &version); err != nil {
		return dockerFailure(b, err)
	}
	negotiated, err := dockerVersion(version.ApiVersion, version.MinAPIVersion)
	if err != nil {
		unavailableBlock(b, "unsupported", "DOCKER_API_INCOMPATIBLE")
		return nil
	}
	var containers []containerEntry
	if err = dockerGet(ctx, client, "/v"+negotiated+"/containers/json?all=1", &containers); err != nil {
		return dockerFailure(b, err)
	}
	sort.Slice(containers, func(i, j int) bool { return containers[i].ID < containers[j].ID })
	if len(containers) > 256 {
		containers = containers[:256]
		b.Reason = ptr("CONTAINER_LIMIT")
	}
	if l.docker == nil {
		l.docker = &dockerAdapter{cache: map[string]dockerCached{}}
	}
	d := l.docker
	out := []any{}
	seen := map[string]bool{}
	running, problem := 0, 0
	healthComplete := true
	expected := int64(max(1, (len(containers)+15)/16)) * b.Interval
	polled := map[string]bool{}
	for i := 0; i < min(16, len(containers)); i++ {
		index := (d.next + i) % len(containers)
		polled[containers[index].ID] = true
	}
	if len(containers) > 0 {
		d.next = (d.next + 16) % len(containers)
	}
	for _, container := range containers {
		if !dockerID.MatchString(container.ID) || seen[container.ID] {
			return adapterError(b, ErrUnavailable, "DOCKER_FORMAT_UNSUPPORTED")
		}
		seen[container.ID] = true
		switch container.State {
		case "created", "restarting", "running", "removing", "paused", "exited", "dead":
		default:
			return adapterError(b, ErrUnavailable, "DOCKER_FORMAT_UNSUPPORTED")
		}
		cached := d.cache[container.ID]
		cached.health = nil
		if !polled[container.ID] {
			healthComplete = false
		}
		if cached.metrics == nil {
			cached.metrics = []Metric{}
		}
		resource := ref("docker", container.ID)
		if container.State == "running" {
			running++
		}
		if polled[container.ID] && ctx.Err() == nil {
			var inspect struct {
				State struct {
					Health   *struct{ Status string }
					ExitCode int
				}
			}
			if err = dockerGet(ctx, client, "/v"+negotiated+"/containers/"+container.ID+"/json", &inspect); err == nil && inspect.State.Health != nil {
				switch health := inspect.State.Health.Status; health {
				case "healthy", "unhealthy", "starting":
					cached.health = health
				default:
					cached.health = nil
					b.Reason = ptr("DOCKER_FORMAT_UNSUPPORTED")
				}
			} else {
				cached.health = nil
				if err != nil {
					healthComplete = false
				}
			}
			mb := block("docker", s, expected)
			if container.State == "running" {
				var stats struct {
					CPUStats struct {
						CPUUsage struct {
							TotalUsage uint64 `json:"total_usage"`
						} `json:"cpu_usage"`
						System uint64 `json:"system_cpu_usage"`
						Online uint64 `json:"online_cpus"`
					} `json:"cpu_stats"`
					Memory struct {
						Usage, Limit uint64
						Stats        map[string]uint64
					} `json:"memory_stats"`
				}
				suffix := "/stats?stream=false"
				minor, _ := apiNumber(negotiated)
				if minor >= 41 {
					suffix += "&one-shot=true"
				}
				if err = dockerGet(ctx, client, "/v"+negotiated+"/containers/"+container.ID+suffix, &stats); err == nil {
					cpu, system := stats.CPUStats.CPUUsage.TotalUsage, stats.CPUStats.System
					if cached.mono > 0 && s.Mono > cached.mono && cpu >= cached.total && system > cached.system && stats.CPUStats.Online > 0 && stats.CPUStats.Online <= 4096 {
						measure(&mb, "cpu_percent", resource, "percent", float64(cpu-cached.total)/float64(system-cached.system)*float64(stats.CPUStats.Online)*100, "available", "", s)
					} else {
						measure(&mb, "cpu_percent", resource, "percent", nil, "source_error", "WARMING_UP", s)
					}
					cached.total, cached.system, cached.mono = cpu, system, s.Mono
					cache, cacheKnown := stats.Memory.Stats["inactive_file"]
					if n, ok := stats.Memory.Stats["total_inactive_file"]; ok {
						cache = n
						cacheKnown = true
					}
					used := stats.Memory.Usage
					if cache <= used {
						used -= cache
					}
					if cacheKnown && cache <= stats.Memory.Usage {
						measure(&mb, "memory_used_bytes", resource, "byte", strconv.FormatUint(used, 10), "available", "", s)
					} else {
						measure(&mb, "memory_used_bytes", resource, "byte", nil, "unsupported", "MEMORY_WORKING_SET_UNAVAILABLE", s)
					}
					if stats.Memory.Limit > 0 && stats.Memory.Limit < 1<<60 {
						measure(&mb, "memory_limit_bytes", resource, "byte", strconv.FormatUint(stats.Memory.Limit, 10), "available", "", s)
					} else {
						measure(&mb, "memory_limit_bytes", resource, "byte", nil, "unsupported", "MEMORY_LIMIT_UNAVAILABLE", s)
					}
				} else {
					for _, field := range []struct{ key, unit string }{{"cpu_percent", "percent"}, {"memory_used_bytes", "byte"}, {"memory_limit_bytes", "byte"}} {
						measure(&mb, field.key, resource, field.unit, nil, "source_error", "DOCKER_STATS_UNAVAILABLE", s)
					}
				}
			}

			oldMetrics := map[string]Metric{}
			for _, m := range cached.metrics {
				oldMetrics[m.Key] = m
			}
			for i, m := range mb.Metrics {
				if m.Value == nil {
					if old, ok := oldMetrics[m.Key]; ok && old.Value != nil {
						m.Value = old.Value
						m.MeasuredAt = old.MeasuredAt
						m.measuredMono = old.measuredMono
						m.Freshness = "stale"
						mb.Metrics[i] = m
					}
				}
			}
			cached.metrics = mb.Metrics
			d.cache[container.ID] = cached
		}
		for i := range cached.metrics {
			m := &cached.metrics[i]
			m.Interval = expected
			if s.Mono-m.measuredMono >= time.Duration(3*expected)*time.Millisecond {
				m.Freshness = "stale"
			}
		}
		if container.State == "dead" || container.State == "restarting" || cached.health == "unhealthy" {
			problem++
		}
		name := ""
		if len(container.Names) > 0 {
			name = cleanLabel(strings.TrimPrefix(container.Names[0], "/"), 256)
		}
		label := func(key string) any {
			if v := container.Labels[key]; v != "" {
				return cleanLabel(v, 256)
			}
			return nil
		}
		out = append(out, map[string]any{"id": container.ID, "name": name, "state": cleanLabel(container.State, 64), "health": cached.health, "compose_project": label("com.docker.compose.project"), "compose_service": label("com.docker.compose.service"), "metrics": cached.metrics})
	}
	for id := range d.cache {
		if !seen[id] {
			delete(d.cache, id)
		}
	}
	if len(out) == 0 {
		out = []any{}
	}
	record(b, map[string]any{"record_type": "docker", "resource_id": "docker.engine", "engine_version": cleanLabel(version.Version, 80), "api_version": negotiated, "containers": out})
	for _, v := range []struct {
		key string
		n   int
	}{{"container_count", len(out)}, {"running_container_count", running}, {"problem_container_count", problem}} {
		if v.key == "problem_container_count" && !healthComplete {
			measure(b, v.key, "docker.engine", "count", nil, "source_error", "HEALTH_COVERAGE_PARTIAL", s)
		} else {
			measure(b, v.key, "docker.engine", "count", strconv.Itoa(v.n), "available", "", s)
		}
	}
	return nil
}
func dockerFailure(b *Block, err error) error {
	var httpError dockerHTTPError
	if errors.As(err, &httpError) && (httpError == 401 || httpError == 403) {
		unavailableBlock(b, "permission_denied", "DOCKER_PERMISSION_DENIED")
		return nil
	}
	return adapterError(b, err, "DOCKER_DAEMON_UNAVAILABLE")
}
