// SPDX-License-Identifier: Apache-2.0
package config

import (
	"io"
	"net/netip"
	"strings"

	"serverdeck.local/agent/internal/contracts"
)

type Config struct {
	ConfigVersion  int            `json:"config_version"`
	InstallationID contracts.UUID `json:"installation_id"`
	RuntimeUser    string         `json:"runtime_user"`
	Paths          struct {
		State    string `json:"state"`
		Runtime  string `json:"runtime"`
		Releases string `json:"releases"`
	} `json:"paths"`
	TLS struct {
		CertificateFile string `json:"certificate_file"`
		PrivateKeyFile  string `json:"private_key_file"`
	} `json:"tls"`
	Transport struct {
		Mode            string   `json:"mode"`
		ListenAddresses []string `json:"listen_addresses"`
		AllowedCIDRs    []string `json:"allowed_cidrs"`
		Port            int      `json:"port"`
	} `json:"transport"`
	Adapters struct {
		DockerSocket    *string `json:"docker_socket"`
		SecuritySources string  `json:"security_sources"`
		PingExecutable  string  `json:"ping_executable"`
	} `json:"adapters"`
	Modules struct {
		CgroupDelegation bool `json:"cgroup_delegation"`
	} `json:"modules"`
	LimitsProfile  string  `json:"limits_profile"`
	RuntimeInitial Runtime `json:"runtime_initial"`
}

// Runtime types share the same pure semantics with API config.set.
type Budget = contracts.RuntimeBudget
type Root = contracts.RuntimeRoot
type Runtime = contracts.RuntimeConfig

// Load performs pure structural/semantic checks. It does not claim that Linux
// ownership, no-symlink, certificates or installation permissions are verified.
func Load(r io.Reader) (Config, error) {
	c, e := contracts.Decode[Config](r, contracts.Target{Family: "config"}, contracts.MaxJSONBytes)
	if e != nil {
		return c, e
	}
	if e = c.Validate(); e != nil {
		return Config{}, e
	}
	return c, nil
}
func (c Config) Validate() error {
	if e := c.RuntimeInitial.Validate(); e != nil {
		return e
	}
	paths := []string{c.Paths.State, c.Paths.Runtime, c.Paths.Releases, c.TLS.CertificateFile, c.TLS.PrivateKeyFile, c.Adapters.PingExecutable}
	if c.Adapters.DockerSocket != nil {
		paths = append(paths, *c.Adapters.DockerSocket)
	}
	for _, p := range paths {
		if !cleanAbsolute(p) {
			return contracts.ErrInvalid
		}
	}
	if c.TLS.CertificateFile == c.TLS.PrivateKeyFile {
		return contracts.ErrInvalid
	}
	// The three owned trees cannot contain each other or be the filesystem root.
	trees := []string{c.Paths.State, c.Paths.Runtime, c.Paths.Releases}
	for i, p := range trees {
		if p == "/" {
			return contracts.ErrInvalid
		}
		for j, q := range trees {
			if i != j && (p == q || strings.HasPrefix(p, q+"/")) {
				return contracts.ErrInvalid
			}
		}
	}
	seen := map[netip.Addr]bool{}
	for _, s := range c.Transport.ListenAddresses {
		ip, e := netip.ParseAddr(s)
		if e != nil || ip.Zone() != "" || ip.Is4In6() {
			return contracts.ErrInvalid
		}
		if seen[ip] {
			return contracts.ErrInvalid
		}
		seen[ip] = true
		if c.Transport.Mode == "localhost" && !ip.IsLoopback() {
			return contracts.ErrInvalid
		}
	}
	prefixes := map[netip.Prefix]bool{}
	for _, s := range c.Transport.AllowedCIDRs {
		p, e := netip.ParsePrefix(s)
		if e != nil || p != p.Masked() || p.Addr().Is4In6() {
			return contracts.ErrInvalid
		}
		if prefixes[p] {
			return contracts.ErrInvalid
		}
		prefixes[p] = true
		if c.Transport.Mode == "localhost" && !((p.Addr().Is4() && p.Bits() >= 8 && p.Addr().IsLoopback()) || (p.Addr().Is6() && p.Bits() == 128 && p.Addr().IsLoopback())) {
			return contracts.ErrInvalid
		}
	}
	return nil
}
func cleanAbsolute(s string) bool { return contracts.CleanAbsolutePath(s) }
