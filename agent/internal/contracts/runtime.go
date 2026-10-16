// SPDX-License-Identifier: Apache-2.0
package contracts

import (
	"bytes"
	"encoding/json"
	"io"
	"net/netip"
	"path"
	"strings"
)

type RuntimeBudget struct {
	RetentionDays int   `json:"retention_days"`
	BudgetBytes   int64 `json:"budget_bytes"`
}
type RuntimeRoot struct {
	RootID UUID   `json:"root_id"`
	Path   string `json:"path"`
}
type RuntimeConfig struct {
	History struct {
		BudgetBytes        int64 `json:"budget_bytes"`
		ModuleSharePercent int   `json:"module_share_percent"`
	} `json:"history"`
	Events RuntimeBudget `json:"events"`
	Audit  RuntimeBudget `json:"audit"`
	Files  struct {
		FullTextBytes int64         `json:"full_text_bytes"`
		EditBytes     int64         `json:"edit_bytes"`
		UploadBytes   int64         `json:"upload_bytes"`
		DownloadBytes int64         `json:"download_bytes"`
		Roots         []RuntimeRoot `json:"roots"`
	} `json:"files"`
	Trash struct {
		RetentionDays    int   `json:"retention_days"`
		BudgetBytesPerFS int64 `json:"budget_bytes_per_fs"`
	} `json:"trash"`
	ICMP struct {
		Target            *string `json:"target"`
		BackgroundEnabled bool    `json:"background_enabled"`
	} `json:"icmp"`
}

func (r RuntimeConfig) Validate() error {
	if r.Files.EditBytes > r.Files.FullTextBytes {
		return ErrInvalid
	}
	ids := map[UUID]bool{}
	paths := map[string]bool{}
	for _, root := range r.Files.Roots {
		if !cleanAbsolute(root.Path) || ids[root.RootID] || paths[root.Path] {
			return ErrInvalid
		}
		ids[root.RootID] = true
		paths[root.Path] = true
	}
	if r.ICMP.BackgroundEnabled && r.ICMP.Target == nil {
		return ErrInvalid
	}
	if r.ICMP.Target != nil && !validTarget(*r.ICMP.Target) {
		return ErrInvalid
	}
	return nil
}
func cleanAbsolute(s string) bool {
	return strings.HasPrefix(s, "/") && path.Clean(s) == s && !strings.ContainsRune(s, 0)
}
func validTarget(s string) bool {
	if ip, e := netip.ParseAddr(s); e == nil {
		return ip.Zone() == "" && !ip.IsUnspecified() && !ip.IsMulticast()
	}
	if len(s) < 1 || len(s) > 253 {
		return false
	}
	s = strings.TrimSuffix(s, ".")
	for _, label := range strings.Split(s, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// CleanAbsolutePath checks lexical Linux syntax only, not OS ownership or links.
func CleanAbsolutePath(s string) bool { return cleanAbsolute(s) }

// validateRuntimeValue also accepts a ConfigChanges patch: each provided group
// is complete by schema, and all current pure invariants are group-local.
func validateRuntimeValue(v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return ErrInvalid
	}
	var r RuntimeConfig
	if json.Unmarshal(b, &r) != nil {
		return ErrInvalid
	}
	return r.Validate()
}

// ApplyRuntimeChanges validates a full current snapshot, an atomic group patch
// and the merged result. It performs no storage/effects; callers must guard the
// current revision and repeat preflight before durable intent/commit.
func ApplyRuntimeChanges(current RuntimeConfig, changes io.Reader) (RuntimeConfig, error) {
	var original bytes.Buffer
	if e := Encode(&original, Target{"api", "Runtime"}, current, MaxJSONBytes); e != nil {
		return RuntimeConfig{}, e
	}
	patch, e := Validate(changes, Target{"api", "ConfigChanges"}, MaxJSONBytes)
	if e != nil {
		return RuntimeConfig{}, e
	}
	var base, updates map[string]json.RawMessage
	if json.Unmarshal(original.Bytes(), &base) != nil || json.Unmarshal(patch, &updates) != nil {
		return RuntimeConfig{}, ErrInvalid
	}
	for key, value := range updates {
		base[key] = value
	}
	merged, e := json.Marshal(base)
	if e != nil {
		return RuntimeConfig{}, ErrInvalid
	}
	return Decode[RuntimeConfig](bytes.NewReader(merged), Target{"api", "Runtime"}, MaxJSONBytes)
}

// ValidICMPTarget accepts the same restricted syntax as runtime configuration.
func ValidICMPTarget(s string) bool { return validTarget(s) }
