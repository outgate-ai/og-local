// Package gate is OG OS's on-device gate (og-os module M08): every byte an Outgate
// component sends off the phone leaves through it. It listens only on unix
// sockets, identifies callers by uid and SELinux domain, refuses destinations
// outside Outgate's own hosts, records every request in the egress ledger, and
// fails closed.
package gate

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/route"
)

// Mode is how the gate treats request content.
type Mode string

const (
	// Passthrough forwards content unchanged (integration builds; debuggable only).
	Passthrough Mode = "passthrough"
	// Mask detects and masks content before it leaves; without a working detector
	// content-bearing requests are refused.
	Mask Mode = "mask"
)

// CallerRule admits one kind of peer. Empty fields match anything.
type CallerRule struct {
	Domain string  `json:"domain,omitempty"`
	UID    *uint32 `json:"uid,omitempty"`
	MinUID uint32  `json:"min_uid,omitempty"`
	// Package: the peer's uid belongs to this app (packages.list), for app callers
	// whose uid is assigned at install.
	Package        string `json:"package,omitempty"`
	Class          string `json:"class"`
	DebuggableOnly bool   `json:"debuggable_only,omitempty"`
}

// Config is gate.conf plus what the command line and properties decide.
type Config struct {
	Environments []route.Environment `json:"environments"`
	Learn        []route.LearnRule   `json:"learn"`
	Callers      []CallerRule        `json:"callers"`
	ModelSocket  string              `json:"model_socket"`
	AllowHTTP    []string            `json:"allow_http,omitempty"`
	// UploadDirs are where callers' upload files may live (og-agentd's tmp/).
	UploadDirs []string `json:"upload_dirs,omitempty"`
	// PackagesList is packages.list, for package caller rules (default: Android's).
	PackagesList     string `json:"packages_list,omitempty"`
	LedgerRetentionD int    `json:"ledger_retention_days,omitempty"`
	RegionTTLDays    int    `json:"region_ttl_days,omitempty"`

	DataDir    string `json:"-"`
	Mode       Mode   `json:"-"`
	Debuggable bool   `json:"-"`
	Version    string `json:"-"`
}

func LoadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("gate: %s: %w", path, err)
	}
	return c, nil
}

func (c *Config) ledgerRetention() time.Duration {
	if c.LedgerRetentionD <= 0 {
		return 30 * 24 * time.Hour
	}
	return time.Duration(c.LedgerRetentionD) * 24 * time.Hour
}

func (c *Config) regionTTL() time.Duration {
	if c.RegionTTLDays <= 0 {
		return 30 * 24 * time.Hour
	}
	return time.Duration(c.RegionTTLDays) * 24 * time.Hour
}
