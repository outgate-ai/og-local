// Package gate is OG OS's on-device gate (og-os module M08): every byte an Outgate
// component sends off the phone leaves through it. It listens only on unix
// sockets, identifies callers by uid and SELinux domain, refuses destinations
// outside Outgate's own hosts (and the phone region's external model providers),
// and records every request in the egress ledger. The model manager downloads
// model files from Outgate's model mirror through it, into a descriptor it passes.
//
// Masking is decided per destination class (gate.conf "classes"). Traffic to
// Outgate (global, the OIDC issuer, regions, app tenancies) is not masked: the
// region is the trust point and its guardrail masks on its own provider path, so
// masking on the phone too would anonymize twice. Only a class marked mask, the
// phone region's external providers, is masked, and only it fails closed when
// content can't be masked. The on-device model is never masked.
package gate

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
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

// ClassRule says whether content to one destination class is masked.
type ClassRule struct {
	Class string `json:"class"`
	Mask  bool   `json:"mask"`
	// Destinations are the class's endpoints; only the provider class lists any
	// (Outgate's come from environments, learning and tenancies).
	Destinations []route.Provider `json:"destinations,omitempty"`
}

// DefaultClasses apply when gate.conf names none: Outgate, the on-device model and
// the model mirror unmasked, the phone region's external providers masked (none configured).
func DefaultClasses() []ClassRule {
	return []ClassRule{
		{Class: route.ClassOutgate, Mask: false},
		{Class: route.ClassOnDevice, Mask: false},
		{Class: route.ClassProvider, Mask: true},
		{Class: route.ClassMirror, Mask: false},
	}
}

// StoreRule names a field of a global API response the gate keeps instead of handing it on (og-os
// M12c): on a 2xx from an environment's global API to Method Path (":name" segments match any one
// segment), the app tenancy package at Field (a dotted path of object keys) is sealed in the gate's
// store under the name at NameField, and Field becomes {"stored": "<name>"}. The object holding the
// name may say the tenancy's thread_id and app_name. Kind is "appq", the only kind.
type StoreRule struct {
	Path      string `json:"path"`
	Method    string `json:"method"`
	Field     string `json:"field"`
	NameField string `json:"name_field"`
	Kind      string `json:"kind"`
}

func (r *StoreRule) validate() error {
	switch {
	case r.Kind != "appq":
		return fmt.Errorf("store: unknown kind %q", r.Kind)
	case !strings.HasPrefix(r.Path, "/") || strings.ContainsAny(r.Path, "?#"):
		return fmt.Errorf("store: bad path %q", r.Path)
	case !methods[strings.ToUpper(r.Method)]:
		return fmt.Errorf("store: bad method %q", r.Method)
	case !dottedPath(r.Field) || !dottedPath(r.NameField) || r.Field == r.NameField:
		return fmt.Errorf("store: field %q and name_field %q must be different dotted paths", r.Field, r.NameField)
	}
	return nil
}

func dottedPath(p string) bool {
	if p == "" || strings.ContainsAny(p, "[]") {
		return false
	}
	for _, seg := range strings.Split(p, ".") {
		if seg == "" {
			return false
		}
	}
	return true
}

// Ledger and response values of a request's mask state.
const (
	// MaskOn: the request's content went through the masker.
	MaskOn = "on"
	// MaskOff: its class requires masking, but the gate runs in passthrough (debuggable only).
	MaskOff = "off"
	// MaskNotRequired: its class isn't masked, or it carried no content.
	MaskNotRequired = "not_required"
)

// Config is gate.conf plus what the command line and properties decide.
type Config struct {
	Environments []route.Environment `json:"environments"`
	Learn        []route.LearnRule   `json:"learn"`
	// Store names global API responses whose app tenancy package the gate keeps (og-os M12c).
	Store []StoreRule `json:"store,omitempty"`
	// Classes decide masking per destination class (DefaultClasses when empty).
	Classes     []ClassRule  `json:"classes,omitempty"`
	Callers     []CallerRule `json:"callers"`
	ModelSocket string       `json:"model_socket"`
	// ModelSockets maps each on-device model alias to its llama.cpp server's socket
	// (M14: og-local, og-local-agent). Absent: model_socket serves og-local.
	ModelSockets map[string]string `json:"model_sockets,omitempty"`
	AllowHTTP    []string          `json:"allow_http,omitempty"`
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
	if err := c.Validate(); err != nil {
		return c, fmt.Errorf("gate: %s: %w", path, err)
	}
	return c, nil
}

// Validate checks the destination classes: known names, each once, the on-device
// model and the model mirror never masked, endpoints only for providers, and a
// provider never on one of Outgate's own hosts (Outgate traffic must not become
// maskable by a typo). It checks the model sockets too.
func (c *Config) Validate() error {
	if err := c.validateModels(); err != nil {
		return err
	}
	for i := range c.Store {
		if err := c.Store[i].validate(); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for _, r := range c.Classes {
		switch r.Class {
		case route.ClassOutgate, route.ClassOnDevice, route.ClassProvider, route.ClassMirror:
		default:
			return fmt.Errorf("classes: unknown class %q", r.Class)
		}
		if seen[r.Class] {
			return fmt.Errorf("classes: %q twice", r.Class)
		}
		seen[r.Class] = true
		if r.Class == route.ClassOnDevice && r.Mask {
			return errors.New("classes: the on-device model is never masked")
		}
		if r.Class == route.ClassMirror && r.Mask {
			return errors.New("classes: the model mirror is never masked")
		}
		if len(r.Destinations) > 0 && r.Class != route.ClassProvider {
			return fmt.Errorf("classes: %q takes no destinations", r.Class)
		}
		ids := map[string]bool{}
		for _, d := range r.Destinations {
			u, err := url.Parse(d.Base)
			if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
				return fmt.Errorf("classes: provider %q: bad base %q", d.ID, d.Base)
			}
			if d.ID == "" || ids[d.ID] {
				return fmt.Errorf("classes: provider ids must be set and unique (%q)", d.ID)
			}
			ids[d.ID] = true
			for _, e := range c.Environments {
				if sameHost(u, e.Global) || sameHost(u, e.OIDC) {
					return fmt.Errorf("classes: provider %q is on Outgate's own host %s", d.ID, u.Hostname())
				}
			}
		}
	}
	return nil
}

// DefaultModel is the alias a request that names no model goes to (M09's outgate-model).
const DefaultModel = "og-local"

var modelAlias = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Models maps each on-device model alias to its socket: model_sockets, else
// model_socket as og-local.
func (c *Config) Models() map[string]string {
	if len(c.ModelSockets) > 0 {
		return c.ModelSockets
	}
	if c.ModelSocket != "" {
		return map[string]string{DefaultModel: c.ModelSocket}
	}
	return nil
}

// validateModels: model_sockets names og-local, model_socket is that same socket
// or absent, aliases are plain names and sockets absolute paths.
func (c *Config) validateModels() error {
	if len(c.ModelSockets) > 0 {
		def, ok := c.ModelSockets[DefaultModel]
		if !ok {
			return fmt.Errorf("model_sockets: no %q (the default model)", DefaultModel)
		}
		if c.ModelSocket != "" && c.ModelSocket != def {
			return fmt.Errorf("model_socket %q is not model_sockets %q (%q)", c.ModelSocket, DefaultModel, def)
		}
	}
	models := c.Models()
	for _, alias := range slices.Sorted(maps.Keys(models)) {
		if !modelAlias.MatchString(alias) {
			return fmt.Errorf("model_sockets: bad alias %q", alias)
		}
		if !filepath.IsAbs(models[alias]) {
			return fmt.Errorf("model_sockets: %q: socket %q is not an absolute path", alias, models[alias])
		}
	}
	return nil
}

func sameHost(u *url.URL, base string) bool {
	b, err := url.Parse(base)
	return err == nil && b.Hostname() != "" && strings.EqualFold(b.Hostname(), u.Hostname())
}

func (c *Config) classes() []ClassRule {
	if len(c.Classes) == 0 {
		return DefaultClasses()
	}
	return c.Classes
}

// Masks reports whether content to destination class is masked. A class gate.conf
// doesn't list takes its default.
func (c *Config) Masks(class string) bool {
	for _, r := range c.classes() {
		if r.Class == class {
			return r.Mask
		}
	}
	for _, r := range DefaultClasses() {
		if r.Class == class {
			return r.Mask
		}
	}
	return false
}

// Providers are the configured external provider endpoints.
func (c *Config) Providers() []route.Provider {
	for _, r := range c.classes() {
		if r.Class == route.ClassProvider {
			return r.Destinations
		}
	}
	return nil
}

// MaskingNeeded reports whether any configured destination needs masking: a
// masked class with endpoints, or Outgate itself if gate.conf masks it. Without
// it the detector is never loaded and its absence is not a fault.
func (c *Config) MaskingNeeded() bool {
	if c.Masks(route.ClassOutgate) {
		return true
	}
	return c.Masks(route.ClassProvider) && len(c.Providers()) > 0
}

// MaskingClasses maps each class to whether it is masked (health).
func (c *Config) MaskingClasses() map[string]bool {
	return map[string]bool{
		route.ClassOutgate:  c.Masks(route.ClassOutgate),
		route.ClassOnDevice: c.Masks(route.ClassOnDevice),
		route.ClassProvider: c.Masks(route.ClassProvider),
		route.ClassMirror:   c.Masks(route.ClassMirror),
	}
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
