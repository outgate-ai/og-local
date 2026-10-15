// Package route turns a gate request into a destination: an https base the gate
// may reach (global, the OIDC issuer, a learned region endpoint, an app's command
// queue, an external model provider of the phone region) or the on-device model
// socket. Everything else is refused. Each destination has a class; the gate
// decides masking per class.
package route

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Environment is one Outgate deployment.
type Environment struct {
	ID     string `json:"id"`
	Global string `json:"global"`
	OIDC   string `json:"oidc"`
	// DebuggableOnly environments are reachable only on debuggable builds.
	DebuggableOnly bool `json:"debuggable_only,omitempty"`
}

type Kind int

const (
	Cloud Kind = iota
	OnDevice
)

// Destination classes. Whether content to a class is masked is gate.conf's call.
const (
	// ClassOutgate: Outgate global, the OIDC issuer, learned regions, app tenancies.
	ClassOutgate = "outgate"
	// ClassOnDevice: the on-device model service (M09).
	ClassOnDevice = "on-device"
	// ClassProvider: an external model provider the phone region calls.
	ClassProvider = "provider"
	// ClassMirror: Outgate's model mirror, reached only by downloads (never content).
	ClassMirror = "mirror"
)

// Provider is an external model provider endpoint of the phone region (class provider).
type Provider struct {
	ID   string `json:"id"`
	Base string `json:"base"`
}

// Destination is where one request goes.
type Destination struct {
	Kind Kind
	// URL is the full upstream URL for Cloud.
	URL *url.URL
	// Socket and Path are the model socket and request path for OnDevice.
	Socket string
	Path   string
	// Display is what the ledger and the user see ("api.outgate.ai").
	Display string
	// Headers are added by the gate (an app tenancy's hook token).
	Headers map[string]string
	// Env is the environment the destination belongs to ("" for on-device and providers).
	Env string
	// Class is the destination class (ClassOutgate, ClassOnDevice, ClassProvider, ClassMirror).
	Class string
}

var (
	ErrNotAllowed    = errors.New("destination not allowed")
	ErrUnknownRegion = errors.New("unknown region")
	ErrBadURL        = errors.New("bad url")
)

// Router resolves destinations. Its state (regions, tenancies) is safe for concurrent use.
type Router struct {
	Envs        []Environment
	Debuggable  bool
	ModelSocket string
	// AllowHTTP lists hosts reachable over plain http (debuggable builds, LAN test regions).
	AllowHTTP []string
	Regions   *Regions
	Tenancies *Tenancies
	// Providers are the phone region's external model providers, reached as
	// "provider:<id>" or by an absolute URL on their host.
	Providers []Provider
}

// Resolve picks the destination for absolute url u, or for path+query under regionID.
func (r *Router) Resolve(regionID, rawURL, path string, query url.Values) (*Destination, error) {
	if rawURL != "" {
		u, err := url.Parse(rawURL)
		if err != nil || u.Host == "" || u.User != nil {
			return nil, ErrBadURL
		}
		if len(query) > 0 {
			u.RawQuery = mergeQuery(u.RawQuery, query)
		}
		if env, ok := r.allowed(u); ok {
			return &Destination{Kind: Cloud, URL: u, Display: u.Hostname(), Env: env, Class: ClassOutgate}, nil
		}
		if _, ok := r.provider(u); ok {
			return &Destination{Kind: Cloud, URL: u, Display: u.Hostname(), Class: ClassProvider}, nil
		}
		return nil, fmt.Errorf("%w: %s", ErrNotAllowed, u.Host)
	}
	if !strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "?") {
		path = "/" + path
	}
	switch {
	case regionID == "on-device":
		if r.ModelSocket == "" {
			return nil, fmt.Errorf("%w: on-device model", ErrNotAllowed)
		}
		return &Destination{Kind: OnDevice, Socket: r.ModelSocket, Path: path + encode(query), Display: "on-device model", Class: ClassOnDevice}, nil
	case strings.HasPrefix(regionID, "provider:"):
		return r.providerPath(strings.TrimPrefix(regionID, "provider:"), path, query)
	case strings.HasPrefix(regionID, "appq:"):
		return r.tenancy(strings.TrimPrefix(regionID, "appq:"), path, query)
	case regionID == "global" || regionID == "oidc" || regionID == "":
		env := r.env("prod")
		if env == nil {
			return nil, ErrUnknownRegion
		}
		base := env.Global
		if regionID == "oidc" {
			base = env.OIDC
		}
		return r.join(base, path, query, env.ID)
	default:
		reg, ok := r.Regions.Get(regionID)
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnknownRegion, regionID)
		}
		return r.join(reg.Base, path, query, reg.Env)
	}
}

func (r *Router) join(base, path string, query url.Values, env string) (*Destination, error) {
	u, err := url.Parse(strings.TrimRight(base, "/") + path)
	if err != nil {
		return nil, ErrBadURL
	}
	if len(query) > 0 {
		u.RawQuery = mergeQuery(u.RawQuery, query)
	}
	if _, ok := r.allowed(u); !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotAllowed, u.Host)
	}
	return &Destination{Kind: Cloud, URL: u, Display: u.Hostname(), Env: env, Class: ClassOutgate}, nil
}

func (r *Router) providerPath(id, path string, query url.Values) (*Destination, error) {
	var base string
	for _, p := range r.Providers {
		if p.ID == id {
			base = p.Base
			break
		}
	}
	if base == "" {
		return nil, fmt.Errorf("%w: provider:%s", ErrUnknownRegion, id)
	}
	u, err := url.Parse(strings.TrimRight(base, "/") + path)
	if err != nil {
		return nil, ErrBadURL
	}
	if len(query) > 0 {
		u.RawQuery = mergeQuery(u.RawQuery, query)
	}
	if _, ok := r.provider(u); !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotAllowed, u.Host)
	}
	return &Destination{Kind: Cloud, URL: u, Display: u.Hostname(), Class: ClassProvider}, nil
}

// provider reports whether u is on a configured provider's host, over https (or
// plain http to an AllowHTTP host), and which provider.
func (r *Router) provider(u *url.URL) (string, bool) {
	host := strings.ToLower(u.Hostname())
	switch u.Scheme {
	case "https":
	case "http":
		if !contains(r.AllowHTTP, host) {
			return "", false
		}
	default:
		return "", false
	}
	for _, p := range r.Providers {
		if hostOf(p.Base) == host {
			return p.ID, true
		}
	}
	return "", false
}

func (r *Router) tenancy(name, path string, query url.Values) (*Destination, error) {
	t, ok := r.Tenancies.Get(name)
	if !ok {
		return nil, fmt.Errorf("%w: appq:%s", ErrUnknownRegion, name)
	}
	base := t.Hook
	if strings.HasPrefix(path, "/commands") {
		base = strings.TrimSuffix(t.Commands, "/commands")
	}
	if strings.HasPrefix(path, "/?") {
		path = path[1:]
	}
	u, err := url.Parse(strings.TrimRight(base, "/") + path)
	if err != nil {
		return nil, ErrBadURL
	}
	if len(query) > 0 {
		u.RawQuery = mergeQuery(u.RawQuery, query)
	}
	env, ok := r.allowed(u)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotAllowed, u.Host)
	}
	return &Destination{
		Kind: Cloud, URL: u, Display: u.Hostname(), Env: env, Class: ClassOutgate,
		Headers: map[string]string{t.AuthHeader: t.Token},
	}, nil
}

// allowed reports whether u may be reached and the environment it belongs to:
// https to an environment's global or OIDC host, or to a region host learned from
// that environment's region list.
func (r *Router) allowed(u *url.URL) (string, bool) {
	host := strings.ToLower(u.Hostname())
	switch u.Scheme {
	case "https":
	case "http":
		if !contains(r.AllowHTTP, host) {
			return "", false
		}
	default:
		return "", false
	}
	for _, e := range r.Envs {
		if e.DebuggableOnly && !r.Debuggable {
			continue
		}
		if hostOf(e.Global) == host || hostOf(e.OIDC) == host {
			return e.ID, true
		}
	}
	if env, ok := r.Regions.HostEnv(host); ok {
		if e := r.env(env); e != nil {
			return env, true
		}
	}
	return "", false
}

func (r *Router) env(id string) *Environment {
	for i := range r.Envs {
		e := &r.Envs[i]
		if e.ID == id && (!e.DebuggableOnly || r.Debuggable) {
			return e
		}
	}
	return nil
}

// IsOutgateHost reports whether host is an environment's global or OIDC host
// (debuggable-only environments included), whatever the build.
func (r *Router) IsOutgateHost(host string) bool {
	host = strings.ToLower(host)
	for _, e := range r.Envs {
		if hostOf(e.Global) == host || hostOf(e.OIDC) == host {
			return true
		}
	}
	return false
}

// EnvForGlobal returns the environment whose global API is at host.
func (r *Router) EnvForGlobal(host string) (string, bool) {
	for _, e := range r.Envs {
		if hostOf(e.Global) == strings.ToLower(host) && (!e.DebuggableOnly || r.Debuggable) {
			return e.ID, true
		}
	}
	return "", false
}

func hostOf(base string) string {
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

func mergeQuery(raw string, q url.Values) string {
	v, _ := url.ParseQuery(raw)
	for k, vals := range q {
		for _, x := range vals {
			v.Add(k, x)
		}
	}
	return v.Encode()
}

func encode(q url.Values) string {
	if len(q) == 0 {
		return ""
	}
	return "?" + q.Encode()
}

// idSegment matches the ids in Outgate paths. App and device ids are "app_" and "dev_" + hex; a
// hyphen after "app" is a word ("app-tenancies"), not an id.
var idSegment = regexp.MustCompile(`^(?:[0-9]+|[0-9a-fA-F-]{16,}|(?:thr|reg|ln|gt|upl|dec|gate|run|cmd|acct|o|u)[-_][A-Za-z0-9_-]+|(?:app|dev)_[A-Za-z0-9_-]+|[A-Za-z0-9_-]{24,})$`)

// PathClass replaces id-like segments with ":id" so ledger rows group by endpoint.
func PathClass(path string) string {
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if p != "" && idSegment.MatchString(p) {
			parts[i] = ":id"
		}
	}
	return strings.Join(parts, "/")
}

// ThreadID extracts the thread id from an agents API path, or "".
func ThreadID(path string) string {
	parts := strings.Split(strings.SplitN(path, "?", 2)[0], "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "threads" && parts[i+1] != "" {
			return parts[i+1]
		}
	}
	return ""
}
