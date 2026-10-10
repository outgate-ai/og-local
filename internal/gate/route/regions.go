package route

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Region is a region endpoint the gate learned from an environment's global API.
type Region struct {
	ID   string    `json:"id,omitempty"`
	Base string    `json:"base"`
	Env  string    `json:"env"`
	Seen time.Time `json:"seen"`
}

// Regions holds the region hosts the gate may reach. They are learned only from
// responses of an environment's own global API (LearnRule) and expire when not
// seen again within the TTL.
type Regions struct {
	mu    sync.Mutex
	path  string
	ttl   time.Duration
	now   func() time.Time
	hosts map[string]Region
	byID  map[string]Region
}

type regionsFile struct {
	Hosts []Region `json:"hosts"`
}

func NewRegions(path string, ttl time.Duration) *Regions {
	r := &Regions{path: path, ttl: ttl, now: time.Now, hosts: map[string]Region{}, byID: map[string]Region{}}
	r.load()
	return r
}

func (r *Regions) load() {
	if r.path == "" {
		return
	}
	b, err := os.ReadFile(r.path)
	if err != nil {
		return
	}
	var f regionsFile
	if json.Unmarshal(b, &f) != nil {
		return
	}
	for _, reg := range f.Hosts {
		r.put(reg)
	}
}

func (r *Regions) save() {
	if r.path == "" {
		return
	}
	f := regionsFile{}
	for _, reg := range r.hosts {
		f.Hosts = append(f.Hosts, reg)
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return
	}
	tmp := r.path + ".tmp"
	if os.MkdirAll(filepath.Dir(r.path), 0o750) != nil || os.WriteFile(tmp, b, 0o600) != nil {
		return
	}
	_ = os.Rename(tmp, r.path)
}

func (r *Regions) put(reg Region) {
	host := hostOf(reg.Base)
	if host == "" {
		return
	}
	if old, ok := r.hosts[host]; ok && reg.ID == "" {
		reg.ID = old.ID
	}
	r.hosts[host] = reg
	if reg.ID != "" {
		r.byID[reg.ID] = reg
	}
}

func (r *Regions) fresh(reg Region) bool {
	return r.ttl <= 0 || r.now().Sub(reg.Seen) < r.ttl
}

// Learn records a region base URL (scheme://host) for env.
func (r *Regions) Learn(id, rawURL, env string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return false
	}
	reg := Region{ID: id, Base: u.Scheme + "://" + u.Host, Env: env, Seen: r.now().UTC().Truncate(time.Second)}
	r.mu.Lock()
	defer r.mu.Unlock()
	old, had := r.hosts[strings.ToLower(u.Hostname())]
	r.put(reg)
	changed := !had || old.Base != reg.Base || old.Env != env || (id != "" && old.ID != id) || reg.Seen.Sub(old.Seen) > time.Hour
	if changed {
		r.save()
	}
	return changed
}

func (r *Regions) Get(id string) (Region, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	reg, ok := r.byID[id]
	if !ok || !r.fresh(reg) {
		return Region{}, false
	}
	return reg, true
}

func (r *Regions) HostEnv(host string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	reg, ok := r.hosts[strings.ToLower(host)]
	if !ok || !r.fresh(reg) {
		return "", false
	}
	return reg.Env, true
}

func (r *Regions) All() []Region {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Region, 0, len(r.hosts))
	for _, reg := range r.hosts {
		if r.fresh(reg) {
			out = append(out, reg)
		}
	}
	return out
}

// LearnRule names a JSON field of a global API response that carries a region URL.
// Path is a PathClass pattern; Field is "url" or "regions[].endpoint"; IDField, when
// set, is the sibling field with the region id ("regions[].id").
type LearnRule struct {
	Path    string `json:"path"`
	Field   string `json:"field"`
	IDField string `json:"id_field,omitempty"`
}

// LearnFrom applies the rules to one response body of env's global API.
func (r *Regions) LearnFrom(rules []LearnRule, pathClass string, body []byte, env string) int {
	var doc any
	n := 0
	for _, rule := range rules {
		if rule.Path != pathClass {
			continue
		}
		if doc == nil && json.Unmarshal(body, &doc) != nil {
			return 0
		}
		for _, hit := range extract(doc, rule.Field, rule.IDField) {
			if r.Learn(hit[1], hit[0], env) {
				n++
			}
		}
	}
	return n
}

// extract walks "a.b", "a[].b" paths and returns [value, id] pairs of strings.
func extract(doc any, field, idField string) [][2]string {
	list, leaf := split(field)
	_, idLeaf := split(idField)
	var items []any
	if list == "" {
		items = []any{doc}
	} else if m, ok := doc.(map[string]any); ok {
		if arr, ok := m[list].([]any); ok {
			items = arr
		}
	}
	var out [][2]string
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		v, _ := m[leaf].(string)
		if v == "" {
			continue
		}
		id := ""
		if idLeaf != "" {
			id, _ = m[idLeaf].(string)
		}
		out = append(out, [2]string{v, id})
	}
	return out
}

func split(field string) (list, leaf string) {
	if i := strings.Index(field, "[]."); i >= 0 {
		return field[:i], field[i+3:]
	}
	return "", field
}
