package route

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Tenancy is an app command-queue tenancy (.ogpkg) og-agentd's appq bring-up uses.
// The gate alone holds its join token; og-agentd only knows the tenancy name.
type Tenancy struct {
	Name        string
	Participant string
	Hook        string
	Commands    string
	AuthHeader  string
	Token       string
}

// Tenancies loads <dir>/<name>.ogpkg files, re-reading them when the directory changes.
type Tenancies struct {
	dir string

	mu      sync.Mutex
	byName  map[string]Tenancy
	checked time.Time
	stamp   string
}

func NewTenancies(dir string) *Tenancies {
	return &Tenancies{dir: dir, byName: map[string]Tenancy{}}
}

func (t *Tenancies) Get(name string) (Tenancy, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.refresh()
	x, ok := t.byName[name]
	return x, ok
}

func (t *Tenancies) Names() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.refresh()
	out := make([]string, 0, len(t.byName))
	for n := range t.byName {
		out = append(out, n)
	}
	return out
}

func (t *Tenancies) refresh() {
	if t.dir == "" || time.Since(t.checked) < 2*time.Second {
		return
	}
	t.checked = time.Now()
	entries, err := os.ReadDir(t.dir)
	if err != nil {
		t.byName, t.stamp = map[string]Tenancy{}, ""
		return
	}
	var stamp strings.Builder
	for _, e := range entries {
		if info, err := e.Info(); err == nil {
			stamp.WriteString(e.Name() + info.ModTime().String() + ";")
		}
	}
	if stamp.String() == t.stamp {
		return
	}
	t.stamp = stamp.String()
	byName := map[string]Tenancy{}
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".ogpkg")
		if !ok || name == "" {
			continue
		}
		if x, ok := parsePackage(filepath.Join(t.dir, e.Name())); ok {
			x.Name = name
			byName[name] = x
		}
	}
	t.byName = byName
}

func parsePackage(path string) (Tenancy, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Tenancy{}, false
	}
	var p struct {
		App struct {
			Endpoints struct {
				Hook     string `json:"hook"`
				Commands string `json:"commands"`
			} `json:"endpoints"`
		} `json:"app"`
		Client struct {
			Auth struct {
				Header string `json:"header"`
			} `json:"auth"`
		} `json:"client"`
		Join struct {
			Participant string `json:"participant"`
			Token       string `json:"token"`
		} `json:"join"`
	}
	if json.Unmarshal(b, &p) != nil || p.App.Endpoints.Hook == "" || p.Join.Token == "" {
		return Tenancy{}, false
	}
	header := p.Client.Auth.Header
	if header == "" {
		header = "X-Outgate-Hook-Token"
	}
	commands := p.App.Endpoints.Commands
	if commands == "" {
		commands = strings.TrimRight(p.App.Endpoints.Hook, "/") + "/commands"
	}
	return Tenancy{
		Participant: p.Join.Participant, Hook: p.App.Endpoints.Hook, Commands: commands,
		AuthHeader: header, Token: p.Join.Token,
	}, true
}
