// Package tunnelconf reads the tunnel front's settings and client keys from the tunnel's
// credential-encrypted directory, and again whenever either file changes. The directory
// may be absent (before the first unlock, or before the owner set a tunnel up): the
// tunnel is then not configured.
package tunnelconf

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

const (
	SettingsFile = "settings.json"
	ClientsFile  = "clients.json"

	maxSettings = 64 << 10
	maxClients  = 1 << 20
	// statEvery is how often Load looks at the files.
	statEvery = time.Second
)

// ErrNotConfigured: settings.json (or, while client keys are required, clients.json) is
// missing or can't be read.
var ErrNotConfigured = errors.New("tunnel not configured")

var (
	teamDomain = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cloudflareaccess\.com$`)
	audTag     = regexp.MustCompile(`^[A-Za-z0-9._-]{1,256}$`)
	keyID      = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// Config is one consistent reading of both files.
type Config struct {
	TunnelID string
	Hostname string
	// Team is the Cloudflare Access team domain (<team>.cloudflareaccess.com), AUD the
	// Access application's audience tag.
	Team string
	AUD  string
	// RequireClientKey: a request also needs a client key (default true).
	RequireClientKey bool
	// Model: the on-device model is served (default false).
	Model bool
	Keys  []Key
}

// Key is a client key by its id and the SHA-256 of the key; the key itself is never stored.
type Key struct {
	ID  string
	sum [sha256.Size]byte
}

// Match returns the id of the key whose SHA-256 is key's. Every hash is compared, in constant time.
func (c *Config) Match(key string) (string, bool) {
	sum := sha256.Sum256([]byte(key))
	id, found := "", false
	for i := range c.Keys {
		if subtle.ConstantTimeCompare(sum[:], c.Keys[i].sum[:]) == 1 {
			id, found = c.Keys[i].ID, true
		}
	}
	return id, found
}

// Store keeps the last reading of Dir and reads the files again when their size, mtime
// or identity changes; it looks at most once a second.
type Store struct {
	Dir string
	// Now replaces time.Now (tests).
	Now func() time.Time

	mu      sync.Mutex
	checked time.Time
	stamps  [2]os.FileInfo
	loaded  bool
	conf    *Config
	err     error
}

// Load returns the current configuration, or ErrNotConfigured or why the files are invalid.
func (s *Store) Load() (*Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	if s.loaded && now.Sub(s.checked) < statEvery && !now.Before(s.checked) {
		return s.conf, s.err
	}
	s.checked = now
	var stamps [2]os.FileInfo
	for i, name := range []string{SettingsFile, ClientsFile} {
		if s.Dir != "" {
			stamps[i], _ = os.Stat(filepath.Join(s.Dir, name))
		}
	}
	if s.loaded && same(stamps[0], s.stamps[0]) && same(stamps[1], s.stamps[1]) {
		return s.conf, s.err
	}
	s.stamps, s.loaded = stamps, true
	s.conf, s.err = read(s.Dir, stamps)
	return s.conf, s.err
}

func same(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

type settingsFile struct {
	TunnelID string `json:"tunnel_id"`
	Hostname string `json:"hostname"`
	Access   struct {
		Team string `json:"team"`
		AUD  string `json:"aud"`
	} `json:"access"`
	RequireClientKey *bool `json:"require_client_key"`
	Services         struct {
		Model bool `json:"model"`
	} `json:"services"`
}

type clientsFile struct {
	Keys []struct {
		ID     string `json:"id"`
		SHA256 string `json:"sha256"`
	} `json:"keys"`
}

func read(dir string, stamps [2]os.FileInfo) (*Config, error) {
	if stamps[0] == nil {
		return nil, ErrNotConfigured
	}
	var st settingsFile
	if err := readJSON(filepath.Join(dir, SettingsFile), maxSettings, &st); err != nil {
		return nil, err
	}
	c := &Config{
		TunnelID: st.TunnelID, Hostname: st.Hostname, Team: st.Access.Team, AUD: st.Access.AUD,
		RequireClientKey: st.RequireClientKey == nil || *st.RequireClientKey, Model: st.Services.Model,
	}
	if !teamDomain.MatchString(c.Team) {
		return nil, fmt.Errorf("%s: access.team %.80q is not a <team>.cloudflareaccess.com domain", SettingsFile, c.Team)
	}
	if !audTag.MatchString(c.AUD) {
		return nil, fmt.Errorf("%s: access.aud missing or malformed", SettingsFile)
	}
	if stamps[1] == nil {
		if c.RequireClientKey {
			return nil, ErrNotConfigured
		}
		return c, nil
	}
	var cl clientsFile
	if err := readJSON(filepath.Join(dir, ClientsFile), maxClients, &cl); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for i, k := range cl.Keys {
		if !keyID.MatchString(k.ID) || seen[k.ID] {
			return nil, fmt.Errorf("%s: key %d: id missing, malformed or repeated", ClientsFile, i)
		}
		seen[k.ID] = true
		sum, err := hex.DecodeString(k.SHA256)
		if err != nil || len(sum) != sha256.Size {
			return nil, fmt.Errorf("%s: key %s: sha256 is not 64 hex digits", ClientsFile, k.ID)
		}
		key := Key{ID: k.ID}
		copy(key.sum[:], sum)
		c.Keys = append(c.Keys, key)
	}
	return c, nil
}

func readJSON(path string, limit int64, v any) error {
	f, err := os.Open(path) //nolint:gosec // the tunnel's own directory
	if err != nil {
		return ErrNotConfigured
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return ErrNotConfigured
	}
	if int64(len(b)) > limit {
		return fmt.Errorf("%s: larger than %d bytes", filepath.Base(path), limit)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return nil
}
