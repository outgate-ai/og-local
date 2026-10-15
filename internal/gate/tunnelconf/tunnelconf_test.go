package tunnelconf

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func settings(team, extra string) string {
	return fmt.Sprintf(`{"tunnel_id":"t1","hostname":"phone.example.test","access":{"team":%q,"aud":"aud0"}%s}`, team, extra)
}

func newKey(t *testing.T) (key, sum string) {
	t.Helper()
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	key = hex.EncodeToString(b)
	s := sha256.Sum256([]byte(key))
	return key, hex.EncodeToString(s[:])
}

func TestNotConfigured(t *testing.T) {
	for _, dir := range []string{"", filepath.Join(t.TempDir(), "absent")} {
		s := &Store{Dir: dir}
		if _, err := s.Load(); !errors.Is(err, ErrNotConfigured) {
			t.Errorf("%q: %v", dir, err)
		}
	}
	dir := t.TempDir()
	write(t, dir, SettingsFile, settings("team.cloudflareaccess.com", ""))
	if _, err := (&Store{Dir: dir}).Load(); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("no clients.json while keys are required: %v", err)
	}
	write(t, dir, SettingsFile, settings("team.cloudflareaccess.com", `,"require_client_key":false`))
	c, err := (&Store{Dir: dir}).Load()
	if err != nil || c.RequireClientKey || len(c.Keys) != 0 {
		t.Errorf("Access only: %+v %v", c, err)
	}
}

func TestTeamDomainPinned(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ClientsFile, `{"keys":[]}`)
	for _, team := range []string{"team.cloudflareaccess.com", "a.cloudflareaccess.com", "my-team-2.cloudflareaccess.com", strings.Repeat("a", 63) + ".cloudflareaccess.com"} {
		write(t, dir, SettingsFile, settings(team, ""))
		if c, err := (&Store{Dir: dir}).Load(); err != nil || c.Team != team {
			t.Errorf("%s: %v", team, err)
		}
	}
	for _, team := range []string{
		"", "cloudflareaccess.com", "evil.example", "team.cloudflareaccess.com.evil.example", "a.b.cloudflareaccess.com",
		"Team.cloudflareaccess.com", "-team.cloudflareaccess.com", "team-.cloudflareaccess.com", "team.cloudflareaccess.com.",
		"team.cloudflareaccess.com/x", "team.cloudflareaccess.com:443", "team.cloudflareaccess.com?x", strings.Repeat("a", 64) + ".cloudflareaccess.com",
		"team.cloudflareaccess.com\n",
	} {
		write(t, dir, SettingsFile, settings(team, ""))
		if _, err := (&Store{Dir: dir}).Load(); err == nil || errors.Is(err, ErrNotConfigured) || !strings.Contains(err.Error(), "access.team") {
			t.Errorf("%q accepted: %v", team, err)
		}
	}
	write(t, dir, SettingsFile, `{"access":{"team":"team.cloudflareaccess.com"}}`)
	if _, err := (&Store{Dir: dir}).Load(); err == nil || !strings.Contains(err.Error(), "access.aud") {
		t.Errorf("no aud: %v", err)
	}
	write(t, dir, SettingsFile, `{"access":`)
	if _, err := (&Store{Dir: dir}).Load(); err == nil || errors.Is(err, ErrNotConfigured) {
		t.Errorf("truncated settings: %v", err)
	}
}

func TestDefaultsAndUnknownFields(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ClientsFile, `{"keys":[],"later":1}`)
	write(t, dir, SettingsFile, settings("team.cloudflareaccess.com", `,"future":{"x":1}`))
	c, err := (&Store{Dir: dir}).Load()
	if err != nil || !c.RequireClientKey || c.Model || c.TunnelID != "t1" || c.Hostname != "phone.example.test" || c.AUD != "aud0" {
		t.Errorf("%+v %v", c, err)
	}
	write(t, dir, SettingsFile, settings("team.cloudflareaccess.com", `,"require_client_key":true,"services":{"model":true}`))
	if c, err := (&Store{Dir: dir}).Load(); err != nil || !c.RequireClientKey || !c.Model {
		t.Errorf("%+v %v", c, err)
	}
}

func TestClientKeys(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, SettingsFile, settings("team.cloudflareaccess.com", ""))
	k1, s1 := newKey(t)
	k2, s2 := newKey(t)
	write(t, dir, ClientsFile, fmt.Sprintf(`{"keys":[{"id":"k_1","name":"Laptop","created":1760000000000,"sha256":%q},{"id":"k_2","sha256":%q}]}`, s1, strings.ToUpper(s2)))
	c, err := (&Store{Dir: dir}).Load()
	if err != nil || len(c.Keys) != 2 {
		t.Fatalf("%+v %v", c, err)
	}
	for key, want := range map[string]string{k1: "k_1", k2: "k_2"} {
		if id, ok := c.Match(key); !ok || id != want {
			t.Errorf("Match = %q %v, want %s", id, ok, want)
		}
	}
	for _, bad := range []string{"", k1 + " ", " " + k1, strings.ToUpper(k1), s1} {
		if id, ok := c.Match(bad); ok || id != "" {
			t.Errorf("Match(%d bytes) = %q", len(bad), id)
		}
	}
	for name, body := range map[string]string{
		"short hash":   `{"keys":[{"id":"k_1","sha256":"abcd"}]}`,
		"not hex":      `{"keys":[{"id":"k_1","sha256":"` + strings.Repeat("z", 64) + `"}]}`,
		"no id":        `{"keys":[{"sha256":"` + s1 + `"}]}`,
		"bad id":       `{"keys":[{"id":"k 1","sha256":"` + s1 + `"}]}`,
		"repeated id":  `{"keys":[{"id":"k_1","sha256":"` + s1 + `"},{"id":"k_1","sha256":"` + s2 + `"}]}`,
		"not an array": `{"keys":{}}`,
	} {
		write(t, dir, ClientsFile, body)
		_, err := (&Store{Dir: dir}).Load()
		if err == nil || errors.Is(err, ErrNotConfigured) {
			t.Errorf("%s accepted: %v", name, err)
		} else if strings.Contains(err.Error(), s1) {
			t.Errorf("%s: the error carries the hash: %v", name, err)
		}
	}
}

func TestReloadsOnChangeAtMostOnceASecond(t *testing.T) {
	dir := t.TempDir()
	clk := &clock{t: time.Unix(1760000000, 0)}
	s := &Store{Dir: dir, Now: clk.now}
	if _, err := s.Load(); !errors.Is(err, ErrNotConfigured) {
		t.Fatal(err)
	}
	k1, s1 := newKey(t)
	_, s2 := newKey(t)
	write(t, dir, SettingsFile, settings("team.cloudflareaccess.com", ""))
	write(t, dir, ClientsFile, fmt.Sprintf(`{"keys":[{"id":"k_1","sha256":%q}]}`, s1))
	if _, err := s.Load(); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("looked again within a second: %v", err)
	}
	clk.t = clk.t.Add(time.Second)
	c, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Match(k1); !ok {
		t.Error("k_1 not loaded")
	}
	// Revoked: same size, new content.
	write(t, dir, ClientsFile, fmt.Sprintf(`{"keys":[{"id":"k_2","sha256":%q}]}`, s2))
	mt := time.Now().Add(time.Minute)
	_ = os.Chtimes(filepath.Join(dir, ClientsFile), mt, mt)
	clk.t = clk.t.Add(1500 * time.Millisecond)
	if c, _ := s.Load(); c == nil || len(c.Keys) != 1 || c.Keys[0].ID != "k_2" {
		t.Errorf("not reloaded: %+v", c)
	}
	// Replaced by rename, same size and mtime.
	tmp := filepath.Join(dir, "clients.tmp")
	write(t, dir, "clients.tmp", fmt.Sprintf(`{"keys":[{"id":"k_1","sha256":%q}]}`, s1))
	_ = os.Chtimes(tmp, mt, mt)
	if err := os.Rename(tmp, filepath.Join(dir, ClientsFile)); err != nil {
		t.Fatal(err)
	}
	clk.t = clk.t.Add(time.Second)
	if c, _ := s.Load(); c == nil || len(c.Keys) != 1 || c.Keys[0].ID != "k_1" {
		t.Errorf("rename not noticed: %+v", c)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	clk.t = clk.t.Add(time.Second)
	if _, err := s.Load(); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("dir removed: %v", err)
	}
}
