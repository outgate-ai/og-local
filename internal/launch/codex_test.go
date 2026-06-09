package launch

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRenderCodexConfig(t *testing.T) {
	base := "http://127.0.0.1:5000/_k/ogl_live_tok/v1"
	got := renderCodexConfig(base)

	wants := []string{
		`profile = "ogl"`,
		`[model_providers.ogl]`,
		`name = "ogl"`,
		`base_url = "` + base + `"`,
		`wire_api = "responses"`,
		`requires_openai_auth = true`,
		`[profiles.ogl]`,
		`model_provider = "ogl"`,
	}
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("config missing %q in:\n%s", w, got)
		}
	}
}

func TestRenderCodexConfigEmbedsBaseURLVerbatim(t *testing.T) {
	base := "http://127.0.0.1:65535/_k/abc123/v1"
	if !strings.Contains(renderCodexConfig(base), `base_url = "`+base+`"`) {
		t.Errorf("base_url not embedded verbatim")
	}
}

func TestPrepareCodexHomeRealFS(t *testing.T) {
	home := t.TempDir()
	// Seed a real ~/.codex/auth.json to be mirrored.
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	authBytes := []byte(`{"OPENAI_API_KEY":"sk-real","auth_mode":"apikey"}`)
	if err := os.WriteFile(filepath.Join(home, ".codex", "auth.json"), authBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	env, err := prepareCodexHome(osCodexFS{}, home, "http://127.0.0.1:5000", "ogl_live_tok")
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	dir := filepath.Join(home, ".codex", "ogl")
	if env["CODEX_HOME"] != dir {
		t.Errorf("CODEX_HOME = %q, want %q", env["CODEX_HOME"], dir)
	}

	cfg, err := os.ReadFile(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(cfg), `base_url = "http://127.0.0.1:5000/_k/ogl_live_tok/v1"`) {
		t.Errorf("config base_url wrong:\n%s", cfg)
	}
	if runtime.GOOS != "windows" {
		// Windows does not honor Unix permission bits; Stat reports 0666/0777.
		if fi, _ := os.Stat(filepath.Join(dir, "config.toml")); fi != nil && fi.Mode().Perm() != 0o600 {
			t.Errorf("config perm = %v, want 0600", fi.Mode().Perm())
		}
		if fi, _ := os.Stat(dir); fi != nil && fi.Mode().Perm() != 0o700 {
			t.Errorf("dir perm = %v, want 0700", fi.Mode().Perm())
		}
	}

	mirrored, err := os.ReadFile(filepath.Join(dir, "auth.json"))
	if err != nil {
		t.Fatalf("read mirrored auth: %v", err)
	}
	if !bytes.Equal(mirrored, authBytes) {
		t.Errorf("auth.json not mirrored verbatim: %s", mirrored)
	}
}

func TestPrepareCodexHomeNoAuthFile(t *testing.T) {
	home := t.TempDir() // no ~/.codex/auth.json present
	env, err := prepareCodexHome(osCodexFS{}, home, "http://127.0.0.1:6000", "tok")
	if err != nil {
		t.Fatalf("prepare must not fail when auth.json is absent: %v", err)
	}
	dir := env["CODEX_HOME"]
	if _, err := os.Stat(filepath.Join(dir, "config.toml")); err != nil {
		t.Errorf("config.toml should still be written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "auth.json")); !os.IsNotExist(err) {
		t.Errorf("auth.json should NOT exist when source is absent")
	}
}

type failCodexFS struct {
	failMkdir bool
	failWrite int // fail on the Nth WriteFile (1-based); 0 = never
	writes    int
	auth      []byte
	authErr   error
}

func (f *failCodexFS) MkdirAll(string, fs.FileMode) error {
	if f.failMkdir {
		return errFake
	}
	return nil
}

func (f *failCodexFS) WriteFile(string, []byte, fs.FileMode) error {
	f.writes++
	if f.failWrite == f.writes {
		return errFake
	}
	return nil
}

func (f *failCodexFS) ReadFile(string) ([]byte, error) { return f.auth, f.authErr }

var errFake = &fakeErr{}

type fakeErr struct{}

func (*fakeErr) Error() string { return "fake fs error" }

func TestPrepareCodexHomeErrors(t *testing.T) {
	if _, err := prepareCodexHome(&failCodexFS{failMkdir: true}, "/home", "http://x", "t"); err == nil {
		t.Error("expected MkdirAll error")
	}
	if _, err := prepareCodexHome(&failCodexFS{failWrite: 1, authErr: errFake}, "/home", "http://x", "t"); err == nil {
		t.Error("expected config WriteFile error")
	}
	// auth.json present (ReadFile ok) but its WriteFile (the 2nd write) fails.
	if _, err := prepareCodexHome(&failCodexFS{failWrite: 2, auth: []byte("{}")}, "/home", "http://x", "t"); err == nil {
		t.Error("expected auth.json WriteFile error to surface")
	}
}

func TestChooseCodexBackend(t *testing.T) {
	apikeyJSON := []byte(`{"OPENAI_API_KEY":"sk-x","auth_mode":"apikey"}`)
	chatgptJSON := []byte(`{"auth_mode":"chatgpt","tokens":{"access_token":"x"}}`)

	cases := []struct {
		name    string
		env     map[string]string
		auth    []byte
		wantSub bool // true => chatgpt.com/backend-api/codex; false => api.openai.com/v1
	}{
		{"env key set beats everything", map[string]string{"OPENAI_API_KEY": "sk-env"}, chatgptJSON, false},
		{"auth_mode apikey", map[string]string{}, apikeyJSON, false},
		{"auth.json has api key field", map[string]string{}, []byte(`{"OPENAI_API_KEY":"sk-y"}`), false},
		{"auth_mode chatgpt", map[string]string{}, chatgptJSON, true},
		{"auth.json absent", map[string]string{}, nil, true},
		{"auth.json unparseable", map[string]string{}, []byte(`{not json`), true},
		{"auth_mode empty", map[string]string{}, []byte(`{"auth_mode":""}`), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := chooseCodexBackend(c.env, c.auth)
			if c.wantSub {
				if got.UpstreamBase != chatGPTBase || got.ConfigPath != chatGPTPath {
					t.Errorf("got %+v, want subscription (%s%s)", got, chatGPTBase, chatGPTPath)
				}
			} else {
				if got.UpstreamBase != openAIAPIBase || got.ConfigPath != openAIAPIPath {
					t.Errorf("got %+v, want api-key (%s%s)", got, openAIAPIBase, openAIAPIPath)
				}
			}
		})
	}
}
