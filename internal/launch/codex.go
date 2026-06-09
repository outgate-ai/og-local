package launch

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	openAIAPIBase = "https://api.openai.com"
	openAIAPIPath = "/v1"
	chatGPTBase   = "https://chatgpt.com"
	chatGPTPath   = "/backend-api/codex"
)

type codexBackend struct {
	UpstreamBase string
	ConfigPath   string
}

func chooseCodexBackend(env map[string]string, authJSON []byte) codexBackend {
	apiKey := codexBackend{UpstreamBase: openAIAPIBase, ConfigPath: openAIAPIPath}
	subscription := codexBackend{UpstreamBase: chatGPTBase, ConfigPath: chatGPTPath}

	if env["OPENAI_API_KEY"] != "" {
		return apiKey
	}
	var auth struct {
		AuthMode     string `json:"auth_mode"`
		OpenAIAPIKey string `json:"OPENAI_API_KEY"`
	}
	if err := json.Unmarshal(authJSON, &auth); err == nil {
		if auth.AuthMode == "apikey" || auth.OpenAIAPIKey != "" {
			return apiKey
		}
	}
	return subscription
}

type codexFS interface {
	MkdirAll(path string, perm fs.FileMode) error
	WriteFile(path string, data []byte, perm fs.FileMode) error
	ReadFile(path string) ([]byte, error)
}

type osCodexFS struct{}

func (osCodexFS) MkdirAll(path string, perm fs.FileMode) error {
	return os.MkdirAll(path, perm) //nolint:gosec // a directory under the user's home, not network input.
}

func (osCodexFS) WriteFile(path string, data []byte, perm fs.FileMode) error {
	return os.WriteFile(path, data, perm) //nolint:gosec // a file under the user's home, not network input.
}

func (osCodexFS) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path) //nolint:gosec // the user's own codex auth file under their home.
}

func codexHomeDir(userHome string) string {
	return filepath.Join(userHome, ".codex", "ogl")
}

func prepareCodexHome(fsys codexFS, userHome, loopbackURL, token, configPath string) (map[string]string, error) {
	dir := codexHomeDir(userHome)
	if err := fsys.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	base := strings.TrimRight(loopbackURL, "/") + "/_k/" + token + configPath
	if err := fsys.WriteFile(filepath.Join(dir, "config.toml"), []byte(renderCodexConfig(base)), 0o600); err != nil {
		return nil, err
	}
	src := filepath.Join(userHome, ".codex", "auth.json")
	if data, err := fsys.ReadFile(src); err == nil {
		if werr := fsys.WriteFile(filepath.Join(dir, "auth.json"), data, 0o600); werr != nil {
			return nil, werr
		}
	}
	return map[string]string{"CODEX_HOME": dir}, nil
}

func newCodexPrepare(fsys codexFS, userHome, configPath string) func(loopbackURL, token string) (map[string]string, error) {
	return func(loopbackURL, token string) (map[string]string, error) {
		return prepareCodexHome(fsys, userHome, loopbackURL, token, configPath)
	}
}

// CodexLaunch carries the codex-specific launch overrides: the proxy upstream
// and the PrepareChild hook that writes the synthetic Codex home.
type CodexLaunch struct {
	UpstreamBase string
	PrepareChild func(loopbackURL, token string) (map[string]string, error)
}

func newCodexLaunch(fsys codexFS, userHome string, env map[string]string, authJSON []byte) CodexLaunch {
	backend := chooseCodexBackend(env, authJSON)
	return CodexLaunch{
		UpstreamBase: backend.UpstreamBase,
		PrepareChild: newCodexPrepare(fsys, userHome, backend.ConfigPath),
	}
}

// CodexLaunchFor reads the Codex auth mode under userHome and returns the
// matching upstream and PrepareChild hook (subscription vs. API key).
func CodexLaunchFor(userHome string, env map[string]string) CodexLaunch {
	fsys := osCodexFS{}
	authJSON, _ := fsys.ReadFile(filepath.Join(userHome, ".codex", "auth.json"))
	return newCodexLaunch(fsys, userHome, env, authJSON)
}

func renderCodexConfig(baseURL string) string {
	return `profile = "ogl"

[model_providers.ogl]
name = "ogl"
base_url = "` + baseURL + `"
wire_api = "responses"
requires_openai_auth = true

[profiles.ogl]
model_provider = "ogl"
`
}
