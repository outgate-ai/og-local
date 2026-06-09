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

func prepareCodexHome(fsys codexFS, userHome, loopbackURL, token string) (map[string]string, error) {
	dir := codexHomeDir(userHome)
	if err := fsys.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	base := strings.TrimRight(loopbackURL, "/") + "/_k/" + token + "/v1"
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

func newCodexPrepare(fsys codexFS, userHome string) func(loopbackURL, token string) (map[string]string, error) {
	return func(loopbackURL, token string) (map[string]string, error) {
		return prepareCodexHome(fsys, userHome, loopbackURL, token)
	}
}

// CodexPrepare returns a PrepareChild hook that writes the synthetic Codex home
// under userHome and yields the CODEX_HOME overlay.
func CodexPrepare(userHome string) func(loopbackURL, token string) (map[string]string, error) {
	return newCodexPrepare(osCodexFS{}, userHome)
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
