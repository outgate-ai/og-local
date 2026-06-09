package launch

import (
	"strings"
	"testing"

	"github.com/outgate-ai/og-local/internal/provider"
)

func TestResolveAnthropicDefaultUpstream(t *testing.T) {
	env := map[string]string{"ANTHROPIC_API_KEY": "sk-ant-real"}
	r, err := Resolve(provider.Anthropic, env, "http://127.0.0.1:5000", "ogl_live_tok")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.UpstreamBase != "https://api.anthropic.com" {
		t.Errorf("upstream = %q", r.UpstreamBase)
	}
	if want := "http://127.0.0.1:5000/_k/ogl_live_tok"; r.ChildEnv["ANTHROPIC_BASE_URL"] != want {
		t.Errorf("child base = %q, want %q", r.ChildEnv["ANTHROPIC_BASE_URL"], want)
	}
	if _, set := r.ChildEnv["ANTHROPIC_API_KEY"]; set {
		t.Error("overlay must not touch ANTHROPIC_API_KEY; the agent keeps its own auth")
	}
}

func TestResolveOpenAIDefaultUpstream(t *testing.T) {
	r, err := Resolve(provider.OpenAIChat, map[string]string{}, "http://127.0.0.1:6000", "ogl_live_tok2")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.UpstreamBase != "https://api.openai.com" {
		t.Errorf("upstream = %q", r.UpstreamBase)
	}
	if want := "http://127.0.0.1:6000/_k/ogl_live_tok2"; r.ChildEnv["OPENAI_BASE_URL"] != want {
		t.Errorf("child base = %q, want %q", r.ChildEnv["OPENAI_BASE_URL"], want)
	}
}

func TestResolveNoKeyRequired(t *testing.T) {
	if _, err := Resolve(provider.Anthropic, map[string]string{}, "http://x", "tok"); err != nil {
		t.Errorf("resolve must not require an API key, got %v", err)
	}
	if _, err := Resolve(provider.OpenAIChat, map[string]string{}, "http://x", "tok"); err != nil {
		t.Errorf("resolve must not require an API key, got %v", err)
	}
}

func TestResolveChainsExistingBaseURL(t *testing.T) {
	env := map[string]string{"ANTHROPIC_BASE_URL": "https://my-gateway.internal/anthropic"}
	r, err := Resolve(provider.Anthropic, env, "http://127.0.0.1:5000", "tok")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.UpstreamBase != "https://my-gateway.internal/anthropic" {
		t.Errorf("upstream should chain to user's base URL, got %q", r.UpstreamBase)
	}
	if !strings.HasPrefix(r.ChildEnv["ANTHROPIC_BASE_URL"], "http://127.0.0.1:5000/_k/") {
		t.Errorf("child base = %q, want loopback with token path", r.ChildEnv["ANTHROPIC_BASE_URL"])
	}
}

func TestResolveTrimsTrailingSlashOnLoopback(t *testing.T) {
	r, err := Resolve(provider.Anthropic, map[string]string{}, "http://127.0.0.1:5000/", "tok")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := r.ChildEnv["ANTHROPIC_BASE_URL"]; got != "http://127.0.0.1:5000/_k/tok" {
		t.Errorf("child base = %q, want single slash before _k", got)
	}
}

func TestResolveUnsupportedKind(t *testing.T) {
	if _, err := Resolve(provider.Passthrough, map[string]string{}, "http://x", "tok"); err == nil {
		t.Error("expected error for unsupported kind")
	}
	if _, err := Resolve(provider.Ollama, map[string]string{}, "http://x", "tok"); err == nil {
		t.Error("expected error for ollama (deferred)")
	}
}
