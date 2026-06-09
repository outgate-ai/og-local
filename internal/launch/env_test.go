package launch

import (
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
	if r.UpstreamKey != "sk-ant-real" {
		t.Errorf("key = %q", r.UpstreamKey)
	}
	if r.ChildEnv["ANTHROPIC_BASE_URL"] != "http://127.0.0.1:5000" {
		t.Errorf("child base = %q", r.ChildEnv["ANTHROPIC_BASE_URL"])
	}
	if r.ChildEnv["ANTHROPIC_API_KEY"] != "ogl_live_tok" {
		t.Errorf("child key = %q, want loopback token", r.ChildEnv["ANTHROPIC_API_KEY"])
	}
}

func TestResolveOpenAIDefaultUpstream(t *testing.T) {
	env := map[string]string{"OPENAI_API_KEY": "sk-oai-real"}
	r, err := Resolve(provider.OpenAIChat, env, "http://127.0.0.1:6000", "ogl_live_tok2")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.UpstreamBase != "https://api.openai.com" {
		t.Errorf("upstream = %q", r.UpstreamBase)
	}
	if r.ChildEnv["OPENAI_BASE_URL"] != "http://127.0.0.1:6000" {
		t.Errorf("child base = %q", r.ChildEnv["OPENAI_BASE_URL"])
	}
	if r.ChildEnv["OPENAI_API_KEY"] != "ogl_live_tok2" {
		t.Errorf("child key = %q", r.ChildEnv["OPENAI_API_KEY"])
	}
}

func TestResolveChainsExistingBaseURL(t *testing.T) {
	env := map[string]string{
		"ANTHROPIC_API_KEY":  "sk-ant-real",
		"ANTHROPIC_BASE_URL": "https://my-gateway.internal/anthropic",
	}
	r, err := Resolve(provider.Anthropic, env, "http://127.0.0.1:5000", "tok")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.UpstreamBase != "https://my-gateway.internal/anthropic" {
		t.Errorf("upstream should chain to user's base URL, got %q", r.UpstreamBase)
	}
	// The child must still point at the loopback proxy, not the chained upstream.
	if r.ChildEnv["ANTHROPIC_BASE_URL"] != "http://127.0.0.1:5000" {
		t.Errorf("child base = %q, want loopback", r.ChildEnv["ANTHROPIC_BASE_URL"])
	}
}

func TestResolveMissingKey(t *testing.T) {
	if _, err := Resolve(provider.Anthropic, map[string]string{}, "http://x", "tok"); err == nil {
		t.Error("expected error when API key is unset")
	}
	if _, err := Resolve(provider.OpenAIChat, map[string]string{"ANTHROPIC_API_KEY": "x"}, "http://x", "tok"); err == nil {
		t.Error("expected error when OpenAI key is unset")
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
