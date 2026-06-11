package launch

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
)

func failLookPath(string) (string, error) { return "", errors.New("not found") }

func noShell(context.Context, string, ...string) (string, error) {
	return "", errors.New("no shell in this test")
}

func TestResolveAgentOverrideWins(t *testing.T) {
	env := []string{"OGL_CLAUDE_BIN=/opt/agents/claude", "SHELL=/bin/zsh"}
	got, err := resolveAgent(context.Background(), "claude", env, failLookPath, noShell)
	if err != nil || got != "/opt/agents/claude" {
		t.Fatalf("got %q err=%v", got, err)
	}
}

func TestResolveAgentPathHit(t *testing.T) {
	lookPath := func(name string) (string, error) { return "/usr/bin/" + name, nil }
	got, err := resolveAgent(context.Background(), "codex", nil, lookPath, noShell)
	if err != nil || got != "/usr/bin/codex" {
		t.Fatalf("got %q err=%v", got, err)
	}
}

func TestResolveAgentShellFallback(t *testing.T) {
	var calls [][]string
	shellOut := func(_ context.Context, shell string, args ...string) (string, error) {
		calls = append(calls, append([]string{shell}, args...))
		if len(calls) == 1 {
			return "", nil // login shell: rc files not sourced, nothing found
		}
		return "Now using node v20.19.0 (npm v10.8.2)\n/Users/u/.nvm/versions/node/v20.19.0/bin/claude\n", nil
	}
	env := []string{"SHELL=/bin/zsh"}
	got, err := resolveAgent(context.Background(), "claude", env, failLookPath, shellOut)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "/Users/u/.nvm/versions/node/v20.19.0/bin/claude" {
		t.Errorf("got %q", got)
	}
	if len(calls) != 2 || calls[0][1] != "-l" || calls[1][1] != "-i" {
		t.Errorf("probe order = %v", calls)
	}
	if last := calls[1][len(calls[1])-1]; last != "command -v -- claude" {
		t.Errorf("probe script = %q", last)
	}
}

func TestResolveAgentShellErrorsSkipped(t *testing.T) {
	shellOut := func(context.Context, string, ...string) (string, error) {
		return "", errors.New("boom")
	}
	_, err := resolveAgent(context.Background(), "claude", []string{"SHELL=/bin/zsh"}, failLookPath, shellOut)
	if err == nil || !strings.Contains(err.Error(), "OGL_CLAUDE_BIN") {
		t.Fatalf("want hint error, got %v", err)
	}
}

func TestResolveAgentNoShell(t *testing.T) {
	_, err := resolveAgent(context.Background(), "codex", nil, failLookPath, noShell)
	if err == nil || !strings.Contains(err.Error(), "OGL_CODEX_BIN") {
		t.Fatalf("want hint error, got %v", err)
	}
}

func TestLastAbsLine(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/usr/bin/claude\n", "/usr/bin/claude"},
		{"noise line\n  /a/b  \n", "/a/b"},
		{"alias claude=x\nnot-a-path\n", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := lastAbsLine(c.in); got != c.want {
			t.Errorf("lastAbsLine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRunShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX sh")
	}
	out, err := runShell(context.Background(), "/bin/sh", "-c", "printf /tmp/agent")
	if err != nil || out != "/tmp/agent" {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

func TestEnvValue(t *testing.T) {
	env := []string{"A=1", "SHELL=/bin/zsh", "SHELLX=/no"}
	if got := envValue(env, "SHELL"); got != "/bin/zsh" {
		t.Errorf("SHELL = %q", got)
	}
	if got := envValue(env, "B"); got != "" {
		t.Errorf("B = %q", got)
	}
}
