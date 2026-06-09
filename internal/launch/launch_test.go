package launch

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/outgate-ai/og-local/internal/provider"
)

func osPipe(t *testing.T) (read, write *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	return r, w
}

type recordingRunner struct {
	argv     []string
	env      []string
	exitCode int
	runErr   error
	onRun    func(env []string)
}

func (r *recordingRunner) Run(_ context.Context, argv, env []string, _ Stdio) (int, error) {
	r.argv = argv
	r.env = env
	if r.onRun != nil {
		r.onRun(env)
	}
	return r.exitCode, r.runErr
}

func envValue(environ []string, key string) string {
	for _, kv := range environ {
		if strings.HasPrefix(kv, key+"=") {
			return strings.TrimPrefix(kv, key+"=")
		}
	}
	return ""
}

func okHandler() HandlerFunc {
	return func(_ string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	}
}

func TestRunWiresServerAndChildEnv(t *testing.T) {
	var serverReachable bool
	var childBase string
	runner := &recordingRunner{
		exitCode: 0,
		onRun: func(env []string) {
			childBase = envValue(env, "ANTHROPIC_BASE_URL")
			resp, err := http.Get(childBase) //nolint:gosec // hitting our own freshly-bound loopback server in-test.
			if err == nil {
				_ = resp.Body.Close()
				serverReachable = resp.StatusCode == http.StatusOK
			}
		},
	}
	code, err := Run(context.Background(), Options{
		Kind:        provider.Anthropic,
		Args:        []string{"claude", "do a thing"},
		Env:         map[string]string{"ANTHROPIC_API_KEY": "sk-real", "PATH": "/usr/bin"},
		LoopbackTok: "ogl_live_tok",
		Handler:     okHandler(),
		Runner:      runner,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
	if !serverReachable {
		t.Error("loopback server was not reachable from the child")
	}
	if !strings.HasPrefix(childBase, "http://127.0.0.1:") || !strings.Contains(childBase, "/_k/ogl_live_tok") {
		t.Errorf("child base = %q, want loopback with /_k/<token>", childBase)
	}
	if got := envValue(runner.env, "ANTHROPIC_API_KEY"); got != "sk-real" {
		t.Errorf("child key = %q, want the agent's own key preserved", got)
	}
	if got := envValue(runner.env, "PATH"); got != "/usr/bin" {
		t.Errorf("inherited PATH dropped: %q", got)
	}
	if runner.argv[0] != "claude" {
		t.Errorf("argv = %v", runner.argv)
	}
}

func TestRunMirrorsExitCode(t *testing.T) {
	runner := &recordingRunner{exitCode: 7}
	code, err := Run(context.Background(), Options{
		Kind:        provider.OpenAIChat,
		Args:        []string{"codex"},
		Env:         map[string]string{"OPENAI_API_KEY": "sk"},
		LoopbackTok: "tok",
		Handler:     okHandler(),
		Runner:      runner,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 7 {
		t.Errorf("exit = %d, want 7 (child's code)", code)
	}
}

func TestRunResolveErrorClosesListener(t *testing.T) {
	var ln net.Listener
	listen := func() (net.Listener, error) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		ln = l
		return l, err
	}
	// Passthrough is unsupported by Resolve, which triggers the error path.
	_, err := Run(context.Background(), Options{
		Kind:        provider.Passthrough,
		Args:        []string{"x"},
		Env:         map[string]string{},
		LoopbackTok: "tok",
		Handler:     okHandler(),
		Runner:      &recordingRunner{},
		Listen:      listen,
	})
	if err == nil {
		t.Fatal("expected resolve error")
	}
	if ln != nil {
		if _, e := ln.Accept(); e == nil {
			t.Error("listener should be closed after resolve error")
		}
	}
}

func TestRunListenError(t *testing.T) {
	_, err := Run(context.Background(), Options{
		Kind:    provider.Anthropic,
		Env:     map[string]string{"ANTHROPIC_API_KEY": "sk"},
		Handler: okHandler(),
		Runner:  &recordingRunner{},
		Listen:  func() (net.Listener, error) { return nil, errors.New("bind failed") },
	})
	if err == nil {
		t.Error("expected listen error")
	}
}

func TestRunPropagatesRunnerError(t *testing.T) {
	runner := &recordingRunner{runErr: errors.New("spawn failed")}
	_, err := Run(context.Background(), Options{
		Kind:        provider.Anthropic,
		Args:        []string{"claude"},
		Env:         map[string]string{"ANTHROPIC_API_KEY": "sk"},
		LoopbackTok: "tok",
		Handler:     okHandler(),
		Runner:      runner,
	})
	if err == nil {
		t.Error("expected runner error to propagate")
	}
}

func TestExecRunnerExitCode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX sh")
	}
	code, err := ExecRunner{}.Run(context.Background(), []string{"sh", "-c", "exit 5"}, nil, Stdio{})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 5 {
		t.Errorf("exit = %d, want 5", code)
	}
}

func TestExecRunnerSuccessAndStdout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX sh")
	}
	r, w := osPipe(t)
	code, err := ExecRunner{}.Run(context.Background(), []string{"sh", "-c", "printf hello"}, nil, Stdio{Out: w})
	_ = w.Close()
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	out, _ := io.ReadAll(r)
	if string(out) != "hello" {
		t.Errorf("stdout = %q", out)
	}
}

func TestExecRunnerEmptyArgv(t *testing.T) {
	if _, err := (ExecRunner{}).Run(context.Background(), nil, nil, Stdio{}); err == nil {
		t.Error("expected error on empty argv")
	}
}

func TestExecRunnerBadCommand(t *testing.T) {
	_, err := ExecRunner{}.Run(context.Background(), []string{"this-command-does-not-exist-ogl"}, nil, Stdio{})
	if err == nil {
		t.Error("expected error for missing executable")
	}
}

func TestRunPrepareChildAddsToEnv(t *testing.T) {
	runner := &recordingRunner{exitCode: 0}
	var gotURL, gotTok string
	code, err := Run(context.Background(), Options{
		Kind:        provider.OpenAIChat,
		Args:        []string{"codex"},
		Env:         map[string]string{"OPENAI_API_KEY": "sk-real"},
		LoopbackTok: "ogl_live_tok",
		Handler:     okHandler(),
		Runner:      runner,
		PrepareChild: func(loopbackURL, token string) (map[string]string, error) {
			gotURL, gotTok = loopbackURL, token
			return map[string]string{"CODEX_HOME": "/tmp/x"}, nil
		},
	})
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if !strings.HasPrefix(gotURL, "http://127.0.0.1:") || gotTok != "ogl_live_tok" {
		t.Errorf("hook got url=%q tok=%q", gotURL, gotTok)
	}
	if got := envValue(runner.env, "CODEX_HOME"); got != "/tmp/x" {
		t.Errorf("CODEX_HOME = %q, want /tmp/x", got)
	}
	// The base-URL overlay still applies alongside the hook's additions.
	if got := envValue(runner.env, "OPENAI_BASE_URL"); !strings.Contains(got, "/_k/") {
		t.Errorf("OPENAI_BASE_URL overlay lost: %q", got)
	}
}

func TestRunNilPrepareChildNoCodexHome(t *testing.T) {
	runner := &recordingRunner{exitCode: 0}
	_, err := Run(context.Background(), Options{
		Kind:        provider.Anthropic,
		Args:        []string{"claude"},
		Env:         map[string]string{"ANTHROPIC_API_KEY": "sk"},
		LoopbackTok: "tok",
		Handler:     okHandler(),
		Runner:      runner,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := envValue(runner.env, "CODEX_HOME"); got != "" {
		t.Errorf("claude must not get CODEX_HOME, got %q", got)
	}
}

func TestRunPrepareChildErrorFailsLaunch(t *testing.T) {
	runner := &recordingRunner{exitCode: 0}
	code, err := Run(context.Background(), Options{
		Kind:        provider.OpenAIChat,
		Args:        []string{"codex"},
		Env:         map[string]string{"OPENAI_API_KEY": "sk"},
		LoopbackTok: "tok",
		Handler:     okHandler(),
		Runner:      runner,
		PrepareChild: func(string, string) (map[string]string, error) {
			return nil, errors.New("prepare failed")
		},
	})
	if err == nil {
		t.Error("expected PrepareChild error to fail the launch")
	}
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	if runner.argv != nil {
		t.Error("runner must not be invoked when PrepareChild fails")
	}
}

func TestNewCodexPrepareWiresPrepareCodexHome(t *testing.T) {
	home := t.TempDir()
	prep := newCodexPrepare(osCodexFS{}, home, "/v1")
	env, err := prep("http://127.0.0.1:5000", "tok")
	if err != nil {
		t.Fatalf("prep: %v", err)
	}
	if env["CODEX_HOME"] != codexHomeDir(home) {
		t.Errorf("CODEX_HOME = %q", env["CODEX_HOME"])
	}
}

func TestRunUpstreamOverrideBeatsResolve(t *testing.T) {
	var gotUpstream string
	handler := func(upstreamBase string) http.Handler {
		gotUpstream = upstreamBase
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	}
	_, err := Run(context.Background(), Options{
		Kind:             provider.OpenAIChat,
		Args:             []string{"codex"},
		Env:              map[string]string{"OPENAI_API_KEY": "sk"},
		LoopbackTok:      "tok",
		Handler:          handler,
		Runner:           &recordingRunner{},
		UpstreamOverride: "https://chatgpt.com",
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if gotUpstream != "https://chatgpt.com" {
		t.Errorf("handler upstream = %q, want the override https://chatgpt.com", gotUpstream)
	}
}

func TestRunNoOverrideUsesResolveDefault(t *testing.T) {
	var gotUpstream string
	handler := func(upstreamBase string) http.Handler {
		gotUpstream = upstreamBase
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	}
	_, err := Run(context.Background(), Options{
		Kind:        provider.Anthropic,
		Args:        []string{"claude"},
		Env:         map[string]string{"ANTHROPIC_API_KEY": "sk"},
		LoopbackTok: "tok",
		Handler:     handler,
		Runner:      &recordingRunner{},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if gotUpstream != "https://api.anthropic.com" {
		t.Errorf("handler upstream = %q, want the Resolve default (claude unchanged)", gotUpstream)
	}
}
