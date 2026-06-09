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
