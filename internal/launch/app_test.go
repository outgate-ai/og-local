package launch

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/outgate-ai/og-local/internal/obs"
	"github.com/outgate-ai/og-local/internal/pii"
	"github.com/outgate-ai/og-local/internal/provider"
	"github.com/outgate-ai/og-local/internal/testutil/fakeclock"
	"github.com/outgate-ai/og-local/internal/token"
)

type noopDetector struct{}

func (noopDetector) Detect(_ context.Context, _ string) ([]pii.Span, error) { return nil, nil }

func testApp(runner Runner, environ []string) *App {
	return &App{
		NewDetector: func() (pii.Detector, func() error, error) { return noopDetector{}, func() error { return nil }, nil },
		NewMinter: func() (*token.Minter, error) {
			return token.NewMinter(4242, fakeclock.New(time.Unix(1_700_000_000, 0)), time.Hour)
		},
		Environ: func() []string { return environ },
		Runner:  runner,
	}
}

func TestAppMainHappyPath(t *testing.T) {
	runner := &recordingRunner{exitCode: 0}
	app := testApp(runner, []string{"ANTHROPIC_API_KEY=sk-real", "PATH=/usr/bin"})
	code, err := app.Main(context.Background(), provider.Anthropic, []string{"claude", "hello"})
	if err != nil {
		t.Fatalf("main: %v", err)
	}
	if code != 0 {
		t.Errorf("code = %d", code)
	}
	if runner.argv[0] != "claude" || runner.argv[1] != "hello" {
		t.Errorf("argv = %v", runner.argv)
	}
	if got := envValue(runner.env, "ANTHROPIC_BASE_URL"); !strings.Contains(got, "/_k/") {
		t.Errorf("child base URL = %q, want loopback with /_k/ token path", got)
	}
	if got := envValue(runner.env, "ANTHROPIC_API_KEY"); got != "sk-real" {
		t.Errorf("child key = %q, want the agent's own key preserved (not swapped)", got)
	}
}

func TestAppMainMirrorsExit(t *testing.T) {
	runner := &recordingRunner{exitCode: 3}
	app := testApp(runner, []string{"OPENAI_API_KEY=sk"})
	code, err := app.Main(context.Background(), provider.OpenAIChat, []string{"codex"})
	if err != nil || code != 3 {
		t.Fatalf("code=%d err=%v", code, err)
	}
}

func TestAppMainDetectorPreflightFails(t *testing.T) {
	app := testApp(&recordingRunner{}, []string{"ANTHROPIC_API_KEY=sk"})
	app.NewDetector = func() (pii.Detector, func() error, error) {
		return nil, nil, errors.New("reinstall with -tags onnx")
	}
	code, err := app.Main(context.Background(), provider.Anthropic, []string{"claude"})
	if err == nil {
		t.Fatal("expected preflight error before launch")
	}
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
}

func TestAppMainMinterFails(t *testing.T) {
	app := testApp(&recordingRunner{}, []string{"ANTHROPIC_API_KEY=sk"})
	app.NewMinter = func() (*token.Minter, error) { return nil, errors.New("no secret") }
	if _, err := app.Main(context.Background(), provider.Anthropic, []string{"claude"}); err == nil {
		t.Error("expected minter error")
	}
}

func TestAppMainLaunchesWithoutAPIKey(t *testing.T) {
	runner := &recordingRunner{exitCode: 0}
	app := testApp(runner, []string{"PATH=/usr/bin"})
	code, err := app.Main(context.Background(), provider.Anthropic, []string{"claude"})
	if err != nil {
		t.Fatalf("must launch without an API key, got %v", err)
	}
	if code != 0 {
		t.Errorf("code = %d", code)
	}
	if got := envValue(runner.env, "ANTHROPIC_BASE_URL"); !strings.Contains(got, "/_k/") {
		t.Errorf("child base URL = %q, want loopback token path", got)
	}
}

func TestDefaultAppWiring(t *testing.T) {
	app := DefaultApp()
	if app.NewDetector == nil || app.NewMinter == nil || app.Environ == nil || app.Runner == nil {
		t.Error("DefaultApp left a seam nil")
	}
	m, err := app.NewMinter()
	if err != nil || m == nil {
		t.Errorf("default minter: %v", err)
	}
}

func TestRealClockNow(t *testing.T) {
	if (realClock{}).Now().IsZero() {
		t.Error("realClock returned zero time")
	}
}

func TestAppMainWithDebugLogger(t *testing.T) {
	var buf bytes.Buffer
	runner := &recordingRunner{exitCode: 0}
	app := testApp(runner, []string{"ANTHROPIC_API_KEY=sk-real"})
	app.Logger = obs.Debug(&buf)
	if _, err := app.Main(context.Background(), provider.Anthropic, []string{"claude", "hi"}); err != nil {
		t.Fatalf("main: %v", err)
	}
}

func TestDebugLogPathResolution(t *testing.T) {
	if _, on := debugLogPath(""); on {
		t.Error("empty OGL_DEBUG must disable logging")
	}
	for _, v := range []string{"1", "true", "yes", "on"} {
		p, on := debugLogPath(v)
		if !on {
			t.Errorf("%q must enable logging", v)
		}
		if filepath.Base(p) != "debug.log" {
			t.Errorf("%q -> %q, want default debug.log under cache root", v, p)
		}
	}
	p, on := debugLogPath("/custom/where.log")
	if !on || p != "/custom/where.log" {
		t.Errorf("custom path = (%q,%v), want (/custom/where.log,true)", p, on)
	}
}

func TestOpenDebugLogWritesToFileAndAnnounces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "debug.log")
	var notice bytes.Buffer
	logger, closer := openDebugLog(path, &notice)
	if logger == nil {
		t.Fatal("expected a logger for an explicit path")
	}
	logger.Debug("hello", "k", "v")
	// Close before the t.TempDir cleanup runs; Windows refuses to remove a file
	// that is still open.
	if err := closer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if !strings.Contains(notice.String(), path) {
		t.Errorf("startup notice should name the path: %q", notice.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !strings.Contains(string(data), "hello") {
		t.Errorf("debug record not written to file: %q", data)
	}
}

func TestOpenDebugLogDisabled(t *testing.T) {
	logger, closer := openDebugLog("", &bytes.Buffer{})
	if logger != nil {
		t.Error("empty value must yield no logger")
	}
	if err := closer.Close(); err != nil {
		t.Errorf("disabled closer must be a safe no-op: %v", err)
	}
}

func TestOpenDebugLogUnwritablePathFallsBack(t *testing.T) {
	var notice bytes.Buffer
	// A path whose parent is a file, not a directory, cannot be created.
	bad := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(bad, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	logger, closer := openDebugLog(filepath.Join(bad, "nested.log"), &notice)
	if logger != nil {
		t.Error("unwritable path must fall back to no logger")
	}
	_ = closer.Close()
	if !strings.Contains(notice.String(), "could not open debug log") {
		t.Errorf("expected a fallback notice, got %q", notice.String())
	}
}

func TestDefaultNewDetectorUnavailableInPureGoBuild(t *testing.T) {
	det, closeFn, err := defaultNewDetector()
	if err == nil {
		t.Fatal("pure-Go build must not produce a working detector")
	}
	if det != nil || closeFn != nil {
		t.Errorf("on error, detector/close must be nil: det=%v closeNil=%v", det, closeFn == nil)
	}
}

func TestAppMainPrepareChildThreadsCodexHome(t *testing.T) {
	runner := &recordingRunner{exitCode: 0}
	app := testApp(runner, []string{"OPENAI_API_KEY=sk-real"})
	app.PrepareChild = func(string, string) (map[string]string, error) {
		return map[string]string{"CODEX_HOME": "/tmp/ogl-home"}, nil
	}
	if _, err := app.Main(context.Background(), provider.OpenAIChat, []string{"codex"}); err != nil {
		t.Fatalf("main: %v", err)
	}
	if got := envValue(runner.env, "CODEX_HOME"); got != "/tmp/ogl-home" {
		t.Errorf("CODEX_HOME = %q, want /tmp/ogl-home", got)
	}
}

func TestAppMainNilPrepareChildNoCodexHome(t *testing.T) {
	runner := &recordingRunner{exitCode: 0}
	app := testApp(runner, []string{"ANTHROPIC_API_KEY=sk"})
	// PrepareChild left nil (the claude path).
	if _, err := app.Main(context.Background(), provider.Anthropic, []string{"claude"}); err != nil {
		t.Fatalf("main: %v", err)
	}
	if got := envValue(runner.env, "CODEX_HOME"); got != "" {
		t.Errorf("claude must not set CODEX_HOME, got %q", got)
	}
}

func TestDefaultAppHasNilPrepareChild(t *testing.T) {
	if DefaultApp().PrepareChild != nil {
		t.Error("DefaultApp must leave PrepareChild nil; the cmd layer wires it for codex")
	}
}

func TestCodexPrepareProducesWorkingHook(t *testing.T) {
	home := t.TempDir()
	hook := CodexPrepare(home)
	env, err := hook("http://127.0.0.1:5000", "tok")
	if err != nil {
		t.Fatalf("hook: %v", err)
	}
	if env["CODEX_HOME"] != codexHomeDir(home) {
		t.Errorf("CODEX_HOME = %q", env["CODEX_HOME"])
	}
}
