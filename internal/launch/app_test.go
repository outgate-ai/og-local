package launch

import (
	"context"
	"errors"
	"testing"
	"time"

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
	if got := envValue(runner.env, "ANTHROPIC_BASE_URL"); got == "" {
		t.Error("child base URL not set")
	}
	if got := envValue(runner.env, "ANTHROPIC_API_KEY"); got == "sk-real" {
		t.Error("child still has the real key; should be the loopback token")
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

func TestAppMainMissingKey(t *testing.T) {
	app := testApp(&recordingRunner{}, []string{"PATH=/usr/bin"})
	if _, err := app.Main(context.Background(), provider.Anthropic, []string{"claude"}); err == nil {
		t.Error("expected missing-key error from Resolve")
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

func TestDefaultNewDetectorUnavailableInPureGoBuild(t *testing.T) {
	det, closeFn, err := defaultNewDetector()
	if err == nil {
		t.Fatal("pure-Go build must not produce a working detector")
	}
	if det != nil || closeFn != nil {
		t.Errorf("on error, detector/close must be nil: det=%v closeNil=%v", det, closeFn == nil)
	}
}
