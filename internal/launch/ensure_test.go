package launch

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/outgate-ai/og-local/internal/detector"
	"github.com/outgate-ai/og-local/internal/models"
	"github.com/outgate-ai/og-local/internal/pii"
	"github.com/outgate-ai/og-local/internal/provider"
)

// seqDetector fails with each error in turn, then succeeds.
func seqDetector(errs ...error) func() (pii.Detector, func() error, error) {
	i := 0
	return func() (pii.Detector, func() error, error) {
		if i < len(errs) {
			err := errs[i]
			i++
			return nil, nil, err
		}
		return noopDetector{}, func() error { return nil }, nil
	}
}

func ensureApp(t *testing.T, errs ...error) (app *App, runner *recordingRunner, prompts *[]string, modelPulls, runtimePulls *int) {
	t.Helper()
	runner = &recordingRunner{exitCode: 0}
	app = testApp(runner, []string{"ANTHROPIC_API_KEY=sk"})
	app.NewDetector = seqDetector(errs...)
	prompts = &[]string{}
	modelPulls, runtimePulls = new(int), new(int)
	app.Confirm = func(msg string) bool { *prompts = append(*prompts, msg); return true }
	app.PullModel = func(context.Context) error { *modelPulls++; return nil }
	app.PullRuntime = func(context.Context) error { *runtimePulls++; return nil }
	return app, runner, prompts, modelPulls, runtimePulls
}

func TestMainOffersModelDownload(t *testing.T) {
	app, runner, prompts, modelPulls, _ := ensureApp(t, detector.ErrModelMissing)
	code, err := app.Main(context.Background(), provider.Anthropic, []string{"claude"})
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if *modelPulls != 1 {
		t.Errorf("model pulls = %d, want 1", *modelPulls)
	}
	if len(*prompts) != 1 || !strings.Contains((*prompts)[0], "openai/privacy-filter") || !strings.Contains((*prompts)[0], "837 MB") {
		t.Errorf("prompt = %q, want model name + size", *prompts)
	}
	if runner.argv == nil {
		t.Error("agent must launch after the download")
	}
}

func TestMainOffersRuntimeDownload(t *testing.T) {
	app, _, prompts, _, runtimePulls := ensureApp(t, models.ErrRuntimeNotFound)
	code, err := app.Main(context.Background(), provider.Anthropic, []string{"claude"})
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if *runtimePulls != 1 {
		t.Errorf("runtime pulls = %d, want 1", *runtimePulls)
	}
	want := humanSize(models.RuntimeDownloadSize())
	if len(*prompts) != 1 || !strings.Contains((*prompts)[0], "ONNX Runtime") || !strings.Contains((*prompts)[0], want) {
		t.Errorf("prompt = %q, want runtime mention + %q", *prompts, want)
	}
}

func TestMainFixesModelThenRuntime(t *testing.T) {
	app, _, prompts, modelPulls, runtimePulls := ensureApp(t, detector.ErrModelMissing, models.ErrRuntimeNotFound)
	code, err := app.Main(context.Background(), provider.Anthropic, []string{"claude"})
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if *modelPulls != 1 || *runtimePulls != 1 || len(*prompts) != 2 {
		t.Errorf("modelPulls=%d runtimePulls=%d prompts=%d, want 1/1/2", *modelPulls, *runtimePulls, len(*prompts))
	}
}

func TestMainDeclinedPromptKeepsError(t *testing.T) {
	app, runner, _, modelPulls, _ := ensureApp(t, detector.ErrModelMissing)
	app.Confirm = func(string) bool { return false }
	code, err := app.Main(context.Background(), provider.Anthropic, []string{"claude"})
	if !errors.Is(err, detector.ErrModelMissing) || code != 1 {
		t.Fatalf("code=%d err=%v, want the original error", code, err)
	}
	if *modelPulls != 0 {
		t.Errorf("model pulls = %d, want 0 after decline", *modelPulls)
	}
	if runner.argv != nil {
		t.Error("agent must not launch")
	}
}

func TestMainNoPromptForOtherErrors(t *testing.T) {
	for _, e := range []error{detector.ErrUnavailable, errors.New("boom")} {
		app, _, prompts, _, _ := ensureApp(t, e)
		if _, err := app.Main(context.Background(), provider.Anthropic, []string{"claude"}); !errors.Is(err, e) {
			t.Fatalf("err = %v, want %v", err, e)
		}
		if len(*prompts) != 0 {
			t.Errorf("prompts = %q, want none for %v", *prompts, e)
		}
	}
}

func TestMainNilConfirmKeepsFailFast(t *testing.T) {
	runner := &recordingRunner{}
	app := testApp(runner, []string{"ANTHROPIC_API_KEY=sk"})
	app.NewDetector = seqDetector(detector.ErrModelMissing)
	code, err := app.Main(context.Background(), provider.Anthropic, []string{"claude"})
	if !errors.Is(err, detector.ErrModelMissing) || code != 1 {
		t.Fatalf("code=%d err=%v, want fail-fast with nil Confirm", code, err)
	}
}

func TestMainPullFailureSurfaces(t *testing.T) {
	app, _, _, _, _ := ensureApp(t, detector.ErrModelMissing)
	app.PullModel = func(context.Context) error { return errors.New("network gone") }
	r, w := osPipe(t)
	app.Stdio.Err = w
	code, err := app.Main(context.Background(), provider.Anthropic, []string{"claude"})
	_ = w.Close()
	if !errors.Is(err, detector.ErrModelMissing) || code != 1 {
		t.Fatalf("code=%d err=%v, want original error after failed pull", code, err)
	}
	out, _ := io.ReadAll(r)
	if !strings.Contains(string(out), "download failed: network gone") {
		t.Errorf("stderr = %q, want download-failed notice", out)
	}
}

func TestConfirmFrom(t *testing.T) {
	yes := func() bool { return true }
	cases := []struct {
		input string
		want  bool
	}{
		{"\n", true},
		{"y\n", true},
		{"Y\n", true},
		{"yes\n", true},
		{"n\n", false},
		{"no\n", false},
		{"x\n", false},
		{"y", true},
		{"n", false},
		{"", false},
	}
	for _, c := range cases {
		var out bytes.Buffer
		got := confirmFrom(yes, strings.NewReader(c.input), &out)("Download? [Y/n] ")
		if got != c.want {
			t.Errorf("input %q → %v, want %v", c.input, got, c.want)
		}
		if !strings.Contains(out.String(), "Download?") {
			t.Errorf("prompt not written for %q", c.input)
		}
	}

	var out bytes.Buffer
	if confirmFrom(func() bool { return false }, strings.NewReader("y\n"), &out)("msg") {
		t.Error("non-interactive must decline")
	}
	if out.Len() != 0 {
		t.Error("non-interactive must not write the prompt")
	}
}

func TestStdinIsTerminal(t *testing.T) {
	_ = stdinIsTerminal()
}

func TestHumanSize(t *testing.T) {
	cases := map[int64]string{
		8590023:    "9 MB",
		31717869:   "32 MB",
		837099555:  "837 MB",
		1500000000: "1.5 GB",
		75675381:   "76 MB",
	}
	for n, want := range cases {
		if got := humanSize(n); got != want {
			t.Errorf("humanSize(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestProgressTo(t *testing.T) {
	var buf bytes.Buffer
	p := progressTo(&buf)
	p(models.File{Path: "a"}, 5, 10)
	p(models.File{Path: "b"}, 5, 0)
	out := buf.String()
	if !strings.Contains(out, "a 5/10 bytes") || !strings.Contains(out, "b 5 bytes") {
		t.Errorf("progress output = %q", out)
	}
}

func TestDefaultAppWiresDownloadSeams(t *testing.T) {
	app := DefaultApp()
	if app.Confirm == nil || app.PullModel == nil || app.PullRuntime == nil {
		t.Error("DefaultApp must wire Confirm/PullModel/PullRuntime")
	}
}

func TestDefaultAppPullSeamsRunOffline(t *testing.T) {
	// Stage a cache where everything is already present (sparse files at the
	// exact catalog sizes), so the real pull closures complete without network.
	cache := t.TempDir()
	t.Setenv("OGL_CACHE_DIR", cache)
	m := models.Default()
	dir := models.ModelDir(cache, m)
	for _, f := range m.Files {
		p := filepath.Join(dir, f.Path)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		fh, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := fh.Truncate(f.Size); err != nil {
			t.Fatal(err)
		}
		if err := fh.Close(); err != nil {
			t.Fatal(err)
		}
	}
	rt := filepath.Join(cache, "runtime", runtime.GOOS+"-"+runtime.GOARCH)
	if err := os.MkdirAll(rt, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rt, models.SharedLibName()), []byte("lib"), 0o600); err != nil {
		t.Fatal(err)
	}

	app := DefaultApp()
	if err := app.PullModel(context.Background()); err != nil {
		t.Fatalf("PullModel: %v", err)
	}
	if err := app.PullRuntime(context.Background()); err != nil {
		t.Fatalf("PullRuntime: %v", err)
	}
}

func TestMainPipeStdinDoesNotPrompt(t *testing.T) {
	// A pipe is not a character device, so the default Confirm declines.
	r, _ := osPipe(t)
	fi, err := r.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeCharDevice != 0 {
		t.Skip("pipe unexpectedly reports as a char device")
	}
	var out bytes.Buffer
	isTTY := func() bool {
		st, serr := r.Stat()
		return serr == nil && st.Mode()&os.ModeCharDevice != 0
	}
	if confirmFrom(isTTY, r, &out)("msg") {
		t.Error("pipe stdin must decline")
	}
}
