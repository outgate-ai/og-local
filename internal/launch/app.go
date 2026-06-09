package launch

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/outgate-ai/og-local/internal/models"
	"github.com/outgate-ai/og-local/internal/obs"
	"github.com/outgate-ai/og-local/internal/pii"
	"github.com/outgate-ai/og-local/internal/provider"
	"github.com/outgate-ai/og-local/internal/proxy"
	"github.com/outgate-ai/og-local/internal/redact"
	"github.com/outgate-ai/og-local/internal/storage/memory"
	"github.com/outgate-ai/og-local/internal/token"
)

const (
	cacheEntries = 1024
	tokenTTL     = 30 * 24 * time.Hour
)

type App struct {
	NewDetector func() (pii.Detector, func() error, error)
	NewMinter   func() (*token.Minter, error)
	Environ     func() []string
	Runner      Runner
	Stdio       Stdio
	Logger      *slog.Logger
}

func (a *App) Main(ctx context.Context, kind provider.Kind, args []string) (int, error) {
	det, closeFn, err := a.NewDetector()
	if err != nil {
		return 1, err
	}
	if closeFn != nil {
		defer func() { _ = closeFn() }()
	}

	minter, err := a.NewMinter()
	if err != nil {
		return 1, err
	}
	loopbackTok := minter.Mint()

	cache, err := memory.New[[]pii.Span](cacheEntries)
	if err != nil {
		//coverage:ignore reason=memory.New only fails on a non-positive size, which is a constant here.
		return 1, err
	}
	logger := obs.OrDiscard(a.Logger)
	pipeline := redact.New(det, cache, redact.WithLogger(logger))

	handler := func(upstreamBase string) http.Handler {
		return proxy.New(proxy.Config{
			Minter:       minter,
			Redactor:     pipeline,
			UpstreamBase: upstreamBase,
			Logger:       logger,
		})
	}

	return Run(ctx, Options{
		Kind:        kind,
		Args:        args,
		Env:         mapEnviron(a.Environ()),
		LoopbackTok: loopbackTok,
		Handler:     handler,
		Runner:      a.Runner,
		Stdio:       a.Stdio,
	})
}

func DefaultApp() *App {
	logger := openDebugLog(os.Getenv("OGL_DEBUG"), os.Stderr)
	return &App{
		NewDetector: defaultNewDetector,
		NewMinter:   func() (*token.Minter, error) { return token.NewMinter(int32(os.Getpid()), realClock{}, tokenTTL) }, //nolint:gosec // pid fits int32 on supported platforms.
		Environ:     os.Environ,
		Runner:      ExecRunner{},
		Stdio:       Stdio{In: os.Stdin, Out: os.Stdout, Err: os.Stderr},
		Logger:      logger,
	}
}

// debugLogPath resolves where OGL_DEBUG should write. An empty value disables
// logging; "1"/"true"/"yes" select the default file under the cache root; any
// other value is taken as an explicit file path.
func debugLogPath(value string) (path string, enabled bool) {
	switch value {
	case "":
		return "", false
	case "1", "true", "yes", "on":
		return filepath.Join(models.CacheRoot(), "debug.log"), true
	default:
		return value, true
	}
}

// openDebugLog returns a debug logger writing to the OGL_DEBUG file, or nil when
// disabled. It announces the chosen path on notice before the agent takes over
// the terminal, so debug output never interleaves with the agent's TUI. A file
// that cannot be opened falls back to a one-line notice and no logging.
func openDebugLog(value string, notice io.Writer) *slog.Logger {
	path, enabled := debugLogPath(value)
	if !enabled {
		return nil
	}
	if dir := filepath.Dir(path); dir != "" {
		_ = os.MkdirAll(dir, 0o750) //nolint:gosec // dir derives from the operator-supplied OGL_DEBUG path, not network input.
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // path is the operator-supplied OGL_DEBUG value, not network input.
	if err != nil {
		_, _ = fmt.Fprintf(notice, "ogl: could not open debug log %q: %v\n", path, err)
		return nil
	}
	_, _ = fmt.Fprintf(notice, "ogl: debug log → %s\n", path)
	return obs.Debug(f)
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func mapEnviron(environ []string) map[string]string {
	m := make(map[string]string, len(environ))
	for _, kv := range environ {
		for i := 0; i < len(kv); i++ {
			if kv[i] == '=' {
				m[kv[:i]] = kv[i+1:]
				break
			}
		}
	}
	return m
}
