package launch

import (
	"context"
	"net/http"
	"os"
	"time"

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
	pipeline := redact.New(det, cache)

	handler := func(upstreamBase string) http.Handler {
		return proxy.New(proxy.Config{
			Minter:       minter,
			Redactor:     pipeline,
			UpstreamBase: upstreamBase,
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
	return &App{
		NewDetector: defaultNewDetector,
		NewMinter:   func() (*token.Minter, error) { return token.NewMinter(int32(os.Getpid()), realClock{}, tokenTTL) }, //nolint:gosec // pid fits int32 on supported platforms.
		Environ:     os.Environ,
		Runner:      ExecRunner{},
		Stdio:       Stdio{In: os.Stdin, Out: os.Stdout, Err: os.Stderr},
	}
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
