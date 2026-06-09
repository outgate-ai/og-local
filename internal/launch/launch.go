package launch

import (
	"context"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/outgate-ai/og-local/internal/provider"
)

type Stdio struct {
	In  *os.File
	Out *os.File
	Err *os.File
}

type Runner interface {
	Run(ctx context.Context, argv, env []string, stdio Stdio) (int, error)
}

type HandlerFunc func(upstreamBase string) http.Handler

type Options struct {
	Kind             provider.Kind
	Args             []string
	Env              map[string]string
	LoopbackTok      string
	Handler          HandlerFunc
	Runner           Runner
	Listen           func() (net.Listener, error)
	Stdio            Stdio
	PrepareChild     func(loopbackURL, token string) (map[string]string, error)
	UpstreamOverride string
}

func Run(ctx context.Context, opts Options) (int, error) { //nolint:gocritic // single top-level entry; value Options reads clearly at the call site.
	listen := opts.Listen
	if listen == nil {
		listen = defaultListen
	}
	ln, err := listen()
	if err != nil {
		return 1, err
	}

	res, err := Resolve(opts.Kind, opts.Env, loopbackURL(ln), opts.LoopbackTok)
	if err != nil {
		_ = ln.Close()
		return 1, err
	}

	upstream := res.UpstreamBase
	if opts.UpstreamOverride != "" {
		upstream = opts.UpstreamOverride
	}

	h := opts.Handler(upstream)
	srv := serve(ln, h)
	defer shutdown(srv)

	overlay := res.ChildEnv
	if opts.PrepareChild != nil {
		extra, perr := opts.PrepareChild(loopbackURL(ln), opts.LoopbackTok)
		if perr != nil {
			return 1, perr
		}
		for k, v := range extra {
			overlay[k] = v
		}
	}

	env := childEnviron(opts.Env, overlay)
	return opts.Runner.Run(ctx, opts.Args, env, opts.Stdio)
}

func defaultListen() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}

func loopbackURL(l net.Listener) string {
	return "http://" + l.Addr().String()
}

func serve(l net.Listener, h http.Handler) *http.Server {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(l) }()
	return srv
}

func shutdown(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func childEnviron(base, overlay map[string]string) []string {
	merged := make(map[string]string, len(base)+len(overlay))
	for k, v := range base {
		merged[k] = v
	}
	for k, v := range overlay {
		merged[k] = v
	}
	out := make([]string, 0, len(merged))
	for k, v := range merged {
		out = append(out, k+"="+v)
	}
	return out
}
