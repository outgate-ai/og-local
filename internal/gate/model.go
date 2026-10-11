package gate

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/ledger"
	"github.com/outgate-ai/og-local/internal/gate/peer"
	"github.com/outgate-ai/og-local/internal/gate/route"
)

type credKey struct{}

// modelPaths is the OpenAI-compatible surface OGChat's on-device region uses.
var modelPaths = map[string]bool{"/health": true, "/v1/models": true, "/v1/chat/completions": true}

// ServeModel fronts the on-device model service (M09) on its own socket with the
// same HTTP API, so on-device requests are recorded too ("nothing left the device").
// Responses stream through unchanged. The model manager may only GET /health and
// /v1/models.
func (s *Server) ServeModel(ctx context.Context, ln net.Listener) error {
	target, _ := url.Parse("http://on-device")
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = unixTransport(s.cfg.ModelSocket)
	proxy.FlushInterval = -1
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		http.Error(w, `{"error":"model_unreachable"}`, http.StatusBadGateway)
	}
	srv := &http.Server{
		Handler:           s.modelHandler(proxy),
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if uc, ok := c.(*net.UnixConn); ok {
				if cred, err := peer.Of(uc); err == nil {
					return context.WithValue(ctx, credKey{}, cred)
				}
			}
			return ctx
		},
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	err := srv.Serve(ln)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func (s *Server) modelHandler(proxy *httputil.ReverseProxy) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cred, _ := r.Context().Value(credKey{}).(peer.Cred)
		class := s.classify(cred)
		if class == "" {
			http.Error(w, `{"error":"caller_not_allowed"}`, http.StatusForbidden)
			return
		}
		// The model manager only watches the model service load.
		if class == callerModels && (r.Method != http.MethodGet || (r.URL.Path != "/health" && r.URL.Path != "/v1/models")) {
			http.Error(w, `{"error":"caller_not_allowed"}`, http.StatusForbidden)
			return
		}
		if !modelPaths[r.URL.Path] {
			http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
			return
		}
		if r.URL.Path == "/health" || r.URL.Path == "/v1/models" {
			proxy.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		in := &countingReader{r: r.Body}
		r.Body = in
		cw := &countingWriter{ResponseWriter: w}
		r.Header.Del("Cookie")
		proxy.ServeHTTP(cw, r)
		s.ledger.Record(&ledger.Row{
			ID: s.nextID(), Time: start.UTC(), DurationMs: time.Since(start).Milliseconds(),
			Caller: class, UID: cred.UID, RegionID: "on-device", Destination: "on-device model",
			Method: r.Method, PathClass: r.URL.Path, Kind: "llm", Status: cw.status(),
			BytesOut: in.n.Load(), BytesOutRaw: in.n.Load(), BytesIn: cw.n.Load(),
			Content: in.n.Load() > 0, OnDevice: true, Mode: string(s.cfg.Mode),
			Class: route.ClassOnDevice, Mask: MaskNotRequired,
		})
	})
}

type countingReader struct {
	r io.ReadCloser
	n atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

func (c *countingReader) Close() error { return c.r.Close() }

type countingWriter struct {
	http.ResponseWriter
	n    atomic.Int64
	code atomic.Int64
}

func (c *countingWriter) WriteHeader(code int) {
	c.code.Store(int64(code))
	c.ResponseWriter.WriteHeader(code)
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.ResponseWriter.Write(p)
	c.n.Add(int64(n))
	return n, err
}

func (c *countingWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (c *countingWriter) status() int {
	if code := c.code.Load(); code != 0 {
		return int(code)
	}
	return http.StatusOK
}
