package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/ledger"
	"github.com/outgate-ai/og-local/internal/gate/peer"
	"github.com/outgate-ai/og-local/internal/gate/route"
	"github.com/outgate-ai/og-local/internal/gate/wire"
)

type credKey struct{}

// modelPaths is the OpenAI-compatible surface OGChat's on-device region uses.
var modelPaths = map[string]bool{"/health": true, "/v1/models": true, "/v1/chat/completions": true}

// agentModel is the agent instance's alias (og-models-api CONTRACT.md: run/agent.sock).
const agentModel = "og-local-agent"

// voiceAllowed is what conversation mode (ai.outgate.voice), transcription's summaries
// (ai.outgate.transcribe) and the on-device agent (ai.outgate.localagent) may ask of the model front:
// completions and health. The instance itself is checked once resolved.
func voiceAllowed(r *http.Request) bool {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/completions":
		return true
	case r.Method == http.MethodGet && r.URL.Path == "/health":
		return true
	}
	return false
}

// modelListTimeout bounds each instance's answer to an aggregated GET /v1/models.
const modelListTimeout = 2 * time.Second

var errNoModelAnswered = errors.New("no on-device model answered")

// modelInstance is one llama.cpp server of the on-device model service, by alias.
type modelInstance struct {
	alias  string
	socket string
	// display is the ledger destination: "on-device model" for og-local, "on-device/<alias>" otherwise.
	display string
	client  *http.Client
	proxy   *httputil.ReverseProxy
}

func newModels(sockets map[string]string) map[string]*modelInstance {
	target, _ := url.Parse("http://on-device")
	out := make(map[string]*modelInstance, len(sockets))
	for alias, socket := range sockets {
		tr := unixTransport(socket)
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.Transport = tr
		proxy.FlushInterval = -1
		proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
			http.Error(w, `{"error":"model_unreachable"}`, http.StatusBadGateway)
		}
		display := "on-device model"
		if alias != DefaultModel {
			display = "on-device/" + alias
		}
		out[alias] = &modelInstance{
			alias: alias, socket: socket, display: display, proxy: proxy,
			client: &http.Client{Transport: tr, CheckRedirect: noRedirects},
		}
	}
	return out
}

// modelFor picks the instance a request is for: a POST names it in its JSON body's
// "model", anything else with ?model=; naming none is og-local.
func (s *Server) modelFor(method string, query url.Values, body []byte) (*modelInstance, error) {
	alias := query.Get("model")
	if method == http.MethodPost {
		var err error
		if alias, err = bodyModel(body); err != nil {
			return nil, err
		}
	}
	if alias == "" {
		alias = DefaultModel
	}
	if m, ok := s.models[alias]; ok {
		return m, nil
	}
	return nil, fmt.Errorf("no model %.64q (%s)", alias, strings.Join(slices.Sorted(maps.Keys(s.models)), ", "))
}

// bodyModel is the top-level "model" of a JSON object body; "" when the body isn't
// one or names none.
func bodyModel(body []byte) (string, error) {
	var b map[string]json.RawMessage
	if json.Unmarshal(body, &b) != nil || b["model"] == nil || string(b["model"]) == "null" {
		return "", nil
	}
	var alias string
	if err := json.Unmarshal(b["model"], &alias); err != nil {
		return "", errors.New("model is not a string")
	}
	return alias, nil
}

// aggregatesModels: GET /v1/models lists every instance's models when there are several.
func (s *Server) aggregatesModels(method, path string) bool {
	return method == http.MethodGet && path == "/v1/models" && len(s.models) > 1
}

// modelList asks every instance for GET /v1/models at once and joins their "data"
// in one OpenAI list. Instances that don't answer 200 in time are left out.
func (s *Server) modelList(ctx context.Context) ([]byte, error) {
	aliases := slices.Sorted(maps.Keys(s.models))
	lists := make([][]json.RawMessage, len(aliases))
	answered := make([]bool, len(aliases))
	var wg sync.WaitGroup
	for i, alias := range aliases {
		wg.Go(func() { lists[i], answered[i] = s.models[alias].list(ctx) })
	}
	wg.Wait()
	if !slices.Contains(answered, true) {
		return nil, errNoModelAnswered
	}
	data := []json.RawMessage{}
	for _, l := range lists {
		data = append(data, l...)
	}
	return json.Marshal(map[string]any{"object": "list", "data": data})
}

func (m *modelInstance) list(ctx context.Context) ([]json.RawMessage, bool) {
	ctx, cancel := context.WithTimeout(ctx, modelListTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://on-device/v1/models", nil)
	if err != nil {
		return nil, false
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, false
	}
	defer func() { _ = resp.Body.Close() }()
	var l struct {
		Data []json.RawMessage `json:"data"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&l) != nil {
		return nil, false
	}
	return l.Data, true
}

// ServeModel fronts the on-device model service (M09) on its own socket with the
// same HTTP API, so on-device requests are recorded too ("nothing left the device").
// Each request goes to the instance it names (the body's "model", or ?model=);
// GET /v1/models lists them all. Responses stream through unchanged. The model
// manager may only GET /health and /v1/models.
func (s *Server) ServeModel(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.modelHandler(),
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if uc, ok := c.(*net.UnixConn); ok {
				if cred, err := s.peerOf(uc); err == nil {
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

func (s *Server) modelHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cred, _ := r.Context().Value(credKey{}).(peer.Cred)
		class := s.classify(cred)
		if class == "" || class == callerTunnel || class == callerTunnelLauncher || class == callerBackup {
			http.Error(w, `{"error":"caller_not_allowed"}`, http.StatusForbidden)
			return
		}
		// The model manager only watches the model service load.
		if class == callerModels && (r.Method != http.MethodGet || (r.URL.Path != "/health" && r.URL.Path != "/v1/models")) {
			http.Error(w, `{"error":"caller_not_allowed"}`, http.StatusForbidden)
			return
		}
		if (class == callerVoice || class == callerTranscribe || class == callerLocalAgent) && !voiceAllowed(r) {
			http.Error(w, `{"error":"caller_not_allowed"}`, http.StatusForbidden)
			return
		}
		if !modelPaths[r.URL.Path] {
			http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
			return
		}
		if s.aggregatesModels(r.Method, r.URL.Path) {
			list, err := s.modelList(r.Context())
			if err != nil {
				http.Error(w, `{"error":"model_unreachable"}`, http.StatusBadGateway)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(list)
			return
		}
		var body []byte
		if r.Method == http.MethodPost {
			b, err := io.ReadAll(io.LimitReader(r.Body, wire.MaxLine+1))
			if err != nil {
				http.Error(w, `{"error":"bad_body"}`, http.StatusBadRequest)
				return
			}
			if len(b) > wire.MaxLine {
				http.Error(w, `{"error":"body_too_large"}`, http.StatusRequestEntityTooLarge)
				return
			}
			body = b
			r.Body, r.ContentLength, r.TransferEncoding = io.NopCloser(bytes.NewReader(b)), int64(len(b)), nil
		}
		m, err := s.modelFor(r.Method, r.URL.Query(), body)
		if err != nil {
			e, _ := json.Marshal(map[string]string{"error": "unknown_model", "detail": err.Error()})
			http.Error(w, string(e), http.StatusNotFound)
			return
		}
		if class == callerVoice && m.alias != DefaultModel {
			http.Error(w, `{"error":"caller_not_allowed"}`, http.StatusForbidden)
			return
		}
		if class == callerTranscribe && m.alias != DefaultModel && m.alias != agentModel {
			http.Error(w, `{"error":"caller_not_allowed"}`, http.StatusForbidden)
			return
		}
		// The agent never falls back to another model: only its own instance.
		if class == callerLocalAgent && m.alias != agentModel {
			http.Error(w, `{"error":"caller_not_allowed"}`, http.StatusForbidden)
			return
		}
		if r.URL.Path == "/health" || r.URL.Path == "/v1/models" {
			m.proxy.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		in := &countingReader{r: r.Body}
		r.Body = in
		cw := &countingWriter{ResponseWriter: w}
		r.Header.Del("Cookie")
		m.proxy.ServeHTTP(cw, r)
		s.ledger.Record(&ledger.Row{
			ID: s.nextID(), Time: start.UTC(), DurationMs: time.Since(start).Milliseconds(),
			Caller: class, UID: cred.UID, RegionID: "on-device", Destination: m.display,
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
