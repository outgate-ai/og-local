package proxy

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/outgate-ai/og-local/internal/obs"
	"github.com/outgate-ai/og-local/internal/pii"
	"github.com/outgate-ai/og-local/internal/provider"
	"github.com/outgate-ai/og-local/internal/stream"
)

const defaultMaxBodyBytes = 32 << 20

type redactor interface {
	Redact(ctx context.Context, ep provider.Endpoint, body []byte) ([]byte, pii.Mapping, error)
}

type Config struct {
	Minter       verifier
	Redactor     redactor
	UpstreamBase string
	Client       *http.Client
	MaxBodyBytes int64
	Logger       *slog.Logger
}

type Handler struct {
	minter       verifier
	redactor     redactor
	upstreamBase string
	client       *http.Client
	maxBodyBytes int64
	log          *slog.Logger
}

func New(cfg Config) *Handler { //nolint:gocritic // one-shot constructor; value config reads clearly at the call site.
	client := cfg.Client
	if client == nil {
		client = http.DefaultClient
	}
	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = defaultMaxBodyBytes
	}
	return &Handler{
		minter:       cfg.Minter,
		redactor:     cfg.Redactor,
		upstreamBase: strings.TrimRight(cfg.UpstreamBase, "/"),
		client:       client,
		maxBodyBytes: maxBody,
		log:          obs.OrDiscard(cfg.Logger),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path, ok := h.authorize(r.URL.Path)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.maxBodyBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}

	ep := provider.Route(r.Method, path)
	h.log.Debug("request", "method", r.Method, "path", path,
		"redactable", ep.Redactable(), "req_bytes", len(body))

	var mapping pii.Mapping
	outBody := body
	if ep.Redactable() {
		redacted, m, rerr := h.redactor.Redact(r.Context(), ep, body)
		if rerr != nil {
			h.log.Debug("redaction failed", "path", path, "err", rerr)
			writeError(w, http.StatusBadGateway, "redaction failed")
			return
		}
		outBody = redacted
		mapping = m
	}

	upReq, err := h.upstreamRequest(r, path, outBody)
	if err != nil {
		//coverage:ignore reason=upstreamRequest only fails on an unreachable NewRequest error.
		writeError(w, http.StatusBadGateway, "bad upstream request")
		return
	}

	resp, err := h.client.Do(upReq) //nolint:gosec // forwarding to the operator-configured upstream is this tool's purpose.
	if err != nil {
		h.log.Debug("upstream unreachable", "url", h.upstreamBase+path, "err", err)
		writeError(w, http.StatusBadGateway, "upstream unreachable")
		return
	}
	defer func() { _ = resp.Body.Close() }()

	streaming := shouldStream(ep, resp.Header)
	mode := "passthrough"
	switch {
	case len(mapping) == 0:
	case streaming:
		mode = "stream-restore"
	default:
		mode = "buffered-restore"
	}
	h.log.Debug("upstream response", "status", resp.StatusCode,
		"content_type", resp.Header.Get("Content-Type"), "mode", mode, "restorable", len(mapping))

	h.writeResponse(w, ep, resp, mapping, streaming)
}

func (h *Handler) upstreamRequest(r *http.Request, path string, body []byte) (*http.Request, error) {
	url := h.upstreamBase + path
	if r.URL.RawQuery != "" {
		url += "?" + r.URL.RawQuery
	}
	upReq, err := http.NewRequestWithContext(r.Context(), r.Method, url, bytes.NewReader(body)) //nolint:gosec // url targets the operator-configured upstream base, not a caller-supplied host.
	if err != nil {
		//coverage:ignore reason=NewRequestWithContext only errors on an invalid method or URL, neither reachable here.
		return nil, err
	}
	copyHeaders(upReq.Header, r.Header)
	stripHopHeaders(upReq.Header)
	upReq.Header.Set("Accept-Encoding", "identity")
	upReq.Header.Del("Content-Length")
	upReq.ContentLength = int64(len(body))
	return upReq, nil
}

func (h *Handler) writeResponse(w http.ResponseWriter, ep provider.Endpoint, resp *http.Response, mapping pii.Mapping, streaming bool) {
	copyHeaders(w.Header(), resp.Header)
	w.Header().Del("Content-Length")

	if len(mapping) == 0 {
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}

	if streaming {
		w.WriteHeader(resp.StatusCode)
		flush := flusherOf(w)
		tr := stream.New(w, ep.DeltaCodec(), mapping, stream.WithFlush(flush))
		_, _ = io.Copy(tr, resp.Body)
		_ = tr.Close()
		return
	}

	full, err := io.ReadAll(resp.Body)
	if err != nil {
		//coverage:ignore reason=response body read errors are surfaced as a truncated body downstream.
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	restored := mapping.Restore(string(full))
	w.WriteHeader(resp.StatusCode)
	_, _ = io.WriteString(w, restored) //nolint:gosec // relaying an upstream API response body, not rendering HTML.
}
