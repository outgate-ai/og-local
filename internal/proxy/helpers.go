package proxy

import (
	"net/http"
	"strings"

	"github.com/outgate-ai/og-local/internal/provider"
)

var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func stripHopHeaders(h http.Header) {
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

func isEventStream(h http.Header) bool {
	return strings.HasPrefix(h.Get("Content-Type"), "text/event-stream")
}

func isJSON(h http.Header) bool {
	return strings.HasPrefix(h.Get("Content-Type"), "application/json")
}

// shouldStream reports whether to run the split-safe SSE restorer: an explicit
// event-stream, or a streamable route whose body is not declared JSON (some
// upstreams stream with no Content-Type).
func shouldStream(ep provider.Endpoint, h http.Header) bool {
	if isEventStream(h) {
		return true
	}
	return ep.StreamsSSE() && !isJSON(h)
}

func flusherOf(w http.ResponseWriter) func() {
	f, ok := w.(http.Flusher)
	if !ok {
		return nil
	}
	return f.Flush
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(`{"error":{"message":"` + msg + `"}}`))
}
