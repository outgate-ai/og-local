package proxy

import (
	"net/http"
	"strings"
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

// stripHopHeaders removes only the RFC 7230 hop-by-hop headers. It deliberately
// leaves CDN/edge headers in place: this proxy listens on loopback with no edge
// in front, so they never appear on inbound requests, and the upstream's own
// edge sets its own.
func stripHopHeaders(h http.Header) {
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

func isEventStream(h http.Header) bool {
	return strings.HasPrefix(h.Get("Content-Type"), "text/event-stream")
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
