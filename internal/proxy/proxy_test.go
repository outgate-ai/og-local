package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/outgate-ai/og-local/internal/pii"
	"github.com/outgate-ai/og-local/internal/provider"
	"github.com/outgate-ai/og-local/internal/testutil/fakeclock"
	"github.com/outgate-ai/og-local/internal/token"
)

type fakeRedactor struct {
	pairs []pii.Pair
	err   error
}

func (f *fakeRedactor) Redact(_ context.Context, ep provider.Endpoint, body []byte) ([]byte, pii.Mapping, error) {
	if f.err != nil {
		return nil, nil, f.err
	}
	refs, reassemble, err := ep.Fields(body)
	if err != nil {
		return nil, nil, err
	}
	m := pii.Mapping{}
	for _, ref := range refs {
		out := ref.Text
		for _, p := range f.pairs {
			out = strings.ReplaceAll(out, p.From, p.To)
		}
		ref.Set(out)
	}
	for _, p := range f.pairs {
		m = append(m, p)
	}
	nb, err := reassemble()
	return nb, m, err
}

func testMinter(t *testing.T) *token.Minter {
	t.Helper()
	m, err := token.NewMinter(4242, fakeclock.New(time.Unix(1_700_000_000, 0)), time.Hour)
	if err != nil {
		t.Fatalf("minter: %v", err)
	}
	return m
}

func mustToken(t *testing.T, m *token.Minter) string {
	t.Helper()
	return m.Mint()
}

func doRequest(t *testing.T, h *Handler, method, target, tok, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestProxyRejectsMissingToken(t *testing.T) {
	m := testMinter(t)
	h := New(Config{Minter: m, Redactor: &fakeRedactor{}, Kind: provider.Anthropic, UpstreamBase: "http://unused"})
	rr := doRequest(t, h, "POST", "/v1/messages", "", `{}`)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rr.Code)
	}
}

func TestProxyRejectsBadToken(t *testing.T) {
	m := testMinter(t)
	h := New(Config{Minter: m, Redactor: &fakeRedactor{}, Kind: provider.Anthropic, UpstreamBase: "http://unused"})
	rr := doRequest(t, h, "POST", "/v1/messages", "ogl_live_garbage", `{}`)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rr.Code)
	}
}

func TestProxyRedactsRequestBodyAndKeyToUpstream(t *testing.T) {
	var gotBody, gotKey, gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotKey = r.Header.Get("x-api-key")
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	m := testMinter(t)
	h := New(Config{
		Minter:       m,
		Redactor:     &fakeRedactor{pairs: []pii.Pair{{From: "alice@example.com", To: "OG_PRIVATE_EMAIL_abc123"}}},
		Kind:         provider.Anthropic,
		UpstreamBase: upstream.URL,
		UpstreamKey:  "sk-real-secret",
		Client:       upstream.Client(),
	})
	rr := doRequest(t, h, "POST", "/v1/messages", mustToken(t, m),
		`{"model":"claude","messages":[{"role":"user","content":"mail alice@example.com"}]}`)

	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d", rr.Code)
	}
	if strings.Contains(gotBody, "alice@example.com") {
		t.Errorf("upstream saw raw email: %s", gotBody)
	}
	if !strings.Contains(gotBody, "OG_PRIVATE_EMAIL_abc123") {
		t.Errorf("upstream body not redacted: %s", gotBody)
	}
	if gotKey != "sk-real-secret" {
		t.Errorf("upstream x-api-key = %q, want real key", gotKey)
	}
	if gotAuth != "" {
		t.Errorf("inbound loopback token leaked to upstream Authorization: %q", gotAuth)
	}
}

func TestProxyRestoresStreamingResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		// Placeholder split across two SSE events.
		_, _ = io.WriteString(w, "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi OG_PRIVATE_\"}}\n")
		if fl != nil {
			fl.Flush()
		}
		_, _ = io.WriteString(w, "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"EMAIL_abc123 bye\"}}\n")
		_, _ = io.WriteString(w, "data: {\"type\":\"message_stop\"}\n")
	}))
	defer upstream.Close()

	m := testMinter(t)
	h := New(Config{
		Minter:       m,
		Redactor:     &fakeRedactor{pairs: []pii.Pair{{From: "alice@example.com", To: "OG_PRIVATE_EMAIL_abc123"}}},
		Kind:         provider.Anthropic,
		UpstreamBase: upstream.URL,
		UpstreamKey:  "sk-real",
		Client:       upstream.Client(),
	})
	rr := doRequest(t, h, "POST", "/v1/messages", mustToken(t, m),
		`{"model":"claude","messages":[{"role":"user","content":"x"}]}`)

	out := rr.Body.String()
	if strings.Contains(out, "OG_PRIVATE_EMAIL") {
		t.Errorf("placeholder leaked to client: %s", out)
	}
	if !strings.Contains(out, "alice@example.com") {
		t.Errorf("response not restored: %s", out)
	}
}

func TestProxyPassthroughEndpoint(t *testing.T) {
	var gotBody, gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer upstream.Close()

	m := testMinter(t)
	rdct := &fakeRedactor{err: errors.New("should not be called")}
	h := New(Config{
		Minter:       m,
		Redactor:     rdct,
		Kind:         provider.OpenAIChat,
		UpstreamBase: upstream.URL,
		UpstreamKey:  "sk-real",
		Client:       upstream.Client(),
	})
	body := `{"anything":"passes"}`
	rr := doRequest(t, h, "POST", "/v1/models", mustToken(t, m), body)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d", rr.Code)
	}
	if gotBody != body {
		t.Errorf("passthrough body changed: %q", gotBody)
	}
	if gotAuth != "Bearer sk-real" {
		t.Errorf("upstream auth = %q", gotAuth)
	}
}

func TestProxyOversizedBody(t *testing.T) {
	m := testMinter(t)
	h := New(Config{Minter: m, Redactor: &fakeRedactor{}, Kind: provider.Anthropic, UpstreamBase: "http://unused", MaxBodyBytes: 16})
	rr := doRequest(t, h, "POST", "/v1/messages", mustToken(t, m), strings.Repeat("x", 100))
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("code = %d, want 413", rr.Code)
	}
}

func TestProxyRedactionError(t *testing.T) {
	m := testMinter(t)
	h := New(Config{
		Minter:       m,
		Redactor:     &fakeRedactor{err: errors.New("boom")},
		Kind:         provider.Anthropic,
		UpstreamBase: "http://unused",
	})
	rr := doRequest(t, h, "POST", "/v1/messages", mustToken(t, m), `{"messages":[{"role":"user","content":"x"}]}`)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502", rr.Code)
	}
}

func TestProxyUpstreamUnreachable(t *testing.T) {
	m := testMinter(t)
	h := New(Config{
		Minter:       m,
		Redactor:     &fakeRedactor{},
		Kind:         provider.OpenAIChat,
		UpstreamBase: "http://127.0.0.1:1",
		UpstreamKey:  "sk",
		Client:       &http.Client{Timeout: time.Second},
	})
	rr := doRequest(t, h, "POST", "/v1/models", mustToken(t, m), `{}`)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502", rr.Code)
	}
}

func TestProxyNonStreamingRestore(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"reply":"contact OG_PRIVATE_EMAIL_abc123 soon"}`))
	}))
	defer upstream.Close()

	m := testMinter(t)
	h := New(Config{
		Minter:       m,
		Redactor:     &fakeRedactor{pairs: []pii.Pair{{From: "alice@example.com", To: "OG_PRIVATE_EMAIL_abc123"}}},
		Kind:         provider.OpenAIChat,
		UpstreamBase: upstream.URL,
		UpstreamKey:  "sk",
		Client:       upstream.Client(),
	})
	rr := doRequest(t, h, "POST", "/v1/chat/completions", mustToken(t, m),
		`{"model":"gpt","messages":[{"role":"user","content":"mail alice@example.com"}]}`)
	out := rr.Body.String()
	if strings.Contains(out, "OG_PRIVATE_EMAIL") || !strings.Contains(out, "alice@example.com") {
		t.Errorf("non-streaming restore failed: %s", out)
	}
}

func TestProxyDefaultsClientAndMaxBody(t *testing.T) {
	h := New(Config{Minter: testMinter(t), Redactor: &fakeRedactor{}, Kind: provider.Anthropic, UpstreamBase: "http://x"})
	if h.client == nil {
		t.Error("client not defaulted")
	}
	if h.maxBodyBytes != defaultMaxBodyBytes {
		t.Errorf("maxBodyBytes = %d, want default", h.maxBodyBytes)
	}
}

func TestProxyForwardsQueryString(t *testing.T) {
	var gotQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()
	m := testMinter(t)
	h := New(Config{Minter: m, Redactor: &fakeRedactor{}, Kind: provider.OpenAIChat, UpstreamBase: upstream.URL, UpstreamKey: "sk", Client: upstream.Client()})
	doRequest(t, h, "GET", "/v1/models?limit=5&after=x", mustToken(t, m), "")
	if gotQuery != "limit=5&after=x" {
		t.Errorf("upstream query = %q, want limit=5&after=x", gotQuery)
	}
}

type nonFlushWriter struct{ http.ResponseWriter }

func TestProxyStreamingWithoutFlusher(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"x OG_PRIVATE_EMAIL_abc123\"}}\n")
		_, _ = io.WriteString(w, "data: {\"type\":\"message_stop\"}\n")
	}))
	defer upstream.Close()
	m := testMinter(t)
	h := New(Config{
		Minter:       m,
		Redactor:     &fakeRedactor{pairs: []pii.Pair{{From: "alice@example.com", To: "OG_PRIVATE_EMAIL_abc123"}}},
		Kind:         provider.Anthropic,
		UpstreamBase: upstream.URL,
		UpstreamKey:  "sk",
		Client:       upstream.Client(),
	})
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(`{"messages":[{"role":"user","content":"x"}]}`))
	req.Header.Set("Authorization", "Bearer "+mustToken(t, m))
	rr := httptest.NewRecorder()
	h.ServeHTTP(nonFlushWriter{rr}, req)
	if out := rr.Body.String(); !strings.Contains(out, "alice@example.com") {
		t.Errorf("non-flusher restore failed: %s", out)
	}
}

func TestBearerTokenFromXAPIKey(t *testing.T) {
	req := httptest.NewRequest("POST", "/v1/messages", http.NoBody)
	req.Header.Set("x-api-key", "  tok-123  ")
	if got := bearerToken(req); got != "tok-123" {
		t.Errorf("bearerToken = %q, want tok-123", got)
	}
	req2 := httptest.NewRequest("POST", "/v1/messages", http.NoBody)
	if got := bearerToken(req2); got != "" {
		t.Errorf("empty headers should yield empty token, got %q", got)
	}
}
