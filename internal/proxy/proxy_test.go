package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/outgate-ai/og-local/internal/obs"
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
	m = append(m, f.pairs...)
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

// keyPath wraps a request path with the /_k/<token> prefix the agent is given.
func keyPath(tok, path string) string {
	return keyPathPrefix + tok + path
}

func doRequest(t *testing.T, h *Handler, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestProxyRejectsMissingToken(t *testing.T) {
	m := testMinter(t)
	h := New(Config{Minter: m, Redactor: &fakeRedactor{}, UpstreamBase: "http://unused"})
	rr := doRequest(t, h, "POST", "/v1/messages", `{}`, nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rr.Code)
	}
}

func TestProxyRejectsBadToken(t *testing.T) {
	m := testMinter(t)
	h := New(Config{Minter: m, Redactor: &fakeRedactor{}, UpstreamBase: "http://unused"})
	rr := doRequest(t, h, "POST", keyPath("ogl_live_garbage", "/v1/messages"), `{}`, nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rr.Code)
	}
}

func TestProxyForwardsAgentAuthAndRedactsBody(t *testing.T) {
	var gotBody, gotXKey, gotVersion string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotXKey = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")
		if !strings.HasSuffix(r.URL.Path, "/v1/messages") {
			t.Errorf("upstream path = %q, want it to end with /v1/messages (token stripped)", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	m := testMinter(t)
	h := New(Config{
		Minter:       m,
		Redactor:     &fakeRedactor{pairs: []pii.Pair{{From: "alice@example.com", To: "OG_PRIVATE_EMAIL_abc123"}}},
		UpstreamBase: upstream.URL,
		Client:       upstream.Client(),
	})
	rr := doRequest(t, h, "POST", keyPath(m.Mint(), "/v1/messages"),
		`{"model":"claude","messages":[{"role":"user","content":"mail alice@example.com"}]}`,
		map[string]string{"x-api-key": "sk-agent-own-key", "anthropic-version": "2023-06-01"})

	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d", rr.Code)
	}
	if strings.Contains(gotBody, "alice@example.com") {
		t.Errorf("upstream saw raw email: %s", gotBody)
	}
	if !strings.Contains(gotBody, "OG_PRIVATE_EMAIL_abc123") {
		t.Errorf("upstream body not redacted: %s", gotBody)
	}
	if gotXKey != "sk-agent-own-key" {
		t.Errorf("agent's own x-api-key not forwarded to upstream: %q", gotXKey)
	}
	if gotVersion != "2023-06-01" {
		t.Errorf("agent's anthropic-version header not forwarded: %q", gotVersion)
	}
}

func TestProxyRestoresStreamingResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
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
		UpstreamBase: upstream.URL,
		Client:       upstream.Client(),
	})
	rr := doRequest(t, h, "POST", keyPath(m.Mint(), "/v1/messages"),
		`{"model":"claude","messages":[{"role":"user","content":"x"}]}`, nil)

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
	h := New(Config{Minter: m, Redactor: rdct, UpstreamBase: upstream.URL, Client: upstream.Client()})
	body := `{"anything":"passes"}`
	rr := doRequest(t, h, "POST", keyPath(m.Mint(), "/v1/models"), body,
		map[string]string{"Authorization": "Bearer sk-agent-bearer"})
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d", rr.Code)
	}
	if gotBody != body {
		t.Errorf("passthrough body changed: %q", gotBody)
	}
	if gotAuth != "Bearer sk-agent-bearer" {
		t.Errorf("agent bearer not forwarded on passthrough: %q", gotAuth)
	}
}

func TestProxyOversizedBody(t *testing.T) {
	m := testMinter(t)
	h := New(Config{Minter: m, Redactor: &fakeRedactor{}, UpstreamBase: "http://unused", MaxBodyBytes: 16})
	rr := doRequest(t, h, "POST", keyPath(m.Mint(), "/v1/messages"), strings.Repeat("x", 100), nil)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("code = %d, want 413", rr.Code)
	}
}

func TestProxyRedactionError(t *testing.T) {
	m := testMinter(t)
	h := New(Config{Minter: m, Redactor: &fakeRedactor{err: errors.New("boom")}, UpstreamBase: "http://unused"})
	rr := doRequest(t, h, "POST", keyPath(m.Mint(), "/v1/messages"), `{"messages":[{"role":"user","content":"x"}]}`, nil)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502", rr.Code)
	}
}

func TestProxyUpstreamUnreachable(t *testing.T) {
	m := testMinter(t)
	h := New(Config{
		Minter:       m,
		Redactor:     &fakeRedactor{},
		UpstreamBase: "http://127.0.0.1:1",
		Client:       &http.Client{Timeout: time.Second},
	})
	rr := doRequest(t, h, "POST", keyPath(m.Mint(), "/v1/models"), `{}`, nil)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502", rr.Code)
	}
}

func TestProxyNonStreamingRestore(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"reply":"contact OG_PRIVATE_EMAIL_abc123 soon"}`))
	}))
	defer upstream.Close()

	m := testMinter(t)
	h := New(Config{
		Minter:       m,
		Redactor:     &fakeRedactor{pairs: []pii.Pair{{From: "alice@example.com", To: "OG_PRIVATE_EMAIL_abc123"}}},
		UpstreamBase: upstream.URL,
		Client:       upstream.Client(),
	})
	rr := doRequest(t, h, "POST", keyPath(m.Mint(), "/v1/chat/completions"),
		`{"model":"gpt","messages":[{"role":"user","content":"mail alice@example.com"}]}`, nil)
	out := rr.Body.String()
	if strings.Contains(out, "OG_PRIVATE_EMAIL") || !strings.Contains(out, "alice@example.com") {
		t.Errorf("non-streaming restore failed: %s", out)
	}
}

func TestProxyDefaultsClientAndMaxBody(t *testing.T) {
	h := New(Config{Minter: testMinter(t), Redactor: &fakeRedactor{}, UpstreamBase: "http://x"})
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
	h := New(Config{Minter: m, Redactor: &fakeRedactor{}, UpstreamBase: upstream.URL, Client: upstream.Client()})
	doRequest(t, h, "GET", keyPath(m.Mint(), "/v1/models")+"?limit=5&after=x", "", nil)
	if gotQuery != "limit=5&after=x" {
		t.Errorf("upstream query = %q, want limit=5&after=x", gotQuery)
	}
}

type nonFlushWriter struct{ http.ResponseWriter }

func TestProxyStreamingWithoutFlusher(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"x OG_PRIVATE_EMAIL_abc123\"}}\n")
		_, _ = io.WriteString(w, "data: {\"type\":\"message_stop\"}\n")
	}))
	defer upstream.Close()
	m := testMinter(t)
	h := New(Config{
		Minter:       m,
		Redactor:     &fakeRedactor{pairs: []pii.Pair{{From: "alice@example.com", To: "OG_PRIVATE_EMAIL_abc123"}}},
		UpstreamBase: upstream.URL,
		Client:       upstream.Client(),
	})
	req := httptest.NewRequest("POST", keyPath(m.Mint(), "/v1/messages"), strings.NewReader(`{"messages":[{"role":"user","content":"x"}]}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(nonFlushWriter{rr}, req)
	if out := rr.Body.String(); !strings.Contains(out, "alice@example.com") {
		t.Errorf("non-flusher restore failed: %s", out)
	}
}

func TestProxyDebugLogsRouteAndResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	var buf bytes.Buffer
	m := testMinter(t)
	h := New(Config{
		Minter:       m,
		Redactor:     &fakeRedactor{pairs: []pii.Pair{{From: "alice@example.com", To: "OG_PRIVATE_EMAIL_abc123"}}},
		UpstreamBase: upstream.URL,
		Client:       upstream.Client(),
		Logger:       obs.Debug(&buf),
	})
	doRequest(t, h, "POST", keyPath(m.Mint(), "/v1/messages"),
		`{"model":"claude","messages":[{"role":"user","content":"mail alice@example.com"}]}`, nil)

	out := buf.String()
	for _, want := range []string{"method=POST", "path=/v1/messages", "redactable=true", "status=200", "mode=buffered-restore"} {
		if !strings.Contains(out, want) {
			t.Errorf("debug log missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "alice@example.com") {
		t.Errorf("proxy debug leaked request content: %s", out)
	}
}

func TestProxyForwardsHostAndIdentityHeaders(t *testing.T) {
	var gotHost, gotAuth, gotAccount, gotOriginator string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotAuth = r.Header.Get("Authorization")
		gotAccount = r.Header.Get("chatgpt-account-id")
		gotOriginator = r.Header.Get("originator")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")

	m := testMinter(t)
	h := New(Config{Minter: m, Redactor: &fakeRedactor{}, UpstreamBase: upstream.URL, Client: upstream.Client()})
	rr := doRequest(t, h, "POST", keyPath(m.Mint(), "/backend-api/codex/responses"), `{}`,
		map[string]string{
			"Authorization":      "Bearer oauth-subscription-tok",
			"chatgpt-account-id": "acct-123",
			"originator":         "codex_exec",
		})
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d", rr.Code)
	}
	if gotHost != upstreamHost {
		t.Errorf("upstream Host = %q, want %q (derived from UpstreamBase, not the inbound loopback host)", gotHost, upstreamHost)
	}
	if gotAuth != "Bearer oauth-subscription-tok" {
		t.Errorf("Authorization not forwarded: %q", gotAuth)
	}
	if gotAccount != "acct-123" {
		t.Errorf("chatgpt-account-id not forwarded: %q", gotAccount)
	}
	if gotOriginator != "codex_exec" {
		t.Errorf("originator not forwarded: %q", gotOriginator)
	}
}

func TestSplitKeyPath(t *testing.T) {
	cases := []struct {
		path      string
		tok, rest string
		ok        bool
	}{
		{"/_k/abc/v1/messages", "abc", "/v1/messages", true},
		{"/_k/abc", "abc", "/", true},
		{"/_k/abc/", "abc", "/", true},
		{"/v1/messages", "", "", false},
		{"/_k/", "", "/", true},
		{"", "", "", false},
	}
	for _, c := range cases {
		tok, rest, ok := splitKeyPath(c.path)
		if ok != c.ok || tok != c.tok || rest != c.rest {
			t.Errorf("splitKeyPath(%q) = (%q,%q,%v), want (%q,%q,%v)", c.path, tok, rest, ok, c.tok, c.rest, c.ok)
		}
	}
}
