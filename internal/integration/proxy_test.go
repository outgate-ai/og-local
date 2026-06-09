//go:build integration

package integration

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/outgate-ai/og-local/internal/launch"
	"github.com/outgate-ai/og-local/internal/pii"
	"github.com/outgate-ai/og-local/internal/provider"
	"github.com/outgate-ai/og-local/internal/proxy"
	"github.com/outgate-ai/og-local/internal/redact"
	"github.com/outgate-ai/og-local/internal/storage/memory"
	"github.com/outgate-ai/og-local/internal/token"
)

type scriptedDetector struct {
	value string
	class pii.Class
}

func (d scriptedDetector) Detect(_ context.Context, text string) ([]pii.Span, error) {
	i := strings.Index(text, d.value)
	if i < 0 {
		return nil, nil
	}
	return []pii.Span{{Start: i, End: i + len(d.value), Class: d.class}}, nil
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

func TestProxyPipelineEndToEnd(t *testing.T) {
	const secret = "alice@example.com"

	var upstreamSawBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		upstreamSawBody = string(b)

		// Echo back the redacted placeholder, split across two SSE writes so the
		// split-token restore path is exercised end to end.
		var placeholder string
		if i := strings.Index(upstreamSawBody, "OG_PRIVATE_EMAIL_"); i >= 0 {
			placeholder = upstreamSawBody[i : i+len("OG_PRIVATE_EMAIL_")+6]
		}
		half := len(placeholder) / 2

		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"reply to `+placeholder[:half]+`"}}`+"\n")
		if fl != nil {
			fl.Flush()
		}
		_, _ = io.WriteString(w, `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"`+placeholder[half:]+` thanks"}}`+"\n")
		_, _ = io.WriteString(w, `data: {"type":"message_stop"}`+"\n")
	}))
	defer upstream.Close()

	minter, err := token.NewMinter(4242, fixedClock{time.Unix(1_700_000_000, 0)}, time.Hour)
	if err != nil {
		t.Fatalf("minter: %v", err)
	}
	cache, err := memory.New[[]pii.Span](16)
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	pipeline := redact.New(scriptedDetector{value: secret, class: pii.ClassEmail}, cache)

	h := proxy.New(proxy.Config{
		Minter:       minter,
		Redactor:     pipeline,
		UpstreamBase: upstream.URL,
		Client:       upstream.Client(),
	})
	front := httptest.NewServer(h)
	defer front.Close()

	reqBody := `{"model":"claude","messages":[{"role":"user","content":"email ` + secret + ` for me"}]}`
	// The agent is handed a base URL ending in /_k/<token>; it appends /v1/messages.
	req, _ := http.NewRequest("POST", front.URL+"/_k/"+minter.Mint()+"/v1/messages", strings.NewReader(reqBody))
	req.Header.Set("x-api-key", "sk-agent-own-credential")

	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)

	if strings.Contains(upstreamSawBody, secret) {
		t.Errorf("upstream received the raw secret: %s", upstreamSawBody)
	}
	if !strings.Contains(upstreamSawBody, "OG_PRIVATE_EMAIL_") {
		t.Errorf("upstream body was not redacted: %s", upstreamSawBody)
	}

	out := string(respBody)
	if strings.Contains(out, "OG_PRIVATE_EMAIL_") {
		t.Errorf("placeholder leaked to client: %s", out)
	}
	if !strings.Contains(out, secret) {
		t.Errorf("response was not restored to the original secret: %s", out)
	}
}

func TestResponsesPipelineEndToEnd(t *testing.T) {
	const secret = "alice@example.com"

	var upstreamSawBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		upstreamSawBody = string(b)

		var placeholder string
		if i := strings.Index(upstreamSawBody, "OG_PRIVATE_EMAIL_"); i >= 0 {
			placeholder = upstreamSawBody[i : i+len("OG_PRIVATE_EMAIL_")+6]
		}
		half := len(placeholder) / 2

		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		ev := func(delta string) string {
			return `event: response.output_text.delta` + "\n" +
				`data: {"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"` + delta + `"}` + "\n\n"
		}
		_, _ = io.WriteString(w, ev("reply to "+placeholder[:half]))
		if fl != nil {
			fl.Flush()
		}
		_, _ = io.WriteString(w, ev(placeholder[half:]+" thanks"))
		_, _ = io.WriteString(w, `data: {"type":"response.completed","response":{}}`+"\n\n")
	}))
	defer upstream.Close()

	minter, err := token.NewMinter(4242, fixedClock{time.Unix(1_700_000_000, 0)}, time.Hour)
	if err != nil {
		t.Fatalf("minter: %v", err)
	}
	cache, err := memory.New[[]pii.Span](16)
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	pipeline := redact.New(scriptedDetector{value: secret, class: pii.ClassEmail}, cache)

	h := proxy.New(proxy.Config{
		Minter:       minter,
		Redactor:     pipeline,
		UpstreamBase: upstream.URL,
		Client:       upstream.Client(),
	})
	front := httptest.NewServer(h)
	defer front.Close()

	reqBody := `{"model":"gpt-5.1","input":[{"role":"user","content":"email ` + secret + ` for me"}]}`
	req, _ := http.NewRequest("POST", front.URL+"/_k/"+minter.Mint()+"/v1/responses", strings.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer sk-agent-own-credential")

	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)

	if strings.Contains(upstreamSawBody, secret) {
		t.Errorf("upstream received the raw secret: %s", upstreamSawBody)
	}
	if !strings.Contains(upstreamSawBody, "OG_PRIVATE_EMAIL_") {
		t.Errorf("upstream body was not redacted: %s", upstreamSawBody)
	}

	out := string(respBody)
	if strings.Contains(out, "OG_PRIVATE_EMAIL_") {
		t.Errorf("placeholder leaked to client: %s", out)
	}
	if !strings.Contains(out, secret) {
		t.Errorf("response was not restored: %s", out)
	}
}

func TestCodexConfigResolvesToRedactingRoute(t *testing.T) {
	home := t.TempDir()
	hook := launch.CodexPrepare(home)
	env, err := hook("http://127.0.0.1:5000", "ogl_live_tok")
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	codexHome := env["CODEX_HOME"]

	cfg, err := os.ReadFile(filepath.Join(codexHome, "config.toml"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	// Pull base_url out of the generated TOML.
	base := ""
	for _, line := range strings.Split(string(cfg), "\n") {
		if strings.HasPrefix(line, "base_url = ") {
			base = strings.Trim(strings.TrimPrefix(line, "base_url = "), `"`)
		}
	}
	if base == "" {
		t.Fatalf("no base_url in config:\n%s", cfg)
	}

	// Codex (wire_api=responses) appends "/responses" to base_url. Verify the
	// resulting request, after the proxy strips the /_k/<token> prefix, hits the
	// redacting /v1/responses route.
	full := base + "/responses" // e.g. http://127.0.0.1:5000/_k/ogl_live_tok/v1/responses
	u, err := url.Parse(full)
	if err != nil {
		t.Fatalf("parse %q: %v", full, err)
	}
	rest, ok := strings.CutPrefix(u.Path, "/_k/ogl_live_tok")
	if !ok {
		t.Fatalf("path %q lacks the /_k/<token> prefix", u.Path)
	}
	ep := provider.Route("POST", rest)
	if !ep.Redactable() {
		t.Errorf("codex path %q (stripped: %q) is not redactable", full, rest)
	}
	if ep.Kind != provider.OpenAIResponses {
		t.Errorf("kind = %v, want OpenAIResponses", ep.Kind)
	}
}
