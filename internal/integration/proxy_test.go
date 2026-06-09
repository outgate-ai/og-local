//go:build integration

package integration

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
		Kind:         provider.Anthropic,
		UpstreamBase: upstream.URL,
		UpstreamKey:  "sk-upstream-real",
		Client:       upstream.Client(),
	})
	front := httptest.NewServer(h)
	defer front.Close()

	reqBody := `{"model":"claude","messages":[{"role":"user","content":"email ` + secret + ` for me"}]}`
	req, _ := http.NewRequest("POST", front.URL+"/v1/messages", strings.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+minter.Mint())

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
