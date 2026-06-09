package stream

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/outgate-ai/og-local/internal/pii"
	"github.com/outgate-ai/og-local/internal/provider"
)

func anthropicCodec(t *testing.T) provider.DeltaCodec {
	t.Helper()
	c := provider.Route("POST", "/v1/messages").DeltaCodec()
	if c == nil {
		t.Fatal("no anthropic codec")
	}
	return c
}

func openAICodec(t *testing.T) provider.DeltaCodec {
	t.Helper()
	c := provider.Route("POST", "/v1/chat/completions").DeltaCodec()
	if c == nil {
		t.Fatal("no openai codec")
	}
	return c
}

func anthropicTextDelta(text string) string {
	b, _ := json.Marshal(map[string]any{
		"type":  "content_block_delta",
		"index": 0,
		"delta": map[string]any{"type": "text_delta", "text": text},
	})
	return "data: " + string(b) + "\n"
}

func openAITextDelta(text string) string {
	b, _ := json.Marshal(map[string]any{
		"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": text}}},
	})
	return "data: " + string(b) + "\n"
}

// collectText pulls the concatenated restored delta text out of an SSE output
// stream produced by the transformer, for Anthropic text_delta events.
func collectAnthropicText(t *testing.T, out string) string {
	t.Helper()
	var sb strings.Builder
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var env struct {
			Type  string `json:"type"`
			Delta struct {
				Text string `json:"text"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &env); err != nil {
			continue
		}
		if env.Type == "content_block_delta" {
			sb.WriteString(env.Delta.Text)
		}
	}
	return sb.String()
}

func collectOpenAIText(t *testing.T, out string) string {
	t.Helper()
	var sb strings.Builder
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var env struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &env); err != nil {
			continue
		}
		for _, c := range env.Choices {
			sb.WriteString(c.Delta.Content)
		}
	}
	return sb.String()
}

func feed(t *testing.T, tr *Transformer, chunks []string) {
	t.Helper()
	for _, c := range chunks {
		if _, err := tr.Write([]byte(c)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := tr.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func mapping(pairs ...[2]string) pii.Mapping {
	m := make(pii.Mapping, len(pairs))
	for i, p := range pairs {
		m[i] = pii.Pair{From: p[0], To: p[1]}
	}
	return m
}

func TestStreamCompleteTokenSingleEvent(t *testing.T) {
	m := mapping([2]string{"alice@example.com", "OG_PRIVATE_EMAIL_abc123"})
	var buf bytes.Buffer
	tr := New(&buf, anthropicCodec(t), m)
	feed(t, tr, []string{
		anthropicTextDelta("contact OG_PRIVATE_EMAIL_abc123 now"),
		"data: {\"type\":\"content_block_stop\",\"index\":0}\n",
	})
	got := collectAnthropicText(t, buf.String())
	if got != "contact alice@example.com now" {
		t.Errorf("got %q", got)
	}
}

func TestStreamTokenSplitAcrossTwoChunks(t *testing.T) {
	m := mapping([2]string{"alice@example.com", "OG_PRIVATE_EMAIL_abc123"})
	full := anthropicTextDelta("contact OG_PRIVATE_EMAIL_abc123 now")
	mid := len(full) / 2
	var buf bytes.Buffer
	tr := New(&buf, anthropicCodec(t), m)
	feed(t, tr, []string{full[:mid], full[mid:], "data: {\"type\":\"message_stop\"}\n"})
	got := collectAnthropicText(t, buf.String())
	if got != "contact alice@example.com now" {
		t.Errorf("got %q", got)
	}
}

func TestStreamTokenSplitAcrossEvents(t *testing.T) {
	m := mapping([2]string{"alice@example.com", "OG_PRIVATE_EMAIL_abc123"})
	var buf bytes.Buffer
	tr := New(&buf, anthropicCodec(t), m)
	feed(t, tr, []string{
		anthropicTextDelta("contact OG_PRIVATE_"),
		anthropicTextDelta("EMAIL_"),
		anthropicTextDelta("abc123 now"),
		"data: {\"type\":\"message_stop\"}\n",
	})
	got := collectAnthropicText(t, buf.String())
	if got != "contact alice@example.com now" {
		t.Errorf("got %q", got)
	}
	if strings.Contains(buf.String(), "OG_PRIVATE_EMAIL") {
		t.Errorf("placeholder leaked into output: %s", buf.String())
	}
}

func TestStreamSplitAfterCompletedToken(t *testing.T) {
	m := mapping(
		[2]string{"alice@example.com", "OG_PRIVATE_EMAIL_abc123"},
		[2]string{"Bob Jones", "OG_PRIVATE_PERSON_def456"},
	)
	var buf bytes.Buffer
	tr := New(&buf, anthropicCodec(t), m)
	feed(t, tr, []string{
		anthropicTextDelta("to OG_PRIVATE_EMAIL_abc123 and OG_PRIVATE_"),
		anthropicTextDelta("PERSON_def456 today"),
		"data: {\"type\":\"message_stop\"}\n",
	})
	got := collectAnthropicText(t, buf.String())
	if got != "to alice@example.com and Bob Jones today" {
		t.Errorf("got %q", got)
	}
}

func TestStreamNeverEmitsPartialPlaceholder(t *testing.T) {
	m := mapping([2]string{"alice@example.com", "OG_PRIVATE_EMAIL_abc123"})
	tok := "OG_PRIVATE_EMAIL_abc123"
	full := anthropicTextDelta("x OG_PRIVATE_EMAIL_abc123 y")
	for split := 1; split < len(full); split++ {
		pw := &partialWatcher{t: t, token: tok}
		tr := New(pw, anthropicCodec(t), m)
		_, _ = tr.Write([]byte(full[:split]))
		_, _ = tr.Write([]byte(full[split:]))
		_ = tr.Close()
		got := collectAnthropicText(t, pw.buf.String())
		if got != "x alice@example.com y" {
			t.Fatalf("split %d: got %q", split, got)
		}
	}
}

type partialWatcher struct {
	t     *testing.T
	token string
	buf   bytes.Buffer
}

func (w *partialWatcher) Write(p []byte) (int, error) {
	w.buf.Write(p)
	for _, line := range strings.Split(string(p), "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var env struct {
			Type  string `json:"type"`
			Delta struct {
				Text string `json:"text"`
			} `json:"delta"`
		}
		if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &env) != nil {
			continue
		}
		txt := env.Delta.Text
		for n := 1; n < len(w.token); n++ {
			if strings.HasSuffix(txt, w.token[:n]) {
				w.t.Errorf("emitted a partial placeholder suffix %q in %q", w.token[:n], txt)
			}
		}
		if strings.Contains(txt, w.token) {
			w.t.Errorf("emitted full placeholder %q", w.token)
		}
	}
	return len(p), nil
}

func TestStreamBlockStopResetsBetweenBlocks(t *testing.T) {
	m := mapping([2]string{"alice@example.com", "OG_PRIVATE_EMAIL_abc123"})
	var buf bytes.Buffer
	tr := New(&buf, anthropicCodec(t), m)
	feed(t, tr, []string{
		anthropicTextDelta("first OG_PRIVATE_EMAIL_abc123"),
		"data: {\"type\":\"content_block_stop\",\"index\":0}\n",
		anthropicTextDelta("second OG_PRIVATE_EMAIL_abc123"),
		"data: {\"type\":\"content_block_stop\",\"index\":1}\n",
		"data: {\"type\":\"message_stop\"}\n",
	})
	got := collectAnthropicText(t, buf.String())
	if got != "first alice@example.comsecond alice@example.com" {
		t.Errorf("got %q", got)
	}
}

func TestStreamBase64StraddleUntouched(t *testing.T) {
	blob := strings.Repeat("A", 80)
	m := mapping([2]string{"alice@example.com", "OG_PRIVATE_EMAIL_abc123"})
	full := anthropicTextDelta("blob " + blob + " end")
	mid := len(full) / 2
	var buf bytes.Buffer
	tr := New(&buf, anthropicCodec(t), m)
	feed(t, tr, []string{full[:mid], full[mid:], "data: {\"type\":\"message_stop\"}\n"})
	got := collectAnthropicText(t, buf.String())
	if got != "blob "+blob+" end" {
		t.Errorf("base64 mangled: %q", got)
	}
}

func TestStreamPassthroughLines(t *testing.T) {
	m := mapping([2]string{"alice@example.com", "OG_PRIVATE_EMAIL_abc123"})
	var buf bytes.Buffer
	tr := New(&buf, anthropicCodec(t), m)
	feed(t, tr, []string{
		"event: message_start\n",
		": this is a comment\n",
		"\n",
		anthropicTextDelta("hi OG_PRIVATE_EMAIL_abc123"),
		"data: {\"type\":\"message_stop\"}\n",
	})
	out := buf.String()
	if !strings.Contains(out, "event: message_start") {
		t.Errorf("event line dropped: %s", out)
	}
	if !strings.Contains(out, ": this is a comment") {
		t.Errorf("comment dropped: %s", out)
	}
	if got := collectAnthropicText(t, out); got != "hi alice@example.com" {
		t.Errorf("got %q", got)
	}
}

func TestStreamOpenAISplitAcrossEvents(t *testing.T) {
	m := mapping([2]string{"415-555-0100", "OG_PRIVATE_PHONE_aaa111"})
	var buf bytes.Buffer
	tr := New(&buf, openAICodec(t), m)
	feed(t, tr, []string{
		openAITextDelta("call OG_PRIVATE_"),
		openAITextDelta("PHONE_aaa111 please"),
		"data: [DONE]\n",
	})
	got := collectOpenAIText(t, buf.String())
	if got != "call 415-555-0100 please" {
		t.Errorf("got %q", got)
	}
	if !strings.Contains(buf.String(), "data: [DONE]") {
		t.Errorf("[DONE] sentinel dropped: %s", buf.String())
	}
}

func TestStreamEmptyMapping(t *testing.T) {
	var buf bytes.Buffer
	tr := New(&buf, anthropicCodec(t), nil)
	feed(t, tr, []string{
		anthropicTextDelta("plain text no pii"),
		"data: {\"type\":\"message_stop\"}\n",
	})
	if got := collectAnthropicText(t, buf.String()); got != "plain text no pii" {
		t.Errorf("got %q", got)
	}
}

type failWriter struct {
	failAfter int
	n         int
}

func (w *failWriter) Write(p []byte) (int, error) {
	w.n++
	if w.n > w.failAfter {
		return 0, errors.New("write failed")
	}
	return len(p), nil
}

func TestStreamWriteErrorPropagates(t *testing.T) {
	m := mapping([2]string{"alice@example.com", "OG_PRIVATE_EMAIL_abc123"})
	tr := New(&failWriter{failAfter: 0}, anthropicCodec(t), m)
	if _, err := tr.Write([]byte(anthropicTextDelta("hi"))); err == nil {
		t.Error("expected write error to propagate")
	}
}

func TestStreamCloseErrorPropagates(t *testing.T) {
	m := mapping([2]string{"alice@example.com", "OG_PRIVATE_EMAIL_abc123"})
	// One successful delta write, then fail on the flush at Close.
	fw := &failWriter{failAfter: 1}
	tr := New(fw, anthropicCodec(t), m)
	_, _ = tr.Write([]byte(anthropicTextDelta("hi OG_PRIVATE_EMAIL_")))
	if err := tr.Close(); err == nil {
		t.Error("expected close flush error to propagate")
	}
}

func TestStreamCloseFlushesLeftoverLine(t *testing.T) {
	m := mapping([2]string{"alice@example.com", "OG_PRIVATE_EMAIL_abc123"})
	var buf bytes.Buffer
	tr := New(&buf, anthropicCodec(t), m)
	// Final data line arrives with no trailing newline.
	line := strings.TrimSuffix(anthropicTextDelta("done OG_PRIVATE_EMAIL_abc123"), "\n")
	if _, err := tr.Write([]byte(line)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := collectAnthropicText(t, buf.String()); got != "done alice@example.com" {
		t.Errorf("got %q", got)
	}
}

func TestStreamBlockStopWithNoPriorDelta(t *testing.T) {
	m := mapping([2]string{"alice@example.com", "OG_PRIVATE_EMAIL_abc123"})
	var buf bytes.Buffer
	tr := New(&buf, anthropicCodec(t), m)
	feed(t, tr, []string{
		"data: {\"type\":\"content_block_stop\",\"index\":0}\n",
		"data: {\"type\":\"message_stop\"}\n",
	})
	if !strings.Contains(buf.String(), "content_block_stop") {
		t.Errorf("block_stop dropped: %s", buf.String())
	}
}

func TestStreamOtherDataEventPassesThrough(t *testing.T) {
	m := mapping([2]string{"alice@example.com", "OG_PRIVATE_EMAIL_abc123"})
	var buf bytes.Buffer
	tr := New(&buf, anthropicCodec(t), m)
	feed(t, tr, []string{
		"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\"}}\n",
		anthropicTextDelta("hi OG_PRIVATE_EMAIL_abc123"),
		"data: {\"type\":\"message_stop\"}\n",
	})
	if !strings.Contains(buf.String(), "message_start") || !strings.Contains(buf.String(), "msg_1") {
		t.Errorf("EvOther data event not passed through: %s", buf.String())
	}
}

func TestStreamBlockStopWriteError(t *testing.T) {
	m := mapping([2]string{"alice@example.com", "OG_PRIVATE_EMAIL_abc123"})
	// Held-back partial then a block_stop whose flush write fails.
	fw := &failWriter{failAfter: 1}
	tr := New(fw, anthropicCodec(t), m)
	_, _ = tr.Write([]byte(anthropicTextDelta("x OG_PRIVATE_EMAIL_")))
	if _, err := tr.Write([]byte("data: {\"type\":\"content_block_stop\",\"index\":0}\n")); err == nil {
		t.Error("expected block_stop flush write error to propagate")
	}
}

func TestStreamCloseLeftoverLineError(t *testing.T) {
	m := mapping([2]string{"alice@example.com", "OG_PRIVATE_EMAIL_abc123"})
	fw := &failWriter{failAfter: 0}
	tr := New(fw, anthropicCodec(t), m)
	// A leftover line (no newline) that errors when flushed at Close.
	line := strings.TrimSuffix(anthropicTextDelta("hi OG_PRIVATE_EMAIL_abc123"), "\n")
	if err := func() error {
		if _, err := tr.Write([]byte(line)); err != nil {
			return err
		}
		return tr.Close()
	}(); err == nil {
		t.Error("expected leftover-line flush error at Close")
	}
}

func TestStreamFlushIsCalled(t *testing.T) {
	m := mapping([2]string{"alice@example.com", "OG_PRIVATE_EMAIL_abc123"})
	var buf bytes.Buffer
	flushed := 0
	tr := New(&buf, anthropicCodec(t), m, WithFlush(func() { flushed++ }))
	feed(t, tr, []string{anthropicTextDelta("hi"), "data: {\"type\":\"message_stop\"}\n"})
	if flushed == 0 {
		t.Error("flush never called")
	}
}
