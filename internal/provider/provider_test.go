package provider

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func fieldTexts(refs []FieldRef) []string {
	out := make([]string, len(refs))
	for i, r := range refs {
		out[i] = r.Text
	}
	return out
}

func TestRoute(t *testing.T) {
	cases := []struct {
		method, path string
		want         Kind
		redactable   bool
	}{
		{"POST", "/v1/messages", Anthropic, true},
		{"POST", "https://api.anthropic.com/v1/messages", Anthropic, true},
		{"POST", "/v1/messages/", Anthropic, true},
		{"POST", "/v1/chat/completions", OpenAIChat, true},
		{"POST", "/v1/responses", OpenAIResponses, true},
		{"POST", "https://api.openai.com/v1/responses", OpenAIResponses, true},
		{"POST", "/api/chat", Passthrough, false},
		{"POST", "/v1/messages/count_tokens", Passthrough, false},
		{"GET", "/v1/models", Passthrough, false},
		{"GET", "/v1/messages", Passthrough, false},
		{"POST", "/v1/models", Passthrough, false},
	}
	for _, c := range cases {
		ep := Route(c.method, c.path)
		if ep.Kind != c.want {
			t.Errorf("Route(%s,%s) kind = %v, want %v", c.method, c.path, ep.Kind, c.want)
		}
		if ep.Redactable() != c.redactable {
			t.Errorf("Route(%s,%s) redactable = %v, want %v", c.method, c.path, ep.Redactable(), c.redactable)
		}
		if hasCodec := ep.DeltaCodec() != nil; hasCodec != c.redactable {
			t.Errorf("Route(%s,%s) hasCodec = %v, want %v", c.method, c.path, hasCodec, c.redactable)
		}
	}
}

func TestAnthropicExtractStringFields(t *testing.T) {
	body := []byte(`{"model":"claude-opus-4","max_tokens":1024,"system":"you are helpful","messages":[{"role":"user","content":"my email is a@b.com"}]}`)
	ep := Route("POST", "/v1/messages")
	refs, reassemble, err := ep.Fields(body)
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	got := fieldTexts(refs)
	want := map[string]bool{"you are helpful": true, "my email is a@b.com": true}
	if len(got) != len(want) {
		t.Fatalf("got %d fields %v, want %d", len(got), got, len(want))
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected field %q", g)
		}
	}

	out, err := reassemble()
	if err != nil {
		t.Fatalf("reassemble: %v", err)
	}
	assertField(t, out, "model", "claude-opus-4")
	assertNumber(t, out, "max_tokens", 1024)
}

func TestAnthropicExtractBlockContent(t *testing.T) {
	body := []byte(`{"model":"claude","messages":[{"role":"user","content":[{"type":"text","text":"hello a@b.com"},{"type":"image","source":{"data":"AAAA"}}]}]}`)
	ep := Route("POST", "/v1/messages")
	refs, reassemble, err := ep.Fields(body)
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	if got := fieldTexts(refs); len(got) != 1 || got[0] != "hello a@b.com" {
		t.Fatalf("got %v, want [hello a@b.com]", got)
	}

	refs[0].Set("hello OG_PRIVATE_EMAIL_abc123")
	out, err := reassemble()
	if err != nil {
		t.Fatalf("reassemble: %v", err)
	}
	if !strings.Contains(string(out), "OG_PRIVATE_EMAIL_abc123") {
		t.Errorf("redacted text not in output: %s", out)
	}
	if strings.Contains(string(out), "a@b.com") {
		t.Errorf("original email survived: %s", out)
	}
	if !strings.Contains(string(out), `"image"`) || !strings.Contains(string(out), "AAAA") {
		t.Errorf("non-text block dropped: %s", out)
	}
}

func TestAnthropicSystemBlocks(t *testing.T) {
	body := []byte(`{"model":"claude","system":[{"type":"text","text":"secret sk-123"}],"messages":[]}`)
	ep := Route("POST", "/v1/messages")
	refs, _, err := ep.Fields(body)
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	if got := fieldTexts(refs); len(got) != 1 || got[0] != "secret sk-123" {
		t.Fatalf("got %v, want [secret sk-123]", got)
	}
}

func TestOpenAIChatExtract(t *testing.T) {
	body := []byte(`{"model":"gpt-5.1","temperature":0.7,"messages":[{"role":"system","content":"be terse"},{"role":"user","content":"call me at 415-555-0100"}]}`)
	ep := Route("POST", "/v1/chat/completions")
	refs, reassemble, err := ep.Fields(body)
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	got := fieldTexts(refs)
	want := map[string]bool{"be terse": true, "call me at 415-555-0100": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected field %q", g)
		}
	}
	out, err := reassemble()
	if err != nil {
		t.Fatalf("reassemble: %v", err)
	}
	assertField(t, out, "model", "gpt-5.1")
}

func TestOpenAIChatContentParts(t *testing.T) {
	body := []byte(`{"model":"gpt-5.1","messages":[{"role":"user","content":[{"type":"text","text":"see a@b.com"},{"type":"image_url","image_url":{"url":"http://x"}}]}]}`)
	ep := Route("POST", "/v1/chat/completions")
	refs, reassemble, err := ep.Fields(body)
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	if got := fieldTexts(refs); len(got) != 1 || got[0] != "see a@b.com" {
		t.Fatalf("got %v", got)
	}
	refs[0].Set("see OG_PRIVATE_EMAIL_aaa111")
	out, err := reassemble()
	if err != nil {
		t.Fatalf("reassemble: %v", err)
	}
	if !strings.Contains(string(out), "image_url") || !strings.Contains(string(out), "http://x") {
		t.Errorf("non-text part dropped: %s", out)
	}
	if strings.Contains(string(out), "a@b.com") {
		t.Errorf("original survived: %s", out)
	}
}

func TestModelValueNeverExtracted(t *testing.T) {
	body := []byte(`{"model":"john.smith@corp.com","messages":[{"role":"user","content":"hi"}]}`)
	for _, path := range []string{"/v1/messages", "/v1/chat/completions"} {
		ep := Route("POST", path)
		refs, _, err := ep.Fields(body)
		if err != nil {
			t.Fatalf("%s Fields: %v", path, err)
		}
		for _, r := range refs {
			if strings.Contains(r.Text, "john.smith@corp.com") {
				t.Errorf("%s: model value leaked into detection field %q", path, r.Text)
			}
		}
	}
}

func TestPassthroughFieldsReturnsBody(t *testing.T) {
	body := []byte(`{"anything":"goes"}`)
	ep := Route("GET", "/v1/models")
	refs, reassemble, err := ep.Fields(body)
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	if len(refs) != 0 {
		t.Errorf("passthrough should yield no fields, got %v", refs)
	}
	out, err := reassemble()
	if err != nil {
		t.Fatalf("reassemble: %v", err)
	}
	if !bytes.Equal(out, body) {
		t.Errorf("passthrough reassemble changed body: %s", out)
	}
}

func TestExtractInvalidJSON(t *testing.T) {
	bad := [][]byte{
		[]byte(`{not json`),
		[]byte(`{"messages":"notarray"}`),
		[]byte(`{"messages":[42]}`),
		[]byte(`{"messages":[{"content":[{"type":"text","text":99}]}]}`),
		[]byte(`{"messages":[{"content":["notblock"]}]}`),
	}
	for _, ex := range []extractFn{anthropicExtract, openAIChatExtract} {
		for _, b := range bad {
			if _, _, err := ex(b); err == nil {
				t.Errorf("expected error on %s", b)
			}
		}
	}
}

func TestExtractBadSystemField(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"system":"\uZZZZ"}`),
		[]byte(`{"system":["notblock"]}`),
		[]byte(`{"system":[{"type":"text","text":5}]}`),
	}
	for _, b := range cases {
		if _, _, err := anthropicExtract(b); err == nil {
			t.Errorf("expected error on system %s", b)
		}
	}
}

func TestStringFieldReassembleRoundTrips(t *testing.T) {
	refs, rebuild, err := extractContentField(json.RawMessage(`"plain text a@b.com"`))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(refs) != 1 || refs[0].Text != "plain text a@b.com" {
		t.Fatalf("got %v", fieldTexts(refs))
	}
	refs[0].Set("plain text OG_PRIVATE_EMAIL_zzz999")
	out := rebuild()
	var got string
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal rebuilt: %v", err)
	}
	if got != "plain text OG_PRIVATE_EMAIL_zzz999" {
		t.Errorf("rebuild = %q", got)
	}
}

func TestAnthropicNonTextSystemIgnored(t *testing.T) {
	refs, reassemble, err := anthropicExtract([]byte(`{"system":42,"messages":[]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 0 {
		t.Errorf("non-text system should yield no fields, got %v", fieldTexts(refs))
	}
	if _, err := reassemble(); err != nil {
		t.Fatalf("reassemble: %v", err)
	}
}

func TestContentFieldEdgeShapes(t *testing.T) {
	refs, rebuild, err := extractContentField(nil)
	if err != nil || refs != nil || rebuild != nil {
		t.Errorf("empty raw: refs=%v err=%v rebuildNil=%v", refs, err, rebuild == nil)
	}
	refs, rebuild, err = extractContentField(json.RawMessage(`42`))
	if err != nil || refs != nil || rebuild != nil {
		t.Errorf("number content: refs=%v err=%v rebuildNil=%v", refs, err, rebuild == nil)
	}
}

func TestMessageWithoutContent(t *testing.T) {
	body := []byte(`{"model":"claude","messages":[{"role":"assistant"},{"role":"user","content":"redact a@b.com"}]}`)
	for _, path := range []string{"/v1/messages", "/v1/chat/completions"} {
		ep := Route("POST", path)
		refs, reassemble, err := ep.Fields(body)
		if err != nil {
			t.Fatalf("%s Fields: %v", path, err)
		}
		if got := fieldTexts(refs); len(got) != 1 || got[0] != "redact a@b.com" {
			t.Fatalf("%s got %v", path, got)
		}
		out, err := reassemble()
		if err != nil {
			t.Fatalf("%s reassemble: %v", path, err)
		}
		if !strings.Contains(string(out), `"assistant"`) {
			t.Errorf("%s dropped content-less message: %s", path, out)
		}
	}
}

func TestRoundTripNoRedaction(t *testing.T) {
	body := []byte(`{"model":"claude","system":"sys","messages":[{"role":"user","content":"hi"}]}`)
	ep := Route("POST", "/v1/messages")
	_, reassemble, err := ep.Fields(body)
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	out, err := reassemble()
	if err != nil {
		t.Fatalf("reassemble: %v", err)
	}
	var a, b map[string]any
	_ = json.Unmarshal(body, &a)
	_ = json.Unmarshal(out, &b)
	if a["system"] != b["system"] {
		t.Errorf("system changed: %v vs %v", a["system"], b["system"])
	}
}

func assertField(t *testing.T, body []byte, key, want string) {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var got string
	if err := json.Unmarshal(m[key], &got); err != nil {
		t.Fatalf("unmarshal %s: %v", key, err)
	}
	if got != want {
		t.Errorf("%s = %q, want %q", key, got, want)
	}
}

func assertNumber(t *testing.T, body []byte, key string, want float64) {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var got float64
	if err := json.Unmarshal(m[key], &got); err != nil {
		t.Fatalf("unmarshal %s: %v", key, err)
	}
	if got != want {
		t.Errorf("%s = %v, want %v", key, got, want)
	}
}
