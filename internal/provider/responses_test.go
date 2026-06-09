package provider

import (
	"strings"
	"testing"
)

func TestResponsesExtractStringInput(t *testing.T) {
	body := []byte(`{"model":"gpt-5.1","instructions":"be terse","input":"my email is a@b.com"}`)
	refs, reassemble, err := openAIResponsesExtract(body)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	got := fieldTexts(refs)
	want := map[string]bool{"be terse": true, "my email is a@b.com": true}
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

func TestResponsesExtractMessageStringContent(t *testing.T) {
	body := []byte(`{"model":"gpt","input":[{"role":"developer","content":"talk like a pirate"},{"role":"user","content":"call me at 415-555-0100"}]}`)
	refs, reassemble, err := openAIResponsesExtract(body)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	got := fieldTexts(refs)
	want := map[string]bool{"talk like a pirate": true, "call me at 415-555-0100": true}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected field %q", g)
		}
	}
	refs[0].Set("REDACTED-A")
	refs[1].Set("REDACTED-B")
	out, err := reassemble()
	if err != nil {
		t.Fatalf("reassemble: %v", err)
	}
	if strings.Contains(string(out), "pirate") || strings.Contains(string(out), "415-555-0100") {
		t.Errorf("originals survived: %s", out)
	}
}

func TestResponsesExtractInputTextParts(t *testing.T) {
	body := []byte(`{"model":"gpt","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"see a@b.com"},{"type":"input_image","image_url":"http://x"}]}]}`)
	refs, reassemble, err := openAIResponsesExtract(body)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if got := fieldTexts(refs); len(got) != 1 || got[0] != "see a@b.com" {
		t.Fatalf("got %v, want [see a@b.com]", got)
	}
	refs[0].Set("see OG_PRIVATE_EMAIL_abc123")
	out, err := reassemble()
	if err != nil {
		t.Fatalf("reassemble: %v", err)
	}
	if strings.Contains(string(out), "a@b.com") {
		t.Errorf("email survived: %s", out)
	}
	if !strings.Contains(string(out), "input_image") || !strings.Contains(string(out), "http://x") {
		t.Errorf("non-text part dropped: %s", out)
	}
}

func TestResponsesExtractOutputTextPart(t *testing.T) {
	body := []byte(`{"model":"gpt","input":[{"role":"assistant","content":[{"type":"output_text","text":"prior reply secret-x"}]}]}`)
	refs, _, err := openAIResponsesExtract(body)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if got := fieldTexts(refs); len(got) != 1 || got[0] != "prior reply secret-x" {
		t.Fatalf("got %v", got)
	}
}

func TestResponsesFrameFieldsUntouched(t *testing.T) {
	body := []byte(`{"model":"gpt-5.1","temperature":0.5,"tools":[{"type":"function","name":"f"}],"previous_response_id":"resp_123","metadata":{"k":"v"},"input":[{"role":"user","content":"hi"}]}`)
	refs, reassemble, err := openAIResponsesExtract(body)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	for _, r := range refs {
		if strings.Contains(r.Text, "resp_123") || strings.Contains(r.Text, "function") || r.Text == "gpt-5.1" {
			t.Errorf("frame value leaked into a field: %q", r.Text)
		}
	}
	out, err := reassemble()
	if err != nil {
		t.Fatalf("reassemble: %v", err)
	}
	for _, frag := range []string{`"previous_response_id":"resp_123"`, `"resp_123"`, "function", `"metadata"`} {
		if !strings.Contains(string(out), frag) {
			t.Errorf("frame field %q lost in reassembly: %s", frag, out)
		}
	}
	assertField(t, out, "model", "gpt-5.1")
}

func TestResponsesModelValueNeverExtracted(t *testing.T) {
	body := []byte(`{"model":"john.smith@corp.com","input":[{"role":"user","content":"hi"}]}`)
	refs, _, err := openAIResponsesExtract(body)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	for _, r := range refs {
		if strings.Contains(r.Text, "john.smith@corp.com") {
			t.Errorf("model value leaked into detection field %q", r.Text)
		}
	}
}

func TestResponsesNoInput(t *testing.T) {
	body := []byte(`{"model":"gpt","instructions":"only instructions"}`)
	refs, reassemble, err := openAIResponsesExtract(body)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if got := fieldTexts(refs); len(got) != 1 || got[0] != "only instructions" {
		t.Fatalf("got %v", got)
	}
	if _, err := reassemble(); err != nil {
		t.Fatalf("reassemble: %v", err)
	}
}

func TestResponsesNonMessageItemPassesThrough(t *testing.T) {
	body := []byte(`{"model":"gpt","input":[{"type":"function_call","name":"f","arguments":"{}"},{"role":"user","content":"redact a@b.com"}]}`)
	refs, reassemble, err := openAIResponsesExtract(body)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if got := fieldTexts(refs); len(got) != 1 || got[0] != "redact a@b.com" {
		t.Fatalf("got %v", got)
	}
	out, err := reassemble()
	if err != nil {
		t.Fatalf("reassemble: %v", err)
	}
	if !strings.Contains(string(out), "function_call") {
		t.Errorf("non-message item dropped: %s", out)
	}
}

func TestResponsesInvalidJSON(t *testing.T) {
	cases := [][]byte{
		[]byte(`{bad`),
		[]byte(`{"input":[42]}`),
		[]byte(`{"instructions":["notstring"]}`),
		[]byte(`{"input":["notstring"]}`),
		[]byte(`{"input":[{"role":"user","content":[{"type":"input_text","text":99}]}]}`),
	}
	for _, b := range cases {
		if _, _, err := openAIResponsesExtract(b); err == nil {
			t.Errorf("expected error on %s", b)
		}
	}
}

func TestResponsesNonTextInstructionsIgnored(t *testing.T) {
	// A numeric instructions field is not text — no extraction, no error.
	refs, reassemble, err := openAIResponsesExtract([]byte(`{"instructions":42,"input":"hi"}`))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	for _, r := range refs {
		if r.Text == "42" {
			t.Error("numeric instructions should not be extracted")
		}
	}
	if _, err := reassemble(); err != nil {
		t.Fatalf("reassemble: %v", err)
	}
}
