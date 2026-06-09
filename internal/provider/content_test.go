package provider

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExtractContentFieldTypesCustomTypeSet(t *testing.T) {
	raw := json.RawMessage(`[{"type":"input_text","text":"mail a@b.com"},{"type":"input_image","image_url":"http://x"}]`)

	// The default set keys on "text" and must NOT match an "input_text" part.
	refs, _, err := extractContentField(raw)
	if err != nil {
		t.Fatalf("default: %v", err)
	}
	if len(refs) != 0 {
		t.Errorf("default {text} set should not match input_text, got %v", fieldTexts(refs))
	}

	// A custom set including input_text matches and extracts its .text.
	refs, rebuild, err := extractContentFieldTypes(raw, map[string]bool{"input_text": true})
	if err != nil {
		t.Fatalf("custom: %v", err)
	}
	if len(refs) != 1 || refs[0].Text != "mail a@b.com" {
		t.Fatalf("custom set got %v, want [mail a@b.com]", fieldTexts(refs))
	}

	refs[0].Set("mail OG_PRIVATE_EMAIL_abc123")
	out := rebuild()
	if !strings.Contains(string(out), "OG_PRIVATE_EMAIL_abc123") || strings.Contains(string(out), "a@b.com") {
		t.Errorf("rebuild wrong: %s", out)
	}
	if !strings.Contains(string(out), "input_image") || !strings.Contains(string(out), "http://x") {
		t.Errorf("non-matching part dropped: %s", out)
	}
}

func TestExtractContentFieldTypesStringBranchUnaffected(t *testing.T) {
	// String content is extracted regardless of the type set.
	refs, _, err := extractContentFieldTypes(json.RawMessage(`"just text"`), map[string]bool{"input_text": true})
	if err != nil {
		t.Fatalf("string: %v", err)
	}
	if len(refs) != 1 || refs[0].Text != "just text" {
		t.Errorf("string branch got %v", fieldTexts(refs))
	}
}
