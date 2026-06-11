package provider

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestExtractJSONStringValuesNested(t *testing.T) {
	raw := json.RawMessage(`{"path":"/Users/bob/notes.txt","opts":{"mode":"append","depth":3},"tags":["alpha","beta"],"dry":false,"n":null}`)
	refs, rebuild, err := extractJSONStringValues(raw)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	got := map[string]bool{}
	for _, r := range refs {
		got[r.Text] = true
	}
	want := []string{"/Users/bob/notes.txt", "append", "alpha", "beta"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", fieldTexts(refs), want)
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing field %q", w)
		}
	}
	for _, r := range refs {
		if r.Text == "/Users/bob/notes.txt" {
			r.Set("OG_PRIVATE_URL_abc123")
		}
	}
	out := rebuild()
	if strings.Contains(string(out), "/Users/bob") {
		t.Errorf("original survived: %s", out)
	}
	var round map[string]any
	if err := json.Unmarshal(out, &round); err != nil {
		t.Fatalf("rebuilt JSON invalid: %v\n%s", err, out)
	}
	if round["path"] != "OG_PRIVATE_URL_abc123" {
		t.Errorf("path = %v", round["path"])
	}
	opts, _ := round["opts"].(map[string]any)
	if opts == nil || opts["depth"] != float64(3) || round["dry"] != false {
		t.Errorf("non-string values mangled: %s", out)
	}
}

func TestExtractJSONStringValuesNoStrings(t *testing.T) {
	for _, raw := range []string{`{"a":1,"b":[2,3],"c":{"d":null}}`, `42`, `true`, `[]`, `{}`, `""`} {
		refs, rebuild, err := extractJSONStringValues(json.RawMessage(raw))
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if refs != nil || rebuild != nil {
			t.Errorf("%s: want no refs and nil rebuild, got %v", raw, fieldTexts(refs))
		}
	}
}

func TestExtractJSONStringValuesUntouchedSubtreeKeepsBytes(t *testing.T) {
	raw := json.RawMessage(`{"keep":{"n":[1,2,3]},"v":"secret"}`)
	refs, rebuild, err := extractJSONStringValues(raw)
	if err != nil || len(refs) != 1 {
		t.Fatalf("refs=%v err=%v", fieldTexts(refs), err)
	}
	refs[0].Set("X")
	out := rebuild()
	if !bytes.Contains(out, []byte(`{"n":[1,2,3]}`)) {
		t.Errorf("untouched subtree re-encoded: %s", out)
	}
}

func TestExtractJSONStringValuesEscaping(t *testing.T) {
	raw := mustMarshal(map[string]string{"text": "line1\nline2 \"quoted\" → ünïcode"})
	refs, rebuild, err := extractJSONStringValues(raw)
	if err != nil || len(refs) != 1 {
		t.Fatalf("refs=%v err=%v", fieldTexts(refs), err)
	}
	if refs[0].Text != "line1\nline2 \"quoted\" → ünïcode" {
		t.Fatalf("decoded text wrong: %q", refs[0].Text)
	}
	refs[0].Set("a\nb \"c\"")
	var round map[string]string
	if err := json.Unmarshal(rebuild(), &round); err != nil {
		t.Fatalf("rebuilt invalid: %v", err)
	}
	if round["text"] != "a\nb \"c\"" {
		t.Errorf("round-trip = %q", round["text"])
	}
}

func TestExtractJSONStringValuesDepthGuard(t *testing.T) {
	n := maxWalkDepth + 2
	for _, deep := range []string{
		strings.Repeat(`[`, n) + `"x"` + strings.Repeat(`]`, n),
		strings.Repeat(`{"a":`, n) + `"x"` + strings.Repeat(`}`, n),
	} {
		if _, _, err := extractJSONStringValues(json.RawMessage(deep)); err == nil {
			t.Error("expected depth-limit error")
		}
	}
}

func TestToolExtractionDepthGuard(t *testing.T) {
	n := maxWalkDepth + 2
	deep := strings.Repeat(`{"a":`, n) + `"x"` + strings.Repeat(`}`, n)
	anthropic := []byte(`{"messages":[{"content":[{"type":"tool_use","input":` + deep + `}]}]}`)
	if _, _, err := anthropicExtract(anthropic); err == nil {
		t.Error("anthropic: expected depth error")
	}
	args, _ := json.Marshal(deep)
	openai := []byte(`{"messages":[{"role":"assistant","tool_calls":[{"function":{"arguments":` + string(args) + `}}]}]}`)
	if _, _, err := openAIChatExtract(openai); err == nil {
		t.Error("openai chat: expected depth error")
	}
	responses := []byte(`{"input":[{"type":"function_call","arguments":` + string(args) + `}]}`)
	if _, _, err := openAIResponsesExtract(responses); err == nil {
		t.Error("responses: expected depth error")
	}
}

func TestExtractArguments(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"encoded object", `"{\"cmd\":\"ssh bob@10.0.0.1\",\"retries\":2}"`, []string{"ssh bob@10.0.0.1"}},
		{"bare object", `{"cmd":"ssh bob@10.0.0.1"}`, []string{"ssh bob@10.0.0.1"}},
		{"invalid json falls back to whole string", `"not {json"`, []string{"not {json"}},
		{"empty string", `""`, nil},
		{"empty object", `"{}"`, nil},
		{"number content", `"42"`, nil},
	}
	for _, c := range cases {
		refs, rebuild, err := extractArguments(json.RawMessage(c.raw))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := fieldTexts(refs); len(got) != len(c.want) {
			t.Fatalf("%s: got %v, want %v", c.name, got, c.want)
		}
		for i, w := range c.want {
			if refs[i].Text != w {
				t.Errorf("%s: field %d = %q, want %q", c.name, i, refs[i].Text, w)
			}
		}
		if c.want == nil && rebuild != nil {
			t.Errorf("%s: want nil rebuild", c.name)
		}
	}
}

func TestExtractArgumentsEncodedRoundTrip(t *testing.T) {
	raw := json.RawMessage(`"{\"path\":\"/home/ali/.ssh/id_rsa\",\"lines\":40}"`)
	refs, rebuild, err := extractArguments(raw)
	if err != nil || len(refs) != 1 {
		t.Fatalf("refs=%v err=%v", fieldTexts(refs), err)
	}
	refs[0].Set("OG_PRIVATE_URL_def456")
	out := rebuild()
	var s string
	if err := json.Unmarshal(out, &s); err != nil {
		t.Fatalf("rebuilt not a JSON string: %v\n%s", err, out)
	}
	var inner map[string]any
	if err := json.Unmarshal([]byte(s), &inner); err != nil {
		t.Fatalf("inner not valid JSON: %v\n%s", err, s)
	}
	if inner["path"] != "OG_PRIVATE_URL_def456" || inner["lines"] != float64(40) {
		t.Errorf("inner = %v", inner)
	}
}
