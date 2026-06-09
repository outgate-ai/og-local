package provider

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAnthropicDeltaTextEvent(t *testing.T) {
	codec := anthropicDelta{}
	payload := []byte(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello OG_PRIVATE_EMAIL_abc123"}}`)
	ev, ok := codec.Event(payload)
	if !ok {
		t.Fatal("expected ok")
	}
	if ev.Kind != EvDelta {
		t.Fatalf("kind = %v, want EvDelta", ev.Kind)
	}
	if ev.Text != "hello OG_PRIVATE_EMAIL_abc123" {
		t.Fatalf("text = %q", ev.Text)
	}

	out := ev.Reencode("hello alice@example.com")
	if !strings.Contains(string(out), "alice@example.com") {
		t.Errorf("reencoded text missing: %s", out)
	}
	if strings.Contains(string(out), "OG_PRIVATE_EMAIL") {
		t.Errorf("placeholder survived: %s", out)
	}
	var env map[string]json.RawMessage
	_ = json.Unmarshal(out, &env)
	var idx int
	_ = json.Unmarshal(env["index"], &idx)
	if idx != 0 {
		t.Errorf("index field not preserved: %s", out)
	}
	var typ string
	_ = json.Unmarshal(env["type"], &typ)
	if typ != "content_block_delta" {
		t.Errorf("type not preserved: %s", out)
	}
}

func TestAnthropicDeltaControlEvents(t *testing.T) {
	codec := anthropicDelta{}
	cases := map[string]EventKind{
		`{"type":"content_block_stop","index":0}`: EvBlockStop,
		`{"type":"message_stop"}`:                 EvDone,
		`{"type":"message_start","message":{}}`:   EvOther,
		`{"type":"ping"}`:                         EvOther,
		`{"type":"content_block_delta","delta":{"type":"input_json_delta","partial_json":"{"}}`: EvOther,
		`{"type":"content_block_start","index":0,"content_block":{}}`:                           EvOther,
	}
	for payload, want := range cases {
		ev, ok := codec.Event([]byte(payload))
		if !ok {
			t.Errorf("%s: expected ok", payload)
			continue
		}
		if ev.Kind != want {
			t.Errorf("%s: kind = %v, want %v", payload, ev.Kind, want)
		}
		if ev.Kind != EvDelta && ev.Reencode != nil {
			t.Errorf("%s: non-delta event should not carry Reencode", payload)
		}
	}
}

func TestAnthropicDeltaMalformed(t *testing.T) {
	codec := anthropicDelta{}
	if _, ok := codec.Event([]byte(`not json`)); ok {
		t.Error("expected !ok on non-JSON")
	}
	if ev, ok := codec.Event([]byte(`{"type":"content_block_delta","delta":"notobject"}`)); !ok || ev.Kind != EvOther {
		t.Errorf("malformed delta: ok=%v kind=%v", ok, ev.Kind)
	}
	if ev, ok := codec.Event([]byte(`{"type":"content_block_delta","delta":{"type":"text_delta","text":5}}`)); !ok || ev.Kind != EvOther {
		t.Errorf("non-string text: ok=%v kind=%v", ok, ev.Kind)
	}
}

func TestOpenAIChatDeltaTextEvent(t *testing.T) {
	codec := openAIChatDelta{}
	payload := []byte(`{"id":"cmpl-1","choices":[{"index":0,"delta":{"content":"see OG_PRIVATE_EMAIL_abc123"},"finish_reason":null}]}`)
	ev, ok := codec.Event(payload)
	if !ok || ev.Kind != EvDelta {
		t.Fatalf("ok=%v kind=%v", ok, ev.Kind)
	}
	if ev.Text != "see OG_PRIVATE_EMAIL_abc123" {
		t.Fatalf("text = %q", ev.Text)
	}
	out := ev.Reencode("see alice@example.com")
	if !strings.Contains(string(out), "alice@example.com") || strings.Contains(string(out), "OG_PRIVATE_EMAIL") {
		t.Errorf("reencode wrong: %s", out)
	}
	var env map[string]json.RawMessage
	_ = json.Unmarshal(out, &env)
	var id string
	_ = json.Unmarshal(env["id"], &id)
	if id != "cmpl-1" {
		t.Errorf("id not preserved: %s", out)
	}
}

func TestOpenAIChatDeltaNonText(t *testing.T) {
	codec := openAIChatDelta{}
	cases := []string{
		`{"choices":[{"delta":{"role":"assistant"}}]}`,
		`{"choices":[{"delta":{},"finish_reason":"stop"}]}`,
		`{"choices":[]}`,
		`{"choices":[{"delta":{"content":null}}]}`,
	}
	for _, p := range cases {
		ev, ok := codec.Event([]byte(p))
		if !ok || ev.Kind != EvOther {
			t.Errorf("%s: ok=%v kind=%v", p, ok, ev.Kind)
		}
	}
}

func TestOpenAIChatDeltaMalformed(t *testing.T) {
	codec := openAIChatDelta{}
	if _, ok := codec.Event([]byte(`[DONE]`)); ok {
		t.Error("expected !ok on [DONE] sentinel")
	}
	for _, p := range []string{
		`{"choices":"notarray"}`,
		`{"choices":["notobject"]}`,
		`{"choices":[{"delta":"notobject"}]}`,
		`{"choices":[{"delta":{"content":5}}]}`,
	} {
		ev, ok := codec.Event([]byte(p))
		if !ok || ev.Kind != EvOther {
			t.Errorf("%s: ok=%v kind=%v", p, ok, ev.Kind)
		}
	}
}
