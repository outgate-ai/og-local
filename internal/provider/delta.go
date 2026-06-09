package provider

import "encoding/json"

type anthropicDelta struct{}

func (anthropicDelta) Event(payload []byte) (Event, bool) {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(payload, &env); err != nil {
		return Event{}, false
	}
	typ := ""
	if t, ok := env["type"]; ok {
		_ = json.Unmarshal(t, &typ)
	}
	switch typ {
	case "content_block_stop":
		return Event{Kind: EvBlockStop}, true
	case "message_stop":
		return Event{Kind: EvDone}, true
	case "content_block_delta":
		var delta map[string]json.RawMessage
		if err := json.Unmarshal(env["delta"], &delta); err != nil {
			return Event{Kind: EvOther}, true
		}
		dtyp := ""
		if t, ok := delta["type"]; ok {
			_ = json.Unmarshal(t, &dtyp)
		}
		if dtyp != "text_delta" {
			return Event{Kind: EvOther}, true
		}
		var text string
		if err := json.Unmarshal(delta["text"], &text); err != nil {
			return Event{Kind: EvOther}, true
		}
		reencode := func(newText string) []byte {
			delta["text"] = mustMarshal(newText)
			env["delta"] = mustMarshal(delta)
			return mustMarshal(env)
		}
		return Event{Text: text, Kind: EvDelta, Reencode: reencode}, true
	default:
		return Event{Kind: EvOther}, true
	}
}

type openAIChatDelta struct{}

func (openAIChatDelta) Event(payload []byte) (Event, bool) {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(payload, &env); err != nil {
		return Event{}, false
	}
	var choices []json.RawMessage
	if err := json.Unmarshal(env["choices"], &choices); err != nil || len(choices) == 0 {
		return Event{Kind: EvOther}, true
	}
	var choice map[string]json.RawMessage
	if err := json.Unmarshal(choices[0], &choice); err != nil {
		return Event{Kind: EvOther}, true
	}
	var delta map[string]json.RawMessage
	if err := json.Unmarshal(choice["delta"], &delta); err != nil {
		return Event{Kind: EvOther}, true
	}
	raw, ok := delta["content"]
	if !ok || len(raw) == 0 || raw[0] != '"' {
		return Event{Kind: EvOther}, true
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		//coverage:ignore reason=raw is a validated JSON string token; unmarshal to string cannot fail.
		return Event{Kind: EvOther}, true
	}
	reencode := func(newText string) []byte {
		delta["content"] = mustMarshal(newText)
		choice["delta"] = mustMarshal(delta)
		choices[0] = mustMarshal(choice)
		env["choices"] = mustMarshal(choices)
		return mustMarshal(env)
	}
	return Event{Text: text, Kind: EvDelta, Reencode: reencode}, true
}

type openAIResponsesDelta struct{}

func (openAIResponsesDelta) Event(payload []byte) (Event, bool) {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(payload, &env); err != nil {
		return Event{}, false
	}
	typ := ""
	if t, ok := env["type"]; ok {
		_ = json.Unmarshal(t, &typ)
	}
	switch typ {
	case "response.output_text.done":
		return Event{Kind: EvBlockStop}, true
	case "response.completed":
		return Event{Kind: EvDone}, true
	case "response.output_text.delta":
		raw, ok := env["delta"]
		if !ok || len(raw) == 0 || raw[0] != '"' {
			return Event{Kind: EvOther}, true
		}
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			//coverage:ignore reason=raw is a validated JSON string token; unmarshal to string cannot fail.
			return Event{Kind: EvOther}, true
		}
		reencode := func(newText string) []byte {
			env["delta"] = mustMarshal(newText)
			return mustMarshal(env)
		}
		return Event{Text: text, Kind: EvDelta, Reencode: reencode}, true
	default:
		return Event{Kind: EvOther}, true
	}
}
