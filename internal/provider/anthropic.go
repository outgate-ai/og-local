package provider

import "encoding/json"

// thinking/redacted_thinking blocks carry an upstream-verified signature and
// must pass through byte-identical; server_tool_use and web_search_tool_result
// are server-generated. Only client-supplied tool blocks are redacted.
var anthropicToolHandlers = map[string]blockExtractor{
	"tool_use":    extractToolUseBlock,
	"tool_result": extractToolResultBlock,
}

func extractToolUseBlock(block map[string]json.RawMessage) ([]FieldRef, func() json.RawMessage, error) {
	refs, rebuild, err := extractJSONStringValues(block["input"])
	if err != nil || rebuild == nil {
		return nil, nil, err
	}
	return refs, func() json.RawMessage {
		block["input"] = rebuild()
		return mustMarshal(block)
	}, nil
}

func extractToolResultBlock(block map[string]json.RawMessage) ([]FieldRef, func() json.RawMessage, error) {
	refs, rebuild, err := extractContentField(block["content"])
	if err != nil || rebuild == nil {
		return nil, nil, err
	}
	return refs, func() json.RawMessage {
		block["content"] = rebuild()
		return mustMarshal(block)
	}, nil
}

func anthropicExtract(body []byte) ([]FieldRef, func() ([]byte, error), error) {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, nil, err
	}

	var refs []FieldRef

	sysRefs, sysRebuild, err := extractContentField(env["system"])
	if err != nil {
		return nil, nil, err
	}
	refs = append(refs, sysRefs...)

	var msgs []json.RawMessage
	if raw, ok := env["messages"]; ok {
		if err := json.Unmarshal(raw, &msgs); err != nil {
			return nil, nil, err
		}
	}
	msgRebuilds := make([]func() json.RawMessage, len(msgs))
	for i := range msgs {
		var msg map[string]json.RawMessage
		if err := json.Unmarshal(msgs[i], &msg); err != nil {
			return nil, nil, err
		}
		cRefs, cRebuild, err := extractContentBlocks(msg["content"], textTypeOnly, anthropicToolHandlers)
		if err != nil {
			return nil, nil, err
		}
		idx := i
		if cRebuild == nil {
			msgRebuilds[idx] = func() json.RawMessage { return msgs[idx] }
			continue
		}
		refs = append(refs, cRefs...)
		msgRebuilds[idx] = func() json.RawMessage {
			msg["content"] = cRebuild()
			return mustMarshal(msg)
		}
	}

	reassemble := func() ([]byte, error) {
		if sysRebuild != nil {
			env["system"] = sysRebuild()
		}
		if msgs != nil {
			rebuilt := make([]json.RawMessage, len(msgRebuilds))
			for i, rb := range msgRebuilds {
				rebuilt[i] = rb()
			}
			env["messages"] = mustMarshal(rebuilt)
		}
		return mustMarshal(env), nil
	}

	return refs, reassemble, nil
}
