package provider

import "encoding/json"

func openAIChatExtract(body []byte) ([]FieldRef, func() ([]byte, error), error) {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, nil, err
	}

	var msgs []json.RawMessage
	if raw, ok := env["messages"]; ok {
		if err := json.Unmarshal(raw, &msgs); err != nil {
			return nil, nil, err
		}
	}

	var refs []FieldRef
	msgRebuilds := make([]func() json.RawMessage, len(msgs))
	for i := range msgs {
		var msg map[string]json.RawMessage
		if err := json.Unmarshal(msgs[i], &msg); err != nil {
			return nil, nil, err
		}
		cRefs, cRebuild, err := extractContentField(msg["content"])
		if err != nil {
			return nil, nil, err
		}
		tcRefs, tcRebuild, err := extractToolCalls(msg["tool_calls"])
		if err != nil {
			return nil, nil, err
		}
		fcRefs, fcRebuild, err := extractFunctionCall(msg["function_call"])
		if err != nil {
			return nil, nil, err
		}
		idx := i
		if cRebuild == nil && tcRebuild == nil && fcRebuild == nil {
			msgRebuilds[idx] = func() json.RawMessage { return msgs[idx] }
			continue
		}
		refs = append(refs, cRefs...)
		refs = append(refs, tcRefs...)
		refs = append(refs, fcRefs...)
		msgRebuilds[idx] = func() json.RawMessage {
			if cRebuild != nil {
				msg["content"] = cRebuild()
			}
			if tcRebuild != nil {
				msg["tool_calls"] = tcRebuild()
			}
			if fcRebuild != nil {
				msg["function_call"] = fcRebuild()
			}
			return mustMarshal(msg)
		}
	}

	reassemble := func() ([]byte, error) {
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

func extractToolCalls(raw json.RawMessage) ([]FieldRef, func() json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil, nil
	}
	var calls []json.RawMessage
	if err := json.Unmarshal(raw, &calls); err != nil {
		return nil, nil, err
	}
	var refs []FieldRef
	rebuilds := make(map[int]func() json.RawMessage)
	for i := range calls {
		var call map[string]json.RawMessage
		if err := json.Unmarshal(calls[i], &call); err != nil {
			return nil, nil, err
		}
		fRefs, fRebuild, err := extractFunctionCall(call["function"])
		if err != nil {
			return nil, nil, err
		}
		if fRebuild == nil {
			continue
		}
		refs = append(refs, fRefs...)
		rebuilds[i] = func() json.RawMessage {
			call["function"] = fRebuild()
			return mustMarshal(call)
		}
	}
	if len(rebuilds) == 0 {
		return nil, nil, nil
	}
	rebuild := func() json.RawMessage {
		for i, rb := range rebuilds {
			calls[i] = rb()
		}
		return mustMarshal(calls)
	}
	return refs, rebuild, nil
}

func extractFunctionCall(raw json.RawMessage) ([]FieldRef, func() json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil, nil
	}
	var fn map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fn); err != nil {
		return nil, nil, err
	}
	refs, rebuild, err := extractArguments(fn["arguments"])
	if err != nil || rebuild == nil {
		return nil, nil, err
	}
	return refs, func() json.RawMessage {
		fn["arguments"] = rebuild()
		return mustMarshal(fn)
	}, nil
}
