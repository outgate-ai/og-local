package provider

import "encoding/json"

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
		cRefs, cRebuild, err := extractContentField(msg["content"])
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
