package provider

import "encoding/json"

var responsesTextTypes = map[string]bool{"input_text": true, "output_text": true}

func openAIResponsesExtract(body []byte) ([]FieldRef, func() ([]byte, error), error) {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, nil, err
	}

	var refs []FieldRef

	insRefs, insRebuild, err := extractContentFieldTypes(env["instructions"], responsesTextTypes)
	if err != nil {
		return nil, nil, err
	}
	refs = append(refs, insRefs...)

	inputRefs, inputRebuild, err := extractInput(env["input"])
	if err != nil {
		return nil, nil, err
	}
	refs = append(refs, inputRefs...)

	reassemble := func() ([]byte, error) {
		if insRebuild != nil {
			env["instructions"] = insRebuild()
		}
		if inputRebuild != nil {
			env["input"] = inputRebuild()
		}
		return mustMarshal(env), nil
	}

	return refs, reassemble, nil
}

func extractInput(raw json.RawMessage) ([]FieldRef, func() json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil, nil
	}
	if raw[0] != '[' {
		return extractContentFieldTypes(raw, responsesTextTypes)
	}

	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		//coverage:ignore reason=raw is a validated JSON array token; unmarshal to []RawMessage cannot fail.
		return nil, nil, err
	}
	var refs []FieldRef
	rebuilds := make([]func() json.RawMessage, len(items))
	for i := range items {
		var item map[string]json.RawMessage
		if err := json.Unmarshal(items[i], &item); err != nil {
			return nil, nil, err
		}
		key, extract := responsesItemField(item)
		cRefs, cRebuild, err := extract(item[key])
		if err != nil {
			return nil, nil, err
		}
		idx := i
		if cRebuild == nil {
			rebuilds[idx] = func() json.RawMessage { return items[idx] }
			continue
		}
		refs = append(refs, cRefs...)
		rebuilds[idx] = func() json.RawMessage {
			item[key] = cRebuild()
			return mustMarshal(item)
		}
	}
	rebuild := func() json.RawMessage {
		out := make([]json.RawMessage, len(rebuilds))
		for i, rb := range rebuilds {
			out[i] = rb()
		}
		return mustMarshal(out)
	}
	return refs, rebuild, nil
}

type fieldExtractor func(json.RawMessage) ([]FieldRef, func() json.RawMessage, error)

// responsesItemField picks which field of an input item holds user-supplied
// text. reasoning items stay untouched: their encrypted_content is
// integrity-checked upstream.
func responsesItemField(item map[string]json.RawMessage) (key string, extract fieldExtractor) {
	typ := ""
	if t, ok := item["type"]; ok {
		_ = json.Unmarshal(t, &typ)
	}
	contentTypes := func(raw json.RawMessage) ([]FieldRef, func() json.RawMessage, error) {
		return extractContentFieldTypes(raw, responsesTextTypes)
	}
	switch typ {
	case "function_call":
		return "arguments", extractArguments
	case "custom_tool_call":
		return "input", contentTypes
	case "function_call_output", "custom_tool_call_output":
		return "output", contentTypes
	default:
		return "content", contentTypes
	}
}
