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
		cRefs, cRebuild, err := extractContentFieldTypes(item["content"], responsesTextTypes)
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
			item["content"] = cRebuild()
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
