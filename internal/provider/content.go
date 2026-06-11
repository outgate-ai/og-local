package provider

import "encoding/json"

var textTypeOnly = map[string]bool{"text": true}

// blockExtractor handles one content block of a registered type. A nil rebuild
// keeps the block's original bytes.
type blockExtractor func(block map[string]json.RawMessage) ([]FieldRef, func() json.RawMessage, error)

func extractContentField(raw json.RawMessage) ([]FieldRef, func() json.RawMessage, error) {
	return extractContentBlocks(raw, textTypeOnly, nil)
}

func extractContentFieldTypes(raw json.RawMessage, textTypes map[string]bool) ([]FieldRef, func() json.RawMessage, error) {
	return extractContentBlocks(raw, textTypes, nil)
}

func extractContentBlocks(raw json.RawMessage, textTypes map[string]bool, handlers map[string]blockExtractor) ([]FieldRef, func() json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil, nil
	}

	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			//coverage:ignore reason=raw is a validated JSON string token; unmarshal to string cannot fail.
			return nil, nil, err
		}
		val := s
		ref := FieldRef{Text: s, set: func(r string) { val = r }}
		rebuild := func() json.RawMessage { return mustMarshal(val) }
		return []FieldRef{ref}, rebuild, nil
	}

	if raw[0] == '[' {
		var blocks []json.RawMessage
		if err := json.Unmarshal(raw, &blocks); err != nil {
			//coverage:ignore reason=raw is a validated JSON array token; unmarshal to []RawMessage cannot fail.
			return nil, nil, err
		}
		var refs []FieldRef
		rebuilds := make([]func() json.RawMessage, len(blocks))
		for i := range blocks {
			var block map[string]json.RawMessage
			if err := json.Unmarshal(blocks[i], &block); err != nil {
				return nil, nil, err
			}
			idx := i
			typ := ""
			if t, ok := block["type"]; ok {
				_ = json.Unmarshal(t, &typ)
			}
			if h, ok := handlers[typ]; ok {
				hRefs, hRebuild, err := h(block)
				if err != nil {
					return nil, nil, err
				}
				if hRebuild == nil {
					rebuilds[idx] = func() json.RawMessage { return blocks[idx] }
					continue
				}
				refs = append(refs, hRefs...)
				rebuilds[idx] = hRebuild
				continue
			}
			if !textTypes[typ] {
				rebuilds[idx] = func() json.RawMessage { return blocks[idx] }
				continue
			}
			var text string
			if err := json.Unmarshal(block["text"], &text); err != nil {
				return nil, nil, err
			}
			val := text
			refs = append(refs, FieldRef{Text: text, set: func(r string) { val = r }})
			rebuilds[idx] = func() json.RawMessage {
				block["text"] = mustMarshal(val)
				return mustMarshal(block)
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

	return nil, nil, nil
}
