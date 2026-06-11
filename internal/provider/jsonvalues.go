package provider

import (
	"encoding/json"
	"errors"
)

const maxWalkDepth = 1000

var errWalkTooDeep = errors.New("provider: json nesting exceeds depth limit")

// extractJSONStringValues emits one FieldRef per JSON string value in raw,
// recursing through objects and arrays. Keys and non-string scalars are left
// untouched. A nil rebuild means no refs were produced and the caller keeps
// the original bytes.
func extractJSONStringValues(raw json.RawMessage) ([]FieldRef, func() json.RawMessage, error) {
	return walkJSONValue(raw, 0)
}

func walkJSONValue(raw json.RawMessage, depth int) ([]FieldRef, func() json.RawMessage, error) {
	if depth > maxWalkDepth {
		return nil, nil, errWalkTooDeep
	}
	if len(raw) == 0 {
		return nil, nil, nil
	}
	switch raw[0] {
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			//coverage:ignore reason=raw is a validated JSON string token; unmarshal to string cannot fail.
			return nil, nil, err
		}
		if s == "" {
			return nil, nil, nil
		}
		val := s
		ref := FieldRef{Text: s, set: func(r string) { val = r }}
		return []FieldRef{ref}, func() json.RawMessage { return mustMarshal(val) }, nil
	case '{':
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			//coverage:ignore reason=raw is a validated JSON object token; unmarshal to map cannot fail.
			return nil, nil, err
		}
		var refs []FieldRef
		rebuilds := make(map[string]func() json.RawMessage)
		for k, v := range obj {
			r, rb, err := walkJSONValue(v, depth+1)
			if err != nil {
				return nil, nil, err
			}
			if rb == nil {
				continue
			}
			refs = append(refs, r...)
			rebuilds[k] = rb
		}
		if len(rebuilds) == 0 {
			return nil, nil, nil
		}
		rebuild := func() json.RawMessage {
			for k, rb := range rebuilds {
				obj[k] = rb()
			}
			return mustMarshal(obj)
		}
		return refs, rebuild, nil
	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			//coverage:ignore reason=raw is a validated JSON array token; unmarshal to []RawMessage cannot fail.
			return nil, nil, err
		}
		var refs []FieldRef
		rebuilds := make(map[int]func() json.RawMessage)
		for i, v := range items {
			r, rb, err := walkJSONValue(v, depth+1)
			if err != nil {
				return nil, nil, err
			}
			if rb == nil {
				continue
			}
			refs = append(refs, r...)
			rebuilds[i] = rb
		}
		if len(rebuilds) == 0 {
			return nil, nil, nil
		}
		rebuild := func() json.RawMessage {
			for i, rb := range rebuilds {
				items[i] = rb()
			}
			return mustMarshal(items)
		}
		return refs, rebuild, nil
	default:
		return nil, nil, nil
	}
}

// extractArguments handles a tool-call arguments value: the spec form is a
// JSON-encoded string holding a JSON document, but OpenAI-compatible clients
// also send bare objects.
func extractArguments(raw json.RawMessage) ([]FieldRef, func() json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil, nil
	}
	if raw[0] == '"' {
		return extractEncodedJSONString(raw)
	}
	return extractJSONStringValues(raw)
}

// extractEncodedJSONString extracts string values from a JSON string token
// whose content is itself a JSON document. Content that is not valid JSON
// falls back to a single FieldRef over the decoded string.
func extractEncodedJSONString(raw json.RawMessage) ([]FieldRef, func() json.RawMessage, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		//coverage:ignore reason=raw is a validated JSON string token; unmarshal to string cannot fail.
		return nil, nil, err
	}
	if s == "" {
		return nil, nil, nil
	}
	if inner := json.RawMessage(s); json.Valid(inner) {
		refs, rebuild, err := extractJSONStringValues(inner)
		if err != nil || rebuild == nil {
			return nil, nil, err
		}
		return refs, func() json.RawMessage { return mustMarshal(string(rebuild())) }, nil
	}
	val := s
	ref := FieldRef{Text: s, set: func(r string) { val = r }}
	return []FieldRef{ref}, func() json.RawMessage { return mustMarshal(val) }, nil
}
