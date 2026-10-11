package mask

import (
	"encoding/json"
	"strconv"
	"strings"
)

// structural keys carry protocol data, never user content: they are not scanned
// on the way out. Everything else that is a string is.
var structural = map[string]bool{
	"kind": true, "type": true, "subkind": true, "status": true, "state": true, "role": true,
	"by": true, "reason": true, "error_code": true, "code": true, "tool": true, "tool_name": true,
	"action": true, "mode": true, "event": true, "outcome": true, "choice": true, "treatment": true,
	"class": true, "category": true, "version": true, "client_version": true, "protocol_version": true,
	"capabilities_rev": true, "sha256": true, "bytes": true, "mime": true, "mime_type": true,
	"content_type": true, "contentType": true, "model": true, "effort": true, "id": true, "seq": true,
	"ts": true, "client_ts": true, "at": true, "created_at": true, "updated_at": true, "expires_at": true,
	"expiresAt": true, "createdAt": true, "since": true, "until": true, "limit": true, "wait": true,
	"package": true, "app": true, "apps": true, "screen_id": true, "ref": true, "priority": true,
	"driving": true, "control_state": true, "permission": true, "decision": true, "scope": true,
	"region": true, "regionId": true, "threadId": true, "commandId": true, "claimId": true,
	"participant": true, "agentConfigId": true, "projectId": true, "workspaceId": true, "tool_use_id": true,
}

func isStructural(key string) bool {
	return structural[key] || strings.HasSuffix(key, "_id") || strings.HasSuffix(key, "_ids") ||
		(strings.HasSuffix(key, "Id") && len(key) > 2)
}

// field is one string inside a JSON document.
type field struct {
	path string
	text string
	set  func(string)
}

// walkStrings visits every string value of v (not keys). skipStructural leaves
// strings under structural keys out.
func walkStrings(v any, path string, skipStructural bool, visit func(f field)) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			if skipStructural && isStructural(k) {
				continue
			}
			p := path + "." + k
			if s, ok := child.(string); ok {
				m, key := x, k
				visit(field{path: p, text: s, set: func(n string) { m[key] = n }})
				continue
			}
			walkStrings(child, p, skipStructural, visit)
		}
	case []any:
		for i, child := range x {
			p := path + "[" + strconv.Itoa(i) + "]"
			if s, ok := child.(string); ok {
				arr, idx := x, i
				visit(field{path: p, text: s, set: func(n string) { arr[idx] = n }})
				continue
			}
			walkStrings(child, p, skipStructural, visit)
		}
	}
}

func decodeJSON(b []byte) (any, error) {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

func encodeJSON(v any) ([]byte, error) {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return []byte(strings.TrimSuffix(b.String(), "\n")), nil
}
