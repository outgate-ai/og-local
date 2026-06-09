package proxy

import (
	"strings"

	"github.com/outgate-ai/og-local/internal/token"
)

const keyPathPrefix = "/_k/"

type verifier interface {
	VerifySignature(tok string) (token.Claims, error)
}

// splitKeyPath pulls the loopback token out of a "/_k/<token>/rest" path,
// returning the token and the remaining request path. The agent is handed a
// base URL ending in /_k/<token>, so every request it makes carries the token
// in the path while its own provider credential rides the headers untouched.
func splitKeyPath(path string) (tok, rest string, ok bool) {
	if !strings.HasPrefix(path, keyPathPrefix) {
		return "", "", false
	}
	after := path[len(keyPathPrefix):]
	slash := strings.IndexByte(after, '/')
	if slash < 0 {
		return after, "/", true
	}
	return after[:slash], after[slash:], true
}

func (h *Handler) authorize(path string) (rest string, ok bool) {
	tok, rest, ok := splitKeyPath(path)
	if !ok {
		return "", false
	}
	if _, err := h.minter.VerifySignature(tok); err != nil {
		return "", false
	}
	return rest, true
}
