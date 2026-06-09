package proxy

import (
	"strings"

	"github.com/outgate-ai/og-local/internal/token"
)

const keyPathPrefix = "/_k/"

type verifier interface {
	VerifySignature(tok string) (token.Claims, error)
}

// splitKeyPath splits a "/_k/<token>/rest" path into the token and the
// remaining request path.
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
