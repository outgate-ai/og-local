package proxy

import (
	"net/http"
	"strings"

	"github.com/outgate-ai/og-local/internal/token"
)

type verifier interface {
	VerifySignature(tok string) (token.Claims, error)
}

func bearerToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if v, ok := strings.CutPrefix(h, "Bearer "); ok {
			return strings.TrimSpace(v)
		}
	}
	if h := r.Header.Get("x-api-key"); h != "" {
		return strings.TrimSpace(h)
	}
	return ""
}

func (h *Handler) authorized(r *http.Request) bool {
	tok := bearerToken(r)
	if tok == "" {
		return false
	}
	_, err := h.minter.VerifySignature(tok)
	return err == nil
}
