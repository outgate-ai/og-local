package redact

import (
	"context"

	"github.com/outgate-ai/og-local/internal/pii"
)

// Spans runs detection over one free-standing text with the same chunking and
// span cache as Redact, for callers that build their own placeholders.
func (p *Pipeline) Spans(ctx context.Context, text string) ([]pii.Span, error) {
	return p.detect(ctx, text)
}
