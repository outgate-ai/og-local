package redact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"

	"github.com/outgate-ai/og-local/internal/obs"
	"github.com/outgate-ai/og-local/internal/pii"
	"github.com/outgate-ai/og-local/internal/provider"
	"github.com/outgate-ai/og-local/internal/storage"
)

type Pipeline struct {
	detector    pii.Detector
	cache       storage.Store[[]pii.Span]
	newRedactor func() (*pii.Redactor, error)
	log         *slog.Logger
}

type Option func(*Pipeline)

func WithLogger(l *slog.Logger) Option {
	return func(p *Pipeline) { p.log = obs.OrDiscard(l) }
}

func New(detector pii.Detector, cache storage.Store[[]pii.Span], opts ...Option) *Pipeline {
	p := &Pipeline{
		detector:    detector,
		cache:       cache,
		newRedactor: pii.NewRedactor,
		log:         obs.Discard(),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func (p *Pipeline) Redact(ctx context.Context, ep provider.Endpoint, body []byte) ([]byte, pii.Mapping, error) {
	refs, reassemble, err := ep.Fields(body)
	if err != nil {
		return nil, nil, err
	}
	if len(refs) == 0 {
		out, err := reassemble()
		return out, nil, err
	}

	red, err := p.newRedactor()
	if err != nil {
		//coverage:ignore reason=crypto/rand.Read does not fail on supported platforms.
		return nil, nil, err
	}

	merged := pii.Mapping{}
	seen := map[string]bool{}
	for i, ref := range refs {
		spans, err := p.detect(ctx, ref.Text)
		if err != nil {
			return nil, nil, err
		}
		p.log.Debug("field detected",
			"field", i, "field_len", len(ref.Text),
			"spans", len(spans), "classes", classesOf(spans))
		redacted, m := red.Apply(ref.Text, spans)
		ref.Set(redacted)
		for _, pair := range m {
			if seen[pair.From] {
				continue
			}
			seen[pair.From] = true
			merged = append(merged, pair)
		}
	}

	out, err := reassemble()
	if err != nil {
		//coverage:ignore reason=current provider reassemblers do not error; defensive propagation.
		return nil, nil, err
	}
	p.log.Debug("request redacted", "fields", len(refs), "placeholders", placeholdersOf(merged))
	return out, merged, nil
}

func classesOf(spans []pii.Span) []string {
	out := make([]string, len(spans))
	for i, s := range spans {
		out[i] = string(s.Class)
	}
	return out
}

func placeholdersOf(m pii.Mapping) []string {
	out := make([]string, len(m))
	for i, p := range m {
		out[i] = p.To
	}
	return out
}

func (p *Pipeline) detect(ctx context.Context, text string) ([]pii.Span, error) {
	key := hashText(text)
	if p.cache != nil {
		if spans, ok := p.cache.Get(key); ok {
			return spans, nil
		}
	}
	spans, err := p.detector.Detect(ctx, text)
	if err != nil {
		return nil, err
	}
	if p.cache != nil {
		p.cache.Put(key, spans)
	}
	return spans, nil
}

func hashText(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}
