package redact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/outgate-ai/og-local/internal/pii"
	"github.com/outgate-ai/og-local/internal/provider"
	"github.com/outgate-ai/og-local/internal/storage"
)

type Pipeline struct {
	detector    pii.Detector
	cache       storage.Store[[]pii.Span]
	newRedactor func() (*pii.Redactor, error)
}

func New(detector pii.Detector, cache storage.Store[[]pii.Span]) *Pipeline {
	return &Pipeline{
		detector:    detector,
		cache:       cache,
		newRedactor: pii.NewRedactor,
	}
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
	for _, ref := range refs {
		spans, err := p.detect(ctx, ref.Text)
		if err != nil {
			return nil, nil, err
		}
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
	return out, merged, nil
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
