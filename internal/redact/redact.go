package redact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/outgate-ai/og-local/internal/obs"
	"github.com/outgate-ai/og-local/internal/pii"
	"github.com/outgate-ai/og-local/internal/provider"
	"github.com/outgate-ai/og-local/internal/storage"
)

// chunkTarget bounds a single detector call. The model's sliding-window
// attention gives it a receptive field of roughly a thousand tokens, so a
// 4 KiB chunk loses no usable context while keeping inference memory and
// detector-mutex hold time flat. chunkOverlap is re-detected after hard
// (mid-run) cuts so spans truncated by the cut are seen whole.
const (
	chunkTarget  = 4096
	chunkOverlap = 512
)

type Pipeline struct {
	detector     pii.Detector
	cache        storage.Store[[]pii.Span]
	newRedactor  func() (*pii.Redactor, error)
	log          *slog.Logger
	now          func() time.Time
	chunkTarget  int
	chunkOverlap int
}

type Option func(*Pipeline)

func WithLogger(l *slog.Logger) Option {
	return func(p *Pipeline) { p.log = obs.OrDiscard(l) }
}

func withClock(now func() time.Time) Option {
	return func(p *Pipeline) { p.now = now }
}

func withChunking(target, overlap int) Option {
	return func(p *Pipeline) { p.chunkTarget, p.chunkOverlap = target, overlap }
}

func New(detector pii.Detector, cache storage.Store[[]pii.Span], opts ...Option) *Pipeline {
	p := &Pipeline{
		detector:     detector,
		cache:        cache,
		newRedactor:  pii.NewRedactor,
		log:          obs.Discard(),
		now:          time.Now,
		chunkTarget:  chunkTarget,
		chunkOverlap: chunkOverlap,
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
	if len(text) < pii.MinDetectionLen {
		return nil, nil
	}
	chunks := splitChunks(text, p.chunkTarget, p.chunkOverlap)
	perChunk := make([][]pii.Span, len(chunks))
	for i, c := range chunks {
		if len(c.text) < pii.MinDetectionLen {
			continue
		}
		spans, err := p.detectChunk(ctx, c.text)
		if err != nil {
			return nil, err
		}
		perChunk[i] = spans
	}
	return mergeSpans(chunks, perChunk), nil
}

// detectChunk caches raw chunk-relative detector output. Hard-cut edge
// filtering happens in mergeSpans, never before Put: the same chunk text can
// sit at a different position of another field.
func (p *Pipeline) detectChunk(ctx context.Context, text string) ([]pii.Span, error) {
	key := hashText(text)
	if p.cache != nil {
		if spans, ok := p.cache.Get(key); ok {
			p.log.Debug("detect", "cached", true, "field_len", len(text),
				"spans", len(spans), "cache_size", p.cacheLen())
			return spans, nil
		}
	}
	start := p.now()
	spans, err := p.detector.Detect(ctx, text)
	dur := p.now().Sub(start)
	if err != nil {
		p.log.Debug("detect failed", "field_len", len(text), "dur", dur, "err", err)
		return nil, err
	}
	if p.cache != nil {
		p.cache.Put(key, spans)
	}
	p.log.Debug("detect", "cached", false, "field_len", len(text),
		"spans", len(spans), "dur", dur, "cache_size", p.cacheLen())
	return spans, nil
}

func (p *Pipeline) cacheLen() int {
	if p.cache == nil {
		return 0
	}
	return p.cache.Len()
}

func hashText(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}
