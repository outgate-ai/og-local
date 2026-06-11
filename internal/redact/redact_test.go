package redact

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/outgate-ai/og-local/internal/obs"
	"github.com/outgate-ai/og-local/internal/pii"
	"github.com/outgate-ai/og-local/internal/provider"
	"github.com/outgate-ai/og-local/internal/storage"
	"github.com/outgate-ai/og-local/internal/storage/memory"
	"github.com/outgate-ai/og-local/internal/testutil/fakeclock"
)

func newPipeline(t *testing.T, det pii.Detector, cache storage.Store[[]pii.Span], opts ...Option) *Pipeline {
	t.Helper()
	p, err := New(det, cache, opts...)
	if err != nil {
		t.Fatalf("pipeline: %v", err)
	}
	return p
}

func anthropicBody(t *testing.T, content string) []byte {
	t.Helper()
	c, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("marshal content: %v", err)
	}
	return []byte(`{"model":"claude","messages":[{"role":"user","content":` + string(c) + `}]}`)
}

type fakeDetector struct {
	spansFor map[string][]pii.Span
	calls    []string
	err      error
}

func (f *fakeDetector) Detect(_ context.Context, text string) ([]pii.Span, error) {
	f.calls = append(f.calls, text)
	if f.err != nil {
		return nil, f.err
	}
	return f.spansFor[text], nil
}

func spanOf(text, sub string, class pii.Class) pii.Span {
	i := strings.Index(text, sub)
	return pii.Span{Start: i, End: i + len(sub), Class: class}
}

func newCache(t *testing.T) *memory.Store[[]pii.Span] {
	t.Helper()
	c, err := memory.New[[]pii.Span](128)
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	return c
}

func TestRedactPerFieldIndependentDetection(t *testing.T) {
	usr := "email alice@example.com"
	det := &fakeDetector{spansFor: map[string][]pii.Span{
		usr: {spanOf(usr, "alice@example.com", pii.ClassEmail)},
	}}
	p := newPipeline(t, det, newCache(t))
	body := []byte(`{"model":"claude","system":"system says hi","messages":[{"role":"user","content":"email alice@example.com"}]}`)
	ep := provider.Route("POST", "/v1/messages")

	out, m, err := p.Redact(context.Background(), ep, body)
	if err != nil {
		t.Fatalf("redact: %v", err)
	}
	if len(det.calls) != 2 {
		t.Fatalf("expected 2 detect calls (one per field), got %d: %v", len(det.calls), det.calls)
	}
	if strings.Contains(string(out), "alice@example.com") {
		t.Errorf("email survived redaction: %s", out)
	}
	if !strings.Contains(string(out), "OG_PRIVATE_EMAIL_") {
		t.Errorf("no placeholder in output: %s", out)
	}
	if len(m) != 1 || m[0].From != "alice@example.com" {
		t.Fatalf("mapping = %+v", m)
	}
	if restored := m.Restore(string(out)); !strings.Contains(restored, "alice@example.com") {
		t.Errorf("restore failed: %s", restored)
	}
	if !strings.Contains(string(out), `"model":"claude"`) {
		t.Errorf("frame field changed: %s", out)
	}
}

func TestRedactModelNeverDetected(t *testing.T) {
	det := &fakeDetector{spansFor: map[string][]pii.Span{}}
	p := newPipeline(t, det, newCache(t))
	body := []byte(`{"model":"secret-model-x","messages":[{"role":"user","content":"hi"}]}`)
	ep := provider.Route("POST", "/v1/chat/completions")
	if _, _, err := p.Redact(context.Background(), ep, body); err != nil {
		t.Fatalf("redact: %v", err)
	}
	for _, c := range det.calls {
		if strings.Contains(c, "secret-model-x") {
			t.Errorf("model value reached detector: %q", c)
		}
	}
}

func TestRedactCacheHitOnRepeatedField(t *testing.T) {
	text := "repeated alice@example.com here"
	det := &fakeDetector{spansFor: map[string][]pii.Span{
		text: {spanOf(text, "alice@example.com", pii.ClassEmail)},
	}}
	p := newPipeline(t, det, newCache(t))
	body := []byte(`{"model":"claude","messages":[{"role":"user","content":"repeated alice@example.com here"},{"role":"user","content":"repeated alice@example.com here"}]}`)
	ep := provider.Route("POST", "/v1/messages")
	if _, m, err := p.Redact(context.Background(), ep, body); err != nil {
		t.Fatalf("redact: %v", err)
	} else if len(m) != 1 {
		t.Fatalf("expected 1 merged pair, got %+v", m)
	}
	n := 0
	for _, c := range det.calls {
		if c == text {
			n++
		}
	}
	if n != 1 {
		t.Errorf("expected detector called once for repeated text, got %d", n)
	}
}

func TestRedactCrossFieldPlaceholderConsistency(t *testing.T) {
	a := "from alice@example.com"
	b := "reply alice@example.com"
	det := &fakeDetector{spansFor: map[string][]pii.Span{
		a: {spanOf(a, "alice@example.com", pii.ClassEmail)},
		b: {spanOf(b, "alice@example.com", pii.ClassEmail)},
	}}
	p := newPipeline(t, det, newCache(t))
	body := []byte(`{"model":"claude","messages":[{"role":"user","content":"from alice@example.com"},{"role":"assistant","content":"reply alice@example.com"}]}`)
	ep := provider.Route("POST", "/v1/messages")
	out, m, err := p.Redact(context.Background(), ep, body)
	if err != nil {
		t.Fatalf("redact: %v", err)
	}
	if len(m) != 1 {
		t.Fatalf("same value in two fields must merge to one pair, got %+v", m)
	}
	if c := strings.Count(string(out), m[0].To); c != 2 {
		t.Errorf("expected same placeholder twice, got %d in %s", c, out)
	}
}

func TestRedactPassthroughNoFields(t *testing.T) {
	det := &fakeDetector{}
	p := newPipeline(t, det, newCache(t))
	body := []byte(`{"whatever":true}`)
	ep := provider.Route("GET", "/v1/models")
	out, m, err := p.Redact(context.Background(), ep, body)
	if err != nil {
		t.Fatalf("redact: %v", err)
	}
	if m != nil {
		t.Errorf("passthrough should have nil mapping, got %+v", m)
	}
	if !bytes.Equal(out, body) {
		t.Errorf("passthrough changed body: %s", out)
	}
	if len(det.calls) != 0 {
		t.Errorf("passthrough should not detect, got %v", det.calls)
	}
}

func TestRedactDetectorError(t *testing.T) {
	det := &fakeDetector{err: errors.New("boom"), spansFor: map[string][]pii.Span{}}
	p := newPipeline(t, det, newCache(t))
	body := []byte(`{"model":"claude","messages":[{"role":"user","content":"email alice@example.com"}]}`)
	ep := provider.Route("POST", "/v1/messages")
	if _, _, err := p.Redact(context.Background(), ep, body); err == nil {
		t.Error("expected detector error to propagate")
	}
}

func TestRedactInvalidBody(t *testing.T) {
	p := newPipeline(t, &fakeDetector{}, newCache(t))
	ep := provider.Route("POST", "/v1/messages")
	if _, _, err := p.Redact(context.Background(), ep, []byte(`{bad json`)); err == nil {
		t.Error("expected error on invalid body")
	}
}

func TestRedactDebugLogsNeverLeakPII(t *testing.T) {
	const secret = "alice@example.com"
	usr := "email " + secret
	det := &fakeDetector{spansFor: map[string][]pii.Span{
		usr: {spanOf(usr, secret, pii.ClassEmail)},
	}}
	var buf bytes.Buffer
	p := newPipeline(t, det, newCache(t), WithLogger(obs.Debug(&buf)))
	body := []byte(`{"model":"claude","messages":[{"role":"user","content":"email alice@example.com"}]}`)
	ep := provider.Route("POST", "/v1/messages")
	_, m, err := p.Redact(context.Background(), ep, body)
	if err != nil {
		t.Fatalf("redact: %v", err)
	}

	logged := buf.String()
	if logged == "" {
		t.Fatal("expected debug output")
	}
	if strings.Contains(logged, secret) {
		t.Errorf("debug log leaked the original PII value: %s", logged)
	}
	if !strings.Contains(logged, string(pii.ClassEmail)) {
		t.Errorf("debug log missing span class: %s", logged)
	}
	if len(m) == 1 && !strings.Contains(logged, m[0].To) {
		t.Errorf("debug log missing placeholder %q: %s", m[0].To, logged)
	}
}

type clockDetector struct {
	clk   *fakeclock.Clock
	step  time.Duration
	spans map[string][]pii.Span
	calls int
}

func (d *clockDetector) Detect(_ context.Context, text string) ([]pii.Span, error) {
	d.calls++
	d.clk.Advance(d.step) // simulate the OPF inference taking d.step
	return d.spans[text], nil
}

func TestRedactDebugLogsOPFLatencyAndCacheSize(t *testing.T) {
	usr := "email " + "alice@example.com"
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	det := &clockDetector{
		clk:   clk,
		step:  42 * time.Millisecond,
		spans: map[string][]pii.Span{usr: {spanOf(usr, "alice@example.com", pii.ClassEmail)}},
	}
	var buf bytes.Buffer
	p := newPipeline(t, det, newCache(t), WithLogger(obs.Debug(&buf)), withClock(clk.Now))
	body := []byte(`{"model":"claude","messages":[{"role":"user","content":"email alice@example.com"}]}`)
	ep := provider.Route("POST", "/v1/messages")

	if _, _, err := p.Redact(context.Background(), ep, body); err != nil {
		t.Fatalf("redact: %v", err)
	}
	out := buf.String()
	if det.calls != 1 {
		t.Fatalf("expected 1 OPF call, got %d", det.calls)
	}
	if !strings.Contains(out, "cached=false") || !strings.Contains(out, "dur=42ms") {
		t.Errorf("missing OPF latency line: %s", out)
	}
	if !strings.Contains(out, "cache_size=1") {
		t.Errorf("missing cache_size after miss: %s", out)
	}
}

func TestRedactDebugCacheHitLogsNoInference(t *testing.T) {
	a := "from alice@example.com"
	b := "from alice@example.com"
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	det := &clockDetector{
		clk:   clk,
		step:  10 * time.Millisecond,
		spans: map[string][]pii.Span{a: {spanOf(a, "alice@example.com", pii.ClassEmail)}},
	}
	var buf bytes.Buffer
	p := newPipeline(t, det, newCache(t), WithLogger(obs.Debug(&buf)), withClock(clk.Now))
	body := []byte(`{"model":"claude","messages":[{"role":"user","content":"` + a + `"},{"role":"user","content":"` + b + `"}]}`)
	if _, _, err := p.Redact(context.Background(), provider.Route("POST", "/v1/messages"), body); err != nil {
		t.Fatalf("redact: %v", err)
	}
	if det.calls != 1 {
		t.Errorf("identical fields must hit cache; OPF calls = %d, want 1", det.calls)
	}
	out := buf.String()
	if !strings.Contains(out, "cached=true") {
		t.Errorf("expected a cache-hit line: %s", out)
	}
}

func TestRedactWithLoggerNilIsSafe(t *testing.T) {
	det := &fakeDetector{spansFor: map[string][]pii.Span{}}
	p := newPipeline(t, det, newCache(t), WithLogger(nil))
	body := []byte(`{"model":"claude","messages":[{"role":"user","content":"hi"}]}`)
	if _, _, err := p.Redact(context.Background(), provider.Route("POST", "/v1/messages"), body); err != nil {
		t.Fatalf("nil logger must be safe: %v", err)
	}
}

func TestRedactChunkedFieldSpansAtFieldOffsets(t *testing.T) {
	text := strings.Repeat("a", 10) + "\n" + "bob@x.io 12345\n" + strings.Repeat("c", 10)
	mid := "bob@x.io 12345\n"
	det := &fakeDetector{spansFor: map[string][]pii.Span{
		mid: {spanOf(mid, "bob@x.io", pii.ClassEmail)},
	}}
	p := newPipeline(t, det, newCache(t), withChunking(16, 4))
	ep := provider.Route("POST", "/v1/messages")

	out, m, err := p.Redact(context.Background(), ep, anthropicBody(t, text))
	if err != nil {
		t.Fatalf("redact: %v", err)
	}
	if len(det.calls) != 3 {
		t.Fatalf("expected one detect call per chunk, got %d: %q", len(det.calls), det.calls)
	}
	if len(m) != 1 || m[0].From != "bob@x.io" {
		t.Fatalf("mapping = %+v", m)
	}
	if strings.Contains(string(out), "bob@x.io") {
		t.Errorf("value survived: %s", out)
	}
	if !strings.Contains(string(out), strings.Repeat("a", 10)) || !strings.Contains(string(out), "12345") {
		t.Errorf("non-PII chunk text mangled: %s", out)
	}
}

func TestRedactAppendOnlyReusesChunks(t *testing.T) {
	base := strings.Repeat("a", 10) + "\n" + "bob@x.io 12345\n" + strings.Repeat("c", 10)
	det := &fakeDetector{spansFor: map[string][]pii.Span{}}
	p := newPipeline(t, det, newCache(t), withChunking(16, 4))
	ep := provider.Route("POST", "/v1/messages")

	if _, _, err := p.Redact(context.Background(), ep, anthropicBody(t, base)); err != nil {
		t.Fatalf("first redact: %v", err)
	}
	first := len(det.calls)
	if _, _, err := p.Redact(context.Background(), ep, anthropicBody(t, base+"XY")); err != nil {
		t.Fatalf("second redact: %v", err)
	}
	added := det.calls[first:]
	if len(added) != 1 || added[0] != strings.Repeat("c", 10)+"XY" {
		t.Errorf("append must re-detect only the final chunk, got %q", added)
	}
}

func TestRedactHardCutTruncationRedetected(t *testing.T) {
	text := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"
	chunk0, chunk1 := text[0:16], text[12:28]
	det := &fakeDetector{spansFor: map[string][]pii.Span{
		chunk0: {{Start: 13, End: 16, Class: pii.ClassSecret}}, // "nop" truncated at the cut
		chunk1: {{Start: 1, End: 4, Class: pii.ClassSecret}},   // "nop" whole inside the overlap
	}}
	p := newPipeline(t, det, newCache(t), withChunking(16, 4))
	ep := provider.Route("POST", "/v1/messages")

	_, m, err := p.Redact(context.Background(), ep, anthropicBody(t, text))
	if err != nil {
		t.Fatalf("redact: %v", err)
	}
	if len(m) != 1 || m[0].From != "nop" {
		t.Fatalf("expected the overlap re-detection to win once, got %+v", m)
	}
}

func TestRedactTinyFieldSkipsDetectorAndCache(t *testing.T) {
	det := &fakeDetector{spansFor: map[string][]pii.Span{}}
	cache := newCache(t)
	p := newPipeline(t, det, cache)
	if _, _, err := p.Redact(context.Background(), provider.Route("POST", "/v1/messages"), anthropicBody(t, "hi")); err != nil {
		t.Fatalf("redact: %v", err)
	}
	if len(det.calls) != 0 {
		t.Errorf("sub-minimum field reached detector: %q", det.calls)
	}
	if cache.Len() != 0 {
		t.Errorf("sub-minimum field cached: %d entries", cache.Len())
	}
}

func TestPlaceholderStableAcrossRequests(t *testing.T) {
	text := "email alice@example.com"
	det := &fakeDetector{spansFor: map[string][]pii.Span{
		text: {spanOf(text, "alice@example.com", pii.ClassEmail)},
	}}
	p := newPipeline(t, det, newCache(t))
	ep := provider.Route("POST", "/v1/messages")
	body := anthropicBody(t, text)

	_, m1, err := p.Redact(context.Background(), ep, body)
	if err != nil {
		t.Fatalf("first redact: %v", err)
	}
	_, m2, err := p.Redact(context.Background(), ep, body)
	if err != nil {
		t.Fatalf("second redact: %v", err)
	}
	if len(m1) != 1 || len(m2) != 1 || m1[0].To != m2[0].To {
		t.Errorf("placeholder must be stable across requests: %+v vs %+v", m1, m2)
	}

	p2 := newPipeline(t, det, newCache(t))
	_, m3, err := p2.Redact(context.Background(), ep, body)
	if err != nil {
		t.Fatalf("third redact: %v", err)
	}
	if len(m3) != 1 || m3[0].To == m1[0].To {
		t.Errorf("distinct pipelines must use distinct nonces: %+v vs %+v", m1, m3)
	}
}

func TestRedactNoCache(t *testing.T) {
	usr := "email alice@example.com"
	det := &fakeDetector{spansFor: map[string][]pii.Span{
		usr: {spanOf(usr, "alice@example.com", pii.ClassEmail)},
	}}
	p := newPipeline(t, det, nil)
	body := []byte(`{"model":"claude","messages":[{"role":"user","content":"email alice@example.com"}]}`)
	ep := provider.Route("POST", "/v1/messages")
	out, m, err := p.Redact(context.Background(), ep, body)
	if err != nil {
		t.Fatalf("redact: %v", err)
	}
	if len(m) != 1 || strings.Contains(string(out), "alice@example.com") {
		t.Errorf("nil-cache path failed: m=%+v out=%s", m, out)
	}
}
