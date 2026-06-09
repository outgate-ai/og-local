package redact

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/outgate-ai/og-local/internal/pii"
	"github.com/outgate-ai/og-local/internal/provider"
	"github.com/outgate-ai/og-local/internal/storage/memory"
)

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
	p := New(det, newCache(t))
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
	p := New(det, newCache(t))
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
	p := New(det, newCache(t))
	// Same content in two messages → detector should run once for that text.
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
	p := New(det, newCache(t))
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
	p := New(det, newCache(t))
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
	p := New(det, newCache(t))
	body := []byte(`{"model":"claude","messages":[{"role":"user","content":"email alice@example.com"}]}`)
	ep := provider.Route("POST", "/v1/messages")
	if _, _, err := p.Redact(context.Background(), ep, body); err == nil {
		t.Error("expected detector error to propagate")
	}
}

func TestRedactInvalidBody(t *testing.T) {
	p := New(&fakeDetector{}, newCache(t))
	ep := provider.Route("POST", "/v1/messages")
	if _, _, err := p.Redact(context.Background(), ep, []byte(`{bad json`)); err == nil {
		t.Error("expected error on invalid body")
	}
}

func TestRedactNoCache(t *testing.T) {
	usr := "email alice@example.com"
	det := &fakeDetector{spansFor: map[string][]pii.Span{
		usr: {spanOf(usr, "alice@example.com", pii.ClassEmail)},
	}}
	p := New(det, nil)
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
