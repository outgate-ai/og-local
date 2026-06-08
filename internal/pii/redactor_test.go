package pii

import (
	"strings"
	"testing"
)

func fixedRedactor() *Redactor { return newRedactor([]byte("test-nonce-1234")) }

func TestApplyRoundTrip(t *testing.T) {
	cases := []struct {
		text  string
		spans []Span
	}{
		{"email alice@x.com here", []Span{{6, 17, ClassEmail, 0.9}}},
		{"call +1-555-0100 now", []Span{{5, 16, ClassPhone, 0.9}}},
		{"no pii at all", nil},
		{"two alice@x.com and bob@y.com", []Span{{4, 15, ClassEmail, 0.9}, {20, 29, ClassEmail, 0.9}}},
	}
	r := fixedRedactor()
	for _, c := range cases {
		redacted, m := r.Apply(c.text, c.spans)
		if got := m.Restore(redacted); got != c.text {
			t.Errorf("round-trip failed: Apply then Restore = %q, want %q", got, c.text)
		}
	}
}

func TestApplyRedactsValue(t *testing.T) {
	r := fixedRedactor()
	redacted, m := r.Apply("email alice@x.com here", []Span{{6, 17, ClassEmail, 0.9}})
	if strings.Contains(redacted, "alice@x.com") {
		t.Errorf("original value leaked into redacted text: %q", redacted)
	}
	if len(m) != 1 || m[0].From != "alice@x.com" {
		t.Errorf("mapping = %+v, want one pair for alice@x.com", m)
	}
	if !strings.HasPrefix(m[0].To, "OG_PRIVATE_EMAIL_") {
		t.Errorf("placeholder %q lacks OG_PRIVATE_EMAIL_ prefix", m[0].To)
	}
}

func TestPlaceholderDeterministicPerNonce(t *testing.T) {
	r := fixedRedactor()
	a := r.placeholder(ClassEmail, "alice@x.com")
	b := r.placeholder(ClassEmail, "alice@x.com")
	if a != b {
		t.Errorf("same value gave different placeholders: %q vs %q", a, b)
	}
	if c := r.placeholder(ClassEmail, "bob@y.com"); c == a {
		t.Errorf("different values gave the same placeholder: %q", c)
	}
}

func TestApplyCollapsesRepeatedValue(t *testing.T) {
	r := fixedRedactor()
	text := "alice@x.com and alice@x.com"
	_, m := r.Apply(text, []Span{{0, 11, ClassEmail, 0.9}, {16, 27, ClassEmail, 0.9}})
	if len(m) != 1 {
		t.Errorf("mapping has %d entries, want 1 (repeated value should collapse)", len(m))
	}
}

func TestApplySkipsInvalidSpans(t *testing.T) {
	r := fixedRedactor()
	text := "short"
	_, m := r.Apply(text, []Span{
		{-1, 3, ClassEmail, 0}, // negative start
		{0, 99, ClassEmail, 0}, // end past len
		{3, 3, ClassEmail, 0},  // empty
		{4, 2, ClassEmail, 0},  // start >= end
	})
	if len(m) != 0 {
		t.Errorf("invalid spans produced mappings: %+v", m)
	}
}

func TestNewRedactorRandomNonce(t *testing.T) {
	a, err := NewRedactor()
	if err != nil {
		t.Fatalf("NewRedactor: %v", err)
	}
	b, err := NewRedactor()
	if err != nil {
		t.Fatalf("NewRedactor: %v", err)
	}
	if a.placeholder(ClassEmail, "x@y.com") == b.placeholder(ClassEmail, "x@y.com") {
		t.Error("two redactors produced the same placeholder; nonce not random")
	}
}
