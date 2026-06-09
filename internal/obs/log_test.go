package obs

import (
	"bytes"
	"strings"
	"testing"
)

func TestDiscardWritesNothing(t *testing.T) {
	l := Discard()
	l.Debug("should not appear", "k", "v")
	l.Info("nor this")
	// No panic, no output target to assert — the contract is simply that it is
	// safe to call and produces no output. A nil-safe smoke test.
}

func TestDebugWritesAtDebugLevel(t *testing.T) {
	var buf bytes.Buffer
	l := Debug(&buf)
	l.Debug("hello", "answer", 42)
	out := buf.String()
	if !strings.Contains(out, "hello") || !strings.Contains(out, "answer=42") {
		t.Errorf("debug record missing: %q", out)
	}
	if !strings.Contains(out, "level=DEBUG") {
		t.Errorf("expected DEBUG level: %q", out)
	}
}

func TestOrDiscardNil(t *testing.T) {
	if OrDiscard(nil) == nil {
		t.Error("OrDiscard(nil) must return a usable logger")
	}
	l := Debug(&bytes.Buffer{})
	if OrDiscard(l) != l {
		t.Error("OrDiscard must return the provided logger unchanged")
	}
}
