package pii

import (
	"strings"
	"testing"
)

func TestSubstituteBasic(t *testing.T) {
	out, n := substitute("hello alice", []Pair{{From: "alice", To: "X"}})
	if out != "hello X" || n != 1 {
		t.Fatalf("got %q, %d; want \"hello X\", 1", out, n)
	}
}

func TestSubstituteAllOccurrences(t *testing.T) {
	out, n := substitute("a a a", []Pair{{From: "a", To: "b"}})
	if out != "b b b" || n != 3 {
		t.Fatalf("got %q, %d; want \"b b b\", 3", out, n)
	}
}

func TestSubstituteLongestFirst(t *testing.T) {
	// "abc" must be replaced before "ab" so the longer token isn't shadowed.
	out, _ := substitute("abc", []Pair{{From: "ab", To: "X"}, {From: "abc", To: "Y"}})
	if out != "Y" {
		t.Fatalf("got %q, want \"Y\" (longest-first)", out)
	}
}

func TestSubstitutePositionShift(t *testing.T) {
	out, n := substitute("aXa", []Pair{{From: "a", To: "LONG"}})
	if out != "LONGXLONG" || n != 2 {
		t.Fatalf("got %q, %d; want \"LONGXLONG\", 2", out, n)
	}
}

func TestSubstituteEmptyFromSkipped(t *testing.T) {
	out, n := substitute("text", []Pair{{From: "", To: "X"}})
	if out != "text" || n != 0 {
		t.Fatalf("got %q, %d; want unchanged", out, n)
	}
}

func TestSubstituteNoMatch(t *testing.T) {
	out, n := substitute("text", []Pair{{From: "zzz", To: "X"}})
	if out != "text" || n != 0 {
		t.Fatalf("got %q, %d; want unchanged", out, n)
	}
}

func TestSubstituteSkipsBase64Blob(t *testing.T) {
	blob := strings.Repeat("A", 50)
	text := `{"token":"` + blob + `","name":"secret"}`
	out, n := substitute(text, []Pair{{From: "A", To: "z"}})
	if strings.Contains(out, "z") {
		t.Errorf("substituted inside protected base64 blob: %q", out)
	}
	if n != 0 {
		t.Errorf("count = %d, want 0 (all matches were in the blob)", n)
	}
}

func TestSubstituteOutsideBlobStillApplies(t *testing.T) {
	blob := strings.Repeat("A", 50)
	text := `A "` + blob + `" A`
	out, n := substitute(text, []Pair{{From: "A", To: "z"}})
	// The two bare A's outside the quoted blob are replaced; the blob is untouched.
	if n != 2 {
		t.Errorf("count = %d, want 2", n)
	}
	if !strings.Contains(out, blob) {
		t.Errorf("blob was modified: %q", out)
	}
}
