package pii

import (
	"strings"
	"testing"
)

func TestProtectedRangesFindsLongBlob(t *testing.T) {
	blob := strings.Repeat("a", 50)
	s := `x "` + blob + `" y`
	ranges := protectedRanges(s)
	if len(ranges) != 1 {
		t.Fatalf("got %d ranges, want 1", len(ranges))
	}
	start, end := ranges[0][0], ranges[0][1]
	if s[start:end] != blob {
		t.Errorf("range covers %q, want the blob", s[start:end])
	}
}

func TestProtectedRangesIgnoresShortQuoted(t *testing.T) {
	if r := protectedRanges(`"short"`); len(r) != 0 {
		t.Errorf("short quoted string was protected: %v", r)
	}
}

func TestProtectedRangesBase64Padding(t *testing.T) {
	blob := strings.Repeat("a", 48) + "=="
	if r := protectedRanges(`"` + blob + `"`); len(r) != 1 {
		t.Errorf("padded base64 not protected: %v", r)
	}
}

func TestInRanges(t *testing.T) {
	ranges := [][2]int{{5, 10}}
	cases := map[int]bool{4: false, 5: true, 9: true, 10: false, 11: false}
	for pos, want := range cases {
		if got := inRanges(pos, ranges); got != want {
			t.Errorf("inRanges(%d) = %v, want %v", pos, got, want)
		}
	}
}
