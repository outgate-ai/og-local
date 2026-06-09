package pii

import "testing"

func TestPartialSuffixLen(t *testing.T) {
	m := Mapping{
		{From: "alice@example.com", To: "OG_PRIVATE_EMAIL_abc123"},
		{From: "x", To: "Y"},
	}
	cases := []struct {
		buf  string
		want int
	}{
		{"", 0},
		{"no tokens here", 0},
		{"trailing OG_PRIVATE_EMAIL_abc123", 0},
		{"trailing OG_PRIVATE_", len("OG_PRIVATE_")},
		{"end OG_PR", len("OG_PR")},
		{"OG_PRIVATE_EMAIL_abc12", len("OG_PRIVATE_EMAIL_abc12")},
		{"plain O", 1},
	}
	for _, c := range cases {
		if got := m.PartialSuffixLen(c.buf); got != c.want {
			t.Errorf("PartialSuffixLen(%q) = %d, want %d", c.buf, got, c.want)
		}
	}
}

func TestPartialSuffixLenEmptyMapping(t *testing.T) {
	if got := (Mapping{}).PartialSuffixLen("anything OG_"); got != 0 {
		t.Errorf("empty mapping = %d, want 0", got)
	}
}
