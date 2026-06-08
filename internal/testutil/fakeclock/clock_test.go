package fakeclock

import (
	"testing"
	"time"
)

func TestNewAndNow(t *testing.T) {
	start := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	c := New(start)
	if got := c.Now(); !got.Equal(start) {
		t.Fatalf("Now() = %v, want %v", got, start)
	}
}

func TestAdvance(t *testing.T) {
	start := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	c := New(start)
	c.Advance(90 * time.Minute)
	want := start.Add(90 * time.Minute)
	if got := c.Now(); !got.Equal(want) {
		t.Fatalf("after Advance, Now() = %v, want %v", got, want)
	}
}

func TestSet(t *testing.T) {
	c := New(time.Unix(0, 0).UTC())
	target := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	c.Set(target)
	if got := c.Now(); !got.Equal(target) {
		t.Fatalf("after Set, Now() = %v, want %v", got, target)
	}
}
