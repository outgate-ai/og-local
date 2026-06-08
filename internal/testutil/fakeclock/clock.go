package fakeclock

import "time"

// Clock is a deterministic clock for tests. It is not safe for concurrent
// advancement; tests that control time should drive it from a single goroutine.
type Clock struct {
	now time.Time
}

// New returns a Clock fixed at t.
func New(t time.Time) *Clock {
	return &Clock{now: t}
}

// Now returns the current instant.
func (c *Clock) Now() time.Time {
	return c.now
}

// Advance moves the clock forward by d.
func (c *Clock) Advance(d time.Duration) {
	c.now = c.now.Add(d)
}

// Set jumps the clock to t.
func (c *Clock) Set(t time.Time) {
	c.now = t
}
