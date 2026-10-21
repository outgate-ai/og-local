package gate

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

const (
	// upstreamStaleTimeouts timeouts in a row with nothing read from one host drop the pool.
	upstreamStaleTimeouts = 2
	// netChangeSettle gathers a burst of address, link and rule changes into one reset.
	netChangeSettle = 500 * time.Millisecond
)

// upstreamPool is the gate's pool of connections to Outgate's hosts. A connection opened on a network
// that is no longer the default can stay open and silent, so the pool is replaced when the
// network changes and when one host keeps timing out with nothing read. Requests in flight on the
// old pool finish there; nothing new is sent on it.
type upstreamPool struct {
	newTransport func() *http.Transport
	log          *slog.Logger

	mu       sync.Mutex
	tr       *http.Transport
	timeouts map[string]int
}

func newUpstreamPool(newTransport func() *http.Transport, log *slog.Logger) *upstreamPool {
	return &upstreamPool{newTransport: newTransport, log: log, tr: newTransport(), timeouts: map[string]int{}}
}

func (u *upstreamPool) RoundTrip(r *http.Request) (*http.Response, error) {
	u.mu.Lock()
	tr := u.tr
	u.mu.Unlock()
	return tr.RoundTrip(r)
}

func (u *upstreamPool) CloseIdleConnections() {
	u.mu.Lock()
	tr := u.tr
	u.mu.Unlock()
	tr.CloseIdleConnections()
}

// reset replaces the pool. The old one's busy connections close once idle (IdleConnTimeout).
func (u *upstreamPool) reset(reason string) {
	u.mu.Lock()
	old := u.tr
	u.tr = u.newTransport()
	clear(u.timeouts)
	u.mu.Unlock()
	old.CloseIdleConnections()
	u.log.Info("upstream connections dropped", "reason", reason)
}

// observe counts timeouts with nothing read per host; anything else from the host clears it.
func (u *upstreamPool) observe(host string, timedOutEmpty bool) {
	u.mu.Lock()
	if !timedOutEmpty {
		delete(u.timeouts, host)
		u.mu.Unlock()
		return
	}
	u.timeouts[host]++
	stale := u.timeouts[host] >= upstreamStaleTimeouts
	u.mu.Unlock()
	if stale {
		u.reset("timeouts")
	}
}

// followNetwork resets the pool after each settled burst of network changes until ctx ends.
func (u *upstreamPool) followNetwork(ctx context.Context, changes <-chan struct{}) {
	var settle <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-changes:
			if !ok {
				return
			}
			settle = time.After(netChangeSettle)
		case <-settle:
			settle = nil
			u.reset("network_changed")
		}
	}
}
