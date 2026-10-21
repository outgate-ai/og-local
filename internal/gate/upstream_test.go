package gate

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/corelink"
	"github.com/outgate-ai/og-local/internal/gate/wire"
)

// network stands in for the phone's default network: connections opened before a change stay
// open, but what is written to them goes nowhere and nothing comes back.
type network struct{ gen atomic.Int64 }

type netConn struct {
	net.Conn
	n   *network
	gen int64
}

func (c *netConn) Write(b []byte) (int, error) {
	if c.n.gen.Load() != c.gen {
		return len(b), nil
	}
	return c.Conn.Write(b)
}

func (n *network) transport(addr *string) func() *http.Transport {
	return func() *http.Transport {
		tr := &http.Transport{Protocols: new(http.Protocols), DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			c, err := (&net.Dialer{}).DialContext(ctx, network, *addr)
			if err != nil {
				return nil, err
			}
			return &netConn{Conn: c, n: n, gen: n.gen.Load()}, nil
		}}
		tr.Protocols.SetUnencryptedHTTP2(true)
		return tr
	}
}

// startOnNetwork starts a gate whose upstream speaks HTTP/2, as Outgate's hosts do: one connection
// per host carries every request.
func startOnNetwork(t *testing.T, n *network, changes chan struct{}) *harness {
	t.Helper()
	h2 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	h2.Config.Protocols = new(http.Protocols)
	h2.Config.Protocols.SetUnencryptedHTTP2(true)
	h2.Start()
	t.Cleanup(h2.Close)
	addr := strings.TrimPrefix(h2.URL, "http://")
	return startOpts(t, Passthrough, nil, nil, nil, func(o *Options) {
		o.Transport, o.NewTransport, o.NetChanges = nil, n.transport(&addr), changes
	})
}

func (h *harness) get(path string) map[string]any {
	h.t.Helper()
	return h.call(fmt.Sprintf(`{"source":{"region_id":"global","adapter":"chat"},"method":"GET","path":%q,"egress":{}}`, path))
}

func (p *upstreamPool) current() *http.Transport {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tr
}

func (p *upstreamPool) generation() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.gen
}

func TestNetworkChangeDropsPooledConnections(t *testing.T) {
	n := &network{}
	changes := make(chan struct{})
	h := startOnNetwork(t, n, changes)
	if resp := h.get("/api/v1/me"); resp["status"].(float64) != 200 {
		t.Fatalf("before: %v", resp)
	}
	before := h.srv.pool.current()
	n.gen.Add(1)
	changes <- struct{}{}
	deadline := time.Now().Add(3 * time.Second)
	for h.srv.pool.current() == before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	start := time.Now()
	resp := h.get("/api/v1/me")
	if resp["status"].(float64) != 200 {
		t.Fatalf("after the network changed: %v (%s)", resp, time.Since(start))
	}
}

func TestRepeatedEmptyTimeoutsDropPooledConnections(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the gate's 12 s upstream deadline")
	}
	n := &network{}
	h := startOnNetwork(t, n, make(chan struct{}))
	if resp := h.get("/api/v1/me"); resp["status"].(float64) != 200 {
		t.Fatalf("before: %v", resp)
	}

	n.gen.Add(1)
	var wg sync.WaitGroup
	statuses := make(chan float64, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses <- h.get("/api/v1/me")["status"].(float64)
		}()
	}
	wg.Wait()
	close(statuses)
	for st := range statuses {
		if st != 504 {
			t.Fatalf("a request on a silent connection = %v, want 504", st)
		}
	}
	if resp := h.get("/api/v1/me"); resp["status"].(float64) != 200 {
		t.Fatalf("after two timeouts with nothing read: %v", resp)
	}
}

func TestUpstreamPoolResetsOnRepeatedTimeoutsPerHost(t *testing.T) {
	made := 0
	p := newUpstreamPool(func() *http.Transport { made++; return &http.Transport{} }, slog.New(slog.DiscardHandler))
	p.observe("a", p.generation(), true)
	p.observe("b", p.generation(), true)
	if made != 1 {
		t.Fatalf("reset after one timeout per host (%d transports)", made)
	}
	p.observe("a", p.generation(), false)
	p.observe("a", p.generation(), true)
	if made != 1 {
		t.Fatalf("an answer did not clear the count (%d transports)", made)
	}
	p.observe("a", p.generation(), true)
	if made != 2 {
		t.Fatalf("two timeouts in a row did not reset (%d transports)", made)
	}
	p.observe("b", p.generation(), true)
	if made != 2 {
		t.Fatalf("a reset kept other hosts' counts (%d transports)", made)
	}
}

func TestUpstreamPoolSettlesNetworkChanges(t *testing.T) {
	var made atomic.Int32
	p := newUpstreamPool(func() *http.Transport { made.Add(1); return &http.Transport{} }, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes := make(chan struct{})
	go p.followNetwork(ctx, changes)
	for range 5 {
		changes <- struct{}{}
	}
	time.Sleep(netChangeSettle + 300*time.Millisecond)
	if got := made.Load(); got != 2 {
		t.Fatalf("transports = %d, want one reset for the burst", got)
	}
}

// slowMasker takes its time, as the detector does on a busy phone.
type slowMasker struct{ markerMasker }

func (m *slowMasker) Mask(ctx context.Context, c *Call, body []byte) ([]byte, wire.Masked, error) {
	time.Sleep(3 * time.Second)
	return m.markerMasker.Mask(ctx, c, body)
}

func TestUpstreamDeadlineCountsFromTheRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the gate's 12 s upstream deadline")
	}
	h := startWith(t, Mask, func(c *Config) { withProvider(portOf(c.Environments[0].Global))(c) }, &slowMasker{}, nil)
	h.up.mu.Lock()
	h.up.custom = func(_ http.ResponseWriter, r *http.Request) bool {
		<-r.Context().Done()
		return true
	}
	h.up.mu.Unlock()
	start := time.Now()
	resp := h.call(`{"source":{"region_id":"provider:llm","adapter":"local"},"method":"POST","path":"/v1/chat/completions","body":{"text":"x"},"egress":{},"timeout_ms":10000}`)
	took := time.Since(start)
	if resp["status"].(float64) != 504 {
		t.Fatalf("resp = %v", resp)
	}
	// Callers wait max(timeout_ms, 10 s) + 5 s; the gate answers within max(timeout_ms, 10 s) + 2 s.
	if took > 12500*time.Millisecond {
		t.Fatalf("answered after %s, past the 12 s the gate promises", took)
	}
}

// countTransports counts the pools a gate makes: one at the start, one per reset.
func countTransports(made *atomic.Int32, newTransport func() *http.Transport) func() *http.Transport {
	return func() *http.Transport {
		made.Add(1)
		return newTransport()
	}
}

func TestOldPoolTimeoutsKeepTheNewPool(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the gate's 12 s upstream deadline")
	}
	n := &network{}
	var made atomic.Int32
	h := startOnNetwork(t, n, make(chan struct{}))
	h.srv.pool.mu.Lock()
	h.srv.pool.newTransport = countTransports(&made, h.srv.pool.newTransport)
	h.srv.pool.mu.Unlock()
	if resp := h.get("/api/v1/me"); resp["status"].(float64) != 200 {
		t.Fatalf("before: %v", resp)
	}

	// Four requests stuck on the dead connection: the first two timeouts replace the pool, the
	// other two still belong to the old one.
	n.gen.Add(1)
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(i) * 200 * time.Millisecond)
			if st := h.get("/api/v1/me")["status"].(float64); st != 504 {
				t.Errorf("a request on a silent connection = %v, want 504", st)
			}
		}()
	}
	wg.Wait()
	if got := made.Load(); got != 1 {
		t.Fatalf("pools made after the timeouts = %d, want 1 (one reset)", got)
	}
	if resp := h.get("/api/v1/me"); resp["status"].(float64) != 200 {
		t.Fatalf("after: %v", resp)
	}
}

// stallMasker masks after the gate's upstream deadline has passed.
type stallMasker struct{ markerMasker }

func (m *stallMasker) Mask(ctx context.Context, c *Call, body []byte) ([]byte, wire.Masked, error) {
	time.Sleep(12500 * time.Millisecond)
	return m.markerMasker.Mask(ctx, c, body)
}

func TestUnsentLateRequestsKeepThePool(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the gate's 12 s upstream deadline")
	}
	var made atomic.Int32
	h := startOpts(t, Mask, func(c *Config) { withProvider(portOf(c.Environments[0].Global))(c) }, &stallMasker{}, nil, func(o *Options) {
		o.Transport, o.NewTransport = nil, countTransports(&made, upstreamTransport)
	})
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := h.call(`{"source":{"region_id":"provider:llm","adapter":"local"},"method":"POST","path":"/v1/chat/completions","body":{"text":"x"},"egress":{}}`)
			if resp["status"].(float64) != 504 {
				t.Errorf("resp = %v", resp)
			}
		}()
	}
	wg.Wait()
	if got := made.Load(); got != 1 {
		t.Fatalf("pools made = %d, want 1: requests never sent counted as silent timeouts", got)
	}
}

func TestApprovalHoldEndsBeforeTheGateDeadline(t *testing.T) {
	ap := &fakeApprover{byID: map[string]*corelink.Approval{}, noReply: true}
	h := startWith(t, Mask, nil, nil, ap)
	png := filepath.Join(h.dir, "uploads", "shot.png")
	_ = os.MkdirAll(filepath.Dir(png), 0o700)
	_ = os.WriteFile(png, []byte("\x89PNG\r\n\x1a\n synthetic"), 0o600)
	start := time.Now()
	resp := h.call(fmt.Sprintf(`{"source":{"region_id":"global","adapter":"devq"},"method":"POST","path":"/api/v1/agents/devices/d1/uploads",`+
		`"body":{"lane_id":"ln_1","step_index":2},"file":%q,"egress":{"kind":"upload"},"timeout_ms":0}`, png))
	took := time.Since(start)
	if resp["refused"] != "needs_approval" || resp["approval_id"] != "ap_g1" {
		t.Fatalf("held: %v", resp)
	}
	// Answered no later than the 12 s the gate promises, less what the upstream request keeps.
	if took > 12*time.Second-holdMargin+500*time.Millisecond {
		t.Fatalf("held for %s", took)
	}
}
