package corelink

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/ledger"
)

// TestHelperLink plays og-gate-link: it attaches at once (unless $LINK_DETACHED), pushes a policy,
// answers raise, get_approval, seal and open, and logs every message it gets to $LINK_LOG.
func TestHelperLink(t *testing.T) {
	if os.Getenv("LINK_HELPER") != "1" {
		return
	}
	logf, _ := os.OpenFile(os.Getenv("LINK_LOG"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // test helper
	out := bufio.NewWriter(os.Stdout)
	send := func(v any) {
		b, _ := json.Marshal(v)
		_, _ = out.Write(append(b, '\n'))
		_ = out.Flush()
	}
	if os.Getenv("LINK_DETACHED") == "1" {
		goto serve
	}
	send(map[string]any{"t": "attached", "api": 4})
	send(map[string]any{"t": "policy", "rules": []any{map[string]any{"c": 1, "a": 2, "user": true}}})
	send(map[string]any{"t": "lanes", "lanes": []any{map[string]any{"id": "ln_1", "title": "Dinner · Trattoria"}}})
serve:
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		_, _ = fmt.Fprintln(logf, sc.Text())
		var m map[string]any
		_ = json.Unmarshal(sc.Bytes(), &m)
		switch m["t"] {
		case "raise":
			send(map[string]any{"t": "raised", "id": m["id"], "approval_id": "ap_1"})
			send(map[string]any{"t": "resolved", "approval": map[string]any{
				"id": "ap_1", "state": 2,
				"answer": map[string]any{"role": 1, "choices": []any{map[string]any{"item": "d0", "treatment": 1}}},
			}})
		case "seal", "open":
			// A stand-in for the keystore2 key: "sealing" prefixes ff, opening strips it.
			if m["aad"] == hex.EncodeToString([]byte("refuse")) {
				send(map[string]any{"t": "error", "id": m["id"], "op": m["t"], "error": "keymint error -30"})
				break
			}
			d, _ := m["data"].(string)
			if m["t"] == "seal" {
				send(map[string]any{"t": "sealed", "id": m["id"], "data": "ff" + d})
			} else {
				send(map[string]any{"t": "opened", "id": m["id"], "data": strings.TrimPrefix(d, "ff")})
			}
		case "get_approval":
			send(map[string]any{"t": "approval", "id": m["id"], "approval": map[string]any{"id": m["approval_id"], "state": 2}})
		case "health":
			if m["detail"] == "crash" {
				os.Exit(3)
			}
		}
	}
	os.Exit(0)
}

func startLink(t *testing.T) (*Link, string, *events) {
	t.Helper()
	log := filepath.Join(t.TempDir(), "link.log")
	t.Setenv("LINK_HELPER", "1")
	t.Setenv("LINK_LOG", log)
	ev := &events{}
	l := &Link{Path: os.Args[0], Args: []string{"-test.run=TestHelperLink"}, Log: slog.New(slog.DiscardHandler), H: Handlers{
		Policy:   func(r []Rule) { ev.add(fmt.Sprintf("policy %d:%d", r[0].Category, r[0].Action)) },
		Resolved: func(a Approval) { ev.add("resolved " + a.ID) },
		Attached: func(api int) { ev.add(fmt.Sprintf("attached %d", api)) },
	}}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l.Start(ctx)
	waitFor(t, func() bool { return l.Up() })
	return l, log, ev
}

type events struct {
	mu  sync.Mutex
	all []string
}

func (e *events) add(s string) { e.mu.Lock(); e.all = append(e.all, s); e.mu.Unlock() }
func (e *events) has(s string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, x := range e.all {
		if x == s {
			return true
		}
	}
	return false
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out")
}

func readLog(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

func TestLinkRelaysBothWays(t *testing.T) {
	l, log, ev := startLink(t)
	waitFor(t, func() bool { return ev.has("attached 4") && ev.has("policy 1:2") })

	l.ReportHealth(false, "detector unavailable")
	l.ReportHealth(false, "detector unavailable")
	l.Record(&ledger.Row{
		Time: time.Unix(1700000000, 0), LaneID: "ln_1", Caller: "chat", Destination: "api.example.test",
		Kind: "event", Content: true, MaskedCount: 2, MaskedCategories: map[string]int{"PII": 2},
	})
	l.Record(&ledger.Row{Time: time.Unix(1700000001, 0), Destination: "api.example.test", Kind: "event"})
	waitFor(t, func() bool { return strings.Contains(readLog(log), `"t":"egress"`) })
	got := readLog(log)
	if strings.Count(got, `"t":"health"`) != 1 {
		t.Errorf("health not deduplicated: %s", got)
	}
	if !strings.Contains(got, `"lane_label":"dinner"`) || !strings.Contains(got, `"masked_categories":"PII:2"`) ||
		!strings.Contains(got, `"app_package":"ai.outgate.chat"`) || strings.Count(got, `"ts_ms"`) != 1 {
		t.Errorf("egress rows: %s", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	id, err := l.Raise(ctx, &Request{Title: "Send this?", Kicker: "YOUR CALL · GATE 1 OF 1", GateIndex: 1, GateCount: 1})
	if err != nil || id != "ap_1" {
		t.Fatalf("raise: %q %v", id, err)
	}
	waitFor(t, func() bool { return ev.has("resolved ap_1") })
	a, err := l.Get(ctx, "ap_9")
	if err != nil || a == nil || a.ID != "ap_9" || a.State != StateAnswered {
		t.Errorf("get: %+v %v", a, err)
	}
}

func TestLinkRestartsAndReplaysHealth(t *testing.T) {
	l, log, _ := startLink(t)
	// The helper dies on this detail; the link restarts it and replays the health
	// first thing, so the second helper sees it too (and dies again).
	l.ReportHealth(true, "crash")
	waitFor(t, func() bool { return strings.Count(readLog(log), `"detail":"crash"`) >= 2 })
}

func TestLaneLabel(t *testing.T) {
	for in, want := range map[string]string{"Travel": "travel", "Dinner · Trattoria Nove": "dinner", "Inbox: drafts": "inbox", "": ""} {
		if got := laneLabel(in); got != want {
			t.Errorf("laneLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

// The keystore ops need only the helper: they work while OG Core isn't attached.
func TestSealOpenWithoutCore(t *testing.T) {
	t.Setenv("LINK_HELPER", "1")
	t.Setenv("LINK_LOG", filepath.Join(t.TempDir(), "link.log"))
	t.Setenv("LINK_DETACHED", "1")
	l := &Link{Path: os.Args[0], Args: []string{"-test.run=TestHelperLink"}, Log: slog.New(slog.DiscardHandler)}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l.Start(ctx)
	var sealed []byte
	waitFor(t, func() bool {
		var err error
		sealed, err = l.Seal(ctx, []byte{1, 2, 3}, []byte("aad"))
		return err == nil
	})
	if l.Up() {
		t.Fatal("OG Core attached in a detached helper")
	}
	if !bytes.Equal(sealed, []byte{0xff, 1, 2, 3}) {
		t.Errorf("sealed = %x", sealed)
	}
	plain, err := l.Open(ctx, sealed, []byte("aad"))
	if err != nil || !bytes.Equal(plain, []byte{1, 2, 3}) {
		t.Errorf("open = %x %v", plain, err)
	}
	if _, err := l.Seal(ctx, []byte{1}, []byte("refuse")); err == nil || !strings.Contains(err.Error(), "keymint error") {
		t.Errorf("refused seal: %v", err)
	}
	if _, err := l.Get(ctx, "ap_1"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("an OG Core call while detached: %v", err)
	}
}
