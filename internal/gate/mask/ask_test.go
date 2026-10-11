package mask

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/outgate-ai/og-local/internal/gate"
	"github.com/outgate-ai/og-local/internal/gate/corelink"
	"github.com/outgate-ai/og-local/internal/gate/route"
)

// fakeCore answers approvals like OG Core would after the user tapped the sheet.
type fakeCore struct {
	mu      sync.Mutex
	raised  []*corelink.Request
	answer  *corelink.Answer
	srv     *gate.Server
	byID    map[string]*corelink.Approval
	noReply bool
	// rejectLanes: refuse approvals scoped to a lane, like OG Core for lanes it doesn't know.
	rejectLanes bool
}

func (f *fakeCore) Up() bool { return true }

func (f *fakeCore) Raise(_ context.Context, r *corelink.Request) (string, error) {
	f.mu.Lock()
	reject := f.rejectLanes
	f.mu.Unlock()
	if reject && r.LaneID != "" {
		return "", errors.New("unknown lane")
	}
	f.mu.Lock()
	cp := *r
	f.raised = append(f.raised, &cp)
	id := fmt.Sprintf("ap_%d", len(f.raised))
	ans, noReply := f.answer, f.noReply
	f.mu.Unlock()
	if !noReply {
		go func() {
			time.Sleep(20 * time.Millisecond)
			f.srv.ApprovalResolved(&corelink.Approval{ID: id, State: corelink.StateAnswered, Answer: ans})
		}()
	}
	return id, nil
}

func (f *fakeCore) Get(_ context.Context, id string) (*corelink.Approval, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.byID[id], nil
}

func (f *fakeCore) Cancel(string, string) {}

// set changes the fake under its lock: the gate reads it from its own goroutines.
func (f *fakeCore) set(change func(f *fakeCore)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

func (f *fakeCore) raisedList() []*corelink.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*corelink.Request(nil), f.raised...)
}

type askHarness struct {
	sock string
	core *fakeCore
	seen *[]string
	mu   *sync.Mutex
}

func startAsk(t *testing.T, pol Policy) *askHarness {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 1<<16)
		n, _ := r.Body.Read(b)
		mu.Lock()
		seen = append(seen, string(b[:n]))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(up.Close)
	m, _, _ := newTestMasker(t, nil)
	m.SetPolicy(pol)
	uid := uint32(os.Getuid()) //nolint:gosec // uids fit uint32
	dir := t.TempDir()
	core := &fakeCore{byID: map[string]*corelink.Approval{}}
	cfg := &gate.Config{
		Environments: []route.Environment{{ID: "prod", Global: up.URL, OIDC: "https://oidc.example.test"}},
		Classes:      providerClasses(up.URL),
		Callers:      []gate.CallerRule{{UID: &uid, Class: "agent"}},
		AllowHTTP:    []string{"127.0.0.1", "localhost"}, UploadDirs: []string{dir},
		DataDir: dir, Mode: gate.Mask, Version: "test",
	}
	srv, err := gate.New(cfg, &gate.Options{Masker: m, Approver: core})
	if err != nil {
		t.Fatal(err)
	}
	core.srv = srv
	sock := filepath.Join(dir, "g.sock")
	ln, _ := gate.ListenPath(sock, 0o600)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx, ln) }()
	return &askHarness{sock: sock, core: core, seen: &seen, mu: &mu}
}

func (h *askHarness) call(t *testing.T, req map[string]any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(req)
	c, err := net.Dial("unix", h.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = c.Write(append(b, '\n'))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	_ = json.Unmarshal([]byte(line), &out)
	return out
}

// providerClasses configures one external provider, "llm", on the upstream's port
// under the name localhost (Outgate's global is the same upstream as 127.0.0.1).
func providerClasses(upstream string) []gate.ClassRule {
	u, _ := url.Parse(upstream)
	return []gate.ClassRule{
		{Class: "outgate"}, {Class: "on-device"},
		{Class: "provider", Mask: true, Destinations: []route.Provider{{ID: "llm", Base: "http://localhost:" + u.Port()}}},
	}
}

// eventReq goes to the external provider: only its class is masked, so only it asks.
func eventReq(text string, timeoutMs int) map[string]any {
	return map[string]any{
		"source": map[string]any{"region_id": "provider:llm", "adapter": "local", "account_id": "acct-fake"}, "method": "POST",
		"path": "/v1/messages", "timeout_ms": timeoutMs,
		"body":   map[string]any{"kind": "input.text", "payload": map[string]any{"text": text}},
		"egress": map[string]any{"lane_id": "ln_fake"},
	}
}

// The same request to Outgate: never masked, never held.
func outgateReq(text string) map[string]any {
	r := eventReq(text, 1000)
	r["source"] = map[string]any{"region_id": "global", "adapter": "devq", "account_id": "acct-fake"}
	r["path"] = "/api/v1/agents/threads/thr-fake-m08/events"
	return r
}

func TestAskPolicyDoesNotHoldOutgateTraffic(t *testing.T) {
	h := startAsk(t, DefaultPolicy().Merge(map[Category]Action{Email: Ask, Name: Block}))
	resp := h.call(t, outgateReq("mail me at "+testEmail))
	if resp["status"].(float64) != 200 || resp["refused"] != nil {
		t.Fatalf("resp = %v", resp)
	}
	h.mu.Lock()
	sent := (*h.seen)[0]
	h.mu.Unlock()
	if !strings.Contains(sent, testEmail) || len(Placeholders(sent)) != 0 {
		t.Errorf("Outgate traffic was masked: %s", sent)
	}
	if n := len(h.core.raisedList()); n != 0 {
		t.Errorf("an approval was raised for Outgate traffic: %d", n)
	}
}

func TestAskHoldsRaisesAndProceeds(t *testing.T) {
	h := startAsk(t, DefaultPolicy().Merge(map[Category]Action{Email: Ask}))
	h.core.set(func(f *fakeCore) {
		f.answer = &corelink.Answer{Role: corelink.RoleApprove, Choices: []corelink.Choice{{Item: "d0", Treatment: corelink.TreatReal}}}
	})
	resp := h.call(t, eventReq("mail me at "+testEmail, 5000))
	if resp["status"].(float64) != 200 {
		t.Fatalf("resp = %v", resp)
	}
	h.mu.Lock()
	sent := (*h.seen)[0]
	h.mu.Unlock()
	if !strings.Contains(sent, testEmail) {
		t.Errorf("approved REAL value did not leave: %s", sent)
	}
	r := h.core.raisedList()[0]
	if r.LaneID != "ln_fake" || r.AccountID != "acct-fake" || len(r.Disclosures) != 1 || r.Disclosures[0].Field != "email" ||
		r.Disclosures[0].Preview != testEmail || r.Disclosures[0].Default != corelink.TreatMasked || r.Kicker == "" {
		t.Errorf("approval = %+v", r)
	}
}

func TestAskMaskedAnswerAndDenial(t *testing.T) {
	h := startAsk(t, DefaultPolicy().Merge(map[Category]Action{Email: Ask}))
	h.core.set(func(f *fakeCore) { f.answer = &corelink.Answer{Role: corelink.RoleApprove} })
	resp := h.call(t, eventReq("mail me at "+testEmail, 5000))
	h.mu.Lock()
	sent := (*h.seen)[0]
	h.mu.Unlock()
	if resp["status"].(float64) != 200 || strings.Contains(sent, testEmail) || len(Placeholders(sent)) != 1 {
		t.Errorf("approve with the default (masked): %v %s", resp, sent)
	}

	h.core.set(func(f *fakeCore) { f.answer = &corelink.Answer{Role: corelink.RoleSkip} })
	resp = h.call(t, eventReq("other mail "+testEmail+" again", 5000))
	if resp["refused"] != "approval_denied" {
		t.Errorf("don't send: %v", resp)
	}
	h.mu.Lock()
	n := len(*h.seen)
	h.mu.Unlock()
	if n != 1 {
		t.Error("a denied request left the phone")
	}
}

func TestAskTimesOutThenRetryJoins(t *testing.T) {
	h := startAsk(t, DefaultPolicy().Merge(map[Category]Action{Email: Ask}))
	h.core.set(func(f *fakeCore) { f.noReply = true })
	resp := h.call(t, eventReq("mail "+testEmail, 200))
	if resp["refused"] != "needs_approval" || resp["approval_id"] != "ap_1" {
		t.Fatalf("held past the budget: %v", resp)
	}
	h.core.srv.ApprovalResolved(&corelink.Approval{
		ID: "ap_1", State: corelink.StateAnswered,
		Answer: &corelink.Answer{Role: corelink.RoleApprove, Choices: []corelink.Choice{{Item: "d0", Treatment: corelink.TreatReal}}},
	})
	resp = h.call(t, eventReq("mail "+testEmail, 200))
	if resp["status"].(float64) != 200 || len(h.core.raisedList()) != 1 {
		t.Errorf("retry: %v, raised %d", resp, len(h.core.raisedList()))
	}
}

func TestUploadNeedsConfirmedApproval(t *testing.T) {
	h := startAsk(t, DefaultPolicy())
	dir := filepath.Dir(h.sock)
	png := filepath.Join(dir, "cap.png")
	_ = os.WriteFile(png, []byte("\x89PNG\r\n\x1a\n synthetic"), 0o600)
	up := func(approval string) map[string]any {
		return map[string]any{
			"source": map[string]any{"region_id": "global", "adapter": "devq"}, "method": "POST",
			"path": "/api/v1/agents/devices/d1/uploads", "file": png, "body": map[string]any{"lane_id": "ln_1"},
			"egress": map[string]any{"kind": "upload", "lane_id": "ln_1", "approval_id": approval}, "timeout_ms": 1500,
		}
	}
	h.core.set(func(f *fakeCore) {
		f.byID["ap_pending"] = &corelink.Approval{ID: "ap_pending", State: corelink.StatePending}
	})
	if resp := h.call(t, up("ap_pending")); resp["refused"] != "needs_approval" {
		t.Errorf("pending approval: %v", resp)
	}
	h.core.set(func(f *fakeCore) {
		f.byID["ap_no"] = &corelink.Approval{ID: "ap_no", State: corelink.StateAnswered, Answer: &corelink.Answer{Role: corelink.RoleAlternative}}
	})
	if resp := h.call(t, up("ap_no")); resp["refused"] != "approval_denied" {
		t.Errorf("text only: %v", resp)
	}
	h.core.set(func(f *fakeCore) {
		f.byID["ap_yes"] = &corelink.Approval{ID: "ap_yes", State: corelink.StateAnswered, Answer: &corelink.Answer{Role: corelink.RoleApprove}}
	})
	if resp := h.call(t, up("ap_yes")); resp["status"].(float64) != 200 {
		t.Errorf("approved screenshot: %v", resp)
	}
	h.mu.Lock()
	n := len(*h.seen)
	h.mu.Unlock()
	if n != 1 {
		t.Errorf("uploads that left: %d, want 1", n)
	}
}

func TestGateImageApproval(t *testing.T) {
	h := startAsk(t, DefaultPolicy())
	dir := filepath.Dir(h.sock)
	png := filepath.Join(dir, "own.png")
	_ = os.WriteFile(png, []byte("\x89PNG\r\n\x1a\n synthetic"), 0o600)
	req := func(body string) map[string]any {
		return map[string]any{
			"source": map[string]any{"region_id": "global", "adapter": "devq"}, "method": "POST",
			"path": "/api/v1/agents/devices/d1/uploads", "file": png, "body": map[string]any{"note": body},
			"egress": map[string]any{"kind": "upload", "lane_id": "ln_unknown"}, "timeout_ms": 1500,
		}
	}
	// A plain approve keeps the image's default: blocked.
	h.core.set(func(f *fakeCore) { f.answer = &corelink.Answer{Role: corelink.RoleApprove} })
	if resp := h.call(t, req("a")); resp["refused"] != "blocked_by_policy" {
		t.Errorf("approve without choosing the image: %v", resp)
	}
	h.core.set(func(f *fakeCore) {
		f.answer = &corelink.Answer{Role: corelink.RoleApprove, Choices: []corelink.Choice{{Item: "image", Treatment: corelink.TreatReal}}}
	})
	if resp := h.call(t, req("b")); resp["status"].(float64) != 200 {
		t.Errorf("image chosen REAL: %v", resp)
	}
	h.mu.Lock()
	n := len(*h.seen)
	h.mu.Unlock()
	if n != 1 {
		t.Errorf("images that left: %d, want 1", n)
	}
}

func TestRaiseRetriesWithoutUnknownLane(t *testing.T) {
	h := startAsk(t, DefaultPolicy().Merge(map[Category]Action{Email: Ask}))
	h.core.set(func(f *fakeCore) { f.rejectLanes = true })
	h.core.set(func(f *fakeCore) { f.answer = &corelink.Answer{Role: corelink.RoleApprove} })
	if resp := h.call(t, eventReq("mail "+testEmail, 3000)); resp["status"].(float64) != 200 {
		t.Fatalf("resp = %v", resp)
	}
	if list := h.core.raisedList(); list[len(list)-1].LaneID != "" {
		r := list[len(list)-1]
		t.Errorf("retry kept the unknown lane %q", r.LaneID)
	}
}
