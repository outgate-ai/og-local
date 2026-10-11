package gate

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/corelink"
	"github.com/outgate-ai/og-local/internal/gate/ledger"
	"github.com/outgate-ai/og-local/internal/gate/route"
	"github.com/outgate-ai/og-local/internal/gate/wire"
)

type upstream struct {
	mu   sync.Mutex
	got  []seen
	srv  *httptest.Server
	host string
}

type seen struct {
	Method, Path, Query, Body, ContentType string
	Header                                 http.Header
}

func newUpstream(t *testing.T) *upstream {
	u := &upstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.got = append(u.got, seen{r.Method, r.URL.Path, r.URL.RawQuery, string(b), r.Header.Get("Content-Type"), r.Header.Clone()})
		u.mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/events-token"):
			_, _ = fmt.Fprintf(w, `{"url":"http://%s/v1/agents/threads/thr-1/events","token":"<redacted>"}`, "region.localhost:"+portOf(u.srv.URL))
		case r.URL.Path == "/text":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "plain words")
		case r.URL.Path == "/redirect":
			http.Redirect(w, r, "https://evil.test/", http.StatusFound)
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"ok":true,"echo_len":%d}`, len(b))
		}
	}))
	t.Cleanup(u.srv.Close)
	u.host = "127.0.0.1"
	return u
}

func mustHost(raw string) string {
	u, _ := url.Parse(raw)
	return u.Hostname()
}

func portOf(raw string) string {
	p, _ := url.Parse(raw)
	return p.Port()
}

func (u *upstream) last() seen {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.got[len(u.got)-1]
}

type rec struct {
	mu   sync.Mutex
	rows []ledger.Row
}

func (r *rec) Record(row *ledger.Row) {
	r.mu.Lock()
	r.rows = append(r.rows, *row)
	r.mu.Unlock()
}

func (r *rec) last(t *testing.T) ledger.Row {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		n := len(r.rows)
		var row ledger.Row
		if n > 0 {
			row = r.rows[n-1]
		}
		r.mu.Unlock()
		if n > 0 {
			return row
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no ledger row")
	return ledger.Row{}
}

type harness struct {
	t      *testing.T
	sock   string
	up     *upstream
	rows   *rec
	srv    *Server
	cancel context.CancelFunc
	dir    string
}

func start(t *testing.T, mode Mode, mutate func(*Config)) *harness {
	t.Helper()
	return startWith(t, mode, mutate, nil, nil)
}

// startWith also takes a masker and an approver (nil: the defaults of New).
func startWith(t *testing.T, mode Mode, mutate func(*Config), masker Masker, ap Approver) *harness {
	t.Helper()
	up := newUpstream(t)
	dir := t.TempDir()
	uid := uint32(os.Getuid()) //nolint:gosec // uids fit uint32
	cfg := Config{
		Environments: []route.Environment{{ID: "prod", Global: up.srv.URL, OIDC: "http://localhost:" + portOf(up.srv.URL)}},
		Learn:        []route.LearnRule{{Path: "/api/v1/agents/threads/:id/events-token", Field: "url"}},
		Callers:      []CallerRule{{UID: &uid, Class: "agent"}},
		AllowHTTP:    []string{"127.0.0.1", "localhost", "region.localhost"},
		UploadDirs:   []string{filepath.Join(dir, "uploads")},
		DataDir:      dir, Mode: mode, Version: "test",
	}
	if mutate != nil {
		mutate(&cfg)
	}
	rows := &rec{}
	srv, err := New(&cfg, &Options{Sinks: []ledger.Sink{rows}, Transport: regionDialer(up.srv.URL), Masker: masker, Approver: ap})
	if err != nil {
		t.Fatal(err)
	}
	if fa, ok := ap.(*fakeApprover); ok {
		fa.srv = srv
	}
	sock := filepath.Join(dir, "gate.sock")
	ln, err := ListenPath(sock, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(cancel)
	return &harness{t: t, sock: sock, up: up, rows: rows, srv: srv, cancel: cancel, dir: dir}
}

// regionDialer sends every host to the test upstream, so learned region hosts resolve.
func regionDialer(upstreamURL string) http.RoundTripper {
	addr := strings.TrimPrefix(upstreamURL, "http://")
	return &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}}
}

func (h *harness) call(line string) map[string]any {
	h.t.Helper()
	c, err := net.Dial("unix", h.sock)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := io.WriteString(c, line+"\n"); err != nil {
		h.t.Fatal(err)
	}
	out, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		h.t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		h.t.Fatalf("bad response %q: %v", out, err)
	}
	return m
}

func (h *harness) callFD(line string, fd int) map[string]any {
	h.t.Helper()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: h.sock, Net: "unix"})
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, _, err := c.WriteMsgUnix([]byte(line+"\n"), syscall.UnixRights(fd), nil); err != nil {
		h.t.Fatal(err)
	}
	out, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		h.t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		h.t.Fatalf("bad response %q: %v", out, err)
	}
	return m
}

func TestPassthroughForwardsUnchangedAndRecords(t *testing.T) {
	h := start(t, Passthrough, nil)
	// The exact shape og-agentd's serde writes (kind null, body always present).
	resp := h.call(`{"source":{"account_id":"acct-1","region_id":"global","adapter":"devq"},"method":"POST",` +
		`"path":"/api/v1/agents/threads/thr-abc123/events","body":{"kind":"input.text","payload":{"text":"Call Jane Example on 555-0100"}},` +
		`"egress":{"lane_id":"ln_1","step_index":3,"kind":null},"timeout_ms":0}`)
	if resp["status"].(float64) != 200 || resp["refused"] != nil {
		t.Fatalf("resp = %v", resp)
	}
	if m := resp["masked"].(map[string]any); m["count"].(float64) != 0 || m["blocked"].(float64) != 0 {
		t.Errorf("masked = %v", m)
	}
	got := h.up.last()
	if got.Body != `{"kind":"input.text","payload":{"text":"Call Jane Example on 555-0100"}}` || got.ContentType != "application/json" {
		t.Errorf("upstream got %+v", got)
	}
	row := h.rows.last(t)
	if row.PathClass != "/api/v1/agents/threads/:id/events" || row.ThreadID != "thr-abc123" || row.Kind != "event" ||
		!row.Content || row.BytesOut != int64(len(got.Body)) || row.Status != 200 || row.LaneID != "ln_1" ||
		row.StepIndex == nil || *row.StepIndex != 3 || row.Mode != "passthrough" || row.Blocked || row.Caller != "agent" ||
		row.Class != "outgate" || row.Mask != MaskNotRequired {
		t.Errorf("row = %+v", row)
	}
	if resp["ledger"] != row.ID {
		t.Errorf("ledger id %v vs %s", resp["ledger"], row.ID)
	}
	files, _ := filepath.Glob(filepath.Join(h.dir, "ledger", "egress-*.jsonl"))
	if len(files) != 1 {
		t.Errorf("ledger files = %v", files)
	}
	b, _ := os.ReadFile(files[0])
	if strings.Contains(string(b), "Call ") || strings.Contains(string(b), "input.text") {
		t.Errorf("ledger file holds content: %s", b)
	}
}

func TestRefusesHostsOutsideTheAllowlist(t *testing.T) {
	h := start(t, Passthrough, nil)
	for _, u := range []string{"https://evil.test/x", "http://10.0.0.1/x", "file:///etc/passwd"} {
		resp := h.call(fmt.Sprintf(`{"source":{"adapter":"chat"},"method":"GET","url":%q,"egress":{}}`, u))
		if resp["refused"] != "destination_not_allowed" && resp["refused"] != "bad_url" {
			t.Errorf("%s: %v", u, resp)
		}
		row := h.rows.last(t)
		if !row.Blocked {
			t.Errorf("%s: row not blocked: %+v", u, row)
		}
		if want := mustHost(u); row.Destination != want {
			t.Errorf("%s: destination %q, want %q", u, row.Destination, want)
		}
	}
	resp := h.call(fmt.Sprintf(`{"source":{"adapter":"chat"},"method":"GET","url":"%s/redirect","egress":{}}`, h.up.srv.URL))
	if resp["status"].(float64) != 302 {
		t.Errorf("redirect followed: %v", resp)
	}
}

// Traffic to Outgate is not masked on the phone: without any detector, content to
// global and to regions leaves unchanged and the gate is healthy.
func TestOutgateContentLeavesUnmaskedWithoutDetector(t *testing.T) {
	h := start(t, Mask, nil)
	body := `{"kind":"input.text","payload":{"text":"Call Jane Example on 555-0100"}}`
	resp := h.call(`{"source":{"region_id":"global","adapter":"chat"},"method":"POST","path":"/api/v1/agents/threads/thr-1/events",` +
		`"body":` + body + `,"egress":{}}`)
	if resp["status"].(float64) != 200 || resp["refused"] != nil || resp["class"] != "outgate" {
		t.Fatalf("content to Outgate refused: %v", resp)
	}
	if m := resp["masked"].(map[string]any); m["count"].(float64) != 0 || m["mask"] != MaskNotRequired {
		t.Errorf("masked = %v", m)
	}
	if got := h.up.last().Body; got != body {
		t.Errorf("upstream got %s", got)
	}
	row := h.rows.last(t)
	if row.Blocked || !row.Content || row.Class != "outgate" || row.Mask != MaskNotRequired || row.MaskedCount != 0 ||
		row.BytesOut != int64(len(body)) || row.Status != 200 || row.Destination != "127.0.0.1" || row.PathClass != "/api/v1/agents/threads/:id/events" {
		t.Errorf("row = %+v", row)
	}
	if ledger.Outcome(&row) != "CLEAN" {
		t.Errorf("outcome = %s", ledger.Outcome(&row))
	}
	health := h.call(`{"op":"health"}`)["body"].(map[string]any)
	content := health["content"].(map[string]any)
	masking := health["masking"].(map[string]any)
	if content["ready"] != true || content["reason"] != DetectorNotNeeded || masking["needed"] != false ||
		masking["providers"].(float64) != 0 || health["mode"] != "mask" {
		t.Errorf("health = %v", health)
	}
	if cl := masking["classes"].(map[string]any); cl["outgate"] != false || cl["on-device"] != false || cl["provider"] != true {
		t.Errorf("classes = %v", cl)
	}
}

func withProvider(port string) func(*Config) {
	return func(c *Config) {
		c.AllowHTTP = append(c.AllowHTTP, "provider.localhost")
		c.Classes = []ClassRule{
			{Class: "outgate"}, {Class: "on-device"},
			{Class: "provider", Mask: true, Destinations: []route.Provider{{ID: "llm", Base: "http://provider.localhost:" + port}}},
		}
	}
}

// Fail closed applies to the masked class only: with an external provider configured
// and no detector, content to the provider is refused, everything else still leaves.
func TestProviderContentFailsClosedWithoutDetector(t *testing.T) {
	var h *harness
	h = startWith(t, Mask, func(c *Config) { withProvider(portOf(c.Environments[0].Global))(c) }, nil, nil)
	n := len(h.up.got)
	resp := h.call(`{"source":{"region_id":"provider:llm","adapter":"local"},"method":"POST","path":"/v1/chat/completions",` +
		`"body":{"messages":[{"role":"user","content":"hello"}]},"egress":{}}`)
	if resp["refused"] != "detector_unavailable" || resp["status"].(float64) != 503 || resp["class"] != "provider" {
		t.Fatalf("provider content not refused: %v", resp)
	}
	if len(h.up.got) != n {
		t.Fatal("provider content reached the upstream")
	}
	if row := h.rows.last(t); !row.Blocked || row.BlockReason != "detector_unavailable" || row.Class != "provider" ||
		row.Mask != MaskOn || row.BytesOut != 0 || row.Destination != "provider.localhost" {
		t.Errorf("row = %+v", row)
	}
	resp = h.call(`{"source":{"region_id":"provider:llm","adapter":"local"},"method":"GET","path":"/v1/models","egress":{}}`)
	if resp["status"].(float64) != 200 {
		t.Errorf("content-free provider GET refused: %v", resp)
	}
	if row := h.rows.last(t); row.Mask != MaskNotRequired || row.Class != "provider" || row.Content {
		t.Errorf("content-free row = %+v", row)
	}
	resp = h.call(`{"source":{"region_id":"global","adapter":"chat"},"method":"POST","path":"/api/v1/agents/threads/thr-1/events","body":{"text":"hello"},"egress":{}}`)
	if resp["status"].(float64) != 200 {
		t.Errorf("Outgate content refused with a provider configured: %v", resp)
	}
	health := h.call(`{"op":"health"}`)["body"].(map[string]any)
	if health["masking"].(map[string]any)["needed"] != true || health["content"].(map[string]any)["ready"] != false {
		t.Errorf("health = %v", health)
	}
}

// markerMasker masks one synthetic marker and counts its calls.
type markerMasker struct {
	mu    sync.Mutex
	calls int
}

const marker = "synthetic-marker-4711"

func (m *markerMasker) Mask(_ context.Context, _ *Call, body []byte) ([]byte, wire.Masked, error) {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()
	if !strings.Contains(string(body), marker) {
		return body, wire.Masked{}, nil
	}
	return []byte(strings.ReplaceAll(string(body), marker, "[masked]")), wire.Masked{Count: 1, Categories: map[string]int{"PII": 1}}, nil
}

func (m *markerMasker) Restore(_ context.Context, _ *Call, body []byte) ([]byte, []wire.Restored) {
	return body, nil
}

func (m *markerMasker) Ready() (bool, string) { return true, "" }

func (m *markerMasker) n() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

// The class split with a working masker: Outgate unmasked, the provider masked,
// the provider unmasked in passthrough (debuggable builds), each row saying which.
func TestMaskingFollowsTheDestinationClass(t *testing.T) {
	mm := &markerMasker{}
	var h *harness
	h = startWith(t, Mask, func(c *Config) { withProvider(portOf(c.Environments[0].Global))(c) }, mm, nil)
	body := `{"text":"note ` + marker + `"}`
	resp := h.call(`{"source":{"region_id":"global","adapter":"chat"},"method":"POST","path":"/api/v1/agents/threads/thr-1/events","body":` + body + `,"egress":{}}`)
	if resp["status"].(float64) != 200 || h.up.last().Body != body || mm.n() != 0 {
		t.Fatalf("Outgate content masked: %v %s (masker calls %d)", resp, h.up.last().Body, mm.n())
	}
	if row := h.rows.last(t); row.Class != "outgate" || row.Mask != MaskNotRequired || row.MaskedCount != 0 {
		t.Errorf("outgate row = %+v", row)
	}

	resp = h.call(`{"source":{"region_id":"provider:llm","adapter":"local"},"method":"POST","path":"/v1/chat/completions","body":` + body + `,"egress":{}}`)
	if resp["status"].(float64) != 200 || strings.Contains(h.up.last().Body, marker) || mm.n() != 1 {
		t.Fatalf("provider content not masked: %v %s", resp, h.up.last().Body)
	}
	if m := resp["masked"].(map[string]any); m["count"].(float64) != 1 || m["mask"] != MaskOn || resp["class"] != "provider" {
		t.Errorf("masked = %v", resp)
	}
	if row := h.rows.last(t); row.Class != "provider" || row.Mask != MaskOn || row.MaskedCount != 1 || ledger.Outcome(&row) != "MASKED" {
		t.Errorf("provider row = %+v", row)
	}

	// An absolute URL on the provider's host is the provider class too.
	resp = h.call(fmt.Sprintf(`{"source":{"adapter":"local"},"method":"POST","url":"http://provider.localhost:%s/v1/chat/completions","body":%s,"egress":{}}`, portOf(h.up.srv.URL), body))
	if resp["status"].(float64) != 200 || resp["class"] != "provider" || strings.Contains(h.up.last().Body, marker) {
		t.Errorf("provider by URL: %v %s", resp, h.up.last().Body)
	}

	// Passthrough (debuggable builds only): the masked class leaves unmasked, and says so.
	pt := startWith(t, Passthrough, func(c *Config) { withProvider(portOf(c.Environments[0].Global))(c) }, nil, nil)
	resp = pt.call(`{"source":{"region_id":"provider:llm","adapter":"local"},"method":"POST","path":"/v1/chat/completions","body":` + body + `,"egress":{}}`)
	if resp["status"].(float64) != 200 || pt.up.last().Body != body {
		t.Fatalf("passthrough: %v %s", resp, pt.up.last().Body)
	}
	if row := pt.rows.last(t); row.Mask != MaskOff || row.Class != "provider" {
		t.Errorf("passthrough row = %+v", row)
	}
}

func TestProviderRouting(t *testing.T) {
	h := startWith(t, Passthrough, func(c *Config) { withProvider(portOf(c.Environments[0].Global))(c) }, nil, nil)
	if resp := h.call(`{"source":{"region_id":"provider:nope"},"method":"GET","path":"/v1/models","egress":{}}`); resp["refused"] != "unknown_region" {
		t.Errorf("unknown provider: %v", resp)
	}
	if resp := h.call(`{"source":{},"method":"GET","url":"https://api.other-llm.test/v1/models","egress":{}}`); resp["refused"] != "destination_not_allowed" {
		t.Errorf("unconfigured provider host: %v", resp)
	}
	h2 := start(t, Passthrough, nil)
	if resp := h2.call(`{"source":{"region_id":"provider:llm"},"method":"GET","path":"/v1/models","egress":{}}`); resp["refused"] != "unknown_region" {
		t.Errorf("no providers configured: %v", resp)
	}
}

func TestClassConfig(t *testing.T) {
	var c Config
	if c.Masks("outgate") || c.Masks("on-device") || !c.Masks("provider") || c.MaskingNeeded() {
		t.Errorf("defaults: %v needed=%v", c.MaskingClasses(), c.MaskingNeeded())
	}
	c.Classes = []ClassRule{{Class: "provider", Mask: true, Destinations: []route.Provider{{ID: "a", Base: "https://llm.example.test"}}}}
	if err := c.Validate(); err != nil || !c.MaskingNeeded() || c.Masks("outgate") {
		t.Errorf("provider configured: %v needed=%v", err, c.MaskingNeeded())
	}
	env := []route.Environment{{ID: "prod", Global: "https://api.outgate.test", OIDC: "https://console.outgate.test"}}
	bad := map[string][]ClassRule{
		"unknown class":     {{Class: "region"}},
		"twice":             {{Class: "outgate"}, {Class: "outgate"}},
		"on-device masked":  {{Class: "on-device", Mask: true}},
		"outgate endpoints": {{Class: "outgate", Destinations: []route.Provider{{ID: "x", Base: "https://x.test"}}}},
		"provider on Outgate's host": {{Class: "provider", Mask: true,
			Destinations: []route.Provider{{ID: "x", Base: "https://api.outgate.test/v1"}}}},
		"provider without id": {{Class: "provider", Destinations: []route.Provider{{Base: "https://x.test"}}}},
		"provider bad base":   {{Class: "provider", Destinations: []route.Provider{{ID: "x", Base: "ftp://x.test"}}}},
	}
	for name, classes := range bad {
		c := Config{Environments: env, Classes: classes}
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	dir := t.TempDir()
	conf := filepath.Join(dir, "gate.conf")
	_ = os.WriteFile(conf, []byte(`{"classes":[{"class":"on-device","mask":true}]}`), 0o600)
	if _, err := LoadConfig(conf); err == nil {
		t.Error("LoadConfig accepted a masked on-device class")
	}
	if _, err := New(&Config{DataDir: dir, Classes: []ClassRule{{Class: "x"}}}, &Options{}); err == nil {
		t.Error("New accepted an unknown class")
	}
}

// fakeApprover answers approvals like OG Core after the user tapped the 08 sheet.
type fakeApprover struct {
	mu     sync.Mutex
	srv    *Server
	answer *corelink.Answer
	byID   map[string]*corelink.Approval
	raised int
}

func (f *fakeApprover) Up() bool { return true }

func (f *fakeApprover) Raise(_ context.Context, _ *corelink.Request) (string, error) {
	f.mu.Lock()
	f.raised++
	id := fmt.Sprintf("ap_g%d", f.raised)
	ans := f.answer
	f.mu.Unlock()
	go func() {
		time.Sleep(10 * time.Millisecond)
		f.srv.ApprovalResolved(&corelink.Approval{ID: id, State: corelink.StateAnswered, Answer: ans})
	}()
	return id, nil
}

func (f *fakeApprover) Get(_ context.Context, id string) (*corelink.Approval, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.byID[id], nil
}

func (f *fakeApprover) Cancel(string, string) {}

func (f *fakeApprover) set(change func(f *fakeApprover)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

func (f *fakeApprover) raisedN() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.raised
}

// Decision #18 stays: images an agent uploads to Outgate need an 08 approval even
// though nothing is masked; images the user attaches in Chat pass.
func TestImageConsentForAgentUploadsOnly(t *testing.T) {
	ap := &fakeApprover{byID: map[string]*corelink.Approval{}}
	h := startWith(t, Mask, nil, nil, ap)
	png := filepath.Join(h.dir, "shot.png")
	_ = os.WriteFile(png, []byte("\x89PNG\r\n\x1a\n synthetic"), 0o600)
	upload := func(approval string) string {
		return fmt.Sprintf(`{"source":{"region_id":"global","adapter":"devq"},"method":"POST","path":"/api/v1/agents/devices/d1/uploads",`+
			`"body":{"lane_id":"ln_1"},"file":"fd:0","egress":{"kind":"upload","approval_id":%q},"timeout_ms":1500}`, approval)
	}
	send := func(line string) map[string]any {
		f, err := os.Open(png)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		return h.callFD(line, int(f.Fd()))
	}
	n := len(h.up.got)
	// The agent, approve without choosing the image: its default is blocked.
	ap.set(func(f *fakeApprover) { f.answer = &corelink.Answer{Role: corelink.RoleApprove} })
	if resp := send(upload("")); resp["refused"] != "blocked_by_policy" || resp["approval_id"] != "ap_g1" {
		t.Errorf("image left without being chosen: %v", resp)
	}
	if row := h.rows.last(t); !row.Blocked || row.Class != "outgate" || row.Mask != MaskNotRequired || row.ApprovalID != "ap_g1" {
		t.Errorf("row = %+v", row)
	}
	// Chosen REAL on the sheet: it leaves.
	ap.set(func(f *fakeApprover) {
		f.answer = &corelink.Answer{Role: corelink.RoleApprove, Choices: []corelink.Choice{{Item: "image", Treatment: corelink.TreatReal}}}
	})
	if resp := send(upload("")); resp["status"].(float64) != 200 {
		t.Errorf("approved image: %v", resp)
	}
	// og-agentd's own screenshot approval, answered yes.
	ap.set(func(f *fakeApprover) {
		f.byID["ap_shot"] = &corelink.Approval{ID: "ap_shot", State: corelink.StateAnswered, Answer: &corelink.Answer{Role: corelink.RoleApprove}}
	})
	if resp := send(upload("ap_shot")); resp["status"].(float64) != 200 {
		t.Errorf("agent's approved screenshot: %v", resp)
	}
	if got := len(h.up.got) - n; got != 2 {
		t.Errorf("uploads that left: %d, want 2", got)
	}

	// Chat: the user attached it, no approval is raised.
	uid := uint32(os.Getuid()) //nolint:gosec // uids fit uint32
	chatAp := &fakeApprover{byID: map[string]*corelink.Approval{}}
	chat := startWith(t, Mask, func(c *Config) { c.Callers = []CallerRule{{UID: &uid, Class: "chat"}} }, nil, chatAp)
	cf, err := os.Open(png)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cf.Close() }()
	if resp := chat.callFD(upload(""), int(cf.Fd())); resp["status"].(float64) != 200 || len(chat.up.got) != 1 {
		t.Errorf("chat attachment: %v", resp)
	}
	if chatAp.raisedN() != 0 {
		t.Error("an approval was raised for a chat attachment")
	}

	// Without OG Core nobody can approve: nothing leaves.
	h2 := start(t, Mask, nil)
	f, _ := os.Open(png)
	defer func() { _ = f.Close() }()
	if resp := h2.callFD(upload(""), int(f.Fd())); resp["refused"] != "core_unavailable" || len(h2.up.got) != 0 {
		t.Errorf("no approver: %v", resp)
	}
}

func TestCallerNotAllowed(t *testing.T) {
	other := uint32(os.Getuid() + 1) //nolint:gosec // uids fit uint32
	h := start(t, Passthrough, func(c *Config) { c.Callers = []CallerRule{{UID: &other, Class: "agent"}} })
	resp := h.call(`{"source":{"region_id":"global"},"method":"GET","path":"/x","egress":{}}`)
	if resp["refused"] != "caller_not_allowed" {
		t.Errorf("resp = %v", resp)
	}
	if len(h.up.got) != 0 {
		t.Error("refused caller reached the upstream")
	}
}

func TestRegionHostsLearnedFromGlobal(t *testing.T) {
	h := start(t, Passthrough, func(c *Config) { c.AllowHTTP = []string{"127.0.0.1", "region.localhost"} })
	regionURL := "http://region.localhost:" + portOf(h.up.srv.URL) + "/v1/agents/threads/thr-1/events"
	resp := h.call(fmt.Sprintf(`{"source":{"adapter":"chat"},"method":"GET","url":%q,"egress":{}}`, regionURL))
	if resp["refused"] != "destination_not_allowed" {
		t.Fatalf("unknown region host allowed: %v", resp)
	}
	resp = h.call(`{"source":{"region_id":"global","adapter":"chat"},"method":"POST","path":"/api/v1/agents/threads/thr-1/events-token","body":{},"egress":{"kind":"token"}}`)
	if resp["status"].(float64) != 200 {
		t.Fatalf("events-token: %v", resp)
	}
	resp = h.call(fmt.Sprintf(`{"source":{"adapter":"chat"},"method":"GET","url":%q,"query":{"since":5,"wait":15},"egress":{"kind":"poll"},"timeout_ms":25000}`, regionURL))
	if resp["status"].(float64) != 200 {
		t.Fatalf("learned region host refused: %v", resp)
	}
	if q := h.up.last().Query; !strings.Contains(q, "since=5") || !strings.Contains(q, "wait=15") {
		t.Errorf("query = %q", q)
	}
	if row := h.rows.last(t); row.Destination != "region.localhost" || row.Content {
		t.Errorf("row = %+v", row)
	}
}

func TestAppqTenancyTokenInjected(t *testing.T) {
	h := start(t, Passthrough, nil)
	if err := os.MkdirAll(filepath.Join(h.dir, "appq"), 0o700); err != nil {
		t.Fatal(err)
	}
	pkg := fmt.Sprintf(`{"app":{"endpoints":{"hook":"%[1]s/api/v1/hooks/apps/app_1","commands":"%[1]s/api/v1/hooks/apps/app_1/commands"}},"client":{"auth":{"header":"X-Outgate-Hook-Token"}},"join":{"participant":"phone","token":"tok-synthetic"}}`, h.up.srv.URL)
	if err := os.WriteFile(filepath.Join(h.dir, "appq", "travel.ogpkg"), []byte(pkg), 0o600); err != nil {
		t.Fatal(err)
	}
	resp := h.call(`{"source":{"account_id":"phone","region_id":"appq:travel","adapter":"appq"},"method":"POST","path":"/commands/pop","body":{},"egress":{"kind":"poll"},"timeout_ms":10000}`)
	if resp["status"].(float64) != 200 {
		t.Fatalf("resp = %v", resp)
	}
	got := h.up.last()
	if got.Path != "/api/v1/hooks/apps/app_1/commands/pop" || got.Header.Get("X-Outgate-Hook-Token") != "tok-synthetic" {
		t.Errorf("upstream got %+v", got)
	}
	resp = h.call(`{"source":{"account_id":"phone","region_id":"appq:travel","adapter":"appq"},"method":"POST","path":"/?hook=events","body":{"kind":"gate.open"},"egress":{"kind":"gate"}}`)
	if resp["status"].(float64) != 200 || h.up.last().Query != "hook=events" {
		t.Errorf("hook fire: %v %+v", resp, h.up.last())
	}

	uid := uint32(os.Getuid()) //nolint:gosec // uids fit uint32
	chat := start(t, Passthrough, func(c *Config) { c.Callers = []CallerRule{{UID: &uid, Class: "chat"}} })
	if err := os.MkdirAll(filepath.Join(chat.dir, "appq"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(chat.dir, "appq", "travel.ogpkg"), []byte(pkg), 0o600); err != nil {
		t.Fatal(err)
	}
	resp = chat.call(`{"source":{"region_id":"appq:travel","adapter":"chat"},"method":"POST","path":"/commands/pop","body":{},"egress":{"kind":"poll"}}`)
	if resp["refused"] != "destination_not_allowed" || len(chat.up.got) != 0 {
		t.Errorf("chat used the agent's tenancy: %v", resp)
	}
}

func TestUploadMultipart(t *testing.T) {
	ap := &fakeApprover{
		byID:   map[string]*corelink.Approval{"ap_1": {ID: "ap_1", State: corelink.StateAnswered, Answer: &corelink.Answer{Role: corelink.RoleApprove}}},
		answer: &corelink.Answer{Role: corelink.RoleApprove, Choices: []corelink.Choice{{Item: "image", Treatment: corelink.TreatReal}}},
	}
	h := startWith(t, Passthrough, nil, nil, ap)
	up := filepath.Join(h.dir, "uploads")
	_ = os.MkdirAll(up, 0o700)
	png := filepath.Join(up, "step-3.png")
	_ = os.WriteFile(png, []byte("\x89PNG synthetic"), 0o600)
	resp := h.call(fmt.Sprintf(`{"source":{"region_id":"global","adapter":"devq"},"method":"POST","path":"/api/v1/agents/devices/d1/uploads","body":{"lane_id":"ln_1","step_index":3},"file":%q,"egress":{"kind":"upload","approval_id":"ap_1"}}`, png))
	if resp["status"].(float64) != 200 {
		t.Fatalf("resp = %v", resp)
	}
	got := h.up.last()
	mt, params, _ := mime.ParseMediaType(got.ContentType)
	if mt != "multipart/form-data" {
		t.Fatalf("content type %q", got.ContentType)
	}
	mr := multipart.NewReader(strings.NewReader(got.Body), params["boundary"])
	parts := map[string]string{}
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		b, _ := io.ReadAll(p)
		parts[p.FormName()] = string(b)
	}
	if parts["lane_id"] != "ln_1" || parts["step_index"] != "3" || parts["file"] != "\x89PNG synthetic" {
		t.Errorf("parts = %v", parts)
	}
	if row := h.rows.last(t); row.Kind != "upload" || row.ApprovalID != "ap_1" {
		t.Errorf("row = %+v", row)
	}
	resp = h.call(`{"source":{"region_id":"global","adapter":"devq"},"method":"POST","path":"/x","file":"/etc/hosts","egress":{"kind":"upload"}}`)
	if resp["refused"] != "bad_body" {
		t.Errorf("file outside upload dirs: %v", resp)
	}

	// The same upload with the file passed as a descriptor (SCM_RIGHTS), from anywhere.
	other := filepath.Join(h.dir, "elsewhere.png")
	_ = os.WriteFile(other, []byte("\x89PNG\r\n\x1a\n synthetic"), 0o600)
	f, err := os.Open(other)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	resp = h.callFD(`{"source":{"region_id":"global","adapter":"devq"},"method":"POST","path":"/api/v1/agents/devices/d1/uploads","body":{"lane_id":"ln_2"},"file":"fd:0","egress":{"kind":"upload"}}`, int(f.Fd()))
	if resp["status"].(float64) != 200 {
		t.Fatalf("fd upload: %v", resp)
	}
	if got := h.up.last(); !strings.Contains(got.Body, "synthetic") || !strings.Contains(got.Body, `filename="upload.png"`) {
		t.Errorf("fd upload body = %q", got.Body)
	}
	resp = h.call(`{"source":{"region_id":"global","adapter":"devq"},"method":"POST","path":"/x","file":"fd:0","egress":{"kind":"upload"}}`)
	if resp["refused"] != "bad_body" {
		t.Errorf("missing descriptor: %v", resp)
	}
}

func TestResponseEncodings(t *testing.T) {
	h := start(t, Passthrough, nil)
	resp := h.call(`{"source":{"region_id":"global"},"method":"GET","path":"/text","egress":{}}`)
	if resp["body_text"] != "plain words" || resp["headers"].(map[string]any)["Content-Type"] != "text/plain" {
		t.Errorf("text: %v", resp)
	}
}

func TestOnDeviceModelFront(t *testing.T) {
	dir := t.TempDir()
	modelSock := filepath.Join(dir, "model.sock")
	mln, err := net.Listen("unix", modelSock)
	if err != nil {
		t.Fatal(err)
	}
	model := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; i < 3; i++ {
			_, _ = fmt.Fprintf(w, "data: {\"i\":%d}\n\n", i)
			w.(http.Flusher).Flush()
		}
	})}
	go func() { _ = model.Serve(mln) }()
	t.Cleanup(func() { _ = model.Close() })

	h := start(t, Mask, func(c *Config) { c.ModelSocket = modelSock })
	front := filepath.Join(dir, "front.sock")
	fln, err := ListenPath(front, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.srv.ServeModel(ctx, fln) }()
	cl := &http.Client{Transport: unixTransport(front)}
	resp, err := cl.Post("http://x/v1/chat/completions", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(b), `data: {"i":2}`) {
		t.Fatalf("stream = %q", b)
	}
	row := h.rows.last(t)
	if !row.OnDevice || row.Kind != "llm" || row.Destination != "on-device model" || row.BytesIn != int64(len(b)) || row.BytesOut == 0 {
		t.Errorf("row = %+v", row)
	}
	if ledger.Outcome(&row) != "ON_DEVICE" {
		t.Errorf("outcome = %s", ledger.Outcome(&row))
	}
	if r2, err := cl.Get("http://x/slots"); err != nil || r2.StatusCode != 404 {
		t.Errorf("unlisted model path: %v %v", r2, err)
	}

	gresp := h.call(`{"source":{"region_id":"on-device","adapter":"local"},"method":"POST","path":"/v1/chat/completions","body":{"messages":[]},"egress":{}}`)
	if gresp["status"].(float64) != 200 {
		t.Errorf("on-device via the gate socket: %v", gresp)
	}
	if row := h.rows.last(t); !row.OnDevice || row.Blocked {
		t.Errorf("on-device row = %+v", row)
	}
}

func TestWireRejectsBadInput(t *testing.T) {
	h := start(t, Passthrough, nil)
	if resp := h.call(`not json`); resp["refused"] != "bad_request" {
		t.Errorf("resp = %v", resp)
	}
	if resp := h.call(`{"source":{"region_id":"global"},"method":"TRACE","path":"/x","egress":{}}`); resp["refused"] != "bad_method" {
		t.Errorf("resp = %v", resp)
	}
}

func TestCallerByPackage(t *testing.T) {
	uid := os.Getuid()
	list := filepath.Join(t.TempDir(), "packages.list")
	h := start(t, Passthrough, func(c *Config) {
		c.Callers = []CallerRule{{Package: "ai.outgate.chat", Class: "chat"}}
		c.PackagesList = list
	})
	write := func(pkg string) {
		line := fmt.Sprintf("%s %d 0 /data/user/0/%s platform 3003\n", pkg, uid, pkg)
		if err := os.WriteFile(list, []byte(line), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("com.example.other")
	if resp := h.call(`{"op":"health"}`); resp["refused"] != "caller_not_allowed" {
		t.Errorf("another package: %v", resp)
	}
	time.Sleep(10 * time.Millisecond)
	write("ai.outgate.chat")
	if resp := h.call(`{"op":"health"}`); resp["status"].(float64) != 200 {
		t.Errorf("chat: %v", resp)
	}
}

func TestUnreadablePackagesListIsReported(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any file; peer.TestPackagesListUnreadableByTheGate covers it as another uid")
	}
	uid := uint32(os.Getuid()) //nolint:gosec // uids fit uint32
	list := filepath.Join(t.TempDir(), "packages.list")
	if err := os.WriteFile(list, []byte(fmt.Sprintf("ai.outgate.chat %d 0 /x platform 3003\n", uid)), 0o040); err != nil { //nolint:gosec // unreadable on purpose
		t.Fatal(err)
	}
	h := start(t, Passthrough, func(c *Config) {
		c.Callers = []CallerRule{{Package: "ai.outgate.chat", Class: "chat"}, {UID: &uid, Class: "debug"}}
		c.PackagesList = list
	})
	if err := h.srv.CheckCallers(); err == nil {
		t.Error("CheckCallers accepted an unreadable list")
	}
	resp := h.call(`{"op":"health"}`)
	body := resp["body"].(map[string]any)
	if got, _ := body["packages_list"].(string); !strings.Contains(got, "permission denied") {
		t.Errorf("health packages_list = %v", body["packages_list"])
	}
}
