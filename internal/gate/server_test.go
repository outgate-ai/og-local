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
	"testing"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/ledger"
	"github.com/outgate-ai/og-local/internal/gate/route"
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
	srv, err := New(&cfg, Options{Sinks: []ledger.Sink{rows}, Transport: regionDialer(up.srv.URL)})
	if err != nil {
		t.Fatal(err)
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
		row.StepIndex == nil || *row.StepIndex != 3 || row.Mode != "passthrough" || row.Blocked || row.Caller != "agent" {
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
		if row := h.rows.last(t); !row.Blocked {
			t.Errorf("%s: row not blocked: %+v", u, row)
		}
	}
	resp := h.call(fmt.Sprintf(`{"source":{"adapter":"chat"},"method":"GET","url":"%s/redirect","egress":{}}`, h.up.srv.URL))
	if resp["status"].(float64) != 302 {
		t.Errorf("redirect followed: %v", resp)
	}
}

func TestMaskModeFailsClosedWithoutDetector(t *testing.T) {
	h := start(t, Mask, nil)
	n := len(h.up.got)
	resp := h.call(`{"source":{"region_id":"global","adapter":"chat"},"method":"POST","path":"/api/v1/agents/threads/thr-1/events",` +
		`"body":{"kind":"input.text","payload":{"text":"hello"}},"egress":{}}`)
	if resp["refused"] != "detector_unavailable" || resp["status"].(float64) != 503 {
		t.Fatalf("content not refused: %v", resp)
	}
	if len(h.up.got) != n {
		t.Fatal("content reached the upstream")
	}
	if row := h.rows.last(t); !row.Blocked || row.BlockReason != "detector_unavailable" || row.BytesOut != 0 {
		t.Errorf("row = %+v", row)
	}
	resp = h.call(`{"source":{"region_id":"global","adapter":"chat"},"method":"GET","path":"/api/v1/agents/threads","egress":{"kind":"poll"}}`)
	if resp["status"].(float64) != 200 {
		t.Errorf("content-free GET refused: %v", resp)
	}
	resp = h.call(`{"source":{"region_id":"global","adapter":"devq"},"method":"POST","path":"/api/v1/agents/devices/d1/presence","body":{"driving":"agents"},"egress":{"kind":"presence"}}`)
	if resp["status"].(float64) != 200 {
		t.Errorf("presence refused: %v", resp)
	}
	resp = h.call(fmt.Sprintf(`{"source":{"adapter":"chat"},"method":"POST","url":"http://localhost:%s/oauth2/token","body_text":"grant_type=refresh_token","content_type":"application/x-www-form-urlencoded","egress":{}}`, portOf(h.up.srv.URL)))
	if resp["status"].(float64) != 200 {
		t.Errorf("token refresh refused: %v", resp)
	}
	health := h.call(`{"op":"health"}`)
	body := health["body"].(map[string]any)
	if body["content"].(map[string]any)["ready"] != false || body["mode"] != "mask" {
		t.Errorf("health = %v", body)
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
}

func TestUploadMultipart(t *testing.T) {
	h := start(t, Passthrough, nil)
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
