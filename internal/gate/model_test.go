package gate

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/ledger"
)

// fakeLlama is one llama.cpp server instance; it answers with its alias.
type fakeLlama struct {
	alias   string
	loading bool
	hang    bool
	release chan struct{}

	mu   sync.Mutex
	hits []llamaHit
}

type llamaHit struct {
	Method, Path, Query, Body string
	Length                    int64
}

func (f *fakeLlama) serve(t *testing.T, sock string) *fakeLlama {
	t.Helper()
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.hits = append(f.hits, llamaHit{r.Method, r.URL.Path, r.URL.RawQuery, string(b), r.ContentLength})
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/health":
			if f.loading {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, `{"error":{"code":503,"message":"Loading model","type":"unavailable_error"}}`)
				return
			}
			_, _ = fmt.Fprintf(w, `{"status":"ok","alias":%q}`, f.alias)
		case "/v1/models":
			if f.hang {
				<-r.Context().Done()
				return
			}
			_, _ = fmt.Fprintf(w, `{"object":"list","data":[{"id":%q,"object":"model","owned_by":"llamacpp"}]}`, f.alias)
		default:
			if !strings.Contains(string(b), `"stream":true`) {
				_, _ = fmt.Fprintf(w, `{"object":"chat.completion","model":%q}`, f.alias)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			for i := 0; i < 3; i++ {
				_, _ = fmt.Fprintf(w, "data: {\"model\":%q,\"i\":%d}\n\n", f.alias, i)
				w.(http.Flusher).Flush()
				if i == 0 && f.release != nil {
					select {
					case <-f.release:
					case <-time.After(5 * time.Second):
					}
				}
			}
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return f
}

func (f *fakeLlama) seen() []llamaHit {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.hits)
}

// rowsAfter waits for the n-th ledger row and returns them all.
func (r *rec) rowsAfter(t *testing.T, n int) []ledger.Row {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		rows := slices.Clone(r.rows)
		r.mu.Unlock()
		if len(rows) >= n {
			return rows
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("fewer than %d ledger rows", n)
	return nil
}

func (r *rec) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.rows)
}

// twoModels serves og-local and og-local-agent; a nil mutate leaves them plain.
func twoModels(t *testing.T, mutate func(local, agent *fakeLlama)) (sockets map[string]string, local, agent *fakeLlama) {
	t.Helper()
	dir := t.TempDir()
	local, agent = &fakeLlama{alias: "og-local"}, &fakeLlama{alias: "og-local-agent"}
	if mutate != nil {
		mutate(local, agent)
	}
	sockets = map[string]string{"og-local": filepath.Join(dir, "model.sock"), "og-local-agent": filepath.Join(dir, "agent.sock")}
	local.serve(t, sockets["og-local"])
	agent.serve(t, sockets["og-local-agent"])
	return sockets, local, agent
}

// startFront starts the gate with these model sockets and its model front.
func startFront(t *testing.T, sockets map[string]string, mutate func(*Config)) (*harness, *http.Client) {
	t.Helper()
	h := start(t, Mask, func(c *Config) {
		c.ModelSockets = sockets
		if mutate != nil {
			mutate(c)
		}
	})
	front := filepath.Join(h.dir, "front.sock")
	fln, err := ListenPath(front, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = h.srv.ServeModel(ctx, fln) }()
	return h, &http.Client{Transport: unixTransport(front)}
}

func frontDo(t *testing.T, cl *http.Client, method, path string, body io.Reader) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, "http://x"+path, body)
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(b)
}

func TestModelFrontRoutesByModel(t *testing.T) {
	sockets, local, agent := twoModels(t, nil)
	h, cl := startFront(t, sockets, nil)
	cases := []struct{ body, want, dest string }{
		{`{"messages":[{"role":"user","content":"hi"}]}`, "og-local", "on-device model"},
		{`{"model":null,"messages":[]}`, "og-local", "on-device model"},
		{`{"model":"og-local","messages":[]}`, "og-local", "on-device model"},
		{`{"Model":"og-local-agent","messages":[]}`, "og-local", "on-device model"},
		{"{ \"messages\" : [{\"content\":\"h\\u00e9 \\\"x\\\"\"}],\n  \"model\":\"og-local-agent\" }", "og-local-agent", "on-device/og-local-agent"},
	}
	for i, c := range cases {
		code, got := frontDo(t, cl, "POST", "/v1/chat/completions", strings.NewReader(c.body))
		if code != 200 || !strings.Contains(got, `"model":"`+c.want+`"`) {
			t.Errorf("%s: %d %s", c.body, code, got)
		}
		row := h.rows.rowsAfter(t, i+1)[i]
		if row.Destination != c.dest || !row.OnDevice || row.Class != "on-device" || row.BytesOut != int64(len(c.body)) || row.Blocked {
			t.Errorf("%s: row = %+v", c.body, row)
		}
	}
	// A chunked body is buffered and forwarded with its length.
	body := `{"model":"og-local-agent","messages":[{"role":"user","content":"chunked"}]}`
	if code, got := frontDo(t, cl, "POST", "/v1/chat/completions", io.MultiReader(strings.NewReader(body))); code != 200 || !strings.Contains(got, "og-local-agent") {
		t.Errorf("chunked: %d %s", code, got)
	}
	l, a := local.seen(), agent.seen()
	if len(l) != 4 || len(a) != 2 {
		t.Fatalf("og-local saw %d, og-local-agent %d", len(l), len(a))
	}
	for i, hit := range l {
		if hit.Body != cases[i].body || hit.Length != int64(len(cases[i].body)) {
			t.Errorf("og-local got %+v", hit)
		}
	}
	if a[0].Body != cases[4].body || a[0].Length != int64(len(cases[4].body)) || a[1].Body != body || a[1].Length != int64(len(body)) {
		t.Errorf("og-local-agent got %+v", a)
	}

	n := len(cases) + 1
	if row := h.rows.rowsAfter(t, n)[n-1]; row.Destination != "on-device/og-local-agent" || row.BytesOut != int64(len(body)) {
		t.Errorf("chunked: row = %+v", row)
	}
	for _, bad := range []string{`{"model":"gpt-4o","messages":[]}`, `{"model":"OG-LOCAL"}`, `{"model":["og-local-agent"]}`, `{"model":"og-local-agent ","messages":[]}`} {
		code, got := frontDo(t, cl, "POST", "/v1/chat/completions", strings.NewReader(bad))
		var e map[string]string
		if code != 404 || json.Unmarshal([]byte(got), &e) != nil || e["error"] != "unknown_model" || e["detail"] == "" {
			t.Errorf("%s: %d %s", bad, code, got)
		}
	}
	if len(local.seen())+len(agent.seen()) != 6 {
		t.Error("an unknown model reached an instance")
	}
	time.Sleep(20 * time.Millisecond)
	if h.rows.count() != n {
		t.Error("unknown models recorded")
	}
}

func TestModelFrontHealthByAlias(t *testing.T) {
	sockets, local, agent := twoModels(t, func(_, agent *fakeLlama) { agent.loading = true })
	sockets["og-local-down"] = filepath.Join(filepath.Dir(sockets["og-local"]), "down.sock")
	h, cl := startFront(t, sockets, nil)
	if code, got := frontDo(t, cl, "GET", "/health", nil); code != 200 || !strings.Contains(got, `"alias":"og-local"`) {
		t.Errorf("default: %d %s", code, got)
	}
	if code, got := frontDo(t, cl, "GET", "/health?model=og-local", nil); code != 200 || !strings.Contains(got, `"alias":"og-local"`) {
		t.Errorf("og-local: %d %s", code, got)
	}
	if code, got := frontDo(t, cl, "GET", "/health?model=og-local-agent", nil); code != 503 || !strings.Contains(got, "Loading model") {
		t.Errorf("og-local-agent loading: %d %s", code, got)
	}
	if code, got := frontDo(t, cl, "GET", "/health?model=og-local-down", nil); code != 502 || !strings.Contains(got, `"error":"model_unreachable"`) {
		t.Errorf("down: %d %s", code, got)
	}
	if code, got := frontDo(t, cl, "GET", "/health?model=nope", nil); code != 404 || !strings.Contains(got, `"error":"unknown_model"`) {
		t.Errorf("unknown: %d %s", code, got)
	}
	if len(local.seen()) != 2 || len(agent.seen()) != 1 || agent.seen()[0].Path != "/health" {
		t.Errorf("og-local saw %v, og-local-agent %v", local.seen(), agent.seen())
	}
	if n := h.rows.count(); n != 0 {
		t.Errorf("%d ledger rows for health checks", n)
	}
}

func TestModelFrontListsAllModels(t *testing.T) {
	sockets, _, _ := twoModels(t, func(_, agent *fakeLlama) { agent.hang = true })
	sockets["og-local-down"] = filepath.Join(filepath.Dir(sockets["og-local"]), "down.sock")
	h, cl := startFront(t, sockets, nil)
	ids := func(body string) []string {
		var l struct {
			Object string
			Data   []struct{ ID string }
		}
		if err := json.Unmarshal([]byte(body), &l); err != nil || l.Object != "list" || l.Data == nil {
			t.Fatalf("list %s: %v", body, err)
		}
		var out []string
		for _, d := range l.Data {
			out = append(out, d.ID)
		}
		return out
	}
	start := time.Now()
	code, got := frontDo(t, cl, "GET", "/v1/models", nil)
	if code != 200 || !slices.Equal(ids(got), []string{"og-local"}) {
		t.Errorf("one up, one hung, one down: %d %s", code, got)
	}
	if d := time.Since(start); d > modelListTimeout+time.Second {
		t.Errorf("list took %s", d)
	}

	sockets2, _, _ := twoModels(t, nil)
	_, cl2 := startFront(t, sockets2, nil)
	if code, got := frontDo(t, cl2, "GET", "/v1/models", nil); code != 200 || !slices.Equal(ids(got), []string{"og-local", "og-local-agent"}) {
		t.Errorf("both up: %d %s", code, got)
	}

	dir := t.TempDir()
	_, cl3 := startFront(t, map[string]string{"og-local": filepath.Join(dir, "a.sock"), "og-local-agent": filepath.Join(dir, "b.sock")}, nil)
	if code, got := frontDo(t, cl3, "GET", "/v1/models", nil); code != 502 || !strings.Contains(got, `"error":"model_unreachable"`) {
		t.Errorf("none up: %d %s", code, got)
	}
	if n := h.rows.count(); n != 0 {
		t.Errorf("%d ledger rows for model lists", n)
	}
}

func TestModelFrontStreamsFromAgent(t *testing.T) {
	release := make(chan struct{})
	sockets, local, _ := twoModels(t, func(_, agent *fakeLlama) { agent.release = release })
	h, cl := startFront(t, sockets, nil)
	req, _ := http.NewRequest("POST", "http://x/v1/chat/completions", strings.NewReader(`{"model":"og-local-agent","stream":true,"messages":[]}`))
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("resp = %d %v", resp.StatusCode, resp.Header)
	}
	rd := bufio.NewReader(resp.Body)
	first, err := rd.ReadString('\n')
	if err != nil || first != "data: {\"model\":\"og-local-agent\",\"i\":0}\n" {
		t.Fatalf("first chunk before the rest: %q %v", first, err)
	}
	close(release)
	rest, _ := io.ReadAll(rd)
	if !strings.Contains(string(rest), `data: {"model":"og-local-agent","i":2}`) {
		t.Fatalf("rest = %q", rest)
	}
	row := h.rows.last(t)
	if row.Destination != "on-device/og-local-agent" || row.Kind != "llm" || row.BytesIn != int64(len(first)+len(rest)) || ledger.Outcome(&row) != "ON_DEVICE" {
		t.Errorf("row = %+v", row)
	}
	if len(local.seen()) != 0 {
		t.Errorf("og-local saw %v", local.seen())
	}
}

func TestModelFrontModelsCallerPicksInstance(t *testing.T) {
	sockets, local, agent := twoModels(t, nil)
	uid := uint32(os.Getuid()) //nolint:gosec // uids fit uint32
	h, cl := startFront(t, sockets, func(c *Config) { c.Callers = []CallerRule{{UID: &uid, Class: "models"}} })
	if code, got := frontDo(t, cl, "GET", "/health?model=og-local-agent", nil); code != 200 || !strings.Contains(got, `"alias":"og-local-agent"`) {
		t.Errorf("GET /health?model=og-local-agent: %d %s", code, got)
	}
	if code, got := frontDo(t, cl, "GET", "/v1/models", nil); code != 200 || !strings.Contains(got, `"og-local-agent"`) || !strings.Contains(got, `"og-local"`) {
		t.Errorf("GET /v1/models: %d %s", code, got)
	}
	if code, got := frontDo(t, cl, "GET", "/health?model=nope", nil); code != 404 || !strings.Contains(got, "unknown_model") {
		t.Errorf("unknown: %d %s", code, got)
	}
	for _, r := range [][2]string{{"POST", "/v1/chat/completions"}, {"POST", "/health?model=og-local-agent"}, {"GET", "/slots?model=og-local-agent"}} {
		if code, got := frontDo(t, cl, r[0], r[1], strings.NewReader(`{"model":"og-local-agent","messages":[]}`)); code != 403 || !strings.Contains(got, "caller_not_allowed") {
			t.Errorf("%s %s: %d %s", r[0], r[1], code, got)
		}
	}
	for _, f := range []*fakeLlama{local, agent} {
		for _, hit := range f.seen() {
			if hit.Method != "GET" || (hit.Path != "/health" && hit.Path != "/v1/models") {
				t.Errorf("%s saw %+v", f.alias, hit)
			}
		}
	}
	if n := h.rows.count(); n != 0 {
		t.Errorf("%d ledger rows", n)
	}
}

func TestOnDeviceDestinationRoutesByModel(t *testing.T) {
	sockets, local, agent := twoModels(t, nil)
	h := start(t, Mask, func(c *Config) { c.ModelSockets = sockets })
	body := `{"model":"og-local-agent","messages":[{"role":"user","content":"hé"}]}`
	resp := h.call(`{"source":{"region_id":"on-device","adapter":"local"},"method":"POST","path":"/v1/chat/completions","body":` + body + `,"egress":{}}`)
	if resp["status"].(float64) != 200 || resp["body"].(map[string]any)["model"] != "og-local-agent" || resp["class"] != "on-device" {
		t.Errorf("og-local-agent: %v", resp)
	}
	if a := agent.seen(); len(a) != 1 || a[0].Body != body {
		t.Errorf("og-local-agent got %+v", a)
	}
	if row := h.rows.last(t); row.Destination != "on-device/og-local-agent" || !row.OnDevice || row.Blocked || row.BytesOut != int64(len(body)) {
		t.Errorf("row = %+v", row)
	}

	resp = h.call(`{"source":{"region_id":"on-device"},"method":"POST","path":"/v1/chat/completions","body":{"messages":[]},"egress":{}}`)
	if resp["status"].(float64) != 200 || resp["body"].(map[string]any)["model"] != "og-local" {
		t.Errorf("default: %v", resp)
	}
	if row := h.rows.rowsAfter(t, 2)[1]; row.Destination != "on-device model" {
		t.Errorf("row = %+v", row)
	}

	resp = h.call(`{"source":{"region_id":"on-device"},"method":"POST","path":"/v1/chat/completions","body":{"model":"gpt-4o"},"egress":{}}`)
	if resp["refused"] != "unknown_model" || resp["status"].(float64) != 404 || resp["body"].(map[string]any)["error"] != "unknown_model" {
		t.Errorf("unknown: %v", resp)
	}
	if row := h.rows.rowsAfter(t, 3)[2]; !row.Blocked || row.BlockReason != "unknown_model" || row.Status != 404 {
		t.Errorf("row = %+v", row)
	}

	resp = h.call(`{"source":{"region_id":"on-device"},"method":"GET","path":"/health","query":{"model":"og-local-agent"},"egress":{}}`)
	if resp["status"].(float64) != 200 || resp["body"].(map[string]any)["alias"] != "og-local-agent" {
		t.Errorf("health: %v", resp)
	}
	resp = h.call(`{"source":{"region_id":"on-device"},"method":"GET","path":"/health?model=nope","egress":{}}`)
	if resp["refused"] != "unknown_model" {
		t.Errorf("health unknown: %v", resp)
	}

	resp = h.call(`{"source":{"region_id":"on-device"},"method":"GET","path":"/v1/models","egress":{}}`)
	b, _ := json.Marshal(resp["body"])
	if resp["status"].(float64) != 200 || !strings.Contains(string(b), `"id":"og-local"`) || !strings.Contains(string(b), `"id":"og-local-agent"`) {
		t.Errorf("models: %v", resp)
	}
	if len(local.seen()) != 2 || len(agent.seen()) != 3 {
		t.Errorf("og-local saw %v, og-local-agent %v", local.seen(), agent.seen())
	}
}

func TestModelSocketsConfig(t *testing.T) {
	ok := []Config{
		{ModelSocket: "/run/model.sock"},
		{ModelSockets: map[string]string{"og-local": "/run/model.sock", "og-local-agent": "/run/agent.sock"}},
		{ModelSocket: "/run/model.sock", ModelSockets: map[string]string{"og-local": "/run/model.sock", "og-local-agent": "/run/agent.sock"}},
		{ModelSockets: map[string]string{"og-local": "/run/model.sock", "a": "/a", "x9._-y": "/b", strings.Repeat("a", 64): "/c"}},
		{},
	}
	for _, c := range ok {
		if err := c.Validate(); err != nil {
			t.Errorf("%+v: %v", c, err)
		}
	}
	bad := map[string]Config{
		"conflicting model_socket": {ModelSocket: "/run/other.sock", ModelSockets: map[string]string{"og-local": "/run/model.sock"}},
		"no og-local":              {ModelSockets: map[string]string{"og-local-agent": "/run/agent.sock"}},
		"upper-case alias":         {ModelSockets: map[string]string{"og-local": "/m", "Agent": "/a"}},
		"leading dash":             {ModelSockets: map[string]string{"og-local": "/m", "-agent": "/a"}},
		"slash in alias":           {ModelSockets: map[string]string{"og-local": "/m", "og/agent": "/a"}},
		"empty alias":              {ModelSockets: map[string]string{"og-local": "/m", "": "/a"}},
		"long alias":               {ModelSockets: map[string]string{"og-local": "/m", strings.Repeat("a", 65): "/a"}},
		"relative socket":          {ModelSockets: map[string]string{"og-local": "/m", "og-local-agent": "run/agent.sock"}},
		"relative model_socket":    {ModelSocket: "model.sock"},
	}
	for name, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	if m := (&Config{ModelSocket: "/run/model.sock"}).Models(); len(m) != 1 || m["og-local"] != "/run/model.sock" {
		t.Errorf("model_socket alone: %v", m)
	}
	path := filepath.Join(t.TempDir(), "gate.conf")
	conf := `{"callers":[],"model_socket":"/run/model.sock","model_sockets":{"og-local":"/run/model.sock","og-local-agent":"/run/agent.sock"}}`
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(path)
	if err != nil || c.Models()["og-local-agent"] != "/run/agent.sock" || len(c.Models()) != 2 {
		t.Errorf("LoadConfig: %v %v", c.Models(), err)
	}
	if err := os.WriteFile(path, []byte(`{"model_socket":"/run/x.sock","model_sockets":{"og-local":"/run/model.sock"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "model_socket") {
		t.Errorf("LoadConfig conflict: %v", err)
	}
}

func TestModelFrontVoiceCaller(t *testing.T) {
	sockets, local, agent := twoModels(t, nil)
	uid := uint32(os.Getuid()) //nolint:gosec // uids fit uint32
	h, cl := startFront(t, sockets, func(c *Config) { c.Callers = []CallerRule{{UID: &uid, Class: "voice"}} })
	for _, body := range []string{`{"model":"og-local","messages":[]}`, `{"messages":[]}`} {
		if code, got := frontDo(t, cl, "POST", "/v1/chat/completions", strings.NewReader(body)); code != 200 || !strings.Contains(got, `"og-local"`) {
			t.Errorf("POST %s: %d %s", body, code, got)
		}
	}
	if code, got := frontDo(t, cl, "GET", "/health", nil); code != 200 || !strings.Contains(got, `"alias":"og-local"`) {
		t.Errorf("GET /health: %d %s", code, got)
	}
	for _, r := range [][3]string{
		{"POST", "/v1/chat/completions", `{"model":"og-local-agent","messages":[]}`},
		{"GET", "/health?model=og-local-agent", ""},
		{"GET", "/v1/models", ""},
		{"POST", "/health", `{"messages":[]}`},
		{"GET", "/slots", ""},
	} {
		if code, got := frontDo(t, cl, r[0], r[1], strings.NewReader(r[2])); code != 403 || !strings.Contains(got, "caller_not_allowed") {
			t.Errorf("%s %s %s: %d %s", r[0], r[1], r[2], code, got)
		}
	}
	if a := agent.seen(); len(a) != 0 {
		t.Errorf("og-local-agent saw %v", a)
	}
	if n := len(local.seen()); n != 3 {
		t.Errorf("og-local saw %d requests", n)
	}
	row := h.rows.last(t)
	if row.Caller != "voice" || row.Destination != "on-device model" || ledger.Outcome(&row) != "ON_DEVICE" || h.rows.count() != 2 {
		t.Errorf("rows = %d, last %+v", h.rows.count(), row)
	}
}

func TestModelFrontTranscribeCaller(t *testing.T) {
	sockets, local, agent := twoModels(t, nil)
	uid := uint32(os.Getuid()) //nolint:gosec // uids fit uint32
	h, cl := startFront(t, sockets, func(c *Config) { c.Callers = []CallerRule{{UID: &uid, Class: "transcribe"}} })
	for _, r := range [][3]string{
		{"POST", "/v1/chat/completions", `{"model":"og-local-agent","messages":[]}`},
		{"POST", "/v1/chat/completions", `{"model":"og-local","messages":[]}`},
		{"GET", "/health?model=og-local-agent", ""},
	} {
		if code, got := frontDo(t, cl, r[0], r[1], strings.NewReader(r[2])); code != 200 {
			t.Errorf("%s %s %s: %d %s", r[0], r[1], r[2], code, got)
		}
	}
	for _, r := range [][3]string{
		{"GET", "/v1/models", ""},
		{"POST", "/health", `{"messages":[]}`},
		{"GET", "/slots", ""},
	} {
		if code, got := frontDo(t, cl, r[0], r[1], strings.NewReader(r[2])); code != 403 || !strings.Contains(got, "caller_not_allowed") {
			t.Errorf("%s %s %s: %d %s", r[0], r[1], r[2], code, got)
		}
	}
	if n := len(agent.seen()); n != 2 {
		t.Errorf("og-local-agent saw %d requests", n)
	}
	if n := len(local.seen()); n != 1 {
		t.Errorf("og-local saw %d requests", n)
	}
	row := h.rows.last(t)
	if row.Caller != "transcribe" || ledger.Outcome(&row) != "ON_DEVICE" {
		t.Errorf("last row %+v", row)
	}
}
