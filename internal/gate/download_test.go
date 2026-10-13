package gate

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/ledger"
)

// modelData is a synthetic model file, larger than one read of the gate's copy loop.
var modelData = func() []byte {
	b := make([]byte, 600_000)
	for i := range b {
		b[i] = byte(i*7 + i>>9)
	}
	return b
}()

var modelSize = int64(len(modelData))

type mirrorHit struct {
	Path, Range, UserAgent, AcceptEncoding string
}

// mirror is a TLS model mirror whose file names choose its behaviour.
type mirror struct {
	srv  *httptest.Server
	mu   sync.Mutex
	hits []mirrorHit
}

func newMirror(t *testing.T) *mirror {
	m := &mirror{}
	m.srv = httptest.NewTLSServer(http.HandlerFunc(m.serve))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mirror) serve(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	m.hits = append(m.hits, mirrorHit{r.URL.Path, r.Header.Get("Range"), r.Header.Get("User-Agent"), r.Header.Get("Accept-Encoding")})
	m.mu.Unlock()
	length := strconv.Itoa(len(modelData))
	switch path.Base(r.URL.Path) {
	case "model.bin":
		http.ServeContent(w, r, "model.bin", time.Time{}, bytes.NewReader(modelData))
	case "norange.bin":
		w.Header().Set("Content-Length", length)
		_, _ = w.Write(modelData)
	case "long.bin":
		_, _ = w.Write(modelData)
		_, _ = w.Write([]byte("bytes past the end of the file"))
	case "badlength.bin":
		w.Header().Set("Content-Length", strconv.Itoa(len(modelData)-1))
		_, _ = w.Write(modelData[:len(modelData)-1])
	case "badrange.bin":
		w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", len(modelData)-1, len(modelData)))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(modelData)
	case "redirect.bin":
		http.Redirect(w, r, "/m/model.bin", http.StatusFound)
	case "away.bin":
		http.Redirect(w, r, "https://models.example.test/model.bin", http.StatusFound)
	case "loop.bin":
		http.Redirect(w, r, r.URL.Path, http.StatusFound)
	case "missing.bin":
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write(bytes.Repeat([]byte("not here "), 300))
	case "stall.bin":
		w.Header().Set("Content-Length", length)
		_, _ = w.Write(modelData[:1000])
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	case "slow.bin":
		w.Header().Set("Content-Length", length)
		for i := 0; i < 4; i++ {
			_, _ = w.Write(modelData[i*len(modelData)/4 : (i+1)*len(modelData)/4])
			w.(http.Flusher).Flush()
			time.Sleep(200 * time.Millisecond)
		}
	default:
		http.NotFound(w, r)
	}
}

func (m *mirror) seen() []mirrorHit {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]mirrorHit(nil), m.hits...)
}

func setMirror(t *testing.T, base string) {
	t.Setenv("OGL_PROP_"+strings.ReplaceAll(MirrorProp, ".", "_"), base)
}

// startModels starts a gate for one caller class whose upstream transport trusts the
// mirror (idle 0: the gate's default idle timeout).
func startModels(t *testing.T, m *mirror, class string, idle time.Duration, mutate func(*Config)) *harness {
	t.Helper()
	uid := uint32(os.Getuid()) //nolint:gosec // uids fit uint32
	return startOpts(t, Mask, func(c *Config) {
		c.Callers = []CallerRule{{UID: &uid, Class: class}}
		if mutate != nil {
			mutate(c)
		}
	}, nil, nil, func(o *Options) {
		o.Transport = m.srv.Client().Transport
		o.DownloadIdle = idle
	})
}

// partFile is the caller's partial file, holding prefix, opened read-write.
func partFile(t *testing.T, prefix []byte) *os.File {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(t.TempDir(), "model.part"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := f.Write(prefix); err != nil {
		t.Fatal(err)
	}
	return f
}

func fileBytes(t *testing.T, f *os.File) []byte {
	t.Helper()
	b, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func dlReq(p string, offset int64, timeoutMs int) string {
	return fmt.Sprintf(`{"v":1,"id":"dl-1","op":"download","path":%q,"offset":%d,"size":%d,"file":"fd:0","timeout_ms":%d}`,
		p, offset, modelSize, timeoutMs)
}

func num(v any) int64 {
	f, _ := v.(float64)
	return int64(f)
}

func TestDownloadFullFile(t *testing.T) {
	m := newMirror(t)
	setMirror(t, m.srv.URL+"/m")
	h := startModels(t, m, "models", 0, nil)
	// A stale, longer file at offset 0: it ends up exactly the model.
	f := partFile(t, bytes.Repeat([]byte{0xee}, len(modelData)+500))
	resp := h.callFD(dlReq("embeddinggemma-2/740m/model.bin", 0, 60000), int(f.Fd()))
	if resp["status"].(float64) != 200 || resp["refused"] != nil || resp["op"] != "download" || resp["class"] != "mirror" ||
		resp["id"] != "dl-1" || resp["start"] != float64(0) || num(resp["written"]) != modelSize || resp["complete"] != true {
		t.Fatalf("resp = %v", resp)
	}
	if got := fileBytes(t, f); !bytes.Equal(got, modelData) {
		t.Errorf("file: %d bytes, want the model's %d", len(got), modelSize)
	}
	hits := m.seen()
	if len(hits) != 1 || hits[0].Path != "/m/embeddinggemma-2/740m/model.bin" || hits[0].Range != "" ||
		hits[0].UserAgent != "og-gate/test" || hits[0].AcceptEncoding != "identity" {
		t.Errorf("mirror saw %+v", hits)
	}
	row := h.rows.last(t)
	if row.ID != resp["ledger"] || row.Caller != "models" || row.Destination != "127.0.0.1" || row.Class != "mirror" ||
		row.Method != "GET" || row.PathClass != "/m/embeddinggemma-2/740m/model.bin" || row.EgressKind != "model" ||
		row.Content || row.Mask != MaskNotRequired || row.BytesIn != modelSize || row.BytesOut != 0 || row.Status != 200 ||
		row.Blocked || row.Error != "" || row.OnDevice {
		t.Errorf("row = %+v", row)
	}
	if ledger.Outcome(&row) != "CLEAN" {
		t.Errorf("outcome = %s", ledger.Outcome(&row))
	}
}

func TestDownloadResumes(t *testing.T) {
	m := newMirror(t)
	setMirror(t, m.srv.URL+"/m/")
	h := startModels(t, m, "models", 0, nil)
	off := int64(250_000)
	f := partFile(t, modelData[:off])
	resp := h.callFD(dlReq("e/model.bin", off, 0), int(f.Fd()))
	if resp["status"].(float64) != 206 || num(resp["start"]) != off || num(resp["written"]) != modelSize-off || resp["complete"] != true {
		t.Fatalf("resp = %v", resp)
	}
	if got := fileBytes(t, f); !bytes.Equal(got, modelData) {
		t.Errorf("resumed file differs (%d bytes)", len(got))
	}
	if hit := m.seen()[0]; hit.Range != "bytes=250000-" || hit.Path != "/m/e/model.bin" {
		t.Errorf("mirror saw %+v", hit)
	}
	if row := h.rows.last(t); row.Status != 206 || row.BytesIn != modelSize-off || row.Blocked {
		t.Errorf("row = %+v", row)
	}

	// A mirror that ignores Range: the file is rewritten from 0.
	g := partFile(t, bytes.Repeat([]byte{0xee}, int(off)))
	resp = h.callFD(dlReq("e/norange.bin", off, 0), int(g.Fd()))
	if resp["status"].(float64) != 200 || resp["start"] != float64(0) || num(resp["written"]) != modelSize || resp["complete"] != true {
		t.Fatalf("Range ignored: %v", resp)
	}
	if got := fileBytes(t, g); !bytes.Equal(got, modelData) {
		t.Errorf("rewritten file differs (%d bytes)", len(got))
	}
	if hit := m.seen()[1]; hit.Range != "bytes=250000-" {
		t.Errorf("mirror saw %+v", hit)
	}
}

func TestDownloadSizeMismatch(t *testing.T) {
	m := newMirror(t)
	setMirror(t, m.srv.URL+"/m")
	h := startModels(t, m, "models", 0, nil)

	// A body longer than size: never written past size.
	f := partFile(t, nil)
	resp := h.callFD(dlReq("e/long.bin", 0, 0), int(f.Fd()))
	if resp["refused"] != "size_mismatch" || resp["status"].(float64) != 502 || resp["complete"] != false || num(resp["written"]) > modelSize {
		t.Fatalf("longer body: %v", resp)
	}
	if got := fileBytes(t, f); int64(len(got)) > modelSize || !bytes.Equal(got, modelData[:len(got)]) {
		t.Errorf("file holds %d bytes", len(got))
	}
	if row := h.rows.last(t); !row.Blocked || row.BlockReason != "size_mismatch" || row.Class != "mirror" || row.BytesIn > modelSize {
		t.Errorf("row = %+v", row)
	}

	// A Content-Length or Content-Range that disagrees: refused before anything is written.
	off := int64(1000)
	for _, name := range []string{"badlength.bin", "badrange.bin"} {
		g := partFile(t, modelData[:off])
		resp = h.callFD(dlReq("e/"+name, off, 0), int(g.Fd()))
		if resp["refused"] != "size_mismatch" || resp["status"].(float64) != 502 || resp["written"] != nil {
			t.Errorf("%s: %v", name, resp)
		}
		if got := fileBytes(t, g); !bytes.Equal(got, modelData[:off]) {
			t.Errorf("%s: the file changed (%d bytes)", name, len(got))
		}
		if row := h.rows.last(t); !row.Blocked || row.BlockReason != "size_mismatch" || row.BytesIn != 0 {
			t.Errorf("%s: row = %+v", name, row)
		}
	}
}

func TestDownloadMirrorNotConfigured(t *testing.T) {
	m := newMirror(t)
	h := startModels(t, m, "models", 0, nil)
	f := partFile(t, nil)
	for base, detail := range map[string]string{
		"":                                   "no model mirror configured",
		"http://mirror.test/m":               "mirror is not https",
		"https://user@mirror.test/m":         "mirror is not a plain base URL",
		"https://mirror.test/m?token=secret": "mirror is not a plain base URL",
	} {
		setMirror(t, base)
		resp := h.callFD(dlReq("e/model.bin", 0, 0), int(f.Fd()))
		if resp["refused"] != "mirror_not_configured" || resp["status"].(float64) != 503 || resp["detail"] != detail {
			t.Errorf("%q: %v", base, resp)
		}
		if row := h.rows.last(t); !row.Blocked || row.BlockReason != "mirror_not_configured" || row.Class != "mirror" {
			t.Errorf("%q: row = %+v", base, row)
		}
		mh := h.call(`{"op":"health"}`)["body"].(map[string]any)["mirror"].(map[string]any)
		if mh["configured"] != false || mh["host"] != "" {
			t.Errorf("%q: health mirror = %v", base, mh)
		}
	}
	if n := len(m.seen()); n != 0 {
		t.Errorf("the mirror was reached %d times", n)
	}
	// The property is read at each request: no restart.
	setMirror(t, m.srv.URL+"/m")
	mh := h.call(`{"op":"health"}`)["body"].(map[string]any)["mirror"].(map[string]any)
	if mh["configured"] != true || mh["host"] != "127.0.0.1" {
		t.Errorf("health mirror = %v", mh)
	}
	if resp := h.callFD(dlReq("e/model.bin", 0, 0), int(f.Fd())); resp["status"].(float64) != 200 {
		t.Errorf("after the property was set: %v", resp)
	}
}

func TestDownloadBadPath(t *testing.T) {
	m := newMirror(t)
	setMirror(t, m.srv.URL+"/m")
	h := startModels(t, m, "models", 0, nil)
	f := partFile(t, nil)
	for _, p := range []string{"", "/abs/model.bin", "../model.bin", "e/../../model.bin", "e/./model.bin", "e//model.bin",
		"model.bin?x=1", "model.bin#x", `e\model.bin`, "e/model bin", "%2e%2e/model.bin"} {
		resp := h.callFD(dlReq(p, 0, 0), int(f.Fd()))
		if resp["refused"] != "bad_path" || resp["status"].(float64) != 400 {
			t.Errorf("%q: %v", p, resp)
		}
		if row := h.rows.last(t); !row.Blocked || row.BlockReason != "bad_path" || strings.ContainsAny(row.PathClass, "?#") {
			t.Errorf("%q: row = %+v", p, row)
		}
	}
	if n := len(m.seen()); n != 0 {
		t.Errorf("the mirror was reached %d times", n)
	}
}

func TestDownloadUpstreamStatus(t *testing.T) {
	m := newMirror(t)
	setMirror(t, m.srv.URL+"/m")
	h := startModels(t, m, "models", 0, nil)
	f := partFile(t, modelData[:10])
	resp := h.callFD(dlReq("e/redirect.bin", 10, 0), int(f.Fd()))
	if resp["status"].(float64) != 302 || resp["refused"] != nil || resp["written"] != nil ||
		resp["headers"].(map[string]any)["Location"] != "/m/model.bin" {
		t.Errorf("redirect: %v", resp)
	}
	if hits := m.seen(); len(hits) != 1 {
		t.Errorf("redirect followed: %+v", hits)
	}
	resp = h.callFD(dlReq("e/missing.bin", 10, 0), int(f.Fd()))
	text, _ := resp["body_text"].(string)
	if resp["status"].(float64) != 404 || resp["refused"] != nil || len(text) == 0 || len(text) > 1024 || !strings.HasPrefix(text, "not here") {
		t.Errorf("404: %v", resp)
	}
	if row := h.rows.last(t); row.Status != 404 || row.Blocked || row.BytesIn != 0 {
		t.Errorf("row = %+v", row)
	}
	if got := fileBytes(t, f); !bytes.Equal(got, modelData[:10]) {
		t.Errorf("the file changed (%d bytes)", len(got))
	}
}

func TestDownloadCallers(t *testing.T) {
	m := newMirror(t)
	setMirror(t, m.srv.URL+"/m")
	f := partFile(t, nil)
	h := startModels(t, m, "models", 0, nil)
	for _, line := range []string{
		`{"source":{"region_id":"global"},"method":"GET","path":"/api/v1/agents/threads","egress":{}}`,
		`{"op":"ledger","limit":5}`,
		`{"op":"anything"}`,
	} {
		if resp := h.call(line); resp["refused"] != "caller_not_allowed" || resp["status"].(float64) != 403 {
			t.Errorf("models %s: %v", line, resp)
		}
	}
	if len(h.up.got) != 0 {
		t.Error("a models request reached Outgate")
	}
	if resp := h.call(`{"op":"health"}`); resp["status"].(float64) != 200 {
		t.Errorf("models health: %v", resp)
	}
	for _, class := range []string{"agent", "chat"} {
		o := startModels(t, m, class, 0, nil)
		if resp := o.callFD(dlReq("e/model.bin", 0, 0), int(f.Fd())); resp["refused"] != "caller_not_allowed" {
			t.Errorf("%s download: %v", class, resp)
		}
	}
	if n := len(m.seen()); n != 0 {
		t.Errorf("the mirror was reached %d times", n)
	}
	d := startModels(t, m, "debug", 0, nil)
	if resp := d.callFD(dlReq("e/model.bin", 0, 0), int(f.Fd())); resp["status"].(float64) != 200 || resp["complete"] != true {
		t.Errorf("debug download: %v", resp)
	}

	// The model manager admitted by its package, as gate.conf does (with its domain).
	list := filepath.Join(t.TempDir(), "packages.list")
	line := fmt.Sprintf("ai.outgate.models %d 0 /data/user/0/ai.outgate.models platform:privapp 3003\n", os.Getuid())
	if err := os.WriteFile(list, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	p := startModels(t, m, "agent", 0, func(c *Config) {
		c.Callers = []CallerRule{{Package: "ai.outgate.models", Class: "models"}}
		c.PackagesList = list
	})
	g := partFile(t, nil)
	if resp := p.callFD(dlReq("e/model.bin", 0, 0), int(g.Fd())); resp["status"].(float64) != 200 {
		t.Errorf("models by package: %v", resp)
	}
	if row := p.rows.last(t); row.Caller != "models" {
		t.Errorf("row = %+v", row)
	}
}

func TestDownloadBadRequest(t *testing.T) {
	m := newMirror(t)
	setMirror(t, m.srv.URL+"/m")
	h := startModels(t, m, "models", 0, nil)
	f := partFile(t, modelData[:100])
	for name, line := range map[string]string{
		"no offset":        fmt.Sprintf(`{"op":"download","path":"e/model.bin","size":%d,"file":"fd:0"}`, modelSize),
		"no size":          `{"op":"download","path":"e/model.bin","offset":0,"file":"fd:0"}`,
		"offset at size":   fmt.Sprintf(`{"op":"download","path":"e/model.bin","offset":%d,"size":%d,"file":"fd:0"}`, modelSize, modelSize),
		"negative offset":  fmt.Sprintf(`{"op":"download","path":"e/model.bin","offset":-1,"size":%d,"file":"fd:0"}`, modelSize),
		"past the file":    dlReq("e/model.bin", 101, 0),
		"a path, not a fd": fmt.Sprintf(`{"op":"download","path":"e/model.bin","offset":0,"size":%d,"file":%q}`, modelSize, f.Name()),
		"fd:1":             fmt.Sprintf(`{"op":"download","path":"e/model.bin","offset":0,"size":%d,"file":"fd:1"}`, modelSize),
	} {
		if resp := h.callFD(line, int(f.Fd())); resp["refused"] != "bad_request" || resp["status"].(float64) != 400 {
			t.Errorf("%s: %v", name, resp)
		}
	}
	if resp := h.call(dlReq("e/model.bin", 0, 0)); resp["refused"] != "bad_request" {
		t.Errorf("no descriptor: %v", resp)
	}
	for name, flag := range map[string]int{"read-only": os.O_RDONLY, "append": os.O_WRONLY | os.O_APPEND} {
		g, err := os.OpenFile(f.Name(), flag, 0)
		if err != nil {
			t.Fatal(err)
		}
		resp := h.callFD(dlReq("e/model.bin", 0, 0), int(g.Fd()))
		_ = g.Close()
		if resp["refused"] != "bad_request" {
			t.Errorf("%s descriptor: %v", name, resp)
		}
	}
	if row := h.rows.last(t); !row.Blocked || row.BlockReason != "bad_request" {
		t.Errorf("row = %+v", row)
	}
	if n := len(m.seen()); n != 0 {
		t.Errorf("the mirror was reached %d times", n)
	}
	if got := fileBytes(t, f); !bytes.Equal(got, modelData[:100]) {
		t.Errorf("the file changed (%d bytes)", len(got))
	}
}

func TestDownloadIdleTimeout(t *testing.T) {
	m := newMirror(t)
	setMirror(t, m.srv.URL+"/m")
	h := startModels(t, m, "models", 300*time.Millisecond, nil)
	f := partFile(t, nil)
	began := time.Now()
	resp := h.callFD(dlReq("e/stall.bin", 0, 100), int(f.Fd()))
	took := time.Since(began)
	body, _ := resp["body"].(map[string]any)
	if resp["status"].(float64) != 504 || resp["refused"] != nil || body["error"] != "upstream_unreachable" ||
		num(resp["written"]) != 1000 || resp["complete"] != false {
		t.Fatalf("resp = %v", resp)
	}
	if took < 300*time.Millisecond || took > 3*time.Second {
		t.Errorf("idle timeout after %v, want about 300ms", took)
	}
	if got := fileBytes(t, f); !bytes.Equal(got, modelData[:1000]) {
		t.Errorf("partial file: %d bytes", len(got))
	}
	if row := h.rows.last(t); row.Status != 504 || row.Error != "timeout" || row.BytesIn != 1000 || row.Blocked {
		t.Errorf("row = %+v", row)
	}

	// The timeout is idle, not total: a download that keeps receiving outlasts it.
	slow := startModels(t, m, "models", 600*time.Millisecond, nil)
	g := partFile(t, nil)
	if resp := slow.callFD(dlReq("e/slow.bin", 0, 0), int(g.Fd())); resp["status"].(float64) != 200 || resp["complete"] != true {
		t.Errorf("slow download: %v", resp)
	}
}

// A caller that closes its connection cancels its download; one that only shuts
// down its write side after the request line keeps it.
func TestDownloadEndsWithItsCaller(t *testing.T) {
	m := newMirror(t)
	setMirror(t, m.srv.URL+"/m")
	h := startModels(t, m, "models", 0, nil)
	send := func(line string, f *os.File) *net.UnixConn {
		c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: h.sock, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.WriteMsgUnix([]byte(line+"\n"), syscall.UnixRights(int(f.Fd())), nil); err != nil {
			t.Fatal(err)
		}
		return c
	}
	f := partFile(t, nil)
	began := time.Now()
	_ = send(dlReq("e/stall.bin", 0, 0), f).Close()
	row := h.rows.last(t)
	if row.Status != 499 || row.Error != "cancelled" || time.Since(began) > 2*time.Second {
		t.Errorf("row = %+v after %v", row, time.Since(began))
	}

	g := partFile(t, nil)
	c := send(dlReq("e/slow.bin", 0, 0), g)
	defer func() { _ = c.Close() }()
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	out, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"].(float64) != 200 || resp["complete"] != true {
		t.Errorf("half-closed caller: %v", resp)
	}
	if got := fileBytes(t, g); !bytes.Equal(got, modelData) {
		t.Errorf("file differs (%d bytes)", len(got))
	}
}

const hubRev = "0123456789abcdef0123456789abcdef01234567"

func hubReq(repo, rev, p string, offset int64) string {
	return fmt.Sprintf(`{"v":1,"id":"dl-1","op":"download","repo":%q,"revision":%q,"path":%q,"offset":%d,"size":%d,"file":"fd:0"}`,
		repo, rev, p, offset, modelSize)
}

// startHub starts a gate for the models caller whose Hugging Face origin is the test mirror.
func startHub(t *testing.T, m *mirror) *harness {
	t.Helper()
	uid := uint32(os.Getuid()) //nolint:gosec // uids fit uint32
	return startOpts(t, Mask, func(c *Config) {
		c.Callers = []CallerRule{{UID: &uid, Class: "models"}}
	}, nil, nil, func(o *Options) {
		o.Transport = m.srv.Client().Transport
		o.HubBase = m.srv.URL
	})
}

func TestDownloadHub(t *testing.T) {
	m := newMirror(t)
	setMirror(t, "")
	h := startHub(t, m)
	f := partFile(t, modelData[:1000])
	resp := h.callFD(hubReq("ggml-org/model-GGUF", hubRev, "model.bin", 1000), int(f.Fd()))
	if resp["status"].(float64) != 206 || resp["refused"] != nil || resp["class"] != "mirror" || resp["start"] != float64(1000) ||
		num(resp["written"]) != modelSize-1000 || resp["complete"] != true {
		t.Fatalf("resp = %v", resp)
	}
	if got := fileBytes(t, f); !bytes.Equal(got, modelData) {
		t.Errorf("file: %d bytes, want the model's %d", len(got), modelSize)
	}
	hits := m.seen()
	if len(hits) != 1 || hits[0].Path != "/ggml-org/model-GGUF/resolve/"+hubRev+"/model.bin" || hits[0].Range != "bytes=1000-" ||
		hits[0].UserAgent != "og-gate/test" || hits[0].AcceptEncoding != "identity" {
		t.Errorf("hub saw %+v", hits)
	}
	row := h.rows.last(t)
	if row.Destination != "127.0.0.1" || row.Class != "mirror" || row.Method != "GET" || row.EgressKind != "model" ||
		row.PathClass != "/ggml-org/model-GGUF/resolve/:id/model.bin" || row.BytesIn != modelSize-1000 || row.Status != 206 ||
		row.Blocked || row.Content {
		t.Errorf("row = %+v", row)
	}
}

func TestDownloadHubRedirects(t *testing.T) {
	m := newMirror(t)
	h := startHub(t, m)
	// Within Hugging Face's hosts: followed, with the Range.
	f := partFile(t, modelData[:10])
	resp := h.callFD(hubReq("o/r", hubRev, "redirect.bin", 10), int(f.Fd()))
	if resp["status"].(float64) != 206 || resp["complete"] != true {
		t.Fatalf("resp = %v", resp)
	}
	if got := fileBytes(t, f); !bytes.Equal(got, modelData) {
		t.Errorf("file: %d bytes, want the model's %d", len(got), modelSize)
	}
	if hits := m.seen(); len(hits) != 2 || hits[1].Path != "/m/model.bin" || hits[1].Range != "bytes=10-" {
		t.Errorf("hub saw %+v", hits)
	}
	// Anywhere else, or too many hops: refused, nothing written.
	for p, hops := range map[string]int{"away.bin": 1, "loop.bin": 1 + hubMaxRedirects} {
		before := len(m.seen())
		g := partFile(t, modelData[:10])
		resp = h.callFD(hubReq("o/r", hubRev, p, 10), int(g.Fd()))
		if resp["refused"] != "redirect_not_allowed" || resp["status"].(float64) != 502 || resp["written"] != nil {
			t.Errorf("%s: %v", p, resp)
		}
		if row := h.rows.last(t); !row.Blocked || row.BlockReason != "redirect_not_allowed" || row.BytesIn != 0 {
			t.Errorf("%s: row = %+v", p, row)
		}
		if got := fileBytes(t, g); !bytes.Equal(got, modelData[:10]) {
			t.Errorf("%s: the file changed (%d bytes)", p, len(got))
		}
		if n := len(m.seen()) - before; n != hops {
			t.Errorf("%s: %d requests, want %d", p, n, hops)
		}
	}
}

func TestDownloadHubBadRepo(t *testing.T) {
	m := newMirror(t)
	h := startHub(t, m)
	f := partFile(t, nil)
	for _, c := range [][3]string{
		{"gemma", hubRev, "model.bin"}, {"o/r", "main", "model.bin"}, {"o/r", "", "model.bin"},
		{"", hubRev, "model.bin"}, {"o/r", hubRev, "../model.bin"}, {"o/r/x", hubRev, "model.bin"},
	} {
		resp := h.callFD(hubReq(c[0], c[1], c[2], 0), int(f.Fd()))
		if resp["refused"] != "bad_path" || resp["status"].(float64) != 400 {
			t.Errorf("%q: %v", c, resp)
		}
	}
	if n := len(m.seen()); n != 0 {
		t.Errorf("the hub was reached %d times", n)
	}
}
