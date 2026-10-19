package gate

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/route"
)

const webPublic = "93.184.216.34"

// webSite is a TLS stand-in for a web host (its certificate is for example.com). The gate's dialer is
// pointed at it whatever address it is handed; the addresses it was handed are kept.
type webSite struct {
	srv *httptest.Server

	mu     sync.Mutex
	hits   []*http.Request
	bodies []string
	dialed []string
}

func newWebSite(t *testing.T, h http.HandlerFunc) *webSite {
	w := &webSite{}
	w.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.mu.Lock()
		w.hits, w.bodies = append(w.hits, r), append(w.bodies, string(b))
		w.mu.Unlock()
		h(rw, r)
	}))
	w.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	w.srv.StartTLS()
	t.Cleanup(w.srv.Close)
	return w
}

func (w *webSite) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	w.mu.Lock()
	w.dialed = append(w.dialed, addr)
	w.mu.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, w.srv.Listener.Addr().String())
}

func (w *webSite) count() (hits, dials int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.hits), len(w.dialed)
}

func (w *webSite) last(t *testing.T) (r *http.Request, body string) {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.hits) == 0 {
		t.Fatal("no request reached the site")
	}
	return w.hits[len(w.hits)-1], w.bodies[len(w.bodies)-1]
}

// webDNS answers the gate's one lookup per request from a table.
type webDNS map[string][]string

func (d webDNS) resolve(_ context.Context, host string) ([]netip.Addr, error) {
	answers, ok := d[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	var out []netip.Addr
	for _, a := range answers {
		out = append(out, netip.MustParseAddr(a))
	}
	return out, nil
}

type webHarness struct {
	*harness
	site  *webSite
	peers *fakePeers
	uid   uint32
}

// startWeb starts a gate with OG Core as the containers caller (og_core, ai.outgate.core in
// packages.list) and og-agentd as agent, two model instances and a site at example.com.
func startWeb(t *testing.T, mode Mode, mm Masker, site http.HandlerFunc, mutate func(*Config)) *webHarness {
	t.Helper()
	if site == nil {
		site = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "hello from the web")
		}
	}
	ws := newWebSite(t, site)
	uid := uint32(os.Getuid()) //nolint:gosec // uids fit uint32
	list := filepath.Join(t.TempDir(), "packages.list")
	if err := os.WriteFile(list, []byte(fmt.Sprintf("ai.outgate.core %d 0 /data/user/0/ai.outgate.core platform 3003\n", uid)), 0o600); err != nil {
		t.Fatal(err)
	}
	sockets, _, _ := twoModels(t, nil)
	fp := &fakePeers{}
	fp.set(uid, "og_core")
	dns := webDNS{
		"example.com":     {webPublic},
		"api.example.com": {webPublic},
		"example.net":     {webPublic},
		"ten.example.com": {"10.0.0.5"},
		"lo.example.com":  {"127.0.0.1"},
		"lo6.example.com": {"::1"},
		"ula.example.com": {"fd00::1"},
		"cgn.example.com": {"100.64.1.1"},
		"mix.example.com": {webPublic, "192.168.1.20"},
		"map.example.com": {"::ffff:10.0.0.1"},
		"n64.example.com": {"64:ff9b::a00:1"},
		"ll.example.com":  {"169.254.169.254"},
	}
	roots := x509.NewCertPool()
	roots.AddCert(ws.srv.Certificate())
	h := startOpts(t, mode, func(c *Config) {
		c.Callers = []CallerRule{
			{Domain: "og_core", Package: "ai.outgate.core", Class: callerContainers},
			{Domain: "outgate_agent", UID: &uid, Class: "agent"},
		}
		c.PackagesList = list
		c.ModelSockets = sockets
		if mutate != nil {
			mutate(c)
		}
	}, mm, nil, func(o *Options) {
		o.PeerOf, o.Resolve, o.WebDial, o.WebRootCAs = fp.of, dns.resolve, ws.dial, roots
	})
	return &webHarness{harness: h, site: ws, peers: fp, uid: uid}
}

// webReq is a containers web request for url with extra request fields and egress fields.
func webReq(method, url, extra, egress string) string {
	if extra != "" {
		extra = "," + extra
	}
	if egress != "" {
		egress = "," + egress
	}
	return fmt.Sprintf(`{"method":%q,"url":%q%s,"egress":{"kind":"container","container":"ai.example.weather","run_id":"run-7",`+
		`"allow":["example.com","*.example.com"]%s}}`, method, url, extra, egress)
}

func TestHostAllowed(t *testing.T) {
	allow := []string{"example.com", "*.cdn.example.net"}
	for host, want := range map[string]bool{
		"example.com":          true,
		"www.example.com":      false,
		"cdn.example.net":      false,
		"a.cdn.example.net":    true,
		"a.b.cdn.example.net":  true,
		"evilcdn.example.net":  false,
		"a.cdn.example.net.io": false,
		"example.com.evil.io":  false,
	} {
		if got := hostAllowed(allow, host); got != want {
			t.Errorf("%s: %v, want %v", host, got, want)
		}
	}
	for p, want := range map[string]bool{
		"example.com": true, "*.example.com": true, "Example.com": false, "*.com": false, "com": false,
		"*example.com": false, "a.*.example.com": false, "example.com:443": false, "10.0.0.1": false,
		"example.com.": false, "": false, "*.": false, "xn--bcher-kva.example": true,
	} {
		if got := webPattern(p); got != want {
			t.Errorf("pattern %q: %v, want %v", p, got, want)
		}
	}
}

func TestPrivateAddr(t *testing.T) {
	for a, want := range map[string]bool{
		webPublic: false, "1.1.1.1": false, "2606:4700:4700::1111": false, "64:ff9b::5db8:d822": false,
		"10.0.0.5": true, "127.0.0.1": true, "127.8.9.10": true, "172.16.0.1": true, "172.31.255.255": true,
		"172.32.0.1": false, "192.168.1.1": true, "169.254.169.254": true, "100.64.1.1": true, "100.127.255.255": true,
		"100.128.0.1": false, "0.0.0.0": true, "0.1.2.3": true, "192.0.0.8": true, "198.18.0.1": true, "198.19.255.1": true,
		"224.0.0.1": true, "240.0.0.1": true, "255.255.255.255": true,
		"::1": true, "::": true, "fe80::1": true, "fd00::1": true, "fc00::1": true, "ff02::1": true,
		"::ffff:10.0.0.1": true, "::ffff:127.0.0.1": true, "::ffff:93.184.216.34": false, "64:ff9b::a00:1": true,
		"64:ff9b::7f00:1": true,
	} {
		if got := privateAddr(netip.MustParseAddr(a)); got != want {
			t.Errorf("%s: private %v, want %v", a, got, want)
		}
	}
}

// A web request reaches its host at the address that was checked, with the name as SNI and Host, only
// Accept, Accept-Language and Content-Type of the caller's headers and the containers User-Agent.
func TestWebFetch(t *testing.T) {
	h := startWeb(t, Passthrough, nil, nil, nil)
	resp := h.call(webReq("GET", "https://Example.COM:443/forecast/berlin?days=3",
		`"headers":{"Accept":"text/plain","Accept-Language":"de","Authorization":"Bearer x","Cookie":"a=b","X-Region-Id":"r","User-Agent":"mine","Host":"evil.test"}`, ""))
	if resp["status"].(float64) != 200 || resp["body_text"] != "hello from the web" || resp["class"] != "web" || resp["truncated"] != nil {
		t.Fatalf("resp = %v", resp)
	}
	r, _ := h.site.last(t)
	if r.Host != "example.com" || r.TLS == nil || r.TLS.ServerName != "example.com" || r.URL.RequestURI() != "/forecast/berlin?days=3" {
		t.Errorf("request = host %q sni %v uri %q", r.Host, r.TLS, r.URL.RequestURI())
	}
	for k := range r.Header {
		switch k {
		case "Accept", "Accept-Language", "User-Agent", "Connection":
		default:
			t.Errorf("header %s reached the site", k)
		}
	}
	if r.Header.Get("User-Agent") != webUserAgent || r.Header.Get("Accept") != "text/plain" || r.Header.Get("Accept-Language") != "de" {
		t.Errorf("headers = %v", r.Header)
	}
	h.site.mu.Lock()
	dialed := append([]string(nil), h.site.dialed...)
	h.site.mu.Unlock()
	for _, d := range dialed {
		if d != webPublic+":443" {
			t.Errorf("dialed %s, not the checked address", d)
		}
	}
	row := h.rows.last(t)
	if row.Caller != callerContainers || row.Class != "web" || row.Destination != "example.com" || row.Container != "ai.example.weather" ||
		row.RunID != "run-7" || row.Status != 200 || row.BytesIn != int64(len("hello from the web")) || row.PathClass != "" ||
		row.EgressKind != "container" || !row.Content || row.Mask != MaskOff {
		t.Errorf("row = %+v", row)
	}
	b, _ := json.Marshal(row)
	if strings.Contains(string(b), "berlin") || strings.Contains(string(b), "days") {
		t.Errorf("row has the path or query: %s", b)
	}

	// A POST carries its text body and Content-Type; a HEAD comes back without one.
	resp = h.call(webReq("POST", "https://api.example.com/v1/ask", `"body_text":"what is the weather","headers":{"Content-Type":"text/plain; charset=utf-8"}`, ""))
	if r, body := h.site.last(t); resp["status"].(float64) != 200 || body != "what is the weather" || r.Header.Get("Content-Type") != "text/plain; charset=utf-8" || r.Host != "api.example.com" {
		t.Errorf("POST text: %v %q %v", resp, body, r.Header)
	}
	resp = h.call(webReq("GET", "https://example.net/", "", `"allow":["example.net"]`))
	if resp["status"].(float64) != 502 || resp["refused"] != nil {
		t.Errorf("example.net (the certificate is for example.com): %v", resp)
	}
	if row := h.rows.last(t); row.Error != "tls_verify" || row.Destination != "example.net" {
		t.Errorf("TLS is verified against the name: %+v", row)
	}
	resp = h.call(webReq("POST", "https://example.com/v1/ask", `"body":{"q":"weather"}`, ""))
	if r, body := h.site.last(t); resp["status"].(float64) != 200 || body != `{"q":"weather"}` || r.Header.Get("Content-Type") != "application/json" {
		t.Errorf("POST: %v %q %v", resp, body, r.Header)
	}
	if row := h.rows.last(t); row.BytesOut != int64(len(`{"q":"weather"}`)) {
		t.Errorf("POST row = %+v", row)
	}
	if resp := h.call(webReq("HEAD", "https://example.com/", "", "")); resp["status"].(float64) != 200 || resp["body_text"] != nil {
		t.Errorf("HEAD: %v", resp)
	}
}

// The name is looked up once; any private answer refuses the request before a connection is made.
func TestWebPrivateAddresses(t *testing.T) {
	h := startWeb(t, Passthrough, nil, nil, nil)
	for host, want := range map[string]string{
		"example.com":     "",
		"ten.example.com": "private_address",
		"lo.example.com":  "private_address",
		"lo6.example.com": "private_address",
		"ula.example.com": "private_address",
		"cgn.example.com": "private_address",
		"mix.example.com": "private_address",
		"map.example.com": "private_address",
		"n64.example.com": "private_address",
		"ll.example.com":  "private_address",
	} {
		_, before := h.site.count()
		resp := h.call(webReq("GET", "https://"+host+"/", "", ""))
		_, after := h.site.count()
		if want == "" {
			if resp["status"].(float64) != 200 || after == before {
				t.Errorf("%s: %v", host, resp)
			}
			continue
		}
		if resp["refused"] != want || resp["status"].(float64) != 403 || after != before {
			t.Errorf("%s: %v (dials %d→%d)", host, resp, before, after)
		}
		if d, _ := resp["detail"].(string); !strings.Contains(d, host) || strings.ContainsAny(d, ":") ||
			strings.Contains(d, "10.0") || strings.Contains(d, "127.") {
			t.Errorf("%s: detail %q", host, d)
		}
		if row := h.rows.last(t); !row.Blocked || row.BlockReason != want || row.Destination != host || row.Class != "web" {
			t.Errorf("%s: row = %+v", host, row)
		}
	}
	for _, u := range []string{"https://93.184.216.34/", "https://10.0.0.5/", "https://[2606:4700::1111]/", "https://[::1]/", "https://2130706433/", "https://0x7f.0.0.1/"} {
		if resp := h.call(webReq("GET", u, "", `"allow":["example.com"]`)); resp["refused"] != "bad_url" {
			t.Errorf("%s: %v", u, resp)
		}
	}
	if resp := h.call(webReq("GET", "https://gone.example.com/", "", "")); resp["status"].(float64) != 502 || resp["refused"] != nil {
		t.Errorf("unknown name: %v", resp)
	}
	if row := h.rows.last(t); row.Error != "dns" {
		t.Errorf("unknown name row = %+v", row)
	}
	if hits, _ := h.site.count(); hits != 1 {
		t.Errorf("site hits = %d, want 1", hits)
	}
}

func TestWebRequestRules(t *testing.T) {
	h := startWeb(t, Passthrough, nil, nil, nil)
	big := strings.Repeat("x", webBodyMax+1)
	long := strings.Repeat("c", webNameMax+1)
	cases := []struct {
		name, req, refused string
	}{
		{"http", webReq("GET", "http://example.com/", "", ""), "bad_url"},
		{"port", webReq("GET", "https://example.com:8443/", "", ""), "bad_url"},
		{"userinfo", webReq("GET", "https://u:p@example.com/", "", ""), "bad_url"},
		{"no url", `{"method":"GET","path":"/x","egress":{"kind":"container","container":"c","run_id":"r","allow":["example.com"]}}`, "destination_not_allowed"},
		{"relative", webReq("GET", "/x", "", ""), "bad_url"},
		{"single label", webReq("GET", "https://localhost/", "", `"allow":["example.com"]`), "bad_url"},
		{"not allowed", webReq("GET", "https://example.org/", "", ""), "destination_not_allowed"},
		{"wildcard base", webReq("GET", "https://example.com/", "", `"allow":["*.example.com"]`), "destination_not_allowed"},
		{"suffix", webReq("GET", "https://badexample.com/", "", ""), "destination_not_allowed"},
		{"PUT", webReq("PUT", "https://example.com/", "", ""), "bad_method"},
		{"DELETE", webReq("DELETE", "https://example.com/", "", ""), "bad_method"},
		{"GET body", webReq("GET", "https://example.com/", `"body_text":"x"`, ""), "bad_body"},
		{"body_b64", webReq("POST", "https://example.com/", `"body_b64":"aGk="`, ""), "bad_body"},
		{"file", webReq("POST", "https://example.com/", `"file":"fd:0"`, ""), "bad_body"},
		{"body_fd", webReq("POST", "https://example.com/", `"body_fd":"fd:0","body_size":1`, ""), "bad_request"},
		{"too large", webReq("POST", "https://example.com/", `"body_text":"`+big+`"`, ""), "too_large"},
		{"no allow", strings.Replace(webReq("GET", "https://example.com/", "", ""), `"allow":["example.com","*.example.com"]`, `"allow":[]`, 1), "bad_request"},
		{"17 hosts", webReq("GET", "https://example.com/", "", `"allow":[`+strings.TrimSuffix(strings.Repeat(`"example.com",`, 17), ",")+`]`), "bad_request"},
		{"bad pattern", webReq("GET", "https://example.com/", "", `"allow":["Example.com"]`), "bad_request"},
		{"no container", webReq("GET", "https://example.com/", "", `"container":""`), "bad_request"},
		{"no run", webReq("GET", "https://example.com/", "", `"run_id":""`), "bad_request"},
		{"long container", webReq("GET", "https://example.com/", "", `"container":"`+long+`"`), "bad_request"},
		{"other kind", strings.Replace(webReq("GET", "https://example.com/", "", ""), `"kind":"container"`, `"kind":"report"`, 1), "destination_not_allowed"},
	}
	for _, c := range cases {
		if resp := h.call(c.req); resp["refused"] != c.refused {
			t.Errorf("%s: %v, want %s", c.name, resp, c.refused)
		}
		if row := h.rows.last(t); !row.Blocked || len(row.Container) > webNameMax {
			t.Errorf("%s: row = %+v", c.name, row)
		}
	}
	if hits, dials := h.site.count(); hits != 0 || dials != 0 {
		t.Errorf("refused requests reached the site: %d hits, %d dials", hits, dials)
	}
}

func TestWebResponses(t *testing.T) {
	big := strings.Repeat("y", webResponseMax+1000)
	h := startWeb(t, Passthrough, nil, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, big)
		case "/moved":
			w.Header().Set("Location", "https://example.com/elsewhere")
			w.Header().Set("Set-Cookie", "s=1")
			w.WriteHeader(http.StatusFound)
		case "/slow":
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		case "/json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"temp":21}`)
		}
	}, nil)
	resp := h.call(webReq("GET", "https://example.com/big", "", ""))
	if s, _ := resp["body_text"].(string); resp["truncated"] != true || len(s) != webResponseMax {
		t.Errorf("big: truncated %v, %d bytes", resp["truncated"], len(s))
	}
	if row := h.rows.last(t); row.BytesIn != webResponseMax || row.Status != 200 {
		t.Errorf("big row = %+v", row)
	}
	resp = h.call(webReq("GET", "https://example.com/moved", "", ""))
	hdr, _ := resp["headers"].(map[string]any)
	if resp["status"].(float64) != 302 || hdr["Location"] != "https://example.com/elsewhere" || hdr["Set-Cookie"] != nil {
		t.Errorf("3xx: %v", resp)
	}
	if hits, _ := h.site.count(); hits != 2 {
		t.Errorf("the redirect was followed: %d hits", hits)
	}
	if resp := h.call(webReq("GET", "https://example.com/json", "", "")); string(mustMarshal(resp["body"])) != `{"temp":21}` {
		t.Errorf("json: %v", resp)
	}
	resp = h.call(webReq("GET", "https://example.com/slow", `"timeout_ms":200`, ""))
	if resp["status"].(float64) != 504 || resp["refused"] != nil {
		t.Errorf("timeout: %v", resp)
	}
}

// Query values and bodies to the web are masked in one masker call; without a detector they don't
// leave, and a request with no content still does.
func TestWebMasking(t *testing.T) {
	mm := &markerMasker{}
	h := startWeb(t, Mask, mm, nil, nil)
	resp := h.call(webReq("POST", "https://example.com/ask?who="+marker+"&n=1", `"body_text":"about `+marker+`"`, ""))
	r, body := h.site.last(t)
	if resp["status"].(float64) != 200 || mm.n() != 1 || strings.Contains(r.URL.RawQuery, marker) || strings.Contains(body, marker) ||
		r.URL.Query().Get("who") != "[masked]" || r.URL.Query().Get("n") != "1" || body != "about [masked]" {
		t.Fatalf("masked: %v query %q body %q calls %d", resp, r.URL.RawQuery, body, mm.n())
	}
	if m := resp["masked"].(map[string]any); m["mask"] != MaskOn || m["count"].(float64) != 1 {
		t.Errorf("masked = %v", m)
	}
	if row := h.rows.last(t); row.Mask != MaskOn || row.MaskedCount != 1 || row.BytesOut != int64(len("about [masked]")) {
		t.Errorf("row = %+v", row)
	}
	resp = h.call(webReq("POST", "https://example.com/ask", `"body":{"text":"`+marker+`","id":"`+marker+`"}`, ""))
	if _, body := h.site.last(t); resp["status"].(float64) != 200 || !strings.Contains(body, `"text":"[masked]"`) {
		t.Errorf("JSON body: %v %s", resp, body)
	}
	if resp := h.call(webReq("GET", "https://example.com/ask?q=plain", "", "")); resp["status"].(float64) != 200 || mm.n() != 3 {
		t.Errorf("plain query: %v (calls %d)", resp, mm.n())
	}

	closed := startWeb(t, Mask, nil, nil, nil)
	for _, req := range []string{
		webReq("GET", "https://example.com/ask?q=hello", "", ""),
		webReq("POST", "https://example.com/ask", `"body_text":"hello"`, ""),
	} {
		resp := closed.call(req)
		if resp["refused"] != "detector_unavailable" || resp["status"].(float64) != 503 || resp["class"] != "web" {
			t.Errorf("without a detector: %v", resp)
		}
		if row := closed.rows.last(t); !row.Blocked || row.Mask != MaskOn || row.BytesOut != 0 {
			t.Errorf("fail-closed row = %+v", row)
		}
	}
	if hits, _ := closed.site.count(); hits != 0 {
		t.Errorf("content left without a detector: %d hits", hits)
	}
	if resp := closed.call(webReq("GET", "https://example.com/", "", "")); resp["status"].(float64) != 200 {
		t.Errorf("content-free GET without a detector: %v", resp)
	}
	health := closed.call(`{"source":{},"method":"GET","url":"https://example.com/","egress":{}}`)
	if health["refused"] != "destination_not_allowed" {
		t.Errorf("non-container request: %v", health)
	}
	closed.peers.set(closed.uid, "outgate_agent")
	hh := closed.call(`{"op":"health"}`)["body"].(map[string]any)
	if hh["masking"].(map[string]any)["needed"] != true || hh["masking"].(map[string]any)["classes"].(map[string]any)["web"] != true {
		t.Errorf("health = %v", hh)
	}
}

// OG Core reaches the web class and the two model instances' completions and health, nothing else;
// nobody else reaches the web class.
func TestContainersCallerScope(t *testing.T) {
	third := &fakeLlama{alias: "og-local-vision"}
	h := startWeb(t, Passthrough, nil, nil, func(c *Config) {
		c.ModelSockets["og-local-vision"] = filepath.Join(filepath.Dir(c.ModelSockets["og-local"]), "vision.sock")
	})
	third.serve(t, h.srv.cfg.ModelSockets["og-local-vision"])
	eg := `"egress":{"kind":"container","container":"ai.example.weather","run_id":"run-7"}`
	for _, model := range []string{"og-local", "og-local-agent"} {
		resp := h.call(`{"source":{"region_id":"on-device"},"method":"POST","path":"/v1/chat/completions","body":{"model":"` + model + `","messages":[]},` + eg + `}`)
		if resp["status"].(float64) != 200 || resp["class"] != "on-device" {
			t.Errorf("%s completion: %v", model, resp)
		}
		if row := h.rows.last(t); row.Caller != callerContainers || row.Class != "on-device" || row.Container != "ai.example.weather" ||
			row.RunID != "run-7" || !row.OnDevice || row.Kind != "llm" {
			t.Errorf("%s row = %+v", model, row)
		}
	}
	if resp := h.call(`{"source":{"region_id":"on-device"},"method":"GET","path":"/health","query":{"model":"og-local-agent"},` + eg + `}`); resp["status"].(float64) != 200 {
		t.Errorf("health: %v", resp)
	}
	for name, c := range map[string]struct{ req, refused string }{
		"vision model":  {`{"source":{"region_id":"on-device"},"method":"POST","path":"/v1/chat/completions","body":{"model":"og-local-vision"},` + eg + `}`, "destination_not_allowed"},
		"model list":    {`{"source":{"region_id":"on-device"},"method":"GET","path":"/v1/models",` + eg + `}`, "destination_not_allowed"},
		"slots":         {`{"source":{"region_id":"on-device"},"method":"GET","path":"/slots",` + eg + `}`, "destination_not_allowed"},
		"global":        {`{"source":{"region_id":"global"},"method":"GET","path":"/api/v1/agents/threads",` + eg + `}`, "destination_not_allowed"},
		"oidc":          {`{"source":{"region_id":"oidc"},"method":"POST","path":"/token",` + eg + `}`, "destination_not_allowed"},
		"region":        {`{"source":{"region_id":"reg-1"},"method":"GET","path":"/x",` + eg + `}`, "destination_not_allowed"},
		"appq":          {`{"source":{"region_id":"appq:travel"},"method":"POST","path":"/commands/pop",` + eg + `}`, "destination_not_allowed"},
		"provider":      {`{"source":{"region_id":"provider:llm"},"method":"GET","path":"/v1/models",` + eg + `}`, "destination_not_allowed"},
		"outgate url":   {`{"source":{},"method":"GET","url":"` + h.up.srv.URL + `/api/v1/agents/threads","egress":{}}`, "destination_not_allowed"},
		"web, no kind":  {`{"source":{},"method":"GET","url":"https://example.com/","egress":{"container":"c","run_id":"r","allow":["example.com"]}}`, "destination_not_allowed"},
		"outgate, kind": {webReq("GET", "https://api.outgate.test/api/v1/agents/threads", "", ""), "destination_not_allowed"},
		"outgate, http": {webReq("GET", h.up.srv.URL+"/api/v1/agents/threads", "", ""), "bad_url"},
	} {
		if resp := h.call(c.req); resp["refused"] != c.refused {
			t.Errorf("%s: %v, want %s", name, resp, c.refused)
		}
	}
	for _, op := range []string{"health", "download", "ledger", "appq_list", "note"} {
		if resp := h.call(`{"op":"` + op + `"}`); resp["refused"] != "caller_not_allowed" {
			t.Errorf("op %s: %v", op, resp)
		}
	}
	if len(third.seen()) != 0 || len(h.up.got) != 0 {
		t.Errorf("refused requests left: vision %d, upstream %d", len(third.seen()), len(h.up.got))
	}

	// og-agentd (any caller but containers) never reaches the web class, with or without the egress fields.
	h.peers.set(h.uid, "outgate_agent")
	if resp := h.call(webReq("GET", "https://example.com/", "", "")); resp["refused"] != "destination_not_allowed" {
		t.Errorf("agent to the web: %v", resp)
	}
	if hits, dials := h.site.count(); hits != 0 || dials != 0 {
		t.Errorf("the site was reached: %d hits, %d dials", hits, dials)
	}
	// Another app's uid with OG Core's domain is not OG Core.
	h.peers.set(h.uid+1, "og_core")
	if resp := h.call(webReq("GET", "https://example.com/", "", "")); resp["refused"] != "caller_not_allowed" {
		t.Errorf("og_core domain, other uid: %v", resp)
	}
}

func TestContainersOnModelFront(t *testing.T) {
	h := startWeb(t, Passthrough, nil, nil, nil)
	front := filepath.Join(h.dir, "front.sock")
	fln, err := ListenPath(front, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = h.srv.ServeModel(ctx, fln) }()
	cl := &http.Client{Transport: unixTransport(front)}
	if code, body := frontDo(t, cl, "POST", "/v1/chat/completions", strings.NewReader(`{"model":"og-local-agent","messages":[]}`)); code != 200 || !strings.Contains(body, "og-local-agent") {
		t.Errorf("completion: %d %s", code, body)
	}
	if code, _ := frontDo(t, cl, "GET", "/health", nil); code != 200 {
		t.Errorf("health: %d", code)
	}
	if code, _ := frontDo(t, cl, "GET", "/v1/models", nil); code != 403 {
		t.Errorf("model list: %d", code)
	}
}

func TestContainersConfig(t *testing.T) {
	var c Config
	if !c.Masks("web") || c.MaskingNeeded() {
		t.Errorf("web default: masked %v needed %v", c.Masks("web"), c.MaskingNeeded())
	}
	c.Callers = []CallerRule{{Domain: "og_core", Package: "ai.outgate.core", Class: callerContainers}}
	if err := c.Validate(); err != nil || !c.MaskingNeeded() {
		t.Errorf("containers caller: %v needed %v", err, c.MaskingNeeded())
	}
	for name, rule := range map[string]CallerRule{
		"no package": {Domain: "og_core", Class: callerContainers},
		"no domain":  {Package: "ai.outgate.core", Class: callerContainers},
	} {
		c := Config{Callers: []CallerRule{rule}}
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	w := Config{Classes: []ClassRule{{Class: "web", Mask: true, Destinations: []route.Provider{{ID: "x", Base: "https://x.test"}}}}}
	if err := w.Validate(); err == nil {
		t.Error("web destinations accepted")
	}
	w = Config{Classes: []ClassRule{{Class: "outgate"}, {Class: "web", Mask: true}}}
	if err := w.Validate(); err != nil || !w.Masks("web") {
		t.Errorf("web class: %v", err)
	}
}
