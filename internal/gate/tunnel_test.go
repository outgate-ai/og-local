package gate

import (
	"bufio"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/ledger"
	"github.com/outgate-ai/og-local/internal/gate/peer"
	"github.com/outgate-ai/og-local/internal/gate/tunnelconf"
)

// fakePeers answers Options.PeerOf with whatever identity the test sets.
type fakePeers struct{ cred atomic.Pointer[peer.Cred] }

func (f *fakePeers) set(uid uint32, domain string) {
	c := peer.Cred{UID: uid}
	if domain != "" {
		c.Context = "u:r:" + domain + ":s0"
	}
	f.cred.Store(&c)
}

func (f *fakePeers) of(*net.UnixConn) (peer.Cred, error) {
	return *f.cred.Load(), nil
}

func TestPeerOfOption(t *testing.T) {
	uid := uint32(os.Getuid()) //nolint:gosec // uids fit uint32
	rules := func(c *Config) { c.Callers = []CallerRule{{Domain: "outgate_test", UID: &uid, Class: "debug"}} }
	fp := &fakePeers{}
	fp.set(uid, "outgate_test")
	h := startOpts(t, Passthrough, rules, nil, nil, func(o *Options) { o.PeerOf = fp.of })
	if resp := h.call(`{"op":"health"}`); resp["status"].(float64) != 200 {
		t.Errorf("domain from PeerOf: %v", resp)
	}
	fp.set(uid, "outgate_other")
	if resp := h.call(`{"op":"health"}`); resp["refused"] != "caller_not_allowed" {
		t.Errorf("another domain: %v", resp)
	}
	if resp := start(t, Passthrough, rules).call(`{"op":"health"}`); resp["refused"] != "caller_not_allowed" {
		t.Errorf("peer.Of on a host without SELinux: %v", resp)
	}
}

const (
	tunnelUID      = 7510
	tunnelDomain   = "outgate_tunnel"
	launcherDomain = "outgate_tunnel_launcher"
)

// tunnelCallers admits the tunnel daemon, its launcher, su on debuggable builds and the test's own
// uid as the agent.
func tunnelCallers(c *Config) {
	uid, me := uint32(tunnelUID), uint32(os.Getuid()) //nolint:gosec // uids fit uint32
	c.Callers = []CallerRule{
		{Domain: tunnelDomain, UID: &uid, Class: callerTunnel},
		{Domain: launcherDomain, UID: &uid, Class: callerTunnelLauncher},
		{Domain: "su", Class: "debug", DebuggableOnly: true},
		{UID: &me, Class: "agent"},
	}
}

func TestTunnelCallersNeedDomainAndUID(t *testing.T) {
	uid := uint32(tunnelUID)
	for _, class := range []string{callerTunnel, callerTunnelLauncher} {
		for name, r := range map[string]CallerRule{
			"no domain": {UID: &uid, Class: class},
			"no uid":    {Domain: tunnelDomain, Class: class},
			"neither":   {MinUID: 1000, Class: class},
		} {
			c := Config{Callers: []CallerRule{r}}
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "domain and uid") {
				t.Errorf("%s %s: %v", class, name, err)
			}
		}
		c := Config{Callers: []CallerRule{{Domain: tunnelDomain, UID: &uid, Class: class}}}
		if err := c.Validate(); err != nil {
			t.Errorf("%s: %v", class, err)
		}
	}
	path := filepath.Join(t.TempDir(), "gate.conf")
	if err := os.WriteFile(path, []byte(`{"callers":[{"uid":7510,"class":"tunnel"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Error("LoadConfig accepted a tunnel rule without a domain")
	}
}

func TestNoteOp(t *testing.T) {
	fp := &fakePeers{}
	h := startOpts(t, Passthrough, tunnelCallers, nil, nil, func(o *Options) { o.PeerOf = fp.of })
	fp.set(tunnelUID, launcherDomain)
	resp := h.call(`{"v":1,"op":"note","event":"tunnel.connected","links":4}`)
	if resp["status"].(float64) != 200 || len(resp["body"].(map[string]any)) != 0 || resp["ledger"] == "" {
		t.Fatalf("connected: %v", resp)
	}
	row := h.rows.last(t)
	if row.Caller != "tunnel_launcher" || row.UID != tunnelUID || row.Event != "tunnel.connected" || row.Destination != "tunnel" ||
		row.Kind != "event" || row.Status != 200 || row.Content || row.Blocked || row.Error != "" || row.ID != resp["ledger"] {
		t.Errorf("row = %+v", row)
	}
	resp = h.call(`{"v":1,"op":"note","event":"tunnel.disconnected","links":0,"error_kind":"dns"}`)
	if resp["status"].(float64) != 200 {
		t.Fatalf("disconnected: %v", resp)
	}
	if row := h.rows.rowsAfter(t, 2)[1]; row.Event != "tunnel.disconnected" || row.Error != "dns" {
		t.Errorf("row = %+v", row)
	}
	for _, ev := range []string{"tunnel.enabled", "tunnel.disabled"} {
		if resp := h.call(`{"op":"note","event":"` + ev + `"}`); resp["status"].(float64) != 200 {
			t.Errorf("%s: %v", ev, resp)
		}
	}
	for _, line := range []string{
		`{"op":"note","event":"tunnel.exploded"}`,
		`{"op":"note"}`,
		`{"op":"note","event":"tunnel.disconnected","error_kind":"cosmic"}`,
		`{"op":"note","event":"tunnel.connected","links":-1}`,
	} {
		if resp := h.call(line); resp["status"].(float64) != 400 || resp["refused"] != "bad_request" {
			t.Errorf("%s: %v", line, resp)
		}
	}
	if n := h.rows.count(); n != 4 {
		t.Errorf("%d ledger rows", n)
	}
	// The launcher may only send notes.
	for _, line := range []string{
		`{"op":"health"}`,
		`{"source":{"region_id":"global"},"method":"GET","path":"/x","egress":{}}`,
		`{"source":{"region_id":"on-device"},"method":"POST","path":"/v1/chat/completions","body":{},"egress":{}}`,
		`{"op":"download","url":"https://huggingface.co/x","file":"fd:0"}`,
		`{"op":"ledger"}`,
		`{"op":"appq_list"}`,
	} {
		if resp := h.call(line); resp["refused"] != "caller_not_allowed" || resp["status"].(float64) != 403 {
			t.Errorf("launcher %s: %v", line, resp)
		}
	}
	// Nobody else may send one.
	me := uint32(os.Getuid()) //nolint:gosec // uids fit uint32
	for _, who := range []struct {
		uid    uint32
		domain string
	}{{tunnelUID, tunnelDomain}, {me, ""}, {me, "su"}} {
		fp.set(who.uid, who.domain)
		if resp := h.call(`{"op":"note","event":"tunnel.connected"}`); resp["refused"] != "caller_not_allowed" {
			t.Errorf("note from %v: %v", who, resp)
		}
	}
	if n := h.rows.count(); n != 4 || len(h.up.got) != 0 {
		t.Errorf("%d ledger rows, %d upstream requests", n, len(h.up.got))
	}
}

func TestNoteInHealth(t *testing.T) {
	fp := &fakePeers{}
	h := startOpts(t, Passthrough, tunnelCallers, nil, nil, func(o *Options) { o.PeerOf = fp.of })
	fp.set(tunnelUID, launcherDomain)
	h.call(`{"op":"note","event":"tunnel.disconnected","links":1,"error_kind":"network"}`)
	fp.set(uint32(os.Getuid()), "") //nolint:gosec // uids fit uint32
	tun, _ := h.call(`{"op":"health"}`)["body"].(map[string]any)["tunnel"].(map[string]any)
	if tun["event"] != "tunnel.disconnected" || tun["links"] != float64(1) || tun["error_kind"] != "network" {
		t.Errorf("health tunnel = %v", tun)
	}
}

func TestTunnelCallerHasNoRequestSocketOrModelFront(t *testing.T) {
	sockets, local, agent := twoModels(t, nil)
	fp := &fakePeers{}
	h := startOpts(t, Passthrough, func(c *Config) {
		tunnelCallers(c)
		c.ModelSockets = sockets
	}, nil, nil, func(o *Options) { o.PeerOf = fp.of })
	fp.set(tunnelUID, tunnelDomain)
	for _, line := range []string{
		`{"op":"health"}`,
		`{"source":{"region_id":"on-device","adapter":"local"},"method":"POST","path":"/v1/chat/completions","body":{"messages":[]},"egress":{}}`,
		`{"method":"GET","url":"https://api.outgate.ai/health"}`,
		`{"op":"download","url":"https://huggingface.co/x","file":"fd:0"}`,
		`{"op":"note","event":"tunnel.connected"}`,
		`{"op":"ledger"}`,
		`{"op":"appq_list"}`,
	} {
		if resp := h.call(line); resp["refused"] != "caller_not_allowed" {
			t.Errorf("%s: %v", line, resp)
		}
	}

	front := filepath.Join(h.dir, "front.sock")
	fln, err := ListenPath(front, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = h.srv.ServeModel(ctx, fln) }()
	cl := &http.Client{Transport: unixTransport(front)}
	for _, domain := range []string{tunnelDomain, launcherDomain} {
		fp.set(tunnelUID, domain)
		cl.CloseIdleConnections()
		for _, r := range [][3]string{
			{"POST", "/v1/chat/completions", `{"messages":[]}`},
			{"GET", "/health", ""},
			{"GET", "/v1/models", ""},
		} {
			if code, got := frontDo(t, cl, r[0], r[1], strings.NewReader(r[2])); code != 403 || !strings.Contains(got, "caller_not_allowed") {
				t.Errorf("%s %s %s: %d %s", domain, r[0], r[1], code, got)
			}
		}
	}
	if len(local.seen())+len(agent.seen()) != 0 || h.rows.count() != 0 || len(h.up.got) != 0 {
		t.Errorf("model saw %d requests, %d ledger rows", len(local.seen())+len(agent.seen()), h.rows.count())
	}
}

// tunnelEnv is a gate with its tunnel front, a Cloudflare Access team's certs on a TLS test
// server, two fake model instances and a client key. Keys, the audience tag and the client key
// are made at run time.
type tunnelEnv struct {
	t            *testing.T
	h            *harness
	fp           *fakePeers
	tf           *tunnelFront
	cl           *http.Client
	clk          *fakeClock
	certs        *certServer
	dir          string
	team, aud    string
	key          *rsa.PrivateKey
	kid          string
	ckey         string
	local, agent *recModel
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

var (
	rsaKeysMu sync.Mutex
	rsaKeys   []*rsa.PrivateKey
)

// testRSAKey is the i-th RSA key of this test run.
func testRSAKey(t *testing.T, i int) *rsa.PrivateKey {
	t.Helper()
	rsaKeysMu.Lock()
	defer rsaKeysMu.Unlock()
	for len(rsaKeys) <= i {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		rsaKeys = append(rsaKeys, k)
	}
	return rsaKeys[i]
}

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// certServer is a team's /cdn-cgi/access/certs.
type certServer struct {
	srv    *httptest.Server
	hits   atomic.Int32
	mu     sync.Mutex
	keys   map[string]*rsa.PublicKey
	status int
}

func newCertServer(t *testing.T) *certServer {
	c := &certServer{keys: map[string]*rsa.PublicKey{}, status: 200}
	c.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.hits.Add(1)
		c.mu.Lock()
		defer c.mu.Unlock()
		if r.URL.Path != "/cdn-cgi/access/certs" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		if c.status == http.StatusFound {
			http.Redirect(w, r, "https://elsewhere.example.test/certs", http.StatusFound)
			return
		}
		if c.status != 200 {
			w.WriteHeader(c.status)
			return
		}
		keys := []map[string]string{{"kty": "EC", "kid": "ec-1", "crv": "P-256", "x": "AA", "y": "AA"}}
		for kid, k := range c.keys {
			keys = append(keys, map[string]string{
				"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
				"n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes()),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *certServer) set(change func(c *certServer)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	change(c)
}

// transport reaches the cert server for any host, verifying its test certificate.
func (c *certServer) transport() http.RoundTripper {
	tr := c.srv.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.ServerName = "example.com"
	addr := c.srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	return tr
}

// recModel is a llama.cpp instance that records what reaches it, headers included.
type recModel struct {
	alias string
	hold  chan struct{}

	mu   sync.Mutex
	hits []modelHit
}

type modelHit struct {
	Method, Path, Query, Body string
	Header                    http.Header
}

func (m *recModel) serve(t *testing.T, sock string) {
	t.Helper()
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		m.hits = append(m.hits, modelHit{r.Method, r.URL.Path, r.URL.RawQuery, string(b), r.Header.Clone()})
		hold := m.hold
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/health":
			_, _ = io.WriteString(w, `{"status":"ok"}`)
		case r.URL.Path == "/v1/models":
			_, _ = fmt.Fprintf(w, `{"object":"list","data":[{"id":%q,"object":"model"}]}`, m.alias)
		case strings.Contains(string(b), `"stream":true`):
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("X-Upstream-Only", "1")
			for i := 0; i < 3; i++ {
				_, _ = fmt.Fprintf(w, "data: {\"model\":%q,\"i\":%d}\n\n", m.alias, i)
				w.(http.Flusher).Flush()
				if i == 0 && hold != nil {
					select {
					case <-hold:
					case <-time.After(5 * time.Second):
					}
				}
			}
		default:
			_, _ = fmt.Fprintf(w, `{"object":"chat.completion","model":%q}`, m.alias)
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
}

// holdStreams makes streams wait after their first event until the returned channel is closed.
func (m *recModel) holdStreams() chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hold = make(chan struct{})
	return m.hold
}

func (m *recModel) seen() []modelHit {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.hits)
}

// newTunnelEnv starts it all; settings is merged into settings.json's top level.
func newTunnelEnv(t *testing.T, debuggable bool, settings map[string]any) *tunnelEnv {
	t.Helper()
	e := &tunnelEnv{
		t: t, fp: &fakePeers{}, clk: &fakeClock{t: time.Now().Truncate(time.Second)}, certs: newCertServer(t),
		dir: t.TempDir(), team: "ogtest.cloudflareaccess.com", aud: randHex(t, 32),
		key: testRSAKey(t, 0), kid: "kid-" + randHex(t, 4), ckey: randHex(t, 24),
		local: &recModel{alias: "og-local"}, agent: &recModel{alias: "og-local-agent"},
	}
	e.certs.keys[e.kid] = &e.key.PublicKey
	mdir := t.TempDir()
	sockets := map[string]string{"og-local": filepath.Join(mdir, "model.sock"), "og-local-agent": filepath.Join(mdir, "agent.sock")}
	e.local.serve(t, sockets["og-local"])
	e.agent.serve(t, sockets["og-local-agent"])
	e.writeSettings(settings)
	e.writeKeys(map[string]string{"k_laptop": e.ckey})
	e.h = startOpts(t, Mask, func(c *Config) {
		tunnelCallers(c)
		c.ModelSockets = sockets
		c.Debuggable = debuggable
	}, nil, nil, func(o *Options) {
		o.PeerOf, o.TunnelDir, o.Transport = e.fp.of, e.dir, e.certs.transport()
	})
	e.fp.set(tunnelUID, tunnelDomain)
	e.tf = e.h.srv.newTunnelFront()
	e.tf.now, e.tf.busyWait = e.clk.now, 300*time.Millisecond
	sock := filepath.Join(e.h.dir, "tunnel.sock")
	ln, err := ListenPath(sock, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = e.h.srv.serveTunnel(ctx, ln, e.tf) }()
	e.cl = &http.Client{Transport: unixTransport(sock)}
	return e
}

// as makes the next connections come from uid in domain (credentials are read per connection).
func (e *tunnelEnv) as(uid uint32, domain string) {
	e.fp.set(uid, domain)
	e.cl.CloseIdleConnections()
}

func (e *tunnelEnv) writeSettings(extra map[string]any) {
	e.t.Helper()
	s := map[string]any{
		"tunnel_id": "t-1", "hostname": "phone.example.test",
		"access":   map[string]string{"team": e.team, "aud": e.aud},
		"services": map[string]bool{"model": true},
	}
	maps.Copy(s, extra)
	b, _ := json.Marshal(s)
	e.writeFile(tunnelconf.SettingsFile, b)
}

// writeKeys replaces clients.json with these keys (id -> key).
func (e *tunnelEnv) writeKeys(keys map[string]string) {
	e.t.Helper()
	var list []map[string]any
	for id, k := range keys {
		sum := sha256.Sum256([]byte(k))
		list = append(list, map[string]any{"id": id, "name": "Laptop", "created": 1, "sha256": hex.EncodeToString(sum[:])})
	}
	b, _ := json.Marshal(map[string]any{"keys": list})
	e.writeFile(tunnelconf.ClientsFile, b)
}

// writeFile replaces a file by rename and lets the store notice it.
func (e *tunnelEnv) writeFile(name string, b []byte) {
	e.t.Helper()
	tmp := filepath.Join(e.dir, name+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		e.t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(e.dir, name)); err != nil {
		e.t.Fatal(err)
	}
	e.clk.add(2 * time.Second)
}

func mintJWT(t *testing.T, key *rsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	in := b64(hb) + "." + b64(cb)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + b64(sig)
}

// jwt is a valid service-token assertion, changed by mutate (a nil value deletes a claim).
func (e *tunnelEnv) jwt(mutate map[string]any) string {
	e.t.Helper()
	now := e.clk.now().Unix()
	c := map[string]any{
		"aud": []string{e.aud}, "iss": "https://" + e.team, "exp": now + 600, "iat": now, "nbf": now,
		"common_name": "laptop.access", "type": "app",
	}
	for k, v := range mutate {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return mintJWT(e.t, e.key, map[string]any{"alg": "RS256", "kid": e.kid, "typ": "JWT"}, c)
}

// do sends a request with a valid assertion and client key unless hdr says otherwise ("" removes one).
func (e *tunnelEnv) do(method, path string, body io.Reader, hdr map[string]string) (int, string, http.Header) {
	e.t.Helper()
	req, err := http.NewRequest(method, "http://tunnel"+path, body)
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Cf-Access-Jwt-Assertion", e.jwt(nil))
	req.Header.Set("Authorization", "Bearer "+e.ckey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := e.cl.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(b), resp.Header
}

func (e *tunnelEnv) post(body string, hdr map[string]string) (int, string) {
	e.t.Helper()
	code, got, _ := e.do("POST", "/v1/chat/completions", strings.NewReader(body), hdr)
	return code, got
}

// rows are the ledger rows so far: tunnel requests, and access-certs fetches.
func (e *tunnelEnv) rows() (in, certs []ledger.Row) {
	e.h.rows.mu.Lock()
	defer e.h.rows.mu.Unlock()
	for _, r := range e.h.rows.rows {
		switch {
		case r.Direction == "in":
			in = append(in, r)
		case r.Class == "access-certs":
			certs = append(certs, r)
		}
	}
	return in, certs
}

func (e *tunnelEnv) lastIn() ledger.Row {
	e.t.Helper()
	in, _ := e.rows()
	if len(in) == 0 {
		e.t.Fatal("no tunnel rows")
	}
	return in[len(in)-1]
}

func refusedWith(code int, body string, wantCode int, want string) bool {
	return code == wantCode && body == `{"error":"`+want+`"}`
}

func TestTunnelServesTheModel(t *testing.T) {
	e := newTunnelEnv(t, false, nil)
	if code, got, _ := e.do("GET", "/health", nil, nil); code != 200 || got != `{"status":"ok"}` {
		t.Errorf("health: %d %s", code, got)
	}
	if row := e.lastIn(); row.Kind != "other" || row.PathClass != "/health" || row.Method != "GET" || row.Content || row.Blocked {
		t.Errorf("health row = %+v", row)
	}
	body := `{"model":"og-local","messages":[{"role":"user","content":"hi"}]}`
	code, got := e.post(body, nil)
	if code != 200 || !strings.Contains(got, `"model":"og-local"`) {
		t.Fatalf("completion: %d %s", code, got)
	}
	row := e.lastIn()
	want := ledger.Row{
		ID: row.ID, Time: row.Time, DurationMs: row.DurationMs, Caller: "tunnel", UID: tunnelUID, Direction: "in",
		RegionID: "on-device", Destination: "on-device model", Class: "on-device", Kind: "llm", Method: "POST",
		PathClass: "/v1/chat/completions", Status: 200, BytesOut: int64(len(body)), BytesOutRaw: int64(len(body)),
		BytesIn: int64(len(got)), Content: true, OnDevice: true, Mask: MaskNotRequired, Mode: "mask",
		Subject: "service_token:laptop.access", ClientKey: "k_laptop",
	}
	if !reflect.DeepEqual(row, want) || row.ID == "" || row.Time.IsZero() {
		t.Errorf("row =  %+v\nwant %+v", row, want)
	}
	if hits := e.local.seen(); len(hits) != 2 || hits[1].Body != body {
		t.Errorf("og-local saw %+v", hits)
	}
	if n := len(e.agent.seen()); n != 0 {
		t.Errorf("og-local-agent saw %d requests", n)
	}
	if _, certs := e.rows(); len(certs) != 1 {
		t.Errorf("%d certs fetches", len(certs))
	}
}

func TestTunnelAccessJWT(t *testing.T) {
	e := newTunnelEnv(t, false, nil)
	now := e.clk.now().Unix()
	other := testRSAKey(t, 1)
	hdr := func(h map[string]any, claims map[string]any, key *rsa.PrivateKey) string {
		c := map[string]any{"aud": e.aud, "iss": "https://" + e.team, "exp": now + 60, "common_name": "x.access"}
		maps.Copy(c, claims)
		return mintJWT(t, key, h, c)
	}
	rs := map[string]any{"alg": "RS256", "kid": e.kid}
	parts := strings.Split(e.jwt(nil), ".")
	hs := map[string]any{"alg": "HS256", "kid": e.kid}
	hsIn := b64(mustMarshal(hs)) + "." + parts[1]
	mac := hmac.New(sha256.New, e.key.N.Bytes())
	mac.Write([]byte(hsIn))
	good := map[string]string{
		"valid":            e.jwt(nil),
		"aud as a string":  e.jwt(map[string]any{"aud": e.aud}),
		"aud among others": e.jwt(map[string]any{"aud": []string{"other", e.aud}}),
		"exp within skew":  e.jwt(map[string]any{"exp": now - 30}),
		"nbf within skew":  e.jwt(map[string]any{"nbf": now + 30, "iat": now + 30}),
		"no nbf or iat":    e.jwt(map[string]any{"nbf": nil, "iat": nil}),
	}
	for name, tok := range good {
		if code, got, _ := e.do("GET", "/health", nil, map[string]string{"Cf-Access-Jwt-Assertion": tok}); code != 200 {
			t.Errorf("%s: %d %s", name, code, got)
		}
	}
	bad := map[string][2]string{
		"wrong aud":         {e.jwt(map[string]any{"aud": []string{randHex(t, 32)}}), "aud"},
		"no aud":            {e.jwt(map[string]any{"aud": nil}), "aud"},
		"aud not a string":  {e.jwt(map[string]any{"aud": 7}), "aud"},
		"wrong iss":         {e.jwt(map[string]any{"iss": "https://other.cloudflareaccess.com"}), "iss"},
		"iss without https": {e.jwt(map[string]any{"iss": e.team}), "iss"},
		"expired":           {e.jwt(map[string]any{"exp": now - 120}), "expired"},
		"no exp":            {e.jwt(map[string]any{"exp": nil}), "expired"},
		"nbf in the future": {e.jwt(map[string]any{"nbf": now + 300}), "not_yet_valid"},
		"iat in the future": {e.jwt(map[string]any{"iat": now + 300}), "not_yet_valid"},
		"other key":         {hdr(rs, nil, other), "signature"},
		"payload swapped":   {parts[0] + "." + strings.Split(e.jwt(map[string]any{"common_name": "y.access"}), ".")[1] + "." + parts[2], "signature"},
		"alg none":          {b64(mustMarshal(map[string]any{"alg": "none", "kid": e.kid})) + "." + parts[1] + ".", "alg"},
		"alg HS256":         {hsIn + "." + b64(mac.Sum(nil)), "alg"},
		"alg RS512":         {hdr(map[string]any{"alg": "RS512", "kid": e.kid}, nil, e.key), "alg"},
		"alg lower case":    {hdr(map[string]any{"alg": "rs256", "kid": e.kid}, nil, e.key), "alg"},
		"crit header":       {hdr(map[string]any{"alg": "RS256", "kid": e.kid, "crit": []string{"exp"}}, nil, e.key), "alg"},
		"no kid":            {hdr(map[string]any{"alg": "RS256"}, nil, e.key), "malformed"},
		"two parts":         {parts[0] + "." + parts[1], "malformed"},
		"padded":            {parts[0] + "." + parts[1] + "." + parts[2] + "==", "malformed"},
		"jku elsewhere":     {hdr(map[string]any{"alg": "RS256", "kid": "evil", "jku": "https://evil.example.test/certs"}, nil, other), "kid"},
	}
	for name, c := range bad {
		code, got, _ := e.do("GET", "/health", nil, map[string]string{"Cf-Access-Jwt-Assertion": c[0]})
		row := e.lastIn()
		if !refusedWith(code, got, 403, "access_jwt") || !row.Blocked || row.BlockReason != "access_jwt" || row.Error != "access:"+c[1] || row.Content || row.Subject != "" {
			t.Errorf("%s: %d %s, row %+v", name, code, got, row)
		}
	}
	for name, h := range map[string]map[string]string{"missing": {"Cf-Access-Jwt-Assertion": ""}, "cookie only": {"Cf-Access-Jwt-Assertion": "", "Cookie": "CF_Authorization=" + e.jwt(nil)}} {
		if code, got, _ := e.do("GET", "/health", nil, h); !refusedWith(code, got, 403, "access_jwt") || e.lastIn().Error != "access:missing" {
			t.Errorf("%s: %d %s", name, code, got)
		}
	}
	req, _ := http.NewRequest("GET", "http://tunnel/health", nil)
	req.Header.Add("Cf-Access-Jwt-Assertion", e.jwt(nil))
	req.Header.Add("Cf-Access-Jwt-Assertion", e.jwt(nil))
	req.Header.Set("Authorization", "Bearer "+e.ckey)
	if resp, err := e.cl.Do(req); err != nil || resp.StatusCode != 403 {
		t.Errorf("two assertions: %v %v", resp, err)
	}
	if n := len(e.local.seen()); n != len(good) {
		t.Errorf("the model saw %d requests", n)
	}
	// Only the first request fetched the certs (kid "evil" came within the minute); jku is never fetched.
	if _, certs := e.rows(); len(certs) != 1 || e.certs.hits.Load() != 1 {
		t.Errorf("%d certs rows, %d fetches", len(certs), e.certs.hits.Load())
	}
}

func mustMarshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func TestTunnelAccessCerts(t *testing.T) {
	e := newTunnelEnv(t, false, nil)
	if code, _, _ := e.do("GET", "/health", nil, nil); code != 200 {
		t.Fatal(code)
	}
	_, certs := e.rows()
	if len(certs) != 1 {
		t.Fatalf("%d certs rows", len(certs))
	}
	if c := certs[0]; c.Caller != "gate" || c.Destination != e.team || c.Method != "GET" || c.PathClass != "/cdn-cgi/access/certs" ||
		c.Status != 200 || c.BytesIn == 0 || c.Kind != "other" || c.Content || c.Blocked || c.Error != "" || c.Direction != "" {
		t.Errorf("certs row = %+v", c)
	}
	newKid := "kid-" + randHex(t, 4)
	newKey := testRSAKey(t, 1)
	withKid := func(kid string) map[string]string {
		c := map[string]any{"aud": e.aud, "iss": "https://" + e.team, "exp": e.clk.now().Unix() + 60, "common_name": "x.access"}
		return map[string]string{"Cf-Access-Jwt-Assertion": mintJWT(t, newKey, map[string]any{"alg": "RS256", "kid": kid}, c)}
	}
	// An unknown kid within a minute of the last fetch: refused, nothing fetched.
	if code, got, _ := e.do("GET", "/health", nil, withKid(newKid)); !refusedWith(code, got, 403, "access_jwt") || e.certs.hits.Load() != 1 {
		t.Errorf("unknown kid at once: %d %s, %d fetches", code, got, e.certs.hits.Load())
	}
	// After a minute: fetched again once, still unknown, refused; the next unknown kid waits.
	e.clk.add(61 * time.Second)
	for i := 0; i < 3; i++ {
		if code, got, _ := e.do("GET", "/health", nil, withKid(newKid)); !refusedWith(code, got, 403, "access_jwt") || e.lastIn().Error != "access:kid" {
			t.Errorf("unknown kid: %d %s", code, got)
		}
	}
	if n := e.certs.hits.Load(); n != 2 {
		t.Errorf("%d fetches for an unknown kid", n)
	}
	// Known kids still pass meanwhile, from the cache.
	if code, _, _ := e.do("GET", "/health", nil, nil); code != 200 || e.certs.hits.Load() != 2 {
		t.Errorf("known kid: %d, %d fetches", code, e.certs.hits.Load())
	}
	// The team rotates: the new key is found after the next minute.
	e.certs.set(func(c *certServer) { c.keys[newKid] = &newKey.PublicKey })
	if code, _, _ := e.do("GET", "/health", nil, withKid(newKid)); code != 403 {
		t.Errorf("rotated key within the minute: %d", code)
	}
	e.clk.add(61 * time.Second)
	if code, got, _ := e.do("GET", "/health", nil, withKid(newKid)); code != 200 || e.certs.hits.Load() != 3 {
		t.Errorf("rotated key: %d %s, %d fetches", code, got, e.certs.hits.Load())
	}
	// After an hour the certs are fetched again; a failed fetch keeps the keys known.
	e.certs.set(func(c *certServer) { c.status = http.StatusFound })
	e.clk.add(time.Hour)
	if code, _, _ := e.do("GET", "/health", nil, nil); code != 200 || e.certs.hits.Load() != 4 {
		t.Errorf("stale certs, failed fetch: %d, %d fetches", code, e.certs.hits.Load())
	}
	_, certs = e.rows()
	if c := certs[len(certs)-1]; len(certs) != 4 || c.Status != http.StatusFound || c.Error != "status" {
		t.Errorf("redirected fetch: %d rows, %+v", len(certs), c)
	}
	e.certs.set(func(c *certServer) { c.status = 500 })
	e.clk.add(61 * time.Second)
	if code, _, _ := e.do("GET", "/health", nil, withKid("kid-unknown")); code != 403 || e.certs.hits.Load() != 5 {
		t.Errorf("failed fetch: %d, %d fetches", code, e.certs.hits.Load())
	}
	if _, certs := e.rows(); certs[len(certs)-1].Status != 500 || certs[len(certs)-1].Error != "status" {
		t.Errorf("failed fetch row %+v", certs[len(certs)-1])
	}
}

func TestParseAccessCerts(t *testing.T) {
	k := testRSAKey(t, 0)
	rsaJWK := func(kid string, n []byte, e int, extra map[string]string) map[string]string {
		m := map[string]string{"kty": "RSA", "kid": kid, "n": b64(n), "e": b64(big.NewInt(int64(e)).Bytes())}
		maps.Copy(m, extra)
		return m
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]any{"keys": []map[string]string{
		rsaJWK("ok", k.N.Bytes(), k.E, nil),
		rsaJWK("small", small.N.Bytes(), small.E, nil),
		rsaJWK("enc", k.N.Bytes(), k.E, map[string]string{"use": "enc"}),
		rsaJWK("ps256", k.N.Bytes(), k.E, map[string]string{"alg": "PS256"}),
		rsaJWK("even-e", k.N.Bytes(), 65536, nil),
		rsaJWK("", k.N.Bytes(), k.E, nil),
		{"kty": "EC", "kid": "ec", "crv": "P-256", "x": "AA", "y": "AA"},
		{"kty": "oct", "kid": "hmac", "k": "AA"},
	}}
	keys, err := parseAccessCerts(mustMarshal(set))
	if err != nil || len(keys) != 1 || keys["ok"] == nil || keys["ok"].N.Cmp(k.N) != 0 {
		t.Errorf("keys = %v %v", keys, err)
	}
	for _, b := range []string{`{"keys":[]}`, `[]`, `{"keys":[{"kty":"EC","kid":"a"}]}`, `not json`} {
		if _, err := parseAccessCerts([]byte(b)); err == nil {
			t.Errorf("%s accepted", b)
		}
	}
}

func TestTunnelSubjects(t *testing.T) {
	e := newTunnelEnv(t, false, nil)
	addr := "Some.One" + string(rune(64)) + "Example.Test"
	jwt := func(c map[string]any) map[string]string {
		return map[string]string{"Cf-Access-Jwt-Assertion": e.jwt(c)}
	}
	if code, _, _ := e.do("GET", "/health", nil, jwt(map[string]any{"common_name": nil, "email": addr})); code != 200 {
		t.Fatal(code)
	}
	salt, err := os.ReadFile(filepath.Join(e.h.dir, "state", "tunnel-salt"))
	if err != nil || len(salt) != 32 {
		t.Fatalf("salt: %d bytes, %v", len(salt), err)
	}
	if fi, _ := os.Stat(filepath.Join(e.h.dir, "state", "tunnel-salt")); fi.Mode().Perm() != 0o600 {
		t.Errorf("salt mode %v", fi.Mode())
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(strings.ToLower(addr)))
	user := "user:" + hex.EncodeToString(mac.Sum(nil))[:16]
	if s := e.lastIn().Subject; s != user {
		t.Errorf("user subject %q, want %q", s, user)
	}
	e.do("GET", "/health", nil, jwt(map[string]any{"common_name": nil, "email": strings.ToLower(addr)}))
	if s := e.lastIn().Subject; s != user {
		t.Errorf("lower-case address: %q", s)
	}
	e.do("GET", "/health", nil, jwt(map[string]any{"email": addr}))
	if s := e.lastIn().Subject; s != "service_token:laptop.access" {
		t.Errorf("service token with an email: %q", s)
	}
	e.do("GET", "/health", nil, jwt(map[string]any{"common_name": nil}))
	if s := e.lastIn().Subject; s != "other" {
		t.Errorf("neither: %q", s)
	}
	e.do("GET", "/health", nil, jwt(map[string]any{"common_name": "odd name/" + addr}))
	if s := e.lastIn().Subject; !strings.HasPrefix(s, "service_token:") || len(s) != len("service_token:")+16 {
		t.Errorf("odd service token name: %q", s)
	}
	in, _ := e.rows()
	b, _ := json.Marshal(in)
	for _, leak := range []string{strings.ToLower(addr), addr, "Some.One", "some.one", "Example.Test"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("a row holds %q", leak)
		}
	}
	// The salt is kept: a new front hashes alike.
	tf := e.h.srv.newTunnelFront()
	if s := tf.subject(&accessClaims{Email: addr}); s != user {
		t.Errorf("after restart: %q", s)
	}
}

func TestTunnelClientKey(t *testing.T) {
	e := newTunnelEnv(t, false, nil)
	if code, _, _ := e.do("GET", "/health", nil, nil); code != 200 || e.lastIn().ClientKey != "k_laptop" {
		t.Errorf("key: %d %+v", code, e.lastIn())
	}
	for name, auth := range map[string]string{
		"missing":       "",
		"unknown":       "Bearer " + randHex(t, 24),
		"empty":         "Bearer ",
		"basic":         "Basic " + e.ckey,
		"no scheme":     e.ckey,
		"double bearer": "Bearer Bearer " + e.ckey,
	} {
		code, got, _ := e.do("GET", "/health", nil, map[string]string{"Authorization": auth})
		row := e.lastIn()
		if !refusedWith(code, got, 403, "client_key") || row.BlockReason != "client_key" || row.ClientKey != "" || row.Subject == "" || row.Content {
			t.Errorf("%s: %d %s %+v", name, code, got, row)
		}
	}
	if code, _, _ := e.do("GET", "/health", nil, map[string]string{"Authorization": "bearer " + e.ckey}); code != 200 {
		t.Errorf("scheme case: %d", code)
	}
	// Revoked: clients.json rewritten without it.
	other := randHex(t, 24)
	e.writeKeys(map[string]string{"k_phone": other})
	if code, got, _ := e.do("GET", "/health", nil, nil); !refusedWith(code, got, 403, "client_key") {
		t.Errorf("revoked: %d %s", code, got)
	}
	if code, _, _ := e.do("GET", "/health", nil, map[string]string{"Authorization": "Bearer " + other}); code != 200 || e.lastIn().ClientKey != "k_phone" {
		t.Errorf("new key: %d", code)
	}
	// require_client_key false is ignored on a user build: the key stays required.
	e.writeSettings(map[string]any{"require_client_key": false})
	if code, got, _ := e.do("GET", "/health", nil, map[string]string{"Authorization": ""}); !refusedWith(code, got, 403, "client_key") {
		t.Errorf("user build, require_client_key false, no key: %d %s", code, got)
	}
}

func TestTunnelAccessOnlyDebuggable(t *testing.T) {
	e := newTunnelEnv(t, true, map[string]any{"require_client_key": false})
	if code, _, _ := e.do("GET", "/health", nil, map[string]string{"Authorization": ""}); code != 200 || e.lastIn().ClientKey != "" {
		t.Errorf("access only, no key: %d %+v", code, e.lastIn())
	}
	if code, _, _ := e.do("GET", "/health", nil, map[string]string{"Authorization": "Bearer " + e.ckey}); code != 200 || e.lastIn().ClientKey != "k_laptop" {
		t.Errorf("access only, key: %d", code)
	}
	if code, _, _ := e.do("GET", "/health", nil, map[string]string{"Cf-Access-Jwt-Assertion": ""}); code != 403 {
		t.Errorf("access only, no assertion: %d", code)
	}
}

func TestTunnelNotConfigured(t *testing.T) {
	e := newTunnelEnv(t, false, nil)
	check := func(name string, wantCode int, want string) {
		t.Helper()
		code, got, _ := e.do("GET", "/health", nil, nil)
		if !refusedWith(code, got, wantCode, want) || e.lastIn().BlockReason != want {
			t.Errorf("%s: %d %s", name, code, got)
		}
	}
	e.writeSettings(map[string]any{"services": map[string]bool{"model": false}})
	check("model off", 503, "service_off")
	e.writeSettings(map[string]any{"services": nil})
	check("no services", 503, "service_off")
	e.writeSettings(map[string]any{"access": map[string]string{"team": "evil.example.test", "aud": e.aud}})
	check("team not pinned", 503, "tunnel_not_configured")
	e.writeSettings(map[string]any{"access": map[string]string{"team": e.team}})
	check("no aud", 503, "tunnel_not_configured")
	e.writeSettings(nil)
	_ = os.Remove(filepath.Join(e.dir, tunnelconf.ClientsFile))
	e.clk.add(2 * time.Second)
	check("no clients.json", 503, "tunnel_not_configured")
	_ = os.RemoveAll(e.dir)
	e.clk.add(2 * time.Second)
	check("no tunnel dir", 503, "tunnel_not_configured")
	if n := len(e.local.seen()); n != 0 {
		t.Errorf("the model saw %d requests", n)
	}
}

func TestTunnelAllowlist(t *testing.T) {
	e := newTunnelEnv(t, false, nil)
	for _, r := range [][2]string{
		{"POST", "/health"}, {"GET", "/v1/chat/completions"}, {"GET", "/v1/models/"}, {"GET", "/v1/models/og-local"},
		{"GET", "/slots"}, {"GET", "/h%65alth"}, {"GET", "/v1%2Fmodels"}, {"GET", "/v1/../health"}, {"GET", "//health"},
		{"HEAD", "/health"}, {"DELETE", "/v1/models"}, {"PUT", "/v1/chat/completions"}, {"OPTIONS", "/v1/chat/completions"},
		{"GET", "/health/"}, {"GET", "/v1/completions"}, {"POST", "/v1/embeddings"}, {"PROPFIND", "/health"},
	} {
		code, got, _ := e.do(r[0], r[1], strings.NewReader(`{}`), nil)
		row := e.lastIn()
		_, listed := tunnelRoutes[r[1]]
		wantPath := "other"
		if listed {
			wantPath = r[1]
		}
		if r[0] == "HEAD" {
			got = `{"error":"not_allowed"}`
		}
		if !refusedWith(code, got, 404, "not_allowed") || row.PathClass != wantPath || row.BlockReason != "not_allowed" || row.Content {
			t.Errorf("%s %s: %d %s, row %+v", r[0], r[1], code, got, row)
		}
	}
	if row := e.lastIn(); row.Method != "OTHER" {
		t.Errorf("PROPFIND row method %q", row.Method)
	}
	if n := len(e.local.seen()) + len(e.agent.seen()); n != 0 {
		t.Errorf("the model saw %d requests", n)
	}
	// The query never reaches the model; GET /v1/models is og-local's own list.
	if code, got, _ := e.do("GET", "/health?model=og-local-agent", nil, nil); code != 200 || got != `{"status":"ok"}` {
		t.Errorf("health with a query: %d %s", code, got)
	}
	code, got, _ := e.do("GET", "/v1/models?model=og-local-agent", nil, nil)
	if code != 200 || !strings.Contains(got, `"id":"og-local"`) || strings.Contains(got, "og-local-agent") {
		t.Errorf("models: %d %s", code, got)
	}
	for _, h := range e.local.seen() {
		if h.Query != "" {
			t.Errorf("og-local got query %q", h.Query)
		}
	}
	if n := len(e.agent.seen()); n != 0 {
		t.Errorf("og-local-agent saw %d requests", n)
	}
}

func TestTunnelRefusesOtherModels(t *testing.T) {
	e := newTunnelEnv(t, false, nil)
	for _, body := range []string{
		`{"model":"og-local-agent","messages":[]}`,
		`{"model":"OG-Local-Agent ","messages":[]}`,
		`{"messages":[],"model":"og-local-agent"}`,
	} {
		code, got := e.post(body, nil)
		if !refusedWith(code, got, 403, "not_allowed") || e.lastIn().BlockReason != "not_allowed" || e.lastIn().Content {
			t.Errorf("%s: %d %s", body, code, got)
		}
	}
	forwarded := []string{
		`{"model":"og-local","messages":[]}`,
		`{"model":"gpt-4o","messages":[]}`,
		`{"messages":[{"role":"user","content":"og-local-agent"}]}`,
		`{"model":["og-local-agent"],"messages":[]}`,
		`not json`,
	}
	for _, body := range forwarded {
		if code, got := e.post(body, nil); code != 200 || !strings.Contains(got, `"model":"og-local"`) {
			t.Errorf("%s: %d %s", body, code, got)
		}
	}
	hits := e.local.seen()
	if len(hits) != len(forwarded) {
		t.Fatalf("og-local saw %d", len(hits))
	}
	for i, h := range hits {
		if h.Body != forwarded[i] {
			t.Errorf("og-local got %q, sent %q", h.Body, forwarded[i])
		}
	}
	if n := len(e.agent.seen()); n != 0 {
		t.Errorf("og-local-agent saw %d", n)
	}
}

func TestTunnelStripsHeaders(t *testing.T) {
	e := newTunnelEnv(t, false, nil)
	code, got := e.post(`{"stream":true,"messages":[]}`, map[string]string{
		"Accept": "text/event-stream", "Cookie": "CF_Authorization=x; other=y", "X-Forwarded-For": "192.0.2.1",
		"Cf-Connecting-Ip": "192.0.2.1", "Cf-Access-Client-Id": "x.access", "Cf-Access-Client-Secret": "<redacted>",
		"Cf-Ray": "1-AMS", "X-Request-Id": "r1", "Origin": "https://phone.example.test", "User-Agent": "laptop-client/1",
		"Proxy-Authorization": "Basic <redacted>", "Forwarded": "for=192.0.2.1",
	})
	if code != 200 || !strings.Contains(got, `"i":2`) {
		t.Fatalf("%d %s", code, got)
	}
	hit := e.local.seen()[0]
	if hit.Header.Get("Content-Type") != "application/json" || hit.Header.Get("Accept") != "text/event-stream" {
		t.Errorf("kept headers missing: %v", hit.Header)
	}
	for k := range hit.Header {
		switch k {
		case "Content-Type", "Accept", "Content-Length", "Accept-Encoding", "User-Agent":
		default:
			t.Errorf("the model got %s", k)
		}
	}
	if ua := hit.Header.Get("User-Agent"); strings.Contains(ua, "laptop") {
		t.Errorf("User-Agent passed through: %q", ua)
	}
	// Only Content-Type and Cache-Control come back.
	_, _, h := e.do("POST", "/v1/chat/completions", strings.NewReader(`{"stream":true}`), nil)
	if h.Get("X-Upstream-Only") != "" || h.Get("Content-Type") != "text/event-stream" || h.Get("Cache-Control") != "no-cache" {
		t.Errorf("response headers %v", h)
	}
}

func TestTunnelStreams(t *testing.T) {
	e := newTunnelEnv(t, false, nil)
	hold := e.local.holdStreams()
	req, _ := http.NewRequest("POST", "http://tunnel/v1/chat/completions", strings.NewReader(`{"stream":true,"messages":[]}`))
	req.Header.Set("Cf-Access-Jwt-Assertion", e.jwt(nil))
	req.Header.Set("Authorization", "Bearer "+e.ckey)
	resp, err := e.cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	rd := bufio.NewReader(resp.Body)
	first, err := rd.ReadString('\n')
	if err != nil || first != "data: {\"model\":\"og-local\",\"i\":0}\n" {
		t.Fatalf("first event before the rest: %q %v", first, err)
	}
	close(hold)
	rest, _ := io.ReadAll(rd)
	if !strings.Contains(string(rest), `"i":2`) {
		t.Fatalf("rest %q", rest)
	}
	_ = resp.Body.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if in, _ := e.rows(); len(in) == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if row := e.lastIn(); row.BytesIn != int64(len(first)+len(rest)) || row.Kind != "llm" || row.Status != 200 {
		t.Errorf("row %+v", row)
	}
}

func TestTunnelRateLimit(t *testing.T) {
	e := newTunnelEnv(t, false, nil)
	other := randHex(t, 24)
	e.writeKeys(map[string]string{"k_laptop": e.ckey, "k_phone": other})
	for i := 0; i < 30; i++ {
		if code, got, _ := e.do("GET", "/health", nil, nil); code != 200 {
			t.Fatalf("request %d: %d %s", i, code, got)
		}
	}
	code, got, h := e.do("GET", "/health", nil, nil)
	if !refusedWith(code, got, 429, "rate_limited") || h.Get("Retry-After") != "2" {
		t.Errorf("31st: %d %s %v", code, got, h)
	}
	if row := e.lastIn(); row.BlockReason != "rate_limited" || row.ClientKey != "k_laptop" || row.Content {
		t.Errorf("row %+v", row)
	}
	if code, _, _ := e.do("GET", "/health", nil, map[string]string{"Authorization": "Bearer " + other}); code != 200 {
		t.Errorf("another key: %d", code)
	}
	e.clk.add(2 * time.Second)
	if code, _, _ := e.do("GET", "/health", nil, nil); code != 200 {
		t.Errorf("after 2 s: %d", code)
	}
	if code, _, _ := e.do("GET", "/health", nil, nil); code != 429 {
		t.Errorf("then: %d", code)
	}
	// Refusals before the key check spend no tokens.
	e.clk.add(time.Minute)
	for i := 0; i < 40; i++ {
		e.do("GET", "/health", nil, map[string]string{"Cf-Access-Jwt-Assertion": ""})
	}
	if code, _, _ := e.do("GET", "/health", nil, nil); code != 200 {
		t.Errorf("after refusals: %d", code)
	}
}

func TestTunnelBusy(t *testing.T) {
	e := newTunnelEnv(t, false, nil)
	hold := e.local.holdStreams()
	var wg sync.WaitGroup
	firsts := make(chan string, 2)
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest("POST", "http://tunnel/v1/chat/completions", strings.NewReader(`{"stream":true}`))
		req.Header.Set("Cf-Access-Jwt-Assertion", e.jwt(nil))
		req.Header.Set("Authorization", "Bearer "+e.ckey)
		resp, err := e.cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		rd := bufio.NewReader(resp.Body)
		line, _ := rd.ReadString('\n')
		firsts <- line
		wg.Go(func() {
			_, _ = io.ReadAll(rd)
			_ = resp.Body.Close()
		})
	}
	start := time.Now()
	code, got := e.post(`{"messages":[]}`, nil)
	if !refusedWith(code, got, 503, "busy") || time.Since(start) < 250*time.Millisecond {
		t.Errorf("third: %d %s after %s", code, got, time.Since(start))
	}
	if row := e.lastIn(); row.BlockReason != "busy" || row.Content || row.BytesOut != 0 {
		t.Errorf("row %+v", row)
	}
	close(hold)
	wg.Wait()
	if code, _ := e.post(`{"messages":[]}`, nil); code != 200 {
		t.Errorf("after: %d", code)
	}
	if len(firsts) != 2 {
		t.Error("streams did not start")
	}
}

func TestTunnelBodyLimit(t *testing.T) {
	e := newTunnelEnv(t, false, nil)
	pad := func(n int) string {
		head := `{"messages":[],"pad":"`
		return head + strings.Repeat("a", n-len(head)-2) + `"}`
	}
	if code, got := e.post(pad(tunnelMaxBody), nil); code != 200 {
		t.Errorf("1 MiB: %d %s", code, got)
	}
	if code, got := e.post(pad(tunnelMaxBody+1), nil); !refusedWith(code, got, 413, "body_too_large") {
		t.Errorf("1 MiB + 1: %d %s", code, got)
	}
	code, got, _ := e.do("POST", "/v1/chat/completions", io.MultiReader(strings.NewReader(pad(tunnelMaxBody+1))), nil)
	if !refusedWith(code, got, 413, "body_too_large") {
		t.Errorf("chunked: %d %s", code, got)
	}
	if row := e.lastIn(); row.BlockReason != "body_too_large" || row.Content || row.BytesOut != 0 {
		t.Errorf("row %+v", row)
	}
	if n := len(e.local.seen()); n != 1 {
		t.Errorf("the model saw %d", n)
	}
}

func TestTunnelRefusalRowsCapped(t *testing.T) {
	e := newTunnelEnv(t, false, nil)
	for i := 0; i < 65; i++ {
		if code, _, _ := e.do("GET", "/health", nil, map[string]string{"Cf-Access-Jwt-Assertion": ""}); code != 403 {
			t.Fatal(code)
		}
	}
	in, _ := e.rows()
	if len(in) != 60 {
		t.Fatalf("%d refusal rows", len(in))
	}
	for _, r := range in {
		if !r.Blocked || r.Content || r.BlockReason != "access_jwt" {
			t.Errorf("row %+v", r)
		}
	}
	// Refusals past the key check are not capped.
	if code, _, _ := e.do("GET", "/slots", nil, nil); code != 404 {
		t.Error(code)
	}
	if in, _ := e.rows(); len(in) != 61 || in[60].BlockReason != "not_allowed" {
		t.Errorf("uncapped refusal: %d rows", len(in))
	}
	e.tf.flushSuppressed()
	if in, _ := e.rows(); len(in) != 61 {
		t.Errorf("suppressed written within the minute: %d", len(in))
	}
	e.clk.add(61 * time.Second)
	e.tf.flushSuppressed()
	in, _ = e.rows()
	if s := in[len(in)-1]; len(in) != 62 || s.Error != "suppressed:5" || !s.Blocked || s.BlockReason != "suppressed" || s.Content || s.Caller != "tunnel" {
		t.Errorf("suppressed row: %d rows, %+v", len(in), in[len(in)-1])
	}
	e.tf.flushSuppressed()
	// A new minute: written again; the next dropped count comes with the first refusal after it.
	for i := 0; i < 62; i++ {
		e.do("GET", "/health", nil, map[string]string{"Authorization": ""})
	}
	if in, _ := e.rows(); len(in) != 122 {
		t.Errorf("%d rows", len(in))
	}
	e.clk.add(time.Minute)
	e.do("GET", "/health", nil, map[string]string{"Authorization": ""})
	in, _ = e.rows()
	if len(in) != 124 || in[122].Error != "suppressed:2" || in[123].BlockReason != "client_key" {
		t.Errorf("%d rows, %+v", len(in), in[len(in)-2:])
	}
}

func TestTunnelCallers(t *testing.T) {
	e := newTunnelEnv(t, false, nil)
	me := uint32(os.Getuid()) //nolint:gosec // uids fit uint32
	for _, who := range []struct {
		uid    uint32
		domain string
	}{{tunnelUID, launcherDomain}, {me, ""}, {0, "su"}, {tunnelUID, ""}, {tunnelUID + 1, tunnelDomain}} {
		e.as(who.uid, who.domain)
		if code, got, _ := e.do("GET", "/health", nil, nil); !refusedWith(code, got, 403, "caller_not_allowed") {
			t.Errorf("%v: %d %s", who, code, got)
		}
	}
	if in, certs := e.rows(); len(in)+len(certs) != 0 || len(e.local.seen()) != 0 {
		t.Errorf("refused callers: %d rows, %d certs fetches", len(in), len(certs))
	}

	// su is a debug caller on debuggable builds only (above: refused), there to try the refusals.
	if class := e.h.srv.classify(peer.Cred{UID: 0, Context: "u:r:su:s0"}); class != "" {
		t.Errorf("su classified %q on a user build", class)
	}
	d := newTunnelEnv(t, true, nil)
	d.as(0, "su")
	if code, got, _ := d.do("GET", "/health", nil, nil); code != 200 || d.lastIn().Caller != "debug" || d.lastIn().UID != 0 {
		t.Errorf("debug: %d %s %+v", code, got, d.lastIn())
	}
	if code, got, _ := d.do("GET", "/health", nil, map[string]string{"Authorization": ""}); !refusedWith(code, got, 403, "client_key") || d.lastIn().Caller != "debug" {
		t.Errorf("debug without a key: %d %s", code, got)
	}
	d.as(tunnelUID, tunnelDomain)
	if code, _, _ := d.do("GET", "/health", nil, nil); code != 200 || d.lastIn().Caller != "tunnel" {
		t.Errorf("tunnel on a debuggable build: %d %+v", code, d.lastIn())
	}
}
