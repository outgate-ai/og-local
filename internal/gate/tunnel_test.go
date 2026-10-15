package gate

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/outgate-ai/og-local/internal/gate/peer"
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
