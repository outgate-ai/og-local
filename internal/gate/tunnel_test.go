package gate

import (
	"net"
	"os"
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
