package peer

import (
	"os"
	"testing"
	"time"
)

func TestDomain(t *testing.T) {
	cases := map[string]string{
		"u:r:outgate_agent:s0":          "outgate_agent",
		"u:r:platform_app:s0:c512,c768": "platform_app",
		"":                              "",
		"unconfined":                    "",
	}
	for ctx, want := range cases {
		if got := (Cred{Context: ctx}).Domain(); got != want {
			t.Errorf("Domain(%q) = %q, want %q", ctx, got, want)
		}
	}
}

func TestPackages(t *testing.T) {
	path := t.TempDir() + "/packages.list"
	write := func(s string) {
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("ai.outgate.chat 10187 0 /data/user/0/ai.outgate.chat platform:privapp:targetSdkVersion=35 3003\ncom.example.app 10200 0 /data/user/0/com.example.app default:targetSdkVersion=36 none\n")
	p := &Packages{Path: path}
	if got := p.Names(10187); len(got) != 1 || got[0] != "ai.outgate.chat" {
		t.Errorf("Names(10187) = %v", got)
	}
	if got := p.Names(1010187); len(got) != 1 || got[0] != "ai.outgate.chat" {
		t.Errorf("secondary user: %v", got)
	}
	if got := p.Names(10999); got != nil {
		t.Errorf("unknown uid: %v", got)
	}
	time.Sleep(10 * time.Millisecond)
	write("ai.outgate.chat 10300 0 /data/user/0/ai.outgate.chat platform 3003\n")
	if got := p.Names(10187); got != nil {
		t.Errorf("stale uid after reinstall: %v", got)
	}
}
