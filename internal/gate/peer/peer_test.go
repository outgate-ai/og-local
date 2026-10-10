package peer

import "testing"

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
