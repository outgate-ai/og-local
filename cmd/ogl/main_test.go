package main

import "testing"

func TestInvokedAs(t *testing.T) {
	cases := []struct {
		argv0 string
		cmd   string
		ok    bool
	}{
		{"/usr/local/bin/ogl-claude", "claude", true},
		{"ogl-claude", "claude", true},
		{"dist/ogl-claude.exe", "claude", true},
		{"/opt/bin/ogl-codex", "codex", true},
		{"ogl-codex.exe", "codex", true},
		{"/usr/local/bin/ogl", "", false},
		{"ogl.exe", "", false},
		{"claude", "", false},
		{"my-ogl-claude", "", false},
	}
	for _, c := range cases {
		cmd, ok := invokedAs(c.argv0)
		if cmd != c.cmd || ok != c.ok {
			t.Errorf("invokedAs(%q) = (%q, %v), want (%q, %v)", c.argv0, cmd, ok, c.cmd, c.ok)
		}
	}
}
