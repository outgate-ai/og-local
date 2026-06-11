package launch

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const shellProbeTimeout = 5 * time.Second

// resolveAgent locates the agent binary for argv[0]. GUI hosts (IDE
// extensions) often spawn ogl without the user's shell PATH, so a plain
// lookup miss falls back to asking the login shell where the binary lives —
// interactive last, since version managers commonly hook only interactive rc
// files. OGL_<AGENT>_BIN overrides every step.
func resolveAgent(ctx context.Context, name string, env []string,
	lookPath func(string) (string, error),
	shellOut func(ctx context.Context, shell string, args ...string) (string, error),
) (string, error) {
	override := "OGL_" + strings.ToUpper(name) + "_BIN"
	if bin := envValue(env, override); bin != "" {
		return bin, nil
	}
	if p, err := lookPath(name); err == nil {
		return p, nil
	}
	shell := envValue(env, "SHELL")
	if shell == "" {
		return "", fmt.Errorf("launch: %q not found in PATH and SHELL is unset; set %s to the agent binary", name, override)
	}
	for _, flags := range [][]string{{"-l", "-c"}, {"-i", "-l", "-c"}} {
		probeCtx, cancel := context.WithTimeout(ctx, shellProbeTimeout)
		out, err := shellOut(probeCtx, shell, append(flags, "command -v -- "+name)...)
		cancel()
		if err != nil {
			continue
		}
		if p := lastAbsLine(out); p != "" {
			return p, nil
		}
	}
	return "", fmt.Errorf("launch: %q not found in PATH or via %s; set %s to the agent binary", name, shell, override)
}

// lastAbsLine returns the last absolute-path line of out. Login shells print
// rc-file noise (e.g. version managers announcing themselves) before the
// `command -v` result.
func lastAbsLine(out string) string {
	lines := strings.Split(out, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); strings.HasPrefix(l, "/") {
			return l
		}
	}
	return ""
}

func envValue(env []string, key string) string {
	prefix := key + "="
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			return kv[len(prefix):]
		}
	}
	return ""
}

func runShell(ctx context.Context, shell string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, shell, args...).Output() //nolint:gosec // shell is the user's own $SHELL; the probe runs their login environment.
	return string(out), err
}
