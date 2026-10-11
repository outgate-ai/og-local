//nolint:gosec // file modes, owners and a subprocess under another uid are what this test exercises
package peer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// packages.list on Android is 0640 system:package_info; a gate outside that group can't read
// it, and every caller admitted by package is then refused. These tests read such a file as a
// uid that isn't its owner or in its group: as root, by re-running the test binary as nobody;
// otherwise, with a file whose owner bits are cleared (the owner is then denied too).

// TestHelperReadPackages runs as the unprivileged reader.
func TestHelperReadPackages(t *testing.T) {
	path := os.Getenv("OGL_PACKAGES_HELPER")
	if path == "" {
		return
	}
	p := &Packages{Path: path}
	fmt.Printf("names=%v err=%v\n", p.Names(10187), p.Check())
	os.Exit(0)
}

// helperBinary copies the test binary where another uid can run it (go test builds into a
// 0700 directory).
func helperBinary(t *testing.T) string {
	t.Helper()
	// t.TempDir's parent is 0700; the helper uid must reach the binary.
	dir, err := os.MkdirTemp("", "ogl-peer-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "peer.test")
	if err := os.WriteFile(path, b, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeList(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ogl-peer-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "packages.list")
	line := "ai.outgate.chat 10187 0 /data/user/0/ai.outgate.chat platform:privapp:targetSdkVersion=35 3003\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPackagesListUnreadableByTheGate(t *testing.T) {
	path := writeList(t)
	if os.Geteuid() == 0 {
		// The device's layout: 0640, owner and group not the reader's.
		if err := os.Chown(path, 0, 1032); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o640); err != nil {
			t.Fatal(err)
		}
		bin := helperBinary(t)
		cmd := exec.Command(bin, "-test.run=^TestHelperReadPackages$")
		cmd.Env = []string{"OGL_PACKAGES_HELPER=" + path}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 7511, Gid: 7511, Groups: []uint32{3003}}}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("helper: %v: %s", err, out)
		}
		if !strings.Contains(string(out), "names=[]") || !strings.Contains(string(out), "permission denied") {
			t.Errorf("unreadable list as uid 7511: %s", out)
		}

		// In the package_info group (the rc's fix) the same file is readable.
		cmd = exec.Command(bin, "-test.run=^TestHelperReadPackages$")
		cmd.Env = []string{"OGL_PACKAGES_HELPER=" + path}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 7511, Gid: 7511, Groups: []uint32{3003, 1032}}}
		out, err = cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("helper: %v: %s", err, out)
		}
		if !strings.Contains(string(out), "names=[ai.outgate.chat]") || !strings.Contains(string(out), "err=<nil>") {
			t.Errorf("readable list in package_info: %s", out)
		}
		return
	}
	if err := os.Chmod(path, 0o040); err != nil {
		t.Fatal(err)
	}
	p := &Packages{Path: path}
	if names := p.Names(10187); names != nil {
		t.Errorf("names from an unreadable list: %v", names)
	}
	if err := p.Check(); err == nil || !os.IsPermission(err) {
		t.Errorf("Check = %v, want permission denied", err)
	}
	if err := os.Chmod(path, 0o440); err != nil {
		t.Fatal(err)
	}
	if names := p.Names(10187); len(names) != 1 || p.Check() != nil {
		t.Errorf("after the fix: %v %v", names, p.Check())
	}
}
