//go:build linux

package corelink

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A descriptor opened without close-on-exec (as init's sockets are) is marked before the helper starts.
func TestCloseOnExecAll(t *testing.T) {
	p := filepath.Join(t.TempDir(), "inherited")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Open(p, syscall.O_RDONLY, 0) // no O_CLOEXEC
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Close(fd) }()
	leaked := closeOnExecAll()
	found := false
	for _, l := range leaked {
		if strings.HasSuffix(l, "inherited") {
			found = true
		}
	}
	if !found {
		t.Errorf("not reported: %v", leaked)
	}
	flags, _, _ := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
	if flags&syscall.FD_CLOEXEC == 0 {
		t.Error("still inherited by children")
	}
	if again := closeOnExecAll(); len(again) != 0 {
		t.Errorf("second pass found %v", again)
	}
}

// The keystore ops fail with link_unavailable while the helper isn't running; OG Core calls with core_unavailable.
func TestUnavailableErrors(t *testing.T) {
	l := &Link{}
	if _, err := l.Seal(context.Background(), []byte{1}, nil); !errors.Is(err, ErrLinkUnavailable) {
		t.Errorf("seal without the helper: %v", err)
	}
	if _, err := l.Get(context.Background(), "ap_1"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("an OG Core call without the helper: %v", err)
	}
}
