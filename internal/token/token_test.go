package token

import (
	"errors"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/outgate-ai/og-local/internal/testutil/fakeclock"
)

const testPID = 4242

func newTestMinter(t *testing.T, clk Clock, ttl time.Duration) *Minter {
	t.Helper()
	m, err := NewMinter(testPID, clk, ttl)
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	return m
}

func TestMintVerifyRoundTrip(t *testing.T) {
	start := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	clk := fakeclock.New(start)
	m := newTestMinter(t, clk, time.Hour)

	tok := m.Mint()
	if !strings.HasPrefix(tok, prefix) {
		t.Fatalf("token %q missing prefix %q", tok, prefix)
	}

	claims, err := m.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.PID != testPID {
		t.Errorf("PID = %d, want %d", claims.PID, testPID)
	}
	if !claims.MintedAt.Equal(start) {
		t.Errorf("MintedAt = %v, want %v", claims.MintedAt, start)
	}
	if !claims.ExpiresAt.Equal(start.Add(time.Hour)) {
		t.Errorf("ExpiresAt = %v, want %v", claims.ExpiresAt, start.Add(time.Hour))
	}
}

func TestVerifyRejectsTamper(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	m := newTestMinter(t, clk, time.Hour)
	tok := m.Mint()

	// Flip a character partway through the base32 body for several positions.
	for _, pos := range []int{len(prefix) + 1, len(prefix) + 5, len(tok) - 2} {
		b := []byte(tok)
		if b[pos] == 'a' {
			b[pos] = 'b'
		} else {
			b[pos] = 'a'
		}
		if _, err := m.Verify(string(b)); !errors.Is(err, ErrBadSignature) && !errors.Is(err, ErrMalformed) {
			t.Errorf("tampered token at pos %d: err = %v, want ErrBadSignature or ErrMalformed", pos, err)
		}
	}
}

func TestVerifyRejectsWrongProcess(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	m := newTestMinter(t, clk, time.Hour)
	tok := m.Mint()

	// Same secret (defense-in-depth pid check is only reachable within one
	// process), different pid: white-box mutate the Minter's pid before verify.
	m.pid = testPID + 1
	if _, err := m.Verify(tok); !errors.Is(err, ErrWrongProcess) {
		t.Fatalf("Verify with changed pid: err = %v, want ErrWrongProcess", err)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	start := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	clk := fakeclock.New(start)
	m := newTestMinter(t, clk, time.Hour)
	tok := m.Mint()

	clk.Advance(2 * time.Hour)
	if _, err := m.Verify(tok); !errors.Is(err, ErrExpired) {
		t.Fatalf("Verify after expiry: err = %v, want ErrExpired", err)
	}
}

func TestVerifyAtExactExpiryRejects(t *testing.T) {
	start := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	clk := fakeclock.New(start)
	m := newTestMinter(t, clk, time.Hour)
	tok := m.Mint()

	// now == expiresAt must reject (Verify uses strict Before).
	clk.Advance(time.Hour)
	if _, err := m.Verify(tok); !errors.Is(err, ErrExpired) {
		t.Fatalf("Verify at exact expiry: err = %v, want ErrExpired", err)
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	m := newTestMinter(t, clk, time.Hour)

	cases := map[string]string{
		"empty":          "",
		"prefix only":    prefix,
		"no prefix":      "deadbeef",
		"not base32":     prefix + "0189!@#$", // '0','1','8','9' and symbols are outside std base32
		"too short body": prefix + b32.EncodeToString([]byte{1, 2, 3}),
	}
	for name, tok := range cases {
		if _, err := m.Verify(tok); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
}

func TestVerifyRejectsForeignSecret(t *testing.T) {
	clk := fakeclock.New(time.Unix(1_700_000_000, 0))
	a := newTestMinter(t, clk, time.Hour)
	b := newTestMinter(t, clk, time.Hour) // independent random secret

	tok := a.Mint()
	if _, err := b.Verify(tok); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("cross-minter Verify: err = %v, want ErrBadSignature", err)
	}
}

func TestTTLClampedToCeiling(t *testing.T) {
	start := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	clk := fakeclock.New(start)
	m := newTestMinter(t, clk, 60*24*time.Hour) // 60 days requested

	tok := m.Mint()
	claims, err := m.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	want := start.Add(maxTTL)
	if !claims.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want clamped %v", claims.ExpiresAt, want)
	}
}

func TestNewMinterRejectsNonPositiveTTL(t *testing.T) {
	clk := fakeclock.New(time.Unix(0, 0))
	for _, ttl := range []time.Duration{0, -time.Second} {
		if _, err := NewMinter(testPID, clk, ttl); err == nil {
			t.Errorf("NewMinter(ttl=%v): expected error", ttl)
		}
	}
}

// TestNoFilesystemImports asserts the token package imports nothing that can
// touch the filesystem. This is the structural form of the never-touches-disk
// guarantee — stronger than a runtime hook, since it holds for every code path.
func TestNoFilesystemImports(t *testing.T) {
	denied := map[string]bool{
		"os":            true,
		"io/ioutil":     true,
		"path/filepath": true,
		"os/exec":       true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if denied[p] {
				t.Errorf("%s imports forbidden package %q", name, p)
			}
		}
	}
}
