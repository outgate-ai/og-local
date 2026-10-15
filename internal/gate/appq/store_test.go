package appq

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/corelink"
	"github.com/outgate-ai/og-local/internal/gate/route"
	"github.com/outgate-ai/og-local/internal/gate/sealtest"
)

const testToken = "tok_test_synthetic"

func testPackage(app, participant string) []byte {
	return fmt.Appendf(nil, `{"format":"ogpkg/1","app":{"appId":%q,"name":"Travel","endpoints":{"hook":"https://api.example.test/api/v1/hooks/apps/%[1]s","commands":"https://api.example.test/api/v1/hooks/apps/%[1]s/commands"}},"client":{"auth":{"header":"X-Outgate-Hook-Token"},"docs":"%s"},"join":{"participant":%q,"token":%q}}`,
		app, strings.Repeat("d", 4096), participant, testToken)
}

// newStore is a store in a fresh CE dir (<tmp>/ce/appq) with the stand-in keystore.
func newStore(t *testing.T) (*Store, *sealtest.Sealer, string) {
	t.Helper()
	ce := filepath.Join(t.TempDir(), "ce")
	if err := os.Mkdir(ce, 0o700); err != nil {
		t.Fatal(err)
	}
	k := sealtest.New(t)
	return New(filepath.Join(ce, "appq"), k), k, filepath.Join(ce, "appq")
}

func TestSealOpenRoundTrip(t *testing.T) {
	s, k, dir := newStore(t)
	pkg := testPackage("app_1", "dev-phone")
	info, err := s.Add("travel", pkg, Info{AccountID: "acct-1", ThreadID: "thr-1"}, OriginStore)
	if err != nil {
		t.Fatal(err)
	}
	if info.Participant != "dev-phone" || info.AppID != "app_1" || info.AppName != "Travel" || info.ThreadID != "thr-1" ||
		info.AccountID != "acct-1" || info.State != StateActive || info.AddedAt.IsZero() {
		t.Errorf("info = %+v", info)
	}
	// The package is larger than og-gate-link seals: only its own 32-byte key went to the keystore.
	if k.Seals.Load() != 1 {
		t.Errorf("seals = %d", k.Seals.Load())
	}
	for _, ext := range []string{".pkg", ".key", ".meta"} {
		b, err := os.ReadFile(filepath.Join(dir, "travel"+ext))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte(testToken)) || bytes.Contains(b, []byte("hooks/apps")) && ext != ".meta" {
			t.Errorf("%s holds the package in the clear", ext)
		}
		if bytes.Contains(b, []byte(testToken)) {
			t.Errorf("%s holds the token", ext)
		}
		if fi, _ := os.Stat(filepath.Join(dir, "travel"+ext)); fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", ext, fi.Mode().Perm())
		}
	}

	// A fresh store (a gate restart) opens it through the keystore.
	again := New(dir, k)
	got, err := again.Get("travel")
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != testToken || got.Hook != "https://api.example.test/api/v1/hooks/apps/app_1" ||
		got.AuthHeader != "X-Outgate-Hook-Token" || got.Name != "travel" || got.Gen == "" {
		t.Errorf("opened %+v", got)
	}
	list, err := again.List()
	if err != nil || len(list) != 1 || list[0].Name != "travel" || list[0].ThreadID != "thr-1" {
		t.Errorf("list = %+v %v", list, err)
	}
	if _, err := again.Get("other"); !errors.Is(err, ErrNotFound) || !errors.Is(err, route.ErrUnknownRegion) {
		t.Errorf("unknown tenancy: %v", err)
	}
}

func TestWrongAADFails(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	sealed, err := sealPackage(key, []byte(`{"x":1}`), aadPackage("travel"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openPackage(key, sealed, aadPackage("travel")); err != nil {
		t.Fatal(err)
	}
	if _, err := openPackage(key, sealed, aadPackage("other")); !errors.Is(err, ErrUnreadable) {
		t.Errorf("opened under another name's AAD: %v", err)
	}

	// One tenancy's files moved under another name don't open: the key is bound to its name too.
	s, _, dir := newStore(t)
	if _, err := s.Add("travel", testPackage("app_1", "p"), Info{}, OriginStore); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add("other", testPackage("app_2", "p"), Info{}, OriginStore); err != nil {
		t.Fatal(err)
	}
	for _, ext := range []string{".pkg", ".key"} {
		b, _ := os.ReadFile(filepath.Join(dir, "travel"+ext))
		_ = os.WriteFile(filepath.Join(dir, "other"+ext), b, 0o600)
	}
	fresh := New(dir, s.sealer)
	if _, err := fresh.Get("other"); err == nil {
		t.Error("a package opened under another name")
	}
	// The package alone swapped (its key stays): the package's own AAD refuses it.
	b, _ := os.ReadFile(filepath.Join(dir, "travel.pkg"))
	_ = os.WriteFile(filepath.Join(dir, "travel.pkg"), append(b[:len(b)-1], b[len(b)-1]^1), 0o600)
	if _, err := fresh.Get("travel"); !errors.Is(err, ErrUnreadable) {
		t.Errorf("damaged package: %v", err)
	}
	if list, _ := fresh.List(); list[1].Name != "travel" || list[1].State != StateUnreadable {
		t.Errorf("list = %+v", list)
	}
}

func TestNotReady(t *testing.T) {
	pkg := testPackage("app_1", "p")
	// CE storage not unlocked yet: its directory isn't there.
	locked := New(filepath.Join(t.TempDir(), "missing-ce", "appq"), sealtest.New(t))
	if _, err := locked.Add("travel", pkg, Info{}, OriginStore); !errors.Is(err, ErrLocked) {
		t.Errorf("add while locked: %v", err)
	}
	if _, err := locked.Get("travel"); !errors.Is(err, ErrLocked) {
		t.Errorf("get while locked: %v", err)
	}
	if _, err := locked.List(); !errors.Is(err, ErrLocked) {
		t.Errorf("list while locked: %v", err)
	}
	if err := New("", nil).Ready(); !errors.Is(err, ErrLocked) {
		t.Errorf("no dir: %v", err)
	}

	// No og-gate-link: nothing is sealed or opened; the list still works.
	s, k, dir := newStore(t)
	if _, err := s.Add("travel", pkg, Info{}, OriginStore); err != nil {
		t.Fatal(err)
	}
	none := New(dir, nil)
	if err := none.Ready(); !errors.Is(err, ErrLink) {
		t.Errorf("ready without a link: %v", err)
	}
	if _, err := none.Get("travel"); !errors.Is(err, ErrLink) {
		t.Errorf("get without a link: %v", err)
	}
	if _, err := none.Add("other", pkg, Info{}, OriginStore); !errors.Is(err, ErrLink) {
		t.Errorf("add without a link: %v", err)
	}
	if list, err := none.List(); err != nil || len(list) != 1 {
		t.Errorf("list without a link: %v %v", list, err)
	}

	// The helper running but its keystore refusing; a helper that isn't running.
	k.Down.Store(true)
	fresh := New(dir, k)
	if _, err := fresh.Get("travel"); !errors.Is(err, ErrKeystore) {
		t.Errorf("keystore down: %v", err)
	}
	if _, err := fresh.Add("travel", pkg, Info{}, OriginStore); !errors.Is(err, ErrKeystore) {
		t.Errorf("add with the keystore down: %v", err)
	}
	k.Down.Store(false)
	if _, err := fresh.Get("travel"); err != nil {
		t.Errorf("the old tenancy didn't survive a failed replace: %v", err)
	}
	if _, err := New(dir, downLink{}).Get("travel"); !errors.Is(err, ErrLink) {
		t.Errorf("link down: %v", err)
	}
}

type downLink struct{}

func (downLink) Seal(_ context.Context, _, _ []byte) ([]byte, error) {
	return nil, corelink.ErrLinkUnavailable
}

func (downLink) Open(_ context.Context, _, _ []byte) ([]byte, error) {
	return nil, corelink.ErrLinkUnavailable
}

func TestNames(t *testing.T) {
	s, _, _ := newStore(t)
	pkg := testPackage("app_1", "p")
	for _, bad := range []string{"", ".", "..", "a/b", "a b", strings.Repeat("a", 65), "ä"} {
		if _, err := s.Add(bad, pkg, Info{}, OriginStore); !errors.Is(err, ErrBadName) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	for _, good := range []string{"a", "Travel-2.app_x", strings.Repeat("a", 64)} {
		if _, err := s.Add(good, pkg, Info{}, OriginStore); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
	if _, err := s.Add("travel", []byte(`{"app":{}}`), Info{}, OriginStore); !errors.Is(err, route.ErrBadPackage) {
		t.Errorf("bad package: %v", err)
	}
}

func TestRemoveAndRevoke(t *testing.T) {
	s, _, dir := newStore(t)
	if _, err := s.Add("travel", testPackage("app_1", "p"), Info{}, OriginStore); err != nil {
		t.Fatal(err)
	}
	old, err := s.Get("travel")
	if err != nil {
		t.Fatal(err)
	}
	// Re-created (a new mint rotates the token): a refusal of the old token leaves the new one.
	if _, err := s.Add("travel", testPackage("app_1", "p"), Info{}, OriginStore); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Revoke("travel", old.Gen); ok {
		t.Error("revoked the newer tenancy")
	}
	cur, _ := s.Get("travel")
	if i, ok := s.Revoke("travel", cur.Gen); !ok || i.AppID != "app_1" {
		t.Errorf("revoke: %+v %v", i, ok)
	}
	if _, ok := s.Revoke("travel", cur.Gen); ok {
		t.Error("revoked twice")
	}
	if _, err := s.Get("travel"); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoked tenancy still opens: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("files left: %v", entries)
	}

	if _, err := s.Add("travel", testPackage("app_1", "p"), Info{}, OriginStore); err != nil {
		t.Fatal(err)
	}
	if i, err := s.Remove("travel"); err != nil || i.Name != "travel" {
		t.Errorf("remove: %+v %v", i, err)
	}
	if _, err := s.Remove("travel"); !errors.Is(err, ErrNotFound) {
		t.Errorf("remove twice: %v", err)
	}
	// Leftovers of an interrupted add (no .meta) go at the next list.
	_ = os.WriteFile(filepath.Join(dir, "half.pkg"), []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "half.key.tmp"), []byte("x"), 0o600)
	if list, err := s.List(); err != nil || len(list) != 0 {
		t.Errorf("list = %v %v", list, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("leftovers kept: %v", entries)
	}
}

func TestMigrate(t *testing.T) {
	s, k, _ := newStore(t)
	de := t.TempDir()
	_ = os.WriteFile(filepath.Join(de, "travel.ogpkg"), testPackage("app_1", "dev-phone"), 0o600)
	_ = os.WriteFile(filepath.Join(de, "broken.ogpkg"), []byte("{"), 0o600)
	_ = os.WriteFile(filepath.Join(de, "notes.txt"), []byte("kept"), 0o600)

	// Not ready: a usable package stays until it is sealed (what isn't one goes); try again later.
	k.Down.Store(true)
	if m, n, err := s.Migrate(de, true); !errors.Is(err, ErrKeystore) || len(m) != 0 || n != 1 {
		t.Errorf("migrate with the keystore down: %v %d %v", m, n, err)
	}
	if _, err := os.Stat(filepath.Join(de, "travel.ogpkg")); err != nil {
		t.Error("a package was deleted before it was sealed")
	}
	k.Down.Store(false)
	m, n, err := s.Migrate(de, true)
	if err != nil || len(m) != 1 || m[0].Name != "travel" || m[0].Participant != "dev-phone" || n != 1 {
		t.Fatalf("migrate: %+v %d %v", m, n, err)
	}
	if got, err := s.Get("travel"); err != nil || got.Token != testToken {
		t.Errorf("migrated tenancy: %+v %v", got, err)
	}
	for _, f := range []string{"travel.ogpkg", "broken.ogpkg"} {
		if _, err := os.Stat(filepath.Join(de, f)); !os.IsNotExist(err) {
			t.Errorf("%s left in DE storage", f)
		}
	}
	if _, err := os.Stat(filepath.Join(de, "notes.txt")); err != nil {
		t.Error("an unrelated file was deleted")
	}

	// A user build only deletes; an existing sealed tenancy is kept over a DE copy.
	_ = os.WriteFile(filepath.Join(de, "travel.ogpkg"), testPackage("app_9", "x"), 0o600)
	_ = os.WriteFile(filepath.Join(de, "new.ogpkg"), testPackage("app_2", "x"), 0o600)
	if m, n, err := s.Migrate(de, false); err != nil || len(m) != 0 || n != 2 {
		t.Errorf("user build: %+v %d %v", m, n, err)
	}
	if _, err := s.Info("new"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a user build sealed a DE package: %v", err)
	}
	_ = os.WriteFile(filepath.Join(de, "travel.ogpkg"), testPackage("app_9", "x"), 0o600)
	if m, n, err := s.Migrate(de, true); err != nil || len(m) != 0 || n != 1 {
		t.Errorf("existing tenancy: %+v %d %v", m, n, err)
	}
	if i, _ := s.Info("travel"); i.AppID != "app_1" {
		t.Errorf("the sealed tenancy was replaced by a DE copy: %+v", i)
	}
	if m, n, err := s.Migrate(filepath.Join(de, "missing"), true); err != nil || len(m) != 0 || n != 0 {
		t.Errorf("no DE dir: %v %d %v", m, n, err)
	}
}

func TestIdlePackagesLeaveMemory(t *testing.T) {
	s, _, _ := newStore(t)
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	if _, err := s.Add("travel", testPackage("app_1", "p"), Info{}, OriginStore); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.open["travel"]; !ok {
		t.Fatal("not kept after add")
	}
	now = now.Add(11 * time.Minute)
	if _, err := s.List(); err != nil {
		t.Fatal(err)
	}
	_, _ = s.Get("other")
	if _, ok := s.open["travel"]; ok {
		t.Error("an idle package stayed in memory")
	}
	if _, err := s.Get("travel"); err != nil {
		t.Errorf("reopen: %v", err)
	}
}
