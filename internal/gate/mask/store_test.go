package mask

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/outgate-ai/og-local/internal/gate"
	"github.com/outgate-ai/og-local/internal/gate/sealtest"
	"github.com/outgate-ai/og-local/internal/pii"
)

func newTestSealer(t *testing.T) *sealtest.Sealer { return sealtest.New(t) }

func sealedStore(t *testing.T, dir string, retention time.Duration, maxItems int) *Store {
	t.Helper()
	s := NewStore(dir, retention, maxItems)
	s.Sealer = newTestSealer(t)
	return s
}

func writeLegacy(t *testing.T, dir string, key []byte, entries ...entry) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, legacyKeyFile), key, 0o600); err != nil {
		t.Fatal(err)
	}
	var b []byte
	for i := range entries {
		j, _ := json.Marshal(&entries[i])
		b = append(append(b, j...), '\n')
	}
	if err := os.WriteFile(filepath.Join(dir, legacyMapFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func exists(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, name))
	return err == nil
}

func TestStoreKeepsNothingPlain(t *testing.T) {
	dir := t.TempDir()
	s := sealedStore(t, dir, 30*24*time.Hour, 100)
	if _, err := s.Assign([]Item{{Name, testName}, {Credential, "synthetic-secret-value"}}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{keysFile, mapFile} {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		for _, plain := range []string{testName, "synthetic-secret-value", hex.EncodeToString(s.key)} {
			if bytes.Contains(b, []byte(plain)) {
				t.Errorf("%s holds a plain value", f)
			}
		}
		if fi, _ := os.Stat(filepath.Join(dir, f)); fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", f, fi.Mode().Perm())
		}
	}
	if exists(dir, legacyKeyFile) || exists(dir, legacyMapFile) {
		t.Error("plain files written")
	}
}

func TestStoreMigratesThePlainMap(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	legacyKey := bytes.Repeat([]byte{7}, 32)
	old := entry{P: mint(legacyKey, Name, testName, HexLen), C: Name, V: testName, F: now.Add(-3 * 24 * time.Hour).Unix(), L: now.Add(-2 * 24 * time.Hour).Unix()}
	cred := entry{P: mint(legacyKey, Credential, "synthetic-secret-value", HexLen), C: Credential, V: "synthetic-secret-value", F: now.Unix(), L: now.Unix()}
	writeLegacy(t, dir, legacyKey, old, cred)
	_ = os.WriteFile(filepath.Join(dir, legacyMapFile+".tmp"), []byte("partial"), 0o600)

	k := newTestSealer(t)
	s := NewStore(dir, 30*24*time.Hour, 100)
	s.Sealer, s.now = k, func() time.Time { return now }
	if err := s.Ready(); err != nil {
		t.Fatal(err)
	}
	for _, e := range []entry{old, cred} {
		if v, c, ok := s.Lookup(e.P); !ok || v != e.V || c != e.C {
			t.Errorf("after migration %s: %q %v %v", e.P, v, c, ok)
		}
	}
	for _, f := range []string{legacyKeyFile, legacyMapFile, legacyMapFile + ".tmp"} {
		if exists(dir, f) {
			t.Errorf("%s left behind", f)
		}
	}
	// The Phase-1 HMAC key is kept: known values keep their placeholder, new ones are minted with it.
	phs, _ := s.Assign([]Item{{Name, testName}, {Email, "someone@example.test"}})
	if phs[0] != old.P || phs[1] != mint(legacyKey, Email, "someone@example.test", HexLen) {
		t.Errorf("placeholders changed: %v", phs)
	}
	s2 := NewStore(dir, 30*24*time.Hour, 100)
	s2.Sealer, s2.now = k, func() time.Time { return now }
	if v, _, ok := s2.Lookup(cred.P); !ok || v != cred.V {
		t.Errorf("after reopen: %q %v", v, ok)
	}
}

func TestStoreMigrationResumes(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	legacyKey := bytes.Repeat([]byte{9}, 32)
	e1 := entry{P: mint(legacyKey, Name, testName, HexLen), C: Name, V: testName, F: now.Unix(), L: now.Unix()}

	// Died after keys.json, with a half-written map.v2.jsonl.tmp: the conversion is redone.
	dir := t.TempDir()
	writeLegacy(t, dir, legacyKey, e1)
	k := newTestSealer(t)
	first := NewStore(dir, 30*24*time.Hour, 100)
	first.Sealer, first.now = k, func() time.Time { return now }
	if err := first.loadKeys(); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, mapFile+".tmp"), []byte("{\"p\":\"torn"), 0o600)
	s := NewStore(dir, 30*24*time.Hour, 100)
	s.Sealer, s.now = k, func() time.Time { return now }
	if v, _, ok := s.Lookup(e1.P); !ok || v != e1.V {
		t.Errorf("resumed migration lost the entry: %q %v", v, ok)
	}
	if exists(dir, legacyMapFile) || exists(dir, legacyKeyFile) {
		t.Error("plain files left behind")
	}

	// Died after map.v2.jsonl, before the plain files went: they're deleted, never read again.
	dir2 := t.TempDir()
	writeLegacy(t, dir2, legacyKey, e1)
	k2 := newTestSealer(t)
	a := NewStore(dir2, 30*24*time.Hour, 100)
	a.Sealer, a.now = k2, func() time.Time { return now }
	if err := a.Ready(); err != nil {
		t.Fatal(err)
	}
	extra := entry{P: mint(bytes.Repeat([]byte{1}, 32), Name, "not-migrated", HexLen), C: Name, V: "not-migrated", F: now.Unix(), L: now.Unix()}
	writeLegacy(t, dir2, legacyKey, e1, extra)
	b := NewStore(dir2, 30*24*time.Hour, 100)
	b.Sealer, b.now = k2, func() time.Time { return now }
	if _, _, ok := b.Lookup(extra.P); ok {
		t.Error("a plain map was read after the sealed one existed")
	}
	if v, _, ok := b.Lookup(e1.P); !ok || v != e1.V {
		t.Errorf("sealed entry: %q %v", v, ok)
	}
	if exists(dir2, legacyMapFile) || exists(dir2, legacyKeyFile) {
		t.Error("plain files left behind")
	}
}

func TestStoreFailsClosedWithoutTheKeystore(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

	// No Sealer: closed, and a Phase-1 plain map stays untouched (never read, never moved).
	dir := t.TempDir()
	legacyKey := bytes.Repeat([]byte{3}, 32)
	writeLegacy(t, dir, legacyKey, entry{P: mint(legacyKey, Name, testName, HexLen), C: Name, V: testName, F: now.Unix(), L: now.Unix()})
	none := NewStore(dir, time.Hour, 10)
	if err := none.Ready(); !errors.Is(err, ErrKeystore) {
		t.Errorf("no sealer: %v", err)
	}
	if _, err := none.Assign([]Item{{Name, testName}}); !errors.Is(err, ErrKeystore) {
		t.Errorf("assign without a sealer: %v", err)
	}
	if !exists(dir, legacyMapFile) || exists(dir, keysFile) || exists(dir, mapFile) {
		t.Error("files changed without a keystore")
	}

	// The keystore goes away: an existing sealed map stays closed and untouched, and opens again later.
	dir2 := t.TempDir()
	k := newTestSealer(t)
	a := NewStore(dir2, 30*24*time.Hour, 100)
	a.Sealer, a.now = k, func() time.Time { return now }
	phs, err := a.Assign([]Item{{Name, testName}})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir2, mapFile))
	keysBefore, _ := os.ReadFile(filepath.Join(dir2, keysFile))
	k.Down.Store(true)
	b := NewStore(dir2, 30*24*time.Hour, 100)
	b.Sealer, b.now = k, func() time.Time { return now.Add(24 * time.Hour) }
	if err := b.Ready(); !errors.Is(err, ErrKeystore) {
		t.Errorf("keystore down: %v", err)
	}
	if _, _, ok := b.Lookup(phs[0]); ok {
		t.Error("restored without the keystore")
	}
	after, _ := os.ReadFile(filepath.Join(dir2, mapFile))
	keysAfter, _ := os.ReadFile(filepath.Join(dir2, keysFile))
	if !bytes.Equal(before, after) || !bytes.Equal(keysBefore, keysAfter) {
		t.Error("map or keys rewritten while the keystore was down")
	}
	k.Down.Store(false)
	if v, _, ok := b.Lookup(phs[0]); !ok || v != testName {
		t.Errorf("after the keystore came back: %q %v", v, ok)
	}

	// The masker refuses provider content while the map is closed (fail closed).
	m, _, _ := newTestMasker(t, map[string]pii.Class{testName: pii.ClassPerson})
	m.Store.Sealer.(*sealtest.Sealer).Down.Store(true)
	in := `{"text":"hello ` + testName + `"}`
	if _, _, err := m.Mask(context.Background(), call(in), []byte(in)); !errors.Is(err, gate.ErrStorageLocked) {
		t.Errorf("mask with the keystore down: %v", err)
	}
}

func TestStoreDayKeysExpire(t *testing.T) {
	dir := t.TempDir()
	k := newTestSealer(t)
	day0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	s := NewStore(dir, 30*24*time.Hour, 100)
	s.Sealer, s.now = k, func() time.Time { return day0 }
	old, err := s.Assign([]Item{{Credential, "synthetic-secret-value"}})
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return day0.Add(10 * 24 * time.Hour) }
	kept, err := s.Assign([]Item{{Name, testName}})
	if err != nil {
		t.Fatal(err)
	}
	later := NewStore(dir, 30*24*time.Hour, 100)
	later.Sealer, later.now = k, func() time.Time { return day0.Add(35 * 24 * time.Hour) }
	if _, _, ok := later.Lookup(old[0]); ok {
		t.Error("expired value still restores")
	}
	if v, _, ok := later.Lookup(kept[0]); !ok || v != testName {
		t.Errorf("kept value: %q %v", v, ok)
	}
	var kf keyFile
	b, _ := os.ReadFile(filepath.Join(dir, keysFile))
	_ = json.Unmarshal(b, &kf)
	d0 := strconv.FormatInt(day0.Unix()/86400, 10)
	d10 := strconv.FormatInt(day0.Add(10*24*time.Hour).Unix()/86400, 10)
	if _, ok := kf.Days[d0]; ok {
		t.Error("the expired day's key is still there")
	}
	if _, ok := kf.Days[d10]; !ok {
		t.Error("the kept value's day key is gone")
	}
}
