package models

import (
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/outgate-ai/og-local/internal/testutil/memfs"
)

// failCreateFS wraps an FS but fails every Create, to drive WriteManifest's
// error path.
type failCreateFS struct{ FS }

func (failCreateFS) Create(string) (io.WriteCloser, error) { return nil, errors.New("create denied") }

// failWriteFS returns a writer that errors on Write, to drive WriteManifest's
// write-failure path.
type failWriteFS struct{ FS }

func (failWriteFS) Create(string) (io.WriteCloser, error) { return failWriter{}, nil }

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write denied") }
func (failWriter) Close() error              { return nil }

func TestCacheRoot(t *testing.T) {
	t.Run("OGL_CACHE_DIR wins", func(t *testing.T) {
		t.Setenv("OGL_CACHE_DIR", "/custom/cache")
		t.Setenv("XDG_CACHE_HOME", "/xdg")
		if got := CacheRoot(); got != "/custom/cache" {
			t.Errorf("CacheRoot = %q, want /custom/cache", got)
		}
	})
	t.Run("XDG_CACHE_HOME fallback", func(t *testing.T) {
		xdg := t.TempDir()
		t.Setenv("OGL_CACHE_DIR", "")
		t.Setenv("XDG_CACHE_HOME", xdg)
		if got := CacheRoot(); got != filepath.Join(xdg, "og-local") {
			t.Errorf("CacheRoot = %q", got)
		}
	})
	t.Run("home fallback", func(t *testing.T) {
		t.Setenv("OGL_CACHE_DIR", "")
		t.Setenv("XDG_CACHE_HOME", "")
		got := CacheRoot()
		if !strings.HasSuffix(got, filepath.Join(".cache", "og-local")) {
			t.Errorf("CacheRoot = %q, want .../.cache/og-local", got)
		}
	})
}

func TestModelDir(t *testing.T) {
	root := t.TempDir()
	m := Model{Repo: "openai/privacy-filter", Revision: "abc123"}
	want := filepath.Join(root, "models", "models--openai--privacy-filter", "snapshots", "abc123")
	if got := ModelDir(root, m); got != want {
		t.Errorf("ModelDir = %q, want %q", got, want)
	}
}

func seedFile(t *testing.T, fsys FS, name, data string) {
	t.Helper()
	w, err := fsys.Create(name)
	if err != nil {
		t.Fatalf("Create(%s): %v", name, err)
	}
	if _, err := w.Write([]byte(data)); err != nil {
		t.Fatalf("Write(%s): %v", name, err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close(%s): %v", name, err)
	}
}

func TestIsCachedAndWriteManifest(t *testing.T) {
	fsys := memfs.New()
	dir := "/c"
	m := Model{
		Name:     "m",
		Repo:     "org/m",
		Revision: "rev1",
		Files: []File{
			{Path: "a.bin", Size: 3},
			{Path: "b.bin", Size: 0}, // size 0 => size check skipped
		},
	}

	if IsCached(fsys, dir, m) {
		t.Fatal("IsCached on empty cache = true")
	}

	seedFile(t, fsys, filepath.Join(dir, "a.bin"), "abc")
	seedFile(t, fsys, filepath.Join(dir, "b.bin"), "anything")

	// Files present but no manifest yet.
	if IsCached(fsys, dir, m) {
		t.Fatal("IsCached without manifest = true")
	}

	if err := WriteManifest(fsys, dir, m); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	if !IsCached(fsys, dir, m) {
		t.Fatal("IsCached after full download + manifest = false")
	}
}

func TestIsCachedRejectsWrongSize(t *testing.T) {
	fsys := memfs.New()
	dir := "/c"
	m := Model{Name: "m", Repo: "org/m", Revision: "rev1", Files: []File{{Path: "a.bin", Size: 10}}}
	seedFile(t, fsys, filepath.Join(dir, "a.bin"), "short") // 5 bytes, want 10
	if err := WriteManifest(fsys, dir, m); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	if IsCached(fsys, dir, m) {
		t.Error("IsCached with wrong file size = true")
	}
}

func TestIsCachedRejectsRevisionMismatch(t *testing.T) {
	fsys := memfs.New()
	dir := "/c"
	m := Model{Name: "m", Repo: "org/m", Revision: "rev1", Files: []File{{Path: "a.bin", Size: 1}}}
	seedFile(t, fsys, filepath.Join(dir, "a.bin"), "x")
	if err := WriteManifest(fsys, dir, m); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	m.Revision = "rev2"
	if IsCached(fsys, dir, m) {
		t.Error("IsCached after revision change = true")
	}
}

func TestWriteManifestCreateError(t *testing.T) {
	fsys := failCreateFS{memfs.New()}
	m := Model{Name: "m", Repo: "org/m", Revision: "rev1", Files: []File{{Path: "a.bin"}}}
	if err := WriteManifest(fsys, "/c", m); err == nil {
		t.Error("WriteManifest with failing Create = nil, want error")
	}
}

func TestWriteManifestWriteError(t *testing.T) {
	fsys := failWriteFS{memfs.New()}
	m := Model{Name: "m", Repo: "org/m", Revision: "rev1", Files: []File{{Path: "a.bin"}}}
	if err := WriteManifest(fsys, "/c", m); err == nil {
		t.Error("WriteManifest with failing Write = nil, want error")
	}
}

func TestIsCachedCorruptManifest(t *testing.T) {
	fsys := memfs.New()
	dir := "/c"
	m := Model{Name: "m", Repo: "org/m", Revision: "rev1", Files: []File{{Path: "a.bin", Size: 1}}}
	seedFile(t, fsys, filepath.Join(dir, "a.bin"), "x")
	seedFile(t, fsys, filepath.Join(dir, manifestName), "{not valid json")
	if IsCached(fsys, dir, m) {
		t.Error("IsCached with corrupt manifest = true")
	}
}

func TestReadManifestMissing(t *testing.T) {
	if _, err := readManifest(memfs.New(), "/c"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("readManifest of missing = %v, want ErrNotExist", err)
	}
}
