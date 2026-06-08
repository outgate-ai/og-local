package models

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/outgate-ai/og-local/internal/testutil/memfs"
)

func TestResolve(t *testing.T) {
	if m, err := resolve(""); err != nil || m.Name != Default().Name {
		t.Errorf("resolve(\"\") = %q, %v; want default", m.Name, err)
	}
	if m, err := resolve("openai/privacy-filter"); err != nil || m.Name != "openai/privacy-filter" {
		t.Errorf("resolve(named) = %q, %v", m.Name, err)
	}
	var ue *UnknownModelError
	if _, err := resolve("nope/missing"); !errors.As(err, &ue) {
		t.Errorf("resolve(unknown) err = %v, want *UnknownModelError", err)
	}
}

func TestUnknownModelError(t *testing.T) {
	e := &UnknownModelError{Name: "x/y"}
	if !strings.Contains(e.Error(), "x/y") {
		t.Errorf("Error() = %q, want it to mention x/y", e.Error())
	}
}

func testPuller(t *testing.T, body string) puller {
	t.Helper()
	return puller{
		fsys: memfs.New(),
		root: "cache",
		rt: rtFunc(func(*http.Request) (*http.Response, error) {
			return resp(http.StatusOK, strings.NewReader(body)), nil
		}),
		baseURL: "http://fixture",
	}
}

func TestPullerPullAndList(t *testing.T) {
	const body = `{"ok":true}`
	sum := sha256.Sum256([]byte(body))
	p := testPuller(t, body)

	// Override the catalog model under test with a single-file fixture.
	m := Model{Name: "openai/privacy-filter", Repo: "openai/privacy-filter", Revision: "rev"}
	m.Files = []File{{Path: "config.json", Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])}}
	withCatalogModel(t, m)

	if err := p.pull(context.Background(), m.Name, nil); err != nil {
		t.Fatalf("pull: %v", err)
	}

	found := false
	for _, c := range p.list() {
		if c.Name == m.Name {
			found = true
			if !c.Present {
				t.Error("pulled model reported not present")
			}
		}
	}
	if !found {
		t.Error("model missing from list")
	}
}

func TestPullerPullUnknown(t *testing.T) {
	p := testPuller(t, "x")
	if err := p.pull(context.Background(), "nope/missing", nil); err == nil {
		t.Error("pull of unknown model = nil, want error")
	}
}

func TestPullerDelete(t *testing.T) {
	const body = `{"ok":true}`
	sum := sha256.Sum256([]byte(body))
	p := testPuller(t, body)
	m := Model{Name: "openai/privacy-filter", Repo: "openai/privacy-filter", Revision: "rev"}
	m.Files = []File{{Path: "config.json", Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])}}
	withCatalogModel(t, m)

	if err := p.pull(context.Background(), m.Name, nil); err != nil {
		t.Fatalf("pull: %v", err)
	}
	present, err := p.delete(m.Name)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !present {
		t.Error("delete reported model was not present, but it was just pulled")
	}
	for _, c := range p.list() {
		if c.Name == m.Name && c.Present {
			t.Error("model still present after delete")
		}
	}
}

func TestPullerDeleteAbsent(t *testing.T) {
	p := testPuller(t, "x")
	present, err := p.delete("openai/privacy-filter")
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if present {
		t.Error("delete of never-cached model reported present")
	}
}

func TestPullerDeleteUnknown(t *testing.T) {
	p := testPuller(t, "x")
	if _, err := p.delete("nope/missing"); err == nil {
		t.Error("delete of unknown model = nil, want error")
	}
}

func TestPublicDelete(t *testing.T) {
	t.Setenv("OGL_CACHE_DIR", t.TempDir())
	if _, err := Delete("openai/privacy-filter"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestPublicPullAndList(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OGL_CACHE_DIR", root)

	// A fixture model with all files already present, so Pull skips the network
	// and List reports it cached. Exercises the public Pull/List + defaultPuller.
	const body = "seeded"
	sum := sha256.Sum256([]byte(body))
	m := Model{Name: "openai/privacy-filter", Repo: "openai/privacy-filter", Revision: "rev"}
	m.Files = []File{{Path: "config.json", Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])}}
	withCatalogModel(t, m)

	dir := ModelDir(root, m)
	fsys := OSFS()
	if err := fsys.MkdirAll(dir); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	seedFile(t, fsys, dir+"/config.json", body)

	if err := Pull(context.Background(), m.Name, nil); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	for _, c := range List() {
		if c.Name == m.Name && !c.Present {
			t.Error("List reports seeded model not present")
		}
	}
}

// withCatalogModel temporarily replaces the matching catalog entry for the test,
// restoring it afterward.
func withCatalogModel(t *testing.T, m Model) {
	t.Helper()
	orig := make([]Model, len(catalog))
	copy(orig, catalog)
	t.Cleanup(func() { catalog = orig })
	for i := range catalog {
		if catalog[i].Name == m.Name {
			catalog[i] = m
			return
		}
	}
	catalog = append(catalog, m)
}
