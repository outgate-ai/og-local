package models

import (
	"regexp"
	"testing"
)

func TestLookup(t *testing.T) {
	m, ok := Lookup("openai/privacy-filter")
	if !ok {
		t.Fatal("Lookup(openai/privacy-filter) = false")
	}
	if m.Name != "openai/privacy-filter" {
		t.Errorf("Name = %q", m.Name)
	}
	if _, ok := Lookup("does/not-exist"); ok {
		t.Error("Lookup of unknown model = true")
	}
}

func TestDefaultIsInAll(t *testing.T) {
	def := Default()
	for _, m := range All() {
		if m.Name == def.Name {
			return
		}
	}
	t.Errorf("Default() %q not present in All()", def.Name)
}

func TestAllReturnsCopy(t *testing.T) {
	a := All()
	if len(a) == 0 {
		t.Fatal("All() empty")
	}
	a[0].Name = "mutated"
	if All()[0].Name == "mutated" {
		t.Error("All() exposes the underlying slice; callers can mutate the catalog")
	}
}

func TestCatalogWellFormed(t *testing.T) {
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for _, m := range All() {
		if m.Name == "" || m.Repo == "" || m.Revision == "" {
			t.Errorf("%q: empty Name/Repo/Revision", m.Name)
		}
		if len(m.Files) == 0 {
			t.Errorf("%q: no files", m.Name)
		}
		for _, f := range m.Files {
			if f.Path == "" {
				t.Errorf("%q: file with empty path", m.Name)
			}
			if f.Size < 0 {
				t.Errorf("%q/%s: negative size", m.Name, f.Path)
			}
			if f.SHA256 != "" && !hex64.MatchString(f.SHA256) {
				t.Errorf("%q/%s: SHA256 %q is not 64 lowercase hex", m.Name, f.Path, f.SHA256)
			}
		}
	}
}
