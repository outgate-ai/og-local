package models

import (
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"testing"
)

func TestOSFS(t *testing.T) {
	fsys := OSFS()
	dir := t.TempDir()

	if err := fsys.MkdirAll(filepath.Join(dir, "sub")); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	p := filepath.Join(dir, "sub", "f")
	w, err := fsys.Create(p)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := w.Write([]byte("ab")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	aw, err := fsys.OpenForAppend(p)
	if err != nil {
		t.Fatalf("OpenForAppend: %v", err)
	}
	if _, err := aw.Write([]byte("cd")); err != nil {
		t.Fatalf("append Write: %v", err)
	}
	if err := aw.Close(); err != nil {
		t.Fatalf("append Close: %v", err)
	}

	fi, err := fsys.Stat(p)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Size() != 4 {
		t.Errorf("Size = %d, want 4", fi.Size())
	}

	f, err := fsys.Open(p)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	b, _ := io.ReadAll(f)
	_ = f.Close()
	if string(b) != "abcd" {
		t.Errorf("content = %q, want abcd", b)
	}

	dst := filepath.Join(dir, "sub", "g")
	if err := fsys.Rename(p, dst); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if _, err := fsys.Stat(p); !errors.Is(err, fs.ErrNotExist) {
		t.Error("source present after Rename")
	}

	if err := fsys.Remove(dst); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := fsys.Stat(dst); !errors.Is(err, fs.ErrNotExist) {
		t.Error("file present after Remove")
	}

	if err := fsys.RemoveAll(filepath.Join(dir, "sub")); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if _, err := fsys.Stat(filepath.Join(dir, "sub")); !errors.Is(err, fs.ErrNotExist) {
		t.Error("dir present after RemoveAll")
	}
}
