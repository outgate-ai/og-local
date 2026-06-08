package memfs

import (
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"sync"
	"testing"
)

func readAll(t *testing.T, m *FS, name string) []byte {
	t.Helper()
	f, err := m.Open(name)
	if err != nil {
		t.Fatalf("Open(%s): %v", name, err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("ReadAll(%s): %v", name, err)
	}
	return b
}

func write(t *testing.T, m *FS, name, data string) {
	t.Helper()
	w, err := m.Create(name)
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

func appendTo(t *testing.T, m *FS, name, data string) {
	t.Helper()
	w, err := m.OpenForAppend(name)
	if err != nil {
		t.Fatalf("OpenForAppend(%s): %v", name, err)
	}
	if _, err := w.Write([]byte(data)); err != nil {
		t.Fatalf("Write(%s): %v", name, err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close(%s): %v", name, err)
	}
}

func TestCreateWriteRead(t *testing.T) {
	m := New()
	write(t, m, "a", "hello")
	if got := string(readAll(t, m, "a")); got != "hello" {
		t.Errorf("read = %q, want hello", got)
	}
}

func TestCreateTruncates(t *testing.T) {
	m := New()
	write(t, m, "a", "first")
	write(t, m, "a", "x")
	if got := string(readAll(t, m, "a")); got != "x" {
		t.Errorf("read = %q, want x (Create should truncate)", got)
	}
}

func TestOpenForAppend(t *testing.T) {
	m := New()
	write(t, m, "a", "ab")
	appendTo(t, m, "a", "cd")
	if got := string(readAll(t, m, "a")); got != "abcd" {
		t.Errorf("read = %q, want abcd", got)
	}
}

func TestOpenForAppendMissing(t *testing.T) {
	m := New()
	if _, err := m.OpenForAppend("nope"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("err = %v, want ErrNotExist", err)
	}
}

func TestOpenMissing(t *testing.T) {
	m := New()
	if _, err := m.Open("nope"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("err = %v, want ErrNotExist", err)
	}
}

func TestStat(t *testing.T) {
	m := New()
	write(t, m, "a", "abc")
	fi, err := m.Stat("a")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Size() != 3 || fi.Name() != "a" || fi.IsDir() {
		t.Errorf("Stat = {name:%s size:%d dir:%v}, want {a 3 false}", fi.Name(), fi.Size(), fi.IsDir())
	}
	if _, err := m.Stat("nope"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Stat(nope) err = %v, want ErrNotExist", err)
	}
}

func TestRename(t *testing.T) {
	m := New()
	write(t, m, "old", "v")
	if err := m.Rename("old", "new"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if _, err := m.Open("old"); !errors.Is(err, fs.ErrNotExist) {
		t.Error("old still present after Rename")
	}
	if got := string(readAll(t, m, "new")); got != "v" {
		t.Errorf("new = %q, want v", got)
	}
	if err := m.Rename("missing", "x"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Rename(missing) err = %v, want ErrNotExist", err)
	}
}

func TestRemove(t *testing.T) {
	m := New()
	write(t, m, "a", "")
	if err := m.Remove("a"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := m.Stat("a"); !errors.Is(err, fs.ErrNotExist) {
		t.Error("file present after Remove")
	}
	if err := m.Remove("already-gone"); err != nil {
		t.Errorf("Remove of absent file = %v, want nil", err)
	}
}

func TestRemoveAll(t *testing.T) {
	m := New()
	a := filepath.Join("dir", "a")
	b := filepath.Join("dir", "sub", "b")
	other := filepath.Join("other", "c")
	write(t, m, a, "1")
	write(t, m, b, "2")
	write(t, m, other, "3")
	if err := m.RemoveAll("dir"); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	for _, gone := range []string{a, b} {
		if _, err := m.Stat(gone); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s present after RemoveAll", gone)
		}
	}
	if _, err := m.Stat(other); err != nil {
		t.Error("RemoveAll removed a sibling outside the path")
	}
}

func TestMkdirAll(t *testing.T) {
	if err := New().MkdirAll("any/path"); err != nil {
		t.Errorf("MkdirAll = %v, want nil", err)
	}
}

func TestFileInfoFields(t *testing.T) {
	m := New()
	write(t, m, "a", "abc")
	fi, err := m.Stat("a")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Mode() != 0o644 {
		t.Errorf("Mode = %v, want 0644", fi.Mode())
	}
	if !fi.ModTime().IsZero() {
		t.Errorf("ModTime = %v, want zero", fi.ModTime())
	}
	if fi.Sys() != nil {
		t.Errorf("Sys = %v, want nil", fi.Sys())
	}
}

func TestConcurrent(t *testing.T) {
	m := New()
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := string(rune('a' + i%8))
			w, err := m.Create(name)
			if err != nil {
				return
			}
			_, _ = w.Write([]byte("x"))
			_ = w.Close()
			_, _ = m.Stat(name)
			_ = m.Remove(name)
		}(i)
	}
	wg.Wait()
}
