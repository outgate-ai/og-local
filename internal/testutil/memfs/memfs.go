// Package memfs is an in-memory filesystem for tests that exercise write,
// append, rename, and remove paths (which testing/fstest.MapFS, being
// read-only, cannot). It is safe for concurrent use.
package memfs

import (
	"bytes"
	"io"
	"io/fs"
	"sync"
	"time"
)

type FS struct {
	mu    sync.Mutex
	files map[string][]byte
}

func New() *FS {
	return &FS{files: map[string][]byte{}}
}

func (m *FS) Open(name string) (fs.File, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.files[name]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return &memFile{name: name, r: bytes.NewReader(append([]byte(nil), data...)), size: int64(len(data))}, nil
}

func (m *FS) Create(name string) (io.WriteCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[name] = []byte{}
	return &memWriter{fs: m, name: name}, nil
}

func (m *FS) OpenForAppend(name string) (io.WriteCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.files[name]; !ok {
		return nil, &fs.PathError{Op: "append", Path: name, Err: fs.ErrNotExist}
	}
	return &memWriter{fs: m, name: name}, nil
}

func (m *FS) Stat(name string) (fs.FileInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.files[name]
	if !ok {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
	}
	return memInfo{name: name, size: int64(len(data))}, nil
}

func (m *FS) Rename(oldpath, newpath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.files[oldpath]
	if !ok {
		return &fs.PathError{Op: "rename", Path: oldpath, Err: fs.ErrNotExist}
	}
	m.files[newpath] = data
	delete(m.files, oldpath)
	return nil
}

func (m *FS) MkdirAll(string) error { return nil }

func (m *FS) Remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.files, name)
	return nil
}

type memWriter struct {
	fs   *FS
	name string
}

func (w *memWriter) Write(p []byte) (int, error) {
	w.fs.mu.Lock()
	defer w.fs.mu.Unlock()
	w.fs.files[w.name] = append(w.fs.files[w.name], p...)
	return len(p), nil
}

func (w *memWriter) Close() error { return nil }

type memFile struct {
	name string
	r    *bytes.Reader
	size int64
}

func (f *memFile) Stat() (fs.FileInfo, error) { return memInfo{name: f.name, size: f.size}, nil }
func (f *memFile) Read(p []byte) (int, error) { return f.r.Read(p) }
func (f *memFile) Close() error               { return nil }

type memInfo struct {
	name string
	size int64
}

func (i memInfo) Name() string       { return i.name }
func (i memInfo) Size() int64        { return i.size }
func (i memInfo) Mode() fs.FileMode  { return 0o644 }
func (i memInfo) ModTime() time.Time { return time.Time{} }
func (i memInfo) IsDir() bool        { return false }
func (i memInfo) Sys() any           { return nil }
