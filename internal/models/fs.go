package models

import (
	"io"
	"io/fs"
	"os"
)

type FS interface {
	Open(name string) (fs.File, error)
	Create(name string) (io.WriteCloser, error)
	OpenForAppend(name string) (io.WriteCloser, error)
	Stat(name string) (fs.FileInfo, error)
	Rename(oldpath, newpath string) error
	MkdirAll(path string) error
	Remove(name string) error
	RemoveAll(path string) error
}

type osFS struct{}

func OSFS() FS { return osFS{} }

func (osFS) Open(name string) (fs.File, error) { return os.Open(name) }

func (osFS) Create(name string) (io.WriteCloser, error) { return os.Create(name) }

func (osFS) OpenForAppend(name string) (io.WriteCloser, error) {
	return os.OpenFile(name, os.O_WRONLY|os.O_APPEND, 0o600)
}

func (osFS) Stat(name string) (fs.FileInfo, error) { return os.Stat(name) }

func (osFS) Rename(oldpath, newpath string) error { return os.Rename(oldpath, newpath) }

func (osFS) MkdirAll(path string) error { return os.MkdirAll(path, 0o750) }

func (osFS) Remove(name string) error { return os.Remove(name) }

func (osFS) RemoveAll(path string) error { return os.RemoveAll(path) }
