package models

import (
	"errors"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/outgate-ai/og-local/internal/testutil/memfs"
)

func TestLibName(t *testing.T) {
	cases := map[string]string{
		"windows": "onnxruntime.dll",
		"darwin":  "libonnxruntime.dylib",
		"linux":   "libonnxruntime.so",
		"freebsd": "libonnxruntime.so",
	}
	for goos, want := range cases {
		if got := libName(goos); got != want {
			t.Errorf("libName(%q) = %q, want %q", goos, got, want)
		}
	}
}

func TestSharedLibNameMatchesCurrentOS(t *testing.T) {
	if SharedLibName() != libName(runtime.GOOS) {
		t.Errorf("SharedLibName() = %q, want %q", SharedLibName(), libName(runtime.GOOS))
	}
}

func TestSharedLibPathOverride(t *testing.T) {
	fsys := memfs.New()
	seedFile(t, fsys, "/opt/onnx.so", "")
	got, err := SharedLibPath(fsys, "/cache", "/opt/onnx.so")
	if err != nil {
		t.Fatalf("SharedLibPath: %v", err)
	}
	if got != "/opt/onnx.so" {
		t.Errorf("path = %q, want /opt/onnx.so", got)
	}
}

func TestSharedLibPathOverrideMissing(t *testing.T) {
	_, err := SharedLibPath(memfs.New(), "/cache", "/opt/missing.so")
	if !errors.Is(err, ErrRuntimeNotFound) {
		t.Errorf("err = %v, want ErrRuntimeNotFound", err)
	}
}

func TestSharedLibPathFromCache(t *testing.T) {
	fsys := memfs.New()
	root := "/cache"
	p := filepath.Join(runtimeDir(root), SharedLibName())
	seedFile(t, fsys, p, "")
	got, err := SharedLibPath(fsys, root, "")
	if err != nil {
		t.Fatalf("SharedLibPath: %v", err)
	}
	if got != p {
		t.Errorf("path = %q, want %q", got, p)
	}
}

func TestSharedLibPathNotFound(t *testing.T) {
	_, err := SharedLibPath(memfs.New(), "/cache", "")
	if !errors.Is(err, ErrRuntimeNotFound) {
		t.Errorf("err = %v, want ErrRuntimeNotFound", err)
	}
}
