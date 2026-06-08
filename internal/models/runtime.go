package models

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"
)

var ErrRuntimeNotFound = errors.New("models: onnx runtime shared library not found")

func libName(goos string) string {
	switch goos {
	case "windows":
		return "onnxruntime.dll"
	case "darwin":
		return "libonnxruntime.dylib"
	default:
		return "libonnxruntime.so"
	}
}

func SharedLibName() string { return libName(runtime.GOOS) }

func runtimeDir(root string) string {
	return filepath.Join(root, "runtime", runtime.GOOS+"-"+runtime.GOARCH)
}

// SharedLibPath resolves the ONNX Runtime shared library: OGL_ONNXRUNTIME_LIB
// if set and present, else the cached copy under root. It does not load the
// library; loading is the detector's concern. Returns ErrRuntimeNotFound when
// neither location has it.
func SharedLibPath(fsys FS, root, override string) (string, error) {
	if override != "" {
		if _, err := fsys.Stat(override); err == nil {
			return override, nil
		}
		return "", fmt.Errorf("%w: override %q", ErrRuntimeNotFound, override)
	}
	p := filepath.Join(runtimeDir(root), SharedLibName())
	if _, err := fsys.Stat(p); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", ErrRuntimeNotFound
		}
		return "", err
	}
	return p, nil
}
