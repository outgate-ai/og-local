package models

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"
)

// ErrRuntimeNotFound is returned when the ONNX Runtime shared library is not
// present and no override points at one.
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

// SharedLibName is the ONNX Runtime shared-library filename for the current OS.
func SharedLibName() string { return libName(runtime.GOOS) }

// runtimeDir is where the shared library is cached, namespaced by os/arch.
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
