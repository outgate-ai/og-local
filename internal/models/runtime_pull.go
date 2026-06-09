package models

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

// Pinned ONNX Runtime release. Keep in sync with ORT_VERSION in the CI and
// release workflows and scripts/stage-native.sh.
const ortVersion = "1.26.0"

const ortBaseURL = "https://github.com/microsoft/onnxruntime/releases/download"

type ortAsset struct {
	Name string
	Size int64
}

func ortAssetFor(goos, goarch string) (ortAsset, bool) {
	switch goos + "/" + goarch {
	case "linux/amd64":
		return ortAsset{Name: "onnxruntime-linux-x64-" + ortVersion + ".tgz", Size: 8590023}, true
	case "linux/arm64":
		return ortAsset{Name: "onnxruntime-linux-aarch64-" + ortVersion + ".tgz", Size: 7608947}, true
	case "darwin/arm64":
		return ortAsset{Name: "onnxruntime-osx-arm64-" + ortVersion + ".tgz", Size: 31717869}, true
	case "windows/amd64":
		return ortAsset{Name: "onnxruntime-win-x64-" + ortVersion + ".zip", Size: 75675381}, true
	}
	return ortAsset{}, false
}

// RuntimeDownloadSize reports the expected download size of the ONNX Runtime
// archive for this platform, or 0 when no prebuilt exists.
func RuntimeDownloadSize() int64 { return runtimeDownloadSize(runtime.GOOS, runtime.GOARCH) }

func runtimeDownloadSize(goos, goarch string) int64 {
	a, ok := ortAssetFor(goos, goarch)
	if !ok {
		return 0
	}
	return a.Size
}

// PullRuntime downloads the ONNX Runtime shared library for this platform into
// the cache runtime directory. It is a no-op when the library is already there.
func PullRuntime(ctx context.Context, onProgress ProgressFunc) error {
	p := runtimePuller{
		fsys:    OSFS(),
		root:    CacheRoot(),
		rt:      http.DefaultTransport,
		baseURL: ortBaseURL,
		goos:    runtime.GOOS,
		goarch:  runtime.GOARCH,
	}
	return p.pull(ctx, onProgress)
}

type runtimePuller struct {
	fsys    FS
	root    string
	rt      http.RoundTripper
	baseURL string
	goos    string
	goarch  string
}

func (p *runtimePuller) pull(ctx context.Context, onProgress ProgressFunc) error {
	lib := libName(p.goos)
	dir := filepath.Join(p.root, "runtime", p.goos+"-"+p.goarch)
	final := filepath.Join(dir, lib)
	if _, err := p.fsys.Stat(final); err == nil {
		return nil
	}
	asset, ok := ortAssetFor(p.goos, p.goarch)
	if !ok {
		return fmt.Errorf("models: no onnx runtime prebuilt for %s/%s", p.goos, p.goarch)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+"/v"+ortVersion+"/"+asset.Name, http.NoBody)
	if err != nil {
		//coverage:ignore reason=NewRequestWithContext only errors on an invalid method or URL, neither reachable here.
		return err
	}
	resp, err := (&http.Client{Transport: p.rt}).Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %d", ErrBadStatus, resp.StatusCode)
	}

	body := &countingReader{r: resp.Body, f: File{Path: asset.Name, Size: asset.Size}, onProgress: onProgress}
	var member io.Reader
	if strings.HasSuffix(asset.Name, ".zip") {
		member, err = zipMember(body, lib)
	} else {
		member, err = tarMember(body, lib)
	}
	if err != nil {
		return err
	}

	if err := p.fsys.MkdirAll(dir); err != nil {
		return err
	}
	partial := final + ".partial"
	w, err := p.fsys.Create(partial)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, member)
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = p.fsys.Remove(partial)
		return err
	}
	return p.fsys.Rename(partial, final)
}

// versionedLibName is the versioned file the archive may carry instead of the
// bare name (which is sometimes only a symlink): libonnxruntime.so.<ver> on
// linux, libonnxruntime.<ver>.dylib on darwin.
func versionedLibName(lib string) string {
	if strings.HasSuffix(lib, ".dylib") {
		return strings.TrimSuffix(lib, ".dylib") + "." + ortVersion + ".dylib"
	}
	if strings.HasSuffix(lib, ".so") {
		return lib + "." + ortVersion
	}
	return lib
}

func tarMember(r io.Reader, lib string) (io.Reader, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	want := map[string]bool{lib: true, versionedLibName(lib): true}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag == tar.TypeReg && want[path.Base(hdr.Name)] {
			return tr, nil
		}
	}
	return nil, fmt.Errorf("models: %s not found in onnx runtime archive", lib)
}

func zipMember(r io.Reader, lib string) (io.Reader, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if !f.FileInfo().IsDir() && path.Base(f.Name) == lib {
			return f.Open()
		}
	}
	return nil, fmt.Errorf("models: %s not found in onnx runtime archive", lib)
}

type countingReader struct {
	r          io.Reader
	f          File
	done       int64
	onProgress ProgressFunc
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.done += int64(n)
		if c.onProgress != nil {
			c.onProgress(c.f, c.done, c.f.Size)
		}
	}
	return n, err
}
