package models

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/outgate-ai/og-local/internal/testutil/memfs"
)

func tgzWith(t *testing.T, entries, symlinks map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range symlinks {
		if err := tw.WriteHeader(&tar.Header{Name: name, Linkname: target, Typeflag: tar.TypeSymlink}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zipWith(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func testRuntimePuller(goos, goarch string, archive []byte) runtimePuller {
	return runtimePuller{
		fsys: memfs.New(),
		root: "cache",
		rt: rtFunc(func(*http.Request) (*http.Response, error) {
			return resp(http.StatusOK, bytes.NewReader(archive)), nil
		}),
		baseURL: "http://fixture",
		goos:    goos,
		goarch:  goarch,
	}
}

func readAll(t *testing.T, fsys FS, name string) string {
	t.Helper()
	f, err := fsys.Open(name)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestPullRuntimeLinuxVersionedSoWithBareSymlink(t *testing.T) {
	archive := tgzWith(t,
		map[string]string{"onnxruntime-linux-x64-" + ortVersion + "/lib/libonnxruntime.so." + ortVersion: "SO-BYTES"},
		map[string]string{"onnxruntime-linux-x64-" + ortVersion + "/lib/libonnxruntime.so": "libonnxruntime.so." + ortVersion},
	)
	p := testRuntimePuller("linux", "amd64", archive)
	var calls int
	var lastTotal int64
	err := p.pull(context.Background(), func(_ File, _, total int64) { calls++; lastTotal = total })
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	got := readAll(t, p.fsys, filepath.Join("cache", "runtime", "linux-amd64", "libonnxruntime.so"))
	if got != "SO-BYTES" {
		t.Errorf("lib content = %q", got)
	}
	if calls == 0 || lastTotal != 8590023 {
		t.Errorf("progress calls=%d total=%d, want >0 calls with the pinned asset size", calls, lastTotal)
	}
}

func TestPullRuntimeDarwinBareDylib(t *testing.T) {
	archive := tgzWith(t,
		map[string]string{"onnxruntime-osx-arm64-" + ortVersion + "/lib/libonnxruntime.dylib": "DYLIB-BYTES"},
		nil,
	)
	p := testRuntimePuller("darwin", "arm64", archive)
	if err := p.pull(context.Background(), nil); err != nil {
		t.Fatalf("pull: %v", err)
	}
	if got := readAll(t, p.fsys, filepath.Join("cache", "runtime", "darwin-arm64", "libonnxruntime.dylib")); got != "DYLIB-BYTES" {
		t.Errorf("lib content = %q", got)
	}
}

func TestPullRuntimeWindowsZip(t *testing.T) {
	archive := zipWith(t, map[string]string{
		"onnxruntime-win-x64-" + ortVersion + "/lib/onnxruntime.dll": "DLL-BYTES",
		"onnxruntime-win-x64-" + ortVersion + "/lib/other.txt":       "x",
	})
	p := testRuntimePuller("windows", "amd64", archive)
	if err := p.pull(context.Background(), nil); err != nil {
		t.Fatalf("pull: %v", err)
	}
	if got := readAll(t, p.fsys, filepath.Join("cache", "runtime", "windows-amd64", "onnxruntime.dll")); got != "DLL-BYTES" {
		t.Errorf("lib content = %q", got)
	}
}

func TestPullRuntimeIdempotent(t *testing.T) {
	p := runtimePuller{
		fsys: memfs.New(),
		root: "cache",
		rt: rtFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("no request expected when the lib is already present")
			return nil, nil
		}),
		baseURL: "http://fixture",
		goos:    "linux",
		goarch:  "amd64",
	}
	if err := p.fsys.MkdirAll(filepath.Join("cache", "runtime", "linux-amd64")); err != nil {
		t.Fatal(err)
	}
	w, err := p.fsys.Create(filepath.Join("cache", "runtime", "linux-amd64", "libonnxruntime.so"))
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	if err := p.pull(context.Background(), nil); err != nil {
		t.Fatalf("pull must be a no-op: %v", err)
	}
}

func TestPullRuntimeUnknownPlatform(t *testing.T) {
	p := testRuntimePuller("plan9", "amd64", nil)
	err := p.pull(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "no onnx runtime prebuilt") {
		t.Errorf("err = %v, want no-prebuilt error", err)
	}
}

func TestPullRuntimeBadStatus(t *testing.T) {
	p := testRuntimePuller("linux", "amd64", nil)
	p.rt = rtFunc(func(*http.Request) (*http.Response, error) {
		return resp(http.StatusNotFound, strings.NewReader("")), nil
	})
	if err := p.pull(context.Background(), nil); !errors.Is(err, ErrBadStatus) {
		t.Errorf("err = %v, want ErrBadStatus", err)
	}
}

func TestPullRuntimeMemberMissing(t *testing.T) {
	archive := tgzWith(t, map[string]string{"onnxruntime-linux-x64-" + ortVersion + "/lib/README": "x"}, nil)
	p := testRuntimePuller("linux", "amd64", archive)
	err := p.pull(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "not found in onnx runtime archive") {
		t.Errorf("err = %v, want member-missing error", err)
	}
}

func TestRuntimeDownloadSize(t *testing.T) {
	// The current platform is one of the supported dev/CI targets, so a pinned
	// size must be reported.
	if RuntimeDownloadSize() <= 0 {
		t.Errorf("RuntimeDownloadSize = %d, want > 0 on a supported platform", RuntimeDownloadSize())
	}
	if got := runtimeDownloadSize("plan9", "amd64"); got != 0 {
		t.Errorf("plan9 size = %d, want 0", got)
	}
}

func TestOrtAssetTable(t *testing.T) {
	cases := []struct {
		goos, goarch, wantName string
		wantSize               int64
	}{
		{"linux", "amd64", "onnxruntime-linux-x64-" + ortVersion + ".tgz", 8590023},
		{"linux", "arm64", "onnxruntime-linux-aarch64-" + ortVersion + ".tgz", 7608947},
		{"darwin", "arm64", "onnxruntime-osx-arm64-" + ortVersion + ".tgz", 31717869},
		{"windows", "amd64", "onnxruntime-win-x64-" + ortVersion + ".zip", 75675381},
	}
	for _, c := range cases {
		a, ok := ortAssetFor(c.goos, c.goarch)
		if !ok || a.Name != c.wantName || a.Size != c.wantSize {
			t.Errorf("ortAssetFor(%s/%s) = %+v ok=%v, want %s %d", c.goos, c.goarch, a, ok, c.wantName, c.wantSize)
		}
	}
	if _, ok := ortAssetFor("darwin", "amd64"); ok {
		t.Error("darwin/amd64 must have no asset")
	}
}

func TestPullRuntimeWrapperIdempotent(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("OGL_CACHE_DIR", cache)
	dir := filepath.Join(cache, "runtime", runtime.GOOS+"-"+runtime.GOARCH)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, SharedLibName()), []byte("lib"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Lib already present, so the wrapper must return without any network use.
	if err := PullRuntime(context.Background(), nil); err != nil {
		t.Fatalf("PullRuntime: %v", err)
	}
}

func TestPullRuntimeTransportError(t *testing.T) {
	p := testRuntimePuller("linux", "amd64", nil)
	p.rt = rtFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial refused")
	})
	if err := p.pull(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "dial refused") {
		t.Errorf("err = %v, want transport error", err)
	}
}

func TestPullRuntimeCorruptArchives(t *testing.T) {
	// Not gzip at all.
	p := testRuntimePuller("linux", "amd64", []byte("junk"))
	if err := p.pull(context.Background(), nil); err == nil {
		t.Error("want gzip error")
	}
	// Valid gzip, garbage tar.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte("definitely not a tar stream"))
	_ = gz.Close()
	p = testRuntimePuller("linux", "amd64", buf.Bytes())
	if err := p.pull(context.Background(), nil); err == nil {
		t.Error("want tar error")
	}
	// Garbage zip.
	p = testRuntimePuller("windows", "amd64", []byte("junk"))
	if err := p.pull(context.Background(), nil); err == nil {
		t.Error("want zip error")
	}
	// Body read error on the zip path.
	p = testRuntimePuller("windows", "amd64", nil)
	p.rt = rtFunc(func(*http.Request) (*http.Response, error) {
		return resp(http.StatusOK, io.MultiReader(strings.NewReader("x"), tornReader{})), nil
	})
	if err := p.pull(context.Background(), nil); err == nil {
		t.Error("want body read error")
	}
}

type tornReader struct{}

func (tornReader) Read([]byte) (int, error) { return 0, errors.New("torn connection") }

type failModelsFS struct {
	FS
	failMkdir  bool
	failCreate bool
	failWrite  bool
}

type errWriter struct{ io.WriteCloser }

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func (f *failModelsFS) MkdirAll(path string) error {
	if f.failMkdir {
		return errors.New("mkdir denied")
	}
	return f.FS.MkdirAll(path)
}

func (f *failModelsFS) Create(name string) (io.WriteCloser, error) {
	if f.failCreate {
		return nil, errors.New("create denied")
	}
	w, err := f.FS.Create(name)
	if err != nil {
		return nil, err
	}
	if f.failWrite {
		return errWriter{w}, nil
	}
	return w, nil
}

func TestPullRuntimeFSFailures(t *testing.T) {
	archive := tgzWith(t,
		map[string]string{"onnxruntime-linux-x64-" + ortVersion + "/lib/libonnxruntime.so." + ortVersion: "SO"},
		nil,
	)
	for name, ffs := range map[string]*failModelsFS{
		"mkdir":  {failMkdir: true},
		"create": {failCreate: true},
		"write":  {failWrite: true},
	} {
		p := testRuntimePuller("linux", "amd64", archive)
		ffs.FS = p.fsys
		p.fsys = ffs
		if err := p.pull(context.Background(), nil); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestVersionedLibName(t *testing.T) {
	cases := map[string]string{
		"libonnxruntime.so":    "libonnxruntime.so." + ortVersion,
		"libonnxruntime.dylib": "libonnxruntime." + ortVersion + ".dylib",
		"onnxruntime.dll":      "onnxruntime.dll",
	}
	for in, want := range cases {
		if got := versionedLibName(in); got != want {
			t.Errorf("versionedLibName(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestModelTotalSize(t *testing.T) {
	m := Model{Files: []File{{Size: 1}, {Size: 2}, {Size: 39}}}
	if got := m.TotalSize(); got != 42 {
		t.Errorf("TotalSize = %d, want 42", got)
	}
	if Default().TotalSize() <= 800_000_000 {
		t.Errorf("default model TotalSize = %d, want > 800MB", Default().TotalSize())
	}
}
