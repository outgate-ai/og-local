package models

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/outgate-ai/og-local/internal/testutil/memfs"
)

func sha(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// rtFunc adapts a function to http.RoundTripper.
type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func resp(status int, body io.Reader) *http.Response {
	rc, ok := body.(io.ReadCloser)
	if !ok {
		rc = io.NopCloser(body)
	}
	return &http.Response{StatusCode: status, Body: rc, Header: make(http.Header)}
}

// errReader yields the first `good` bytes of data then returns err.
type errReader struct {
	data []byte
	pos  int
	good int
	err  error
}

func (r *errReader) Read(p []byte) (int, error) {
	if r.pos >= r.good {
		return 0, r.err
	}
	n := copy(p, r.data[r.pos:r.good])
	r.pos += n
	return n, nil
}

func (r *errReader) Close() error { return nil }

func readFile(t *testing.T, fsys FS, name string) string {
	t.Helper()
	f, err := fsys.Open(name)
	if err != nil {
		t.Fatalf("Open(%s): %v", name, err)
	}
	defer func() { _ = f.Close() }()
	b, _ := io.ReadAll(f)
	return string(b)
}

func oneFileModel(content string) Model {
	return Model{
		Name: "m", Repo: "org/m", Revision: "rev",
		Files: []File{{Path: "f.bin", Size: int64(len(content)), SHA256: sha(content)}},
	}
}

func TestFetchCleanDownload(t *testing.T) {
	const content = "hello world"
	fsys := memfs.New()
	m := oneFileModel(content)
	d := NewDownloader(rtFunc(func(*http.Request) (*http.Response, error) {
		return resp(http.StatusOK, strings.NewReader(content)), nil
	}), fsys)

	if err := d.Fetch(context.Background(), m, "c", nil); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got := readFile(t, fsys, filepath.Join("c", "f.bin")); got != content {
		t.Errorf("content = %q, want %q", got, content)
	}
	if _, err := fsys.Stat(filepath.Join("c", "f.bin.partial")); err == nil {
		t.Error("partial file left behind")
	}
}

func TestFetchResume(t *testing.T) {
	const content = "abcdefghij"
	fsys := memfs.New()
	m := oneFileModel(content)

	var rangeHeaders []string
	calls := 0
	d := NewDownloader(rtFunc(func(r *http.Request) (*http.Response, error) {
		rangeHeaders = append(rangeHeaders, r.Header.Get("Range"))
		calls++
		if calls == 1 {
			// Serve first 4 bytes then fail mid-stream.
			return resp(http.StatusOK, &errReader{data: []byte(content), good: 4, err: errors.New("boom")}), nil
		}
		// Resume: server returns 206 with the remaining bytes.
		start := len(content) - len(content[4:])
		return resp(http.StatusPartialContent, strings.NewReader(content[start:])), nil
	}), fsys)

	if err := d.Fetch(context.Background(), m, "c", nil); err == nil {
		t.Fatal("first Fetch should have failed mid-stream")
	}
	if err := d.Fetch(context.Background(), m, "c", nil); err != nil {
		t.Fatalf("resume Fetch: %v", err)
	}
	if got := readFile(t, fsys, filepath.Join("c", "f.bin")); got != content {
		t.Errorf("content after resume = %q, want %q", got, content)
	}
	if len(rangeHeaders) != 2 || rangeHeaders[0] != "" || rangeHeaders[1] != "bytes=4-" {
		t.Errorf("range headers = %v, want [\"\", \"bytes=4-\"]", rangeHeaders)
	}
}

func TestFetchServerIgnoresRange(t *testing.T) {
	const content = "abcdefghij"
	fsys := memfs.New()
	m := oneFileModel(content)

	calls := 0
	d := NewDownloader(rtFunc(func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return resp(http.StatusOK, &errReader{data: []byte(content), good: 4, err: errors.New("boom")}), nil
		}
		// Even though we now send Range, server replies 200 with the FULL body.
		return resp(http.StatusOK, strings.NewReader(content)), nil
	}), fsys)

	_ = d.Fetch(context.Background(), m, "c", nil)
	if err := d.Fetch(context.Background(), m, "c", nil); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// Must not have appended onto the 4 leftover bytes: content is exact, not "abcd"+full.
	if got := readFile(t, fsys, filepath.Join("c", "f.bin")); got != content {
		t.Errorf("content = %q, want %q (no append onto stale partial)", got, content)
	}
}

func TestFetchChecksumMismatch(t *testing.T) {
	fsys := memfs.New()
	m := oneFileModel("correct")
	d := NewDownloader(rtFunc(func(*http.Request) (*http.Response, error) {
		return resp(http.StatusOK, strings.NewReader("WRONG!!")), nil
	}), fsys)

	if err := d.Fetch(context.Background(), m, "c", nil); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("Fetch err = %v, want ErrChecksumMismatch", err)
	}
	if _, err := fsys.Stat(filepath.Join("c", "f.bin.partial")); err == nil {
		t.Error("partial not cleaned up after checksum mismatch")
	}
}

func TestFetchBadStatus(t *testing.T) {
	fsys := memfs.New()
	m := oneFileModel("x")
	d := NewDownloader(rtFunc(func(*http.Request) (*http.Response, error) {
		return resp(http.StatusNotFound, strings.NewReader("nope")), nil
	}), fsys)
	if err := d.Fetch(context.Background(), m, "c", nil); !errors.Is(err, ErrBadStatus) {
		t.Fatalf("Fetch err = %v, want ErrBadStatus", err)
	}
}

func TestFetchCancellation(t *testing.T) {
	const content = "abcdefghij"
	fsys := memfs.New()
	m := oneFileModel(content)
	ctx, cancel := context.WithCancel(context.Background())

	d := NewDownloader(rtFunc(func(r *http.Request) (*http.Response, error) {
		cancel()
		return resp(http.StatusOK, &errReader{data: []byte(content), good: 3, err: r.Context().Err()}), nil
	}), fsys)

	if err := d.Fetch(ctx, m, "c", nil); err == nil {
		t.Fatal("Fetch should fail when context is cancelled mid-stream")
	}
	// Partial should remain for a later resume.
	if _, err := fsys.Stat(filepath.Join("c", "f.bin.partial")); err != nil {
		t.Error("partial should be left intact after cancellation")
	}
}

func TestFetchSkipsComplete(t *testing.T) {
	const content = "already here"
	fsys := memfs.New()
	m := oneFileModel(content)
	seedFile(t, fsys, filepath.Join("c", "f.bin"), content)

	calls := 0
	d := NewDownloader(rtFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return resp(http.StatusOK, strings.NewReader(content)), nil
	}), fsys)

	if err := d.Fetch(context.Background(), m, "c", nil); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if calls != 0 {
		t.Errorf("made %d HTTP calls for an already-complete file, want 0", calls)
	}
}

func TestFetchConcurrentSameModel(t *testing.T) {
	const content = "concurrent"
	fsys := memfs.New()
	m := oneFileModel(content)

	var mu sync.Mutex
	calls := 0
	d := NewDownloader(rtFunc(func(*http.Request) (*http.Response, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return resp(http.StatusOK, strings.NewReader(content)), nil
	}), fsys)

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = d.Fetch(context.Background(), m, "c", nil)
		}()
	}
	wg.Wait()

	if got := readFile(t, fsys, filepath.Join("c", "f.bin")); got != content {
		t.Errorf("content = %q, want %q", got, content)
	}
}

func TestFetchProgressCallback(t *testing.T) {
	const content = "0123456789"
	fsys := memfs.New()
	m := oneFileModel(content)
	var lastDone int64
	d := NewDownloader(rtFunc(func(*http.Request) (*http.Response, error) {
		return resp(http.StatusOK, strings.NewReader(content)), nil
	}), fsys)
	err := d.Fetch(context.Background(), m, "c", func(_ File, done, total int64) {
		lastDone = done
		if total != int64(len(content)) {
			t.Errorf("total = %d, want %d", total, len(content))
		}
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if lastDone != int64(len(content)) {
		t.Errorf("final done = %d, want %d", lastDone, len(content))
	}
}

func TestNewDownloaderNilTransport(t *testing.T) {
	d := NewDownloader(nil, memfs.New())
	if d.rt == nil {
		t.Error("nil transport should default to http.DefaultTransport")
	}
}

func TestFetchSkipsCompleteWithChecksum(t *testing.T) {
	const content = "verified content"
	fsys := memfs.New()
	m := oneFileModel(content) // includes the matching sha256
	seedFile(t, fsys, filepath.Join("c", "f.bin"), content)

	calls := 0
	d := NewDownloader(rtFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return resp(http.StatusOK, strings.NewReader(content)), nil
	}), fsys)

	if err := d.Fetch(context.Background(), m, "c", nil); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if calls != 0 {
		t.Errorf("re-downloaded a sha-verified complete file (%d calls)", calls)
	}
}

func TestFetchRedownloadsWhenChecksumStale(t *testing.T) {
	const content = "fresh content"
	fsys := memfs.New()
	m := oneFileModel(content)
	// Pre-seed a file with the right size but wrong bytes (stale/corrupt).
	seedFile(t, fsys, filepath.Join("c", "f.bin"), strings.Repeat("X", len(content)))

	d := NewDownloader(rtFunc(func(*http.Request) (*http.Response, error) {
		return resp(http.StatusOK, strings.NewReader(content)), nil
	}), fsys)

	if err := d.Fetch(context.Background(), m, "c", nil); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got := readFile(t, fsys, filepath.Join("c", "f.bin")); got != content {
		t.Errorf("stale file not replaced: got %q", got)
	}
}

// mkdirFailFS fails MkdirAll, to drive fetchFile's directory-creation error path.
type mkdirFailFS struct{ FS }

func (mkdirFailFS) MkdirAll(string) error { return errors.New("mkdir denied") }

func TestFetchMkdirError(t *testing.T) {
	d := NewDownloader(rtFunc(func(*http.Request) (*http.Response, error) {
		return resp(http.StatusOK, strings.NewReader("x")), nil
	}), mkdirFailFS{memfs.New()})
	if err := d.Fetch(context.Background(), oneFileModel("x"), "c", nil); err == nil {
		t.Error("Fetch with failing MkdirAll = nil, want error")
	}
}

// openFailFS lets Stat report a file exists (so isComplete tries to verify) but
// fails Open, to drive verify's open-error path.
type openFailFS struct{ *memfs.FS }

func (openFailFS) Open(string) (fs.File, error) { return nil, errors.New("open denied") }

func TestFetchVerifyOpenError(t *testing.T) {
	base := memfs.New()
	seedFile(t, base, filepath.Join("c", "f.bin"), "wrong-size-ok")
	m := oneFileModel("wrong-size-ok") // sha won't matter; Open fails first
	d := NewDownloader(rtFunc(func(*http.Request) (*http.Response, error) {
		return resp(http.StatusOK, strings.NewReader("wrong-size-ok")), nil
	}), openFailFS{base})
	if err := d.Fetch(context.Background(), m, "c", nil); err == nil {
		t.Error("Fetch with failing verify Open = nil, want error")
	}
}

// readErrFile is an fs.File whose Read always errors, to drive verify's
// io.Copy error path.
type readErrFile struct{}

func (readErrFile) Stat() (fs.FileInfo, error) { return nil, errors.New("stat denied") }
func (readErrFile) Read([]byte) (int, error)   { return 0, errors.New("read denied") }
func (readErrFile) Close() error               { return nil }

// readErrFS reports a sized file via Stat but returns a failing reader on Open.
type readErrFS struct{ *memfs.FS }

func (r readErrFS) Stat(name string) (fs.FileInfo, error) { return r.FS.Stat(name) }
func (readErrFS) Open(string) (fs.File, error)            { return readErrFile{}, nil }

func TestFetchVerifyReadError(t *testing.T) {
	base := memfs.New()
	seedFile(t, base, filepath.Join("c", "f.bin"), "present")
	m := oneFileModel("present")
	d := NewDownloader(rtFunc(func(*http.Request) (*http.Response, error) {
		return resp(http.StatusOK, strings.NewReader("present")), nil
	}), readErrFS{base})
	if err := d.Fetch(context.Background(), m, "c", nil); err == nil {
		t.Error("Fetch with failing verify Read = nil, want error")
	}
}

func TestFetchNoChecksumUsesSize(t *testing.T) {
	const content = "no-sha here"
	fsys := memfs.New()
	m := Model{Name: "m", Repo: "org/m", Revision: "rev", Files: []File{{Path: "f.bin", Size: int64(len(content))}}}
	d := NewDownloader(rtFunc(func(*http.Request) (*http.Response, error) {
		return resp(http.StatusOK, strings.NewReader(content)), nil
	}), fsys)
	if err := d.Fetch(context.Background(), m, "c", nil); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got := readFile(t, fsys, filepath.Join("c", "f.bin")); got != content {
		t.Errorf("content = %q, want %q", got, content)
	}
}
