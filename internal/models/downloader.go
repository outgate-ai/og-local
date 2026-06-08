package models

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"strconv"
	"sync"
)

var (
	ErrChecksumMismatch = errors.New("models: checksum mismatch")
	ErrBadStatus        = errors.New("models: unexpected upstream status")
)

const hfBaseURL = "https://huggingface.co"

type Downloader struct {
	rt      http.RoundTripper
	fsys    FS
	baseURL string

	mu    sync.Mutex
	locks map[string]*sync.Mutex // serializes concurrent fetches of the same file
}

func NewDownloader(rt http.RoundTripper, fsys FS) *Downloader {
	return NewDownloaderWithBaseURL(rt, fsys, hfBaseURL)
}

// NewDownloaderWithBaseURL is NewDownloader with the upstream base URL
// overridden, for tests that serve fixtures from a local server.
func NewDownloaderWithBaseURL(rt http.RoundTripper, fsys FS, baseURL string) *Downloader {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &Downloader{rt: rt, fsys: fsys, baseURL: baseURL, locks: map[string]*sync.Mutex{}}
}

// fileLock returns the per-path mutex, creating it on first use. Concurrent
// fetches of the same file serialize so the second sees the first's result and
// skips, rather than racing on the same .partial.
func (d *Downloader) fileLock(path string) *sync.Mutex {
	d.mu.Lock()
	defer d.mu.Unlock()
	l, ok := d.locks[path]
	if !ok {
		l = &sync.Mutex{}
		d.locks[path] = l
	}
	return l
}

// ProgressFunc is called as bytes arrive for a file: done is the cumulative
// bytes written, total is the expected size (0 if unknown).
type ProgressFunc func(f File, done, total int64)

// Fetch downloads every file of m into dir, resuming any *.partial from a prior
// run, verifying sha256 when the catalog provides one, and committing each file
// with an atomic rename. Already-complete files are skipped.
func (d *Downloader) Fetch(ctx context.Context, m Model, dir string, onProgress ProgressFunc) error {
	if err := d.fsys.MkdirAll(dir); err != nil {
		return err
	}
	for _, f := range m.Files {
		if err := d.fetchFile(ctx, m, f, dir, onProgress); err != nil {
			return fmt.Errorf("fetch %s: %w", f.Path, err)
		}
	}
	return nil
}

func (d *Downloader) fetchFile(ctx context.Context, m Model, f File, dir string, onProgress ProgressFunc) error {
	final := filepath.Join(dir, f.Path)

	l := d.fileLock(final)
	l.Lock()
	defer l.Unlock()

	if d.isComplete(final, f) {
		return nil
	}
	if err := d.fsys.MkdirAll(filepath.Dir(final)); err != nil {
		return err
	}

	partial := final + ".partial"
	have := d.partialSize(partial)

	url := fmt.Sprintf("%s/%s/resolve/%s/%s", d.baseURL, m.Repo, m.Revision, f.Path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return err
	}
	if have > 0 {
		req.Header.Set("Range", "bytes="+strconv.FormatInt(have, 10)+"-")
	}

	resp, err := d.rt.RoundTrip(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	var w io.WriteCloser
	switch resp.StatusCode {
	case http.StatusOK:
		// Server ignored Range (or none requested): rewrite from scratch.
		have = 0
		w, err = d.fsys.Create(partial)
	case http.StatusPartialContent:
		w, err = d.fsys.OpenForAppend(partial)
	default:
		return fmt.Errorf("%w: %d", ErrBadStatus, resp.StatusCode)
	}
	if err != nil {
		return err
	}

	err = d.stream(w, resp.Body, f, have, onProgress)
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}

	if f.SHA256 != "" {
		ok, verr := d.verify(partial, f.SHA256)
		if verr != nil {
			return verr
		}
		if !ok {
			_ = d.fsys.Remove(partial)
			return ErrChecksumMismatch
		}
	}
	return d.fsys.Rename(partial, final)
}

func (d *Downloader) stream(w io.Writer, body io.Reader, f File, have int64, onProgress ProgressFunc) error {
	buf := make([]byte, 64*1024)
	done := have
	for {
		n, rerr := body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return werr
			}
			done += int64(n)
			if onProgress != nil {
				onProgress(f, done, f.Size)
			}
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

func (d *Downloader) isComplete(final string, f File) bool {
	fi, err := d.fsys.Stat(final)
	if err != nil {
		return false
	}
	if f.Size > 0 && fi.Size() != f.Size {
		return false
	}
	if f.SHA256 == "" {
		return true
	}
	ok, err := d.verify(final, f.SHA256)
	return err == nil && ok
}

func (d *Downloader) partialSize(partial string) int64 {
	fi, err := d.fsys.Stat(partial)
	if err != nil {
		return 0
	}
	return fi.Size()
}

func (d *Downloader) verify(name, want string) (bool, error) {
	f, err := d.fsys.Open(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}
	return hex.EncodeToString(h.Sum(nil)) == want, nil
}
