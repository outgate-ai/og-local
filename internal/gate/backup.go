package gate

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/ledger"
	"github.com/outgate-ai/og-local/internal/gate/route"
	"github.com/outgate-ai/og-local/internal/gate/wire"
)

// callerBackup is Seedvault (og_backup, og-os M25): requests to the environments' backup buckets only.
const callerBackup = "backup"

// backupHeaders may come from backup callers too: what a SigV4-signed S3 request carries. They
// leave exactly as given; the Host is the URL's, as signed.
var backupHeaders = map[string]bool{
	"X-Amz-Date": true, "X-Amz-Content-Sha256": true, "X-Amz-Security-Token": true, "X-Amz-Tagging": true,
	"X-Amz-Tagging-Directive": true, "X-Amz-Copy-Source": true, "If-None-Match": true, "Range": true,
	"Content-Md5": true, "Content-Type": true,
}

var backupResponseHeaders = []string{
	"Content-Type", "Content-Range", "Etag", "Last-Modified", "Accept-Ranges", "X-Amz-Request-Id", "X-Amz-Id-2",
	"Retry-After", "Date",
}

var errShortBody = errors.New("body_fd ended early")

// backup sends a request to a backup bucket. The caller signed it (SigV4), so it leaves as given:
// the URL's path and query unchanged, its headers as they are, the body exactly body_size bytes
// from body_fd (or body_b64 / body_text) with that Content-Length. Nothing is masked, approved or
// restored: the content is ciphertext. With response_fd a 2xx body goes into that descriptor after
// the response line (the returned stream). The ledger row has the bucket host, never the key.
func (s *Server) backup(ctx context.Context, req *wire.Request, method string, dest *route.Destination,
	row *ledger.Row, fds []int, refuse func(int, string, string) *wire.Response,
) (_ *wire.Response, stream *responseStream) {
	row.PathClass, row.ThreadID = "", ""
	row.Kind = backupKind(method, dest.URL)
	switch {
	case method == http.MethodPatch:
		return refuse(400, "bad_method", method), nil
	case len(req.Query) > 0:
		return refuse(400, "bad_query", "a backup request carries its query in url, as signed"), nil
	case method == http.MethodPost && !dest.URL.Query().Has("delete"):
		return refuse(400, "bad_query", "POST to a backup bucket is DeleteObjects (?delete) only"), nil
	}

	rfd := -1
	if req.ResponseFD != "" {
		i, err := fdIndex(req.ResponseFD, fds)
		switch {
		case err != nil:
			return refuse(400, "bad_request", "response_fd: "+err.Error()), nil
		case req.BodyFD != "" && sameFD(req.BodyFD, i, fds):
			return refuse(400, "bad_request", "body_fd and response_fd must be different descriptors"), nil
		case !streamFD(fds[i]):
			return refuse(400, "bad_request", "response_fd is not open for writing"), nil
		}
		rfd = i
	}

	var rd io.Reader
	var size int64
	switch {
	case req.File != "" || (len(req.Body) > 0 && string(bytes.TrimSpace(req.Body)) != "null"):
		return refuse(400, "bad_body", "a backup body is body_fd, body_b64 or body_text"), nil
	case req.BodyFD != "":
		if req.BodyB64 != "" || req.BodyText != nil {
			return refuse(400, "bad_body", "body_fd and an inline body"), nil
		}
		if req.BodySize == nil || *req.BodySize < 0 {
			return refuse(400, "bad_body", "body_fd needs body_size >= 0"), nil
		}
		size = *req.BodySize
		f, err := fdFile(req.BodyFD, fds, "body")
		if err != nil {
			return refuse(400, "bad_body", "body_fd: "+err.Error()), nil
		}
		defer func() { _ = f.Close() }()
		if st, err := f.Stat(); err == nil && st.Mode().IsRegular() {
			if pos, err := f.Seek(0, io.SeekCurrent); err == nil && st.Size()-pos < size {
				return refuse(400, "bad_body", fmt.Sprintf("body_fd holds %d bytes, body_size is %d", st.Size()-pos, size)), nil
			}
		}
		rd = f
	case req.BodySize != nil:
		return refuse(400, "bad_body", "body_size without body_fd"), nil
	case req.BodyB64 != "":
		b, err := base64.StdEncoding.DecodeString(req.BodyB64)
		if err != nil {
			return refuse(400, "bad_body", "body_b64: "+err.Error()), nil
		}
		rd, size = bytes.NewReader(b), int64(len(b))
	case req.BodyText != nil:
		rd, size = strings.NewReader(*req.BodyText), int64(len(*req.BodyText))
	}
	row.Content = size > 0
	row.BytesOutRaw = size

	idle := s.downloadIdle
	if req.TimeoutMs > 0 {
		idle = max(idle, time.Duration(min(req.TimeoutMs, downloadIdleMax.Milliseconds()))*time.Millisecond)
	}
	ctx, cancel := context.WithCancelCause(ctx)
	timer := time.AfterFunc(idle, func() { cancel(errIdle) })
	defer func() {
		if stream == nil {
			timer.Stop()
			cancel(nil)
		}
	}()

	hreq, err := http.NewRequestWithContext(ctx, method, dest.URL.String(), http.NoBody)
	if err != nil {
		return refuse(400, "bad_url", "url"), nil
	}
	var body *exactReader
	if size > 0 {
		body = &exactReader{r: rd, left: size, progress: func() { timer.Reset(idle) }}
		hreq.Body, hreq.ContentLength = io.NopCloser(body), size
	}
	for k, v := range req.Headers {
		ck := textproto.CanonicalMIMEHeaderKey(k)
		if (requestHeaders[ck] || backupHeaders[ck]) && !strings.ContainsAny(v, "\r\n") {
			hreq.Header.Set(ck, v)
		}
	}
	hreq.Header.Set("Accept-Encoding", "identity")
	if hreq.Header.Get("User-Agent") == "" {
		hreq.Header.Set("User-Agent", "og-gate/"+s.cfg.Version)
	}

	hresp, err := s.client.Do(hreq)
	if body != nil {
		row.BytesOut = body.read
		if body.short {
			if err == nil {
				_ = hresp.Body.Close()
			}
			return refuse(400, "bad_body", fmt.Sprintf("body_fd ended after %d of %d bytes", body.read, size)), nil
		}
	}
	fail := func(err error) *wire.Response {
		status, why := 502, errClass(err)
		switch context.Cause(ctx) {
		case errIdle:
			status, why = 504, "timeout"
		case errCallerGone:
			row.Error, row.Status = "cancelled", 499
			r := wire.Fail(req.ID, 499, "cancelled", "the caller hung up")
			r.Ledger, r.Class, r.Masked.Mask = row.ID, row.Class, row.Mask
			return r
		}
		row.Error, row.Status = why, status
		r := wire.Fail(req.ID, status, "upstream_unreachable", why)
		r.Ledger, r.Class, r.Masked.Mask = row.ID, row.Class, row.Mask
		return r
	}
	if err != nil {
		return fail(err), nil
	}
	row.Status = hresp.StatusCode
	headers := map[string]string{}
	for _, k := range backupResponseHeaders {
		if v := hresp.Header.Get(k); v != "" {
			headers[k] = v
		}
	}
	if hresp.ContentLength >= 0 {
		headers["Content-Length"] = strconv.FormatInt(hresp.ContentLength, 10)
	}
	out := &wire.Response{Status: hresp.StatusCode, Headers: headers, Ledger: row.ID, Class: row.Class}
	out.Masked.Mask = row.Mask
	if rfd >= 0 && hresp.StatusCode/100 == 2 {
		out.Streaming = true
		return out, &responseStream{
			s: s, row: row, fds: fds, fd: rfd, body: hresp.Body, idle: idle, timer: timer, cancel: cancel, ctx: ctx,
		}
	}
	defer func() { _ = hresp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(hresp.Body, maxResponse+1))
	row.BytesIn = int64(len(data))
	if err != nil || len(data) > maxResponse {
		if err == nil {
			err = errors.New("too large")
		}
		r := fail(err)
		row.Error = "response_unreadable"
		return r, nil
	}
	enc := encodeBody(hresp.Header.Get("Content-Type"), data)
	out.Body, out.BodyText, out.BodyB64 = enc.Body, enc.BodyText, enc.BodyB64
	return out, nil
}

// backupKind is a backup row's kind: upload, download, list, delete or head.
func backupKind(method string, u *url.URL) string {
	switch method {
	case http.MethodPut:
		return "upload"
	case http.MethodHead:
		return "head"
	case http.MethodDelete, http.MethodPost:
		return "delete"
	}
	if u.Query().Has("list-type") || u.Path == "" || u.Path == "/" {
		return "list"
	}
	return "download"
}

// exactReader reads exactly left bytes; an early end is errShortBody.
type exactReader struct {
	r        io.Reader
	left     int64
	read     int64
	short    bool
	progress func()
}

func (e *exactReader) Read(p []byte) (int, error) {
	if e.left <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > e.left {
		p = p[:e.left]
	}
	n, err := e.r.Read(p)
	e.left -= int64(n)
	e.read += int64(n)
	if n > 0 {
		e.progress()
	}
	if e.left == 0 {
		return n, io.EOF
	}
	if err != nil {
		e.short = true
		return n, errShortBody
	}
	return n, nil
}

// fdIndex resolves "fd:<n>" to the n-th passed descriptor.
func fdIndex(ref string, fds []int) (int, error) {
	n, ok := strings.CutPrefix(ref, "fd:")
	i, err := strconv.Atoi(n)
	if !ok || err != nil || i < 0 || i >= len(fds) || fds[i] < 0 {
		return 0, errors.New("descriptor missing")
	}
	return i, nil
}

func sameFD(ref string, i int, fds []int) bool {
	j, err := fdIndex(ref, fds)
	return err == nil && j == i
}

// fdFile is a dup of a passed descriptor as an *os.File; the passed one is closed with the request.
func fdFile(ref string, fds []int, name string) (*os.File, error) {
	i, err := fdIndex(ref, fds)
	if err != nil {
		return nil, err
	}
	dup, err := syscall.Dup(fds[i])
	if err != nil {
		return nil, errors.New("descriptor unusable")
	}
	syscall.CloseOnExec(dup)
	return os.NewFile(uintptr(dup), name), nil
}

// responseStream writes a backup response body into the request's response_fd, after the
// response line: the descriptor is closed at the end, then the trailer line follows.
type responseStream struct {
	s      *Server
	row    *ledger.Row
	fds    []int
	fd     int
	body   io.ReadCloser
	idle   time.Duration
	timer  *time.Timer
	cancel context.CancelCauseFunc
	ctx    context.Context
}

// run streams the body when the response line was delivered, records the row and writes the trailer.
func (st *responseStream) run(c *net.UnixConn, id string, delivered bool) {
	start := st.row.Time
	defer func() {
		st.timer.Stop()
		st.cancel(nil)
		_ = st.body.Close()
		st.s.record(st.row, start)
	}()
	fd := st.fds[st.fd]
	st.fds[st.fd] = -1
	f := os.NewFile(uintptr(fd), "response")
	if !delivered {
		_ = f.Close()
		st.row.Error = "response_not_delivered"
		return
	}
	var written int64
	var rerr, werr error
	buf := make([]byte, 256<<10)
	for rerr == nil && werr == nil {
		var n int
		n, rerr = st.body.Read(buf)
		if n > 0 {
			st.timer.Reset(st.idle)
			var w int
			w, werr = f.Write(buf[:n])
			written += int64(w)
		}
	}
	_ = f.Close()
	st.row.BytesIn = written
	t := &wire.Trailer{ID: id, Done: true, BodyWritten: written}
	switch {
	case werr != nil:
		t.Done, t.Error = false, "write_failed"
	case !errors.Is(rerr, io.EOF):
		t.Done, t.Error = false, errClass(rerr)
		switch context.Cause(st.ctx) {
		case errIdle:
			t.Error = "timeout"
		case errCallerGone:
			t.Error = "cancelled"
		}
	}
	st.row.Error = t.Error
	_ = c.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_ = wire.WriteTrailer(c, t)
}
