package gate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/ledger"
	"github.com/outgate-ai/og-local/internal/gate/route"
	"github.com/outgate-ai/og-local/internal/gate/wire"
)

// callerChat is OGChat (og_chat; the dev chat package on debuggable builds).
const callerChat = "chat"

// maxUploadsInline is the largest uploads body that comes back inline (body_b64); a larger one
// needs response_fd.
const maxUploadsInline = 256 << 10

// uploadsHeaders are the caller headers an uploads GET keeps: a range and a revalidation; a PUT
// keeps its Content-Type (part of the signature). The presigned URL is the whole authorization; an
// Authorization header never goes along.
var uploadsHeaders = map[string]bool{"Range": true, "If-None-Match": true}

// maxUploadsPut is the largest file the chat attaches through the gate (global's cap is 25 MiB).
const maxUploadsPut = 100 << 20

// errLongBody: body_fd held more than body_size.
var errLongBody = errors.New("body_fd holds more than body_size")

// presignParams must all be in an uploads URL's query: an S3 SigV4 presigned GET.
var presignParams = []string{
	"X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires", "X-Amz-SignedHeaders", "X-Amz-Signature",
}

// uploads reaches an environment's uploads bucket (og-os M04e) by a presigned URL global handed the
// chat, exactly as signed: a GET of a workspace file (POST /threads/{id}/files/download), or a PUT
// of a file the user attaches (POST /threads/{id}/uploads). Nothing is masked, restored or approved:
// the user's own files. A GET's 2xx body goes into response_fd after the response line (inline only
// up to maxUploadsInline); a PUT's body is body_fd + body_size with that exact
// Content-Length. The ledger row has the bucket host and the bytes, never the key or the signature.
func (s *Server) uploads(ctx context.Context, req *wire.Request, method string, dest *route.Destination,
	row *ledger.Row, fds []int, refuse func(int, string, string) *wire.Response,
) (_ *wire.Response, stream *responseStream) {
	row.PathClass = ""
	row.Kind = "download"
	switch {
	case method != http.MethodGet && method != http.MethodPut:
		return refuse(400, "bad_method", "uploads buckets are GET and PUT only"), nil
	case len(req.Query) > 0:
		return refuse(400, "bad_query", "an uploads request carries its query in url, as signed"), nil
	case !presigned(dest):
		return refuse(400, "bad_url", "not a presigned URL"), nil
	case method == http.MethodPut:
		return s.uploadsPut(ctx, req, dest, row, fds, refuse), nil
	case req.File != "" || req.BodyFD != "" || req.BodySize != nil || req.BodyB64 != "" || req.BodyText != nil ||
		(len(req.Body) > 0 && string(bytes.TrimSpace(req.Body)) != "null"):
		return refuse(400, "bad_body", "an uploads GET has no body"), nil
	}

	rfd := -1
	if req.ResponseFD != "" {
		i, err := fdIndex(req.ResponseFD, fds)
		switch {
		case err != nil:
			return refuse(400, "bad_request", "response_fd: "+err.Error()), nil
		case !streamFD(fds[i]):
			return refuse(400, "bad_request", "response_fd is not open for writing"), nil
		}
		rfd = i
	}

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

	hreq, err := http.NewRequestWithContext(ctx, http.MethodGet, dest.URL.String(), http.NoBody)
	if err != nil {
		return refuse(400, "bad_url", "url"), nil
	}
	for k, v := range req.Headers {
		ck := textproto.CanonicalMIMEHeaderKey(k)
		if uploadsHeaders[ck] && !strings.ContainsAny(v, "\r\n") {
			hreq.Header.Set(ck, v)
		}
	}
	hreq.Header.Set("Accept-Encoding", "identity")
	hreq.Header.Set("User-Agent", "og-gate/"+s.cfg.Version)

	fail := func(status int, why string) *wire.Response {
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
	hresp, err := s.client.Do(hreq)
	if err != nil {
		return fail(502, errClass(err)), nil
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
	ok := hresp.StatusCode/100 == 2
	if rfd >= 0 && ok {
		out.Streaming = true
		return out, &responseStream{
			s: s, row: row, fds: fds, fd: rfd, body: hresp.Body, idle: idle, timer: timer, cancel: cancel, ctx: ctx,
		}
	}
	defer func() { _ = hresp.Body.Close() }()
	if ok && hresp.ContentLength > maxUploadsInline {
		row.Error = "too_large"
		return refuse(413, "too_large", "the file is larger than an inline body; pass response_fd"), nil
	}
	data, err := io.ReadAll(io.LimitReader(hresp.Body, maxUploadsInline+1))
	row.BytesIn = int64(len(data))
	if err == nil && len(data) > maxUploadsInline {
		if ok {
			row.Error = "too_large"
			return refuse(413, "too_large", "the file is larger than an inline body; pass response_fd"), nil
		}
		data, err = data[:maxUploadsInline], nil
	}
	if err != nil {
		if errors.Is(context.Cause(ctx), errIdle) {
			return fail(504, "timeout"), nil
		}
		return fail(502, "response_unreadable"), nil
	}
	enc := encodeBody(hresp.Header.Get("Content-Type"), data)
	out.Body, out.BodyText, out.BodyB64 = enc.Body, enc.BodyText, enc.BodyB64
	return out, nil
}

// uploadsPut sends a file the user attached to its presigned upload URL: exactly body_size bytes
// streamed from body_fd with that Content-Length (more or fewer is size_mismatch, and the upload is
// aborted). Of the caller's headers only Content-Type and those the presign signed (X-Amz-SignedHeaders,
// never host or authorization) go along; the answer (S3 sends none but headers) comes inline.
func (s *Server) uploadsPut(ctx context.Context, req *wire.Request, dest *route.Destination, row *ledger.Row,
	fds []int, refuse func(int, string, string) *wire.Response,
) *wire.Response {
	row.Kind = "upload"
	switch {
	case req.ResponseFD != "":
		return refuse(400, "bad_request", "an uploads PUT has no response_fd")
	case req.File != "" || req.BodyB64 != "" || req.BodyText != nil || (len(req.Body) > 0 && string(bytes.TrimSpace(req.Body)) != "null"):
		return refuse(400, "bad_body", "an uploads body is body_fd only")
	case req.BodyFD == "":
		return refuse(400, "bad_body", "an uploads PUT needs body_fd")
	case req.BodySize == nil || *req.BodySize <= 0:
		return refuse(400, "bad_body", "body_fd needs body_size > 0")
	case *req.BodySize > maxUploadsPut:
		return refuse(413, "too_large", fmt.Sprintf("at most %d bytes", maxUploadsPut))
	}
	size := *req.BodySize
	f, err := fdFile(req.BodyFD, fds, "body")
	if err != nil {
		return refuse(400, "bad_body", "body_fd: "+err.Error())
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err == nil && st.Mode().IsRegular() {
		if pos, err := f.Seek(0, io.SeekCurrent); err == nil && st.Size()-pos != size {
			return refuse(400, "size_mismatch", fmt.Sprintf("body_fd holds %d bytes, body_size is %d", st.Size()-pos, size))
		}
	}
	row.Content = true
	row.BytesOutRaw = size

	idle := s.downloadIdle
	if req.TimeoutMs > 0 {
		idle = max(idle, time.Duration(min(req.TimeoutMs, downloadIdleMax.Milliseconds()))*time.Millisecond)
	}
	ctx, cancel := context.WithCancelCause(ctx)
	timer := time.AfterFunc(idle, func() { cancel(errIdle) })
	defer func() {
		timer.Stop()
		cancel(nil)
	}()
	body := &sizedReader{r: f, left: size, progress: func() { timer.Reset(idle) }}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPut, dest.URL.String(), io.NopCloser(body))
	if err != nil {
		return refuse(400, "bad_url", "url")
	}
	hreq.ContentLength = size
	signed := signedHeaders(dest)
	for k, v := range req.Headers {
		ck := textproto.CanonicalMIMEHeaderKey(k)
		if (ck == "Content-Type" || signed[ck]) && !strings.ContainsAny(v, "\r\n") {
			hreq.Header.Set(ck, v)
		}
	}
	hreq.Header.Set("Accept-Encoding", "identity")
	hreq.Header.Set("User-Agent", "og-gate/"+s.cfg.Version)

	hresp, err := s.client.Do(hreq)
	row.BytesOut = body.read
	if body.short || body.over {
		if err == nil {
			_ = hresp.Body.Close()
		}
		row.Error = "size_mismatch"
		if body.short {
			return refuse(400, "size_mismatch", fmt.Sprintf("body_fd ended after %d of %d bytes", body.read, size))
		}
		return refuse(400, "size_mismatch", fmt.Sprintf("body_fd holds more than %d bytes", size))
	}
	if err != nil {
		status, why := 502, errClass(err)
		switch context.Cause(ctx) {
		case errIdle:
			status, why = 504, "timeout"
		case errCallerGone:
			status, why = 499, "cancelled"
		}
		row.Error, row.Status = why, status
		r := wire.Fail(req.ID, status, "upstream_unreachable", why)
		r.Ledger, r.Class, r.Masked.Mask = row.ID, row.Class, row.Mask
		return r
	}
	defer func() { _ = hresp.Body.Close() }()
	row.Status = hresp.StatusCode
	data, _ := io.ReadAll(io.LimitReader(hresp.Body, maxUploadsInline))
	row.BytesIn = int64(len(data))
	headers := map[string]string{}
	for _, k := range backupResponseHeaders {
		if v := hresp.Header.Get(k); v != "" {
			headers[k] = v
		}
	}
	out := &wire.Response{Status: hresp.StatusCode, Headers: headers, Ledger: row.ID, Class: row.Class}
	out.Masked.Mask = row.Mask
	enc := encodeBody(hresp.Header.Get("Content-Type"), data)
	out.Body, out.BodyText, out.BodyB64 = enc.Body, enc.BodyText, enc.BodyB64
	return out
}

// signedHeaders: the headers a presigned URL signed (X-Amz-SignedHeaders), never host or authorization.
func signedHeaders(dest *route.Destination) map[string]bool {
	out := map[string]bool{}
	for _, h := range strings.Split(dest.URL.Query().Get("X-Amz-SignedHeaders"), ";") {
		h = strings.TrimSpace(strings.ToLower(h))
		if h == "" || h == "host" || h == "authorization" || h == "cookie" {
			continue
		}
		out[textproto.CanonicalMIMEHeaderKey(h)] = true
	}
	return out
}

// sizedReader reads exactly left bytes; ending early is short, holding more is over (both abort).
type sizedReader struct {
	r           io.Reader
	left, read  int64
	short, over bool
	progress    func()
}

func (e *sizedReader) Read(p []byte) (int, error) {
	if e.left <= 0 {
		// One more byte means the descriptor held more than declared.
		var one [1]byte
		if n, _ := e.r.Read(one[:]); n > 0 {
			e.over = true
			return 0, errLongBody
		}
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
	if err != nil && e.left > 0 {
		e.short = true
		return n, errShortBody
	}
	return n, nil
}

// presigned: the URL carries an S3 SigV4 presigned query.
func presigned(dest *route.Destination) bool {
	if dest == nil || dest.URL == nil {
		return false
	}
	q := dest.URL.Query()
	for _, p := range presignParams {
		if q.Get(p) == "" {
			return false
		}
	}
	return q.Get("X-Amz-Algorithm") == "AWS4-HMAC-SHA256"
}
