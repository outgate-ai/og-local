package gate

import (
	"bytes"
	"context"
	"errors"
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

// uploadsHeaders are the caller headers an uploads GET keeps: a range and a revalidation. The
// presigned URL is the whole authorization; an Authorization header never goes along.
var uploadsHeaders = map[string]bool{"Range": true, "If-None-Match": true}

// presignParams must all be in an uploads URL's query: an S3 SigV4 presigned GET.
var presignParams = []string{
	"X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires", "X-Amz-SignedHeaders", "X-Amz-Signature",
}

// uploads fetches a workspace file from an environment's uploads bucket (og-os M04e): a GET of a
// presigned URL global handed the chat (POST /threads/{id}/files/download), exactly as signed. The
// file is the user's own coming in: nothing is masked, restored or approved. With response_fd a 2xx
// body goes into that descriptor after the response line; inline only up to maxUploadsInline. The
// ledger row has the bucket host and the bytes, never the key or the signature.
func (s *Server) uploads(ctx context.Context, req *wire.Request, method string, dest *route.Destination,
	row *ledger.Row, fds []int, refuse func(int, string, string) *wire.Response,
) (_ *wire.Response, stream *responseStream) {
	row.PathClass = ""
	row.Kind = "download"
	switch {
	case method != http.MethodGet:
		return refuse(400, "bad_method", "uploads buckets are GET only"), nil
	case len(req.Query) > 0:
		return refuse(400, "bad_query", "an uploads request carries its query in url, as signed"), nil
	case !presigned(dest):
		return refuse(400, "bad_url", "not a presigned URL"), nil
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
