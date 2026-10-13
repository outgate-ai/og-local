package gate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/ledger"
	"github.com/outgate-ai/og-local/internal/gate/peer"
	"github.com/outgate-ai/og-local/internal/gate/route"
	"github.com/outgate-ai/og-local/internal/gate/sysprop"
	"github.com/outgate-ai/og-local/internal/gate/wire"
)

// MirrorProp is the model mirror's base URL, read at each download.
const MirrorProp = "persist.outgate.models.mirror"

// callerModels is the model manager (ai.outgate.models): downloads and health only.
const callerModels = "models"

// callerVoice is conversation mode (ai.outgate.voice): the voice model on the model front only,
// nothing on the request socket.
const callerVoice = "voice"

const (
	// downloadIdleMin is the shortest idle timeout of a download; there is no total timeout.
	downloadIdleMin = 10 * time.Second
	downloadIdleMax = time.Hour
	// maxErrorBody is how much of an upstream error body a download returns.
	maxErrorBody = 1 << 10
	hangupPoll   = 250 * time.Millisecond
)

var (
	errIdle        = errors.New("idle timeout")
	errCallerGone  = errors.New("caller hung up")
	errHubRedirect = errors.New("redirect not allowed")
)

// hubMaxRedirects bounds a Hugging Face download's redirects (resolve, then its file CDN).
const hubMaxRedirects = 5

// download fetches path from the model mirror, or from a Hugging Face repository at a
// pinned commit, into the descriptor passed with the request, from offset on, and
// reports what it wrote. The gate only counts the bytes; the caller verifies them.
func (s *Server) download(ctx context.Context, class string, cred peer.Cred, req *wire.Request, fds []int) *wire.Response {
	began := time.Now()
	row := ledger.Row{
		ID: s.nextID(), Time: began.UTC(), Caller: class, UID: cred.UID, Class: route.ClassMirror,
		Method: http.MethodGet, EgressKind: "model", Kind: "other", Mode: string(s.cfg.Mode), Mask: MaskNotRequired,
	}
	var from, written int64
	wrote := false
	defer func() {
		row.BytesIn = written
		row.DurationMs = time.Since(began).Milliseconds()
		s.ledger.Record(&row)
		s.log.Info("egress", "id", row.ID, "caller", row.Caller, "dest", row.Destination, "class", row.Class,
			"method", row.Method, "path", row.PathClass, "status", row.Status, "start", from, "in", written,
			"blocked", row.Blocked, "reason", row.BlockReason, "err", row.Error, "ms", row.DurationMs)
	}()
	reply := func(r *wire.Response) *wire.Response {
		r.Op, r.Ledger, r.Class, r.Masked.Mask = "download", row.ID, row.Class, row.Mask
		row.Status = r.Status
		if wrote {
			ok := r.Refused == "" && (r.Status == http.StatusOK || r.Status == http.StatusPartialContent)
			start, n, complete := from, written, ok && from+written == req.Size
			r.Start, r.Written, r.Complete = &start, &n, &complete
		}
		return r
	}
	refuse := func(status int, reason, detail string) *wire.Response {
		row.Blocked, row.BlockReason = true, reason
		return reply(wire.Refuse(req.ID, status, reason, detail))
	}

	var dest *route.Destination
	client := s.client
	if req.Repo != "" || req.Revision != "" {
		row.Destination = s.hubBase.Hostname()
		d, err := route.Hub(s.hubBase, req.Repo, req.Revision, req.Path)
		if err != nil {
			row.PathClass = route.PathClass(req.Path)
			return refuse(400, "bad_path", "repo must be owner/name, revision a 40-hex commit and path a relative file path")
		}
		dest, client = d, s.hubClient
	} else {
		base, err := s.router.MirrorBase(sysprop.Get(MirrorProp, ""))
		if err != nil {
			return refuse(503, "mirror_not_configured", err.Error())
		}
		row.Destination = base.Hostname()
		d, err := route.Mirror(base, req.Path)
		if err != nil {
			row.PathClass = route.PathClass(req.Path)
			return refuse(400, "bad_path", "path must be a relative file path under the mirror")
		}
		dest = d
	}
	row.PathClass = route.PathClass(dest.URL.Path)
	if req.Size <= 0 || req.Offset == nil || *req.Offset < 0 || *req.Offset >= req.Size {
		return refuse(400, "bad_request", "need size > 0 and 0 <= offset < size")
	}
	offset := *req.Offset
	if req.File != "fd:0" || len(fds) != 1 {
		return refuse(400, "bad_request", `a download writes into one passed descriptor, file "fd:0"`)
	}
	fd := fds[0]
	if err := downloadTarget(fd, offset); err != nil {
		return refuse(400, "bad_request", err.Error())
	}

	idle := s.downloadIdle
	if req.TimeoutMs > 0 {
		idle = max(idle, time.Duration(min(req.TimeoutMs, downloadIdleMax.Milliseconds()))*time.Millisecond)
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	timer := time.AfterFunc(idle, func() { cancel(errIdle) })
	defer timer.Stop()
	failUpstream := func(err error) *wire.Response {
		status, why := 502, errClass(err)
		switch context.Cause(ctx) {
		case errIdle:
			status, why = 504, "timeout"
		case errCallerGone:
			row.Error = "cancelled"
			return reply(wire.Fail(req.ID, 499, "cancelled", "the caller hung up"))
		}
		row.Error = why
		return reply(wire.Fail(req.ID, status, "upstream_unreachable", why))
	}
	failWrite := func(err error) *wire.Response {
		status := 500
		if errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT) {
			status = 507
		}
		row.Error = "write_failed"
		return reply(wire.Fail(req.ID, status, "write_failed", err.Error()))
	}

	hreq, err := http.NewRequestWithContext(ctx, http.MethodGet, dest.URL.String(), http.NoBody)
	if err != nil {
		return refuse(400, "bad_path", "path must be a relative file path")
	}
	hreq.Header.Set("User-Agent", "og-gate/"+s.cfg.Version)
	hreq.Header.Set("Accept-Encoding", "identity")
	if offset > 0 {
		hreq.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	hresp, err := client.Do(hreq)
	if err != nil {
		if errors.Is(err, errHubRedirect) {
			return refuse(502, "redirect_not_allowed", "Hugging Face redirected outside its own hosts")
		}
		return failUpstream(err)
	}
	defer func() { _ = hresp.Body.Close() }()
	switch hresp.StatusCode {
	case http.StatusPartialContent:
		from = offset
		if want := fmt.Sprintf("bytes %d-%d/%d", offset, req.Size-1, req.Size); hresp.Header.Get("Content-Range") != want {
			return refuse(502, "size_mismatch", "content range is not "+want)
		}
	case http.StatusOK:
		from = 0
	default:
		b, _ := io.ReadAll(io.LimitReader(hresp.Body, maxErrorBody))
		r := &wire.Response{Status: hresp.StatusCode, Headers: pickHeaders(hresp.Header)}
		if len(b) > 0 {
			text := strings.ToValidUTF8(string(b), "")
			r.BodyText = &text
		}
		return reply(r)
	}
	remaining := req.Size - from
	if hresp.ContentLength >= 0 && hresp.ContentLength != remaining {
		return refuse(502, "size_mismatch", fmt.Sprintf("content length %d, expected %d", hresp.ContentLength, remaining))
	}
	if err := syscall.Ftruncate(fd, from); err != nil {
		return failWrite(err)
	}
	wrote = true

	buf := make([]byte, 256<<10)
	over := false
	var rerr, werr error
	for !over && rerr == nil && werr == nil {
		var n int
		n, rerr = hresp.Body.Read(buf)
		if n == 0 {
			continue
		}
		timer.Reset(idle)
		chunk := buf[:n]
		if int64(n) > remaining-written {
			chunk, over = chunk[:remaining-written], true
		}
		var w int64
		w, werr = pwriteAll(fd, chunk, from+written)
		written += w
	}
	timer.Stop()
	if written > 0 {
		if err := syscall.Fsync(fd); err != nil && werr == nil {
			werr = err
		}
	}
	switch {
	case werr != nil:
		return failWrite(werr)
	case over:
		return refuse(502, "size_mismatch", "the body is longer than size")
	case rerr != nil && !errors.Is(rerr, io.EOF):
		return failUpstream(rerr)
	}
	return reply(&wire.Response{Status: hresp.StatusCode})
}

// downloadTarget checks the caller's file: regular, open for writing without
// O_APPEND (pwrite would append), and at least offset bytes long.
func downloadTarget(fd int, offset int64) error {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return errors.New("download descriptor is not a regular file")
	}
	if !writableFD(fd) {
		return errors.New("download descriptor is not open for writing, or is O_APPEND")
	}
	if st.Size < offset {
		return errors.New("offset is past the end of the file")
	}
	return nil
}

func pwriteAll(fd int, p []byte, off int64) (int64, error) {
	var done int64
	for len(p) > 0 {
		n, err := syscall.Pwrite(fd, p, off+done)
		if n > 0 {
			done += int64(n)
			p = p[n:]
		}
		switch {
		case errors.Is(err, syscall.EINTR):
		case err != nil:
			return done, err
		case n == 0:
			return done, io.ErrShortWrite
		}
	}
	return done, nil
}

// untilHangup returns ctx cancelled (cause errCallerGone) once the caller closes its
// connection, and the function that stops watching.
func untilHangup(ctx context.Context, c *net.UnixConn) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(ctx)
	rc, err := c.SyscallConn()
	if err != nil {
		return ctx, func() { cancel(nil) }
	}
	go func() {
		t := time.NewTicker(hangupPoll)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if hungUp(rc) {
					cancel(errCallerGone)
					return
				}
			}
		}
	}()
	return ctx, func() { cancel(nil) }
}

// hubRedirect lets a Hugging Face download follow a few redirects within Hugging Face's
// hosts (route.HubRedirect); the request's Range goes along.
func (s *Server) hubRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > hubMaxRedirects || !route.HubRedirect(s.hubBase, req.URL) {
		return errHubRedirect
	}
	return nil
}

// mirrorHealth says whether a usable model mirror is configured, and its host.
func (s *Server) mirrorHealth() map[string]any {
	u, err := s.router.MirrorBase(sysprop.Get(MirrorProp, ""))
	if err != nil {
		return map[string]any{"configured": false, "host": ""}
	}
	return map[string]any{"configured": true, "host": u.Hostname()}
}
