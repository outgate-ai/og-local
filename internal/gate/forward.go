package gate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/outgate-ai/og-local/internal/gate/ledger"
	"github.com/outgate-ai/og-local/internal/gate/peer"
	"github.com/outgate-ai/og-local/internal/gate/route"
	"github.com/outgate-ai/og-local/internal/gate/wire"
)

const maxResponse = 32 << 20

var methods = map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true}

// requestHeaders may come from callers; everything else is dropped. Host,
// cookies, proxies and hop-by-hop headers are the gate's.
var requestHeaders = map[string]bool{
	"Authorization": true, "Accept": true, "Accept-Language": true, "If-None-Match": true,
	"If-Match": true, "Idempotency-Key": true, "User-Agent": true, "X-Region-Id": true,
	"X-Account-Id": true, "X-Client-Id": true, "X-Correlation-Id": true, "X-Outgate-Hook-Token": true,
}

var responseHeaders = []string{"Content-Type", "Retry-After", "Etag", "Location", "Www-Authenticate", "X-Request-Id", "Date"}

func (s *Server) forward(ctx context.Context, class string, cred peer.Cred, req *wire.Request, fds []int) *wire.Response {
	start := time.Now()
	method := strings.ToUpper(req.Method)
	if method == "" {
		method = "GET"
	}
	row := ledger.Row{
		ID: s.nextID(), Time: start.UTC(), Caller: class, UID: cred.UID,
		AccountID: req.Source.AccountID, RegionID: req.Source.RegionID, Adapter: req.Source.Adapter,
		Method: method, EgressKind: req.Egress.Kind, LaneID: req.Egress.LaneID,
		StepIndex: req.Egress.StepIndex, ApprovalID: req.Egress.ApprovalID, Mode: string(s.cfg.Mode),
		Mask: MaskNotRequired,
	}
	defer func() {
		row.DurationMs = time.Since(start).Milliseconds()
		s.ledger.Record(&row)
		s.log.Info("egress", "id", row.ID, "caller", row.Caller, "dest", row.Destination, "class", row.Class,
			"method", row.Method, "path", row.PathClass, "status", row.Status, "out", row.BytesOut, "in", row.BytesIn,
			"mask", row.Mask, "masked", row.MaskedCount, "blocked", row.Blocked, "reason", row.BlockReason, "ms", row.DurationMs)
	}()
	refuse := func(status int, reason, detail string) *wire.Response {
		row.Blocked, row.BlockReason, row.Status = true, reason, status
		r := wire.Refuse(req.ID, status, reason, detail)
		r.Ledger, r.Class, r.Masked.Mask = row.ID, row.Class, row.Mask
		return r
	}
	refuseAsk := func(aerr error, approvalID, detail string) *wire.Response {
		status, reason := 403, ErrNeedsApproval.Error()
		switch {
		case errors.Is(aerr, ErrApprovalDenied):
			reason = ErrApprovalDenied.Error()
		case errors.Is(aerr, ErrApprovalCancelled):
			reason = ErrApprovalCancelled.Error()
		case errors.Is(aerr, ErrCoreUnavailable):
			status, reason = 503, ErrCoreUnavailable.Error()
		}
		r := refuse(status, reason, detail)
		r.ApprovalID = approvalID
		return r
	}
	holdBudget := holdDefault
	if req.TimeoutMs > 0 {
		holdBudget = min(time.Duration(req.TimeoutMs)*time.Millisecond, holdMax)
	}
	if !methods[method] {
		return refuse(400, "bad_method", method)
	}

	// App tenancies carry a join token only the gate holds: og-agentd's transport (and debug tools
	// on debuggable builds) only.
	if strings.HasPrefix(req.Source.RegionID, "appq:") && class != "agent" && (class != "debug" || !s.cfg.Debuggable) {
		return refuse(403, "destination_not_allowed", "app tenancies are for the agent runtime")
	}
	query, err := queryValues(req.Query)
	if err != nil {
		return refuse(400, "bad_query", err.Error())
	}
	dest, err := s.router.Resolve(req.Source.RegionID, req.URL, req.Path, query)
	if err != nil {
		if u, perr := url.Parse(req.URL); perr == nil {
			row.Destination, row.PathClass = u.Hostname(), route.PathClass(u.Path)
		} else {
			row.PathClass = route.PathClass(req.Path)
		}
		reason := "destination_not_allowed"
		status := 403
		if errors.Is(err, route.ErrUnknownRegion) {
			reason, status = "unknown_region", 404
		} else if errors.Is(err, route.ErrBadURL) {
			reason, status = "bad_url", 400
		} else if st, code, ok := appqRefusal(err); ok {
			reason, status = code, st
		}
		return refuse(status, reason, err.Error())
	}
	if status, code, detail, refused := s.storeNotReady(method, dest); refused {
		return refuse(status, code, detail)
	}
	path := req.Path
	if dest.URL != nil {
		path = dest.URL.Path
	}
	row.Destination, row.Class = dest.Display, dest.Class
	row.PathClass = route.PathClass(path)
	row.OnDevice = dest.Kind == route.OnDevice
	row.ThreadID = req.Egress.ThreadID
	if row.ThreadID == "" {
		row.ThreadID = route.ThreadID(path)
	}
	row.Kind = coreKind(req.Egress.Kind, method, row.PathClass, row.OnDevice)

	body, ctype, err := s.requestBody(req, fds)
	if err != nil {
		return refuse(400, "bad_body", err.Error())
	}
	call := &Call{
		Caller: class, Req: req, Path: row.PathClass, Kind: row.Kind, ContentType: ctype,
		Binary: req.File != "" || req.BodyB64 != "", Raw: body,
	}
	call.Content = len(body) > 0 && !contentFree[req.Egress.Kind] && !s.isOIDC(dest) && !isEmptyJSON(body)
	row.Content = call.Content
	row.BytesOutRaw = int64(len(body))

	// On-device requests go to the model instance they name; GET /v1/models lists them all.
	var model *modelInstance
	if row.OnDevice {
		p, rawQuery, _ := strings.Cut(dest.Path, "?")
		if !s.aggregatesModels(method, p) {
			q, _ := url.ParseQuery(rawQuery)
			if model, err = s.modelFor(method, q, body); err != nil {
				return refuse(404, "unknown_model", err.Error())
			}
			row.Destination, dest.Socket = model.display, model.socket
		}
	}

	// Images and screenshots an agent sends leave only with the user's approval
	// (decision #18), whatever the destination's masking: this is consent, not
	// anonymization. What the user attaches in Chat passes: they chose to send it.
	if call.Binary && len(body) > 0 && dest.Kind == route.Cloud && imageNeedsConsent(class) {
		na := &NeedsApproval{Images: true}
		d, approvalID, aerr := s.asks.hold(ctx, call, dest.Display, na, holdBudget)
		if approvalID != "" {
			row.ApprovalID = approvalID
		}
		if aerr != nil {
			return refuseAsk(aerr, approvalID, na.Error())
		}
		if !d.images {
			r := refuse(403, "blocked_by_policy", "the image was not chosen to leave")
			r.ApprovalID = approvalID
			return r
		}
		call.Approved = true
	}

	// Content is masked only for a class gate.conf marks mask: the phone region's
	// external providers. Outgate's regions mask with their own guardrail.
	sent := body
	if call.Content && s.cfg.Masks(dest.Class) {
		row.Mask = MaskOn
		if s.cfg.Mode == Passthrough {
			row.Mask = MaskOff
		}
		var m wire.Masked
		sent, m, err = s.masker.Mask(ctx, call, body)
		var na *NeedsApproval
		if errors.As(err, &na) {
			d, approvalID, aerr := s.asks.hold(ctx, call, dest.Display, na, holdBudget)
			row.ApprovalID = approvalID
			if aerr != nil {
				return refuseAsk(aerr, approvalID, na.Error())
			}
			call.Decisions, call.Approved = d.values, call.Approved || d.images
			sent, m, err = s.masker.Mask(ctx, call, body)
		}
		if err != nil {
			status, reason := 503, "mask_failed"
			switch {
			case errors.Is(err, ErrDetectorUnavailable):
				reason = ErrDetectorUnavailable.Error()
			case errors.Is(err, ErrStorageLocked):
				reason = ErrStorageLocked.Error()
			case errors.Is(err, ErrNeedsApproval):
				status, reason = 403, ErrNeedsApproval.Error()
			}
			s.log.Info("content refused", "reason", reason, "err", err)
			return refuse(status, reason, err.Error())
		}
		row.MaskedCount, row.MaskedCategories = m.Count, m.Categories
		if m.Blocked > 0 && len(sent) == 0 {
			return refuse(403, "blocked_by_policy", "")
		}
	}
	row.BytesOut = int64(len(sent))

	timeout := time.Duration(max(req.TimeoutMs, 10_000)+2_000) * time.Millisecond
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	hreq, err := s.upstreamRequest(cctx, dest, req, method, sent, ctype)
	if err != nil {
		return refuse(400, "bad_request", err.Error())
	}
	var hresp *http.Response
	switch {
	case row.OnDevice && model == nil:
		var list []byte
		if list, err = s.modelList(cctx); err == nil {
			hresp = &http.Response{
				StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
				Body: io.NopCloser(bytes.NewReader(list)),
			}
		}
	case row.OnDevice:
		hresp, err = model.client.Do(hreq)
	default:
		hresp, err = s.client.Do(hreq)
	}
	if err != nil {
		row.Error = errClass(err)
		row.Status = 502
		if cctx.Err() != nil {
			row.Status = 504
		}
		r := wire.Fail(req.ID, row.Status, "upstream_unreachable", row.Error)
		r.Ledger, r.Class, r.Masked.Mask = row.ID, row.Class, row.Mask
		return r
	}
	defer func() { _ = hresp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(hresp.Body, maxResponse+1))
	row.Status = hresp.StatusCode
	row.BytesIn = int64(len(data))
	if err != nil || len(data) > maxResponse {
		row.Error = "response_unreadable"
		r := wire.Fail(req.ID, 502, "upstream_unreachable", "response unreadable or too large")
		r.Ledger, r.Class, r.Masked.Mask = row.ID, row.Class, row.Mask
		return r
	}
	if dest.Env != "" && hresp.StatusCode/100 == 2 && s.isGlobal(dest) {
		if n := s.router.Regions.LearnFrom(s.cfg.Learn, row.PathClass, data, dest.Env); n > 0 {
			s.log.Info("region hosts learned", "count", n, "env", dest.Env)
		}
	}
	data, refusal := s.appqResponse(ctx, class, cred.UID, req, method, dest, &row, hresp.StatusCode, data)
	if refusal != nil {
		return refusal
	}
	call.RespContentType = hresp.Header.Get("Content-Type")
	// Placeholders this gate minted come back filled in, whatever the class: those of
	// the provider path, and those still in threads from before Outgate traffic went
	// unmasked (the map keeps them 30 days). Nothing else in a response is touched.
	restored, fields := s.masker.Restore(ctx, call, data)
	row.RestoredCount = len(fields)
	out := encodeBody(hresp.Header.Get("Content-Type"), restored)
	out.Status = hresp.StatusCode
	out.Headers = pickHeaders(hresp.Header)
	out.Masked = wire.Masked{Count: row.MaskedCount, Categories: row.MaskedCategories, Mask: row.Mask}
	out.Restored = fields
	out.Ledger, out.Class = row.ID, row.Class
	return out
}

// imageNeedsConsent: images from every caller but Chat (the agent, debug tools)
// need an 08 approval before they leave.
func imageNeedsConsent(class string) bool { return class != "chat" }

func (s *Server) isGlobal(d *route.Destination) bool {
	if d.URL == nil {
		return false
	}
	_, ok := s.router.EnvForGlobal(d.URL.Hostname())
	return ok
}

// isOIDC is true for the identity provider: token exchanges carry no user content.
func (s *Server) isOIDC(d *route.Destination) bool {
	if d.URL == nil {
		return false
	}
	for _, e := range s.cfg.Environments {
		if u, err := url.Parse(e.OIDC); err == nil && strings.EqualFold(u.Hostname(), d.URL.Hostname()) {
			return true
		}
	}
	return false
}

func isEmptyJSON(b []byte) bool {
	t := bytes.TrimSpace(b)
	return len(t) == 0 || string(t) == "null" || string(t) == "{}" || string(t) == "[]"
}

// requestBody builds the bytes to send and their content type.
func (s *Server) requestBody(req *wire.Request, fds []int) (body []byte, contentType string, err error) {
	if req.File != "" {
		return s.multipartBody(req, fds)
	}
	switch {
	case req.BodyText != nil:
		return []byte(*req.BodyText), orDefault(req.ContentType, "text/plain; charset=utf-8"), nil
	case req.BodyB64 != "":
		b, err := base64.StdEncoding.DecodeString(req.BodyB64)
		if err != nil {
			return nil, "", fmt.Errorf("body_b64: %w", err)
		}
		return b, orDefault(req.ContentType, "application/octet-stream"), nil
	case len(req.Body) > 0 && string(bytes.TrimSpace(req.Body)) != "null":
		if !json.Valid(req.Body) {
			return nil, "", errors.New("body is not JSON")
		}
		return req.Body, orDefault(req.ContentType, "application/json"), nil
	}
	return nil, "", nil
}

func (s *Server) multipartBody(req *wire.Request, fds []int) (body []byte, contentType string, err error) {
	path, data, err := s.uploadFile(req.File, fds)
	if err != nil {
		return nil, "", err
	}
	var fields map[string]any
	if len(req.Body) > 0 && string(req.Body) != "null" {
		if err := json.Unmarshal(req.Body, &fields); err != nil {
			return nil, "", fmt.Errorf("upload fields: %w", err)
		}
	}
	// The same upload is encoded to the same bytes (fields in order, a boundary derived from the
	// content), so a retry after an 08 approval is recognised as the request that was held.
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	vals := make([]string, len(keys))
	sum := sha256.New()
	for i, k := range keys {
		switch x := fields[k].(type) {
		case string:
			vals[i] = x
		default:
			b, _ := json.Marshal(x)
			vals[i] = string(b)
		}
		_, _ = fmt.Fprintf(sum, "%s\x00%s\x00", k, vals[i])
	}
	_, _ = sum.Write(data)
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.SetBoundary("og-gate-" + hex.EncodeToString(sum.Sum(nil))[:40]); err != nil {
		return nil, "", err
	}
	for i, k := range keys {
		if err := w.WriteField(k, vals[i]); err != nil {
			return nil, "", err
		}
	}
	field := orDefault(req.FileField, "file")
	ct := mime.TypeByExtension(filepath.Ext(path))
	if ct == "" {
		ct = "application/octet-stream"
	}
	h := textproto.MIMEHeader{}
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name=%q; filename=%q`, field, filepath.Base(path)))
	h.Set("Content-Type", ct)
	part, err := w.CreatePart(h)
	if err != nil {
		return nil, "", err
	}
	if _, err := part.Write(data); err != nil {
		return nil, "", err
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), w.FormDataContentType(), nil
}

// maxUpload bounds one uploaded file (screenshots are a few MB).
const maxUpload = 32 << 20

// uploadFile reads the file a request uploads: "fd:<n>" is the n-th descriptor
// passed with the request (SCM_RIGHTS); a path must name a regular file directly
// under an upload dir. The name is what the upstream sees as the filename.
func (s *Server) uploadFile(ref string, fds []int) (name string, data []byte, err error) {
	if n, ok := strings.CutPrefix(ref, "fd:"); ok {
		i, err := strconv.Atoi(n)
		if err != nil || i < 0 || i >= len(fds) {
			return "", nil, errors.New("upload descriptor missing")
		}
		// A dup, so the *os.File owns its own descriptor; the passed one is closed with the request.
		dup, err := syscall.Dup(fds[i])
		if err != nil {
			return "", nil, errors.New("upload descriptor unusable")
		}
		f := os.NewFile(uintptr(dup), "upload")
		defer func() { _ = f.Close() }()
		var st os.FileInfo
		if st, err = f.Stat(); err != nil || !st.Mode().IsRegular() {
			return "", nil, errors.New("upload descriptor is not a regular file")
		}
		data, err = io.ReadAll(io.LimitReader(f, maxUpload+1))
		if err != nil || len(data) > maxUpload {
			return "", nil, errors.New("upload unreadable or too large")
		}
		name = "upload"
		if ext := sniffExt(data); ext != "" {
			name += ext
		}
		return name, data, nil
	}
	path, err := s.uploadPath(ref)
	if err != nil {
		return "", nil, err
	}
	data, err = os.ReadFile(path)
	if err != nil {
		return "", nil, fmt.Errorf("upload file: %w", err)
	}
	if len(data) > maxUpload {
		return "", nil, errors.New("upload too large")
	}
	return path, data, nil
}

func sniffExt(data []byte) string {
	switch http.DetectContentType(data) {
	case "image/png":
		return ".png"
	case "image/jpeg":
		return ".jpg"
	case "image/webp":
		return ".webp"
	}
	return ""
}

// uploadPath admits only regular files directly under a configured upload dir.
func (s *Server) uploadPath(p string) (string, error) {
	clean := filepath.Clean(p)
	for _, dir := range s.cfg.UploadDirs {
		dir = filepath.Clean(dir)
		if filepath.Dir(clean) == dir {
			fi, err := os.Lstat(clean)
			if err != nil {
				return "", err
			}
			if !fi.Mode().IsRegular() {
				return "", errors.New("upload file is not a regular file")
			}
			return clean, nil
		}
	}
	return "", errors.New("upload file outside the upload dirs")
}

func (s *Server) upstreamRequest(ctx context.Context, d *route.Destination, req *wire.Request, method string, body []byte, ctype string) (*http.Request, error) {
	target := ""
	if d.Kind == route.OnDevice {
		target = "http://on-device" + d.Path
	} else {
		target = d.URL.String()
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	hr, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return nil, err
	}
	for k, v := range req.Headers {
		ck := textproto.CanonicalMIMEHeaderKey(k)
		if requestHeaders[ck] && !strings.ContainsAny(v, "\r\n") {
			hr.Header.Set(ck, v)
		}
	}
	for k, v := range d.Headers {
		hr.Header.Set(k, v)
	}
	if body != nil {
		hr.Header.Set("Content-Type", ctype)
	}
	if hr.Header.Get("User-Agent") == "" {
		hr.Header.Set("User-Agent", "og-gate/"+s.cfg.Version)
	}
	if hr.Header.Get("Accept") == "" {
		hr.Header.Set("Accept", "application/json")
	}
	return hr, nil
}

func encodeBody(ctype string, data []byte) *wire.Response {
	r := &wire.Response{}
	if len(data) == 0 {
		return r
	}
	mt, _, _ := mime.ParseMediaType(ctype)
	if (mt == "application/json" || strings.HasSuffix(mt, "+json") || mt == "") && json.Valid(data) {
		r.Body = data
		return r
	}
	if utf8.Valid(data) && (strings.HasPrefix(mt, "text/") || mt == "application/x-www-form-urlencoded" || mt == "" || strings.Contains(mt, "json") || strings.Contains(mt, "xml")) {
		s := string(data)
		r.BodyText = &s
		return r
	}
	r.BodyB64 = base64.StdEncoding.EncodeToString(data)
	return r
}

func pickHeaders(h http.Header) map[string]string {
	out := map[string]string{}
	for _, k := range responseHeaders {
		if v := h.Get(k); v != "" {
			out[k] = v
		}
	}
	return out
}

func queryValues(q map[string]any) (url.Values, error) {
	if len(q) == 0 {
		return nil, nil
	}
	v := url.Values{}
	for k, x := range q {
		switch t := x.(type) {
		case string:
			v.Add(k, t)
		case float64, bool:
			v.Add(k, fmt.Sprint(t))
		case []any:
			for _, e := range t {
				v.Add(k, fmt.Sprint(e))
			}
		case nil:
		default:
			return nil, fmt.Errorf("query %q: unsupported value", k)
		}
	}
	return v, nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// errClass reduces a transport error to a short code with no URL or values in it.
func errClass(err error) string {
	var dnsErr *net.DNSError
	var opErr *net.OpError
	var tlsErr *tls.CertificateVerificationError
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.As(err, &dnsErr):
		return "dns"
	case errors.As(err, &tlsErr):
		return "tls_verify"
	case errors.As(err, &opErr):
		return "connect"
	}
	return "transport"
}

func noRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func upstreamTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

func unixTransport(socket string) *http.Transport {
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socket)
		},
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	}
}
