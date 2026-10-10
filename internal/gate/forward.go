package gate

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
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
	"strings"
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

func (s *Server) forward(ctx context.Context, class string, cred peer.Cred, req *wire.Request) *wire.Response {
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
	}
	defer func() {
		row.DurationMs = time.Since(start).Milliseconds()
		s.ledger.Record(&row)
		s.log.Info("egress", "id", row.ID, "caller", row.Caller, "dest", row.Destination, "method", row.Method,
			"path", row.PathClass, "status", row.Status, "out", row.BytesOut, "in", row.BytesIn,
			"masked", row.MaskedCount, "blocked", row.Blocked, "reason", row.BlockReason, "ms", row.DurationMs)
	}()
	refuse := func(status int, reason, detail string) *wire.Response {
		row.Blocked, row.BlockReason, row.Status = true, reason, status
		r := wire.Refuse(req.ID, status, reason, detail)
		r.Ledger = row.ID
		return r
	}
	if !methods[method] {
		return refuse(400, "bad_method", method)
	}

	query, err := queryValues(req.Query)
	if err != nil {
		return refuse(400, "bad_query", err.Error())
	}
	dest, err := s.router.Resolve(req.Source.RegionID, req.URL, req.Path, query)
	if err != nil {
		reason := "destination_not_allowed"
		status := 403
		if errors.Is(err, route.ErrUnknownRegion) {
			reason, status = "unknown_region", 404
		} else if errors.Is(err, route.ErrBadURL) {
			reason, status = "bad_url", 400
		}
		return refuse(status, reason, err.Error())
	}
	path := req.Path
	if dest.URL != nil {
		path = dest.URL.Path
	}
	row.Destination = dest.Display
	row.PathClass = route.PathClass(path)
	row.OnDevice = dest.Kind == route.OnDevice
	row.ThreadID = req.Egress.ThreadID
	if row.ThreadID == "" {
		row.ThreadID = route.ThreadID(path)
	}
	row.Kind = coreKind(req.Egress.Kind, method, row.PathClass, row.OnDevice)

	body, ctype, err := s.requestBody(req)
	if err != nil {
		return refuse(400, "bad_body", err.Error())
	}
	call := &Call{Caller: class, Req: req, Path: row.PathClass, Kind: row.Kind}
	call.Content = len(body) > 0 && !contentFree[req.Egress.Kind] && !s.isOIDC(dest) && !isEmptyJSON(body)
	row.Content = call.Content
	row.BytesOutRaw = int64(len(body))

	sent := body
	if call.Content && !row.OnDevice {
		var m wire.Masked
		sent, m, err = s.masker.Mask(ctx, call, body)
		if err != nil {
			reason := "mask_failed"
			if errors.Is(err, ErrDetectorUnavailable) {
				reason = ErrDetectorUnavailable.Error()
			}
			return refuse(503, reason, err.Error())
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
	client := s.client
	if row.OnDevice {
		client = s.model
	}
	hresp, err := client.Do(hreq)
	if err != nil {
		row.Error = errClass(err)
		row.Status = 502
		if cctx.Err() != nil {
			row.Status = 504
		}
		r := wire.Fail(req.ID, row.Status, "upstream_unreachable", row.Error)
		r.Ledger = row.ID
		return r
	}
	defer func() { _ = hresp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(hresp.Body, maxResponse+1))
	row.Status = hresp.StatusCode
	row.BytesIn = int64(len(data))
	if err != nil || len(data) > maxResponse {
		row.Error = "response_unreadable"
		r := wire.Fail(req.ID, 502, "upstream_unreachable", "response unreadable or too large")
		r.Ledger = row.ID
		return r
	}
	if dest.Env != "" && hresp.StatusCode/100 == 2 && s.isGlobal(dest) {
		if n := s.router.Regions.LearnFrom(s.cfg.Learn, row.PathClass, data, dest.Env); n > 0 {
			s.log.Info("region hosts learned", "count", n, "env", dest.Env)
		}
	}
	restored, fields := s.masker.Restore(ctx, call, data)
	row.RestoredCount = len(fields)
	out := encodeBody(hresp.Header.Get("Content-Type"), restored)
	out.Status = hresp.StatusCode
	out.Headers = pickHeaders(hresp.Header)
	out.Masked = wire.Masked{Count: row.MaskedCount, Categories: row.MaskedCategories}
	out.Restored = fields
	out.Ledger = row.ID
	return out
}

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
func (s *Server) requestBody(req *wire.Request) (body []byte, contentType string, err error) {
	if req.File != "" {
		return s.multipartBody(req)
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

func (s *Server) multipartBody(req *wire.Request) (body []byte, contentType string, err error) {
	path, err := s.uploadPath(req.File)
	if err != nil {
		return nil, "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("upload file: %w", err)
	}
	var fields map[string]any
	if len(req.Body) > 0 && string(req.Body) != "null" {
		if err := json.Unmarshal(req.Body, &fields); err != nil {
			return nil, "", fmt.Errorf("upload fields: %w", err)
		}
	}
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		val := ""
		switch x := v.(type) {
		case string:
			val = x
		default:
			b, _ := json.Marshal(x)
			val = string(b)
		}
		if err := w.WriteField(k, val); err != nil {
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
