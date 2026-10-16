package gate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/ledger"
	"github.com/outgate-ai/og-local/internal/gate/route"
)

const (
	backupHost    = "og-os-backup-test.s3.eu-central-1.amazonaws.com"
	backupDevHost = "og-os-backup-dev-test.s3.eu-central-1.amazonaws.com"
	blobKey       = "/prefix/.SeedVaultAndroidBackup/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
)

// s3Bucket is a TLS stand-in for an S3 bucket: it records each request as it arrived.
type s3Bucket struct {
	mu   sync.Mutex
	got  []s3Hit
	srv  *httptest.Server
	blob []byte
}

type s3Hit struct {
	Method, URI, Host string
	Header            http.Header
	Body              []byte
	Length            int64
	TE                []string
	Complete          bool
}

func newBucket(t *testing.T) *s3Bucket {
	b := &s3Bucket{blob: make([]byte, 6<<20+123)}
	for i := range b.blob {
		b.blob[i] = byte(i*7 + i>>12)
	}
	b.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		hit := s3Hit{
			Method: r.Method, URI: r.RequestURI, Host: r.Host, Header: r.Header.Clone(), Body: body,
			Length: r.ContentLength, TE: r.TransferEncoding, Complete: err == nil && int64(len(body)) == max(r.ContentLength, 0),
		}
		b.mu.Lock()
		b.got = append(b.got, hit)
		b.mu.Unlock()
		if !hit.Complete {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch {
		case r.Method == http.MethodPut:
			w.Header().Set("ETag", `"etag-1"`)
			w.Header().Set("x-amz-request-id", "req-1")
		case r.Method == http.MethodGet && r.URL.Query().Has("list-type"):
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><KeyCount>0</KeyCount></ListBucketResult>`)
		case r.Method == http.MethodGet && r.URL.Path == "/missing":
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `<Error><Code>NoSuchKey</Code></Error>`)
		case r.Method == http.MethodGet, r.Method == http.MethodHead:
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", strconv.Itoa(len(b.blob)))
			if r.Method == http.MethodGet {
				_, _ = w.Write(b.blob)
			}
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<DeleteResult></DeleteResult>`)
		}
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *s3Bucket) hits() []s3Hit {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]s3Hit(nil), b.got...)
}

func (b *s3Bucket) last(t *testing.T) s3Hit {
	t.Helper()
	h := b.hits()
	if len(h) == 0 {
		t.Fatal("no request reached the bucket")
	}
	return h[len(h)-1]
}

// splitTransport sends the backup hosts to the bucket (TLS) and everything else to the plain upstream.
type splitTransport struct{ bucket, other http.RoundTripper }

func (s splitTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Hostname() == backupHost || r.URL.Hostname() == backupDevHost {
		return s.bucket.RoundTrip(r)
	}
	return s.other.RoundTrip(r)
}

func bucketTransport(b *s3Bucket) http.RoundTripper {
	tr := b.srv.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: tr.TLSClientConfig.RootCAs, ServerName: "example.com", MinVersion: tls.VersionTLS12}
	addr := b.srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	return tr
}

// startBackup starts a gate whose prod environment has the test bucket, for one caller class.
func startBackup(t *testing.T, class string, mm Masker, mutate func(*Config)) (*harness, *s3Bucket) {
	t.Helper()
	b := newBucket(t)
	uid := uint32(os.Getuid()) //nolint:gosec // uids fit uint32
	h := startOpts(t, Mask, func(c *Config) {
		c.Environments[0].Backup = "https://" + backupHost
		c.Callers = []CallerRule{{UID: &uid, Class: class}}
		if mutate != nil {
			mutate(c)
		}
	}, mm, nil, func(o *Options) {
		o.Transport = splitTransport{bucket: bucketTransport(b), other: o.Transport}
	})
	return h, b
}

// open sends a request line with descriptors and returns the connection to read the answer from.
func (h *harness) open(line string, fds ...int) (*net.UnixConn, *bufio.Reader) {
	h.t.Helper()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: h.sock, Net: "unix"})
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { _ = c.Close() })
	var oob []byte
	if len(fds) > 0 {
		oob = syscall.UnixRights(fds...)
	}
	if _, _, err := c.WriteMsgUnix([]byte(line+"\n"), oob, nil); err != nil {
		h.t.Fatal(err)
	}
	return c, bufio.NewReader(c)
}

func readLine(t *testing.T, br *bufio.Reader) map[string]any {
	t.Helper()
	out, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v (%q)", err, out)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("bad line %q: %v", out, err)
	}
	return m
}

func (h *harness) callFDs(line string, fds ...int) map[string]any {
	h.t.Helper()
	_, br := h.open(line, fds...)
	return readLine(h.t, br)
}

func backupReq(method, path, extra string) string {
	return fmt.Sprintf(`{"v":1,"id":"b-1","method":%q,"url":"https://%s%s","egress":{}%s}`, method, backupHost, path, extra)
}

// signed is what Seedvault's SigV4 signer sends (values are placeholders).
var signed = map[string]string{
	"authorization":        "AWS4-HMAC-SHA256 Credential=test-key/20261016/eu-central-1/s3/aws4_request, SignedHeaders=host;if-none-match;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=test-sig",
	"x-amz-date":           "20261016T212300Z",
	"X-AMZ-CONTENT-SHA256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
	"x-amz-security-token": "test-token",
	"If-None-Match":        "*",
	"x-amz-tagging":        "k=v",
	"content-md5":          "test-md5==",
	"Content-Type":         "application/octet-stream",
}

func headersJSON(extra map[string]string) string {
	m := map[string]string{}
	for k, v := range signed {
		m[k] = v
	}
	for k, v := range extra {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func TestBackupPutBodyFD(t *testing.T) {
	mm := &markerMasker{}
	h, b := startBackup(t, callerBackup, mm, nil)
	body := append([]byte(marker), b.blob[:3<<20]...)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	hdrs := headersJSON(map[string]string{"Host": "evil.test", "Content-Length": "1", "Transfer-Encoding": "chunked", "Cookie": "c=1"})
	_, br := h.open(backupReq("PUT", blobKey+"?x-id=PutObject", fmt.Sprintf(`,"headers":%s,"body_fd":"fd:0","body_size":%d`, hdrs, len(body))), int(pr.Fd()))
	_ = pr.Close()
	go func() {
		_, _ = pw.Write(body)
		_ = pw.Close()
	}()
	resp := readLine(t, br)
	if resp["status"].(float64) != 200 || resp["refused"] != nil || resp["class"] != "backup" || resp["streaming"] != nil {
		t.Fatalf("resp = %v", resp)
	}
	if hd := resp["headers"].(map[string]any); hd["Etag"] != `"etag-1"` || hd["X-Amz-Request-Id"] != "req-1" {
		t.Errorf("headers = %v", hd)
	}
	got := b.last(t)
	if got.Method != "PUT" || got.URI != blobKey+"?x-id=PutObject" || got.Host != backupHost || !bytes.Equal(got.Body, body) ||
		got.Length != int64(len(body)) || len(got.TE) != 0 {
		t.Fatalf("bucket got %s %s host=%s len=%d te=%v body equal=%v", got.Method, got.URI, got.Host, got.Length, got.TE, bytes.Equal(got.Body, body))
	}
	for k, v := range signed {
		if vals := got.Header.Values(k); len(vals) != 1 || vals[0] != v {
			t.Errorf("header %s = %q, want %q", k, vals, v)
		}
	}
	if got.Header.Get("Accept-Encoding") != "identity" || got.Header.Get("Accept") != "" || got.Header.Get("Cookie") != "" {
		t.Errorf("headers = %v", got.Header)
	}
	if mm.n() != 0 {
		t.Errorf("masker called %d times on a backup body", mm.n())
	}
	row := h.rows.last(t)
	if row.Class != "backup" || row.Kind != "upload" || row.Destination != backupHost || row.PathClass != "" || row.Caller != "backup" ||
		row.BytesOut != int64(len(body)) || row.BytesOutRaw != int64(len(body)) || !row.Content || row.Mask != MaskNotRequired ||
		row.Status != 200 || row.Blocked || row.MaskedCount != 0 {
		t.Errorf("row = %+v", row)
	}
}

func TestBackupGetResponseFD(t *testing.T) {
	h, b := startBackup(t, callerBackup, nil, nil)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pr.Close() }()
	_, br := h.open(backupReq("GET", blobKey, `,"headers":{"Range":"bytes=0-","x-amz-date":"20261016T212300Z"},"response_fd":"fd:0"`), int(pw.Fd()))
	_ = pw.Close()
	// The response line comes before the body: nothing has drained the pipe yet (its buffer is far smaller than the body).
	resp := readLine(t, br)
	if resp["status"].(float64) != 200 || resp["streaming"] != true || resp["body"] != nil || resp["body_b64"] != nil ||
		resp["body_text"] != nil || resp["body_written"] != nil {
		t.Fatalf("resp = %v", resp)
	}
	if hd := resp["headers"].(map[string]any); hd["Content-Length"] != strconv.Itoa(len(b.blob)) || hd["Content-Type"] != "application/octet-stream" {
		t.Errorf("headers = %v", hd)
	}
	data, err := io.ReadAll(pr)
	if err != nil || !bytes.Equal(data, b.blob) {
		t.Fatalf("pipe: %d bytes, err %v", len(data), err)
	}
	tr := readLine(t, br)
	if tr["done"] != true || num(tr["body_written"]) != int64(len(b.blob)) || tr["id"] != "b-1" {
		t.Errorf("trailer = %v", tr)
	}
	if got := b.last(t); got.Header.Get("Range") != "bytes=0-" || got.Header.Get("Accept-Encoding") != "identity" {
		t.Errorf("bucket headers = %v", got.Header)
	}
	row := h.rows.last(t)
	if row.Kind != "download" || row.BytesIn != int64(len(b.blob)) || row.Status != 200 || row.Error != "" || row.PathClass != "" {
		t.Errorf("row = %+v", row)
	}
}

// A non-2xx comes back inline (S3's error XML); the response descriptor is closed unwritten.
func TestBackupResponseFDError(t *testing.T) {
	h, _ := startBackup(t, callerBackup, nil, nil)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pr.Close() }()
	_, br := h.open(backupReq("GET", "/missing", `,"response_fd":"fd:0"`), int(pw.Fd()))
	_ = pw.Close()
	resp := readLine(t, br)
	if resp["status"].(float64) != 404 || resp["streaming"] != nil || !strings.Contains(fmt.Sprint(resp["body_text"]), "NoSuchKey") {
		t.Fatalf("resp = %v", resp)
	}
	if data, err := io.ReadAll(pr); err != nil || len(data) != 0 {
		t.Errorf("pipe got %d bytes, %v", len(data), err)
	}
}

func TestBackupListDeleteHead(t *testing.T) {
	h, b := startBackup(t, callerBackup, nil, nil)
	resp := h.call(backupReq("GET", "/?list-type=2&prefix=prefix%2F.SeedVaultAndroidBackup%2F&continuation-token=abc%2B1", ""))
	if resp["status"].(float64) != 200 || !strings.Contains(fmt.Sprint(resp["body_text"]), "<ListBucketResult>") {
		t.Fatalf("list: %v", resp)
	}
	if got := b.last(t); got.URI != "/?list-type=2&prefix=prefix%2F.SeedVaultAndroidBackup%2F&continuation-token=abc%2B1" {
		t.Errorf("list query rewritten: %s", got.URI)
	}
	if row := h.rows.last(t); row.Kind != "list" || row.PathClass != "" {
		t.Errorf("list row = %+v", row)
	}

	resp = h.call(backupReq("DELETE", blobKey, `,"headers":{"x-amz-date":"20261016T212300Z"}`))
	if resp["status"].(float64) != 204 || b.last(t).Method != "DELETE" {
		t.Fatalf("delete: %v", resp)
	}
	if row := h.rows.last(t); row.Kind != "delete" || row.Content {
		t.Errorf("delete row = %+v", row)
	}

	xml := `<Delete><Object><Key>prefix/a</Key></Object></Delete>`
	resp = h.call(backupReq("POST", "/?delete", fmt.Sprintf(`,"headers":{"Content-MD5":"test-md5==","Content-Type":"application/xml"},"body_text":%q`, xml)))
	got := b.last(t)
	if resp["status"].(float64) != 200 || got.Method != "POST" || got.URI != "/?delete" || string(got.Body) != xml ||
		got.Header.Get("Content-Md5") != "test-md5==" || got.Header.Get("Content-Type") != "application/xml" {
		t.Fatalf("delete objects: %v / %+v", resp, got)
	}
	if row := h.rows.last(t); row.Kind != "delete" || row.BytesOut != int64(len(xml)) {
		t.Errorf("delete objects row = %+v", row)
	}

	resp = h.call(backupReq("HEAD", blobKey, ""))
	if resp["status"].(float64) != 200 || resp["headers"].(map[string]any)["Content-Length"] != strconv.Itoa(len(b.blob)) {
		t.Errorf("head: %v", resp)
	}
	if row := h.rows.last(t); row.Kind != "head" {
		t.Errorf("head row = %+v", row)
	}

	n := len(b.hits())
	for line, want := range map[string]string{
		backupReq("POST", "/", ""):                        "bad_query",
		backupReq("PATCH", blobKey, ""):                   "bad_method",
		backupReq("GET", "/", `,"query":{"list-type":2}`): "bad_query",
	} {
		if resp := h.call(line); resp["refused"] != want {
			t.Errorf("%s: %v", line, resp)
		}
	}
	if len(b.hits()) != n {
		t.Error("a refused request reached the bucket")
	}
}

// A small body without a descriptor: body_b64, no Content-Type added, no image approval for its bytes.
func TestBackupInlineBody(t *testing.T) {
	h, b := startBackup(t, callerBackup, nil, nil)
	png := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{1}, 64)...)
	resp := h.call(backupReq("PUT", blobKey, fmt.Sprintf(`,"body_b64":%q`, base64.StdEncoding.EncodeToString(png))))
	if resp["status"].(float64) != 200 || resp["approval_id"] != nil {
		t.Fatalf("resp = %v", resp)
	}
	got := b.last(t)
	if !bytes.Equal(got.Body, png) || got.Header.Get("Content-Type") != "" || got.Length != int64(len(png)) {
		t.Errorf("bucket got %+v", got)
	}
	resp = h.call(backupReq("PUT", blobKey, ""))
	if got := b.last(t); resp["status"].(float64) != 200 || got.Length != 0 || len(got.TE) != 0 {
		t.Errorf("empty put: %v / %+v", resp, got)
	}
}

func TestBackupBodySizeMismatch(t *testing.T) {
	h, b := startBackup(t, callerBackup, nil, nil)
	f, err := os.CreateTemp(t.TempDir(), "chunk")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	_, _ = f.Write(make([]byte, 1000))
	_, _ = f.Seek(0, io.SeekStart)
	resp := h.callFDs(backupReq("PUT", blobKey, `,"body_fd":"fd:0","body_size":1001`), int(f.Fd()))
	if resp["refused"] != "bad_body" || resp["status"].(float64) != 400 || len(b.hits()) != 0 {
		t.Fatalf("short file: %v (%d hits)", resp, len(b.hits()))
	}
	if row := h.rows.last(t); !row.Blocked || row.BlockReason != "bad_body" || row.Class != "backup" {
		t.Errorf("row = %+v", row)
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, br := h.open(backupReq("PUT", blobKey, `,"body_fd":"fd:0","body_size":300000`), int(pr.Fd()))
	_ = pr.Close()
	_, _ = pw.Write(make([]byte, 200000))
	_ = pw.Close()
	if resp := readLine(t, br); resp["refused"] != "bad_body" {
		t.Errorf("short pipe: %v", resp)
	}
	for _, hit := range b.hits() {
		if hit.Complete {
			t.Errorf("a short body completed: %+v", hit.Length)
		}
	}

	for line, want := range map[string]string{
		backupReq("PUT", blobKey, `,"body_fd":"fd:0"`):                                 "bad_body",
		backupReq("PUT", blobKey, `,"body_fd":"fd:1","body_size":1`):                   "bad_body",
		backupReq("PUT", blobKey, `,"body_size":1`):                                    "bad_body",
		backupReq("PUT", blobKey, `,"body_fd":"fd:0","body_size":1,"body_b64":"AA=="`): "bad_body",
		backupReq("PUT", blobKey, `,"body":{"a":1}`):                                   "bad_body",
		backupReq("GET", blobKey, `,"response_fd":"fd:2"`):                             "bad_request",
	} {
		if resp := h.callFDs(line, int(f.Fd())); resp["refused"] != want {
			t.Errorf("%s: %v", line, resp)
		}
	}
	ro, err := os.Open(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	if resp := h.callFDs(backupReq("GET", blobKey, `,"response_fd":"fd:0"`), int(ro.Fd())); resp["refused"] != "bad_request" {
		t.Errorf("read-only response_fd: %v", resp)
	}
}

func TestBackupAccess(t *testing.T) {
	h, b := startBackup(t, callerBackup, nil, nil)
	for line, want := range map[string]string{
		`{"method":"GET","url":"https://evil.test/x","egress":{}}`:                                     "destination_not_allowed",
		`{"source":{"region_id":"global"},"method":"GET","path":"/api/v1/agents/threads","egress":{}}`: "destination_not_allowed",
		fmt.Sprintf(`{"method":"GET","url":"%s/x","egress":{}}`, h.up.srv.URL):                         "destination_not_allowed",
		fmt.Sprintf(`{"method":"GET","url":"http://%s/x","egress":{}}`, backupHost):                    "destination_not_allowed",
		`{"source":{"region_id":"appq:t1"},"method":"GET","path":"/","egress":{}}`:                     "destination_not_allowed",
		`{"op":"download","path":"m/x.gguf","offset":0,"size":10,"file":"fd:0"}`:                       "caller_not_allowed",
		`{"op":"ledger"}`:    "caller_not_allowed",
		`{"op":"health"}`:    "caller_not_allowed",
		`{"op":"appq_list"}`: "caller_not_allowed",
	} {
		if resp := h.call(line); resp["refused"] != want {
			t.Errorf("%s: %v", line, resp)
		}
	}
	if len(b.hits()) != 0 || len(h.up.got) != 0 {
		t.Errorf("refused requests left: bucket %d, upstream %d", len(b.hits()), len(h.up.got))
	}
	h.rows.mu.Lock()
	rows := append([]ledger.Row(nil), h.rows.rows...)
	h.rows.mu.Unlock()
	for _, row := range rows {
		if row.PathClass != "" {
			t.Errorf("backup caller row with a path: %+v", row)
		}
	}

	agent, ab := startBackup(t, "agent", nil, nil)
	if resp := agent.call(backupReq("GET", blobKey, "")); resp["refused"] != "destination_not_allowed" {
		t.Errorf("agent to the bucket: %v", resp)
	}
	pr, pw, _ := os.Pipe()
	defer func() { _ = pr.Close(); _ = pw.Close() }()
	if resp := agent.callFDs(`{"source":{"region_id":"global"},"method":"GET","path":"/x","response_fd":"fd:0","egress":{}}`, int(pw.Fd())); resp["refused"] != "bad_request" {
		t.Errorf("response_fd to global: %v", resp)
	}
	if len(ab.hits()) != 0 {
		t.Error("the agent reached the bucket")
	}

	debug, _ := startBackup(t, "debug", nil, func(c *Config) { c.Debuggable = true })
	if resp := debug.call(backupReq("HEAD", blobKey, "")); resp["status"].(float64) != 200 {
		t.Errorf("debug on a debuggable build: %v", resp)
	}
	debugUser, _ := startBackup(t, "debug", nil, nil)
	if resp := debugUser.call(backupReq("HEAD", blobKey, "")); resp["refused"] != "destination_not_allowed" {
		t.Errorf("debug on a user build: %v", resp)
	}
}

func TestBackupDevBucketDebuggableOnly(t *testing.T) {
	dev := func(debuggable bool) func(*Config) {
		return func(c *Config) {
			c.Debuggable = debuggable
			c.Environments = append(c.Environments, route.Environment{
				ID: "dev", Global: "https://api.dev.outgate.test", OIDC: "https://console.dev.outgate.test",
				Backup: "https://" + backupDevHost, DebuggableOnly: true,
			})
		}
	}
	line := fmt.Sprintf(`{"method":"HEAD","url":"https://%s%s","egress":{}}`, backupDevHost, blobKey)
	user, _ := startBackup(t, callerBackup, nil, dev(false))
	if resp := user.call(line); resp["refused"] != "destination_not_allowed" {
		t.Errorf("dev bucket on a user build: %v", resp)
	}
	eng, _ := startBackup(t, callerBackup, nil, dev(true))
	if resp := eng.call(line); resp["status"].(float64) != 200 {
		t.Errorf("dev bucket on a debuggable build: %v", resp)
	}
}

func TestBackupCallerByPackage(t *testing.T) {
	list := filepath.Join(t.TempDir(), "packages.list")
	line := fmt.Sprintf("com.stevesoltys.seedvault %d 0 /data/user/0/com.stevesoltys.seedvault platform 3003\n", os.Getuid())
	if err := os.WriteFile(list, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	h, b := startBackup(t, callerBackup, nil, func(c *Config) {
		c.Callers = []CallerRule{{Package: "com.stevesoltys.seedvault", Class: callerBackup}}
		c.PackagesList = list
	})
	if resp := h.call(backupReq("HEAD", blobKey, "")); resp["status"].(float64) != 200 || len(b.hits()) != 1 {
		t.Errorf("seedvault: %v", resp)
	}
}

// The ledger keeps the bucket host, never the object key, the query or a header value.
func TestBackupLedgerHasNoKey(t *testing.T) {
	h, _ := startBackup(t, callerBackup, nil, nil)
	key := strings.Repeat("0123456789abcdef", 4)
	resp := h.call(backupReq("PUT", "/"+key+"?x=y", fmt.Sprintf(`,"headers":%s,"body_text":"ciphertext"`, headersJSON(nil))))
	if resp["status"].(float64) != 200 {
		t.Fatalf("resp = %v", resp)
	}
	row := h.rows.last(t)
	files, _ := filepath.Glob(filepath.Join(h.dir, "ledger", "egress-*.jsonl"))
	if len(files) != 1 {
		t.Fatalf("ledger files = %v", files)
	}
	b, _ := os.ReadFile(files[0])
	rb, _ := json.Marshal(row) //nolint:gosec // a ledger row, checked for leaks
	for _, s := range []string{string(b), string(rb)} {
		for _, leak := range []string{key, "x=y", "?x", "test-sig", "test-token", "20261016T212300Z", "ciphertext"} {
			if strings.Contains(s, leak) {
				t.Errorf("ledger holds %q: %s", leak, s)
			}
		}
	}
	if !strings.Contains(string(b), `"destination":"`+backupHost+`"`) || row.Kind != "upload" || row.PathClass != "" {
		t.Errorf("row = %s", rb)
	}
}

func TestBackupConfig(t *testing.T) {
	good := Config{Environments: []route.Environment{{
		ID: "prod", Global: "https://api.outgate.test", OIDC: "https://console.outgate.test",
		Backup: "https://og-os-backup-prod.s3.eu-central-1.amazonaws.com",
	}}}
	if err := good.Validate(); err != nil || good.Masks("backup") || good.MaskingClasses()["backup"] {
		t.Errorf("good: %v", err)
	}
	for _, backup := range []string{
		"http://og-os-backup-prod.s3.eu-central-1.amazonaws.com",
		"https://og-os-backup-prod.s3.eu-central-1.amazonaws.com/prefix",
		"https://og-os-backup-prod.s3.eu-central-1.amazonaws.com/?x=1",
		"https://og-os-backup-prod.s3.eu-central-1.amazonaws.com?",
		"https://user@og-os-backup-prod.s3.eu-central-1.amazonaws.com",
		"https://api.outgate.test",
		"s3://og-os-backup-prod",
		"og-os-backup-prod.s3.eu-central-1.amazonaws.com",
	} {
		c := good
		c.Environments = []route.Environment{good.Environments[0]}
		c.Environments[0].Backup = backup
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", backup)
		}
	}
	if err := (&Config{Classes: []ClassRule{{Class: "backup", Mask: true}}}).Validate(); err == nil {
		t.Error("masked backup class accepted")
	}
	if err := (&Config{Classes: []ClassRule{{Class: "backup", Destinations: []route.Provider{{ID: "x", Base: "https://x.test"}}}}}).Validate(); err == nil {
		t.Error("backup destinations accepted")
	}
	if err := (&Config{Classes: []ClassRule{{Class: "backup"}}}).Validate(); err != nil {
		t.Errorf("unmasked backup class: %v", err)
	}
	conf := filepath.Join(t.TempDir(), "gate.conf")
	_ = os.WriteFile(conf, []byte(`{"environments":[{"id":"prod","global":"https://api.outgate.test","oidc":"https://console.outgate.test","backup":"http://b.s3.eu-central-1.amazonaws.com"}]}`), 0o600)
	if _, err := LoadConfig(conf); err == nil {
		t.Error("LoadConfig accepted an http backup")
	}
}

// The caller hanging up ends a streaming download early and closes its descriptor.
func TestBackupStreamEndsWithItsCaller(t *testing.T) {
	h, b := startBackup(t, callerBackup, nil, nil)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pr.Close() }()
	c, br := h.open(backupReq("GET", blobKey, `,"response_fd":"fd:0"`), int(pw.Fd()))
	_ = pw.Close()
	if resp := readLine(t, br); resp["streaming"] != true {
		t.Fatalf("resp = %v", resp)
	}
	_ = c.Close()
	done := make(chan []byte)
	go func() {
		data, _ := io.ReadAll(pr)
		done <- data
	}()
	select {
	case data := <-done:
		if len(data) > len(b.blob) {
			t.Errorf("%d bytes", len(data))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the response descriptor stayed open after the caller hung up")
	}
	if row := h.rows.last(t); row.Kind != "download" {
		t.Errorf("row = %+v", row)
	}
}
