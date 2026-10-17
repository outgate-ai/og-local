package gate

import (
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
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/outgate-ai/og-local/internal/gate/route"
)

const (
	uploadsHost    = "outgate-uploads-test.s3.eu-central-1.amazonaws.com"
	uploadsDevHost = "outgate-uploads-dev-test.s3.eu-central-1.amazonaws.com"
	// presign is an S3 SigV4 presigned query (placeholder values).
	presign = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=test-key%2F20261017%2Feu-central-1%2Fs3%2Faws4_request" +
		"&X-Amz-Date=20261017T010000Z&X-Amz-Expires=900&X-Amz-SignedHeaders=host&X-Amz-Signature=test-signature-0123"
	objKey = "/out/org-1/user-1/ws-1/path-chart"
)

// uploadsBucket serves a small and a large image and a missing key, recording each request.
type uploadsBucket struct {
	mu    sync.Mutex
	got   []*http.Request
	srv   *httptest.Server
	small []byte
	big   []byte
}

func newUploadsBucket(t *testing.T) *uploadsBucket {
	b := &uploadsBucket{small: bytes.Repeat([]byte{0x89, 'P', 'N', 'G'}, 25), big: make([]byte, 3<<20+7)}
	for i := range b.big {
		b.big[i] = byte(i*13 + i>>9)
	}
	b.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		b.got = append(b.got, r.Clone(context.Background()))
		b.mu.Unlock()
		switch r.URL.Path {
		case objKey + "-small":
			w.Header().Set("Content-Type", "image/png")
			w.Header().Set("Content-Length", strconv.Itoa(len(b.small)))
			_, _ = w.Write(b.small)
		case objKey + "-big":
			w.Header().Set("Content-Type", "image/png")
			w.Header().Set("Content-Length", strconv.Itoa(len(b.big)))
			_, _ = w.Write(b.big)
		default:
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `<Error><Code>NoSuchKey</Code></Error>`)
		}
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *uploadsBucket) last(t *testing.T) *http.Request {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.got) == 0 {
		t.Fatal("no request reached the bucket")
	}
	return b.got[len(b.got)-1]
}

func (b *uploadsBucket) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.got)
}

type uploadsTransport struct{ bucket, other http.RoundTripper }

func (u uploadsTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if h := r.URL.Hostname(); h == uploadsHost || h == uploadsDevHost {
		return u.bucket.RoundTrip(r)
	}
	return u.other.RoundTrip(r)
}

func startUploads(t *testing.T, class string, mm Masker, mutate func(*Config)) (*harness, *uploadsBucket) {
	t.Helper()
	b := newUploadsBucket(t)
	uid := uint32(os.Getuid()) //nolint:gosec // uids fit uint32
	h := startOpts(t, Mask, func(c *Config) {
		c.Environments[0].Uploads = "https://" + uploadsHost
		c.Callers = []CallerRule{{UID: &uid, Class: class}}
		if mutate != nil {
			mutate(c)
		}
	}, mm, nil, func(o *Options) {
		tr := b.srv.Client().Transport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{RootCAs: tr.TLSClientConfig.RootCAs, ServerName: "example.com", MinVersion: tls.VersionTLS12}
		addr := b.srv.Listener.Addr().String()
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
		o.Transport = uploadsTransport{bucket: tr, other: o.Transport}
	})
	return h, b
}

func uploadsReq(method, path, query, extra string) string {
	u := "https://" + uploadsHost + path
	if query != "" {
		u += "?" + query
	}
	return fmt.Sprintf(`{"v":1,"id":"u-1","method":%q,"url":%q,"egress":{"thread_id":"thr-1"}%s}`, method, u, extra)
}

func TestUploadsSmallInline(t *testing.T) {
	mm := &markerMasker{}
	h, b := startUploads(t, callerChat, mm, nil)
	resp := h.call(uploadsReq("GET", objKey+"-small", presign, `,"headers":{"Authorization":"Bearer leak","Cookie":"c=1","If-None-Match":"\"e1\"","Range":"bytes=0-"}`))
	if resp["status"].(float64) != 200 || resp["refused"] != nil || resp["class"] != route.ClassUploads || resp["streaming"] != nil {
		t.Fatalf("resp = %v", resp)
	}
	got, err := base64.StdEncoding.DecodeString(fmt.Sprint(resp["body_b64"]))
	if err != nil || !bytes.Equal(got, b.small) {
		t.Fatalf("body = %v (%v)", resp["body_b64"], err)
	}
	r := b.last(t)
	if r.Method != "GET" || r.URL.RawQuery != presign || r.Host != uploadsHost {
		t.Errorf("bucket got %s %s?%s host %s", r.Method, r.URL.Path, r.URL.RawQuery, r.Host)
	}
	// The presigned URL is the authorization: nothing else the caller sent goes along but the range and revalidation.
	if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Accept-Encoding") != "identity" ||
		r.Header.Get("If-None-Match") != `"e1"` || r.Header.Get("Range") != "bytes=0-" {
		t.Errorf("bucket headers = %v", r.Header)
	}
	if mm.n() != 0 {
		t.Errorf("masker called %d times", mm.n())
	}
	row := h.rows.last(t)
	if row.Class != route.ClassUploads || row.Kind != "download" || row.Destination != uploadsHost || row.PathClass != "" ||
		row.BytesIn != int64(len(b.small)) || row.Status != 200 || row.Blocked || row.Caller != callerChat || row.Mask != MaskNotRequired {
		t.Errorf("row = %+v", row)
	}
	j, _ := json.Marshal(row)
	if s := string(j); strings.Contains(s, "path-chart") || strings.Contains(s, "test-signature") || strings.Contains(s, "X-Amz") {
		t.Errorf("ledger row leaks the key or signature: %s", s)
	}
}

func TestUploadsResponseFD(t *testing.T) {
	h, b := startUploads(t, callerChat, nil, nil)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pr.Close() }()
	_, br := h.open(uploadsReq("GET", objKey+"-big", presign, `,"response_fd":"fd:0"`), int(pw.Fd()))
	_ = pw.Close()
	resp := readLine(t, br)
	if resp["status"].(float64) != 200 || resp["streaming"] != true || resp["body_b64"] != nil || resp["body_text"] != nil {
		t.Fatalf("resp = %v", resp)
	}
	if hd := resp["headers"].(map[string]any); hd["Content-Length"] != strconv.Itoa(len(b.big)) || hd["Content-Type"] != "image/png" {
		t.Errorf("headers = %v", hd)
	}
	data, err := io.ReadAll(pr)
	if err != nil || !bytes.Equal(data, b.big) {
		t.Fatalf("pipe: %d bytes, err %v", len(data), err)
	}
	tr := readLine(t, br)
	if tr["done"] != true || num(tr["body_written"]) != int64(len(b.big)) || tr["id"] != "u-1" {
		t.Errorf("trailer = %v", tr)
	}
	if row := h.rows.last(t); row.Kind != "download" || row.BytesIn != int64(len(b.big)) || row.Error != "" || row.PathClass != "" {
		t.Errorf("row = %+v", row)
	}
}

// A file larger than an inline body needs response_fd: refused, never buffered into the line.
func TestUploadsLargeInlineRefused(t *testing.T) {
	h, _ := startUploads(t, callerChat, nil, nil)
	resp := h.call(uploadsReq("GET", objKey+"-big", presign, ""))
	if resp["status"].(float64) != 413 || resp["refused"] != "too_large" || resp["body_b64"] != nil {
		t.Fatalf("resp = %v", resp)
	}
	if row := h.rows.last(t); row.Error != "too_large" && row.BlockReason != "too_large" {
		t.Errorf("row = %+v", row)
	}
}

// A missing key comes back inline (S3's error XML); the descriptor is closed unwritten.
func TestUploadsErrorInline(t *testing.T) {
	h, _ := startUploads(t, callerChat, nil, nil)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pr.Close() }()
	_, br := h.open(uploadsReq("GET", "/missing", presign, `,"response_fd":"fd:0"`), int(pw.Fd()))
	_ = pw.Close()
	resp := readLine(t, br)
	if resp["status"].(float64) != 404 || resp["streaming"] != nil || !strings.Contains(fmt.Sprint(resp["body_text"]), "NoSuchKey") {
		t.Fatalf("resp = %v", resp)
	}
	if data, err := io.ReadAll(pr); err != nil || len(data) != 0 {
		t.Errorf("pipe got %d bytes, %v", len(data), err)
	}
}

func TestUploadsRefusals(t *testing.T) {
	h, b := startUploads(t, callerChat, nil, nil)
	cases := []struct{ name, line, reason string }{
		{"put", uploadsReq("PUT", objKey+"-small", presign, `,"body_text":"x"`), "bad_method"},
		{"head", uploadsReq("HEAD", objKey+"-small", presign, ""), "bad_method"},
		{"delete", uploadsReq("DELETE", objKey+"-small", presign, ""), "bad_method"},
		{"not presigned", uploadsReq("GET", objKey+"-small", "", ""), "bad_url"},
		{"no signature", uploadsReq("GET", objKey+"-small", strings.Replace(presign, "&X-Amz-Signature=test-signature-0123", "", 1), ""), "bad_url"},
		{"other algorithm", uploadsReq("GET", objKey+"-small", strings.Replace(presign, "AWS4-HMAC-SHA256", "AWS4-X", 1), ""), "bad_url"},
		{"separate query", uploadsReq("GET", objKey+"-small", presign, `,"query":{"a":"b"}`), "bad_query"},
		{"body", uploadsReq("GET", objKey+"-small", presign, `,"body_b64":"AAAA"`), "bad_body"},
	}
	for _, c := range cases {
		resp := h.call(c.line)
		if resp["refused"] != c.reason {
			t.Errorf("%s: resp = %v, want %s", c.name, resp, c.reason)
		}
	}
	if n := b.count(); n != 0 {
		t.Errorf("%d refused requests reached the bucket", n)
	}
}

// Only the chat (and debug tools on debuggable builds) reaches the uploads bucket.
func TestUploadsOtherCallersRefused(t *testing.T) {
	for _, class := range []string{"agent", callerBackup, "voice", "models", "local-agent", "debug"} {
		t.Run(class, func(t *testing.T) {
			h, b := startUploads(t, class, nil, nil)
			resp := h.call(uploadsReq("GET", objKey+"-small", presign, ""))
			// Callers with no proxy requests at all are refused before routing (caller_not_allowed).
			if r := resp["refused"]; resp["status"].(float64) != 403 || (r != "destination_not_allowed" && r != "caller_not_allowed") {
				t.Fatalf("resp = %v", resp)
			}
			if b.count() != 0 {
				t.Errorf("reached the bucket")
			}
		})
	}
	h, _ := startUploads(t, "debug", nil, func(c *Config) { c.Debuggable = true })
	if resp := h.call(uploadsReq("GET", objKey+"-small", presign, "")); resp["status"].(float64) != 200 {
		t.Errorf("debug on a debuggable build: %v", resp)
	}
}

// The chat still reaches Outgate as before; the uploads host is not reachable as another class.
func TestUploadsChatKeepsOtherDestinations(t *testing.T) {
	h, b := startUploads(t, callerChat, nil, nil)
	resp := h.call(`{"v":1,"id":"o-1","method":"GET","path":"/api/v1/agents/regions","egress":{}}`)
	if resp["refused"] != nil || resp["class"] != route.ClassOutgate {
		t.Fatalf("outgate call = %v", resp)
	}
	resp = h.call(`{"v":1,"id":"o-2","method":"GET","url":"http://` + uploadsHost + objKey + `-small?` + presign + `","egress":{}}`)
	if resp["refused"] == nil || b.count() != 0 {
		t.Errorf("plain http to the uploads host: %v (bucket hits %d)", resp, b.count())
	}
}

// A debuggable-only environment's uploads bucket is unreachable on user builds.
func TestUploadsDebuggableOnlyEnvironment(t *testing.T) {
	mut := func(debuggable bool) func(*Config) {
		return func(c *Config) {
			c.Debuggable = debuggable
			c.Environments = append(c.Environments, route.Environment{
				ID: "dev", Global: "https://api.dev.example", OIDC: "https://console.dev.example",
				Uploads: "https://" + uploadsDevHost, DebuggableOnly: true,
			})
		}
	}
	line := strings.Replace(uploadsReq("GET", objKey+"-small", presign, ""), uploadsHost, uploadsDevHost, 1)
	h, _ := startUploads(t, callerChat, nil, mut(false))
	if resp := h.call(line); resp["refused"] == nil {
		t.Errorf("user build reached the dev uploads bucket: %v", resp)
	}
	h, _ = startUploads(t, callerChat, nil, mut(true))
	if resp := h.call(line); resp["status"].(float64) != 200 {
		t.Errorf("debuggable build: %v", resp)
	}
}

func TestUploadsConfigValidation(t *testing.T) {
	base := func() Config {
		return Config{Environments: []route.Environment{{ID: "prod", Global: "https://api.example", OIDC: "https://console.example"}}}
	}
	good := base()
	good.Environments[0].Uploads = "https://" + uploadsHost
	if err := good.Validate(); err != nil {
		t.Errorf("good: %v", err)
	}
	for _, bad := range []string{
		"http://" + uploadsHost, "https://" + uploadsHost + "/prefix", "https://" + uploadsHost + "?a=b",
		"https://user@" + uploadsHost, "https://api.example", "https://console.example", "https://" + backupHost,
	} {
		c := base()
		c.Environments[0].Backup = "https://" + backupHost
		c.Environments[0].Uploads = bad
		if err := c.Validate(); err == nil {
			t.Errorf("uploads %q accepted", bad)
		}
	}
	masked := good
	masked.Classes = []ClassRule{{Class: route.ClassUploads, Mask: true}}
	if err := masked.Validate(); err == nil {
		t.Error("a masked uploads class was accepted")
	}
}
