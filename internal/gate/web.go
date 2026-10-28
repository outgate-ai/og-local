package gate

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/ledger"
	"github.com/outgate-ai/og-local/internal/gate/route"
	"github.com/outgate-ai/og-local/internal/gate/wire"
)

// callerContainers is OG Core (og_core, ai.outgate.core) for its on-device programs (og-os M40): the
// web class, completions and health on the on-device models, and (the request socket only) op "mask",
// its own screen text to mask before it goes upstream; nothing else.
const callerContainers = "containers"

// egressContainer is the egress kind of an on-device program's web request.
const egressContainer = "container"

const (
	// webAllowMax bounds a request's allow list; webNameMax its container and run ids.
	webAllowMax = 16
	webNameMax  = 160
	webBodyMax  = 64 << 10
	// webResponseMax is how much of a response body a program gets; the rest is cut (truncated).
	webResponseMax    = 512 << 10
	webTimeoutDefault = 30 * time.Second
	webTimeoutMax     = 60 * time.Second
	webUserAgent      = "OG-OS-container/1"
)

// webHeaders are the only caller headers a web request keeps: never authorization or cookies.
var webHeaders = map[string]bool{"Accept": true, "Accept-Language": true, "Content-Type": true}

var webMethods = map[string]bool{http.MethodGet: true, http.MethodHead: true, http.MethodPost: true}

var webLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Resolver looks a host name up once (net.DefaultResolver; tests replace it).
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

func defaultResolve(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// privateNets are never reached by the web class, with the addresses netip classifies itself
// (loopback, private, link-local, multicast, unspecified).
var privateNets = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("ff00::/8"),
}

// nat64 is the well-known NAT64 prefix: its addresses stand for the IPv4 address in their last 32 bits.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// privateAddr reports whether a is an address the web class never reaches, also as an IPv4-mapped
// or NAT64 IPv6 address.
func privateAddr(a netip.Addr) bool {
	a = a.WithZone("")
	if a.Is4In6() {
		a = a.Unmap()
	}
	if a.Is6() && nat64.Contains(a) {
		b := a.As16()
		a = netip.AddrFrom4([4]byte(b[12:]))
	}
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() || a.IsMulticast() {
		return true
	}
	for _, p := range privateNets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// webName: a lowercase DNS name of at least two labels whose last one isn't numeric (no address forms).
func webName(host string) bool {
	if len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 || strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return false
	}
	for _, l := range labels {
		if !webLabel.MatchString(l) {
			return false
		}
	}
	return true
}

// webPattern is an allow list entry: an exact name, or "*." and a name.
func webPattern(p string) bool {
	return webName(strings.TrimPrefix(p, "*."))
}

// hostAllowed: an exact entry matches its host only; "*.<domain>" matches names under it, not the
// domain itself (og-runtime's host_allowed).
func hostAllowed(allow []string, host string) bool {
	for _, a := range allow {
		if base, ok := strings.CutPrefix(a, "*."); ok {
			if len(host) > len(base)+1 && strings.HasSuffix(host, base) && host[len(host)-len(base)-1] == '.' {
				return true
			}
		} else if a == host {
			return true
		}
	}
	return false
}

// containerModel: on-device programs use the voice and agent instances only.
func containerModel(alias string) bool { return alias == DefaultModel || alias == agentModel }

// containerPath: on-device programs send completions and ask health, nothing else of the model service.
func containerPath(method string, d *route.Destination) bool {
	if d.Kind != route.OnDevice {
		return false
	}
	p, _, _ := strings.Cut(d.Path, "?")
	return (method == http.MethodPost && p == "/v1/chat/completions") || (method == http.MethodGet && p == "/health")
}

// webContent is what the masker sees of a web request: the query's values (sorted by key) and the body,
// in one detector call.
type webContent struct {
	Query []string        `json:"query"`
	Body  json.RawMessage `json:"body,omitempty"`
	Text  *string         `json:"text,omitempty"`
}

// web sends an on-device program's request to a host its manifest names (og-os M40). OG Core says
// which hosts (egress.allow); the URL is https on port 443 to a name, never an address. The name is
// resolved once, refused when any answer is a private address, and the connection goes to an address
// that was checked (no rebinding), with the name as SNI and Host. Query values and the body are masked;
// the response is neither masked nor restored, cut at 512 KiB. No redirects, no cookies, no
// authorization. The ledger row has the host, never the path, query or body.
func (s *Server) web(ctx context.Context, req *wire.Request, method string, query url.Values, row *ledger.Row, hold time.Duration,
	refuse func(int, string, string) *wire.Response, refuseAsk func(error, string, string) *wire.Response,
) *wire.Response {
	eg := req.Egress
	if eg.Kind != egressContainer || req.URL == "" {
		return refuse(403, "destination_not_allowed", "on-device programs reach the web and the on-device models only")
	}
	row.Class, row.Kind = route.ClassWeb, "other"
	switch {
	case eg.Container == "" || eg.RunID == "":
		return refuse(400, "bad_request", "a web request names egress.container and egress.run_id")
	case len(eg.Allow) == 0 || len(eg.Allow) > webAllowMax:
		return refuse(400, "bad_request", fmt.Sprintf("egress.allow holds 1 to %d hosts", webAllowMax))
	}
	for _, a := range eg.Allow {
		if !webPattern(a) {
			return refuse(400, "bad_request", "egress.allow: not a lowercase host or *.<domain>")
		}
	}
	u, err := url.Parse(req.URL)
	switch {
	case err != nil || u.Scheme != "https" || u.Opaque != "" || u.Host == "":
		return refuse(400, "bad_url", "web URLs are absolute https URLs")
	case u.User != nil:
		return refuse(400, "bad_url", "web URLs carry no user info")
	case u.Port() != "" && u.Port() != "443":
		return refuse(400, "bad_url", "web URLs use port 443")
	}
	host := strings.ToLower(u.Hostname())
	if _, err := netip.ParseAddr(host); err == nil {
		return refuse(400, "bad_url", "web URLs name a host, not an address")
	}
	if !webName(host) {
		return refuse(400, "bad_url", "web URLs name a DNS host")
	}
	row.Destination = host
	u.Host, u.Fragment, u.RawFragment = host, "", ""
	if !hostAllowed(eg.Allow, host) {
		return refuse(403, "destination_not_allowed", host+" is not one of the program's hosts")
	}
	if !webMethods[method] {
		return refuse(400, "bad_method", "web requests are GET, HEAD and POST only")
	}
	switch {
	case req.BodyFD != "" || req.BodySize != nil || req.ResponseFD != "":
		return refuse(400, "bad_request", "body_fd and response_fd are for backup and uploads destinations")
	case req.File != "" || req.BodyB64 != "":
		return refuse(400, "bad_body", "web bodies are text: body or body_text")
	}
	body, ctype, err := s.requestBody(req, nil)
	if err != nil {
		return refuse(400, "bad_body", err.Error())
	}
	if len(body) > 0 && method != http.MethodPost {
		return refuse(400, "bad_body", "only a POST has a body")
	}
	if len(body) > webBodyMax {
		return refuse(413, "too_large", fmt.Sprintf("web bodies are at most %d bytes", webBodyMax))
	}
	if ct := headerValue(req.Headers, "Content-Type"); len(body) > 0 && req.ContentType == "" && ct != "" {
		ctype = ct
	}
	if len(query) > 0 {
		v := u.Query()
		for k, vals := range query {
			v[k] = append(v[k], vals...)
		}
		u.RawQuery = v.Encode()
	}
	row.Content = len(body) > 0 || u.RawQuery != ""
	row.BytesOutRaw = int64(len(body))

	timeout := webTimeoutDefault
	if req.TimeoutMs > 0 {
		timeout = min(time.Duration(req.TimeoutMs)*time.Millisecond, webTimeoutMax)
	}
	netStart := time.Now()
	rctx, cancel := context.WithTimeout(ctx, timeout)
	addrs, err := s.resolve(rctx, host)
	timedOut := rctx.Err() != nil
	cancel()
	if err == nil && len(addrs) == 0 {
		err = &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true}
	}
	if err != nil {
		return s.webFail(req, row, err, timedOut)
	}
	for _, a := range addrs {
		if privateAddr(a) {
			return refuse(403, "private_address", host+" resolves to a private address")
		}
	}

	sent := body
	if row.Content && s.cfg.Masks(route.ClassWeb) {
		var r *wire.Response
		if sent, r = s.maskWeb(ctx, req, u, body, ctype, row, hold, refuse, refuseAsk); r != nil {
			return r
		}
	}
	row.BytesOut = int64(len(sent))

	cctx, cancel := context.WithTimeout(ctx, max(timeout-time.Since(netStart), time.Millisecond))
	defer cancel()
	var rd io.Reader
	if len(sent) > 0 {
		rd = bytes.NewReader(sent)
	}
	hreq, err := http.NewRequestWithContext(cctx, method, u.String(), rd)
	if err != nil {
		return refuse(400, "bad_url", "url")
	}
	for k, v := range req.Headers {
		ck := textproto.CanonicalMIMEHeaderKey(k)
		if webHeaders[ck] && !strings.ContainsAny(v, "\r\n") {
			hreq.Header.Set(ck, v)
		}
	}
	if len(sent) > 0 {
		hreq.Header.Set("Content-Type", ctype)
	} else {
		hreq.Header.Del("Content-Type")
	}
	hreq.Header.Set("User-Agent", webUserAgent)

	tr := s.webTransport(host, addrs)
	defer tr.CloseIdleConnections()
	hresp, err := (&http.Client{Transport: tr, CheckRedirect: noRedirects}).Do(hreq)
	if err != nil {
		return s.webFail(req, row, err, cctx.Err() != nil)
	}
	defer func() { _ = hresp.Body.Close() }()
	row.Status = hresp.StatusCode
	data, err := io.ReadAll(io.LimitReader(hresp.Body, webResponseMax+1))
	row.BytesIn = int64(len(data))
	if err != nil {
		r := s.webFail(req, row, err, cctx.Err() != nil)
		row.Error = "response_unreadable"
		return r
	}
	truncated := len(data) > webResponseMax
	if truncated {
		data = data[:webResponseMax]
		row.BytesIn = webResponseMax
	}
	out := encodeBody(hresp.Header.Get("Content-Type"), data)
	out.Status = hresp.StatusCode
	out.Headers = pickHeaders(hresp.Header)
	out.Truncated = truncated
	out.Masked = wire.Masked{Count: row.MaskedCount, Categories: row.MaskedCategories, Mask: row.Mask}
	out.Ledger, out.Class = row.ID, row.Class
	return out
}

// maskWeb masks a web request's query values and body in one masker call, and puts the masked
// values back into u. It returns the body to send, or the refusal that keeps the request from leaving.
func (s *Server) maskWeb(ctx context.Context, req *wire.Request, u *url.URL, body []byte, ctype string, row *ledger.Row,
	hold time.Duration, refuse func(int, string, string) *wire.Response, refuseAsk func(error, string, string) *wire.Response,
) ([]byte, *wire.Response) {
	q := u.Query()
	keys := slices.Sorted(maps.Keys(q))
	c := webContent{Query: []string{}}
	for _, k := range keys {
		c.Query = append(c.Query, q[k]...)
	}
	mt, _, _ := mime.ParseMediaType(ctype)
	jsonBody := (mt == "application/json" || strings.HasSuffix(mt, "+json")) && json.Valid(body)
	switch {
	case len(body) == 0:
	case jsonBody:
		c.Body = body
	default:
		t := string(body)
		c.Text = &t
	}
	doc, err := json.Marshal(c)
	if err != nil {
		return nil, refuse(503, "mask_failed", err.Error())
	}
	call := &Call{Caller: callerContainers, Req: req, Kind: row.Kind, Content: true, ContentType: "application/json", Raw: doc}
	sent, r := s.maskContent(ctx, call, row.Destination, doc, row, hold, time.Time{}, refuse, refuseAsk)
	if r != nil {
		return nil, r
	}
	var m webContent
	if err := json.Unmarshal(sent, &m); err != nil || len(m.Query) != len(c.Query) || (m.Body == nil) != (c.Body == nil) ||
		(m.Text == nil) != (c.Text == nil) {
		return nil, refuse(503, "mask_failed", "masked content doesn't match the request")
	}
	if len(keys) > 0 {
		masked, i := url.Values{}, 0
		for _, k := range keys {
			for range q[k] {
				masked.Add(k, m.Query[i])
				i++
			}
		}
		u.RawQuery = masked.Encode()
	}
	switch {
	case m.Body != nil:
		return m.Body, nil
	case m.Text != nil:
		return []byte(*m.Text), nil
	}
	return nil, nil
}

// webTransport connects only to the addresses checked for host, in order, whatever address the
// request names; TLS is verified against host as usual. One connection per request.
func (s *Server) webTransport(host string, addrs []netip.Addr) *http.Transport {
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var last error
			for _, a := range addrs {
				c, err := s.webDial(ctx, "tcp", netip.AddrPortFrom(a, 443).String())
				if err == nil {
					return c, nil
				}
				last = err
			}
			return nil, last
		},
		TLSClientConfig:        &tls.Config{ServerName: host, RootCAs: s.webRoots, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    10 * time.Second,
		ForceAttemptHTTP2:      true,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 64 << 10,
	}
}

// webFail is an upstream failure of a web request (not a refusal): 502, or 504 after its timeout.
func (s *Server) webFail(req *wire.Request, row *ledger.Row, err error, timedOut bool) *wire.Response {
	row.Error, row.Status = errClass(err), 502
	if timedOut {
		row.Error, row.Status = "timeout", 504
	}
	r := wire.Fail(req.ID, row.Status, "upstream_unreachable", row.Error)
	r.Ledger, r.Class, r.Masked.Mask = row.ID, row.Class, row.Mask
	return r
}

func headerValue(h map[string]string, name string) string {
	for k, v := range h {
		if textproto.CanonicalMIMEHeaderKey(k) == name {
			return v
		}
	}
	return ""
}

// validateContainerCallers: OG Core's rule names both its SELinux domain and its package, so no
// other app's uid becomes a containers caller.
func (c *Config) validateContainerCallers() error {
	for _, r := range c.Callers {
		if r.Class == callerContainers && (r.Domain == "" || r.Package == "") {
			return fmt.Errorf("callers: a %q rule needs both domain and package", r.Class)
		}
	}
	return nil
}
