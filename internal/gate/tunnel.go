package gate

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/ledger"
	"github.com/outgate-ai/og-local/internal/gate/peer"
	"github.com/outgate-ai/og-local/internal/gate/route"
	"github.com/outgate-ai/og-local/internal/gate/tunnelconf"
)

const (
	// tunnelRate is how many requests a client key (or, without one, an Access subject) may send a minute.
	tunnelRate = 30
	// tunnelInFlight requests at most are served at once; another waits tunnelBusyWait for a slot.
	tunnelInFlight = 2
	tunnelBusyWait = 5 * time.Second
	tunnelMaxBody  = 1 << 20
	tunnelBodyWait = 30 * time.Second
	// tunnelRefusalCap bounds the refusal rows of requests that never showed valid credentials, per minute.
	tunnelRefusalCap = 60
	tunnelSaltFile   = "tunnel-salt"
)

// tunnelRoutes is everything the tunnel serves, with its one method.
var tunnelRoutes = map[string]string{
	"/health":              http.MethodGet,
	"/v1/models":           http.MethodGet,
	"/v1/chat/completions": http.MethodPost,
}

var serviceTokenName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// tunnelFront serves the Cloudflare tunnel's origin socket (og_gate_tunnel).
type tunnelFront struct {
	s        *Server
	conf     *tunnelconf.Store
	now      func() time.Time
	busyWait time.Duration
	slots    chan struct{}
	certs    accessCerts

	mu      sync.Mutex
	confErr string
	salt    []byte
	buckets map[string]*bucket
	// The refusal cap's window: its start, rows written in it and rows dropped.
	capStart   time.Time
	capWritten int
	capDropped int
	capUID     uint32
}

type bucket struct {
	tokens float64
	last   time.Time
}

func (s *Server) newTunnelFront() *tunnelFront {
	t := &tunnelFront{
		s: s, now: time.Now, busyWait: tunnelBusyWait,
		slots: make(chan struct{}, tunnelInFlight), buckets: map[string]*bucket{},
	}
	t.conf = &tunnelconf.Store{Dir: s.tunnelDir, Now: func() time.Time { return t.now() }}
	return t
}

// ServeTunnel is the tunnel front: the only origin of the Cloudflare tunnel daemon, which
// speaks HTTP/1.1 to it. A request needs a valid Cloudflare Access JWT for the configured
// team and application and (unless the owner turned it off) a client key; it may then use
// GET /health, GET /v1/models and POST /v1/chat/completions of the og-local model only,
// rate- and concurrency-limited. Every request is recorded with direction "in".
func (s *Server) ServeTunnel(ctx context.Context, ln net.Listener) error {
	return s.serveTunnel(ctx, ln, s.newTunnelFront())
}

func (s *Server) serveTunnel(ctx context.Context, ln net.Listener, t *tunnelFront) error {
	srv := &http.Server{
		Handler:           t,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    16 << 10,
		IdleTimeout:       60 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if uc, ok := c.(*net.UnixConn); ok {
				if cred, err := s.peerOf(uc); err == nil {
					return context.WithValue(ctx, credKey{}, cred)
				}
			}
			return ctx
		},
	}
	go func() {
		tick := time.NewTicker(10 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				t.flushSuppressed()
			case <-ctx.Done():
				sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				defer cancel()
				_ = srv.Shutdown(sctx)
				return
			}
		}
	}()
	err := srv.Serve(ln)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func (t *tunnelFront) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s := t.s
	start := time.Now()
	cred, _ := r.Context().Value(credKey{}).(peer.Cred)
	class := s.classify(cred)
	// SELinux lets only cloudflared and, on debuggable builds, su connect.
	if class != callerTunnel && class != "debug" {
		s.log.Warn("tunnel caller refused", "uid", cred.UID, "domain", cred.Domain(), "class", class)
		tunnelError(w, http.StatusForbidden, "caller_not_allowed")
		return
	}
	path := "other"
	if _, ok := tunnelRoutes[r.URL.Path]; ok && r.URL.RawPath == "" {
		path = r.URL.Path
	}
	kind := "other"
	if path == "/v1/chat/completions" {
		kind = "llm"
	}
	row := ledger.Row{
		ID: s.nextID(), Time: start.UTC(), Caller: class, UID: cred.UID, Direction: "in",
		RegionID: "on-device", Destination: "on-device model", Class: route.ClassOnDevice,
		Method: methodClass(r.Method), PathClass: path, Kind: kind, OnDevice: true,
		Mode: string(s.cfg.Mode), Mask: MaskNotRequired,
	}
	// Refusals before a request showed valid credentials are capped (tunnelRefusalCap).
	capped := true
	refuse := func(status int, code string) {
		row.Blocked, row.BlockReason, row.Status = true, code, status
		tunnelError(w, status, code)
	}
	defer func() {
		row.DurationMs = time.Since(start).Milliseconds()
		if row.Blocked && capped && !t.admitRefusal(row.UID) {
			return
		}
		s.ledger.Record(&row)
		s.log.Info("tunnel", "id", row.ID, "caller", row.Caller, "path", row.PathClass, "status", row.Status,
			"subject", row.Subject, "key", row.ClientKey, "out", row.BytesOut, "in", row.BytesIn,
			"blocked", row.Blocked, "reason", row.BlockReason, "err", row.Error, "ms", row.DurationMs)
	}()

	conf, err := t.config()
	if err != nil {
		refuse(http.StatusServiceUnavailable, "tunnel_not_configured")
		return
	}
	claims, err := t.verify(r, conf)
	if err != nil {
		row.Error = "access:" + err.Error()
		refuse(http.StatusForbidden, "access_jwt")
		return
	}
	row.Subject = t.subject(claims)
	keyID, ok := clientKey(r.Header.Values("Authorization"), conf)
	row.ClientKey = keyID
	if !ok && conf.RequireClientKey {
		refuse(http.StatusForbidden, "client_key")
		return
	}
	capped = false
	if !conf.Model {
		refuse(http.StatusServiceUnavailable, "service_off")
		return
	}
	if path == "other" || r.Method != tunnelRoutes[path] {
		refuse(http.StatusNotFound, "not_allowed")
		return
	}
	who := "subject:" + row.Subject
	if keyID != "" {
		who = "key:" + keyID
	}
	if wait, ok := t.allow(who); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
		refuse(http.StatusTooManyRequests, "rate_limited")
		return
	}
	if !t.acquire(r.Context()) {
		refuse(http.StatusServiceUnavailable, "busy")
		return
	}
	defer func() { <-t.slots }()
	var body []byte
	if r.Method == http.MethodPost {
		if r.ContentLength > tunnelMaxBody {
			refuse(http.StatusRequestEntityTooLarge, "body_too_large")
			return
		}
		rc := http.NewResponseController(w)
		_ = rc.SetReadDeadline(time.Now().Add(tunnelBodyWait))
		body, err = io.ReadAll(io.LimitReader(r.Body, tunnelMaxBody+1))
		_ = rc.SetReadDeadline(time.Time{})
		if len(body) > tunnelMaxBody {
			refuse(http.StatusRequestEntityTooLarge, "body_too_large")
			return
		}
		if err != nil {
			row.Status, row.Error = http.StatusBadRequest, "bad_body"
			tunnelError(w, http.StatusBadRequest, "bad_body")
			return
		}
		if t.namesOtherModel(body) {
			refuse(http.StatusForbidden, "not_allowed")
			return
		}
	}
	t.forward(w, r, path, body, &row)
}

// forward sends a fresh request to the og-local instance, with only Content-Type and Accept
// of the caller's headers, and streams the answer back.
func (t *tunnelFront) forward(w http.ResponseWriter, r *http.Request, path string, body []byte, row *ledger.Row) {
	m := t.s.models[DefaultModel]
	if m == nil {
		row.Status, row.Error = http.StatusBadGateway, "model_unreachable"
		tunnelError(w, http.StatusBadGateway, "model_unreachable")
		return
	}
	var rd io.Reader
	if r.Method == http.MethodPost {
		rd = bytes.NewReader(body)
	}
	up, err := http.NewRequestWithContext(r.Context(), r.Method, "http://on-device"+path, rd)
	if err != nil {
		row.Status, row.Error = http.StatusInternalServerError, "internal"
		tunnelError(w, http.StatusInternalServerError, "internal")
		return
	}
	for _, h := range []string{"Content-Type", "Accept"} {
		if v := r.Header.Get(h); v != "" {
			up.Header.Set(h, v)
		}
	}
	resp, err := m.client.Do(up)
	if err != nil {
		row.Status, row.Error = http.StatusBadGateway, "model_unreachable"
		tunnelError(w, http.StatusBadGateway, "model_unreachable")
		return
	}
	defer func() { _ = resp.Body.Close() }()
	row.BytesOut, row.BytesOutRaw, row.Content = int64(len(body)), int64(len(body)), len(body) > 0
	for _, h := range []string{"Content-Type", "Cache-Control"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	row.Status = resp.StatusCode
	rc := http.NewResponseController(w)
	buf := make([]byte, 32<<10)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			wn, werr := w.Write(buf[:n])
			row.BytesIn += int64(wn)
			if werr != nil {
				row.Error = "client_gone"
				return
			}
			_ = rc.Flush()
		}
		if rerr != nil {
			if !errors.Is(rerr, io.EOF) {
				row.Error = "model_stream"
			}
			return
		}
	}
}

// config is the tunnel's configuration; a change of its state is logged once.
func (t *tunnelFront) config() (*tunnelconf.Config, error) {
	c, err := t.conf.Load()
	state := "ok"
	if err != nil {
		state = err.Error()
	}
	t.mu.Lock()
	changed := state != t.confErr
	t.confErr = state
	t.mu.Unlock()
	switch {
	case !changed:
	case err == nil:
		t.s.log.Info("tunnel configured", "team", c.Team, "keys", len(c.Keys), "require_client_key", c.RequireClientKey, "model", c.Model)
	case errors.Is(err, tunnelconf.ErrNotConfigured):
		t.s.log.Info("tunnel not configured")
	default:
		t.s.log.Warn("tunnel configuration invalid", "err", err)
	}
	return c, err
}

func (t *tunnelFront) verify(r *http.Request, c *tunnelconf.Config) (*accessClaims, error) {
	vals := r.Header.Values("Cf-Access-Jwt-Assertion")
	if len(vals) != 1 {
		return nil, errAccessMissing
	}
	return verifyAccessJWT(vals[0], t.now(), c.Team, c.AUD, func(kid string) (*rsa.PublicKey, error) {
		return t.key(r.Context(), c.Team, kid)
	})
}

// subject names who sent a request without storing an address: a service token by its
// name, a user by a keyed hash of the lowercased email (the key, tunnel-salt, stays on the phone).
func (t *tunnelFront) subject(c *accessClaims) string {
	switch {
	case c.CommonName != "" && serviceTokenName.MatchString(c.CommonName):
		return "service_token:" + c.CommonName
	case c.CommonName != "":
		return "service_token:" + t.keyedHash(c.CommonName)
	case c.Email != "":
		return "user:" + t.keyedHash(strings.ToLower(c.Email))
	}
	return "other"
}

func (t *tunnelFront) keyedHash(v string) string {
	salt, err := t.saltBytes()
	if err != nil {
		t.s.log.Warn("tunnel salt", "err", err)
		return "unknown"
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(v))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

// saltBytes is the 32-byte key of subject hashes in <data>/state/tunnel-salt, made on first use.
func (t *tunnelFront) saltBytes() ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.salt != nil {
		return t.salt, nil
	}
	path := filepath.Join(t.s.cfg.DataDir, "state", tunnelSaltFile)
	b, err := os.ReadFile(path) //nolint:gosec // the gate's own state
	if err == nil && len(b) == 32 {
		t.salt = b
		return b, nil
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, salt, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	t.salt = salt
	return salt, nil
}

// clientKey matches "Authorization: Bearer <key>" against the configured keys.
func clientKey(vals []string, c *tunnelconf.Config) (string, bool) {
	const scheme = "Bearer "
	if len(vals) != 1 || len(vals[0]) <= len(scheme) || !strings.EqualFold(vals[0][:len(scheme)], scheme) {
		return "", false
	}
	return c.Match(vals[0][len(scheme):])
}

// namesOtherModel: a body naming another on-device instance (og-local-agent) is refused, not
// quietly answered by og-local.
func (t *tunnelFront) namesOtherModel(body []byte) bool {
	name, err := bodyModel(body)
	if err != nil || name == "" {
		return false
	}
	name = strings.TrimSpace(name)
	for alias := range t.s.models {
		if alias != DefaultModel && strings.EqualFold(name, alias) {
			return true
		}
	}
	return false
}

// allow takes a token from who's bucket (tunnelRate a minute); without one it says how long until the next.
func (t *tunnelFront) allow(who string) (time.Duration, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	b := t.buckets[who]
	if b == nil {
		if len(t.buckets) >= 1024 {
			for k, o := range t.buckets {
				if now.Sub(o.last) > time.Minute {
					delete(t.buckets, k)
				}
			}
		}
		b = &bucket{tokens: tunnelRate, last: now}
		t.buckets[who] = b
	}
	if d := now.Sub(b.last); d > 0 {
		b.tokens = min(tunnelRate, b.tokens+d.Minutes()*tunnelRate)
		b.last = now
	}
	if b.tokens < 1 {
		return time.Duration((1 - b.tokens) / tunnelRate * float64(time.Minute)), false
	}
	b.tokens--
	return 0, true
}

func (t *tunnelFront) acquire(ctx context.Context) bool {
	select {
	case t.slots <- struct{}{}:
		return true
	default:
	}
	timer := time.NewTimer(t.busyWait)
	defer timer.Stop()
	select {
	case t.slots <- struct{}{}:
		return true
	case <-timer.C:
	case <-ctx.Done():
	}
	return false
}

// admitRefusal reports whether a capped refusal row may be written. After a minute in which
// rows were dropped, one row says how many.
func (t *tunnelFront) admitRefusal(uid uint32) bool {
	t.mu.Lock()
	dropped := t.rollCap()
	ok := t.capWritten < tunnelRefusalCap
	if ok {
		t.capWritten++
	} else {
		t.capDropped++
	}
	t.capUID = uid
	t.mu.Unlock()
	if dropped > 0 {
		t.recordSuppressed(dropped, uid)
	}
	return ok
}

// flushSuppressed writes the dropped count of a minute that has ended, with no refusal since.
func (t *tunnelFront) flushSuppressed() {
	t.mu.Lock()
	dropped, uid := 0, t.capUID
	if t.capDropped > 0 {
		dropped = t.rollCap()
	}
	t.mu.Unlock()
	if dropped > 0 {
		t.recordSuppressed(dropped, uid)
	}
}

// rollCap starts a new window once a minute has passed and returns the rows the last one dropped.
func (t *tunnelFront) rollCap() int {
	now := t.now()
	if now.Sub(t.capStart) < time.Minute && !now.Before(t.capStart) {
		return 0
	}
	dropped := t.capDropped
	t.capStart, t.capWritten, t.capDropped = now, 0, 0
	return dropped
}

func (t *tunnelFront) recordSuppressed(n int, uid uint32) {
	s := t.s
	s.ledger.Record(&ledger.Row{
		ID: s.nextID(), Time: time.Now().UTC(), Caller: callerTunnel, UID: uid, Direction: "in",
		RegionID: "on-device", Destination: "on-device model", Class: route.ClassOnDevice, Kind: "other",
		Blocked: true, BlockReason: "suppressed", Error: fmt.Sprintf("suppressed:%d", n), OnDevice: true,
		Mode: string(s.cfg.Mode), Mask: MaskNotRequired,
	})
	s.log.Warn("tunnel refusals not recorded", "count", n)
}

func methodClass(m string) string {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return m
	}
	return "OTHER"
}

func tunnelError(w http.ResponseWriter, status int, code string) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":"`+code+`"}`)
}

// validateTunnelCallers: the tunnel daemon and its launcher share a uid, so their rules name
// both the uid and the SELinux domain that tells them apart.
func (c *Config) validateTunnelCallers() error {
	for _, r := range c.Callers {
		if (r.Class == callerTunnel || r.Class == callerTunnelLauncher) && (r.Domain == "" || r.UID == nil) {
			return fmt.Errorf("callers: a %q rule needs both domain and uid", r.Class)
		}
	}
	return nil
}
