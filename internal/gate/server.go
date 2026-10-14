package gate

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/outgate-ai/og-local/internal/gate/corelink"
	"github.com/outgate-ai/og-local/internal/gate/ledger"
	"github.com/outgate-ai/og-local/internal/gate/peer"
	"github.com/outgate-ai/og-local/internal/gate/route"
	"github.com/outgate-ai/og-local/internal/gate/wire"
)

// Server serves the og_gate socket.
type Server struct {
	cfg     *Config
	log     *slog.Logger
	router  *route.Router
	client  *http.Client
	models  map[string]*modelInstance
	masker  Masker
	ledger  ledger.Sink
	ring    *ledger.Ring
	started time.Time
	seq     atomic.Uint64
	wg      sync.WaitGroup

	mu       sync.Mutex
	health   map[string]any
	healthFn func() map[string]any
	asks     *asks
	packages *peer.Packages
	// downloadIdle is the shortest idle timeout of a download.
	downloadIdle time.Duration
	// hubBase is Hugging Face's origin; hubClient follows its redirects (hubRedirect).
	hubBase   *url.URL
	hubClient *http.Client
}

// Options are the parts tests and the command line replace.
type Options struct {
	Logger *slog.Logger
	Masker Masker
	// Sinks receive every ledger row in addition to the gate's own files.
	Sinks []ledger.Sink
	// Transport overrides the upstream transport (tests).
	Transport http.RoundTripper
	// Health adds live entries to the health op (detector, map, core link).
	Health func() map[string]any
	// Approver raises and follows 08 approvals for "ask" (OG Core, through corelink).
	Approver Approver
	// DownloadIdle is the shortest idle timeout of a download (default 10 s; tests).
	DownloadIdle time.Duration
	// HubBase replaces route.HubOrigin (tests).
	HubBase string
}

func New(cfg *Config, opts *Options) (*Server, error) {
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	files, err := ledger.NewFiles(cfg.DataDir+"/ledger", cfg.ledgerRetention(), func(err error) {
		log.Warn("ledger write failed", "err", err)
	})
	if err != nil {
		return nil, err
	}
	ring := ledger.NewRing(512)
	sinks := append(ledger.Fanout{files, ring}, opts.Sinks...)

	masker := opts.Masker
	if masker == nil {
		if cfg.Mode == Passthrough {
			masker = passthrough{}
		} else {
			masker = unavailable{reason: "no detector in this build"}
		}
	}
	tr := opts.Transport
	if tr == nil {
		tr = upstreamTransport()
	}
	hubBase, err := url.Parse(cmp.Or(opts.HubBase, route.HubOrigin))
	if err != nil {
		return nil, fmt.Errorf("hub base: %w", err)
	}
	s := &Server{
		cfg: cfg, log: log, masker: masker, ledger: sinks, ring: ring, started: time.Now(),
		router: &route.Router{
			Envs: cfg.Environments, Debuggable: cfg.Debuggable, ModelSocket: cfg.Models()[DefaultModel],
			AllowHTTP: cfg.AllowHTTP,
			Regions:   route.NewRegions(cfg.DataDir+"/state/regions.json", cfg.regionTTL()),
			Tenancies: route.NewTenancies(cfg.DataDir + "/appq"),
			Providers: cfg.Providers(),
		},
		client:   &http.Client{Transport: tr, CheckRedirect: noRedirects},
		hubBase:  hubBase,
		models:   newModels(cfg.Models()),
		health:   map[string]any{},
		healthFn: opts.Health,
		asks:     newAsks(opts.Approver),
		packages: &peer.Packages{Path: cfg.PackagesList},

		downloadIdle: opts.DownloadIdle,
	}
	s.hubClient = &http.Client{Transport: tr, CheckRedirect: s.hubRedirect}
	if s.packages.Path == "" {
		s.packages.Path = peer.DefaultPackagesList
	}
	if s.downloadIdle <= 0 {
		s.downloadIdle = downloadIdleMin
	}
	return s, nil
}

// Serve accepts connections until ctx ends, then waits for requests in flight.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				s.wg.Wait()
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		uc, ok := c.(*net.UnixConn)
		if !ok {
			_ = c.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(ctx, uc)
		}()
	}
}

func (s *Server) handle(ctx context.Context, c *net.UnixConn) {
	defer func() { _ = c.Close() }()
	cred, err := peer.Of(c)
	if err != nil {
		s.log.Warn("peer credentials", "err", err)
		return
	}
	class := s.classify(cred)
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	req, fds, err := wire.ReadRequestFDs(c)
	defer closeFDs(fds)
	if err != nil {
		if class != "" {
			_ = wire.WriteResponse(c, wire.Refuse("", 400, "bad_request", err.Error()))
		}
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	var resp *wire.Response
	switch {
	case class == "":
		if err := s.packages.Err(); err != nil {
			s.log.Warn("caller refused", "uid", cred.UID, "domain", cred.Domain(), "packages_list", err)
		} else {
			s.log.Warn("caller refused", "uid", cred.UID, "domain", cred.Domain())
		}
		resp = wire.Refuse(req.ID, 403, "caller_not_allowed", "")
	case class == callerVoice, class == callerTranscribe,
		class == callerModels && req.Op != "download" && req.Op != "health",
		req.Op == "download" && class != callerModels && class != "debug":
		s.log.Warn("op refused for caller", "class", class, "op", req.Op)
		resp = wire.Refuse(req.ID, 403, "caller_not_allowed", "")
	case req.Op == "":
		resp = s.forward(ctx, class, cred, req, fds)
	case req.Op == "download":
		dctx, stop := untilHangup(ctx, c)
		resp = s.download(dctx, class, cred, req, fds)
		stop()
	case req.Op == "health":
		resp = s.healthResponse(class)
	case req.Op == "ledger" && class == "debug":
		resp = jsonResponse(200, s.ring.Last(req.Limit))
	default:
		resp = wire.Refuse(req.ID, 400, "unknown_op", req.Op)
	}
	resp.ID = req.ID
	_ = c.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if err := wire.WriteResponse(c, resp); err != nil {
		s.log.Info("response not delivered", "err", err)
	}
}

func (s *Server) classify(c peer.Cred) string {
	for _, r := range s.cfg.Callers {
		if r.DebuggableOnly && !s.cfg.Debuggable {
			continue
		}
		if r.Domain != "" && c.Domain() != r.Domain {
			continue
		}
		if r.UID != nil && c.UID != *r.UID {
			continue
		}
		if c.UID < r.MinUID {
			continue
		}
		if r.Package != "" && !contains(s.packages.Names(c.UID), r.Package) {
			continue
		}
		return r.Class
	}
	return ""
}

// ApprovalResolved passes OG Core's resolution of an approval the gate raised.
func (s *Server) ApprovalResolved(a *corelink.Approval) {
	s.asks.Resolved(a)
}

// SetHealth publishes a component's state in the health op (detector, core link).
func (s *Server) SetHealth(key string, v any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.health[key] = v
}

// DetectorNotNeeded is the gate's state while no destination needs masking.
const DetectorNotNeeded = "detector not needed (no external providers)"

// MaskingState says whether masked content can leave now. Without a destination
// that needs masking it is ready, and the detector is never probed or loaded.
func (s *Server) MaskingState() (needed, ready bool, reason string) {
	if !s.cfg.MaskingNeeded() {
		return false, true, DetectorNotNeeded
	}
	ready, reason = s.masker.Ready()
	return true, ready, reason
}

func (s *Server) healthResponse(class string) *wire.Response {
	needed, ready, why := s.MaskingState()
	h := map[string]any{
		"version":  s.cfg.Version,
		"mode":     s.cfg.Mode,
		"uptime_s": int64(time.Since(s.started).Seconds()),
		// content: whether content to a masked class can leave now; traffic to Outgate
		// and the on-device model never waits for the detector.
		"content": map[string]any{"ready": ready, "reason": why},
		"masking": map[string]any{
			"needed": needed, "classes": s.cfg.MaskingClasses(), "providers": len(s.cfg.Providers()),
		},
		"today":  s.ring.Totals(),
		"mirror": s.mirrorHealth(),
	}
	s.mu.Lock()
	for k, v := range s.health {
		h[k] = v
	}
	s.mu.Unlock()
	if s.healthFn != nil {
		for k, v := range s.healthFn() {
			h[k] = v
		}
	}
	if s.packageRules() {
		h["packages_list"] = "ok"
		if err := s.packages.Check(); err != nil {
			h["packages_list"] = err.Error()
		}
	}
	if class == "debug" {
		h["regions"] = s.router.Regions.All()
		h["tenancies"] = s.router.Tenancies.Names()
	}
	return jsonResponse(200, h)
}

func (s *Server) nextID() string {
	return fmt.Sprintf("eg_%x_%d", s.started.Unix(), s.seq.Add(1))
}

func jsonResponse(status int, v any) *wire.Response {
	b, err := json.Marshal(v)
	if err != nil {
		return wire.Refuse("", 500, "internal", err.Error())
	}
	return &wire.Response{Status: status, Body: b}
}

func closeFDs(fds []int) {
	for _, fd := range fds {
		_ = syscall.Close(fd)
	}
}

// packageRules reports whether a caller rule needs packages.list.
func (s *Server) packageRules() bool {
	for _, r := range s.cfg.Callers {
		if r.Package != "" {
			return true
		}
	}
	return false
}

// CheckCallers logs, at start, a packages.list the gate can't read while a caller
// rule needs it: every such caller would be refused.
func (s *Server) CheckCallers() error {
	if !s.packageRules() {
		return nil
	}
	if err := s.packages.Check(); err != nil {
		s.log.Error("packages.list unreadable: callers admitted by package will be refused", "err", err)
		return err
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
