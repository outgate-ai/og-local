package gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
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
	model   *http.Client
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
}

func New(cfg *Config, opts *Options) (*Server, error) {
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
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
	s := &Server{
		cfg: cfg, log: log, masker: masker, ledger: sinks, ring: ring, started: time.Now(),
		router: &route.Router{
			Envs: cfg.Environments, Debuggable: cfg.Debuggable, ModelSocket: cfg.ModelSocket,
			AllowHTTP: cfg.AllowHTTP,
			Regions:   route.NewRegions(cfg.DataDir+"/state/regions.json", cfg.regionTTL()),
			Tenancies: route.NewTenancies(cfg.DataDir + "/appq"),
		},
		client:   &http.Client{Transport: tr, CheckRedirect: noRedirects},
		model:    &http.Client{Transport: unixTransport(cfg.ModelSocket), CheckRedirect: noRedirects},
		health:   map[string]any{},
		healthFn: opts.Health,
		asks:     newAsks(opts.Approver),
		packages: &peer.Packages{Path: cfg.PackagesList},
	}
	if s.packages.Path == "" {
		s.packages.Path = peer.DefaultPackagesList
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
		s.log.Warn("caller refused", "uid", cred.UID, "domain", cred.Domain())
		resp = wire.Refuse(req.ID, 403, "caller_not_allowed", "")
	case req.Op == "":
		resp = s.forward(ctx, class, cred, req, fds)
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

func (s *Server) healthResponse(class string) *wire.Response {
	ready, why := s.masker.Ready()
	h := map[string]any{
		"version":  s.cfg.Version,
		"mode":     s.cfg.Mode,
		"uptime_s": int64(time.Since(s.started).Seconds()),
		"content":  map[string]any{"ready": ready, "reason": why},
		"today":    s.ring.Totals(),
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

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
