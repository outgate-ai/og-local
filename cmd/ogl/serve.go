package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/outgate-ai/og-local/internal/detector"
	"github.com/outgate-ai/og-local/internal/gate"
	"github.com/outgate-ai/og-local/internal/gate/alog"
	"github.com/outgate-ai/og-local/internal/gate/corelink"
	"github.com/outgate-ai/og-local/internal/gate/mask"
	"github.com/outgate-ai/og-local/internal/gate/sysprop"
	"github.com/outgate-ai/og-local/internal/models"
	"github.com/outgate-ai/og-local/internal/pii"
)

const serveUsage = `Usage:
  ogl serve [--config FILE] [--data DIR] [--socket NAME | --listen PATH]
            [--model-socket NAME | --model-listen PATH] [--mode passthrough|mask]

Runs the OG OS gate: one JSON request per connection on a unix socket (init's
socket NAME, or PATH), forwarded to Outgate hosts only, recorded in the egress
ledger under DIR/ledger. --mode defaults to persist.outgate.gate.mode, else mask;
passthrough (no masking) is honoured only on debuggable builds.
`

func runServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.Usage = func() { _, _ = os.Stderr.WriteString(serveUsage) }
	config := fs.String("config", "/system_ext/etc/outgate/gate/gate.conf", "gate configuration")
	data := fs.String("data", "/data/misc/outgate/gate", "data directory")
	socket := fs.String("socket", "og_gate", "init socket name")
	listen := fs.String("listen", "", "bind this socket path instead of the init socket")
	modelSocket := fs.String("model-socket", "og_gate_model", "init socket name for the on-device model front")
	modelListen := fs.String("model-listen", "", "bind this socket path for the on-device model front")
	mode := fs.String("mode", "", "passthrough or mask")
	ceDir := fs.String("ce-dir", "/data/misc_ce/0/outgate-gate", "credential-encrypted dir for the placeholder map")
	model := fs.String("model", "openai/privacy-filter-q4", "detector model (og-local catalog name)")
	linkPath := fs.String("link", "/system_ext/bin/og-gate-link", "OG Core binder helper (\"\" for none)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	log := alog.New(slog.LevelInfo)

	cfg, err := gate.LoadConfig(*config)
	if err != nil {
		log.Error("config", "err", err)
		return 1
	}
	cfg.DataDir = *data
	cfg.Version = version
	cfg.Debuggable = sysprop.Bool("ro.debuggable", false)
	gm := gate.Mode(*mode)
	if gm == "" {
		gm = gate.Mode(sysprop.Get("persist.outgate.gate.mode", string(gate.Mask)))
	}
	if gm != gate.Passthrough || !cfg.Debuggable {
		if gm == gate.Passthrough {
			log.Warn("passthrough refused on a non-debuggable build; masking")
		}
		gm = gate.Mask
	}
	cfg.Mode = gm

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	opts := gate.Options{Logger: log}
	var m *mask.Masker
	if cfg.Mode == gate.Mask {
		m = newMasker(*ceDir, *model, log)
		defer m.Detector.Close()
		opts.Masker = m
	}
	var link *corelink.Link
	if *linkPath != "" {
		if _, err := os.Stat(*linkPath); err == nil {
			link = &corelink.Link{Path: *linkPath, Log: log, H: corelink.Handlers{
				Policy: func(rules []corelink.Rule) {
					if m != nil {
						m.SetPolicy(policyFrom(rules))
						log.Info("masking policy from OG Core", "rules", len(rules))
					}
				},
			}}
			opts.Sinks = append(opts.Sinks, link)
			link.Start(ctx)
		} else {
			log.Warn("no OG Core link", "path", *linkPath, "err", err)
		}
	}
	opts.Health = func() map[string]any {
		h := map[string]any{"core": map[string]any{"attached": link != nil && link.Up()}}
		if m != nil {
			h["detector"], h["map"] = m.Detector.Stats(), mapHealth(m)
		}
		return h
	}
	srv, err := gate.New(&cfg, opts)
	if err != nil {
		log.Error("start", "err", err)
		return 1
	}
	ln, err := openListener(*listen, *socket)
	if err != nil {
		log.Error("socket", "err", err)
		return 1
	}
	if link != nil {
		go reportHealth(ctx, link, m)
	}

	errc := make(chan error, 2)
	if mln, err := openListener(*modelListen, *modelSocket); err == nil {
		go func() { errc <- srv.ServeModel(ctx, mln) }()
	} else {
		log.Info("no on-device model front", "err", err)
	}
	log.Info("gate serving", "version", version, "mode", cfg.Mode, "debuggable", cfg.Debuggable)
	go func() { errc <- srv.Serve(ctx, ln) }()
	select {
	case <-ctx.Done():
		<-errc
		return 0
	case err := <-errc:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			log.Error("serve", "err", err)
			return 1
		}
		return 0
	}
}

// newMasker builds the content layer: the placeholder map in credential-encrypted
// storage (30 days) and the detector, loaded on first use and unloaded when idle.
func newMasker(ceDir, model string, log *slog.Logger) *mask.Masker {
	threads := sysprop.Int("persist.outgate.gate.threads", 4)
	idle := time.Duration(sysprop.Int("persist.outgate.gate.detector_idle_seconds", 600)) * time.Second
	load := func() (pii.Detector, func() error, error) {
		start := time.Now()
		d, closeFn, err := detector.New(detector.Config{ModelName: model, LibPath: os.Getenv("OGL_ONNXRUNTIME_LIB"), Threads: threads})
		if err != nil {
			log.Warn("detector unavailable", "model", model, "err", err)
			return nil, nil, err
		}
		log.Info("detector loaded", "model", model, "threads", threads, "ms", time.Since(start).Milliseconds())
		return d, func() error {
			log.Info("detector unloaded (idle)")
			return closeFn()
		}, nil
	}
	det := mask.NewDetector(load, idle)
	det.Present = func() error {
		mdl, ok := models.Lookup(model)
		if !ok {
			return fmt.Errorf("unknown model %s", model)
		}
		if !models.IsCached(models.OSFS(), models.ModelDir(models.CacheRoot(), mdl), mdl) {
			return fmt.Errorf("model not provisioned")
		}
		return nil
	}
	return mask.New(mask.NewStore(ceDir, 30*24*time.Hour, 50000), det)
}

// reportHealth keeps OG Core's gate dot current: red with the reason while content
// can't be masked (decision: the dot and Settings say why chat can't send).
func reportHealth(ctx context.Context, link *corelink.Link, m *mask.Masker) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		connected, detail := true, "passthrough (debug build): content is not masked"
		if m != nil {
			connected, detail = true, "masking"
			if ok, why := m.Ready(); !ok {
				connected, detail = false, healthDetail(why, m)
			}
		}
		link.ReportHealth(connected, detail)
		select {
		case <-ctx.Done():
			link.ReportHealth(false, "gate stopped")
			return
		case <-t.C:
		}
	}
}

func healthDetail(reason string, m *mask.Masker) string {
	switch reason {
	case mask.ErrLocked.Error():
		return "Unlock the phone once: the gate's storage is still locked"
	case mask.ErrDetectorUnavailable.Error():
		if r := m.Detector.Reason(); r != "" {
			return "The gate's detector isn't available (" + r + "), so nothing with content can leave"
		}
		return "The gate's detector isn't available, so nothing with content can leave"
	}
	return reason
}

// policyFrom maps OG Core's rules onto the masker's policy; unknown values keep the defaults.
func policyFrom(rules []corelink.Rule) mask.Policy {
	m := map[mask.Category]mask.Action{}
	for _, r := range rules {
		m[mask.Category(r.Category)] = mask.Action(r.Action)
	}
	return mask.DefaultPolicy().Merge(m)
}

func mapHealth(m *mask.Masker) map[string]any {
	if err := m.Store.Ready(); err != nil {
		return map[string]any{"ready": false, "reason": err.Error()}
	}
	return map[string]any{"ready": true, "entries": m.Store.Len()}
}

func openListener(path, initName string) (net.Listener, error) {
	if path != "" {
		return gate.ListenPath(path, 0o660)
	}
	if initName == "" {
		return nil, fmt.Errorf("no socket")
	}
	return gate.InitSocket(initName)
}
