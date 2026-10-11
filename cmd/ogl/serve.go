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
	"github.com/outgate-ai/og-local/internal/gate/mask"
	"github.com/outgate-ai/og-local/internal/gate/sysprop"
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
	m := gate.Mode(*mode)
	if m == "" {
		m = gate.Mode(sysprop.Get("persist.outgate.gate.mode", string(gate.Mask)))
	}
	if m != gate.Passthrough || !cfg.Debuggable {
		if m == gate.Passthrough {
			log.Warn("passthrough refused on a non-debuggable build; masking")
		}
		m = gate.Mask
	}
	cfg.Mode = m

	opts := gate.Options{Logger: log}
	if cfg.Mode == gate.Mask {
		m := newMasker(*ceDir, *model, log)
		defer m.Detector.Close()
		opts.Masker = m
		opts.Health = func() map[string]any {
			return map[string]any{"detector": m.Detector.Stats(), "map": mapHealth(m)}
		}
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
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

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
	return mask.New(mask.NewStore(ceDir, 30*24*time.Hour, 50000), mask.NewDetector(load, idle))
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
