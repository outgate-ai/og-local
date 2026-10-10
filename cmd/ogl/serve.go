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

	"github.com/outgate-ai/og-local/internal/gate"
	"github.com/outgate-ai/og-local/internal/gate/alog"
	"github.com/outgate-ai/og-local/internal/gate/sysprop"
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

	srv, err := gate.New(&cfg, gate.Options{Logger: log})
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

func openListener(path, initName string) (net.Listener, error) {
	if path != "" {
		return gate.ListenPath(path, 0o660)
	}
	if initName == "" {
		return nil, fmt.Errorf("no socket")
	}
	return gate.InitSocket(initName)
}
