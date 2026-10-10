// Package alog is an slog handler that writes to logcat on Android (tag og-gate)
// and to stderr elsewhere.
package alog

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
)

type handler struct {
	level slog.Level
	mu    *sync.Mutex
	buf   *bytes.Buffer
	text  slog.Handler
	write func(level slog.Level, msg string)
}

func New(level slog.Level) *slog.Logger {
	var buf bytes.Buffer
	h := &handler{level: level, mu: &sync.Mutex{}, buf: &buf}
	h.text = slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && (a.Key == slog.TimeKey || a.Key == slog.LevelKey) && nativeTimestamps {
				return slog.Attr{}
			}
			return a
		},
	})
	h.write = write
	return slog.New(h)
}

func (h *handler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }

func (h *handler) Handle(ctx context.Context, r slog.Record) error { //nolint:gocritic // slog.Handler signature
	h.mu.Lock()
	defer h.mu.Unlock()
	h.buf.Reset()
	if err := h.text.Handle(ctx, r); err != nil {
		return err
	}
	h.write(r.Level, string(bytes.TrimRight(h.buf.Bytes(), "\n")))
	return nil
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *h
	c.text = h.text.WithAttrs(attrs)
	return &c
}

func (h *handler) WithGroup(name string) slog.Handler {
	c := *h
	c.text = h.text.WithGroup(name)
	return &c
}
