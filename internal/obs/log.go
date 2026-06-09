package obs

import (
	"io"
	"log/slog"
)

// Discard returns a logger that drops every record. Components take a
// *slog.Logger and default to this when none is injected, so the non-debug path
// carries no output and no formatting cost.
func Discard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Debug returns a logger that writes human-readable records at debug level to w
// (stderr in practice, never stdout — stdout belongs to the agent's stream).
func Debug(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// OrDiscard returns l, or a discard logger when l is nil.
func OrDiscard(l *slog.Logger) *slog.Logger {
	if l == nil {
		return Discard()
	}
	return l
}
