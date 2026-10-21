//go:build !linux

package gate

import (
	"context"
	"log/slog"
)

func netChanges(context.Context, *slog.Logger) <-chan struct{} { return nil }
