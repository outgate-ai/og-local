//go:build !android || !cgo

package alog

import (
	"log/slog"
	"os"
)

const nativeTimestamps = false

func write(_ slog.Level, msg string) {
	_, _ = os.Stderr.WriteString(msg + "\n")
}
