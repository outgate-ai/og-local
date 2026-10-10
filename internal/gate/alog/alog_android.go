//go:build android && cgo

package alog

/*
#cgo LDFLAGS: -llog
#include <stdlib.h>
#include <android/log.h>
*/
import "C"

import (
	"log/slog"
	"unsafe"
)

const nativeTimestamps = true

var tag = C.CString("og-gate")

func write(level slog.Level, msg string) {
	prio := C.int(C.ANDROID_LOG_INFO)
	switch {
	case level >= slog.LevelError:
		prio = C.ANDROID_LOG_ERROR
	case level >= slog.LevelWarn:
		prio = C.ANDROID_LOG_WARN
	case level < slog.LevelInfo:
		prio = C.ANDROID_LOG_DEBUG
	}
	cmsg := C.CString(msg)
	defer C.free(unsafe.Pointer(cmsg))
	C.__android_log_write(prio, tag, cmsg)
}
