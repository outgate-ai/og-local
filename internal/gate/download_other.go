//go:build !linux

package gate

import "syscall"

func hungUp(syscall.RawConn) bool { return false }

func writableFD(int) bool { return true }

func streamFD(int) bool { return true }
