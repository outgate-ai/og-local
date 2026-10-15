//go:build linux

package corelink

import (
	"os"
	"strconv"
	"syscall"
)

// closeOnExecAll marks every descriptor from 3 up close-on-exec and returns the ones that weren't
// (their /proc/self/fd targets, for the debug log). Go opens its own descriptors close-on-exec;
// what this catches is inherited, such as the sockets init creates for the gate's service.
func closeOnExecAll() []string {
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return nil
	}
	var leaked []string
	for _, e := range ents {
		fd, err := strconv.Atoi(e.Name())
		if err != nil || fd < 3 {
			continue
		}
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
		if errno != 0 || flags&syscall.FD_CLOEXEC != 0 {
			continue
		}
		target, _ := os.Readlink("/proc/self/fd/" + e.Name())
		syscall.CloseOnExec(fd)
		leaked = append(leaked, e.Name()+"="+target)
	}
	return leaked
}
