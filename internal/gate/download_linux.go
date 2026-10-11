package gate

import (
	"syscall"
	"unsafe"
)

const (
	pollErr = 0x8
	pollHup = 0x10
)

// hungUp reports whether the caller closed its connection. POLLHUP needs both
// directions shut, so a caller that only shut down its write side after the
// request line keeps its download.
func hungUp(rc syscall.RawConn) bool {
	hup := false
	_ = rc.Control(func(fd uintptr) {
		p := struct {
			fd              int32
			events, revents int16
		}{fd: int32(fd)} //nolint:gosec // descriptors fit int32
		var ts syscall.Timespec
		n, _, e := syscall.Syscall6(syscall.SYS_PPOLL, uintptr(unsafe.Pointer(&p)), 1, uintptr(unsafe.Pointer(&ts)), 0, 0, 0) //nolint:gosec // ppoll takes pointers
		hup = e == 0 && n == 1 && p.revents&(pollHup|pollErr) != 0
	})
	return hup
}

// writableFD reports whether fd is open for writing without O_APPEND.
func writableFD(fd int) bool {
	fl, _, e := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFL, 0) //nolint:gosec // descriptors are non-negative
	if e != 0 {
		return false
	}
	mode := fl & syscall.O_ACCMODE
	return (mode == syscall.O_WRONLY || mode == syscall.O_RDWR) && fl&syscall.O_APPEND == 0
}
