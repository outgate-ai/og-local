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
	fl, ok := fdFlags(fd)
	return ok && openForWrite(fl) && fl&syscall.O_APPEND == 0
}

// streamFD reports whether fd is open for writing (a pipe, or a file appended to).
func streamFD(fd int) bool {
	fl, ok := fdFlags(fd)
	return ok && openForWrite(fl)
}

func fdFlags(fd int) (uintptr, bool) {
	fl, _, e := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFL, 0) //nolint:gosec // descriptors are non-negative
	return fl, e == 0
}

func openForWrite(fl uintptr) bool {
	mode := fl & syscall.O_ACCMODE
	return mode == syscall.O_WRONLY || mode == syscall.O_RDWR
}
