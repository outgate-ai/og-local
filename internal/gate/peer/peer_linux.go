//go:build linux || android

package peer

import (
	"net"
	"strings"
	"syscall"
	"unsafe"
)

// SO_PEERSEC is not exported by package syscall.
const soPeerSec = 31

func of(c *net.UnixConn) (Cred, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Cred{}, err
	}
	var cred Cred
	var opErr error
	err = raw.Control(func(fd uintptr) {
		uc, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			opErr = err
			return
		}
		cred.PID, cred.UID, cred.GID = uc.Pid, uc.Uid, uc.Gid
		cred.Context = peerSec(int(fd))
	})
	if err != nil {
		return Cred{}, err
	}
	return cred, opErr
}

func peerSec(fd int) string {
	var buf [256]byte
	n := uint32(len(buf))
	// getsockopt(SO_PEERSEC) has no wrapper in package syscall.
	//nolint:gosec // buf and n outlive the call
	_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), syscall.SOL_SOCKET, soPeerSec,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)), 0)
	if e != 0 || n == 0 || int(n) > len(buf) {
		return ""
	}
	return strings.TrimRight(string(buf[:n]), "\x00")
}
