package gate

import (
	"context"
	"errors"
	"log/slog"
	"syscall"
)

const (
	rtnlgrpLink       = 1
	rtnlgrpIPv4IfAddr = 5
	rtnlgrpIPv6IfAddr = 9
	rtnlgrpIPv4Rule   = 8
	rtnlgrpIPv6Rule   = 19
	rtmNewRule        = 0x20
	rtmDelRule        = 0x21
)

// netChanges reports changes of links, addresses and routing rules (Android's netd moves the
// default network with rules) until ctx ends. nil when the kernel's route socket can't be opened.
func netChanges(ctx context.Context, log *slog.Logger) <-chan struct{} {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		log.Warn("network changes not followed", "err", err)
		return nil
	}
	var groups uint32
	for _, g := range []uint{rtnlgrpLink, rtnlgrpIPv4IfAddr, rtnlgrpIPv6IfAddr, rtnlgrpIPv4Rule, rtnlgrpIPv6Rule} {
		groups |= 1 << (g - 1)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: groups}); err != nil {
		_ = syscall.Close(fd)
		log.Warn("network changes not followed", "err", err)
		return nil
	}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 1})
	out := make(chan struct{}, 1)
	go func() {
		defer func() { _ = syscall.Close(fd) }()
		defer close(out)
		buf := make([]byte, 64<<10)
		for ctx.Err() == nil {
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			switch {
			case errors.Is(err, syscall.EAGAIN), errors.Is(err, syscall.EINTR):
				continue
			case errors.Is(err, syscall.ENOBUFS):
			case err != nil:
				log.Warn("network changes no longer followed", "err", err)
				return
			case !netChange(buf[:n]):
				continue
			}
			select {
			case out <- struct{}{}:
			default:
			}
		}
	}()
	return out
}

// netChange reports whether a route socket datagram announces a link, address or rule change.
func netChange(b []byte) bool {
	msgs, err := syscall.ParseNetlinkMessage(b)
	if err != nil {
		return false
	}
	for _, m := range msgs {
		switch m.Header.Type {
		case syscall.RTM_NEWLINK, syscall.RTM_DELLINK, syscall.RTM_NEWADDR, syscall.RTM_DELADDR, rtmNewRule, rtmDelRule:
			return true
		}
	}
	return false
}
