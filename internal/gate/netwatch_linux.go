package gate

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
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
	rtmGetRule        = 0x22
	iflaOperstate     = 16
)

// netChanges reports changes of links, addresses and routing rules (Android's netd moves the
// default network with rules) until ctx ends. nil when the kernel's route socket can't be opened.
// Messages that repeat what is already known (router advertisements refreshing an address's
// lifetimes, link updates that leave it up or down as it was) are not changes.
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
	st := newNetState()
	st.load()
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
				st = newNetState()
				st.load()
			case err != nil:
				log.Warn("network changes no longer followed", "err", err)
				return
			case !st.apply(buf[:n]):
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

type linkState struct {
	up   bool
	oper uint8
}

// netState is what the route socket has said: links, addresses (per interface) and rules.
// Without a complete load, removing something it hasn't seen counts as a change.
type netState struct {
	complete bool
	links    map[int32]linkState
	addrs    map[string]bool
	rules    map[string]bool
}

func newNetState() *netState {
	return &netState{links: map[int32]linkState{}, addrs: map[string]bool{}, rules: map[string]bool{}}
}

// load reads the current links, addresses and rules, so the first messages after it compare with them.
func (st *netState) load() {
	st.complete = true
	for _, req := range []int{syscall.RTM_GETLINK, syscall.RTM_GETADDR, rtmGetRule} {
		b, err := syscall.NetlinkRIB(req, syscall.AF_UNSPEC)
		if err != nil {
			st.complete = false
			continue
		}
		st.apply(b)
	}
}

// apply takes in a route socket datagram and reports whether it changed a link's state, the set of
// addresses or the set of rules.
func (st *netState) apply(b []byte) bool {
	msgs, err := syscall.ParseNetlinkMessage(b)
	if err != nil {
		return false
	}
	changed := false
	for i := range msgs {
		m := &msgs[i]
		switch m.Header.Type {
		case syscall.RTM_NEWLINK, syscall.RTM_DELLINK:
			if len(m.Data) < syscall.SizeofIfInfomsg {
				continue
			}
			idx := int32(binary.NativeEndian.Uint32(m.Data[4:8]))
			now := linkState{up: binary.NativeEndian.Uint32(m.Data[8:12])&syscall.IFF_UP != 0}
			if attrs, err := syscall.ParseNetlinkRouteAttr(m); err == nil {
				for _, a := range attrs {
					if a.Attr.Type == iflaOperstate && len(a.Value) > 0 {
						now.oper = a.Value[0]
					}
				}
			}
			was := st.links[idx]
			if m.Header.Type == syscall.RTM_DELLINK {
				delete(st.links, idx)
				now = linkState{}
			} else {
				st.links[idx] = now
			}
			changed = changed || (now != was && (now.up || was.up))
		case syscall.RTM_NEWADDR, syscall.RTM_DELADDR:
			if len(m.Data) < syscall.SizeofIfAddrmsg {
				continue
			}
			attrs, err := syscall.ParseNetlinkRouteAttr(m)
			if err != nil {
				continue
			}
			var addr, local []byte
			for _, a := range attrs {
				switch a.Attr.Type {
				case syscall.IFA_ADDRESS:
					addr = a.Value
				case syscall.IFA_LOCAL:
					local = a.Value
				}
			}
			if local != nil {
				addr = local
			}
			key := fmt.Sprintf("%d/%x/%d", binary.NativeEndian.Uint32(m.Data[4:8]), addr, m.Data[1])
			known := st.addrs[key]
			if m.Header.Type == syscall.RTM_NEWADDR {
				st.addrs[key] = true
				changed = changed || !known
			} else {
				delete(st.addrs, key)
				changed = changed || known || !st.complete
			}
		case rtmNewRule, rtmDelRule:
			key := string(m.Data)
			known := st.rules[key]
			if m.Header.Type == rtmNewRule {
				st.rules[key] = true
				changed = changed || !known
			} else {
				delete(st.rules, key)
				changed = changed || known || !st.complete
			}
		}
	}
	return changed
}
