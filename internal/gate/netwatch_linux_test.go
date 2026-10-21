package gate

import (
	"encoding/binary"
	"syscall"
	"testing"
)

func nlmsg(typ uint16, payload []byte) []byte {
	b := make([]byte, syscall.NLMSG_HDRLEN, syscall.NLMSG_HDRLEN+len(payload))
	b = append(b, payload...)
	binary.NativeEndian.PutUint32(b[0:], uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:], typ)
	return b
}

func rtattr(typ uint16, value []byte) []byte {
	b := make([]byte, 4, 4+len(value)+3)
	binary.NativeEndian.PutUint16(b[0:], uint16(4+len(value)))
	binary.NativeEndian.PutUint16(b[2:], typ)
	b = append(b, value...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func linkMsg(typ uint16, index uint32, up bool, oper byte) []byte {
	p := make([]byte, syscall.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(p[4:], index)
	if up {
		binary.NativeEndian.PutUint32(p[8:], syscall.IFF_UP)
	}
	return nlmsg(typ, append(p, rtattr(iflaOperstate, []byte{oper})...))
}

// addrMsg is an IPv6 address on an interface; lifetime stands in for the cache info a router
// advertisement refreshes.
func addrMsg(typ uint16, index uint32, last byte, lifetime uint32) []byte {
	p := make([]byte, syscall.SizeofIfAddrmsg)
	p[0], p[1] = syscall.AF_INET6, 64
	binary.NativeEndian.PutUint32(p[4:], index)
	addr := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last}
	ci := make([]byte, 16)
	binary.NativeEndian.PutUint32(ci[0:], lifetime)
	p = append(p, rtattr(syscall.IFA_ADDRESS, addr)...)
	return nlmsg(typ, append(p, rtattr(syscall.IFA_CACHEINFO, ci)...))
}

func ruleMsg(typ uint16, table byte) []byte {
	return nlmsg(typ, []byte{syscall.AF_INET6, 0, 0, 0, table, 0, 0, 1, 0, 0, 0, 0})
}

func TestNetStateCountsRealChangesOnly(t *testing.T) {
	st := newNetState()
	st.complete = true
	const ifUp, ifDown = 6, 2
	for _, step := range []struct {
		name string
		b    []byte
		want bool
	}{
		{"wlan0 comes up", linkMsg(syscall.RTM_NEWLINK, 3, true, ifUp), true},
		{"wlan0 again, unchanged", linkMsg(syscall.RTM_NEWLINK, 3, true, ifUp), false},
		{"a new rmnet, down", linkMsg(syscall.RTM_NEWLINK, 9, false, ifDown), false},
		{"address added", addrMsg(syscall.RTM_NEWADDR, 3, 1, 1800), true},
		{"router advertisement refreshes it", addrMsg(syscall.RTM_NEWADDR, 3, 1, 1700), false},
		{"and again", addrMsg(syscall.RTM_NEWADDR, 3, 1, 1800), false},
		{"the same address on another interface", addrMsg(syscall.RTM_NEWADDR, 4, 1, 1800), true},
		{"default network rule", ruleMsg(rtmNewRule, 100), true},
		{"the same rule again", ruleMsg(rtmNewRule, 100), false},
		{"rule removed", ruleMsg(rtmDelRule, 100), true},
		{"unknown rule removed", ruleMsg(rtmDelRule, 101), false},
		{"route only", nlmsg(syscall.RTM_NEWROUTE, make([]byte, 12)), false},
		{"route then address removed", append(nlmsg(syscall.RTM_NEWROUTE, make([]byte, 12)), addrMsg(syscall.RTM_DELADDR, 3, 1, 0)...), true},
		{"unknown address removed", addrMsg(syscall.RTM_DELADDR, 3, 2, 0), false},
		{"wlan0 loses carrier", linkMsg(syscall.RTM_NEWLINK, 3, true, ifDown), true},
		{"wlan0 removed", linkMsg(syscall.RTM_DELLINK, 3, true, ifDown), true},
		{"truncated", addrMsg(syscall.RTM_NEWADDR, 5, 1, 1800)[:10], false},
	} {
		if got := st.apply(step.b); got != step.want {
			t.Errorf("%s: change = %v, want %v", step.name, got, step.want)
		}
	}
}

func TestNetStateWithoutLoadCountsUnknownRemovals(t *testing.T) {
	st := newNetState()
	if !st.apply(addrMsg(syscall.RTM_DELADDR, 3, 1, 0)) || !st.apply(ruleMsg(rtmDelRule, 100)) {
		t.Error("removals not counted while the current state is unknown")
	}
}

func TestNetStateLoadsTheCurrentState(t *testing.T) {
	st := newNetState()
	st.load()
	if !st.complete {
		t.Skip("route socket dumps not available here")
	}
	b, err := syscall.NetlinkRIB(syscall.RTM_GETADDR, syscall.AF_UNSPEC)
	if err != nil {
		t.Skip(err)
	}
	if st.apply(b) {
		t.Error("addresses already loaded counted as a change")
	}
}
