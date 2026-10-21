package gate

import (
	"encoding/binary"
	"syscall"
	"testing"
)

func nlmsg(typ uint16, payload int) []byte {
	b := make([]byte, syscall.NLMSG_HDRLEN+payload)
	binary.NativeEndian.PutUint32(b[0:], uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:], typ)
	return b
}

func TestNetChangeMessages(t *testing.T) {
	for _, tc := range []struct {
		name string
		b    []byte
		want bool
	}{
		{"address removed", nlmsg(syscall.RTM_DELADDR, 8), true},
		{"address added", nlmsg(syscall.RTM_NEWADDR, 8), true},
		{"link", nlmsg(syscall.RTM_NEWLINK, 16), true},
		{"default network rule", nlmsg(rtmNewRule, 12), true},
		{"rule removed", nlmsg(rtmDelRule, 12), true},
		{"route only", nlmsg(syscall.RTM_NEWROUTE, 12), false},
		{"route then address", append(nlmsg(syscall.RTM_NEWROUTE, 12), nlmsg(syscall.RTM_DELADDR, 8)...), true},
		{"truncated", nlmsg(syscall.RTM_DELADDR, 8)[:10], false},
	} {
		if got := netChange(tc.b); got != tc.want {
			t.Errorf("%s: netChange = %v, want %v", tc.name, got, tc.want)
		}
	}
}
