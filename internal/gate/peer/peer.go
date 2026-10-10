// Package peer identifies the process on the other end of a unix socket.
package peer

import "net"

// Cred is the kernel's view of the connecting process.
type Cred struct {
	PID int32
	UID uint32
	GID uint32
	// Context is the peer's SELinux context (SO_PEERSEC), e.g.
	// "u:r:outgate_agent:s0"; empty where SELinux is off.
	Context string
}

// Domain returns the SELinux type of Context ("outgate_agent"), or "".
func (c Cred) Domain() string {
	parts := splitColon(c.Context)
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}

func splitColon(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// Of reads the peer credentials of a unix connection.
func Of(c *net.UnixConn) (Cred, error) {
	return of(c)
}
