//go:build !linux && !android

package peer

import (
	"errors"
	"net"
)

func of(_ *net.UnixConn) (Cred, error) {
	return Cred{}, errors.New("peer: credentials need linux")
}
