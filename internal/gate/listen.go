package gate

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
)

// InitSocket adopts the unix socket init created for name (the "socket" option
// of the service, passed as ANDROID_SOCKET_<name>). init binds it; it doesn't listen.
func InitSocket(name string) (net.Listener, error) {
	v := os.Getenv("ANDROID_SOCKET_" + name)
	fd, err := strconv.Atoi(v)
	if err != nil || fd < 0 {
		return nil, fmt.Errorf("gate: no init socket %q", name)
	}
	if err := syscall.Listen(fd, 64); err != nil {
		return nil, fmt.Errorf("gate: listen on init socket %q: %w", name, err)
	}
	syscall.CloseOnExec(fd)
	f := os.NewFile(uintptr(fd), name)
	defer func() { _ = f.Close() }()
	return net.FileListener(f)
}

// ListenPath binds a unix socket at path (debug runs and tests), replacing a stale one.
func ListenPath(path string, mode os.FileMode) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
		_ = os.Remove(path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}
