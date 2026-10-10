package wire

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"syscall"
)

// MaxFDs is how many descriptors one request may pass (SCM_RIGHTS).
const MaxFDs = 4

// ReadRequestFDs reads one request line from c together with any file descriptors
// passed alongside it. A request refers to the n-th one as File "fd:<n>". The
// caller owns the returned descriptors and closes them.
func ReadRequestFDs(c *net.UnixConn) (*Request, []int, error) {
	var line []byte
	var fds []int
	buf := make([]byte, 64<<10)
	oob := make([]byte, syscall.CmsgSpace(MaxFDs*4))
	closeAll := func() {
		for _, fd := range fds {
			_ = syscall.Close(fd)
		}
	}
	for {
		n, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
		if oobn > 0 {
			got, perr := parseRights(oob[:oobn])
			fds = append(fds, got...)
			if perr != nil || len(fds) > MaxFDs {
				closeAll()
				return nil, nil, fmt.Errorf("wire: bad descriptors")
			}
		}
		line = append(line, buf[:n]...)
		if len(line) > MaxLine {
			closeAll()
			return nil, nil, ErrTooLong
		}
		if i := bytes.IndexByte(line, '\n'); i >= 0 {
			line = line[:i]
			break
		}
		if err != nil || n == 0 {
			if len(line) > 0 && n == 0 {
				break
			}
			closeAll()
			if err == nil {
				err = fmt.Errorf("wire: connection closed")
			}
			return nil, nil, err
		}
	}
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		closeAll()
		return nil, nil, fmt.Errorf("wire: bad request: %w", err)
	}
	if req.V > Version {
		closeAll()
		return nil, nil, fmt.Errorf("wire: version %d not supported", req.V)
	}
	return &req, fds, nil
}

func parseRights(oob []byte) ([]int, error) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	var fds []int
	for i := range msgs {
		got, err := syscall.ParseUnixRights(&msgs[i])
		if err != nil {
			continue
		}
		fds = append(fds, got...)
	}
	return fds, nil
}
