package keybroker

import (
	"net"
	"syscall"
	"unsafe"
)

func peerUID(c *net.UnixConn) (uint32, error) {
	r, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred struct {
		Version uint32
		UID     uint32
		NGroups int16
		Pad     int16
		Groups  [16]uint32
	}
	size := uint32(unsafe.Sizeof(cred))
	var inner error
	err = r.Control(func(fd uintptr) {
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, 0, 1,
			uintptr(unsafe.Pointer(&cred)), uintptr(unsafe.Pointer(&size)), 0)
		if errno != 0 {
			inner = errno
		}
	})
	if err != nil {
		return 0, err
	}
	if inner != nil {
		return 0, inner
	}
	if size != uint32(unsafe.Sizeof(cred)) || cred.Version != 0 {
		return 0, syscall.EINVAL
	}
	return cred.UID, nil
}
