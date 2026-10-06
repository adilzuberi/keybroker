package keybroker

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// A per-account health boundary. Same-account processes are deliberately not
// distinct harness principals, and no credential-bearing capability is enabled.
func protectedDirectory(path string) error {
	s, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || !s.IsDir() || s.Mode().Perm() != 0o700 || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("runtime directory is not owner-only")
	}
	return nil
}

func trustedSocket(path string) error {
	if err := protectedDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	s, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || s.Mode()&os.ModeSocket == 0 || s.Mode().Perm() != 0o600 || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("socket identity rejected")
	}
	return nil
}

func trustedPeer(conn net.Conn) bool {
	c, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	uid, err := peerUID(c)
	return err == nil && int(uid) == os.Geteuid()
}

func openAudit(path string, create bool) (*os.File, error) {
	if err := protectedDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	flags := os.O_WRONLY | os.O_APPEND | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if create {
		flags |= os.O_CREATE
	}
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return nil, err
	}
	s, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || !s.Mode().IsRegular() || s.Mode().Perm() != 0o600 || int(st.Uid) != os.Geteuid() || st.Nlink != 1 {
		f.Close()
		return nil, fmt.Errorf("audit identity rejected")
	}
	return f, nil
}
