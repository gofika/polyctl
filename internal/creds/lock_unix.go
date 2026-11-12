//go:build unix && !solaris && !aix

package creds

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive advisory lock on the file at path, creating it
// when needed, and waits while another process holds it. The kernel drops
// the lock when the process ends, so a crash never leaves it behind.
func lockFile(path string) (unlock func(), err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if err != syscall.EINTR {
			break
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
