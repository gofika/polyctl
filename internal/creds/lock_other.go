//go:build !windows && (!unix || solaris || aix)

package creds

import "os"

// lockFile only makes sure the lock file can be opened: this platform has no
// advisory lock polyctl knows how to take, so writers in different processes
// are not serialised here.
func lockFile(path string) (unlock func(), err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	return func() { f.Close() }, nil
}
