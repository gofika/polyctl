// Package fsutil holds small file system helpers shared by the stores that
// rewrite a file in place.
package fsutil

import (
	"os"
	"time"
)

// Retry bounds how long Rename keeps trying when the target is busy.
var (
	retryFor   = time.Second
	retryFirst = 10 * time.Millisecond
)

// Rename replaces newpath with oldpath like os.Rename. On Windows, replacing
// a file fails with "access denied" or a sharing violation while another
// process has it open without FILE_SHARE_DELETE: another polyctl reading it,
// an antivirus or indexing service. Rename then tries again for about a
// second before giving up.
func Rename(oldpath, newpath string) error {
	return retry(func() error { return os.Rename(oldpath, newpath) }, busy, time.Sleep)
}

// retry runs op until it succeeds, fails with an error transient does not
// accept, or retryFor has been spent waiting, doubling the wait each time.
func retry(op func() error, transient func(error) bool, sleep func(time.Duration)) error {
	wait, spent := retryFirst, time.Duration(0)
	for {
		err := op()
		if err == nil || !transient(err) || spent >= retryFor {
			return err
		}
		sleep(wait)
		spent += wait
		wait *= 2
	}
}
