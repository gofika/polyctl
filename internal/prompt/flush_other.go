//go:build !linux && !windows && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd

package prompt

import "os"

// discardInput does nothing: this platform has no call polyctl knows to
// drop pending terminal input.
func discardInput(*os.File) {}
