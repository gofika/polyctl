//go:build !windows

package fsutil

// busy reports whether err says the file is open in another process, which
// never stops a rename outside Windows.
func busy(error) bool { return false }
