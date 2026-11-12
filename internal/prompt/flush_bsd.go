//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package prompt

import (
	"os"

	"golang.org/x/sys/unix"
)

// discardInput drops what was typed on the terminal f and not read yet
// (tcflush with TCIFLUSH). It does nothing when f is not a terminal.
func discardInput(f *os.File) {
	const fread = 0x1 // FREAD of <sys/fcntl.h>: the input queue
	_ = unix.IoctlSetPointerInt(int(f.Fd()), unix.TIOCFLUSH, fread)
}
