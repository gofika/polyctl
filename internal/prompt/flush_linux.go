package prompt

import (
	"os"

	"golang.org/x/sys/unix"
)

// discardInput drops what was typed on the terminal f and not read yet
// (tcflush with TCIFLUSH). It does nothing when f is not a terminal.
func discardInput(f *os.File) {
	_ = unix.IoctlSetInt(int(f.Fd()), unix.TCFLSH, unix.TCIFLUSH)
}
