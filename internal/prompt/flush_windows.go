package prompt

import (
	"os"

	"golang.org/x/sys/windows"
)

// discardInput drops what was typed on the console f and not read yet. It
// does nothing when f is not a console.
func discardInput(f *os.File) {
	_ = windows.FlushConsoleInputBuffer(windows.Handle(f.Fd()))
}
