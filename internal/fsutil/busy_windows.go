package fsutil

import (
	"errors"

	"golang.org/x/sys/windows"
)

// busy reports whether err says the file is open in another process.
func busy(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}
