// Package browser opens URLs in the user's default browser.
package browser

import (
	"fmt"
	"os/exec"
	"runtime"
)

// Open launches the default browser for url.
func Open(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("open browser: %w", err)
	}
	go cmd.Wait() //nolint:errcheck
	return nil
}
