//go:build !windows

package app

import (
	"context"
	"os/exec"
)

// shellCommand runs command with /bin/sh -c.
func shellCommand(ctx context.Context, command string) *exec.Cmd {
	return exec.CommandContext(ctx, "/bin/sh", "-c", command)
}
