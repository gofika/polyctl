package app

import (
	"context"
	"os/exec"
	"syscall"
)

// shellCommand runs command with cmd.exe, passing it as written. Go quotes
// each argument by the C runtime's rules (a quote becomes \"), which cmd.exe
// does not understand, so a hook such as "C:\Program Files\x\notify.exe" -v
// would not start. The command line is set instead: /S makes cmd remove
// only the outer pair of quotes added here.
func shellCommand(ctx context.Context, command string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "cmd")
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: shellCmdLine(command)}
	return cmd
}
