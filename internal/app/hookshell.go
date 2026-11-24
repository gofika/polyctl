package app

// shellCmdLine is the Windows command line that runs command with cmd.exe:
// /S removes the outer pair of quotes and runs what is inside unchanged,
// whatever quotes it holds.
func shellCmdLine(command string) string {
	return `cmd /S /C "` + command + `"`
}
