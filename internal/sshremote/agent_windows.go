//go:build windows

package sshremote

import (
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"time"
)

// errorPipeBusy is ERROR_PIPE_BUSY: every instance of the pipe is in use.
const errorPipeBusy = syscall.Errno(231)

// dialAgent connects to the SSH agent at addr: a named pipe
// (\\.\pipe\openssh-ssh-agent, or the pipe of Pageant or another agent
// given in SSH_AUTH_SOCK), else an AF_UNIX socket. The agent protocol is a
// request followed by its answer, so a pipe opened as a file serves it.
func dialAgent(addr string) (io.ReadWriteCloser, error) {
	name, ok := pipeName(addr)
	if !ok {
		return net.Dial("unix", addr)
	}
	for i := 0; ; i++ {
		f, err := os.OpenFile(name, os.O_RDWR, 0)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, errorPipeBusy) || i >= 20 {
			return nil, err
		}
		time.Sleep(50 * time.Millisecond)
	}
}
