//go:build !windows

package sshremote

import (
	"io"
	"net"
)

// dialAgent connects to the SSH agent socket at addr.
func dialAgent(addr string) (io.ReadWriteCloser, error) {
	return net.Dial("unix", addr)
}
