//go:build windows

package sshremote

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// dialAgent connects to the SSH agent at addr: a named pipe
// (\\.\pipe\openssh-ssh-agent, or the pipe of Pageant or another agent
// given in SSH_AUTH_SOCK), else an AF_UNIX socket.
func dialAgent(addr string) (io.ReadWriteCloser, error) {
	name, ok := pipeName(addr)
	if !ok {
		return net.Dial("unix", addr)
	}
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	for i := 0; ; i++ {
		// Overlapped: the agent client reads the pipe in one goroutine
		// while another writes the request. On a handle opened for
		// synchronous I/O Windows runs one operation at a time, so the
		// write would wait for the read, which waits for the answer to
		// the request that was never written.
		h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
			windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
		if err == nil {
			return &pipeConn{h: h}, nil
		}
		// ERROR_PIPE_BUSY: every instance of the pipe is in use.
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) || i >= 20 {
			return nil, &os.PathError{Op: "open", Path: name, Err: err}
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// pipeConn is a named pipe opened for overlapped I/O: a Read and a Write
// may run at the same time, and Close ends both.
type pipeConn struct {
	h windows.Handle

	mu     sync.Mutex
	closed bool
}

// overlapped runs one I/O operation and waits for its end.
func (c *pipeConn) overlapped(start func(o *windows.Overlapped) error) (int, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return 0, os.ErrClosed
	}
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(ev)
	o := &windows.Overlapped{HEvent: ev}
	if err := start(o); err != nil && !errors.Is(err, windows.ERROR_IO_PENDING) {
		return 0, pipeError(err)
	}
	var n uint32
	if err := windows.GetOverlappedResult(c.h, o, &n, true); err != nil {
		return int(n), pipeError(err)
	}
	return int(n), nil
}

func (c *pipeConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	// The system writes into the buffer after ReadFile returned: one of
	// the heap, which does not move.
	buf := make([]byte, len(b))
	n, err := c.overlapped(func(o *windows.Overlapped) error {
		return windows.ReadFile(c.h, buf, nil, o)
	})
	copy(b, buf[:n])
	return n, err
}

func (c *pipeConn) Write(b []byte) (int, error) {
	buf := append([]byte(nil), b...)
	for done := 0; done < len(buf); {
		n, err := c.overlapped(func(o *windows.Overlapped) error {
			return windows.WriteFile(c.h, buf[done:], nil, o)
		})
		done += n
		if err != nil {
			return done, err
		}
		if n == 0 {
			return done, io.ErrShortWrite
		}
	}
	return len(b), nil
}

// Close ends the operations in flight (they fail with os.ErrClosed) and
// closes the pipe.
func (c *pipeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return os.ErrClosed
	}
	c.closed = true
	_ = windows.CancelIoEx(c.h, nil)
	return windows.CloseHandle(c.h)
}

// pipeError maps the errors of a pipe whose other end is gone, or that was
// closed here, to those a connection reports.
func pipeError(err error) error {
	switch {
	case errors.Is(err, windows.ERROR_BROKEN_PIPE), errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED), errors.Is(err, windows.ERROR_HANDLE_EOF):
		return io.EOF
	case errors.Is(err, windows.ERROR_OPERATION_ABORTED), errors.Is(err, windows.ERROR_INVALID_HANDLE):
		return os.ErrClosed
	}
	return err
}
