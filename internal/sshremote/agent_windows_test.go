//go:build windows

package sshremote

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/windows"
)

// servePipeAgent serves an agent holding keys on a new named pipe, as the
// Windows OpenSSH agent does, and returns the pipe's name.
func servePipeAgent(t *testing.T, keys ...testKey) string {
	t.Helper()
	kr := agent.NewKeyring()
	for _, k := range keys {
		if err := kr.Add(agent.AddedKey{PrivateKey: k.priv}); err != nil {
			t.Fatal(err)
		}
	}
	name := fmt.Sprintf(`\\.\pipe\polyctl-test-agent-%d-%d`, os.Getpid(), time.Now().UnixNano())
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	listen := func() (windows.Handle, error) {
		return windows.CreateNamedPipe(p, windows.PIPE_ACCESS_DUPLEX,
			windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT,
			windows.PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, nil)
	}
	h, err := listen()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		for {
			if err := windows.ConnectNamedPipe(h, nil); err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
				_ = windows.CloseHandle(h)
				return
			}
			conn := os.NewFile(uintptr(h), name)
			// The next instance before serving this one, so that
			// another client never finds the pipe gone.
			next, err := listen()
			go func() { _ = agent.ServeAgent(kr, conn); _ = conn.Close() }()
			if err != nil {
				return
			}
			select {
			case <-done:
				_ = windows.CloseHandle(next)
				return
			default:
			}
			h = next
		}
	}()
	return name
}

// SSH_AUTH_SOCK naming a named pipe (backslashes or forward slashes)
// reaches the agent behind it.
func TestAgentNamedPipe(t *testing.T) {
	home(t)
	a, b := newKey(t), newKey(t)
	name := servePipeAgent(t, a, b)
	for _, sock := range []string{name, `//./pipe/` + name[len(`\\.\pipe\`):]} {
		t.Setenv(EnvAgent, sock)
		ks, err := within(t, func() (*KeySet, error) { return LoadKeys(KeyOptions{}) })
		if err != nil {
			t.Fatal(err)
		}
		if len(ks.Signers) != 2 || ks.Signers[0].Source != "SSH agent" || len(ks.Notes) != 0 {
			t.Errorf("%s: signers %+v notes %v", sock, ks.Signers, ks.Notes)
		}
		ks.Close()
	}
}

// within runs f and fails the test when it has not returned after 30
// seconds: a pipe operation that waits forever must not cost the whole
// test timeout.
func within[T any](t *testing.T, f func() (T, error)) (T, error) {
	t.Helper()
	type result struct {
		v   T
		err error
	}
	ch := make(chan result, 1)
	go func() {
		v, err := f()
		ch <- result{v, err}
	}()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-time.After(30 * time.Second):
		t.Fatal("no answer after 30s")
		panic("unreachable")
	}
}

// A request is written while a read of the answer is waiting already, as
// the agent client does: on a pipe opened for synchronous I/O the write
// would never start.
func TestAgentPipeWriteDuringRead(t *testing.T) {
	name := servePipeAgent(t, newKey(t))
	conn, err := dialAgent(name)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	type answer struct {
		kind byte
		err  error
	}
	got := make(chan answer, 1)
	go func() {
		var head [5]byte
		if _, err := io.ReadFull(conn, head[:]); err != nil {
			got <- answer{err: err}
			return
		}
		_, err := io.CopyN(io.Discard, conn, int64(binary.BigEndian.Uint32(head[:4]))-1)
		got <- answer{kind: head[4], err: err}
	}()
	// Long enough for the read to be waiting in the system.
	time.Sleep(300 * time.Millisecond)
	// SSH_AGENTC_REQUEST_IDENTITIES (11), answered by
	// SSH_AGENT_IDENTITIES_ANSWER (12).
	if _, err := within(t, func() (int, error) { return conn.Write([]byte{0, 0, 0, 1, 11}) }); err != nil {
		t.Fatal(err)
	}
	select {
	case a := <-got:
		if a.err != nil || a.kind != 12 {
			t.Fatalf("answer type %d, error %v", a.kind, a.err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("no answer after 30s")
	}
}

// Close ends a read that is waiting, and what follows fails.
func TestAgentPipeCloseEndsRead(t *testing.T) {
	name := servePipeAgent(t, newKey(t))
	conn, err := dialAgent(name)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 4))
		got <- err
	}()
	time.Sleep(300 * time.Millisecond)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-got:
		if err == nil {
			t.Error("the read of a closed pipe succeeded")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the read did not end after Close")
	}
	if _, err := conn.Write([]byte{0}); !errors.Is(err, os.ErrClosed) {
		t.Errorf("write after Close: %v", err)
	}
}

// A pipe nobody serves is a file that does not exist: LoadKeys tells the
// missing OpenSSH agent service by it.
func TestAgentPipeMissing(t *testing.T) {
	_, err := dialAgent(fmt.Sprintf(`\\.\pipe\polyctl-test-none-%d`, os.Getpid()))
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error %v", err)
	}
}
