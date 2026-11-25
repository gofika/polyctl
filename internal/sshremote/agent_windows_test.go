//go:build windows

package sshremote

import (
	"errors"
	"fmt"
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
		ks, err := LoadKeys(KeyOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(ks.Signers) != 2 || ks.Signers[0].Source != "SSH agent" || len(ks.Notes) != 0 {
			t.Errorf("%s: signers %+v notes %v", sock, ks.Signers, ks.Notes)
		}
		ks.Close()
	}
}
