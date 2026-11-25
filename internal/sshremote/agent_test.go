package sshremote

import "testing"

// SSH_AUTH_SOCK names the agent; on Windows, without it, the OpenSSH agent
// pipe is tried (an empty value set by a program turns it off).
func TestAgentAddress(t *testing.T) {
	for _, c := range []struct {
		windows, set bool
		env, addr    string
		explicit     bool
	}{
		{false, false, "", "", false},
		{false, true, "", "", false},
		{false, true, "/tmp/agent.sock", "/tmp/agent.sock", true},
		{true, false, "", WindowsAgentPipe, false},
		{true, true, "", "", false},
		{true, true, `\\.\pipe\pageant.me.1234`, `\\.\pipe\pageant.me.1234`, true},
	} {
		addr, explicit := agentAddress(c.windows, c.env, c.set)
		if addr != c.addr || explicit != c.explicit {
			t.Errorf("%+v: %q %v", c, addr, explicit)
		}
	}
}

func TestPipeName(t *testing.T) {
	for in, want := range map[string]string{
		`\\.\pipe\openssh-ssh-agent`: `\\.\pipe\openssh-ssh-agent`,
		`//./pipe/openssh-ssh-agent`: `\\.\pipe\openssh-ssh-agent`,
		`\\.\PIPE\x`:                 `\\.\PIPE\x`,
		`\\.\pipe\`:                  "",
		`/tmp/agent.sock`:            "",
		`C:\Users\me\agent.sock`:     "",
	} {
		got, ok := pipeName(in)
		if got != want || ok != (want != "") {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
}
