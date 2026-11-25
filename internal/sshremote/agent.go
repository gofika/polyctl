package sshremote

import (
	"strings"
)

// WindowsAgentPipe is the named pipe of the Windows OpenSSH agent service
// (ssh-agent), which 1Password and others also serve: on Windows it is used
// when SSH_AUTH_SOCK is not set.
const WindowsAgentPipe = `\\.\pipe\openssh-ssh-agent`

// agentAddress is the SSH agent to connect to: SSH_AUTH_SOCK (env, set
// says it is in the environment) when it is not empty (explicit), else on
// Windows the OpenSSH agent pipe, unless SSH_AUTH_SOCK is set to an empty
// value (which Windows shells cannot do: it is how a program, or a test,
// turns the agent off), else none ("").
func agentAddress(windows bool, env string, set bool) (addr string, explicit bool) {
	switch {
	case env != "":
		return env, true
	case windows && !set:
		return WindowsAgentPipe, false
	}
	return "", false
}

// pipeName returns addr as a Windows named pipe path (\\.\pipe\name, also
// written with forward slashes) and whether it is one.
func pipeName(addr string) (string, bool) {
	p := strings.ReplaceAll(addr, "/", `\`)
	if len(p) > len(`\\.\pipe\`) && strings.EqualFold(p[:len(`\\.\pipe\`)], `\\.\pipe\`) {
		return p, true
	}
	return "", false
}
