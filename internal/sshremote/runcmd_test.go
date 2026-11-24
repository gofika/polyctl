package sshremote

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/sshremote/sshtest"
)

// rootEditor runs commands as as in sys, as Run Command runs them as root;
// commands records each command line.
func rootEditor(t *testing.T, sys *sshtest.System, as string, commands *[]string) *RootEditor {
	t.Helper()
	return &RootEditor{Via: "Test Run Command", Run: func(ctx context.Context, cmd string) ([]byte, []byte, int, error) {
		if commands != nil {
			*commands = append(*commands, cmd)
		}
		out, errb, code := sys.Run(as, cmd, "")
		return []byte(out), []byte(errb), code, nil
	}}
}

func rootSystem(t *testing.T, users ...string) *sshtest.System {
	t.Helper()
	home(t)
	sys := sshtest.NewSystem(t, users...)
	old := SSHDConfig
	SSHDConfig = filepath.Join(sys.Dir, "sshd_config")
	t.Cleanup(func() { SSHDConfig = old })
	return sys
}

// Through a command run as root, the key script runs as the target user
// (runuser), every value reaches it intact (a comment with quotes and the
// {{ }} of SSM parameters), and the command line is one base64 word.
func TestRootEditorEditsAsTheUser(t *testing.T) {
	sys := rootSystem(t, "alice")
	var cmds []string
	ed := rootEditor(t, sys, "root", &cmds)
	k := newKey(t)
	comment := `it's {{ ssm:x }} "q" $HOME ; rm -rf /`
	added, err := ed.AddKey(t.Context(), "alice", k.pub, comment)
	if err != nil || !added {
		t.Fatalf("add: %v %v", added, err)
	}
	data, _ := os.ReadFile(filepath.Join(sys.Home("alice"), ".ssh", "authorized_keys"))
	if string(data) != line(k.pub, comment)+"\n" {
		t.Errorf("file %q", data)
	}
	for _, c := range cmds {
		if strings.Contains(c, "alice") || strings.Contains(c, "{{") || strings.Count(c, "\n") > 0 {
			t.Errorf("the command line carries values in clear: %q", c)
		}
	}
	ak, err := ed.ListKeys(t.Context(), "alice")
	if err != nil || len(ak.Entries) != 1 || ak.Entries[0].Comment != comment {
		t.Fatalf("list: %v %+v", err, ak)
	}
	// root's own file is edited directly.
	if _, err := ed.AddKey(t.Context(), "root", k.pub, "r"); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(filepath.Join(sys.Home("root"), ".ssh", "authorized_keys")); string(data) != line(k.pub, "r")+"\n" {
		t.Errorf("root's file %q", data)
	}
	n, err := ed.RemoveKeys(t.Context(), "alice", []ssh.PublicKey{k.pub}, nil)
	if err != nil || n != 1 {
		t.Fatalf("remove: %d %v", n, err)
	}
	if _, err := ed.ListKeys(t.Context(), "bob"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("unknown user: %v", err)
	}
}

// Run as another user than root, runuser refuses, and the error names the
// way the command ran.
func TestRootEditorNotRoot(t *testing.T) {
	sys := rootSystem(t, "alice", "bob")
	ed := rootEditor(t, sys, "bob", nil)
	_, err := ed.ListKeys(t.Context(), "alice")
	if err == nil || !strings.Contains(err.Error(), "Test Run Command") || !strings.Contains(err.Error(), "non-root") {
		t.Fatalf("not root: %v", err)
	}
}

// FirstUser returns the first user that exists, "" when none does, and an
// error when the command does not run as expected.
func TestRootEditorFirstUser(t *testing.T) {
	sys := rootSystem(t, "ubuntu")
	ed := rootEditor(t, sys, "root", nil)
	if u, err := ed.FirstUser(t.Context(), []string{"ec2-user", "ubuntu", "admin"}); err != nil || u != "ubuntu" {
		t.Errorf("first user %q %v", u, err)
	}
	if u, err := ed.FirstUser(t.Context(), []string{"ec2-user"}); err != nil || u != "" {
		t.Errorf("none %q %v", u, err)
	}
	bad := &RootEditor{Via: "X", Run: func(ctx context.Context, cmd string) ([]byte, []byte, int, error) {
		return nil, []byte("agent offline\n"), 1, nil
	}}
	if _, err := bad.FirstUser(t.Context(), []string{"a"}); err == nil || !strings.Contains(err.Error(), "agent offline") {
		t.Errorf("failed check: %v", err)
	}
}
