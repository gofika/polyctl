package sshremote

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/sshremote/sshtest"
)

// scriptServer is a server running commands in a fake system with the
// given users, where login authenticates with key.
func scriptServer(t *testing.T, key testKey, users ...string) (*sshtest.Server, *sshtest.System) {
	t.Helper()
	home(t)
	sys := sshtest.NewSystem(t, users...)
	old := SSHDConfig
	SSHDConfig = filepath.Join(sys.Dir, "sshd_config")
	t.Cleanup(func() { SSHDConfig = old })
	srv := sshtest.New(t)
	srv.System = sys
	for _, u := range users {
		srv.Authorize(u, key.pub)
	}
	return srv, sys
}

func login(t *testing.T, srv *sshtest.Server, key testKey, user string) *Client {
	t.Helper()
	c, err := Dial(t.Context(), opts(srv, keys(key.signer), acceptAll(), user))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func line(k ssh.PublicKey, comment string) string { return KeyLine(k, comment) }

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// A first key creates ~/.ssh (0700) and authorized_keys (0600); adding it
// again changes nothing, whatever its comment.
func TestAddKeyCreatesFileAndIsIdempotent(t *testing.T) {
	k := newKey(t)
	srv, sys := scriptServer(t, k, "alice")
	c := login(t, srv, k, "alice")
	if c.User != "alice" {
		t.Fatalf("login user %q", c.User)
	}
	nk := newKey(t)
	added, err := c.AddKey(t.Context(), "alice", nk.pub, "me@laptop")
	if err != nil || !added {
		t.Fatalf("add: %v %v", added, err)
	}
	dir := filepath.Join(sys.Home("alice"), ".ssh")
	f := filepath.Join(dir, "authorized_keys")
	data, _ := os.ReadFile(f)
	if string(data) != line(nk.pub, "me@laptop")+"\n" {
		t.Errorf("file:\n%q", data)
	}
	if m := mode(t, dir); m != 0o700 {
		t.Errorf(".ssh mode %o", m)
	}
	if m := mode(t, f); m != 0o600 {
		t.Errorf("authorized_keys mode %o", m)
	}
	added, err = c.AddKey(t.Context(), "alice", nk.pub, "another comment")
	if err != nil || added {
		t.Fatalf("second add: %v %v", added, err)
	}
	if again, _ := os.ReadFile(f); string(again) != string(data) {
		t.Errorf("file changed by an idempotent add:\n%q", again)
	}
	// No chown as a non-root user.
	if _, err := os.Stat(sys.ChownLog); !os.IsNotExist(err) {
		t.Errorf("chown called: %v", err)
	}
	ak, err := c.ListKeys(t.Context(), "alice")
	if err != nil || len(ak.Entries) != 1 || ak.Entries[0].Comment != "me@laptop" || ak.Path != f {
		t.Fatalf("list: %+v %v", ak, err)
	}
}

// Every other line is kept byte for byte (options, comments, blank lines,
// a CRLF line, a malformed line), the mode of the file is kept, and a
// key under options counts as present.
func TestEditKeepsOtherLines(t *testing.T) {
	k := newKey(t)
	srv, sys := scriptServer(t, k, "alice")
	c := login(t, srv, k, "alice")
	a, b, opt := newKey(t), newKey(t), newKey(t)
	dir := filepath.Join(sys.Home("alice"), ".ssh")
	_ = os.MkdirAll(dir, 0o700)
	f := filepath.Join(dir, "authorized_keys")
	orig := "# managed by hand\n" +
		line(a.pub, "a@host") + "\n" +
		"\n" +
		`command="echo 'hi there'",no-pty,from="10.0.0.0/8" ` + line(opt.pub, "restricted") + "\n" +
		line(k.pub, "login key") + "\r\n" +
		"this is not a key\n" +
		line(b.pub, "b@host") // no final newline
	if err := os.WriteFile(f, []byte(orig), 0o640); err != nil {
		t.Fatal(err)
	}
	ak, err := c.ListKeys(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(ak.Entries) != 4 || ak.Entries[1].Line != 4 || len(ak.Entries[1].Options) != 3 || ak.Entries[2].Comment != "login key" {
		t.Fatalf("entries %+v", ak.Entries)
	}
	if added, err := c.AddKey(t.Context(), "alice", opt.pub, ""); err != nil || added {
		t.Fatalf("key under options added again: %v %v", added, err)
	}
	n, err := c.RemoveKeys(t.Context(), "alice", []ssh.PublicKey{a.pub}, nil)
	if err != nil || n != 1 {
		t.Fatalf("remove: %d %v", n, err)
	}
	want := strings.Replace(orig, line(a.pub, "a@host")+"\n", "", 1) + "\n"
	data, _ := os.ReadFile(f)
	if string(data) != want {
		t.Errorf("after remove:\n%q\nwant\n%q", data, want)
	}
	if m := mode(t, f); m != 0o640 {
		t.Errorf("mode %o, want 640 kept", m)
	}
	nk := newKey(t)
	if added, err := c.AddKey(t.Context(), "alice", nk.pub, "new"); err != nil || !added {
		t.Fatalf("add: %v %v", added, err)
	}
	data, _ = os.ReadFile(f)
	if string(data) != want+line(nk.pub, "new")+"\n" {
		t.Errorf("after add:\n%q", data)
	}
	// Removing a key that is not there writes nothing.
	if n, err := c.RemoveKeys(t.Context(), "alice", []ssh.PublicKey{a.pub}, nil); err != nil || n != 0 {
		t.Fatalf("remove absent: %d %v", n, err)
	}
	// No temporary file is left behind.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf(".ssh holds %v", entries)
	}
}

// A guard sees the file and may refuse the removal; nothing is written.
func TestRemoveGuard(t *testing.T) {
	k := newKey(t)
	srv, sys := scriptServer(t, k, "alice")
	c := login(t, srv, k, "alice")
	if _, err := c.AddKey(t.Context(), "alice", k.pub, "only"); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(sys.Home("alice"), ".ssh", "authorized_keys")
	before, _ := os.ReadFile(f)
	refuse := errors.New("refused")
	_, err := c.RemoveKeys(t.Context(), "alice", []ssh.PublicKey{k.pub}, func(ak *AuthorizedKeys, del []Entry) error {
		if len(ak.Entries) != 1 || len(del) != 1 {
			t.Errorf("guard saw %d entries, %d to delete", len(ak.Entries), len(del))
		}
		return refuse
	})
	if !errors.Is(err, refuse) {
		t.Fatalf("guard: %v", err)
	}
	if after, _ := os.ReadFile(f); string(after) != string(before) {
		t.Error("file changed although the guard refused")
	}
}

// Another user's keys are edited through sudo -n -u <user>, so the script
// runs as that user and no chown is needed. A sudo that wants a password,
// or that refuses for another reason, is explained.
func TestOtherUserThroughSudo(t *testing.T) {
	k := newKey(t)
	srv, sys := scriptServer(t, k, "ec2-user", "deploy")
	c := login(t, srv, k, "ec2-user")
	if !c.NeedsSudo("deploy") || c.NeedsSudo("ec2-user") {
		t.Fatal("NeedsSudo")
	}
	nk := newKey(t)
	if added, err := c.AddKey(t.Context(), "deploy", nk.pub, "ci"); err != nil || !added {
		t.Fatalf("add for deploy: %v %v", added, err)
	}
	data, _ := os.ReadFile(filepath.Join(sys.Home("deploy"), ".ssh", "authorized_keys"))
	if string(data) != line(nk.pub, "ci")+"\n" {
		t.Errorf("deploy's file %q", data)
	}
	if _, err := os.Stat(sys.ChownLog); !os.IsNotExist(err) {
		t.Errorf("chown called: %v", err)
	}
	var sawSudo bool
	for _, cmd := range srv.Commands() {
		if strings.HasPrefix(cmd.Cmd, "sudo -n -u 'deploy' sh -s -- ") {
			sawSudo = true
		}
	}
	if !sawSudo {
		t.Error("no sudo -n -u deploy command")
	}

	sys.SudoPassword = true
	_, err := c.AddKey(t.Context(), "deploy", newKey(t).pub, "")
	if err == nil || !strings.Contains(err.Error(), "sudo -n") || !strings.Contains(err.Error(), "--login-user deploy") {
		t.Fatalf("sudo with a password: %v", err)
	}
	sys.SudoPassword = false

	if _, err := c.ListKeys(t.Context(), "nosuch"); !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "no user nosuch") {
		t.Fatalf("unknown user: %v", err)
	}
}

// root edits another user's keys through sudo -u as well: the script never
// writes the files of another user as root.
func TestRootUsesSudoForOtherUsers(t *testing.T) {
	k := newKey(t)
	srv, sys := scriptServer(t, k, "root", "ecs-user")
	c := login(t, srv, k, "root")
	if !c.NeedsSudo("ecs-user") || c.NeedsSudo("root") {
		t.Error("NeedsSudo")
	}
	if _, err := c.AddKey(t.Context(), "ecs-user", newKey(t).pub, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddKey(t.Context(), "root", newKey(t).pub, ""); err != nil {
		t.Fatal(err)
	}
	var viaSudo, direct int
	for _, cmd := range srv.Commands() {
		switch {
		case strings.HasPrefix(cmd.Cmd, "sudo -n -u 'ecs-user' sh -s -- "):
			viaSudo++
		case strings.HasPrefix(cmd.Cmd, "sh -s -- "):
			direct++
		}
	}
	if viaSudo == 0 || direct == 0 {
		t.Errorf("commands: %d through sudo -u ecs-user, %d direct", viaSudo, direct)
	}
	if _, err := os.Stat(sys.ChownLog); !os.IsNotExist(err) {
		t.Errorf("chown called: %v", err)
	}
}

// The script refuses to run as another user than the target (a sudo that
// did not switch users).
func TestScriptRunsAsTargetUser(t *testing.T) {
	k := newKey(t)
	srv, _ := scriptServer(t, k, "alice", "bob")
	c := login(t, srv, k, "alice")
	c.User = "bob" // pretend bob logged in, so no sudo is used
	_, err := c.ListKeys(t.Context(), "bob")
	if err == nil || !strings.Contains(err.Error(), "runs as alice, not as bob") {
		t.Fatalf("list as the wrong user: %v", err)
	}
}

// A symbolic link is never replaced; a custom AuthorizedKeysFile is
// reported by the listing.
func TestSymlinkAndCustomFile(t *testing.T) {
	k := newKey(t)
	srv, sys := scriptServer(t, k, "alice")
	c := login(t, srv, k, "alice")
	if err := os.WriteFile(SSHDConfig, []byte("# AuthorizedKeysFile .ssh/authorized_keys\nAuthorizedKeysFile /etc/ssh/keys/%u\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(sys.Home("alice"), ".ssh")
	_ = os.MkdirAll(dir, 0o700)
	target := filepath.Join(sys.Dir, "real_keys")
	_ = os.WriteFile(target, []byte(line(k.pub, "x")+"\n"), 0o600)
	if err := os.Symlink(target, filepath.Join(dir, "authorized_keys")); err != nil {
		t.Skip("no symlinks:", err)
	}
	ak, err := c.ListKeys(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !ak.Symlink || ak.AuthorizedKeysFile != "/etc/ssh/keys/%u" || !ak.CustomFile() {
		t.Errorf("listing %+v", ak)
	}
	if _, err := c.AddKey(t.Context(), "alice", newKey(t).pub, ""); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("add through a symlink: %v", err)
	}
	if fi, _ := os.Lstat(filepath.Join(dir, "authorized_keys")); fi.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink was replaced")
	}
}

// A file changed between the read and the write is read again.
func TestChangedFileIsReadAgain(t *testing.T) {
	k := newKey(t)
	srv, sys := scriptServer(t, k, "alice")
	c := login(t, srv, k, "alice")
	f := filepath.Join(sys.Home("alice"), ".ssh", "authorized_keys")
	if _, err := c.AddKey(t.Context(), "alice", k.pub, "a"); err != nil {
		t.Fatal(err)
	}
	ak, err := c.ListKeys(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	// Someone else appends a line after the read.
	other := newKey(t)
	fh, _ := os.OpenFile(f, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = fh.WriteString(line(other.pub, "other") + "\n")
	_ = fh.Close()
	if err := apply(t.Context(), c, ak, nil, line(newKey(t).pub, "late")); !errors.Is(err, ErrChanged) {
		t.Fatalf("stale write: %v", err)
	}
	data, _ := os.ReadFile(f)
	if strings.Contains(string(data), "late") || !strings.Contains(string(data), "other") {
		t.Errorf("file after a refused stale write:\n%s", data)
	}
}

// The script is POSIX sh: it behaves the same under the shells an image
// may have as sh (dash on Debian and Ubuntu, bash elsewhere, ksh, zsh in sh
// emulation), each one tried when it is installed.
func TestScriptUnderEveryShell(t *testing.T) {
	for _, shell := range []string{"/bin/dash", "/bin/bash", "/bin/ksh", "/bin/zsh", "/usr/bin/dash"} {
		if _, err := os.Stat(shell); err != nil {
			continue
		}
		t.Run(filepath.Base(filepath.Dir(shell))+"_"+filepath.Base(shell), func(t *testing.T) {
			k := newKey(t)
			srv, sys := scriptServer(t, k, "alice", "bob")
			sys.Shell = shell
			c := login(t, srv, k, "alice")
			dir := filepath.Join(sys.Home("alice"), ".ssh")
			_ = os.MkdirAll(dir, 0o700)
			f := filepath.Join(dir, "authorized_keys")
			a := newKey(t)
			orig := `command="echo 'x'" ` + line(a.pub, "a") + "\r\n# note\n" + line(k.pub, "k")
			_ = os.WriteFile(f, []byte(orig), 0o644)
			nk := newKey(t)
			if added, err := c.AddKey(t.Context(), "alice", nk.pub, "it's new"); err != nil || !added {
				t.Fatalf("add: %v %v", added, err)
			}
			if n, err := c.RemoveKeys(t.Context(), "alice", []ssh.PublicKey{a.pub}, nil); err != nil || n != 1 {
				t.Fatalf("remove: %d %v", n, err)
			}
			data, _ := os.ReadFile(f)
			if want := "# note\n" + line(k.pub, "k") + "\n" + line(nk.pub, "it's new") + "\n"; string(data) != want {
				t.Errorf("file %q, want %q", data, want)
			}
			if m := mode(t, f); m != 0o644 {
				t.Errorf("mode %o", m)
			}
			if _, err := c.AddKey(t.Context(), "bob", nk.pub, ""); err != nil {
				t.Fatalf("add for bob through sudo: %v", err)
			}
		})
	}
}

// The command line is one line of single-quoted words and the script goes
// to its standard input, so a csh login shell (root on older FreeBSD) runs
// it too, with a comment holding a quote and a '!'.
func TestCshLoginShell(t *testing.T) {
	csh := "/bin/tcsh"
	if _, err := os.Stat(csh); err != nil {
		t.Skip("no " + csh)
	}
	k := newKey(t)
	srv, sys := scriptServer(t, k, "alice", "bob")
	c := login(t, srv, k, "alice")
	sys.LoginShell = csh
	nk := newKey(t)
	if added, err := c.AddKey(t.Context(), "alice", nk.pub, "it's me!"); err != nil || !added {
		t.Fatalf("add under csh: %v %v", added, err)
	}
	if added, err := c.AddKey(t.Context(), "bob", nk.pub, "ci"); err != nil || !added {
		t.Fatalf("add for bob through sudo under csh: %v %v", added, err)
	}
	data, _ := os.ReadFile(filepath.Join(sys.Home("alice"), ".ssh", "authorized_keys"))
	if string(data) != line(nk.pub, "it's me!")+"\n" {
		t.Errorf("file %q", data)
	}
}

