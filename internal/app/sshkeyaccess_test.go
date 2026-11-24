package app_test

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/sshremote/sshtest"
)

// stranger makes the instance a server where no local key is authorized.
func (r *keyRig) stranger() *sshtest.Server {
	r.t.Helper()
	s := sshtest.New(r.t)
	s.System = r.sys
	r.srv = s
	return s
}

// pushAccess is an Instance Connect-like way in: each push authorizes the
// key on srv (when authorize), and is recorded.
func pushAccess(srv *sshtest.Server, pushed *[]string, authorize bool, err error) app.SSHKeyAccess {
	return app.SSHKeyAccess{Name: "Test Connect", PushKey: func(ctx context.Context, user string, key ssh.PublicKey) error {
		if err != nil {
			return err
		}
		*pushed = append(*pushed, user)
		if authorize {
			srv.Authorize(user, key)
		}
		return nil
	}}
}

// runAccess is a Run Command-like way in that runs commands as root in the
// fake system; ran records the scripts it ran (decoded).
func (r *keyRig) runAccess(ran *[]string) app.SSHKeyAccess {
	return app.SSHKeyAccess{Name: "Test Run Command", RunCommand: func(ctx context.Context, cmd string) ([]byte, []byte, int, error) {
		if ran != nil {
			if m := regexp.MustCompile(`echo ([A-Za-z0-9+/=]+) \|`).FindStringSubmatch(cmd); m != nil {
				prog, _ := base64.StdEncoding.DecodeString(m[1])
				*ran = append(*ran, string(prog))
			}
		}
		out, errb, code := r.sys.Run("root", cmd, "")
		return []byte(out), []byte(errb), code, nil
	}}
}

// Without --identity-file only the key pair's private key is offered: a
// local key that is not the key pair's is never tried, even when the
// instance would accept it.
func TestSSHKeyOnlyTheKeyPairKeyIsTried(t *testing.T) {
	r := newKeyRig(t, "ec2-user")
	r.authorized("ec2-user", r.login.line("me")+"\n")
	r.inst.KeyPair = &platform.KeyPair{Name: "ops", PublicKey: newSSHTestKey(t).pub}
	err := r.run("list", "web-1", "--accept-new-host-key")
	if err == nil || !strings.Contains(err.Error(), "the key pair ops of instance web-1 (i-1) has no private key on this machine") ||
		!strings.Contains(err.Error(), "--identity-file") {
		t.Fatalf("no matching key: %v", err)
	}
	if n := len(r.srv.Commands()); n != 0 {
		t.Errorf("logged in although no key matched (%d commands)", n)
	}
	// --identity-file is the user's choice: used whatever the key pair.
	if err := r.run("list", "web-1", "--identity-file", filepath.Join(r.home, ".ssh", "id_ed25519"), "--accept-new-host-key"); err != nil {
		t.Fatal(err)
	}

	// The key pair's key in ~/.ssh/<key pair>.pem is found; the default
	// key, which is another one, is not offered.
	kp := newSSHTestKey(t)
	block, err := ssh.MarshalPrivateKey(kp.priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.home, ".ssh", "ops.pem"), pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	r.inst.KeyPair = &platform.KeyPair{Name: "ops", PublicKey: kp.pub}
	r.srv.Authorize("ec2-user", kp.pub)
	r.inst.LoginUsers = []string{"ec2-user", "admin"}
	if err := r.run("list", "web-1"); err != nil {
		t.Fatal(err)
	}
	if s := r.h.stderr.String(); !strings.Contains(s, "with ~/.ssh/ops.pem") {
		t.Errorf("stderr %q", s)
	}
	// A fingerprint matcher (no public key from the platform).
	r.inst.KeyPair = &platform.KeyPair{Name: "ops", Fingerprint: "x"}
	r.inst.KeyPairMatch = platform.KeyMatcher{Match: func(l *platform.PublicKey, k platform.KeyPair) bool {
		return k.Fingerprint == "x" && l.Equal(kp.pub)
	}}
	if err := r.run("list", "web-1"); err != nil {
		t.Fatal(err)
	}
}

// No key pair: no local key is tried, a note says why, and the one-time
// key of the push access logs in, without a question. The one-time key is
// not guarded (it is not in authorized_keys), the last key still is.
func TestSSHKeyNoKeyPairUsesPushAccess(t *testing.T) {
	r := newKeyRig(t, "ec2-user")
	srv := r.stranger()
	srv.Authorize("ec2-user", r.login.pub) // would log in, but is not the key pair's
	r.inst.KeyPairName, r.inst.KeyPair = "", nil
	var pushed []string
	r.inst.TempAccess = []app.SSHKeyAccess{pushAccess(srv, &pushed, true, nil)}
	a := newSSHTestKey(t)
	r.authorized("ec2-user", a.line("only")+"\n")
	r.h.rt.Flags.Yes = true
	err := r.run("remove", "web-1", "--ssh-key", a.line(""), "--accept-new-host-key")
	if err == nil || !strings.Contains(err.Error(), "last key of ec2-user") {
		t.Fatalf("last key: %v", err)
	}
	s := r.h.stderr.String()
	if !strings.Contains(s, "note: instance web-1 (i-1) has no key pair, so no local key is tried (the instance may have been created for someone else); trying Test Connect") ||
		!strings.Contains(s, "with a one-time Test Connect key") {
		t.Errorf("stderr %q", s)
	}
	if len(pushed) != 1 || pushed[0] != "ec2-user" {
		t.Errorf("pushed %v", pushed)
	}
	nk := newSSHTestKey(t)
	if err := r.run("add", "web-1", "--ssh-key", nk.line("n")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.file("ec2-user"), nk.line("n")) || !strings.Contains(r.h.stdout.String(), "(Test Connect)") {
		t.Errorf("file %q out %q", r.file("ec2-user"), r.h.stdout.String())
	}
	// Now a can go: another key is left.
	if err := r.run("remove", "web-1", "--ssh-key", a.line("")); err != nil {
		t.Fatal(err)
	}
}

// A push the image does not use (the login fails) moves on to the run
// command, which edits the file as the user; --dry-run runs the list
// script only, never the apply script.
func TestSSHKeyFallsBackToRunCommand(t *testing.T) {
	r := newKeyRig(t, "ubuntu")
	srv := r.stranger()
	r.inst.LoginUsers = []string{"ec2-user", "ubuntu"}
	r.inst.KeyPair = nil
	r.inst.KeyPairError = "InvalidKeyPair.NotFound"
	var pushed, ran []string
	r.inst.TempAccess = []app.SSHKeyAccess{pushAccess(srv, &pushed, false, nil), r.runAccess(&ran)}
	nk := newSSHTestKey(t)
	r.h.rt.Flags.DryRun = true
	if err := r.run("add", "web-1", "--ssh-key", nk.line("n"), "--accept-new-host-key"); err != nil {
		t.Fatal(err)
	}
	if r.file("ubuntu") != "" || !strings.Contains(r.h.stdout.String(), "would create") {
		t.Fatalf("dry run: file %q out %q", r.file("ubuntu"), r.h.stdout.String())
	}
	for _, p := range ran {
		if strings.Contains(p, "sh -s -- 'apply'") {
			t.Errorf("the dry run ran the apply script:\n%s", p)
		}
	}
	if len(pushed) != 2 {
		t.Errorf("pushed %v", pushed)
	}
	if s := r.h.stderr.String(); !strings.Contains(s, "the key pair ops of instance web-1 (i-1) cannot be read (InvalidKeyPair.NotFound)") ||
		!strings.Contains(s, "trying Test Connect, then Test Run Command") || !strings.Contains(s, "editing the keys of ubuntu on instance web-1 (i-1) through Test Run Command") {
		t.Errorf("stderr %q", s)
	}
	r.h.rt.Flags.DryRun = false
	if err := r.run("add", "web-1", "--ssh-key", nk.line("n"), "--accept-new-host-key"); err != nil {
		t.Fatal(err)
	}
	if r.file("ubuntu") != nk.line("n")+"\n" || !strings.Contains(r.h.stdout.String(), "via Test Run Command (as root)") {
		t.Errorf("file %q out %q", r.file("ubuntu"), r.h.stdout.String())
	}
	// The last key is guarded on this path too.
	r.h.rt.Flags.Yes = true
	if err := r.run("remove", "web-1", "--ssh-key", nk.line("")); err == nil || !strings.Contains(err.Error(), "last key of ubuntu") {
		t.Fatalf("last key: %v", err)
	}
}

// When nothing works the error names each way and why; it is an
// authorization failure only when the platform denied every way in.
func TestSSHKeyAllAccessFails(t *testing.T) {
	r := newKeyRig(t, "ec2-user")
	srv := r.stranger()
	r.inst.KeyPair = &platform.KeyPair{Name: "ops", PublicKey: newSSHTestKey(t).pub}
	denied := fmt.Errorf("%w: SendSSHPublicKey", platform.ErrUnauthorized)
	offline := app.SSHKeyAccess{Name: "Test Run Command", Check: func(context.Context) error { return errors.New("the agent is offline") },
		RunCommand: func(context.Context, string) ([]byte, []byte, int, error) { panic("run although the check failed") }}
	var pushed []string
	r.inst.TempAccess = []app.SSHKeyAccess{pushAccess(srv, &pushed, false, denied), offline}
	err := r.run("list", "web-1", "--accept-new-host-key")
	if err == nil || errors.Is(err, platform.ErrUnauthorized) {
		t.Fatalf("mixed failures: %v", err)
	}
	for _, want := range []string{"has no private key on this machine", "Test Connect: pushing a key for ec2-user", "Test Run Command: the agent is offline", "--identity-file"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	deniedRun := app.SSHKeyAccess{Name: "Test Run Command", RunCommand: func(context.Context, string) ([]byte, []byte, int, error) {
		return nil, nil, 0, fmt.Errorf("%w: ssm:SendCommand", platform.ErrUnauthorized)
	}}
	r.inst.TempAccess = []app.SSHKeyAccess{pushAccess(srv, &pushed, false, denied), deniedRun}
	if err := r.run("list", "web-1"); !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("all denied: %v", err)
	}
}

// The key pair's local key that the instance refuses (removed from
// authorized_keys) leads to the temporary ways in as well.
func TestSSHKeyRefusedKeyPairKeyUsesTempAccess(t *testing.T) {
	r := newKeyRig(t, "ec2-user")
	r.stranger()
	r.inst.TempAccess = []app.SSHKeyAccess{r.runAccess(nil)}
	if err := r.run("list", "web-1", "--accept-new-host-key"); err != nil {
		t.Fatal(err)
	}
	if s := r.h.stderr.String(); !strings.Contains(s, "note: the key pair ops of instance web-1 (i-1) did not log in: could not log in to") ||
		strings.Contains(s, "no local key is tried") || !strings.Contains(s, "through Test Run Command") {
		t.Errorf("stderr %q", s)
	}
}

// The key pair's key with no way to reach the instance and no temporary
// way in: the error says to pass --address, not another key.
func TestSSHKeyUnreachableKeyPairKeyNoTempAccess(t *testing.T) {
	r := newKeyRig(t, "ec2-user")
	r.inst.PublicIP, r.inst.PrivateIP = "", ""
	err := r.run("list", "web-1", "--accept-new-host-key")
	if err == nil || !strings.Contains(err.Error(), "pass --address") || strings.Contains(err.Error(), "--identity-file") {
		t.Fatalf("unreachable: %v", err)
	}
}
