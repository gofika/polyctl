package aliyun

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
	"github.com/gofika/polyctl/internal/sshremote"
	"github.com/gofika/polyctl/internal/sshremote/sshtest"
)

// ecsKeyRig is a running Linux instance web-1 (i-1) whose public IP is an
// in-process SSH server running the key script in a fake system. The
// login key is ~/.ssh/id_ed25519 of a temporary home, authorized for
// loginUsers.
type ecsKeyRig struct {
	t   *testing.T
	h   *harness
	f   *fakeECS
	srv *sshtest.Server
	sys *sshtest.System
	vm  map[string]any
}

func newECSKeyRig(t *testing.T, users []string, loginUsers ...string) *ecsKeyRig {
	t.Helper()
	h, f, _ := computeHarness(t, app.Flags{})
	r := &ecsKeyRig{t: t, h: h, f: f}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv(sshremote.EnvAgent, "")
	oldGlobal, oldConfig := sshremote.GlobalKnownHosts, sshremote.SSHDConfig
	sshremote.GlobalKnownHosts = filepath.Join(home, "none")
	t.Cleanup(func() { sshremote.GlobalKnownHosts, sshremote.SSHDConfig = oldGlobal, oldConfig })
	r.sys = sshtest.NewSystem(t, users...)
	sshremote.SSHDConfig = filepath.Join(r.sys.Dir, "sshd_config")
	r.srv = sshtest.New(t)
	r.srv.System = r.sys
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range loginUsers {
		r.srv.Authorize(u, signer.PublicKey())
	}
	block, err := ssh.MarshalPrivateKey(priv, "login")
	if err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	r.vm = f.addVM("i-1", "web-1", instRunning, "ecs.u1-c1m1.large", "vpc-1", "vsw-b")
	r.vm["OSType"] = "linux"
	r.vm["PublicIpAddress"] = map[string]any{"IpAddress": []string{r.srv.Host}}
	return r
}

// run runs `aliyun ecs instance ssh-key <args>` against the test server.
func (r *ecsKeyRig) run(args ...string) error {
	r.t.Helper()
	return r.h.run(append(append([]string{"ecs", "instance", "ssh-key"}, args...), "--port", strconv.Itoa(r.srv.Port), "--accept-new-host-key")...)
}

func (r *ecsKeyRig) file(user string) string {
	data, _ := os.ReadFile(filepath.Join(r.sys.Home(user), ".ssh", "authorized_keys"))
	return string(data)
}

// loginUsers are the users the server saw log in, in order.
func (r *ecsKeyRig) loginUsers() []string {
	var out []string
	for _, c := range r.srv.Commands() {
		out = append(out, c.User)
	}
	return out
}

func ecsKeyLine(t *testing.T, comment string) (ssh.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k, sshremote.KeyLine(k, comment)
}

// add, list and remove on an instance created to log in as root (the
// default): add is an ensure, remove keeps the user's last key and removes
// the key once another is there.
func TestECSSSHKeyAddListRemove(t *testing.T) {
	r := newECSKeyRig(t, []string{"root", "ecs-user"}, "root")
	k, line := ecsKeyLine(t, "alice@laptop")
	fp := ssh.FingerprintSHA256(k)
	if err := r.run("add", "web-1", "--ssh-key", line); err != nil {
		t.Fatalf("%v\n%s", err, r.h.stderr.String())
	}
	rep := reportOf(t, r.h)
	if len(rep.Changes) != 1 || rep.Changes[0].Resource != "key/root/"+fp || rep.Changes[0].Action != platform.Created {
		t.Fatalf("add = %+v", rep.Changes)
	}
	if rep.Target != (platform.Target{Platform: platform.Aliyun, Profile: "ali", Region: "cn-shanghai"}) {
		t.Errorf("target = %+v", rep.Target)
	}
	if r.file("root") != line+"\n" || r.file("ecs-user") != "" {
		t.Fatalf("root %q, ecs-user %q", r.file("root"), r.file("ecs-user"))
	}
	if u := r.loginUsers(); len(u) == 0 || u[0] != "root" || strings.Contains(strings.Join(u, ","), "ecs-user") {
		t.Errorf("logins = %v", u)
	}
	if err := r.run("add", "web-1", "--ssh-key", line); err != nil {
		t.Fatal(err)
	}
	if c := reportOf(t, r.h).Changes; len(c) != 1 || c[0].Action != platform.Unchanged {
		t.Fatalf("again = %+v", c)
	}

	if err := r.run("list", "web-1"); err != nil {
		t.Fatal(err)
	}
	var rows []app.SSHKeyRow
	r.h.jsonOut(&rows)
	if len(rows) != 1 || rows[0].User != "root" || rows[0].Fingerprint != fp || rows[0].Source != "authorized_keys" {
		t.Fatalf("rows = %+v", rows)
	}

	if err := r.run("remove", "web-1", "--fingerprint", fp); !errors.Is(err, app.ErrUsage) {
		t.Fatalf("without --yes: %v", err)
	}
	r.h.rt.Flags.Yes = true
	if err := r.run("remove", "web-1", "--fingerprint", fp); err == nil || !strings.Contains(err.Error(), "last key") {
		t.Fatalf("last key: %v", err)
	}
	_, other := ecsKeyLine(t, "bob@desk")
	if err := r.run("add", "web-1", "--ssh-key", other); err != nil {
		t.Fatal(err)
	}
	if err := r.run("remove", "web-1", "--fingerprint", fp); err != nil {
		t.Fatal(err)
	}
	if c := reportOf(t, r.h).Changes; len(c) != 1 || c[0].Action != platform.Deleted || r.file("root") != other+"\n" {
		t.Fatalf("remove = %+v, file %q", c, r.file("root"))
	}
}

// An instance created to log in as ecs-user (ImageOptions.LoginAsNonRoot)
// logs in as ecs-user only, never as root; one created for root falls
// back to ecs-user when root does not log in, with a note.
func TestECSSSHKeyLoginUsers(t *testing.T) {
	r := newECSKeyRig(t, []string{"root", "ecs-user"}, "root", "ecs-user")
	r.vm["ImageOptions"] = map[string]any{"LoginAsNonRoot": true}
	_, line := ecsKeyLine(t, "alice@laptop")
	if err := r.run("add", "web-1", "--ssh-key", line); err != nil {
		t.Fatalf("%v\n%s", err, r.h.stderr.String())
	}
	if c := reportOf(t, r.h).Changes; len(c) != 1 || !strings.HasPrefix(c[0].Resource, "key/ecs-user/") {
		t.Fatalf("add = %+v", c)
	}
	if u := r.loginUsers(); strings.Contains(strings.Join(u, ","), "root") {
		t.Errorf("logged in as root: %v", u)
	}
	if r.file("ecs-user") != line+"\n" || r.file("root") != "" {
		t.Errorf("ecs-user %q, root %q", r.file("ecs-user"), r.file("root"))
	}

	// Created for root, but only ecs-user takes the key: root fails, then
	// ecs-user logs in, and a note names it.
	r2 := newECSKeyRig(t, []string{"root", "ecs-user"}, "ecs-user")
	if err := r2.run("list", "web-1"); err != nil {
		t.Fatalf("%v\n%s", err, r2.h.stderr.String())
	}
	if errOut := r2.h.stderr.String(); !strings.Contains(errOut, "as ecs-user") || !strings.Contains(errOut, "created to log in as root") {
		t.Errorf("stderr:\n%s", errOut)
	}

	// Neither logs in: the error names both users, and --login-user then
	// tries only the user named.
	r3 := newECSKeyRig(t, []string{"root", "ecs-user", "deploy"}, "deploy")
	err := r3.run("list", "web-1")
	if err == nil || !strings.Contains(err.Error(), "root") || !strings.Contains(err.Error(), "ecs-user") || !strings.Contains(err.Error(), "--login-user") {
		t.Fatalf("none: %v", err)
	}
	if err := r3.run("list", "web-1", "--login-user", "deploy"); err != nil {
		t.Fatalf("--login-user: %v\n%s", err, r3.h.stderr.String())
	}
}

// Windows instances are refused with exit code 7, stopped ones with the
// start command to run; neither logs in.
func TestECSSSHKeyRefusals(t *testing.T) {
	r := newECSKeyRig(t, []string{"root"}, "root")
	r.vm["OSType"] = "windows"
	err := r.run("list", "web-1", "--region", "cn-shanghai")
	if !errors.Is(err, platform.ErrNotSupported) || !strings.Contains(err.Error(), "aliyun ecs instance password i-1") {
		t.Fatalf("windows: %v", err)
	}
	r.vm["OSType"], r.vm["Status"] = "linux", instStopped
	err = r.run("list", "web-1", "--region", "cn-shanghai")
	if err == nil || errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "polyctl aliyun ecs instance start i-1") {
		t.Fatalf("stopped: %v", err)
	}
	if len(r.srv.Commands()) != 0 {
		t.Errorf("logged in: %v", r.srv.Commands())
	}
}

// On a terminal, ssh-key list without <name|id> offers the running Linux
// instances only.
func TestECSSSHKeyPick(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	r := newECSKeyRig(t, []string{"root"}, "root")
	win := r.f.addVM("i-2", "win-1", instRunning, "ecs.u1-c1m1.large", "vpc-1", "vsw-b")
	win["OSType"] = "windows"
	r.f.addVM("i-3", "web-off", instStopped, "ecs.u1-c1m1.large", "vpc-1", "vsw-b")
	p := prompttest.New(t, "i-1")
	r.h.rt.Picker = p
	if err := r.run("list"); err != nil {
		t.Fatalf("%v\n%s", err, r.h.stderr.String())
	}
	p.Done()
	if v := prompttest.Values(p.Find("Instance").Options); v != "i-1" {
		t.Errorf("offered %q, want the running Linux instance only", v)
	}
}
