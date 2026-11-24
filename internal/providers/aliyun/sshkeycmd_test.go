package aliyun

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"regexp"
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
	// login is the public key of ~/.ssh/id_ed25519.
	login ssh.PublicKey
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
	r.login = signer.PublicKey()
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
	// The instance's key pair ops is the login key.
	f.addKeyPair("ops", md5Hex(t, string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), "2026-11-17T13:54Z")
	r.vm = f.addVM("i-1", "web-1", instRunning, "ecs.u1-c1m1.large", "vpc-1", "vsw-b")
	r.vm["KeyPairName"] = "ops"
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

	// Not created for ecs-user, but only ecs-user takes the key: root fails, then
	// ecs-user logs in, and a note names it.
	r2 := newECSKeyRig(t, []string{"root", "ecs-user"}, "ecs-user")
	if err := r2.run("list", "web-1"); err != nil {
		t.Fatalf("%v\n%s", err, r2.h.stderr.String())
	}
	if errOut := r2.h.stderr.String(); !strings.Contains(errOut, "as ecs-user") || !strings.Contains(errOut, "not created to log in as ecs-user") {
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

// useAssistant makes Cloud Assistant of the instance online, running the
// commands as root in the rig's fake system.
func (r *ecsKeyRig) useAssistant() *fakeAssistant {
	a := newFakeAssistant(r.t, r.h.api)
	a.status["i-1"] = "true"
	a.exec = func(id, cmd string) (string, string, int) {
		if id != "i-1" {
			r.t.Errorf("RunCommand on %s", id)
		}
		return r.sys.Run("root", cmd, "")
	}
	return a
}

// ranApply reports whether one of the programs Cloud Assistant ran ran the
// apply script.
func ranApply(t *testing.T, progs []string) bool {
	t.Helper()
	re := regexp.MustCompile(`echo ([A-Za-z0-9+/=]+) \|`)
	for _, p := range progs {
		if m := re.FindStringSubmatch(p); m != nil {
			prog, _ := base64.StdEncoding.DecodeString(m[1])
			if strings.Contains(string(prog), "sh -s -- 'apply'") {
				return true
			}
		}
	}
	return false
}

// A key pair whose private key is not on this machine (the instance may
// have been created for someone else): no local key is tried, and the
// keys are listed and edited through Cloud Assistant, as root running the
// key script as the login user. --dry-run runs the read-only script only;
// the last key stays guarded; a missing key pair and an instance without
// one go the same way.
func TestECSSSHKeyCloudAssistant(t *testing.T) {
	r := newECSKeyRig(t, []string{"root", "ecs-user"}, "root", "ecs-user")
	r.vm["KeyPairName"] = "someone-else"
	r.f.addKeyPair("someone-else", strings.Repeat("ab", 16), "2026-11-17T13:54Z")
	a := r.useAssistant()
	a.hidden, a.running = 1, 2

	k, line := ecsKeyLine(t, "alice@laptop")
	r.h.rt.Flags.DryRun = true
	if err := r.run("add", "web-1", "--ssh-key", line); err != nil {
		t.Fatalf("%v\n%s", err, r.h.stderr.String())
	}
	if r.file("root") != "" || !strings.Contains(r.h.stdout.String(), "would_create") || len(a.runs) == 0 {
		t.Fatalf("dry run: file %q out %q runs %d", r.file("root"), r.h.stdout.String(), len(a.runs))
	}
	if ranApply(t, a.programs) {
		t.Fatal("the dry run ran the apply script")
	}
	r.h.rt.Flags.DryRun = false
	if err := r.run("add", "web-1", "--ssh-key", line); err != nil {
		t.Fatalf("%v\n%s", err, r.h.stderr.String())
	}
	errOut := r.h.stderr.String()
	for _, want := range []string{"the key pair someone-else of instance web-1 (i-1) has no private key on this machine",
		"no local key is tried", "trying Cloud Assistant", "editing the keys of root on instance web-1 (i-1) through Cloud Assistant"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errOut)
		}
	}
	if r.file("root") != line+"\n" || r.file("ecs-user") != "" {
		t.Fatalf("root %q, ecs-user %q", r.file("root"), r.file("ecs-user"))
	}
	if n := len(r.srv.Commands()); n != 0 {
		t.Errorf("logged in over SSH (%d commands)", n)
	}
	// Cloud Assistant takes at most 24 KB of base64 command content.
	for _, q := range a.runs {
		if n := len(q.Get("CommandContent")); n > 24*1024 {
			t.Errorf("CommandContent of %d bytes", n)
		}
	}
	q := a.runs[len(a.runs)-1]
	if q.Get("Timeout") != "60" || q.Get("KeepCommand") != "false" || q.Get("Username") != "" || q.Get("Name") != "polyctl-ssh-key" {
		t.Errorf("RunCommand = %v", q)
	}

	if err := r.run("list", "web-1"); err != nil {
		t.Fatal(err)
	}
	var rows []app.SSHKeyRow
	r.h.jsonOut(&rows)
	if len(rows) != 1 || rows[0].User != "root" || rows[0].Fingerprint != ssh.FingerprintSHA256(k) || rows[0].InUse {
		t.Fatalf("rows = %+v", rows)
	}
	r.h.rt.Flags.Yes = true
	if err := r.run("remove", "web-1", "--ssh-key", line); err == nil || !strings.Contains(err.Error(), "last key of root") {
		t.Fatalf("last key: %v", err)
	}

	// A key pair that cannot be read, and an instance without one.
	r.vm["KeyPairName"] = "gone"
	if err := r.run("list", "web-1"); err != nil {
		t.Fatal(err)
	}
	if s := r.h.stderr.String(); !strings.Contains(s, "the key pair gone of instance web-1 (i-1) cannot be read (no key pair of that name in cn-shanghai)") ||
		!strings.Contains(s, "through Cloud Assistant") {
		t.Errorf("missing key pair:\n%s", s)
	}
	r.vm["KeyPairName"] = ""
	if err := r.run("list", "web-1"); err != nil {
		t.Fatal(err)
	}
	if s := r.h.stderr.String(); !strings.Contains(s, "instance web-1 (i-1) has no key pair") || !strings.Contains(s, "through Cloud Assistant") {
		t.Errorf("no key pair:\n%s", s)
	}
	if n := len(r.srv.Commands()); n != 0 {
		t.Errorf("logged in over SSH (%d commands)", n)
	}
}

// When Cloud Assistant cannot be used the error names the key pair and why
// Cloud Assistant failed, and suggests --identity-file: an agent offline or
// missing (RunCommand is not called), an invocation that does not finish,
// output that may be cut. A RAM denial of RunCommand is an authorization
// failure; a denial of the status check leaves RunCommand to decide.
func TestECSSSHKeyCloudAssistantFailures(t *testing.T) {
	r := newECSKeyRig(t, []string{"root"}, "root")
	r.vm["KeyPairName"] = "someone-else"
	r.f.addKeyPair("someone-else", strings.Repeat("ab", 16), "2026-11-17T13:54Z")
	a := r.useAssistant()

	cases := []struct {
		name  string
		setup func()
		want  string
		run   bool
	}{
		{"offline", func() { a.status["i-1"] = "false" }, "Cloud Assistant: the Cloud Assistant agent of the instance is not online", false},
		{"no agent", func() { delete(a.status, "i-1") }, "Cloud Assistant: the instance has no Cloud Assistant agent", false},
		{"timed out", func() { a.result, a.errorCode = "Timeout", "ExecutionTimeout" }, "did not finish: Timeout (ExecutionTimeout)", true},
		{"agent gone", func() { a.result, a.errorCode = "Failed", "ClientNotRunning" }, "did not finish: Failed (ClientNotRunning)", true},
		{"dropped", func() { a.dropped = 10 }, "it may be cut", true},
		{"near the limit", func() { a.pad = strings.Repeat("x", assistantOutputLimit) }, "it may be cut", true},
	}
	for _, c := range cases {
		a.status["i-1"], a.result, a.errorCode, a.dropped, a.pad, a.runs = "true", "", "", 0, "", nil
		c.setup()
		err := r.run("list", "web-1")
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "has no private key on this machine") ||
			!strings.Contains(err.Error(), "--identity-file") || errors.Is(err, platform.ErrForbidden) {
			t.Errorf("%s: %v", c.name, err)
		}
		if (len(a.runs) > 0) != c.run {
			t.Errorf("%s: %d RunCommand calls", c.name, len(a.runs))
		}
	}
	if n := len(r.srv.Commands()); n != 0 {
		t.Errorf("logged in over SSH (%d commands)", n)
	}

	a.status["i-1"], a.result, a.errorCode, a.dropped, a.pad, a.runs = "true", "", "", 0, "", nil
	a.runErr = "Forbidden.RAM"
	err := r.run("list", "web-1")
	if !errors.Is(err, platform.ErrForbidden) || !strings.Contains(err.Error(), "ecs:RunCommand") {
		t.Errorf("RunCommand denied: %v", err)
	}

	a.runErr, a.statusErr = "", "Forbidden.RAM"
	if err := r.run("list", "web-1"); err != nil || len(a.runs) == 0 {
		t.Errorf("status check denied: %v (%d RunCommand calls)\n%s", err, len(a.runs), r.h.stderr.String())
	}
}

// The wrapper Cloud Assistant runs gives back the command's standard
// output exactly and its standard error apart, with its exit status.
func TestAssistantProgramSplitsOutput(t *testing.T) {
	sys := sshtest.NewSystem(t)
	prog, mark := assistantProgram(`printf 'a\n\nb'; echo "warn: x" >&2; printf 'c\n'; exit 5`)
	out, errb, code := sys.Run("root", prog, "")
	so, se, ok := splitAssistantOutput(out+errb, mark)
	if !ok || string(so) != "a\n\nbc\n" || string(se) != "warn: x\n" || code != 5 {
		t.Errorf("stdout %q stderr %q code %d ok %v (raw %q)", so, se, code, ok, out+errb)
	}
	if _, _, ok := splitAssistantOutput("cut", mark); ok {
		t.Error("output without the marker accepted")
	}
	// An output whose last newline was trimmed (no standard error) still
	// splits, standard output exactly.
	prog, mark = assistantProgram(`printf 'a\nb\n'`)
	out, errb, _ = sys.Run("root", prog, "")
	so, se, ok = splitAssistantOutput(strings.TrimRight(out+errb, "\n"), mark)
	if !ok || string(so) != "a\nb\n" || len(se) != 0 {
		t.Errorf("trimmed output: stdout %q stderr %q ok %v", so, se, ok)
	}
}

// The bound key pair is matched by the public key DescribeKeyPairs returns
// with IncludePublicKey=true, whatever form its fingerprint takes; without
// a public key, by the MD5 fingerprint.
func TestECSSSHKeyMatchesByPublicKey(t *testing.T) {
	r := newECSKeyRig(t, []string{"root"}, "root")
	r.f.keyPairs = nil
	r.f.addKeyPairKey("ops", r.login, "89:f0:ba:62:ac:b8:aa:e1:61:5e:fd:81:69:86:6d:6b:f0:c0:5a:01")
	if err := r.run("list", "web-1"); err != nil {
		t.Fatalf("%v\n%s", err, r.h.stderr.String())
	}
	var asked bool
	for _, q := range r.h.api.calls {
		if q.Get("Action") == "DescribeKeyPairs" && q.Get("KeyPairName") == "ops" && q.Get("IncludePublicKey") == "true" {
			asked = true
		}
	}
	if !asked {
		t.Error("DescribeKeyPairs was not asked for the public key of ops")
	}
	if len(r.srv.Commands()) == 0 {
		t.Error("no SSH login")
	}
}
