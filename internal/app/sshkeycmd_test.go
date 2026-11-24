package app_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
	"github.com/gofika/polyctl/internal/sshremote"
	"github.com/gofika/polyctl/internal/sshremote/sshtest"
)

type sshTestKey struct {
	priv ed25519.PrivateKey
	pub  ssh.PublicKey
}

func newSSHTestKey(t *testing.T) sshTestKey {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return sshTestKey{priv: priv, pub: s.PublicKey()}
}

func (k sshTestKey) line(comment string) string { return sshremote.KeyLine(k.pub, comment) }

// keyRig is an instance reachable over SSH (an in-process server running
// the key script in a fake system) behind the ssh-key commands of a fake
// platform. The login key is ~/.ssh/id_ed25519 of a temporary home.
type keyRig struct {
	t     *testing.T
	h     *harness
	srv   *sshtest.Server
	sys   *sshtest.System
	home  string
	login sshTestKey
	inst  app.SSHKeyInstance
	// resolved counts the calls of Resolve; picked holds the instance
	// argument given ("" for the interactive pick).
	resolved int
	picked   []string
}

func newKeyRig(t *testing.T, users ...string) *keyRig {
	t.Helper()
	r := &keyRig{t: t, h: newHarness(t, app.Flags{Profile: "a"}, nil)}
	r.home = t.TempDir()
	t.Setenv("HOME", r.home)
	t.Setenv("USERPROFILE", r.home)
	t.Setenv(sshremote.EnvAgent, "")
	oldGlobal, oldConfig := sshremote.GlobalKnownHosts, sshremote.SSHDConfig
	sshremote.GlobalKnownHosts = filepath.Join(r.home, "none")
	t.Cleanup(func() { sshremote.GlobalKnownHosts, sshremote.SSHDConfig = oldGlobal, oldConfig })
	r.sys = sshtest.NewSystem(t, users...)
	sshremote.SSHDConfig = filepath.Join(r.sys.Dir, "sshd_config")
	r.srv = sshtest.New(t)
	r.srv.System = r.sys
	r.login = newSSHTestKey(t)
	for _, u := range users {
		r.srv.Authorize(u, r.login.pub)
	}
	block, err := ssh.MarshalPrivateKey(r.login.priv, "login")
	if err != nil {
		t.Fatal(err)
	}
	sshDir := filepath.Join(r.home, ".ssh")
	_ = os.MkdirAll(sshDir, 0o700)
	if err := os.WriteFile(filepath.Join(sshDir, "id_ed25519"), pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(sshDir, "id_ed25519.pub"), []byte(r.login.line("me@laptop")+"\n"), 0o644)
	r.inst = app.SSHKeyInstance{Name: "web-1", ID: "i-1", Running: true, PublicIP: r.srv.Host,
		LoginUsers: users[:1], Target: platform.Target{Platform: platform.NameCom, Profile: "a", Region: "r1"}}
	return r
}

// authorized writes the authorized_keys of user.
func (r *keyRig) authorized(user, content string) string {
	r.t.Helper()
	dir := filepath.Join(r.sys.Home(user), ".ssh")
	_ = os.MkdirAll(dir, 0o700)
	f := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
		r.t.Fatal(err)
	}
	return f
}

func (r *keyRig) file(user string) string {
	data, _ := os.ReadFile(filepath.Join(r.sys.Home(user), ".ssh", "authorized_keys"))
	return string(data)
}

func (r *keyRig) spec() app.SSHKeyCommand {
	return app.SSHKeyCommand{Platform: platform.NameCom, Tree: "fake compute instance",
		Resolve: func(ctx context.Context, arg string) (*app.SSHKeyInstance, error) {
			r.resolved++
			r.picked = append(r.picked, arg)
			inst := r.inst
			return &inst, nil
		}}
}

// run runs `ssh-key <args>` with the port of the test server.
func (r *keyRig) run(args ...string) error {
	r.t.Helper()
	return r.runSpec(r.spec(), args...)
}

func (r *keyRig) runSpec(sc app.SSHKeyCommand, args ...string) error {
	r.t.Helper()
	r.h.stdout.Reset()
	r.h.stderr.Reset()
	cmd := app.SSHKeyCommands(r.h.rt, sc)
	if !sc.Metadata {
		args = append(args, "--port", itoa(r.srv.Port))
	}
	cmd.SetArgs(args)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	return cmd.ExecuteContext(context.Background())
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func (r *keyRig) report() platform.Report {
	r.t.Helper()
	var rep platform.Report
	if err := json.Unmarshal(r.h.stdout.Bytes(), &rep); err != nil {
		r.t.Fatalf("report %q: %v", r.h.stdout.String(), err)
	}
	return rep
}

func writePub(t *testing.T, dir, name string, k sshTestKey, comment string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(k.line(comment)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// add is an ensure: created, then unchanged; --dry-run reads and reports
// would create without writing (known_hosts included).
func TestSSHKeyAddEnsure(t *testing.T) {
	r := newKeyRig(t, "ec2-user")
	r.h.rt.Flags.Output = "json"
	_ = r.h.rt.Init()
	nk := newSSHTestKey(t)
	pub := writePub(t, r.home, "new.pub", nk, "alice@laptop")
	known := filepath.Join(r.home, ".ssh", "known_hosts")

	r.h.rt.Flags.DryRun = true
	if err := r.run("add", "web-1", "--ssh-key-file", pub, "--accept-new-host-key"); err != nil {
		t.Fatal(err)
	}
	rep := r.report()
	if !rep.DryRun || len(rep.Changes) != 1 || rep.Changes[0].Action != platform.WouldCreate ||
		rep.Changes[0].Resource != "key/ec2-user/"+ssh.FingerprintSHA256(nk.pub) || rep.Changes[0].Attrs["login_user"] != "ec2-user" {
		t.Fatalf("dry run report %+v", rep)
	}
	if r.file("ec2-user") != "" {
		t.Error("the dry run wrote authorized_keys")
	}
	if _, err := os.Stat(known); !os.IsNotExist(err) {
		t.Error("the dry run wrote known_hosts")
	}
	r.h.rt.Flags.DryRun = false

	if err := r.run("add", "web-1", "--ssh-key-file", pub, "--accept-new-host-key"); err != nil {
		t.Fatal(err)
	}
	if rep := r.report(); rep.Changes[0].Action != platform.Created || rep.Target.Region != "r1" {
		t.Fatalf("report %+v", rep)
	}
	if r.file("ec2-user") != nk.line("alice@laptop")+"\n" {
		t.Errorf("authorized_keys %q", r.file("ec2-user"))
	}
	if _, err := os.Stat(known); err != nil {
		t.Errorf("known_hosts: %v", err)
	}
	// Known host now; the key is there under another comment: unchanged.
	if err := r.run("add", "web-1", "--ssh-key", nk.line("other comment")); err != nil {
		t.Fatal(err)
	}
	if rep := r.report(); rep.Changes[0].Action != platform.Unchanged {
		t.Fatalf("second add %+v", rep)
	}
}

// The non-interactive flow refuses a missing key, and a remove without
// --yes, before the instance is even resolved; an unknown host key needs
// --accept-new-host-key.
func TestSSHKeyNonInteractiveRefusals(t *testing.T) {
	r := newKeyRig(t, "ec2-user")
	for _, args := range [][]string{
		{"add", "web-1"},
		{"remove", "web-1"},
		{"remove", "web-1", "--fingerprint", "SHA256:" + strings.Repeat("A", 43)},
		{"remove", "web-1", "--fingerprint", "nope"},
		{"add", "web-1", "--ssh-key", "ssh-ed25519 AAAA x", "--user", "bad user"},
		{"list"},
	} {
		if err := r.run(args...); !errors.Is(err, app.ErrUsage) && !errors.Is(err, platform.ErrInvalidInput) {
			t.Errorf("%v: %v", args, err)
		}
	}
	if r.resolved != 0 {
		t.Errorf("Resolve called %d times", r.resolved)
	}
	err := r.run("add", "web-1", "--ssh-key", newSSHTestKey(t).line(""))
	if !errors.Is(err, platform.ErrInvalidInput) || !strings.Contains(err.Error(), "--accept-new-host-key") {
		t.Fatalf("unknown host: %v", err)
	}
}

func TestSSHKeyInstanceStates(t *testing.T) {
	r := newKeyRig(t, "ec2-user")
	r.inst.Windows = true
	if err := r.run("list", "web-1"); !errors.Is(err, platform.ErrNotSupported) || !strings.Contains(err.Error(), "fake compute instance password i-1") {
		t.Errorf("windows: %v", err)
	}
	r.inst.Windows, r.inst.Running, r.inst.State = false, false, "stopped"
	if err := r.run("list", "web-1"); err == nil || !strings.Contains(err.Error(), "is stopped") || !strings.Contains(err.Error(), "fake compute instance start i-1") {
		t.Errorf("stopped: %v", err)
	}
	r.inst.Running, r.inst.PublicIP, r.inst.PrivateIP = true, "", ""
	if err := r.run("list", "web-1"); err == nil || !strings.Contains(err.Error(), "--address") {
		t.Errorf("no address: %v", err)
	}
	// The private IP is used with a note.
	r.inst.PrivateIP = r.srv.Host
	if err := r.run("list", "web-1", "--accept-new-host-key"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.h.stderr.String(), "no public IP") {
		t.Errorf("stderr %q", r.h.stderr.String())
	}
	r.inst.LoginUsers = nil
	if err := r.run("list", "web-1"); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--login-user") {
		t.Errorf("no login user: %v", err)
	}
}

// list shows the user's keys, the one in use marked; the login users are
// tried in order and the note names the one used.
func TestSSHKeyListAndLoginTrial(t *testing.T) {
	r := newKeyRig(t, "root", "ec2-user")
	r.srv.Force("root", `Please login as the user "ec2-user" rather than the user "root".`)
	r.inst.LoginUsers, r.inst.LoginUsersFrom = []string{"root", "ec2-user"}, "image al2023-ami"
	other := newSSHTestKey(t)
	r.authorized("ec2-user", `no-pty `+other.line("ops")+"\n"+r.login.line("me@laptop")+"\n")
	r.h.rt.Flags.Output = "json"
	_ = r.h.rt.Init()
	if err := r.run("list", "web-1", "--accept-new-host-key"); err != nil {
		t.Fatal(err)
	}
	var rows []app.SSHKeyRow
	if err := json.Unmarshal(r.h.stdout.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].User != "ec2-user" || rows[0].Comment != "ops" || rows[0].InUse || !rows[1].InUse ||
		rows[1].Fingerprint != ssh.FingerprintSHA256(r.login.pub) || rows[1].Type != "ed25519" || rows[1].Source != "authorized_keys" {
		t.Errorf("rows %+v", rows)
	}
	if s := r.h.stderr.String(); !strings.Contains(s, "logged in to") || !strings.Contains(s, "as ec2-user (default users of image al2023-ami)") {
		t.Errorf("stderr %q", s)
	}
}

// remove refuses the key in use and the last key, removes the others after
// the confirmation (--yes), and reports a missing key unchanged.
func TestSSHKeyRemoveGuards(t *testing.T) {
	r := newKeyRig(t, "ec2-user", "deploy")
	a := newSSHTestKey(t)
	f := r.authorized("ec2-user", r.login.line("me")+"\n"+a.line("old")+"\n")
	r.h.rt.Flags.Yes = true
	err := r.run("remove", "web-1", "--fingerprint", ssh.FingerprintSHA256(r.login.pub), "--accept-new-host-key")
	if err == nil || !strings.Contains(err.Error(), "logged in with") {
		t.Fatalf("key in use: %v", err)
	}
	if err := r.run("remove", "web-1", "--ssh-key", a.line("whatever")); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(f); string(data) != r.login.line("me")+"\n" {
		t.Errorf("after remove %q", data)
	}
	if err := r.run("remove", "web-1", "--ssh-key", a.line("")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.h.stdout.String(), "unchanged") || !strings.Contains(r.h.stdout.String(), "not present") {
		t.Errorf("absent key report %q", r.h.stdout.String())
	}
	// deploy's only key: the last key is refused, through sudo too.
	r.authorized("deploy", a.line("ci")+"\n")
	err = r.run("remove", "web-1", "--user", "deploy", "--ssh-key", a.line(""))
	if err == nil || !strings.Contains(err.Error(), "last key of deploy") {
		t.Fatalf("last key: %v", err)
	}
	if r.file("deploy") != a.line("ci")+"\n" {
		t.Error("the last key was removed")
	}
}

// Another user's keys go through sudo -n, and the report says so.
func TestSSHKeyAddForAnotherUser(t *testing.T) {
	r := newKeyRig(t, "ec2-user", "deploy")
	nk := newSSHTestKey(t)
	if err := r.run("add", "web-1", "--user", "deploy", "--ssh-key", nk.line("ci"), "--accept-new-host-key"); err != nil {
		t.Fatal(err)
	}
	if r.file("deploy") != nk.line("ci")+"\n" {
		t.Errorf("deploy's keys %q", r.file("deploy"))
	}
	if out := r.h.stdout.String(); !strings.Contains(out, "key/deploy/") || !strings.Contains(out, "(sudo)") {
		t.Errorf("report %q", out)
	}
	r.sys.SudoPassword = true
	if err := r.run("add", "web-1", "--user", "deploy", "--ssh-key", newSSHTestKey(t).line("")); err == nil || !strings.Contains(err.Error(), "sudo -n") {
		t.Fatalf("sudo password: %v", err)
	}
}

// The interactive flow: the instance is picked (Resolve with ""), the
// host key is asked about (default no), the key is picked among the local
// ones (the one already there marked), and remove picks among the listed
// keys without the one in use, then confirms.
func TestSSHKeyInteractive(t *testing.T) {
	r := newKeyRig(t, "ec2-user")
	sshDir := filepath.Join(r.home, ".ssh")
	nk := newSSHTestKey(t)
	newPub := writePub(t, sshDir, "work.pub", nk, "work")
	r.authorized("ec2-user", r.login.line("me")+"\n")
	p := prompttest.New(t, true, newPub)
	r.h.rt.Picker = p
	if err := r.run("add"); err != nil {
		t.Fatal(err)
	}
	p.Done()
	if r.picked[0] != "" {
		t.Errorf("Resolve got %q, want the interactive pick", r.picked[0])
	}
	if a := p.Find("Trust this host key and record it in ~/.ssh/known_hosts?"); a.Default != "false" {
		t.Errorf("trust default %q", a.Default)
	}
	labels := prompttest.Labels(p.Find("Public key to add to web-1 (i-1)").Options)
	if !strings.Contains(labels, "id_ed25519.pub") || !strings.Contains(labels, "[already there for ec2-user]") || !strings.Contains(labels, "Enter a public key...") {
		t.Errorf("key options:\n%s", labels)
	}
	if !strings.Contains(r.file("ec2-user"), nk.line("work")) {
		t.Fatalf("not added: %q", r.file("ec2-user"))
	}

	// remove: the key in use is not offered; the confirmation is read
	// from the terminal (here stdin) and a no changes nothing.
	p = prompttest.New(t, []string{"ec2-user " + ssh.FingerprintSHA256(nk.pub)})
	r.h.rt.Picker = p
	r.h.rt.Stdin = strings.NewReader("n\n")
	err := r.run("remove", "web-1")
	if !errors.Is(err, platform.ErrNothingToDo) {
		t.Fatalf("declined: %v", err)
	}
	opts := p.Find("Keys to remove from web-1 (i-1)").Options
	if len(opts) != 1 || strings.Contains(prompttest.Values(opts), ssh.FingerprintSHA256(r.login.pub)) {
		t.Errorf("remove options %v", opts)
	}
	if !strings.Contains(r.file("ec2-user"), nk.line("work")) {
		t.Error("removed although declined")
	}
	p = prompttest.New(t, []string{"ec2-user " + ssh.FingerprintSHA256(nk.pub)})
	r.h.rt.Picker = p
	r.h.rt.Stdin = strings.NewReader("y\n")
	if err := r.run("remove", "web-1"); err != nil {
		t.Fatal(err)
	}
	if r.file("ec2-user") != r.login.line("me")+"\n" {
		t.Errorf("after remove %q", r.file("ec2-user"))
	}
}

// EC2 Instance Connect: when no local key logs in, --instance-connect
// pushes a one-time key for each login user in turn.
func TestSSHKeyInstanceConnect(t *testing.T) {
	r := newKeyRig(t, "ec2-user")
	stranger := sshtest.New(t)
	stranger.System = r.sys
	r.srv = stranger // no key is authorized there
	var pushed []string
	r.inst.InstanceConnect = func(ctx context.Context, user string, key ssh.PublicKey) error {
		pushed = append(pushed, user)
		stranger.Authorize(user, key)
		return nil
	}
	sc := r.spec()
	sc.InstanceConnect = true
	nk := newSSHTestKey(t)
	err := r.runSpec(sc, "add", "web-1", "--ssh-key", nk.line("k"), "--accept-new-host-key")
	if err == nil || !strings.Contains(err.Error(), "--instance-connect") || len(pushed) != 0 {
		t.Fatalf("without the flag: %v (pushed %v)", err, pushed)
	}
	if err := r.runSpec(sc, "add", "web-1", "--ssh-key", nk.line("k"), "--instance-connect"); err != nil {
		t.Fatal(err)
	}
	if len(pushed) != 1 || pushed[0] != "ec2-user" || r.file("ec2-user") != nk.line("k")+"\n" {
		t.Errorf("pushed %v, file %q", pushed, r.file("ec2-user"))
	}
}

// fakeStore is a metadata store (Compute Engine).
type fakeStore struct {
	keys     []app.SSHKeyEntry
	readOnly error
	writes   int
}

func (s *fakeStore) List(context.Context) (*app.SSHKeyListing, error) {
	return &app.SSHKeyListing{Keys: append([]app.SSHKeyEntry(nil), s.keys...), ReadOnly: s.readOnly, Notes: []string{"note: project keys are blocked"}}, nil
}

func (s *fakeStore) Add(_ context.Context, user string, key *platform.PublicKey) (bool, error) {
	for _, e := range s.keys {
		if e.User == user && !e.ReadOnly && sshremote.SameKey(e.Key, key.Key) {
			return false, nil
		}
	}
	s.writes++
	s.keys = append(s.keys, app.SSHKeyEntry{User: user, Key: key.Key, Comment: key.Comment, Source: "instance metadata"})
	return true, nil
}

func (s *fakeStore) Remove(_ context.Context, user string, keys []ssh.PublicKey) (int, error) {
	n := 0
	var kept []app.SSHKeyEntry
	for _, e := range s.keys {
		drop := false
		for _, k := range keys {
			if e.User == user && !e.ReadOnly && sshremote.SameKey(e.Key, k) {
				drop = true
			}
		}
		if drop {
			n++
			continue
		}
		kept = append(kept, e)
	}
	s.keys = kept
	s.writes++
	return n, nil
}

func TestSSHKeyMetadataStore(t *testing.T) {
	r := newKeyRig(t, "ec2-user")
	proj := newSSHTestKey(t)
	st := &fakeStore{keys: []app.SSHKeyEntry{{User: "bob", Key: proj.pub, Source: "project metadata", ReadOnly: true}}}
	r.inst.Metadata = st
	r.inst.Running = false // metadata needs no running instance
	sc := r.spec()
	sc.Metadata = true
	sc.UserFromKey = func(k *platform.PublicKey) string {
		if u, _, ok := strings.Cut(k.Comment, "@"); ok {
			return u
		}
		return ""
	}
	if c := app.SSHKeyCommands(r.h.rt, sc); c.Commands()[1].Flags().Lookup("identity-file") != nil {
		t.Error("a metadata platform registers the SSH flags")
	}
	nk := newSSHTestKey(t)
	// No --user and no user@host in the comment: a usage error, nothing read.
	if err := r.runSpec(sc, "add", "web-1", "--ssh-key", nk.line("laptop")); !errors.Is(err, app.ErrUsage) || r.resolved != 0 {
		t.Fatalf("no user: %v (resolved %d)", err, r.resolved)
	}
	// A comment whose user part is not a user name is not taken as one.
	if err := r.runSpec(sc, "add", "web-1", "--ssh-key", nk.line("a:b@laptop")); !errors.Is(err, app.ErrUsage) || r.resolved != 0 {
		t.Fatalf("invalid user from the comment: %v (resolved %d)", err, r.resolved)
	}
	if err := r.runSpec(sc, "add", "web-1", "--ssh-key", nk.line("alice@laptop")); err != nil {
		t.Fatal(err)
	}
	if len(st.keys) != 2 || st.keys[1].User != "alice" || !strings.Contains(r.h.stdout.String(), "key/alice/") {
		t.Fatalf("keys %+v, out %q", st.keys, r.h.stdout.String())
	}
	if err := r.runSpec(sc, "add", "web-1", "--ssh-key", nk.line("x"), "--user", "alice"); err != nil || st.writes != 1 {
		t.Fatalf("idempotent add: %v, writes %d", err, st.writes)
	}
	// A blocked project key of the same user does not count as present.
	ig := newSSHTestKey(t)
	st.keys = append(st.keys, app.SSHKeyEntry{User: "carol", Key: ig.pub, Source: "project metadata", ReadOnly: true, Ignored: true})
	if err := r.runSpec(sc, "add", "web-1", "--ssh-key", ig.line("carol@x")); err != nil || !strings.Contains(r.h.stdout.String(), "created") {
		t.Fatalf("add over an ignored key: %v %q", err, r.h.stdout.String())
	}
	st.keys = append(st.keys[:2], st.keys[4:]...) // drop carol's two entries
	// A project key is not removed; alice's is, with no lockout guard.
	r.h.rt.Flags.Yes = true
	if err := r.runSpec(sc, "remove", "web-1", "--ssh-key", proj.line("")); err != nil {
		t.Fatal(err)
	}
	if len(st.keys) != 2 || !strings.Contains(r.h.stdout.String(), "not present") {
		t.Errorf("project key: %+v %q", st.keys, r.h.stdout.String())
	}
	if err := r.runSpec(sc, "remove", "web-1", "--fingerprint", ssh.FingerprintSHA256(nk.pub)); err != nil {
		t.Fatal(err)
	}
	if len(st.keys) != 1 {
		t.Errorf("after remove %+v", st.keys)
	}
	// OS Login: list works, add and remove are refused with exit code 7.
	st.readOnly = errors.Join(platform.ErrNotSupported, errors.New("OS Login is enabled"))
	if err := r.runSpec(sc, "list", "web-1"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.h.stdout.String(), "project metadata (read-only)") || !strings.Contains(r.h.stderr.String(), "project keys are blocked") {
		t.Errorf("list %q / %q", r.h.stdout.String(), r.h.stderr.String())
	}
	if err := r.runSpec(sc, "add", "web-1", "--ssh-key", nk.line("a@b")); !errors.Is(err, platform.ErrNotSupported) {
		t.Errorf("add under OS Login: %v", err)
	}
}
