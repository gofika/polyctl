package aws

import (
	"context"
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
	"sync"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2instanceconnect"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"golang.org/x/crypto/ssh"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
	"github.com/gofika/polyctl/internal/sshremote"
	"github.com/gofika/polyctl/internal/sshremote/sshtest"
)

// fakeEC2IC is the EC2 Instance Connect API: a pushed key is authorized on
// the test SSH server for its user.
type fakeEC2IC struct {
	mu     sync.Mutex
	srv    *sshtest.Server
	err    error
	region string
	calls  []ec2instanceconnect.SendSSHPublicKeyInput
}

func (f *fakeEC2IC) SendSSHPublicKey(_ context.Context, in *ec2instanceconnect.SendSSHPublicKeyInput, _ ...func(*ec2instanceconnect.Options)) (*ec2instanceconnect.SendSSHPublicKeyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, *in)
	if f.err != nil {
		return nil, f.err
	}
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(awssdk.ToString(in.SSHPublicKey)))
	if err != nil {
		return nil, err
	}
	f.srv.Authorize(awssdk.ToString(in.InstanceOSUser), k)
	return &ec2instanceconnect.SendSSHPublicKeyOutput{Success: true}, nil
}

// ec2KeyRig is a running instance web-1 whose public IP is an in-process
// SSH server running the key script in a fake system. The login key is
// ~/.ssh/id_ed25519 of a temporary home, authorized for loginUsers.
type ec2KeyRig struct {
	t     *testing.T
	h     *awsHarness
	srv   *sshtest.Server
	sys   *sshtest.System
	login ssh.PublicKey
	inst  *fakeInstance
	ic    *fakeEC2IC
}

func newEC2KeyRig(t *testing.T, image string, users []string, loginUsers ...string) *ec2KeyRig {
	t.Helper()
	r := &ec2KeyRig{t: t, h: newInstanceHarness(t, app.Flags{})}
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
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	r.login = signer.PublicKey()
	for _, u := range loginUsers {
		r.srv.Authorize(u, r.login)
	}
	block, err := ssh.MarshalPrivateKey(priv, "login")
	if err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	r.ic = &fakeEC2IC{srv: r.srv}
	old := newEC2IC
	newEC2IC = func(cfg awssdk.Config) ec2icAPI { r.ic.region = cfg.Region; return r.ic }
	t.Cleanup(func() { newEC2IC = old })
	// The instance's key pair ops is the login key.
	r.h.add("ap-east-1", newFakeKeyPair("ops", r.login))
	in := running("i-0web", "web-1")
	in.pub, in.image, in.keyName = r.srv.Host, image, "ops"
	r.inst = r.h.addInstance("ap-east-1", in)
	return r
}

// addImage registers an image in ap-east-1.
func (r *ec2KeyRig) addImage(id, name, description string) {
	r.h.ec2.mu.Lock()
	defer r.h.ec2.mu.Unlock()
	r.h.ec2.inst.init()
	r.h.ec2.inst.images["ap-east-1"] = append(r.h.ec2.inst.images["ap-east-1"],
		ec2types.Image{ImageId: awssdk.String(id), Name: awssdk.String(name), Description: awssdk.String(description), Architecture: "x86_64"})
}

// run runs `aws ec2 instance ssh-key <args>` against the test server.
func (r *ec2KeyRig) run(args ...string) error {
	r.t.Helper()
	return r.h.run(append(append([]string{"ec2", "instance", "ssh-key"}, args...), "--port", strconv.Itoa(r.srv.Port), "--accept-new-host-key")...)
}

func (r *ec2KeyRig) file(user string) string {
	data, _ := os.ReadFile(filepath.Join(r.sys.Home(user), ".ssh", "authorized_keys"))
	return string(data)
}

func newKeyLine(t *testing.T, comment string) (ssh.PublicKey, string) {
	t.Helper()
	k := genED25519(t)
	return k, sshremote.KeyLine(k, comment)
}

// add, list and remove on an Amazon Linux 2023 instance: the login user is
// ec2-user (from the image), add is an ensure, remove refuses nothing it
// should not and removes the key.
func TestEC2SSHKeyAddListRemove(t *testing.T) {
	r := newEC2KeyRig(t, "ami-0x86", []string{"ec2-user"}, "ec2-user")
	k, line := newKeyLine(t, "alice@laptop")
	fp := ssh.FingerprintSHA256(k)
	if err := r.run("add", "web-1", "--ssh-key", line); err != nil {
		t.Fatalf("%v\n%s", err, r.h.stderr.String())
	}
	if c := r.h.report().Changes; len(c) != 1 || c[0].Resource != "key/ec2-user/"+fp || c[0].Action != platform.Created {
		t.Fatalf("add = %+v", c)
	}
	if r.file("ec2-user") != line+"\n" {
		t.Fatalf("file %q", r.file("ec2-user"))
	}
	if strings.Contains(r.h.stderr.String(), "does not know") {
		t.Errorf("a known image got the unknown note:\n%s", r.h.stderr.String())
	}
	if err := r.run("add", "web-1", "--ssh-key", line); err != nil {
		t.Fatal(err)
	}
	if c := r.h.report().Changes; len(c) != 1 || c[0].Action != platform.Unchanged {
		t.Fatalf("again = %+v", c)
	}

	if err := r.run("list", "web-1"); err != nil {
		t.Fatal(err)
	}
	var rows []app.SSHKeyRow
	r.h.jsonOut(&rows)
	if len(rows) != 1 || rows[0].User != "ec2-user" || rows[0].Fingerprint != fp || rows[0].Source != "authorized_keys" {
		t.Fatalf("rows = %+v", rows)
	}

	// The last key of the user is refused; the non-interactive flow needs
	// --yes first.
	if err := r.run("remove", "web-1", "--fingerprint", fp); !errors.Is(err, app.ErrUsage) {
		t.Fatalf("without --yes: %v", err)
	}
	r.h.rt.Flags.Yes = true
	if err := r.run("remove", "web-1", "--fingerprint", fp); err == nil || !strings.Contains(err.Error(), "last key") {
		t.Fatalf("last key: %v", err)
	}
	_, other := newKeyLine(t, "bob@desk")
	if err := r.run("add", "web-1", "--ssh-key", other); err != nil {
		t.Fatal(err)
	}
	if err := r.run("remove", "web-1", "--fingerprint", fp); err != nil {
		t.Fatal(err)
	}
	if c := r.h.report().Changes; len(c) != 1 || c[0].Action != platform.Deleted || r.file("ec2-user") != other+"\n" {
		t.Fatalf("remove = %+v, file %q", c, r.file("ec2-user"))
	}
	if len(r.ic.calls) != 0 {
		t.Errorf("EC2 Instance Connect used although the key pair's key logged in: %v", r.ic.calls)
	}
}

// An image of no known family tries the documented users in order (the
// first that logs in wins, with notes); --login-user tries only that user
// and prints no note. An image that cannot be read falls back to the
// instance's platform details.
func TestEC2SSHKeyLoginUsers(t *testing.T) {
	r := newEC2KeyRig(t, "ami-0gold", []string{"admin"}, "admin")
	r.addImage("ami-0gold", "golden-2026-11", "our base image")
	if err := r.run("list", "web-1"); err != nil {
		t.Fatalf("%v\n%s", err, r.h.stderr.String())
	}
	errOut := r.h.stderr.String()
	if !strings.Contains(errOut, "does not know the default user of image ami-0gold (golden-2026-11)") ||
		!strings.Contains(errOut, "as admin") {
		t.Errorf("stderr:\n%s", errOut)
	}
	if err := r.run("list", "web-1", "--login-user", "admin"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.h.stderr.String(), "does not know") {
		t.Errorf("--login-user still notes:\n%s", r.h.stderr.String())
	}

	// A RHEL instance whose image is gone: ec2-user, then root (EC2
	// Instance Connect, tried next, is denied here).
	r.ic.err = &fakeAPIError{"AuthException", "you do not have access to the EC2 instance"}
	r.inst.image, r.inst.platformDetails = "ami-0gone", "Red Hat Enterprise Linux"
	err := r.run("list", "web-1")
	errOut = r.h.stderr.String()
	if err == nil || !strings.Contains(errOut, "cannot read image ami-0gone") ||
		!strings.Contains(err.Error(), "ec2-user") || !strings.Contains(err.Error(), "root") || strings.Contains(err.Error(), "ubuntu") {
		t.Fatalf("gone image: %v\n%s", err, errOut)
	}

	// No image and no platform details: the notes name the instance.
	r.inst.image, r.inst.platformDetails = "", ""
	_ = r.run("list", "web-1")
	errOut = r.h.stderr.String()
	if !strings.Contains(errOut, "names no image") || !strings.Contains(errOut, "does not know the default user of instance ") || strings.Contains(errOut, `""`) {
		t.Errorf("no image:\n%s", errOut)
	}
}

// Windows instances are refused with exit code 7, stopped ones with the
// start command to run; neither logs in.
func TestEC2SSHKeyRefusals(t *testing.T) {
	r := newEC2KeyRig(t, "ami-0x86", []string{"ec2-user"}, "ec2-user")
	r.inst.platform = "windows"
	err := r.run("list", "web-1")
	if !errors.Is(err, platform.ErrNotSupported) || !strings.Contains(err.Error(), "aws ec2 instance password i-0web") {
		t.Fatalf("windows: %v", err)
	}
	r.inst.platform, r.inst.state = "", stateStopped
	err = r.run("list", "web-1")
	if err == nil || errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "polyctl aws ec2 instance start i-0web") {
		t.Fatalf("stopped: %v", err)
	}
	if len(r.srv.Commands()) != 0 {
		t.Errorf("logged in: %v", r.srv.Commands())
	}
}

// The key pair's key does not log in and Systems Manager does not manage
// the instance, so a one-time key is pushed with EC2 Instance Connect,
// without a flag or a question, for the login user of the image (with the
// instance's zone), and the key is added in that session; a push denied
// names the IAM action (exit code 3 when Run Command is denied too). An
// instance whose key pair has no local private key goes straight to the
// temporary ways in.
func TestEC2SSHKeyInstanceConnect(t *testing.T) {
	r := newEC2KeyRig(t, "ami-0x86", []string{"ec2-user"}) // no key authorized
	_, line := newKeyLine(t, "alice@laptop")
	if err := r.run("add", "web-1", "--ssh-key", line); err != nil {
		t.Fatalf("%v\n%s", err, r.h.stderr.String())
	}
	if !strings.Contains(r.h.stderr.String(), "did not log in") || !strings.Contains(r.h.stderr.String(), "trying SSM Run Command, then EC2 Instance Connect") {
		t.Errorf("stderr:\n%s", r.h.stderr.String())
	}
	if len(r.ic.calls) != 1 {
		t.Fatalf("calls = %d", len(r.ic.calls))
	}
	c := r.ic.calls[0]
	if awssdk.ToString(c.InstanceId) != "i-0web" || awssdk.ToString(c.InstanceOSUser) != "ec2-user" || awssdk.ToString(c.AvailabilityZone) != "ap-east-1a" || r.ic.region != "ap-east-1" {
		t.Errorf("call = %+v in %s", c, r.ic.region)
	}
	if r.file("ec2-user") != line+"\n" {
		t.Errorf("file %q", r.file("ec2-user"))
	}

	// A denied push on an instance Systems Manager does not manage: both
	// reasons are named, and it is no authorization failure as a whole.
	r.ic.err = &fakeAPIError{"AccessDeniedException", "not authorized to perform ec2-instance-connect:SendSSHPublicKey"}
	_, other := newKeyLine(t, "bob@desk")
	err := r.run("add", "web-1", "--ssh-key", other)
	if err == nil || errors.Is(err, platform.ErrUnauthorized) || !strings.Contains(err.Error(), "IAM action ec2-instance-connect:SendSSHPublicKey") ||
		!strings.Contains(err.Error(), "SSM Run Command: the instance is not managed by Systems Manager") || !strings.Contains(err.Error(), "--identity-file") {
		t.Fatalf("denied, unmanaged: %v", err)
	}

	// Denied by both (exit code 3): the errors name the IAM actions.
	// AuthException (no access to the instance or OS user) counts as
	// denied too.
	r.h.ec2.run.manage("i-0web", ssmtypes.PingStatusOnline)
	r.h.ec2.run.sendErr = &fakeAPIError{"AccessDeniedException", "not authorized to perform ssm:SendCommand"}
	err = r.run("add", "web-1", "--ssh-key", other)
	if !errors.Is(err, platform.ErrUnauthorized) || !strings.Contains(err.Error(), "IAM action ec2-instance-connect:SendSSHPublicKey") ||
		!strings.Contains(err.Error(), "IAM action ssm:SendCommand") {
		t.Fatalf("denied: %v", err)
	}
	r.ic.err = &fakeAPIError{"AuthException", "you do not have access to the EC2 instance"}
	err = r.run("add", "web-1", "--ssh-key", other)
	if !errors.Is(err, platform.ErrUnauthorized) || !strings.Contains(err.Error(), "IAM action ec2-instance-connect:SendSSHPublicKey") {
		t.Fatalf("auth exception: %v", err)
	}
	r.h.ec2.run = fakeRunCommand{}

	// A key pair of someone else: no local key is offered at all.
	r.ic.err = nil
	r.h.add("ap-east-1", newFakeKeyPair("someone-else", genED25519(t)))
	r.inst.keyName = "someone-else"
	r.srv.Authorize("ec2-user", r.login)
	calls := len(r.ic.calls)
	if err := r.run("add", "web-1", "--ssh-key", other); err != nil {
		t.Fatalf("%v\n%s", err, r.h.stderr.String())
	}
	if len(r.ic.calls) != calls+1 || !strings.Contains(r.h.stderr.String(), "the key pair someone-else of instance web-1 (i-0web) has no private key on this machine") {
		t.Errorf("calls %d, stderr:\n%s", len(r.ic.calls)-calls, r.h.stderr.String())
	}
}

func TestFamilyOf(t *testing.T) {
	cases := []struct {
		name, desc, pd string
		users          string
		ic             bool
	}{
		{"al2023-ami-2023.9.20261101.0-kernel-6.12-x86_64", "Amazon Linux 2023 AMI", "Linux/UNIX", "ec2-user", true},
		{"al2023-ami-minimal-2023.9.20261101.0-kernel-6.12-x86_64", "", "", "ec2-user", false},
		{"al2023-ami-ecs-hvm-2023.0.20261101-kernel-6.1-x86_64", "", "", "ec2-user", false},
		{"amzn2-ami-kernel-5.10-hvm-2.0.20261101.0-x86_64-gp2", "", "", "ec2-user", true},
		{"amzn2-ami-hvm-2.0.20190313-x86_64-gp2", "", "", "ec2-user", false},
		{"amzn-ami-hvm-2018.03.0.20231218.0-x86_64-gp2", "", "", "ec2-user", false},
		{"ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-20261101", "Canonical, Ubuntu, 24.04", "", "ubuntu", true},
		{"ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-20230531", "", "", "ubuntu", false},
		{"ubuntu-pro-server/images/hvm-ssd/ubuntu-focal-20.04-amd64-pro-server-20261101", "", "Ubuntu Pro", "ubuntu", true},
		{"debian-12-amd64-20261101-1234", "Debian 12 (20261101-1234)", "", "admin", false},
		{"bitnami-wordpress-6.6.2-r0-debian-12-amd64", "", "", "bitnami", false},
		{"CentOS Stream 9 x86_64 20261101", "", "", "centos,ec2-user", false},
		{"Fedora-Cloud-Base-AmazonEC2.x86_64-41-1.4", "", "", "fedora,ec2-user", false},
		{"Rocky-9-EC2-Base-9.5-20241118.0.x86_64", "", "", "rocky", false},
		{"RHEL-9.4.0_HVM-20240605-x86_64-82-Hourly2-GP3", "", "Red Hat Enterprise Linux", "ec2-user,root", false},
		{"suse-sles-15-sp6-v20261101-hvm-ssd-x86_64", "", "SUSE Linux", "ec2-user,root", false},
		{"OL9.4-x86_64-HVM-2024-06-17", "Oracle Linux 9 update 4", "", "ec2-user", false},
		{"FreeBSD 14.1-RELEASE-amd64", "", "", "ec2-user", false},
		{"amzn-ec2-macos-15.1-20261101-arm64", "", "", "ec2-user", false},
		{"", "", "Red Hat BYOL Linux", "ec2-user,root", false},
		{"AlmaLinux OS 9.5.20241120 x86_64", "", "Linux/UNIX", "", false},
		{"golden-2026-11", "our base image", "Linux/UNIX", "", false},
	}
	for _, c := range cases {
		f := familyOf(c.name, c.desc, c.pd)
		if strings.Join(f.Users, ",") != c.users || f.InstanceConnect != c.ic {
			t.Errorf("%q: users %v ic %v, want %s %v", c.name, f.Users, f.InstanceConnect, c.users, c.ic)
		}
	}
}

// On a terminal, ssh-key list without <name|id> offers the running Linux
// instances only.
func TestEC2SSHKeyPick(t *testing.T) {
	r := newEC2KeyRig(t, "ami-0x86", []string{"ec2-user"}, "ec2-user")
	r.h.rt.Flags.NonInteractive, r.h.rt.Flags.NonInteractiveSet = false, true
	r.inst.id = "i-0aaaaaaaaaaaaaaa1" // an id that resolves as one
	win := running("i-0aaaaaaaaaaaaaaa2", "win-1")
	win.platform = "windows"
	r.h.addInstance("ap-east-1", win)
	r.h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa3", name: "web-off", typ: "t3.nano", state: stateStopped, priv: "10.0.1.5"})
	p := prompttest.New(t, "i-0aaaaaaaaaaaaaaa1")
	r.h.rt.Picker = p
	if err := r.run("list"); err != nil {
		t.Fatalf("%v\n%s", err, r.h.stderr.String())
	}
	p.Done()
	if v := prompttest.Values(p.Find("Instance").Options); v != "i-0aaaaaaaaaaaaaaa1" {
		t.Errorf("offered %q, want the running Linux instance only", v)
	}
}

// useRunCommand makes the instance a managed node whose SSM Agent runs the
// commands as root in the rig's fake system; scripts collects the programs
// it ran (decoded).
func (r *ec2KeyRig) useRunCommand(scripts *[]string) {
	r.h.ec2.run.manage("i-0web", ssmtypes.PingStatusOnline)
	r.h.ec2.run.exec = func(id, cmd string) (string, string, int) {
		if scripts != nil {
			if m := regexp.MustCompile(`echo ([A-Za-z0-9+/=]+) \|`).FindStringSubmatch(cmd); m != nil {
				prog, _ := base64.StdEncoding.DecodeString(m[1])
				*scripts = append(*scripts, string(prog))
			}
		}
		return r.sys.Run("root", cmd, "")
	}
}

// An instance whose key pair has no private key on this machine (created
// for someone else) is never logged in to with a local key: on a managed
// node whose agent is online the keys are listed and edited through Run
// Command, as root running the key script as the login user, without EC2
// Instance Connect. The invocation that is not visible at first is waited
// for; --dry-run runs the read-only script only; the last key stays guarded.
func TestEC2SSHKeyRunCommand(t *testing.T) {
	r := newEC2KeyRig(t, "ami-0x86", []string{"ec2-user"}, "ec2-user")
	r.h.add("ap-east-1", newFakeKeyPair("someone-else", genED25519(t)))
	r.inst.keyName = "someone-else"
	var scripts []string
	r.useRunCommand(&scripts)
	r.h.ec2.run.hidden = 2

	k, line := newKeyLine(t, "alice@laptop")
	r.h.rt.Flags.DryRun = true
	if err := r.run("add", "web-1", "--ssh-key", line); err != nil {
		t.Fatalf("%v\n%s", err, r.h.stderr.String())
	}
	if r.file("ec2-user") != "" || !strings.Contains(r.h.stdout.String(), "would_create") {
		t.Fatalf("dry run: file %q out %q", r.file("ec2-user"), r.h.stdout.String())
	}
	for _, p := range scripts {
		if strings.Contains(p, "sh -s -- 'apply'") {
			t.Fatalf("the dry run ran the apply script:\n%s", p)
		}
	}
	r.h.rt.Flags.DryRun = false
	if err := r.run("add", "web-1", "--ssh-key", line); err != nil {
		t.Fatalf("%v\n%s", err, r.h.stderr.String())
	}
	errOut := r.h.stderr.String()
	for _, want := range []string{"the key pair someone-else of instance web-1 (i-0web) has no private key on this machine",
		"no local key is tried", "trying SSM Run Command, then EC2 Instance Connect", "through SSM Run Command"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errOut)
		}
	}
	if r.file("ec2-user") != line+"\n" {
		t.Fatalf("file %q", r.file("ec2-user"))
	}
	if len(r.ic.calls) != 0 || len(r.srv.Commands()) != 0 {
		t.Errorf("Instance Connect calls %d, SSH commands %d: want none", len(r.ic.calls), len(r.srv.Commands()))
	}
	f := &r.h.ec2.run
	if len(f.sent) == 0 {
		t.Fatal("no SendCommand")
	}
	in := f.sent[0]
	if awssdk.ToString(in.DocumentName) != "AWS-RunShellScript" || strings.Join(in.InstanceIds, ",") != "i-0web" ||
		strings.Join(in.Parameters["executionTimeout"], ",") != "60" || awssdk.ToInt32(in.TimeoutSeconds) != 30 {
		t.Errorf("SendCommand = %+v", in)
	}

	if err := r.run("list", "web-1"); err != nil {
		t.Fatal(err)
	}
	var rows []app.SSHKeyRow
	r.h.jsonOut(&rows)
	if len(rows) != 1 || rows[0].User != "ec2-user" || rows[0].Fingerprint != ssh.FingerprintSHA256(k) || rows[0].InUse {
		t.Fatalf("rows = %+v", rows)
	}
	r.h.rt.Flags.Yes = true
	if err := r.run("remove", "web-1", "--ssh-key", line); err == nil || !strings.Contains(err.Error(), "last key of ec2-user") {
		t.Fatalf("last key: %v", err)
	}

	// A key pair deleted since launch (KeyName stays on the instance) and
	// an instance launched without one go the same way.
	r.inst.keyName = "gone"
	if err := r.run("list", "web-1"); err != nil {
		t.Fatal(err)
	}
	if s := r.h.stderr.String(); !strings.Contains(s, "the key pair gone of instance web-1 (i-0web) cannot be read (no key pair of that name in ap-east-1 (deleted?))") ||
		!strings.Contains(s, "through SSM Run Command") {
		t.Errorf("deleted key pair:\n%s", s)
	}
	r.inst.keyName = ""
	if err := r.run("list", "web-1"); err != nil {
		t.Fatal(err)
	}
	if s := r.h.stderr.String(); !strings.Contains(s, "instance web-1 (i-0web) has no key pair") || !strings.Contains(s, "through SSM Run Command") {
		t.Errorf("no key pair:\n%s", s)
	}
	if len(r.ic.calls) != 0 || len(r.srv.Commands()) != 0 {
		t.Errorf("Instance Connect calls %d, SSH commands %d: want none", len(r.ic.calls), len(r.srv.Commands()))
	}
}

// Run Command is skipped or fails over to EC2 Instance Connect when the
// agent is offline, when the command does not finish, and when its output
// may be cut; when the credentials may not describe the node, SendCommand
// is tried anyway.
func TestEC2SSHKeyRunCommandFallback(t *testing.T) {
	r := newEC2KeyRig(t, "ami-0x86", []string{"ec2-user"})
	r.h.add("ap-east-1", newFakeKeyPair("someone-else", genED25519(t)))
	r.inst.keyName = "someone-else"
	r.useRunCommand(nil)
	f := &r.h.ec2.run

	cases := []struct {
		name  string
		setup func()
		want  string
	}{
		{"offline", func() { f.manage("i-0web", ssmtypes.PingStatusConnectionLost) }, "SSM Run Command: the SSM Agent of the instance is not online (ping status ConnectionLost)"},
		{"timed out", func() { f.status = ssmtypes.CommandInvocationStatusTimedOut }, "did not finish: TimedOut"},
		{"cut", func() { f.stdoutPad = strings.Repeat("x", ssmStdoutLimit) }, "it may be cut"},
	}
	for _, c := range cases {
		f.manage("i-0web", ssmtypes.PingStatusOnline)
		f.status, f.stdoutPad, f.sent = "", "", nil
		c.setup()
		// Instance Connect fails too, so the error shows why Run Command did.
		r.ic.err = &fakeAPIError{"EC2InstanceUnavailableException", "try later"}
		err := r.run("list", "web-1")
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "EC2 Instance Connect: pushing a key") {
			t.Errorf("%s: %v", c.name, err)
		}
		if c.name == "offline" && len(f.sent) != 0 {
			t.Errorf("offline: SendCommand called")
		}
		// With Instance Connect working, it takes over.
		r.ic.err = nil
		if err := r.run("list", "web-1"); err != nil || !strings.Contains(r.h.stderr.String(), "with a one-time EC2 Instance Connect key") {
			t.Errorf("%s: fallback %v\n%s", c.name, err, r.h.stderr.String())
		}
	}

	// DescribeInstanceInformation denied: SendCommand decides.
	f.manage("i-0web", ssmtypes.PingStatusOnline)
	f.status, f.stdoutPad, f.sent = "", "", nil
	f.describeErr = &fakeAPIError{"AccessDeniedException", "not authorized to perform ssm:DescribeInstanceInformation"}
	calls := len(r.ic.calls)
	if err := r.run("list", "web-1"); err != nil {
		t.Fatalf("describe denied: %v\n%s", err, r.h.stderr.String())
	}
	if len(f.sent) == 0 || len(r.ic.calls) != calls {
		t.Errorf("describe denied: sent %d, Instance Connect calls %d", len(f.sent), len(r.ic.calls)-calls)
	}
}
