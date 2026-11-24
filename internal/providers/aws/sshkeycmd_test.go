package aws

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2instanceconnect"
	"golang.org/x/crypto/ssh"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
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
	in := running("i-0web", "web-1")
	in.pub, in.image = r.srv.Host, image
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
		t.Errorf("EC2 Instance Connect used without the flag: %v", r.ic.calls)
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

	// A RHEL instance whose image is gone: ec2-user, then root.
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

// --instance-connect: no local key logs in, so a one-time key is pushed for
// the login user of the image (with the instance's zone) and the key is
// added in that session; a denied push names the IAM action (exit code 3).
func TestEC2SSHKeyInstanceConnect(t *testing.T) {
	r := newEC2KeyRig(t, "ami-0x86", []string{"ec2-user"}) // no key authorized
	_, line := newKeyLine(t, "alice@laptop")
	err := r.run("add", "web-1", "--ssh-key", line)
	if err == nil || !strings.Contains(err.Error(), "or use --instance-connect") || strings.Contains(err.Error(), "installed on the image") {
		t.Fatalf("no key: %v", err)
	}
	if err := r.run("add", "web-1", "--ssh-key", line, "--instance-connect"); err != nil {
		t.Fatalf("%v\n%s", err, r.h.stderr.String())
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

	r.ic.err = &fakeAPIError{"AccessDeniedException", "not authorized to perform ec2-instance-connect:SendSSHPublicKey"}
	_, other := newKeyLine(t, "bob@desk")
	err = r.run("add", "web-1", "--ssh-key", other, "--instance-connect")
	if !errors.Is(err, platform.ErrUnauthorized) || !strings.Contains(err.Error(), "IAM action ec2-instance-connect:SendSSHPublicKey") {
		t.Fatalf("denied: %v", err)
	}

	// AuthException (no access to the instance or OS user) is exit code 3 too.
	r.ic.err = &fakeAPIError{"AuthException", "you do not have access to the EC2 instance"}
	err = r.run("add", "web-1", "--ssh-key", other, "--instance-connect")
	if !errors.Is(err, platform.ErrUnauthorized) || !strings.Contains(err.Error(), "IAM action ec2-instance-connect:SendSSHPublicKey") {
		t.Fatalf("auth exception: %v", err)
	}

	// An image without EC2 Instance Connect: the hint names the condition.
	r.addImage("ami-0deb", "debian-12-amd64-20261101", "Debian 12")
	r.inst.image = "ami-0deb"
	r.ic.err = nil
	err = r.run("add", "web-1", "--ssh-key", other)
	if err == nil || !strings.Contains(err.Error(), "when EC2 Instance Connect is installed on the image") || !strings.Contains(err.Error(), "admin") {
		t.Fatalf("debian: %v", err)
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
