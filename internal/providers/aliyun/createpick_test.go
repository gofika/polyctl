package aliyun

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// withLocalKey puts line as ~/.ssh/id_ed25519.pub of a fresh home.
func withLocalKey(t *testing.T, line string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519.pub"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The user's example: on a terminal, create of a Linux instance without
// --key-pair / --ssh-key / --ssh-key-file lists the key pairs of the
// region (the one holding ~/.ssh/id_ed25519.pub marked and preselected).
// Without a name, --type and --security-group it also asks for the name
// (checked as typed), the size (x86 sizes in stock in the zones of the
// default vSwitches) and the security group of the vSwitch's VPC.
func TestInstanceCreateInteractiveAsksWhatIsMissing(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	line := testKey(t, "ed25519")
	withLocalKey(t, line)
	h, f, _ := sizeHarness(t, app.Flags{})
	siteNet(f)
	f.addKeyPair("laptop", md5Hex(t, line), "2026-11-17T13:54Z")
	f.addKeyPair("other", fmt.Sprintf("%032x", 7), "2026-11-17T13:54Z")

	p := prompttest.New(t, "i-bad", "site-a", "2H4G", "sg-1", "laptop")
	h.rt.Picker = p
	if err := h.run("ecs", "instance", "create", "--no-wait"); err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	run := h.api.callsFor("RunInstances")[0]
	if run.Get("InstanceName") != "site-a" || run.Get("InstanceType") != "ecs.e-c1m2.large" || run.Get("SecurityGroupId") != "sg-1" || run.Get("KeyPairName") != "laptop" {
		t.Errorf("RunInstances = %v", run)
	}
	sizes := p.Find("Instance size (the cheapest x86 type of the size is used)")
	if v := prompttest.Values(sizes.Options); strings.Contains(v, "ARM") || sizes.Default != "2H4G" || !strings.Contains(v, "2H2G") {
		t.Errorf("sizes %q (default %q)", v, sizes.Default)
	}
	kp := p.Find("Key pair")
	if kp.Default != "laptop" || !strings.Contains(prompttest.Labels(kp.Options), "[matches ~/.ssh/id_ed25519.pub]") {
		t.Errorf("key pairs (default %q):\n%s", kp.Default, prompttest.Labels(kp.Options))
	}
	sg := p.Find("Security group (VPC vpc-1)")
	if sg.Default != "sg-1" || !strings.HasSuffix(prompttest.Labels(sg.Options), "Create a new security group...") {
		t.Errorf("groups (default %q):\n%s", sg.Default, prompttest.Labels(sg.Options))
	}
	if c := h.api.callsFor("ImportKeyPair"); len(c) != 0 {
		t.Errorf("an existing key pair was chosen, but ImportKeyPair ran: %v", c)
	}
}

// "Create a new security group..." creates it in the vSwitch's VPC with the
// default rules before the instance; a name the VPC already has is refused
// as it is typed.
func TestInstanceCreateInteractiveNewSecurityGroup(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, f, _ := computeHarness(t, app.Flags{})
	siteNet(f)
	f.addKeyPair("ops", "aa", "2026-11-17T16:10Z")
	p := prompttest.New(t, prompttest.Label("Create a new security group"), "sg-common", "web")
	h.rt.Picker = p
	err := h.run("ecs", "instance", "create", "site-a", "--type", "ecs.u1-c1m1.large", "--key-pair", "ops", "--no-wait")
	if err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if len(f.writes) < 3 || f.writes[0] != "CreateSecurityGroup" || f.writes[1] != "AuthorizeSecurityGroup" || f.writes[len(f.writes)-1] != "RunInstances" {
		t.Errorf("writes = %v", f.writes)
	}
	cs := h.api.callsFor("CreateSecurityGroup")[0]
	if cs.Get("SecurityGroupName") != "web" || cs.Get("VpcId") != "vpc-1" {
		t.Errorf("CreateSecurityGroup = %v", cs)
	}
	if n := len(permissions(h.api.callsFor("AuthorizeSecurityGroup")[0])); n != 3 {
		t.Errorf("rules = %d, want the 3 default ones", n)
	}
}

// Leaving a question creates nothing; the non-interactive flow still
// needs --security-group (and the name, the type and a key) before
// anything is read.
func TestInstanceCreateInteractiveCancelAndNonInteractive(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, f, _ := computeHarness(t, app.Flags{})
	siteNet(f)
	f.addKeyPair("ops", "aa", "2026-11-17T16:10Z")
	h.rt.Picker = prompttest.New(t, prompttest.Abort{})
	if err := h.run("ecs", "instance", "create", "site-a", "--type", "ecs.u1-c1m1.large", "--key-pair", "ops"); !errors.Is(err, prompt.ErrAborted) || len(f.writes) != 0 {
		t.Errorf("abort = %v, writes %v", err, f.writes)
	}

	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	err := h.run("ecs", "instance", "create", "site-a", "--type", "ecs.u1-c1m1.large", "--key-pair", "ops")
	if !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--security-group is required") {
		t.Errorf("non-interactive = %v", err)
	}
	if err := h.run("ecs", "instance", "create", "site-a", "--security-group", "sg-common", "--key-pair", "ops"); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--type") {
		t.Errorf("non-interactive without --type = %v", err)
	}
	if len(f.writes) != 0 {
		t.Errorf("writes = %v", f.writes)
	}
}

// Without the default vSwitches, the interactive create offers the
// Available vSwitches of the region.
func TestInstanceCreateInteractivePicksVSwitch(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, f, _ := computeHarness(t, app.Flags{})
	siteNet(f)
	f.vswitches = nil
	f.addVSwitch("vsw-x", "app", "vpc-1", "cn-shanghai-d", "172.16.8.0/22")
	f.addKeyPair("ops", "aa", "2026-11-17T16:10Z")
	p := prompttest.New(t, "vsw-x")
	h.rt.Picker = p
	if err := h.run("ecs", "instance", "create", "site-a", "--type", "ecs.u1-c1m1.large", "--security-group", "sg-common", "--key-pair", "ops", "--no-wait"); err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if run := h.api.callsFor("RunInstances")[0]; run.Get("VSwitchId") != "vsw-x" {
		t.Errorf("RunInstances = %v", run)
	}
	if l := prompttest.Labels(p.Find("vSwitch").Options); !strings.Contains(l, "app  vsw-x  cn-shanghai-d  172.16.8.0/22  cn-shanghai-vpc (vpc-1)") {
		t.Errorf("labels: %s", l)
	}
}

// defaults.aliyun.ecs_key_pair names the key pair used without asking,
// in both flows, when it exists in the region.
func TestInstanceCreateDefaultKeyPair(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, f, _ := computeHarness(t, app.Flags{NonInteractive: true})
	siteNet(f)
	f.addKeyPair("ops", "aa", "2026-11-17T16:10Z")
	cfg, _ := h.rt.Config()
	cfg.Defaults = config.Defaults{"aliyun": {"ecs_key_pair": "ops"}}
	if err := h.run("ecs", "instance", "create", "site-a", "--type", "ecs.u1-c1m1.large", "--security-group", "sg-common", "--no-wait"); err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	if run := h.api.callsFor("RunInstances")[0]; run.Get("KeyPairName") != "ops" {
		t.Errorf("RunInstances = %v", run)
	}
}

// ensure without <name> offers the instances of the region, or a new name.
func TestInstanceEnsureInteractiveName(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, f, _ := computeHarness(t, app.Flags{DryRun: true})
	siteNet(f)
	f.addVM("i-1", "site-a", instRunning, "ecs.u1-c1m1.large", "vpc-1", "vsw-b")
	f.addKeyPair("ops", "aa", "2026-11-17T16:10Z")
	p := prompttest.New(t, prompttest.Label("New instance name"), "site-b")
	h.rt.Picker = p
	if err := h.run("ecs", "instance", "ensure", "--key-pair", "ops"); err != nil {
		t.Fatalf("ensure: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if l := prompttest.Labels(p.Asked[0].Options); !strings.Contains(l, "site-a  i-1") {
		t.Errorf("labels: %s", l)
	}
	if !strings.Contains(h.stdout.String(), "instance/site-b") {
		t.Errorf("stdout = %s", h.stdout.String())
	}
}

// key-pair import without the key and the name asks for the public key
// file (~/.ssh/*.pub, those registered marked) and a free name.
func TestKeyPairImportInteractive(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	line := testKey(t, "ed25519")
	withLocalKey(t, line)
	h, f := sgHarness(t, app.Flags{})
	f.addKeyPair("taken", fmt.Sprintf("%032x", 7), "2026-11-17T13:54Z")
	home, _ := os.UserHomeDir()
	p := prompttest.New(t, filepath.Join(home, ".ssh", "id_ed25519.pub"), "taken", "laptop")
	h.rt.Picker = p
	if err := h.run("ecs", "key-pair", "import"); err != nil {
		t.Fatalf("import: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	c := h.api.callsFor("ImportKeyPair")
	if len(c) != 1 || c[0].Get("KeyPairName") != "laptop" {
		t.Errorf("import = %v", c)
	}
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("ecs", "key-pair", "import", "x1"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("non-interactive = %v", err)
	}
}
