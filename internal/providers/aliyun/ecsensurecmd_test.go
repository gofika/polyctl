package aliyun

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

func TestInstanceEnsureCreatesTheChain(t *testing.T) {
	h, f, _ := computeHarness(t, app.Flags{})
	f.images = realImages()
	key := testKey(t, "ed25519")
	if err := h.run("ecs", "instance", "ensure", "site_a", "--ssh-key", key, "--key-pair", "ops"); err != nil {
		t.Fatalf("ensure: %v\n%s", err, h.stderr.String())
	}
	want := []string{"ImportKeyPair", "CreateVpc", "CreateVSwitch", "CreateVSwitch", "CreateSecurityGroup", "AuthorizeSecurityGroup",
		"RunInstances", "AllocateEipAddress", "AssociateEipAddress"}
	if !slices.Equal(f.writes, want) {
		t.Fatalf("writes = %v", f.writes)
	}
	run := h.api.callsFor("RunInstances")[0]
	vswB := h.api.callsFor("CreateVSwitch")[0]
	if vswB.Get("ZoneId") != "cn-shanghai-b" {
		t.Fatalf("first vSwitch = %v", vswB)
	}
	for k, v := range map[string]string{"InternetMaxBandwidthOut": "0", "InstanceChargeType": "PostPaid", "SystemDisk.Size": "20",
		"SystemDisk.Category": "cloud_essd_entry", "HostName": "site-a", "InstanceName": "site_a", "InstanceType": "ecs.u1-c1m1.large",
		"ImageId": alinux4, "KeyPairName": "ops"} {
		if run.Get(k) != v {
			t.Errorf("RunInstances %s = %q, want %q", k, run.Get(k), v)
		}
	}
	if !strings.HasPrefix(run.Get("VSwitchId"), "vsw-new") || !strings.HasPrefix(run.Get("SecurityGroupId"), "sg-new") || run.Get("ClientToken") == "" {
		t.Errorf("RunInstances = %v", run)
	}
	auth := h.api.callsFor("AuthorizeSecurityGroup")[0]
	if len(permissions(auth)) != 3 {
		t.Errorf("rules = %v", permissions(auth))
	}
	var out instanceEnsureReport
	h.jsonOut(&out)
	var resources []string
	for _, c := range out.Changes {
		resources = append(resources, c.Resource)
	}
	wantRes := []string{"key-pair/ops", "vpc/cn-shanghai-vpc", "vswitch/cn-shanghai-switch-b", "vswitch/cn-shanghai-switch-c",
		"security-group/sg-common", "security-group/sg-common/rule", "security-group/sg-common/rule", "security-group/sg-common/rule",
		"instance/site_a", "instance/site_a status", "eip/site_a"}
	if !slices.Equal(resources, wantRes) {
		t.Errorf("resources = %v", resources)
	}
	st := changeOf(t, out.Report, "instance/site_a status")
	if st.Action != platform.Updated || !strings.HasPrefix(st.Detail, "Running (waited") {
		t.Errorf("status = %+v", st)
	}
	if !strings.HasPrefix(out.Result.InstanceID, "i-new") || !strings.HasPrefix(out.Result.PublicIP, "203.0.113.") {
		t.Errorf("result = %+v", out.Result)
	}
	if e := changeOf(t, out.Report, "eip/site_a"); e.Attrs["ip"] != out.Result.PublicIP {
		t.Errorf("eip = %+v", e)
	}

	// Again: every row unchanged, nothing written.
	f.writes = nil
	if err := h.run("ecs", "instance", "ensure", "site_a", "--ssh-key", key, "--key-pair", "ops"); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("second run wrote %v", f.writes)
	}
	out = instanceEnsureReport{}
	h.jsonOut(&out)
	for _, c := range out.Changes {
		if c.Action != platform.Unchanged {
			t.Errorf("second run: %+v", c)
		}
	}
	if out.Result.PublicIP == "" {
		t.Errorf("result = %+v", out.Result)
	}
}

func TestInstanceEnsureNonInteractiveNeedsKeyPairName(t *testing.T) {
	h, f, _ := computeHarness(t, app.Flags{})
	siteNet(f)
	err := h.run("ecs", "instance", "ensure", "site-a", "--ssh-key", testKey(t, "ed25519"))
	if !errors.Is(err, platform.ErrInvalidInput) && !errors.Is(err, app.ErrUsage) {
		t.Errorf("err = %v", err)
	}
	if len(f.writes) != 0 {
		t.Errorf("writes = %v", f.writes)
	}
}

func TestInstanceEnsureExistingWithoutEIP(t *testing.T) {
	h, f, _ := computeHarness(t, app.Flags{})
	f.addVM("i-1", "site-a", instRunning, "ecs.u1-c1m1.large", "vpc-1", "vsw-b")
	f.addEIP("eip-idle", "203.0.113.10", "Available", "", "", 0, "BGP_PRO")
	// No key, no network: an existing instance needs none of them.
	if err := h.run("ecs", "instance", "ensure", "site-a"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if !slices.Equal(f.writes, []string{"AssociateEipAddress"}) {
		t.Fatalf("writes = %v", f.writes)
	}
	var out instanceEnsureReport
	h.jsonOut(&out)
	if c := changeOf(t, out.Report, "eip/site-a"); c.Action != platform.Updated || c.ID != "eip-idle" {
		t.Errorf("eip = %+v", c)
	}
	if out.Result.InstanceID != "i-1" || out.Result.PublicIP != "203.0.113.10" {
		t.Errorf("result = %+v", out.Result)
	}
	// Bound now: nothing more to do.
	f.writes = nil
	if err := h.run("ecs", "instance", "ensure", "site-a"); err != nil || len(f.writes) != 0 {
		t.Fatalf("%v, writes %v", err, f.writes)
	}
}

func TestInstanceEnsureAllocatesWithoutIdleEIP(t *testing.T) {
	h, f, _ := computeHarness(t, app.Flags{})
	f.addVM("i-1", "site-a", instRunning, "t", "vpc-1", "vsw-b")
	f.associateFails = 2
	if err := h.run("ecs", "instance", "ensure", "site-a"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if !slices.Equal(f.writes, []string{"AllocateEipAddress", "AssociateEipAddress", "AssociateEipAddress", "AssociateEipAddress"}) {
		t.Fatalf("writes = %v", f.writes)
	}
}

func TestInstanceEnsureAddsOnlyTheMissingVSwitch(t *testing.T) {
	h, f, _ := computeHarness(t, app.Flags{})
	siteNet(f)
	f.vswitches = f.vswitches[:1] // switch-c is missing
	if err := h.run("ecs", "instance", "ensure", "site-a", "--key-pair", "ops", "--ssh-key", testKey(t, "ed25519"), "--eip=false"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if !slices.Equal(f.writes, []string{"ImportKeyPair", "CreateVSwitch", "RunInstances"}) {
		t.Fatalf("writes = %v", f.writes)
	}
	if q := h.api.callsFor("CreateVSwitch")[0]; q.Get("ZoneId") != "cn-shanghai-c" || q.Get("CidrBlock") != "172.16.4.0/22" {
		t.Errorf("CreateVSwitch = %v", q)
	}
	if q := h.api.callsFor("RunInstances")[0]; q.Get("VSwitchId") != "vsw-b" || q.Get("SecurityGroupId") != "sg-1" {
		t.Errorf("RunInstances = %v", q)
	}
}

func TestInstanceEnsureDryRun(t *testing.T) {
	h, f, _ := computeHarness(t, app.Flags{DryRun: true})
	f.images = realImages()
	if err := h.run("ecs", "instance", "ensure", "site-a", "--key-pair", "ops", "--ssh-key", testKey(t, "ed25519")); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if len(f.writes) != 0 {
		t.Fatalf("dry run wrote %v", f.writes)
	}
	var out instanceEnsureReport
	h.jsonOut(&out)
	if !out.DryRun || out.Result.InstanceID != platform.Pending {
		t.Errorf("report = %+v", out)
	}
	sg := changeOf(t, out.Report, "security-group/sg-common")
	inst := changeOf(t, out.Report, "instance/site-a")
	if sg.Action != platform.WouldCreate || !strings.Contains(sg.Detail, platform.Pending) || inst.Action != platform.WouldCreate ||
		!strings.Contains(inst.Detail, "ecs.u1-c1m1.large, system disk 20GiB cloud_essd_entry, image "+alinux4) {
		t.Errorf("sg = %+v, instance = %+v", sg, inst)
	}
	if c := changeOf(t, out.Report, "eip/site-a"); c.Action != platform.WouldCreate || !strings.HasPrefix(c.Detail, "allocate") {
		t.Errorf("eip = %+v", c)
	}
	if c := changeOf(t, out.Report, "instance/site-a status"); c.Action != platform.WouldUpdate || c.Detail != "wait Running" {
		t.Errorf("status = %+v", c)
	}
}

func TestInstanceEnsureTypeDiffersIsSkipped(t *testing.T) {
	h, f, _ := computeHarness(t, app.Flags{})
	in := f.addVM("i-1", "site-a", instRunning, "ecs.u1-c1m1.large", "vpc-1", "vsw-b")
	in["EipAddress"] = map[string]any{"AllocationId": "eip-1", "IpAddress": "203.0.113.10"}
	if err := h.run("ecs", "instance", "ensure", "site-a", "--type", "ecs.u1-c1m2.large", "--disk", "40"); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("writes = %v", f.writes)
	}
	rep := reportOf(t, h)
	c := changeOf(t, rep, "instance/site-a")
	if c.Action != platform.Skipped || !strings.Contains(c.Detail, "type differs: current ecs.u1-c1m1.large, want ecs.u1-c1m2.large; use resize") ||
		!strings.Contains(c.Detail, "system disk differs: current 20GiB, want 40GiB") {
		t.Errorf("change = %+v", c)
	}
}

func TestInstanceEnsureDuplicateNames(t *testing.T) {
	h, f, _ := computeHarness(t, app.Flags{})
	f.addVM("i-1", "site-a", instRunning, "t", "vpc-1", "vsw-b")
	f.addVM("i-2", "site-a", instRunning, "t", "vpc-1", "vsw-b")
	var amb *app.AmbiguousError
	if err := h.run("ecs", "instance", "ensure", "site-a"); !errors.As(err, &amb) {
		t.Errorf("err = %v", err)
	}
	if len(f.writes) != 0 {
		t.Errorf("writes = %v", f.writes)
	}
}

func TestInstanceEnsureNoWaitSkipsEIP(t *testing.T) {
	h, f, _ := computeHarness(t, app.Flags{})
	siteNet(f)
	f.addKeyPair("ops", "aa", "2026-11-17T16:10Z")
	if err := h.run("ecs", "instance", "ensure", "site-a", "--key-pair", "ops", "--no-wait"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if !slices.Equal(f.writes, []string{"RunInstances"}) {
		t.Fatalf("writes = %v", f.writes)
	}
	if c := changeOf(t, reportOf(t, h), "eip/site-a"); c.Action != platform.Skipped || !strings.Contains(c.Detail, "not Running yet") {
		t.Errorf("eip = %+v", c)
	}
}

// namePicker answers the key pair name question of the interactive flow.
type namePicker struct {
	terminalStub
	name  string
	asked []string
}

func (p *namePicker) Input(title, _ string, _ func(string) error) (string, error) {
	p.asked = append(p.asked, title)
	return p.name, nil
}

// On a terminal, ensure asks for the name of a key pair it has to create.
func TestInstanceEnsureAsksForTheKeyPairName(t *testing.T) {
	h, f, _ := computeHarness(t, app.Flags{DryRun: true})
	siteNet(f)
	p := &namePicker{terminalStub: terminalStub{t}, name: "laptop"}
	h.rt.Picker = p
	if err := h.run("ecs", "instance", "ensure", "site-a", "--ssh-key", testKey(t, "ed25519")); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if len(p.asked) != 1 || !strings.Contains(p.asked[0], "key pair") {
		t.Errorf("asked = %v", p.asked)
	}
	if c := changeOf(t, reportOf(t, h), "key-pair/laptop"); c.Action != platform.WouldCreate {
		t.Errorf("key pair = %+v", c)
	}
}

// A binding that fails reports no public address in the result.
func TestInstanceEnsureFailedBindingHasNoAddress(t *testing.T) {
	h, f, _ := computeHarness(t, app.Flags{})
	f.addVM("i-1", "site-a", instRunning, "ecs.u1-c1m1.large", "vpc-1", "vsw-b")
	f.addEIP("eip-idle", "203.0.113.10", "Available", "", "", 0, "BGP_PRO")
	f.associateFails = 100
	if err := h.run("ecs", "instance", "ensure", "site-a"); err == nil {
		t.Fatal("the binding did not fail")
	}
	var out instanceEnsureReport
	h.jsonOut(&out)
	if out.Result.InstanceID != "i-1" || out.Result.PublicIP != "" {
		t.Errorf("result = %+v", out.Result)
	}
}
