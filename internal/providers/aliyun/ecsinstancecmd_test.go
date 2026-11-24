package aliyun

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

const alinux4 = "aliyun_4_x64_20G_alibase_20261103.vhd"

// siteNet is an existing network: the default VPC with both vSwitches and
// the default security group holding the default rules.
func siteNet(f *fakeECS) {
	f.images = realImages()
	f.addVPCFull("vpc-1", "cn-shanghai-vpc", "172.16.0.0/12", false)
	f.addVSwitch("vsw-b", "cn-shanghai-switch-b", "vpc-1", "cn-shanghai-b", "172.16.0.0/22")
	f.addVSwitch("vsw-c", "cn-shanghai-switch-c", "vpc-1", "cn-shanghai-c", "172.16.4.0/22")
	f.addGroup("sg-1", "sg-common", "vpc-1")
	f.addRule("sg-1", "icmp", "-1/-1", "0.0.0.0/0", "Accept")
	f.addRule("sg-1", "tcp", "80/80", "0.0.0.0/0", "Accept")
	f.addRule("sg-1", "tcp", "443/443", "0.0.0.0/0", "Accept")
}

func TestInstanceGetByRegion(t *testing.T) {
	h, f, _ := computeHarness(t, app.Flags{})
	in := f.addVM("i-1", "site-a", instRunning, "ecs.u1-c1m1.large", "vpc-1", "vsw-b")
	in["EipAddress"] = map[string]any{"AllocationId": "eip-1", "IpAddress": "203.0.113.10", "Bandwidth": 200}
	if err := h.run("ecs", "instance", "get", "site-a", "--region", "cn-shanghai"); err != nil {
		t.Fatal(err)
	}
	var d instanceDetail
	h.jsonOut(&d)
	if d.ID != "i-1" || d.Profile != "ali" || d.PublicIP != "203.0.113.10" || d.PrivateIP != "172.16.0.10" || d.EIP == nil ||
		d.EIP.AllocationID != "eip-1" || d.VSwitchID != "vsw-b" || d.KeyPair != "ops" || d.CreatedAt != "2026-11-17T16:10:00Z" || d.Zone != "cn-shanghai-b" {
		t.Errorf("detail = %+v", d)
	}
	// Without an EIP, "eip" is null.
	in["EipAddress"] = map[string]any{"AllocationId": "", "InternetChargeType": "", "IpAddress": ""}
	if err := h.run("ecs", "instance", "get", "i-1", "--region", "cn-shanghai"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.stdout.String(), `"eip": null`) {
		t.Errorf("stdout = %s", h.stdout.String())
	}
}

func TestInstanceGetThroughInventory(t *testing.T) {
	h, f, _ := computeHarness(t, app.Flags{})
	f.addVM("i-1", "site-a", instRunning, "t", "vpc-1", "vsw-b")
	// Not in the inventory: one sync finds it.
	if err := h.run("ecs", "instance", "get", "site-a"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	var d instanceDetail
	h.jsonOut(&d)
	if d.ID != "i-1" || d.Region != "cn-shanghai" {
		t.Errorf("detail = %+v", d)
	}
	if err := h.run("ecs", "instance", "get", "nosuch"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing = %v", err)
	}
	// Offline: the inventory as it is.
	h.rt.Flags.Offline = true
	if err := h.run("ecs", "instance", "get", "site-a"); err != nil {
		t.Fatal(err)
	}
	if err := h.run("ecs", "instance", "get", "nosuch"); !errors.Is(err, app.ErrOffline) {
		t.Errorf("offline miss = %v", err)
	}
}

func TestInstanceGetDuplicateNames(t *testing.T) {
	h, f, _ := computeHarness(t, app.Flags{})
	f.addVM("i-1", "site-a", instRunning, "t", "vpc-1", "vsw-b")
	f.addVM("i-2", "site-a", instStopped, "t", "vpc-1", "vsw-b")
	f.addVM("i-3", "SITE-A", instStopped, "t", "vpc-1", "vsw-b")
	var amb *app.AmbiguousError
	if err := h.run("ecs", "instance", "get", "site-a", "--region", "cn-shanghai"); !errors.As(err, &amb) || len(amb.Candidates) != 2 {
		t.Errorf("err = %v", err)
	}
	if err := h.run("ecs", "instance", "get", "site-a"); !errors.As(err, &amb) {
		t.Errorf("through the inventory: %v", err)
	}
}

func TestInstanceCreate(t *testing.T) {
	h, f, _ := computeHarness(t, app.Flags{})
	siteNet(f)
	f.addKeyPair("ops", "aa", "2026-11-17T16:10Z")
	err := h.run("ecs", "instance", "create", "site-a", "--type", "ecs.u1-c1m2.large", "--security-group", "sg-common",
		"--key-pair", "ops", "--disk", "40", "--wait")
	if err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if !slices.Equal(f.writes, []string{"RunInstances"}) {
		t.Fatalf("writes = %v", f.writes)
	}
	run := h.api.callsFor("RunInstances")[0]
	if run.Get("VSwitchId") != "vsw-b" || run.Get("SecurityGroupId") != "sg-1" || run.Get("SystemDisk.Size") != "40" || run.Get("InstanceType") != "ecs.u1-c1m2.large" {
		t.Errorf("RunInstances = %v", run)
	}
	assertKeyOnly(t, run, "ops")
	rep := reportOf(t, h)
	if c := changeOf(t, rep, "instance/site-a status"); !strings.HasPrefix(c.Detail, "Running") {
		t.Errorf("status = %+v", c)
	}
	// The name is taken now.
	err = h.run("ecs", "instance", "create", "site-a", "--type", "t", "--security-group", "sg-common", "--key-pair", "ops")
	if err == nil || !strings.Contains(err.Error(), "already exists") || errors.Is(err, app.ErrUsage) {
		t.Errorf("duplicate = %v", err)
	}
	// Usage errors before anything is read.
	for _, args := range [][]string{
		{"ecs", "instance", "create", "web", "--security-group", "sg-common", "--key-pair", "ops"},
		{"ecs", "instance", "create", "web", "--type", "t", "--key-pair", "ops"},
		{"ecs", "instance", "create", "web", "--type", "t", "--security-group", "x", "--disk", "0"},
		{"ecs", "instance", "create", "web", "--type", "t", "--security-group", "x", "--os", "ubuntu"},
		{"ecs", "instance", "create", "web", "--type", "t", "--security-group", "x", "--ssh-key", "/tmp/id.pub"},
	} {
		if err := h.run(args...); !errors.Is(err, app.ErrUsage) && !errors.Is(err, platform.ErrInvalidInput) {
			t.Errorf("%v = %v", args, err)
		}
	}
}

func TestInstanceDelete(t *testing.T) {
	t.Run("non-interactive needs --yes", func(t *testing.T) {
		h, f, _ := computeHarness(t, app.Flags{})
		f.addVM("i-1", "site-a", instRunning, "t", "vpc-1", "vsw-b")
		if err := h.run("ecs", "instance", "delete", "site-a"); !errors.Is(err, app.ErrUsage) {
			t.Errorf("err = %v", err)
		}
		if len(h.api.callsFor("DescribeInstances")) != 0 || len(f.writes) != 0 {
			t.Error("the account was read before the refusal")
		}
	})
	t.Run("running is stopped first", func(t *testing.T) {
		h, f, _ := computeHarness(t, app.Flags{Yes: true})
		in := f.addVM("i-1", "site-a", instRunning, "t", "vpc-1", "vsw-b")
		in["EipAddress"] = map[string]any{"AllocationId": "eip-1", "IpAddress": "203.0.113.10"}
		f.addEIP("eip-1", "203.0.113.10", "InUse", "i-1", "EcsInstance", 0, "BGP_PRO")
		f.initializing["i-1"] = 1
		if err := h.run("ecs", "instance", "delete", "site-a"); err != nil {
			t.Fatalf("%v\n%s", err, h.stderr.String())
		}
		if !slices.Equal(f.writes, []string{"StopInstance", "DeleteInstance", "DeleteInstance"}) {
			t.Fatalf("writes = %v", f.writes)
		}
		if q := h.api.callsFor("DeleteInstance"); q[1].Get("Force") != "" {
			t.Errorf("forced: %v", q[1])
		}
		if !strings.Contains(h.stderr.String(), "EIP 203.0.113.10 (eip-1) was unbound and is still billed") {
			t.Errorf("stderr = %s", h.stderr.String())
		}
		rep := reportOf(t, h)
		if len(rep.Changes) != 2 || rep.Changes[0].Detail != "stop; stopped" || rep.Changes[1].Action != platform.Deleted {
			t.Errorf("changes = %+v", rep.Changes)
		}
	})
	t.Run("--force deletes at once", func(t *testing.T) {
		h, f, _ := computeHarness(t, app.Flags{Yes: true})
		f.addVM("i-1", "site-a", instRunning, "t", "vpc-1", "vsw-b")
		if err := h.run("ecs", "instance", "delete", "site-a", "--force"); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(f.writes, []string{"DeleteInstance"}) || h.api.callsFor("DeleteInstance")[0].Get("Force") != "true" {
			t.Errorf("writes = %v", f.writes)
		}
	})
	t.Run("--wait waits until it is gone", func(t *testing.T) {
		h, f, _ := computeHarness(t, app.Flags{Yes: true})
		f.addVM("i-1", "site-a", instStopped, "t", "vpc-1", "vsw-b")
		if err := h.run("ecs", "instance", "delete", "site-a", "--wait"); err != nil {
			t.Fatalf("%v\n%s", err, h.stderr.String())
		}
		if rep := reportOf(t, h); len(rep.Changes) != 1 || rep.Changes[0].Detail != "deleted; gone" {
			t.Errorf("changes = %+v", rep.Changes)
		}
	})
	t.Run("deletion protection", func(t *testing.T) {
		h, f, _ := computeHarness(t, app.Flags{Yes: true})
		f.addVM("i-1", "site-a", instStopped, "t", "vpc-1", "vsw-b")["DeletionProtection"] = true
		err := h.run("ecs", "instance", "delete", "site-a")
		if err == nil || !strings.Contains(err.Error(), "deletion protection") || len(f.writes) != 0 {
			t.Errorf("err = %v, writes %v", err, f.writes)
		}
	})
	t.Run("dry run", func(t *testing.T) {
		h, f, _ := computeHarness(t, app.Flags{DryRun: true})
		f.addVM("i-1", "site-a", instStopped, "t", "vpc-1", "vsw-b")
		if err := h.run("ecs", "instance", "delete", "site-a"); err != nil || len(f.writes) != 0 {
			t.Errorf("err = %v, writes %v", err, f.writes)
		}
		if rep := reportOf(t, h); len(rep.Changes) != 1 || rep.Changes[0].Action != platform.WouldDelete {
			t.Errorf("changes = %+v", rep.Changes)
		}
	})
}

func TestInstanceReboot(t *testing.T) {
	h, f, _ := computeHarness(t, app.Flags{})
	f.addVM("i-1", "site-a", instRunning, "t", "vpc-1", "vsw-b")
	// --force cuts the power: the non-interactive flow needs --yes.
	if err := h.run("ecs", "instance", "reboot", "site-a", "--force"); !errors.Is(err, app.ErrUsage) || len(h.api.callsFor("RebootInstance")) != 0 {
		t.Fatalf("--force without --yes = %v", err)
	}
	h.rt.Flags.Yes = true
	if err := h.run("ecs", "instance", "reboot", "site-a", "--wait", "--force"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if q := h.api.callsFor("RebootInstance"); len(q) != 1 || q[0].Get("ForceStop") != "true" {
		t.Errorf("reboot = %v", q)
	}
	// The first poll still said Running: the wait went on until the end.
	if len(f.seq["i-1"]) != 1 {
		t.Errorf("wait ended early: %v", f.seq["i-1"])
	}
	f.vm("i-1")["Status"] = instStopped
	f.seq["i-1"] = nil
	if err := h.run("ecs", "instance", "reboot", "site-a"); err == nil || !strings.Contains(err.Error(), "only a Running instance") {
		t.Errorf("stopped = %v", err)
	}
}

func TestInstanceResize(t *testing.T) {
	t.Run("same type", func(t *testing.T) {
		h, f, _ := computeHarness(t, app.Flags{})
		f.addVM("i-1", "site-a", instRunning, "ecs.u1-c1m1.large", "vpc-1", "vsw-b")
		if err := h.run("ecs", "instance", "resize", "site-a", "--type", "ecs.u1-c1m1.large"); err != nil || len(f.writes) != 0 {
			t.Fatalf("%v, writes %v", err, f.writes)
		}
		if rep := reportOf(t, h); rep.Changes[0].Action != platform.Unchanged {
			t.Errorf("changes = %+v", rep.Changes)
		}
	})
	t.Run("running: stop, modify, start", func(t *testing.T) {
		h, f, _ := computeHarness(t, app.Flags{})
		f.addVM("i-1", "site-a", instRunning, "ecs.u1-c1m1.large", "vpc-1", "vsw-b")
		if err := h.run("ecs", "instance", "resize", "site-a", "--type", "ecs.u1-c1m2.large"); !errors.Is(err, app.ErrUsage) {
			t.Fatalf("without --yes: %v", err)
		}
		h.rt.Flags.Yes = true
		if err := h.run("ecs", "instance", "resize", "site-a", "--type", "ecs.u1-c1m2.large", "--wait"); err != nil {
			t.Fatalf("%v\n%s", err, h.stderr.String())
		}
		if !slices.Equal(f.writes, []string{"StopInstance", "ModifyInstanceSpec", "StartInstance"}) {
			t.Fatalf("writes = %v", f.writes)
		}
		if f.vm("i-1")["InstanceType"] != "ecs.u1-c1m2.large" || f.vm("i-1")["Status"] != instRunning {
			t.Errorf("instance = %v", f.vm("i-1"))
		}
	})
	t.Run("stopped stays stopped", func(t *testing.T) {
		h, f, _ := computeHarness(t, app.Flags{})
		f.addVM("i-1", "site-a", instStopped, "ecs.u1-c1m1.large", "vpc-1", "vsw-b")
		if err := h.run("ecs", "instance", "resize", "site-a", "--type", "ecs.u1-c1m2.large"); err != nil {
			t.Fatalf("%v\n%s", err, h.stderr.String())
		}
		if !slices.Equal(f.writes, []string{"ModifyInstanceSpec"}) {
			t.Fatalf("writes = %v", f.writes)
		}
	})
}

func TestInstanceResizeStartAndWaitPort(t *testing.T) {
	t.Run("--start starts a stopped instance", func(t *testing.T) {
		h, f, _ := computeHarness(t, app.Flags{})
		f.addVM("i-1", "site-a", instStopped, "ecs.u1-c1m1.large", "vpc-1", "vsw-b")
		if err := h.run("ecs", "instance", "resize", "site-a", "--type", "ecs.u1-c1m2.large", "--start"); err != nil {
			t.Fatalf("%v\n%s", err, h.stderr.String())
		}
		if !slices.Equal(f.writes, []string{"ModifyInstanceSpec", "StartInstance"}) {
			t.Fatalf("writes = %v", f.writes)
		}
	})
	t.Run("--start=false leaves a running one stopped", func(t *testing.T) {
		h, f, _ := computeHarness(t, app.Flags{Yes: true})
		f.addVM("i-1", "site-a", instRunning, "ecs.u1-c1m1.large", "vpc-1", "vsw-b")
		if err := h.run("ecs", "instance", "resize", "site-a", "--type", "ecs.u1-c1m2.large", "--start=false"); err != nil {
			t.Fatalf("%v\n%s", err, h.stderr.String())
		}
		if !slices.Equal(f.writes, []string{"StopInstance", "ModifyInstanceSpec"}) {
			t.Fatalf("writes = %v", f.writes)
		}
	})
	t.Run("--wait-port", func(t *testing.T) {
		h, f, _ := computeHarness(t, app.Flags{Yes: true})
		f.addVM("i-1", "site-a", instRunning, "ecs.u1-c1m1.large", "vpc-1", "vsw-b")
		var dialed []string
		old := dialTCP
		t.Cleanup(func() { dialTCP = old })
		dialTCP = func(_ context.Context, addr string, _ time.Duration) error {
			dialed = append(dialed, addr)
			return nil
		}
		if err := h.run("ecs", "instance", "resize", "site-a", "--type", "ecs.u1-c1m2.large", "--wait-port", "22"); err != nil {
			t.Fatalf("%v\n%s", err, h.stderr.String())
		}
		if len(dialed) != 1 || !strings.HasSuffix(dialed[0], ":22") || !strings.Contains(h.stderr.String(), "accepts connections") {
			t.Errorf("dialed %v, stderr %s", dialed, h.stderr.String())
		}
	})
}

func TestInstanceStartStopWait(t *testing.T) {
	h, f, _ := computeHarness(t, app.Flags{Yes: true})
	f.addVM("i-1", "site-a", instRunning, "t", "vpc-1", "vsw-b")
	if err := h.run("ecs", "instance", "stop", "i-1", "--wait"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if f.vm("i-1")["Status"] != instStopped || !strings.Contains(h.stderr.String(), "is Stopped") {
		t.Errorf("status = %v, stderr %s", f.vm("i-1")["Status"], h.stderr.String())
	}
	if err := h.run("ecs", "instance", "start", "i-1", "--wait"); err != nil {
		t.Fatal(err)
	}
	if f.vm("i-1")["Status"] != instRunning || !strings.Contains(h.stderr.String(), "is Running") {
		t.Errorf("status = %v, stderr %s", f.vm("i-1")["Status"], h.stderr.String())
	}
}

// On a terminal, delete and resize ask (default no); declining is "nothing
// to do", not a failure.
func TestInstanceInteractiveConfirmations(t *testing.T) {
	for _, tc := range []struct {
		answer string
		done   bool
	}{{"y\n", true}, {"n\n", false}, {"\n", false}} {
		h, f, _ := computeHarness(t, app.Flags{})
		f.addVM("i-1", "site-a", instRunning, "ecs.u1-c1m1.large", "vpc-1", "vsw-b")
		f.addVM("i-2", "site-b", instRunning, "ecs.u1-c1m1.large", "vpc-1", "vsw-b")
		h.rt.Picker = terminalStub{t}

		h.rt.Stdin = strings.NewReader(tc.answer)
		err := h.run("ecs", "instance", "delete", "site-a", "--force")
		if !strings.Contains(h.stderr.String(), "Delete instance site-a (i-1)? (y/N)") {
			t.Errorf("delete question: %q", h.stderr.String())
		}
		if tc.done != (err == nil) || !tc.done && !errors.Is(err, platform.ErrNothingToDo) || tc.done == (f.vm("i-1") != nil) {
			t.Errorf("answer %q: delete = %v, instance left %v", tc.answer, err, f.vm("i-1") != nil)
		}

		h.rt.Stdin = strings.NewReader(tc.answer)
		err = h.run("ecs", "instance", "resize", "site-b", "--type", "ecs.u1-c1m2.large")
		if !strings.Contains(h.stderr.String(), "Stop instance site-b to change its type from ecs.u1-c1m1.large to ecs.u1-c1m2.large?") {
			t.Errorf("resize question: %q", h.stderr.String())
		}
		if tc.done != (err == nil) || !tc.done && !errors.Is(err, platform.ErrNothingToDo) || tc.done != (f.vm("i-2")["InstanceType"] == "ecs.u1-c1m2.large") {
			t.Errorf("answer %q: resize = %v, type %v", tc.answer, err, f.vm("i-2")["InstanceType"])
		}
	}
}

func TestInstanceCreateAgainAfterDelete(t *testing.T) {
	h, f, _ := computeHarness(t, app.Flags{})
	siteNet(f)
	f.addKeyPair("ops", "aa", "2026-11-17T16:10Z")
	args := []string{"ecs", "instance", "create", "site-a", "--type", "ecs.u1-c1m1.large", "--security-group", "sg-common", "--key-pair", "ops"}
	if err := h.run(args...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	first := f.instances[0]["InstanceId"].(string)
	// Deleted since: the same request (the same client token) answers the
	// deleted instance again, so a new token is used.
	f.instances = nil
	if err := h.run(args...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	runs := h.api.callsFor("RunInstances")
	if len(runs) != 3 || runs[1].Get("ClientToken") != runs[0].Get("ClientToken") || runs[2].Get("ClientToken") == runs[1].Get("ClientToken") {
		t.Fatalf("RunInstances calls = %d", len(runs))
	}
	if len(f.instances) != 1 || f.instances[0]["InstanceId"] == first {
		t.Errorf("instances = %v", f.instances)
	}
	if c := changeOf(t, reportOf(t, h), "instance/site-a"); c.ID == first || c.ID == "" {
		t.Errorf("change = %+v", c)
	}
}

// assertKeyOnly checks that a Linux RunInstances binds the key pair and
// sets no password: none sent, none inherited from the image.
func assertKeyOnly(t *testing.T, run url.Values, keyPair string) {
	t.Helper()
	if run.Get("KeyPairName") != keyPair {
		t.Errorf("KeyPairName = %q, want %q", run.Get("KeyPairName"), keyPair)
	}
	for _, k := range []string{"Password", "PasswordInherit", "UserData"} {
		if run.Has(k) {
			t.Errorf("RunInstances sends %s", k)
		}
	}
}

// A Linux create without a key pair fails before anything is read.
func TestInstanceCreateRequiresAKeyPair(t *testing.T) {
	h, f, _ := computeHarness(t, app.Flags{})
	siteNet(f)
	err := h.run("ecs", "instance", "create", "site-a", "--type", "ecs.u1-c1m2.large", "--security-group", "sg-common")
	if !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--key-pair") || !strings.Contains(err.Error(), "never a password") {
		t.Fatalf("no key = %v", err)
	}
	if len(f.writes) != 0 || len(h.api.callsFor("DescribeInstances")) != 0 {
		t.Errorf("writes %v, calls %d", f.writes, len(h.api.callsFor("DescribeInstances")))
	}
}
