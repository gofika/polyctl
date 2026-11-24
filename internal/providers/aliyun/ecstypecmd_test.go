package aliyun

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/platform"
)

// sizeHarness is the compute harness with the 2H4G catalog.
func sizeHarness(t *testing.T, flags app.Flags) (*harness, *fakeECS, *fakeCatalog) {
	h, f, _ := computeHarness(t, flags)
	cat := sizeCatalog()
	cat.register(h.api)
	return h, f, cat
}

func TestInstanceCreateWithSize(t *testing.T) {
	h, f, _ := sizeHarness(t, app.Flags{})
	siteNet(f)
	f.addKeyPair("ops", "aa", "2026-11-17T16:10Z")
	err := h.run("ecs", "instance", "create", "site-a", "--type", "2H4G", "--security-group", "sg-common", "--key-pair", "ops", "--no-wait")
	if err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	run := h.api.callsFor("RunInstances")[0]
	// Zone d is cheaper, but the instance may only go to the default
	// vSwitches (zones b and c).
	if run.Get("InstanceType") != "ecs.e-c1m2.large" || run.Get("VSwitchId") != "vsw-c" || run.Get("SystemDisk.Category") != "cloud_essd_entry" {
		t.Errorf("RunInstances = %v", run)
	}
	if !strings.Contains(h.stderr.String(), "2H4G -> ecs.e-c1m2.large (cn-shanghai-c, 0.1 CNY/hour)") {
		t.Errorf("stderr = %s", h.stderr.String())
	}
	if c := changeOf(t, reportOf(t, h), "instance/site-a"); !strings.Contains(c.Detail, "ecs.e-c1m2.large (2H4G, 0.1 CNY/hour)") {
		t.Errorf("change = %+v", c)
	}

	// Only zone b's vSwitch exists: the choice is made there.
	h2, f2, _ := sizeHarness(t, app.Flags{})
	siteNet(f2)
	f2.vswitches = f2.vswitches[:1]
	f2.addKeyPair("ops", "aa", "2026-11-17T16:10Z")
	if err := h2.run("ecs", "instance", "create", "site-b", "--type", "2H4G", "--security-group", "sg-common", "--key-pair", "ops", "--no-wait"); err != nil {
		t.Fatalf("%v\n%s", err, h2.stderr.String())
	}
	if run := h2.api.callsFor("RunInstances")[0]; run.Get("InstanceType") != "ecs.e-c1m2.large" || run.Get("VSwitchId") != "vsw-b" {
		t.Errorf("zone b only: RunInstances = %v", run)
	}

	// --vswitch fixes the zone: a size not in stock there is exit code 4,
	// and nothing is written.
	h3, f3, cat := sizeHarness(t, app.Flags{})
	siteNet(f3)
	f3.addKeyPair("ops", "aa", "2026-11-17T16:10Z")
	cat.closedZones["cn-shanghai-c"] = true
	err = h3.run("ecs", "instance", "create", "site-c", "--type", "2H4G", "--vswitch", "vsw-c", "--security-group", "sg-common", "--key-pair", "ops")
	if !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "zone cn-shanghai-c of cn-shanghai") || len(f3.writes) != 0 {
		t.Errorf("no stock = %v, writes %v", err, f3.writes)
	}
	if q := h3.api.callsFor("DescribeAvailableResource")[0]; q.Get("ZoneId") != "cn-shanghai-c" {
		t.Errorf("fixed zone: %v", q)
	}
}

func TestInstanceCreateExactTypeResolvesNothing(t *testing.T) {
	h, f, _ := sizeHarness(t, app.Flags{})
	siteNet(f)
	f.addKeyPair("ops", "aa", "2026-11-17T16:10Z")
	if err := h.run("ecs", "instance", "create", "site-a", "--type", "ecs.u1-c1m2.large", "--security-group", "sg-common", "--key-pair", "ops", "--no-wait"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	for _, a := range []string{"DescribeAvailableResource", "DescribePrice"} {
		if n := len(h.api.callsFor(a)); n != 0 {
			t.Errorf("%s called %d times", a, n)
		}
	}
	// The one type query is the architecture of the type, for its image.
	if q := h.api.callsFor("DescribeInstanceTypes"); len(q) != 1 || q[0].Get("InstanceTypes.1") != "ecs.u1-c1m2.large" || q[0].Get("CpuArchitecture") != "" {
		t.Errorf("DescribeInstanceTypes = %v", q)
	}
	if run := h.api.callsFor("RunInstances")[0]; run.Get("InstanceType") != "ecs.u1-c1m2.large" || run.Get("VSwitchId") != "vsw-b" {
		t.Errorf("RunInstances = %v", run)
	}
	// With --image the image is read (Windows or Linux), nothing else.
	f.images = append(f.images, img("m-own", "", "Ubuntu 24.04 64 bit", "x86_64", "2026-11-01T00:00:00Z"))
	if err := h.run("ecs", "instance", "create", "site-b", "--type", "ecs.u1-c1m2.large", "--image", "m-own", "--security-group", "sg-common", "--key-pair", "ops", "--no-wait"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if n, m := len(h.api.callsFor("DescribeInstanceTypes")), len(h.api.callsFor("DescribeImages")); n != 1 || m != 2 {
		t.Errorf("--image: %d type and %d image queries in all, want 1 and 2", n, m)
	}
	if run := h.api.callsFor("RunInstances")[1]; run.Get("ImageId") != "m-own" {
		t.Errorf("RunInstances = %v", run)
	}
}

func TestInstanceSizeMalformedIsUsage(t *testing.T) {
	h, f, _ := sizeHarness(t, app.Flags{})
	f.addVM("i-1", "site-a", instStopped, "ecs.u1-c1m1.large", "vpc-1", "vsw-b")
	for _, args := range [][]string{
		{"ecs", "instance", "create", "web", "--type", "0H2G", "--security-group", "sg-common", "--key-pair", "ops"},
		{"ecs", "instance", "ensure", "web", "--type", "2H0G", "--key-pair", "ops"},
		{"ecs", "instance", "resize", "site-a", "--type", "0h4g"},
	} {
		if err := h.run(args...); !errors.Is(err, platform.ErrInvalidInput) {
			t.Errorf("%v = %v", args, err)
		}
	}
	if len(h.api.callsFor("DescribeAvailableResource")) != 0 || len(f.writes) != 0 {
		t.Errorf("malformed sizes read or wrote: writes %v", f.writes)
	}
}

func TestInstanceCreateWithSizeDryRun(t *testing.T) {
	h, f, _ := sizeHarness(t, app.Flags{DryRun: true})
	siteNet(f)
	f.addKeyPair("ops", "aa", "2026-11-17T16:10Z")
	if err := h.run("ecs", "instance", "create", "site-a", "--type", "2h4g", "--security-group", "sg-common", "--key-pair", "ops"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if len(f.writes) != 0 {
		t.Fatalf("dry run wrote %v", f.writes)
	}
	rep := reportOf(t, h)
	if c := changeOf(t, rep, "instance/site-a"); c.Action != platform.WouldCreate || !strings.Contains(c.Detail, "ecs.e-c1m2.large (2h4g, 0.1 CNY/hour), system disk 20GiB cloud_essd_entry") {
		t.Errorf("change = %+v", c)
	}
}

func TestInstanceEnsureWithSize(t *testing.T) {
	t.Run("new instance goes to the zone of the choice", func(t *testing.T) {
		h, f, _ := sizeHarness(t, app.Flags{})
		siteNet(f)
		f.addKeyPair("ops", "aa", "2026-11-17T16:10Z")
		f.addEIP("eip-1", "203.0.113.10", "Available", "", "", 0, "BGP")
		if err := h.run("ecs", "instance", "ensure", "site-a", "--type", "2H4G", "--key-pair", "ops"); err != nil {
			t.Fatalf("%v\n%s", err, h.stderr.String())
		}
		if run := h.api.callsFor("RunInstances")[0]; run.Get("InstanceType") != "ecs.e-c1m2.large" || run.Get("VSwitchId") != "vsw-c" {
			t.Errorf("RunInstances = %v", run)
		}
		var out instanceEnsureReport
		h.jsonOut(&out)
		if c := changeOf(t, out.Report, "instance/site-a"); !strings.Contains(c.Detail, "ecs.e-c1m2.large (2H4G, 0.1 CNY/hour)") {
			t.Errorf("change = %+v", c)
		}
	})
	t.Run("the default type setting takes a size; dry run with a VPC to create", func(t *testing.T) {
		h, f, _ := sizeHarness(t, app.Flags{DryRun: true})
		f.images = realImages()
		cfg, _ := h.rt.Config()
		cfg.Defaults = config.Defaults{"aliyun": {"ecs_instance_type": "2H4G"}}
		if err := h.run("ecs", "instance", "ensure", "site-a", "--key-pair", "ops", "--ssh-key", testKey(t, "ed25519")); err != nil {
			t.Fatalf("%v\n%s", err, h.stderr.String())
		}
		if len(f.writes) != 0 {
			t.Fatalf("dry run wrote %v", f.writes)
		}
		var out instanceEnsureReport
		h.jsonOut(&out)
		if c := changeOf(t, out.Report, "instance/site-a"); c.Action != platform.WouldCreate || !strings.Contains(c.Detail, "ecs.e-c1m2.large (2H4G, 0.1 CNY/hour)") {
			t.Errorf("change = %+v", c)
		}
		if !strings.Contains(h.stderr.String(), "2H4G -> ecs.e-c1m2.large (cn-shanghai-c") {
			t.Errorf("stderr = %s", h.stderr.String())
		}
	})
	t.Run("an existing instance is compared by size, nothing resolved", func(t *testing.T) {
		h, f, _ := sizeHarness(t, app.Flags{})
		in := f.addVM("i-1", "site-a", instRunning, "ecs.u1-c1m2.large", "vpc-1", "vsw-b")
		in["Cpu"], in["Memory"] = 2, 4096
		in["EipAddress"] = map[string]any{"AllocationId": "eip-1", "IpAddress": "203.0.113.10"}
		if err := h.run("ecs", "instance", "ensure", "site-a", "--type", "2H4G"); err != nil {
			t.Fatal(err)
		}
		if c := changeOf(t, reportOf(t, h), "instance/site-a"); c.Action != platform.Unchanged {
			t.Errorf("same size = %+v", c)
		}
		if err := h.run("ecs", "instance", "ensure", "site-a", "--type", "4H8G"); err != nil {
			t.Fatal(err)
		}
		if c := changeOf(t, reportOf(t, h), "instance/site-a"); c.Action != platform.Skipped || !strings.Contains(c.Detail, "size differs: current ecs.u1-c1m2.large (2H4G), want 4H8G; use resize") {
			t.Errorf("other size = %+v", c)
		}
		if n := len(h.api.callsFor("DescribeAvailableResource")) + len(h.api.callsFor("DescribePrice")); n != 0 || len(f.writes) != 0 {
			t.Errorf("resolved %d times, writes %v", n, f.writes)
		}
	})
}

func TestInstanceResizeWithSize(t *testing.T) {
	t.Run("stopped instance gets the cheapest type it can change to", func(t *testing.T) {
		h, f, _ := sizeHarness(t, app.Flags{})
		in := f.addVM("i-1", "site-a", instStopped, "ecs.u1-c1m1.large", "vpc-1", "vsw-b")
		in["Cpu"], in["Memory"], in["ImageId"] = 2, 2048, alinux4
		if err := h.run("ecs", "instance", "resize", "site-a", "--type", "2H4G"); err != nil {
			t.Fatalf("%v\n%s", err, h.stderr.String())
		}
		// Zone b only (the instance's): zone c's cheaper price is not taken.
		if f.vm("i-1")["InstanceType"] != "ecs.e-c1m2.large" || !slices.Equal(f.writes, []string{"ModifyInstanceSpec"}) {
			t.Errorf("instance = %v, writes %v", f.vm("i-1"), f.writes)
		}
		if !strings.Contains(h.stderr.String(), "2H4G -> ecs.e-c1m2.large (cn-shanghai-b, 0.2 CNY/hour)") {
			t.Errorf("stderr = %s", h.stderr.String())
		}
		q := h.api.callsFor("DescribeResourcesModification")
		if len(q) != 1 || q[0].Get("ResourceId") != "i-1" || q[0].Get("Cores") != "2" || q[0].Get("Memory") != "4" ||
			q[0].Get("DestinationResource") != "InstanceType" || q[0].Get("OperationType") != "Upgrade" {
			t.Errorf("DescribeResourcesModification = %v", q)
		}
		if n := len(h.api.callsFor("DescribeAvailableResource")); n != 0 {
			t.Errorf("DescribeAvailableResource called %d times", n)
		}
		for _, p := range h.api.callsFor("DescribePrice") {
			if p.Get("ImageId") != alinux4 || p.Get("ZoneId") != "cn-shanghai-b" || p.Get("SystemDisk.Size") != "20" {
				t.Errorf("DescribePrice = %v", p)
			}
		}
		if c := changeOf(t, reportOf(t, h), "instance/site-a"); !strings.Contains(c.Detail, "ecs.e-c1m2.large (2H4G, 0.2 CNY/hour)") {
			t.Errorf("change = %+v", c)
		}
	})
	t.Run("same size is unchanged", func(t *testing.T) {
		h, f, _ := sizeHarness(t, app.Flags{})
		in := f.addVM("i-1", "site-a", instRunning, "ecs.u1-c1m2.large", "vpc-1", "vsw-b")
		in["Cpu"], in["Memory"] = 2, 4096
		if err := h.run("ecs", "instance", "resize", "site-a", "--type", "2H4G"); err != nil || len(f.writes) != 0 {
			t.Fatalf("%v, writes %v", err, f.writes)
		}
		if c := reportOf(t, h).Changes[0]; c.Action != platform.Unchanged {
			t.Errorf("change = %+v", c)
		}
	})
	t.Run("dry run resolves and writes nothing", func(t *testing.T) {
		h, f, _ := sizeHarness(t, app.Flags{DryRun: true})
		in := f.addVM("i-1", "site-a", instRunning, "ecs.u1-c1m1.large", "vpc-1", "vsw-b")
		in["Cpu"], in["Memory"], in["ImageId"] = 2, 2048, alinux4
		if err := h.run("ecs", "instance", "resize", "site-a", "--type", "2H4G"); err != nil {
			t.Fatalf("%v\n%s", err, h.stderr.String())
		}
		if len(f.writes) != 0 {
			t.Fatalf("writes = %v", f.writes)
		}
		var found bool
		for _, c := range reportOf(t, h).Changes {
			found = found || strings.Contains(c.Detail, "modify type ecs.u1-c1m1.large -> ecs.e-c1m2.large (2H4G, 0.2 CNY/hour)")
		}
		if !found {
			t.Errorf("stdout = %s", h.stdout.String())
		}
	})
	t.Run("nothing to change to is exit code 4 before the stop", func(t *testing.T) {
		h, f, _ := sizeHarness(t, app.Flags{Yes: true})
		in := f.addVM("i-1", "site-a", instRunning, "ecs.u1-c1m1.large", "vpc-1", "vsw-b")
		in["Cpu"], in["Memory"], in["ImageId"] = 2, 2048, alinux4
		if err := h.run("ecs", "instance", "resize", "site-a", "--type", "8H64G"); !errors.Is(err, platform.ErrNotFound) || len(f.writes) != 0 {
			t.Errorf("%v, writes %v", err, f.writes)
		}
	})
}
