package aliyun

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// netHarness is a harness with the fake VPC service and a clock that never
// sleeps.
func netHarness(t *testing.T, flags app.Flags) (*harness, *fakeECS, *fakeSleepClock) {
	h := newHarness(t, flags)
	f := newFakeNet(t, h.api)
	clock := &fakeSleepClock{now: time.Unix(1_700_000_000, 0)}
	netWaitClock = clock
	t.Cleanup(func() { netWaitClock = nil })
	return h, f, clock
}

func changeOf(t *testing.T, rep platform.Report, resource string) platform.Change {
	t.Helper()
	for _, c := range rep.Changes {
		if c.Resource == resource {
			return c
		}
	}
	t.Fatalf("no change for %s in %+v", resource, rep.Changes)
	return platform.Change{}
}

func TestVPCEnsureCreatesWaitsThenAddsVSwitches(t *testing.T) {
	h, f, clock := netHarness(t, app.Flags{})
	if err := h.run("vpc", "vpc", "ensure"); err != nil {
		t.Fatalf("ensure: %v\n%s", err, h.stderr.String())
	}
	if !slices.Equal(f.writes, []string{"CreateVpc", "CreateVSwitch", "CreateVSwitch"}) {
		t.Fatalf("writes = %v", f.writes)
	}
	create := h.api.callsFor("CreateVpc")[0]
	if create.Get("VpcName") != "cn-shanghai-vpc" || create.Get("CidrBlock") != "172.16.0.0/12" {
		t.Errorf("CreateVpc = %v", create)
	}
	// Polled by id: Pending, Pending, Available.
	var polls int
	for _, q := range h.api.callsFor("DescribeVpcs") {
		if q.Get("VpcId") != "" {
			polls++
		}
	}
	if polls != 3 || len(clock.sleeps) < 2 || clock.sleeps[0] != 2*time.Second {
		t.Errorf("polls = %d, sleeps = %v", polls, clock.sleeps)
	}
	rep := reportOf(t, h)
	vpc := changeOf(t, rep, "vpc/cn-shanghai-vpc")
	if vpc.Action != platform.Created || !strings.HasPrefix(vpc.ID, "vpc-new") || !strings.Contains(vpc.Detail, "Available after 4s") {
		t.Errorf("vpc change = %+v", vpc)
	}
	b, c := changeOf(t, rep, "vswitch/cn-shanghai-switch-b"), changeOf(t, rep, "vswitch/cn-shanghai-switch-c")
	if b.Action != platform.Created || !strings.HasSuffix(b.Detail, "cn-shanghai-b 172.16.0.0/22") ||
		c.Action != platform.Created || !strings.HasSuffix(c.Detail, "cn-shanghai-c 172.16.4.0/22") {
		t.Errorf("vswitches = %+v / %+v", b, c)
	}
	for _, q := range h.api.callsFor("CreateVSwitch") {
		if q.Get("VpcId") != vpc.ID || q.Get("RegionId") != "cn-shanghai" {
			t.Errorf("CreateVSwitch = %v", q)
		}
	}

	// Again: nothing written, every row unchanged.
	f.writes = nil
	if err := h.run("vpc", "vpc", "ensure"); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Errorf("second ensure wrote %v", f.writes)
	}
	if rep := reportOf(t, h); countActions(rep, platform.Unchanged) != 3 {
		t.Errorf("second report = %+v", rep.Changes)
	}
}

func TestVPCEnsureDryRunWritesNothing(t *testing.T) {
	h, f, clock := netHarness(t, app.Flags{DryRun: true})
	if err := h.run("vpc", "vpc", "ensure", "--zones", "b,d"); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 || len(clock.sleeps) != 0 {
		t.Fatalf("dry run wrote %v, slept %v", f.writes, clock.sleeps)
	}
	rep := reportOf(t, h)
	if !rep.DryRun {
		t.Error("report is not a dry run")
	}
	if c := changeOf(t, rep, "vpc/cn-shanghai-vpc"); c.Action != platform.WouldCreate || c.ID != platform.Pending || c.Detail != "172.16.0.0/12" {
		t.Errorf("vpc = %+v", c)
	}
	if c := changeOf(t, rep, "vswitch/cn-shanghai-switch-b"); c.Action != platform.WouldCreate || c.Detail != "cn-shanghai-b 172.16.0.0/22 (vpc pending)" {
		t.Errorf("b = %+v", c)
	}
	if c := changeOf(t, rep, "vswitch/cn-shanghai-switch-d"); c.Detail != "cn-shanghai-d 172.16.4.0/22 (vpc pending)" {
		t.Errorf("d = %+v", c)
	}
}

// A VPC an earlier run left Pending is waited for, not created again; a
// VPC that stays Pending is a timeout naming its last status.
func TestVPCEnsureWaitsForPendingVPC(t *testing.T) {
	h, f, _ := netHarness(t, app.Flags{})
	f.addVPCFull("vpc-main", "cn-shanghai-vpc", "172.16.0.0/12", false)
	f.vpcs[0]["Status"] = "Pending"
	f.pending["vpc-main"] = 2
	if err := h.run("vpc", "vpc", "ensure", "--zones", "b"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.writes, []string{"CreateVSwitch"}) {
		t.Fatalf("writes = %v", f.writes)
	}
	if c := changeOf(t, reportOf(t, h), "vpc/cn-shanghai-vpc"); c.Action != platform.Unchanged || !strings.Contains(c.Detail, "now Available") {
		t.Errorf("vpc = %+v", c)
	}

	h2, f2, _ := netHarness(t, app.Flags{})
	f2.addVPCFull("vpc-slow", "cn-shanghai-vpc", "172.16.0.0/12", false)
	f2.vpcs[0]["Status"] = "Pending"
	f2.pending["vpc-slow"] = 1000
	err := h2.run("vpc", "vpc", "ensure", "--timeout", "10s")
	var timeout *platform.WaitTimeoutError
	if !errors.As(err, &timeout) || timeout.LastStatus != "Pending" || !strings.Contains(err.Error(), "vpc-slow") {
		t.Fatalf("err = %v, want a timeout with the last status", err)
	}
	if len(f2.writes) != 0 {
		t.Errorf("writes = %v", f2.writes)
	}
}

func TestVPCEnsureNoWaitSkipsVSwitches(t *testing.T) {
	h, f, clock := netHarness(t, app.Flags{})
	if err := h.run("vpc", "vpc", "ensure", "web", "--no-wait"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.writes, []string{"CreateVpc"}) || len(clock.sleeps) != 0 {
		t.Fatalf("writes = %v, sleeps = %v", f.writes, clock.sleeps)
	}
	rep := reportOf(t, h)
	if countActions(rep, platform.Skipped) != 2 || changeOf(t, rep, "vpc/web").Action != platform.Created {
		t.Errorf("report = %+v", rep.Changes)
	}
}

func TestVPCEnsureAmbiguousName(t *testing.T) {
	h, f, _ := netHarness(t, app.Flags{})
	f.addVPCFull("vpc-a", "cn-shanghai-vpc", "172.16.0.0/12", false)
	f.addVPCFull("vpc-b", "cn-shanghai-vpc", "10.0.0.0/8", false)
	var amb *app.AmbiguousError
	if err := h.run("vpc", "vpc", "ensure"); !errors.As(err, &amb) || len(amb.Candidates) != 2 {
		t.Fatalf("err = %v, want ambiguous", err)
	}
	if err := h.run("vpc", "vpc", "get", "cn-shanghai-vpc"); !errors.As(err, &amb) {
		t.Fatalf("get err = %v, want ambiguous", err)
	}
	if len(f.writes) != 0 {
		t.Errorf("writes = %v", f.writes)
	}
}

// Only the VPC's own vSwitches count: one of the same name in another VPC
// is not the one asked for. The missing one does not overlap the others.
func TestVSwitchEnsurePartial(t *testing.T) {
	h, f, _ := netHarness(t, app.Flags{})
	f.addVPCFull("vpc-main", "cn-shanghai-vpc", "172.16.0.0/12", false)
	f.addVPCFull("vpc-other", "other", "172.16.0.0/12", false)
	f.addVSwitch("vsw-b", "cn-shanghai-switch-b", "vpc-main", "cn-shanghai-b", "172.16.0.0/22")
	f.addVSwitch("vsw-x", "cn-shanghai-switch-c", "vpc-other", "cn-shanghai-c", "172.16.0.0/22")
	f.addVSwitch("vsw-y", "misc", "vpc-main", "cn-shanghai-d", "172.16.4.0/24")
	if err := h.run("vpc", "vswitch", "ensure"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	calls := h.api.callsFor("CreateVSwitch")
	if len(calls) != 1 || calls[0].Get("VSwitchName") != "cn-shanghai-switch-c" || calls[0].Get("VpcId") != "vpc-main" ||
		calls[0].Get("ZoneId") != "cn-shanghai-c" || calls[0].Get("CidrBlock") != "172.16.8.0/22" {
		t.Fatalf("creates = %v", calls)
	}
	for _, q := range h.api.callsFor("DescribeVSwitches") {
		if q.Get("VpcId") != "vpc-main" || q.Get("PageSize") != "50" {
			t.Errorf("DescribeVSwitches = %v", q)
		}
	}
	rep := reportOf(t, h)
	if c := changeOf(t, rep, "vswitch/cn-shanghai-switch-b"); c.Action != platform.Unchanged || c.ID != "vsw-b" {
		t.Errorf("b = %+v", c)
	}
	// The new vSwitch was waited for (Pending once, then Available).
	if n := len(h.api.callsFor("DescribeVSwitchAttributes")); n != 2 {
		t.Errorf("DescribeVSwitchAttributes calls = %d, want 2", n)
	}
}

func TestVSwitchEnsurePrefixAndNetmask(t *testing.T) {
	h, f, _ := netHarness(t, app.Flags{DryRun: true})
	f.addVPCFull("vpc-main", "net", "10.0.0.0/16", false)
	if err := h.run("vpc", "vswitch", "ensure", "--vpc", "net", "--prefix", "web", "--zones", "cn-shanghai-b,c", "--netmask", "24"); err != nil {
		t.Fatal(err)
	}
	rep := reportOf(t, h)
	if c := changeOf(t, rep, "vswitch/web-b"); c.Detail != "cn-shanghai-b 10.0.0.0/24" {
		t.Errorf("b = %+v", c)
	}
	if c := changeOf(t, rep, "vswitch/web-c"); c.Detail != "cn-shanghai-c 10.0.1.0/24" {
		t.Errorf("c = %+v", c)
	}
}

func TestVSwitchEnsureErrors(t *testing.T) {
	h, f, _ := netHarness(t, app.Flags{})
	f.addVPCFull("vpc-main", "cn-shanghai-vpc", "172.16.0.0/12", false)
	cases := []struct {
		args []string
		want error
	}{
		{[]string{"vpc", "vswitch", "ensure", "--zones", "cn-hangzhou-b"}, app.ErrUsage},
		{[]string{"vpc", "vswitch", "ensure", "--zones", "b,b"}, app.ErrUsage},
		{[]string{"vpc", "vswitch", "ensure", "--zones", ""}, app.ErrUsage},
		{[]string{"vpc", "vswitch", "ensure", "--netmask", "30"}, app.ErrUsage},
		{[]string{"vpc", "vswitch", "ensure", "--netmask", "8"}, app.ErrUsage},
		{[]string{"vpc", "vswitch", "ensure", "--vpc", "nosuch"}, platform.ErrNotFound},
		{[]string{"vpc", "vswitch", "create", "s1", "--zone", "b"}, app.ErrUsage},
		{[]string{"vpc", "vswitch", "create", "s1", "--vpc", "vpc-main", "--zone", "b", "--cidr", "172.16.9.0/22"}, app.ErrUsage},
		{[]string{"vpc", "vpc", "create", "vpc-1"}, app.ErrUsage},
		{[]string{"vpc", "vpc", "create", "web", "--cidr", "fd00::/48"}, app.ErrUsage},
		{[]string{"vpc", "vpc", "get", "nosuch"}, platform.ErrNotFound},
		{[]string{"vpc", "vswitch", "get", "vsw-nosuch"}, platform.ErrNotFound},
	}
	for _, c := range cases {
		if err := h.run(c.args...); !errors.Is(err, c.want) {
			t.Errorf("%v: err = %v, want %v", c.args, err, c.want)
		}
	}
	if len(f.writes) != 0 {
		t.Errorf("writes = %v", f.writes)
	}
	// A zone the region does not have is refused by the API: unsupported.
	if err := h.run("vpc", "vswitch", "ensure", "--zones", "z"); !errors.Is(err, platform.ErrNotSupported) || !strings.Contains(err.Error(), "--zones") {
		t.Errorf("zone z: %v", err)
	}
	// The default VPC that does not exist is a usage error naming it.
	h2, _, _ := netHarness(t, app.Flags{})
	if err := h2.run("vpc", "vswitch", "ensure"); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "cn-shanghai-vpc") {
		t.Errorf("missing default VPC: %v", err)
	}
}

func TestVSwitchCreate(t *testing.T) {
	h, f, _ := netHarness(t, app.Flags{})
	f.addVPCFull("vpc-main", "cn-shanghai-vpc", "172.16.0.0/12", false)
	f.addVSwitch("vsw-b", "s1", "vpc-main", "cn-shanghai-b", "172.16.0.0/22")
	// Same name, other zone: created, in a free block.
	if err := h.run("vpc", "vswitch", "create", "s1", "--vpc", "cn-shanghai-vpc", "--zone", "c"); err != nil {
		t.Fatal(err)
	}
	if q := h.api.callsFor("CreateVSwitch"); len(q) != 1 || q[0].Get("CidrBlock") != "172.16.4.0/22" || q[0].Get("ZoneId") != "cn-shanghai-c" {
		t.Fatalf("creates = %v", q)
	}
	// Same name, same zone: refused.
	if err := h.run("vpc", "vswitch", "create", "s1", "--vpc", "vpc-main", "--zone", "cn-shanghai-b"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("duplicate create = %v", err)
	}
	// An overlapping block is the API's refusal, with a hint.
	err := h.run("vpc", "vswitch", "create", "s2", "--vpc", "vpc-main", "--zone", "d", "--cidr", "172.16.0.0/22")
	if !platform.HasErrorCode(err, "InvalidCidrBlock.Overlapped") || !strings.Contains(err.Error(), "--cidr") {
		t.Errorf("overlap = %v", err)
	}
	// Two vSwitches of the name in the region are ambiguous without --vpc.
	var amb *app.AmbiguousError
	if err := h.run("vpc", "vswitch", "get", "s1"); !errors.As(err, &amb) {
		t.Errorf("get = %v", err)
	}
}

func TestVPCAndVSwitchLists(t *testing.T) {
	h, f, _ := netHarness(t, app.Flags{})
	if err := h.run("vpc", "vpc", "list"); err != nil || strings.TrimSpace(h.stdout.String()) != "[]" || !strings.Contains(h.stderr.String(), "no VPCs") {
		t.Fatalf("empty list: %v %q %q", err, h.stdout.String(), h.stderr.String())
	}
	f.addVPCFull("vpc-def", "", "172.16.0.0/12", true)
	f.addVPCFull("vpc-main", "cn-shanghai-vpc", "172.16.0.0/12", false)
	f.addVSwitch("vsw-b", "s1", "vpc-main", "cn-shanghai-b", "172.16.0.0/22")
	f.addVSwitch("vsw-o", "s1", "vpc-def", "cn-shanghai-b", "172.16.0.0/22")
	var vpcs []vpcInfo
	if err := h.run("vpc", "vpc", "list"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&vpcs)
	if len(vpcs) != 1 || vpcs[0].ID != "vpc-main" || vpcs[0].Status != "Available" {
		t.Errorf("list = %+v", vpcs)
	}
	if err := h.run("vpc", "vpc", "list", "--all"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&vpcs)
	if len(vpcs) != 2 {
		t.Errorf("list --all = %+v", vpcs)
	}
	var vsw []vSwitch
	if err := h.run("vpc", "vswitch", "list", "--vpc", "cn-shanghai-vpc"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&vsw)
	if len(vsw) != 1 || vsw[0].ID != "vsw-b" || vsw[0].AvailableIPs != 1020 {
		t.Errorf("vswitch list = %+v", vsw)
	}
	var d vpcDetail
	if err := h.run("vpc", "vpc", "get", "vpc-main"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&d)
	if d.ID != "vpc-main" || d.Profile != "ali" || len(d.VSwitches) != 1 {
		t.Errorf("get = %+v", d)
	}
	// Read-only: --dry-run changes nothing, --offline cannot answer.
	h2, _, _ := netHarness(t, app.Flags{Offline: true})
	if err := h2.run("vpc", "vpc", "list"); !errors.Is(err, app.ErrOffline) {
		t.Errorf("offline = %v", err)
	}
}

// A VPC that is not listed yet right after its creation is waited for,
// not reported missing.
func TestVPCEnsureWaitsForUnlistedVPC(t *testing.T) {
	h, f, _ := netHarness(t, app.Flags{})
	f.newUnlisted = 2
	if err := h.run("vpc", "vpc", "ensure", "--zones", "b"); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if !slices.Equal(f.writes, []string{"CreateVpc", "CreateVSwitch"}) {
		t.Fatalf("writes = %v", f.writes)
	}
}

// A vSwitch given its block does not need room for a /22: a VPC smaller
// than that takes it; without --cidr it is a usage error naming --cidr.
func TestVSwitchCreateInSmallVPC(t *testing.T) {
	h, f, _ := netHarness(t, app.Flags{})
	f.addVPCFull("vpc-small", "small", "10.0.0.0/24", false)
	if err := h.run("vpc", "vswitch", "create", "s1", "--vpc", "vpc-small", "--zone", "b", "--cidr", "10.0.0.0/26"); err != nil {
		t.Fatalf("create with --cidr: %v", err)
	}
	if q := h.api.callsFor("CreateVSwitch"); len(q) != 1 || q[0].Get("CidrBlock") != "10.0.0.0/26" {
		t.Fatalf("creates = %v", q)
	}
	err := h.run("vpc", "vswitch", "create", "s2", "--vpc", "vpc-small", "--zone", "c")
	if !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--cidr") || strings.Contains(err.Error(), "--netmask") {
		t.Errorf("create without --cidr = %v", err)
	}
}
