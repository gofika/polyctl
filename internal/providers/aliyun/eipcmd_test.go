package aliyun

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

type eipEnsureOut struct {
	platform.Report
	Result struct {
		EIPs []eipRef `json:"eips"`
	} `json:"result"`
}

func eipOut(t *testing.T, h *harness) eipEnsureOut {
	t.Helper()
	var out eipEnsureOut
	h.jsonOut(&out)
	return out
}

// addNLBEIP stores the EIP a load balancer holds (the real shape: bound to
// a network interface, managed by the service).
func addNLBEIP(f *fakeECS) {
	e := f.addEIP("eip-0nlb", "203.0.113.20", "InUse", "eni-0123", "NetworkInterface", 1, "BGP_PRO")
	e["Name"], e["Description"] = "CREATE_BY_NLB.nlb-0123", "CREATE_BY_NLB.nlb-0123"
}

func TestEIPEnsureReusesIdle(t *testing.T) {
	h, f, _ := netHarness(t, app.Flags{})
	addNLBEIP(f)
	f.addEIP("eip-1idle", "203.0.113.10", "Available", "", "", 0, "BGP_PRO")
	if err := h.run("eip", "address", "ensure"); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("writes = %v", f.writes)
	}
	out := eipOut(t, h)
	if len(out.Changes) != 1 || out.Changes[0].Action != platform.Unchanged || out.Changes[0].ID != "eip-1idle" || out.Changes[0].Detail != "reuse idle 203.0.113.10" {
		t.Errorf("changes = %+v", out.Changes)
	}
	if len(out.Result.EIPs) != 1 || out.Result.EIPs[0] != (eipRef{AllocationID: "eip-1idle", IP: "203.0.113.10"}) {
		t.Errorf("result = %+v", out.Result)
	}
	if out.Target.Region != "cn-shanghai" || out.Target.Profile != "ali" {
		t.Errorf("target = %+v", out.Target)
	}
}

// --count 2 with one idle EIP: the idle one is reused once, one is
// allocated (then read back), and the managed / bound ones are never
// picked.
func TestEIPEnsureReusesOneAllocatesOne(t *testing.T) {
	h, f, _ := netHarness(t, app.Flags{})
	addNLBEIP(f)
	f.addEIP("eip-2released", "203.0.113.30", "Available", "", "", 1, "BGP_PRO") // a load balancer just let it go
	f.addEIP("eip-3bgp", "203.0.113.40", "Available", "", "", 0, "BGP")          // another ISP
	f.addEIP("eip-1idle", "203.0.113.10", "Available", "", "", 0, "BGP_PRO")
	if err := h.run("eip", "address", "ensure", "--count", "2"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if !slices.Equal(f.writes, []string{"AllocateEipAddress"}) {
		t.Fatalf("writes = %v", f.writes)
	}
	alloc := h.api.callsFor("AllocateEipAddress")[0]
	if alloc.Get("Bandwidth") != "200" || alloc.Get("ISP") != "BGP_PRO" || alloc.Get("AutoPay") != "true" || alloc.Get("ResourceGroupId") != "rg-default0001" {
		t.Errorf("allocate = %v", alloc)
	}
	if q := h.api.callsFor("ListResourceGroups"); len(q) != 1 || q[0].Get("Name") != "default" {
		t.Errorf("resource group lookup = %v", q)
	}
	out := eipOut(t, h)
	if len(out.Changes) != 2 || out.Changes[0].ID != "eip-1idle" || out.Changes[0].Action != platform.Unchanged ||
		out.Changes[1].Action != platform.Created || !strings.HasPrefix(out.Changes[1].ID, "eip-new") ||
		!strings.Contains(out.Changes[1].Detail, "BGP_PRO 200Mbps PayByTraffic") {
		t.Errorf("changes = %+v", out.Changes)
	}
	if len(out.Result.EIPs) != 2 || out.Result.EIPs[1].AllocationID != out.Changes[1].ID || out.Result.EIPs[1].IP == "" {
		t.Errorf("result = %+v", out.Result)
	}
	// The allocated EIP was read back by its allocation id.
	var readBack bool
	for _, q := range h.api.callsFor("DescribeEipAddresses") {
		readBack = readBack || q.Get("AllocationId") == out.Changes[1].ID
	}
	if !readBack {
		t.Error("the allocated EIP was not read back")
	}

	// Again: both are now... the new one is idle too, so nothing is written.
	f.writes = nil
	if err := h.run("eip", "address", "ensure", "--count", "2"); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Errorf("second run wrote %v", f.writes)
	}
}

func TestEIPEnsureDryRunMatchesRealRun(t *testing.T) {
	h, f, _ := netHarness(t, app.Flags{DryRun: true})
	f.addEIP("eip-1idle", "203.0.113.10", "Available", "", "", 0, "BGP_PRO")
	if err := h.run("eip", "address", "ensure", "--count", "2", "--exclude", "eip-9"); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("dry run wrote %v", f.writes)
	}
	out := eipOut(t, h)
	if !out.DryRun || len(out.Changes) != 2 || out.Changes[0].Detail != "reuse idle 203.0.113.10" ||
		out.Changes[1].Action != platform.WouldCreate || out.Changes[1].Detail != "allocate BGP_PRO 200Mbps PayByTraffic" {
		t.Errorf("changes = %+v", out.Changes)
	}
	if out.Result.EIPs[1].AllocationID != platform.Pending {
		t.Errorf("result = %+v", out.Result)
	}
	// --exclude leaves the idle one out.
	if err := h.run("eip", "address", "ensure", "--exclude", "eip-1idle"); err != nil {
		t.Fatal(err)
	}
	if out := eipOut(t, h); out.Changes[0].Action != platform.WouldCreate {
		t.Errorf("exclude = %+v", out.Changes)
	}
}

func TestEIPEnsureBindsInstance(t *testing.T) {
	h, f, _ := netHarness(t, app.Flags{})
	f.addInstance("i-1", "site-a", "vpc-main")
	f.addEIP("eip-1idle", "203.0.113.10", "Available", "", "", 0, "BGP_PRO")
	if err := h.run("eip", "address", "ensure", "--instance", "site-a"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if !slices.Equal(f.writes, []string{"AssociateEipAddress"}) {
		t.Fatalf("writes = %v", f.writes)
	}
	if q := h.api.callsFor("AssociateEipAddress")[0]; q.Get("AllocationId") != "eip-1idle" || q.Get("InstanceId") != "i-1" {
		t.Errorf("associate = %v", q)
	}
	out := eipOut(t, h)
	if c := changeOf(t, out.Report, "instance/site-a"); c.Action != platform.Updated || c.Detail != "associated eip-1idle with i-1" {
		t.Errorf("instance change = %+v", c)
	}
	if f.eip("eip-1idle")["Status"] != "InUse" {
		t.Errorf("EIP not waited for until InUse: %v", f.eip("eip-1idle"))
	}

	// Again: the instance holds it, nothing is reused, allocated or bound.
	f.writes = nil
	n := len(h.api.callsFor("DescribeEipAddresses"))
	if err := h.run("eip", "address", "ensure", "--instance", "site-a"); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 || len(h.api.callsFor("DescribeEipAddresses")) != n {
		t.Errorf("second run wrote %v", f.writes)
	}
	out = eipOut(t, h)
	if len(out.Changes) != 1 || out.Changes[0].Action != platform.Unchanged || out.Changes[0].Detail != "already bound 203.0.113.10 to i-1" ||
		out.Result.EIPs[0].AllocationID != "eip-1idle" {
		t.Errorf("second report = %+v", out)
	}
}

func TestEIPAssociate(t *testing.T) {
	h, f, _ := netHarness(t, app.Flags{})
	f.addInstance("i-1", "site-a", "vpc-main")
	f.addInstance("i-2", "site-b", "vpc-main")
	f.addEIP("eip-1idle", "203.0.113.10", "Available", "", "", 0, "BGP_PRO")
	f.addEIP("eip-2used", "203.0.113.11", "InUse", "i-9", "EcsInstance", 0, "BGP_PRO")
	f.addEIP("eip-3busy", "203.0.113.12", "Unassociating", "", "", 0, "BGP_PRO")

	if err := h.run("eip", "address", "associate", "eip-2used", "--instance", "site-a"); err == nil || !strings.Contains(err.Error(), "bound to i-9") {
		t.Errorf("bound EIP: %v", err)
	}
	if err := h.run("eip", "address", "associate", "eip-3busy", "--instance", "site-a"); err == nil || !strings.Contains(err.Error(), "not Available") {
		t.Errorf("busy EIP: %v", err)
	}
	if err := h.run("eip", "address", "associate", "eip-nosuch", "--instance", "site-a"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing EIP: %v", err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("writes = %v", f.writes)
	}
	if err := h.run("eip", "address", "associate", "203.0.113.10", "--instance", "site-a"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.writes, []string{"AssociateEipAddress"}) {
		t.Fatalf("writes = %v", f.writes)
	}
	// Bound to that instance already: unchanged. Another instance: refused.
	f.writes = nil
	if err := h.run("eip", "address", "associate", "eip-1idle", "--instance", "i-1"); err != nil {
		t.Fatal(err)
	}
	if rep := reportOf(t, h); len(f.writes) != 0 || rep.Changes[0].Action != platform.Unchanged {
		t.Errorf("rebind = %v %+v", f.writes, rep.Changes)
	}
	if err := h.run("eip", "address", "associate", "eip-1idle", "--instance", "site-b"); err == nil || !strings.Contains(err.Error(), "bound to i-1") {
		t.Errorf("steal: %v", err)
	}
}

func TestEIPUsageAndRouting(t *testing.T) {
	h, f, _ := netHarness(t, app.Flags{})
	f.addInstance("i-1", "site-a", "vpc-main")
	cases := []struct {
		args []string
		want error
	}{
		{[]string{"eip", "address", "associate", "eip-1"}, app.ErrUsage},
		{[]string{"eip", "address", "associate", "site-a", "--instance", "i-1"}, app.ErrUsage},
		{[]string{"eip", "address", "associate", "eip-1", "--instance", "i-1", "--region", "cn-hangzhou"}, app.ErrUsage},
		{[]string{"eip", "address", "ensure", "--instance", "i-1", "--region", "cn-hangzhou"}, app.ErrUsage},
		{[]string{"eip", "address", "ensure", "--count", "0"}, app.ErrUsage},
		{[]string{"eip", "address", "ensure", "--count", "2", "--instance", "i-1"}, app.ErrUsage},
		{[]string{"eip", "address", "ensure", "--bandwidth", "0"}, app.ErrUsage},
		{[]string{"eip", "address", "list", "--unused", "--bound"}, app.ErrUsage},
		{[]string{"eip", "address", "associate", "eip-1", "--instance", "nosuch"}, platform.ErrNotFound},
		{[]string{"eip", "address", "allocate", "--resource-group", "nosuch"}, platform.ErrNotFound},
	}
	for _, c := range cases {
		if err := h.run(c.args...); !errors.Is(err, c.want) {
			t.Errorf("%v: err = %v, want %v", c.args, err, c.want)
		}
	}
	if len(f.writes) != 0 {
		t.Errorf("writes = %v", f.writes)
	}
	h2, _, _ := netHarness(t, app.Flags{Offline: true})
	if err := h2.run("eip", "address", "ensure"); !errors.Is(err, app.ErrOffline) {
		t.Errorf("offline = %v", err)
	}
}

func TestEIPAllocate(t *testing.T) {
	h, f, _ := netHarness(t, app.Flags{})
	if err := h.run("eip", "address", "allocate", "--bandwidth", "5", "--isp", "BGP", "--resource-group", "rg-default0001"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.writes, []string{"AllocateEipAddress"}) || len(h.api.callsFor("ListResourceGroups")) != 0 {
		t.Fatalf("writes = %v, group lookups %d", f.writes, len(h.api.callsFor("ListResourceGroups")))
	}
	if q := h.api.callsFor("AllocateEipAddress")[0]; q.Get("Bandwidth") != "5" || q.Get("ISP") != "BGP" {
		t.Errorf("allocate = %v", q)
	}
	// A region that does not offer the ISP is unsupported (exit code 7).
	f.allocateErr = apiErr("COMMODITY.INVALID_COMPONENT", "The component is invalid.")
	if err := h.run("eip", "address", "allocate"); !errors.Is(err, platform.ErrNotSupported) || !strings.Contains(err.Error(), "--isp") {
		t.Errorf("unsupported ISP: %v", err)
	}
	f.allocateErr = apiErr("InvalidResourceGroupId", "The specified resource group id is invalid.")
	if err := h.run("eip", "address", "allocate", "--resource-group", "rg-gone"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("unknown group id: %v", err)
	}
	// Dry run: nothing allocated.
	h2, f2, _ := netHarness(t, app.Flags{DryRun: true})
	if err := h2.run("eip", "address", "allocate"); err != nil {
		t.Fatal(err)
	}
	if rep := reportOf(t, h2); len(f2.writes) != 0 || rep.Changes[0].Action != platform.WouldCreate {
		t.Errorf("dry run = %v %+v", f2.writes, rep.Changes)
	}
}

// An EIP that is not listed yet right after its allocation is waited for,
// not reported missing.
func TestEIPAllocateWaitsForUnlistedEIP(t *testing.T) {
	h, f, clock := netHarness(t, app.Flags{})
	f.newUnlisted = 2
	if err := h.run("eip", "address", "allocate"); err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if rep := reportOf(t, h); rep.Changes[0].Action != platform.Created || !strings.HasPrefix(rep.Changes[0].ID, "eip-new") {
		t.Errorf("changes = %+v", rep.Changes)
	}
	if len(clock.sleeps) != 2 {
		t.Errorf("sleeps = %v, want 2 polls of a missing EIP", clock.sleeps)
	}
}

func TestEIPList(t *testing.T) {
	h, f, _ := netHarness(t, app.Flags{})
	if err := h.run("eip", "address", "list"); err != nil || strings.TrimSpace(h.stdout.String()) != "[]" || !strings.Contains(h.stderr.String(), "no EIPs") {
		t.Fatalf("empty: %v %q %q", err, h.stdout.String(), h.stderr.String())
	}
	addNLBEIP(f)
	f.addEIP("eip-1idle", "203.0.113.10", "Available", "", "", 0, "BGP_PRO")
	var eips []eipAddress
	h.rt.Flags.Refresh = true
	if err := h.run("eip", "address", "list", "--unused"); err != nil {
		t.Fatal(err)
	}
	h.rt.Flags.Refresh = false
	h.jsonOut(&eips)
	if len(eips) != 1 || eips[0].AllocationID != "eip-1idle" {
		t.Errorf("unused = %+v", eips)
	}
	// From the local inventory now.
	if err := h.run("eip", "address", "list", "--bound"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&eips)
	if len(eips) != 1 || eips[0].AllocationID != "eip-0nlb" || !eips[0].ServiceManaged || eips[0].Name != "CREATE_BY_NLB.nlb-0123" {
		t.Errorf("bound = %+v", eips)
	}
	g := eipGrid(eips)
	if g.Headers[0] != "ALLOCATION_ID" || g.Rows[0][3] != "eni-0123 (NetworkInterface)" || g.Rows[0][4] != "CREATE_BY_NLB.nlb-0123" {
		t.Errorf("grid = %+v", g)
	}
}
