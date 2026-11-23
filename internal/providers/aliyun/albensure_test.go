package aliyun

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

// albWrites are the writes of the fake services, in order.
func albWrites(net *fakeECS) []string { return net.writes }

func ensureReportOf(t *testing.T, h *harness) albEnsureReport {
	t.Helper()
	var rep albEnsureReport
	h.jsonOut(&rep)
	return rep
}

func changeIn(rep albEnsureReport, resource string) (platform.Change, bool) {
	for _, c := range rep.Changes {
		if c.Resource == resource {
			return c, true
		}
	}
	return platform.Change{}, false
}

func TestALBEnsureBuildsEverythingThenChangesNothing(t *testing.T) {
	h, net, alb, _, clock := albHarness(t, app.Flags{})
	if err := h.run("alb", "load-balancer", "ensure", "example.com", "--service", "site-a"); err != nil {
		t.Fatalf("ensure: %v\n%s", err, h.stderr.String())
	}
	want := []string{"CreateVSwitch", "CreateVSwitch", "AllocateEipAddress", "AllocateEipAddress", "CreateLoadBalancer",
		"CreateServerGroup", "AddServersToServerGroup", "CreateListener", "CreateListener"}
	if !slices.Equal(albWrites(net), want) {
		t.Fatalf("writes = %v\nwant     %v", albWrites(net), want)
	}
	rep := ensureReportOf(t, h)

	// The load balancer: zones b and c (the first two DescribeZones
	// offers), each with its vSwitch and its EIP.
	create := h.api.callsFor("CreateLoadBalancer")[0]
	vswB, _ := changeIn(rep, "vswitch/cn-shanghai-switch-b")
	vswC, _ := changeIn(rep, "vswitch/cn-shanghai-switch-c")
	eip1, _ := changeIn(rep, "eip/1")
	eip2, _ := changeIn(rep, "eip/2")
	checks := map[string]string{
		"LoadBalancerName": "lb-example-com", "VpcId": "vpc-site", "AddressType": "Internet", "AddressIpVersion": "Ipv4",
		"AddressAllocatedMode": "Fixed", "LoadBalancerEdition": "Standard", "LoadBalancerBillingConfig.PayType": "PostPay",
		"ResourceGroupId":       "rg-default0001",
		"ZoneMappings.1.ZoneId": "cn-shanghai-b", "ZoneMappings.1.VSwitchId": vswB.ID, "ZoneMappings.1.AllocationId": eip1.ID,
		"ZoneMappings.2.ZoneId": "cn-shanghai-c", "ZoneMappings.2.VSwitchId": vswC.ID, "ZoneMappings.2.AllocationId": eip2.ID,
	}
	for k, v := range checks {
		if create.Get(k) != v || v == "" {
			t.Errorf("CreateLoadBalancer %s = %q, want %q", k, create.Get(k), v)
		}
	}
	lb, _ := changeIn(rep, "load-balancer/lb-example-com")
	if lb.Action != platform.Created || !strings.HasPrefix(lb.ID, "alb-new") || !strings.Contains(lb.Detail, "Active after 10s") {
		t.Errorf("load balancer = %+v", lb)
	}
	// Provisioning, Provisioning, Active: polled every 5 seconds.
	if !slices.Contains(clock.sleeps, 5*time.Second) {
		t.Errorf("sleeps = %v", clock.sleeps)
	}
	sg := h.api.callsFor("CreateServerGroup")[0]
	if sg.Get("ServerGroupName") != "site-a-http" || sg.Get("Protocol") != "HTTP" || sg.Get("VpcId") != "vpc-site" || sg.Get("ServerGroupType") != "Instance" ||
		sg.Get("HealthCheckConfig.HealthCheckEnabled") != "false" || sg.Get("StickySessionConfig.StickySessionEnabled") != "false" {
		t.Errorf("CreateServerGroup = %v", sg)
	}
	add := h.api.callsFor("AddServersToServerGroup")[0]
	if add.Get("Servers.1.ServerId") != "i-site" || add.Get("Servers.1.Port") != "80" || add.Get("Servers.1.ServerType") != "Ecs" {
		t.Errorf("AddServersToServerGroup = %v", add)
	}
	ls := h.api.callsFor("CreateListener")
	if ls[0].Get("ListenerProtocol") != "HTTP" || ls[0].Get("ListenerPort") != "80" || ls[0].Get("Certificates.1.CertificateId") != "" ||
		ls[1].Get("ListenerProtocol") != "HTTPS" || ls[1].Get("ListenerPort") != "443" ||
		ls[1].Get("Certificates.1.CertificateId") != "1234567" ||
		ls[1].Get("DefaultActions.1.ForwardGroupConfig.ServerGroupTuples.1.ServerGroupId") != ls[0].Get("DefaultActions.1.ForwardGroupConfig.ServerGroupTuples.1.ServerGroupId") {
		t.Errorf("CreateListener = %v / %v", ls[0], ls[1])
	}
	if c, ok := changeIn(rep, "server-group/site-a-https"); !ok || c.Action != platform.Skipped || !strings.Contains(c.Detail, "reuses site-a-http") {
		t.Errorf("https group row = %+v", c)
	}
	// The addresses, in zone order although ALB answers them reversed.
	ip1 := net.eip(eip1.ID)["IpAddress"].(string)
	ip2 := net.eip(eip2.ID)["IpAddress"].(string)
	if !slices.Equal(rep.Addresses, []string{ip1, ip2}) || rep.LoadBalancer.ID != lb.ID || rep.LoadBalancer.Name != "lb-example-com" ||
		!strings.HasSuffix(rep.LoadBalancer.DNSName, ".alb.aliyuncs.com") {
		t.Errorf("result = %+v %v", rep.LoadBalancer, rep.Addresses)
	}
	last := rep.Changes[len(rep.Changes)-1]
	if last.Resource != "dns/addresses" || last.Action != platform.Skipped || !strings.Contains(last.Detail, ip1+", "+ip2) {
		t.Errorf("last row = %+v", last)
	}
	// The load balancer is in the inventory.
	rows, err := h.db().List(context.Background(), inventory.Query{Platform: platform.Aliyun, Profile: "ali", Type: platform.ResLoadBalancer})
	if err != nil || len(rows) != 1 || rows[0].Name != "lb-example-com" {
		t.Errorf("inventory = %+v, %v", rows, err)
	}

	// Again: nothing written, nothing created.
	net.writes = nil
	if err := h.run("alb", "load-balancer", "ensure", "example.com", "--service", "site-a"); err != nil {
		t.Fatal(err)
	}
	if len(net.writes) != 0 {
		t.Errorf("second ensure wrote %v", net.writes)
	}
	rep = ensureReportOf(t, h)
	for _, c := range rep.Changes {
		if c.Action.Writes() {
			t.Errorf("second ensure: %+v", c)
		}
	}
	if len(alb.lbs) != 1 || len(alb.groups) != 1 || len(alb.listeners) != 2 {
		t.Errorf("state = %d lbs, %d groups, %d listeners", len(alb.lbs), len(alb.groups), len(alb.listeners))
	}
}

func TestALBEnsureDryRunWritesNothing(t *testing.T) {
	h, net, _, _, _ := albHarness(t, app.Flags{DryRun: true})
	// One idle EIP to reuse, one labelled EIP that is never taken.
	net.addEIP("eip-idle", "203.0.113.5", "Available", "", "", 0, "BGP_PRO")
	net.addEIP("eip-kept", "203.0.113.6", "Available", "", "", 0, "BGP_PRO")["Name"] = "reserved"
	if err := h.run("alb", "load-balancer", "ensure", "example.com", "--service", "site-a"); err != nil {
		t.Fatalf("dry run: %v\n%s", err, h.stderr.String())
	}
	if len(net.writes) != 0 {
		t.Fatalf("dry run wrote %v", net.writes)
	}
	rep := ensureReportOf(t, h)
	if !rep.DryRun || rep.LoadBalancer.ID != platform.Pending || len(rep.Addresses) != 0 {
		t.Errorf("report = %+v", rep)
	}
	e1, _ := changeIn(rep, "eip/1")
	e2, _ := changeIn(rep, "eip/2")
	if e1.Action != platform.WouldUpdate || e1.ID != "eip-idle" || !strings.Contains(e1.Detail, "reuse eip-idle 203.0.113.5") ||
		e2.Action != platform.WouldCreate || e2.ID != platform.Pending || !strings.Contains(e2.Detail, "BGP_PRO 200Mbps PayByTraffic") {
		t.Errorf("eips = %+v / %+v", e1, e2)
	}
	for _, res := range []string{"load-balancer/lb-example-com", "server-group/site-a-http", "server-group/site-a-http/server",
		"load-balancer/lb-example-com/listener/http:80", "load-balancer/lb-example-com/listener/https:443"} {
		if c, ok := changeIn(rep, res); !ok || c.Action != platform.WouldCreate {
			t.Errorf("%s = %+v", res, c)
		}
	}
	if c, _ := changeIn(rep, "load-balancer/lb-example-com/listener/https:443"); !strings.Contains(c.Detail, "cert=1234567") {
		t.Errorf("https listener = %+v", c)
	}
	if c, _ := changeIn(rep, "dns/addresses"); c.Action != platform.Skipped {
		t.Errorf("dns row = %+v", c)
	}
}

func TestALBEnsureReusesIdleEIPs(t *testing.T) {
	h, net, _, _, _ := albHarness(t, app.Flags{})
	net.addEIP("eip-idle", "203.0.113.5", "Available", "", "", 0, "BGP_PRO")
	net.addEIP("eip-bgp", "203.0.113.7", "Available", "", "", 0, "BGP")
	if err := h.run("alb", "load-balancer", "ensure", "example.com", "--service", "site-a"); err != nil {
		t.Fatalf("ensure: %v\n%s", err, h.stderr.String())
	}
	if n := len(h.api.callsFor("AllocateEipAddress")); n != 1 {
		t.Errorf("%d allocations, want 1 (one idle EIP of the ISP reused)", n)
	}
	if got := h.api.callsFor("CreateLoadBalancer")[0].Get("ZoneMappings.1.AllocationId"); got != "eip-idle" {
		t.Errorf("first zone EIP = %s", got)
	}
}

func TestALBEnsureOnlyFixesWhatIsMissing(t *testing.T) {
	h, net, alb, _, clock := albHarness(t, app.Flags{})
	alb.addLB("alb-1", "lb-example-com", "vpc-site", "Active", "cn-shanghai-b=eip-a:203.0.113.10", "cn-shanghai-c=eip-b:203.0.113.11")
	alb.addGroup("sgp-1", "site-a-http", "HTTP", "vpc-site") // empty
	alb.addListener("lsn-1", "alb-1", "HTTP", 80, "sgp-1")
	alb.addListener("lsn-2", "alb-1", "HTTPS", 443, "sgp-1", "7654321")
	if err := h.run("alb", "load-balancer", "ensure", "example.com", "--service", "site-a"); err != nil {
		t.Fatalf("ensure: %v\n%s", err, h.stderr.String())
	}
	if !slices.Equal(net.writes, []string{"AddServersToServerGroup", "UpdateListenerAttribute"}) {
		t.Fatalf("writes = %v", net.writes)
	}
	up := h.api.callsFor("UpdateListenerAttribute")[0]
	if up.Get("ListenerId") != "lsn-2" || up.Get("Certificates.1.CertificateId") != "1234567" || up.Get("DefaultActions.1.Type") != "" {
		t.Errorf("UpdateListenerAttribute = %v", up)
	}
	// Configuring, Configuring, Running: two pauses of 5 seconds, no real sleep.
	var fives int
	for _, s := range clock.sleeps {
		if s == 5*time.Second {
			fives++
		}
	}
	if fives != 2 {
		t.Errorf("sleeps = %v", clock.sleeps)
	}
	rep := ensureReportOf(t, h)
	if c, _ := changeIn(rep, "load-balancer/lb-example-com/listener/https:443"); c.Action != platform.Updated || !strings.Contains(c.Detail, "7654321 -> 1234567") {
		t.Errorf("https listener = %+v", c)
	}
	if c, _ := changeIn(rep, "load-balancer/lb-example-com"); c.Action != platform.Unchanged || c.ID != "alb-1" {
		t.Errorf("load balancer = %+v", c)
	}
	if _, ok := changeIn(rep, "eip/1"); ok {
		t.Error("an existing load balancer's EIPs are not looked at")
	}
	if !slices.Equal(rep.Addresses, []string{"203.0.113.10", "203.0.113.11"}) {
		t.Errorf("addresses = %v", rep.Addresses)
	}
}

func TestALBEnsureCreatesOnlyTheMissingHTTPSListener(t *testing.T) {
	h, net, alb, _, _ := albHarness(t, app.Flags{})
	alb.addLB("alb-1", "lb-example-com", "vpc-site", "Active", "cn-hongkong-b=eip-a:203.0.113.10", "cn-hongkong-c=eip-b:203.0.113.11")
	alb.addGroup("sgp-1", "site-a-http", "HTTP", "vpc-site")
	alb.addServer("sgp-1", "i-other", 80) // not the instance: left alone
	alb.addListener("lsn-1", "alb-1", "HTTP", 8080, "sgp-1")
	if err := h.run("alb", "load-balancer", "ensure", "example.com", "--service", "site-a", "--region", "cn-hongkong"); err != nil {
		t.Fatalf("ensure: %v\n%s", err, h.stderr.String())
	}
	if !slices.Equal(net.writes, []string{"CreateListener"}) {
		t.Fatalf("writes = %v", net.writes)
	}
	// cn-hongkong certificates live in the Singapore CAS store.
	if got := h.api.callsFor("CreateListener")[0].Get("Certificates.1.CertificateId"); got != "1234567-ap-southeast-1" {
		t.Errorf("certificate = %s", got)
	}
	rep := ensureReportOf(t, h)
	if c, _ := changeIn(rep, "load-balancer/lb-example-com/listener/http:80"); c.Action != platform.Unchanged || c.ID != "lsn-1" {
		t.Errorf("http:80 matches the HTTP listener on 8080: %+v", c)
	}
	if c, _ := changeIn(rep, "server-group/site-a-http/server"); c.Action != platform.Unchanged || !strings.Contains(c.Detail, "i-other:80") {
		t.Errorf("members = %+v", c)
	}
}

func TestALBEnsureHTTPSBackend(t *testing.T) {
	h, _, _, _, _ := albHarness(t, app.Flags{})
	if err := h.run("alb", "load-balancer", "ensure", "example.com", "--service", "site-a", "--https-backend"); err != nil {
		t.Fatalf("ensure: %v\n%s", err, h.stderr.String())
	}
	groups := h.api.callsFor("CreateServerGroup")
	if len(groups) != 2 || groups[1].Get("ServerGroupName") != "site-a-https" || groups[1].Get("Protocol") != "HTTPS" {
		t.Fatalf("CreateServerGroup = %v", groups)
	}
	adds := h.api.callsFor("AddServersToServerGroup")
	if len(adds) != 2 || adds[1].Get("Servers.1.Port") != "443" {
		t.Errorf("AddServersToServerGroup = %v", adds)
	}
	rep := ensureReportOf(t, h)
	httpsGroup, _ := changeIn(rep, "server-group/site-a-https")
	if httpsGroup.Action != platform.Created {
		t.Errorf("https group = %+v", httpsGroup)
	}
	ls := h.api.callsFor("CreateListener")
	if ls[1].Get("DefaultActions.1.ForwardGroupConfig.ServerGroupTuples.1.ServerGroupId") != httpsGroup.ID {
		t.Errorf("the HTTPS listener forwards to %s, want %s", ls[1].Get("DefaultActions.1.ForwardGroupConfig.ServerGroupTuples.1.ServerGroupId"), httpsGroup.ID)
	}
}

func TestALBEnsurePrerequisitesComeFirst(t *testing.T) {
	h, net, _, cas, _ := albHarness(t, app.Flags{})
	err := h.run("alb", "load-balancer", "ensure", "example.com", "--service", "nosuch")
	if !errors.Is(err, platform.ErrNotFound) || len(net.writes) != 0 {
		t.Errorf("missing instance = %v, writes %v", err, net.writes)
	}
	err = h.run("alb", "load-balancer", "ensure", "example.com", "--service", "site-a", "--cert", "999")
	if !errors.Is(err, platform.ErrNotFound) || len(net.writes) != 0 {
		t.Errorf("missing --cert = %v, writes %v", err, net.writes)
	}
	cas.certs = nil
	err = h.run("alb", "load-balancer", "ensure", "example.com", "--service", "site-a")
	if !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "cert ensure") || len(net.writes) != 0 {
		t.Errorf("no certificate = %v, writes %v", err, net.writes)
	}
	// Without an HTTPS listener no certificate is needed.
	h.rt.Flags.DryRun = true
	if err := h.run("alb", "load-balancer", "ensure", "example.com", "--service", "site-a", "--listener", "http:80"); err != nil {
		t.Errorf("http only: %v", err)
	}
	h.rt.Flags.DryRun = false
	// An instance of another VPC than --vpc.
	net.addVPCFull("vpc-other", "other", "10.0.0.0/16", false)
	if err := h.run("alb", "load-balancer", "ensure", "example.com", "--service", "site-a", "--listener", "http:80", "--vpc", "vpc-other"); err == nil || len(net.writes) != 0 {
		t.Errorf("--vpc of another VPC = %v, writes %v", err, net.writes)
	}
}

func TestALBEnsureUsageErrors(t *testing.T) {
	h, net, _, _, _ := albHarness(t, app.Flags{})
	for _, args := range [][]string{
		{"*.example.com", "--service", "site-a"},
		{"example.com"},
		{"example.com", "--service", "site-a", "--eips", "3"},
		{"example.com", "--service", "site-a", "--listener", "tcp:80"},
		{"example.com", "--service", "site-a", "--listener", "http:80", "--listener", "https:80"},
		{"example.com", "--service", "site-a", "--cert", "abc"},
		{"example.com", "--service", "site-a", "--zones", "b"},
	} {
		err := h.run(append([]string{"alb", "load-balancer", "ensure"}, args...)...)
		if !errors.Is(err, app.ErrUsage) {
			t.Errorf("%v = %v, want a usage error", args, err)
		}
	}
	if len(net.writes) != 0 {
		t.Errorf("writes = %v", net.writes)
	}
}

func TestALBEnsureZonesAndVSwitches(t *testing.T) {
	h, net, alb, _, _ := albHarness(t, app.Flags{})
	// b exists; a vSwitch of the name of c in another VPC is never used.
	net.addVSwitch("vsw-b", "cn-shanghai-switch-b", "vpc-site", "cn-shanghai-b", "172.16.0.0/22")
	net.addVSwitch("vsw-elsewhere", "cn-shanghai-switch-c", "vpc-other", "cn-shanghai-c", "172.16.4.0/22")
	if err := h.run("alb", "load-balancer", "ensure", "example.com", "--service", "site-a", "--listener", "http:80"); err != nil {
		t.Fatalf("ensure: %v\n%s", err, h.stderr.String())
	}
	vs := h.api.callsFor("CreateVSwitch")
	if len(vs) != 1 || vs[0].Get("VSwitchName") != "cn-shanghai-switch-c" || vs[0].Get("CidrBlock") != "172.16.4.0/22" || vs[0].Get("VpcId") != "vpc-site" {
		t.Errorf("CreateVSwitch = %v", vs)
	}
	create := h.api.callsFor("CreateLoadBalancer")[0]
	if create.Get("ZoneMappings.1.VSwitchId") != "vsw-b" || create.Get("ZoneMappings.2.VSwitchId") == "vsw-elsewhere" {
		t.Errorf("CreateLoadBalancer = %v", create)
	}

	// A region offering ALB in one zone only is unsupported.
	alb.zones = []string{"cn-shanghai-b"}
	alb.lbs = nil
	err := h.run("alb", "load-balancer", "ensure", "other.example.com", "--service", "site-a", "--listener", "http:80")
	if !errors.Is(err, platform.ErrNotSupported) {
		t.Errorf("one zone = %v", err)
	}
}

func TestALBEnsureWaits(t *testing.T) {
	h, net, alb, _, _ := albHarness(t, app.Flags{})
	alb.lbPending = 1000
	err := h.run("alb", "load-balancer", "ensure", "example.com", "--service", "site-a", "--timeout", "30s")
	var te *platform.WaitTimeoutError
	if !errors.As(err, &te) || te.LastStatus != "Provisioning" || !strings.Contains(err.Error(), "Provisioning") {
		t.Fatalf("timeout = %v", err)
	}
	if slices.Contains(net.writes, "CreateListener") {
		t.Error("listeners were created on a load balancer that is not Active")
	}

	// An Inactive load balancer fails before anything is written.
	alb.lbs = nil
	alb.addLB("alb-x", "lb-other-example-com", "vpc-site", "Inactive")
	net.writes = nil
	if err := h.run("alb", "load-balancer", "ensure", "other.example.com", "--service", "site-a"); err == nil || !strings.Contains(err.Error(), "Inactive") || len(net.writes) != 0 {
		t.Errorf("inactive = %v, writes %v", err, net.writes)
	}

	// --no-wait stops after the load balancer.
	alb.lbs = nil
	net.writes = nil
	alb.lbPending = 2
	if err := h.run("alb", "load-balancer", "ensure", "third.example.com", "--service", "site-a", "--no-wait"); err != nil {
		t.Fatalf("--no-wait: %v", err)
	}
	if slices.Contains(net.writes, "CreateServerGroup") || !slices.Contains(net.writes, "CreateLoadBalancer") {
		t.Errorf("--no-wait writes = %v", net.writes)
	}
	rep := ensureReportOf(t, h)
	if c, _ := changeIn(rep, "load-balancer/lb-third-example-com/listeners"); c.Action != platform.Skipped {
		t.Errorf("--no-wait rows = %+v", rep.Changes)
	}
}

func TestPickCASCert(t *testing.T) {
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	certs := []casCertificate{
		{ID: "1", Name: "upload_example.com_2026-12-01", CommonName: "example.com", EndDate: "2026-12-01"},
		{ID: "2", Name: "upload_example.com_2027-01-01", CommonName: "example.com", EndDate: "2027-01-01"},
		{ID: "3", Name: "manual", CommonName: "*.example.com", EndDate: "2027-06-01"},
		{ID: "4", Name: "upload_example.com_2026-11-01", CommonName: "example.com", EndDate: "2026-11-01"},
	}
	if c := pickCASCert(certs, "www.example.com", "example.com", now); c == nil || c.ID != "2" {
		t.Errorf("named first = %+v", c)
	}
	if c := pickCASCert(certs[2:], "www.example.com", "example.com", now); c == nil || c.ID != "3" {
		t.Errorf("common name fallback = %+v", c)
	}
	if c := pickCASCert(certs[3:], "example.com", "example.com", now); c != nil {
		t.Errorf("an expired certificate is never picked: %+v", c)
	}
}
