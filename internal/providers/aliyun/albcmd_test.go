package aliyun

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

// albHarness is the net harness with the fake ALB and CAS services, the
// VPC of the instance site-a (i-site) and a certificate of example.com.
func albHarness(t *testing.T, flags app.Flags) (*harness, *fakeECS, *fakeALB, *casFake, *fakeSleepClock) {
	t.Helper()
	h, net, clock := netHarness(t, flags)
	alb := newFakeALB(t, h.api, net)
	cas := newCASFake(t, h.api)
	cas.add(1234567, "upload_example.com_2027-02-01", "2027-02-01")
	casNow = func() time.Time { return time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { casNow = time.Now })
	net.addVPCFull("vpc-site", "cn-shanghai-vpc", "172.16.0.0/12", false)
	net.addInstance("i-site", "site-a", "vpc-site")
	return h, net, alb, cas, clock
}

func TestALBListenerRunningWait(t *testing.T) {
	h, _, alb, _, clock := albHarness(t, app.Flags{})
	alb.addLB("alb-1", "lb-1", "vpc-site", "Active")
	alb.addGroup("sgp-1", "g", "HTTP", "vpc-site")
	alb.addListener("lsn-2", "alb-1", "HTTPS", 443, "sgp-1", "1111")
	if err := h.run("alb", "listener", "cert", "set", "lsn-2", "--cert", "1234567"); err != nil {
		t.Fatalf("cert set: %v", err)
	}
	if !slices.Equal(clock.sleeps, []time.Duration{5 * time.Second, 5 * time.Second}) {
		t.Errorf("sleeps = %v", clock.sleeps)
	}
	// The same certificate again: unchanged, nothing written.
	before := len(h.api.callsFor("UpdateListenerAttribute"))
	if err := h.run("alb", "listener", "cert", "set", "lsn-2", "--cert", "1234567"); err != nil {
		t.Fatal(err)
	}
	if rep := reportOf(t, h); len(h.api.callsFor("UpdateListenerAttribute")) != before || rep.Changes[0].Action != platform.Unchanged {
		t.Errorf("same certificate: %+v", rep.Changes)
	}
	// A listener that stays Configuring for more than a minute fails.
	alb.configuring = 1000
	err := h.run("alb", "listener", "cert", "set", "lsn-2", "--cert", "7654321")
	var te *platform.WaitTimeoutError
	if !errors.As(err, &te) || te.LastStatus != "Configuring" {
		t.Errorf("stuck listener = %v", err)
	}
}

func TestALBListenerCertSetDryRunAndRegions(t *testing.T) {
	h, _, alb, _, _ := albHarness(t, app.Flags{DryRun: true})
	alb.addLB("alb-1", "lb-1", "vpc-site", "Active")
	alb.addGroup("sgp-1", "g", "HTTP", "vpc-site")
	alb.addListener("lsn-2", "alb-1", "HTTPS", 443, "sgp-1", "1111-ap-southeast-1")
	alb.addListener("lsn-1", "alb-1", "HTTP", 80, "sgp-1")
	if err := h.run("alb", "listener", "cert", "set", "lsn-2", "--cert", "1234567", "--region", "cn-hongkong"); err != nil {
		t.Fatal(err)
	}
	rep := reportOf(t, h)
	if len(rep.Changes) != 1 || rep.Changes[0].Action != platform.WouldUpdate || rep.Changes[0].Resource != "listener/lsn-2" ||
		!strings.Contains(rep.Changes[0].Detail, "1111-ap-southeast-1 -> 1234567-ap-southeast-1") {
		t.Errorf("dry run = %+v", rep.Changes)
	}
	if len(h.api.callsFor("UpdateListenerAttribute")) != 0 {
		t.Error("dry run wrote")
	}
	if err := h.run("alb", "listener", "cert", "set", "lsn-1", "--cert", "1234567"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("HTTP listener = %v", err)
	}
	if err := h.run("alb", "listener", "cert", "set", "lsn-nosuch", "--cert", "1234567"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing listener = %v", err)
	}
}

func TestListenerCertIDOfRegion(t *testing.T) {
	c := newClient("cn-shanghai", "k", "s")
	for region, want := range map[string]string{"cn-hongkong": "171744-ap-southeast-1", "cn-shanghai": "171744", "ap-southeast-1": "171744"} {
		got, err := listenerCert(c, region, "171744")
		if err != nil || got != want {
			t.Errorf("%s: %s, %v; want %s", region, got, err, want)
		}
	}
	if got, _ := listenerCert(c, "cn-shanghai", "171744-ap-southeast-1"); got != "171744-ap-southeast-1" {
		t.Errorf("a suffixed id is kept: %s", got)
	}
	if casIDOfListenerCert("171744-ap-southeast-1") != "171744" {
		t.Error("casIDOfListenerCert")
	}
}

func TestALBLoadBalancerListGetAndPages(t *testing.T) {
	h, _, alb, _, _ := albHarness(t, app.Flags{Refresh: true})
	alb.page = 2
	for i := 1; i <= 5; i++ {
		alb.addLB(fmt.Sprintf("alb-%d", i), fmt.Sprintf("lb-%d", i), "vpc-site", "Active", fmt.Sprintf("cn-shanghai-b=eip-%d:203.0.113.%d", i, i))
	}
	if err := h.run("alb", "load-balancer", "list", "--region", "cn-shanghai"); err != nil {
		t.Fatal(err)
	}
	var rows []albLoadBalancer
	h.jsonOut(&rows)
	if len(rows) != 5 {
		t.Fatalf("rows = %+v", rows)
	}
	calls := h.api.callsFor("ListLoadBalancers")
	if len(calls) != 3 || calls[0].Get("MaxResults") != "100" || calls[1].Get("NextToken") != "p2" || calls[2].Get("NextToken") != "p4" {
		t.Errorf("ListLoadBalancers pages = %v", calls)
	}

	alb.addGroup("sgp-1", "g", "HTTP", "vpc-site")
	alb.addListener("lsn-2", "alb-3", "HTTPS", 443, "sgp-1", "1234567")
	h.rt.Flags.Refresh = false
	if err := h.run("alb", "load-balancer", "get", "lb-3"); err != nil {
		t.Fatal(err)
	}
	var d albLBDetail
	h.jsonOut(&d)
	if d.ID != "alb-3" || d.Region != "cn-shanghai" || len(d.Addresses) != 1 || d.Addresses[0].IP != "203.0.113.3" ||
		len(d.Listeners) != 1 || d.Listeners[0].CertificateID != "1234567" {
		t.Errorf("get = %+v", d)
	}
}

func TestALBLoadBalancerRouting(t *testing.T) {
	h, _, alb, _, _ := albHarness(t, app.Flags{})
	alb.addLB("alb-1", "lb-x", "vpc-site", "Active")
	// The inventory knows lb-x in two regions: ambiguous.
	db := h.db()
	set := inventory.Set{Platform: platform.Aliyun, Profile: "ali", Type: platform.ResLoadBalancer}
	for _, r := range []string{"cn-shanghai", "cn-hongkong"} {
		row := albLoadBalancer{ID: "alb-" + r, Name: "lb-x", Region: r}
		if err := db.Upsert(context.Background(), set, row.resource(), time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	err := h.run("alb", "load-balancer", "get", "lb-x")
	var ae *app.AmbiguousError
	if !errors.As(err, &ae) {
		t.Errorf("two regions = %v", err)
	}
	// --region asks that region directly.
	if err := h.run("alb", "load-balancer", "get", "lb-x", "--region", "cn-shanghai"); err != nil {
		t.Errorf("--region = %v", err)
	}
	if err := h.run("alb", "load-balancer", "get", "lb-nosuch", "--region", "cn-shanghai"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing = %v", err)
	}
}

func TestALBListForbiddenAndSyncWarning(t *testing.T) {
	h, _, alb, _, _ := albHarness(t, app.Flags{Refresh: true})
	alb.lbFail, alb.lbFailStatus = "Forbidden.LoadBalancer", 403
	if err := h.run("alb", "load-balancer", "list"); !errors.Is(err, platform.ErrForbidden) {
		t.Errorf("list = %v, want forbidden (exit code 3)", err)
	}
	c, err := openNamed(h.rt, context.Background(), "ali")
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Sync(context.Background(), platform.ResLoadBalancer)
	if len(res) != 0 || platform.AsRegionSyncError(err) == nil {
		t.Errorf("sync = %v, %v; want an empty list with a warning", res, err)
	}
}

func TestALBLoadBalancerCreateAndDelete(t *testing.T) {
	h, net, alb, _, _ := albHarness(t, app.Flags{})
	net.addEIP("eip-1", "203.0.113.1", "Available", "", "", 0, "BGP_PRO")
	net.addEIP("eip-2", "203.0.113.2", "Available", "", "", 0, "BGP_PRO")
	if err := h.run("alb", "load-balancer", "create", "lb-web", "--vpc", "vpc-site", "--zone-mapping", "cn-shanghai-b:vsw-b:eip-1",
		"--zone-mapping", "cn-shanghai-c:vsw-c:eip-2", "--wait"); err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	q := h.api.callsFor("CreateLoadBalancer")[0]
	if q.Get("ZoneMappings.2.VSwitchId") != "vsw-c" || q.Get("ZoneMappings.2.AllocationId") != "eip-2" || q.Get("VpcId") != "vpc-site" {
		t.Errorf("CreateLoadBalancer = %v", q)
	}
	if err := h.run("alb", "load-balancer", "create", "lb-web", "--vpc", "vpc-site", "--zone-mapping", "cn-shanghai-b:vsw-b:eip-1",
		"--zone-mapping", "cn-shanghai-c:vsw-c:eip-2"); err == nil {
		t.Error("a second lb-web was created")
	}
	for _, args := range [][]string{
		{"lb-a", "--zone-mapping", "cn-shanghai-b:vsw-b:eip-1", "--zone-mapping", "cn-shanghai-c:vsw-c:eip-2"},
		{"lb-a", "--vpc", "vpc-site", "--zone-mapping", "cn-shanghai-b:vsw-b:eip-1"},
		{"lb-a", "--vpc", "vpc-site", "--zone-mapping", "b:eip-1", "--zone-mapping", "c:vsw-c:eip-2"},
	} {
		if err := h.run(append([]string{"alb", "load-balancer", "create"}, args...)...); !errors.Is(err, app.ErrUsage) {
			t.Errorf("%v = %v", args, err)
		}
	}

	id := alb.lbs[0]["LoadBalancerId"].(string)
	alb.addGroup("sgp-1", "g", "HTTP", "vpc-site")
	alb.addListener("lsn-1", id, "HTTP", 80, "sgp-1")
	// Non-interactive without --yes: usage error before the account is opened.
	if err := h.run("alb", "load-balancer", "delete", "lb-web", "--region", "cn-shanghai"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("delete without --yes = %v", err)
	}
	h.rt.Flags.Yes = true
	if err := h.run("alb", "load-balancer", "delete", "lb-web", "--region", "cn-shanghai"); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--force") {
		t.Errorf("delete with listeners = %v", err)
	}
	if err := h.run("alb", "load-balancer", "delete", "lb-web", "--region", "cn-shanghai", "--force", "--wait"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(alb.lbs) != 0 || !strings.Contains(h.stderr.String(), "eip-1") || !strings.Contains(h.stderr.String(), "not released") {
		t.Errorf("after delete: %d lbs, stderr %s", len(alb.lbs), h.stderr.String())
	}
	alb.addLB("alb-p", "lb-p", "vpc-site", "Active")["DeletionProtectionConfig"] = map[string]any{"Enabled": true}
	if err := h.run("alb", "load-balancer", "delete", "lb-p", "--region", "cn-shanghai"); err == nil || !strings.Contains(err.Error(), "deletion protection") {
		t.Errorf("protected = %v", err)
	}
}

func TestALBServerGroupsAndListeners(t *testing.T) {
	h, net, alb, _, _ := albHarness(t, app.Flags{Yes: true})
	if err := h.run("alb", "server-group", "create", "web-http", "--vpc", "vpc-site", "--protocol", "http"); err != nil {
		t.Fatal(err)
	}
	if err := h.run("alb", "server-group", "create", "web-http", "--vpc", "vpc-site", "--protocol", "HTTP"); err == nil {
		t.Error("a second group of the name in the VPC was created")
	}
	if err := h.run("alb", "server-group", "server", "add", "web-http", "--instance", "site-a", "--port", "80"); err != nil {
		t.Fatal(err)
	}
	if err := h.run("alb", "server-group", "server", "add", "web-http", "--instance", "i-site", "--port", "80"); err != nil {
		t.Fatal(err)
	}
	if rep := reportOf(t, h); rep.Changes[0].Action != platform.Unchanged || len(h.api.callsFor("AddServersToServerGroup")) != 1 {
		t.Errorf("duplicate server = %+v", rep.Changes)
	}
	if err := h.run("alb", "server-group", "get", "web-http"); err != nil {
		t.Fatal(err)
	}
	var sg albSGDetail
	h.jsonOut(&sg)
	if len(sg.Servers) != 1 || sg.Servers[0].ServerID != "i-site" || sg.Servers[0].Port != 80 {
		t.Errorf("get = %+v", sg)
	}

	alb.addLB("alb-1", "lb-1", "vpc-site", "Active")
	if err := h.run("alb", "listener", "create", "--lb", "lb-1", "--listener", "https:443", "--server-group", "web-http"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("HTTPS without --cert = %v", err)
	}
	if err := h.run("alb", "listener", "create", "--lb", "lb-1", "--listener", "http:80", "--server-group", "web-http"); err != nil {
		t.Fatal(err)
	}
	lsn := alb.listeners[0]["ListenerId"].(string)
	if err := h.run("alb", "listener", "list", "--lb", "lb-1", "--protocol", "HTTP"); err != nil {
		t.Fatal(err)
	}
	var ls []albListener
	h.jsonOut(&ls)
	if len(ls) != 1 || ls[0].ID != lsn || ls[0].Port != 80 {
		t.Errorf("list = %+v", ls)
	}
	alb.addGroup("sgp-2", "web-2", "HTTP", "vpc-site")
	if err := h.run("alb", "listener", "update", lsn, "--server-group", "sgp-2"); err != nil {
		t.Fatal(err)
	}
	if q := h.api.callsFor("UpdateListenerAttribute"); len(q) != 1 || q[0].Get("DefaultActions.1.ForwardGroupConfig.ServerGroupTuples.1.ServerGroupId") != "sgp-2" {
		t.Errorf("update = %v", q)
	}
	if err := h.run("alb", "listener", "get", lsn); err != nil {
		t.Fatal(err)
	}
	var l albListener
	h.jsonOut(&l)
	if !slices.Equal(l.ServerGroups, []string{"sgp-2"}) || l.Status != "Running" {
		t.Errorf("get = %+v", l)
	}
	// The group a listener forwards to cannot be deleted.
	if err := h.run("alb", "server-group", "delete", "web-2"); err == nil || !platform.HasErrorCode(err, "ResourceInUse.ServerGroup") {
		t.Errorf("delete in use = %v", err)
	}
	if err := h.run("alb", "listener", "delete", lsn); err != nil {
		t.Fatal(err)
	}
	if err := h.run("alb", "server-group", "delete", "web-2"); err != nil {
		t.Fatal(err)
	}
	if len(alb.listeners) != 0 || len(alb.groups) != 1 {
		t.Errorf("state = %d listeners, %d groups", len(alb.listeners), len(alb.groups))
	}
	_ = net
}

func TestALBACLs(t *testing.T) {
	h, net, alb, _, _ := albHarness(t, app.Flags{})
	if err := h.run("alb", "acl", "create", "office"); err != nil {
		t.Fatal(err)
	}
	if q := h.api.callsFor("CreateAcl")[0]; q.Get("AclName") != "office" || q.Get("ResourceGroupId") != "rg-default0001" {
		t.Errorf("CreateAcl = %v", q)
	}
	if err := h.run("alb", "acl", "entry", "add", "office", "203.0.113.0/24", "198.51.100.7", "--description", "hq"); err != nil {
		t.Fatal(err)
	}
	q := h.api.callsFor("AddEntriesToAcl")[0]
	if q.Get("AclEntries.1.Entry") != "203.0.113.0/24" || q.Get("AclEntries.2.Entry") != "198.51.100.7/32" || q.Get("AclEntries.1.Description") != "hq" {
		t.Errorf("AddEntriesToAcl = %v", q)
	}
	// Present entries are unchanged; the new one alone is sent.
	if err := h.run("alb", "acl", "entry", "add", "office", "198.51.100.7", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	q = h.api.callsFor("AddEntriesToAcl")[1]
	if q.Get("AclEntries.1.Entry") != "192.0.2.1/32" || q.Get("AclEntries.2.Entry") != "" || q.Get("AclEntries.1.Description") != "" {
		t.Errorf("second AddEntriesToAcl = %v", q)
	}
	rep := reportOf(t, h)
	if countActions(rep, platform.Unchanged) != 1 || countActions(rep, platform.Created) != 1 {
		t.Errorf("report = %+v", rep.Changes)
	}
	// 25 new entries: two calls of at most 20, the ACL waited for between them.
	var many []string
	for i := 0; i < 25; i++ {
		many = append(many, fmt.Sprintf("10.0.%d.0/24", i))
	}
	if err := h.run(append([]string{"alb", "acl", "entry", "add", "office"}, many...)...); err != nil {
		t.Fatal(err)
	}
	if n := len(h.api.callsFor("AddEntriesToAcl")); n != 4 {
		t.Errorf("%d AddEntriesToAcl calls, want 4", n)
	}
	if err := h.run("alb", "acl", "get", "office"); err != nil {
		t.Fatal(err)
	}
	var d albACLDetail
	h.jsonOut(&d)
	if d.EntryCount != 28 || len(d.Entries) != 28 {
		t.Errorf("get = %d entries", d.EntryCount)
	}
	if err := h.run("alb", "acl", "entry", "remove", "office", "192.0.2.1", "192.0.2.99"); err != nil {
		t.Fatal(err)
	}
	if q := h.api.callsFor("RemoveEntriesFromAcl"); len(q) != 1 || q[0].Get("Entries.1") != "192.0.2.1/32" || q[0].Get("Entries.2") != "" {
		t.Errorf("RemoveEntriesFromAcl = %v", q)
	}
	for _, bad := range []string{"203.0.113.5/24", "2001:db8::/32", "nope"} {
		if err := h.run("alb", "acl", "entry", "add", "office", bad); !errors.Is(err, app.ErrUsage) {
			t.Errorf("%s = %v", bad, err)
		}
	}
	// Same-name ACLs are ambiguous.
	alb.addACL("acl-dup", "office")
	var ae *app.AmbiguousError
	if err := h.run("alb", "acl", "get", "office"); !errors.As(err, &ae) {
		t.Errorf("same name = %v", err)
	}
	if err := h.run("alb", "acl", "delete", "acl-dup"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("delete without --yes = %v", err)
	}
	h.rt.Flags.Yes = true
	if err := h.run("alb", "acl", "delete", "acl-dup"); err != nil {
		t.Fatal(err)
	}
	_ = net
}

func TestALBOfflineAndDryRunReads(t *testing.T) {
	h, _, _, _, _ := albHarness(t, app.Flags{Offline: true})
	if err := h.run("alb", "acl", "list"); !errors.Is(err, app.ErrOffline) {
		t.Errorf("offline = %v", err)
	}
	if err := h.run("alb", "load-balancer", "get", "lb-x"); !errors.Is(err, app.ErrOffline) {
		t.Errorf("offline get = %v", err)
	}
}

func TestALBInteractiveConfirmations(t *testing.T) {
	for _, tc := range []struct {
		answer string
		done   bool
	}{{"y\n", true}, {"n\n", false}, {"\n", false}} {
		h, _, alb, _, _ := albHarness(t, app.Flags{})
		alb.addLB("alb-1", "lb-1", "vpc-site", "Active")
		alb.addACL("acl-1", "office")
		h.rt.Picker = terminalStub{t}

		h.rt.Stdin = strings.NewReader(tc.answer)
		err := h.run("alb", "load-balancer", "delete", "lb-1", "--region", "cn-shanghai")
		if !strings.Contains(h.stderr.String(), "Delete load balancer lb-1 (alb-1)? (y/N)") {
			t.Errorf("delete question: %q", h.stderr.String())
		}
		if tc.done != (err == nil) || !tc.done && !errors.Is(err, platform.ErrNothingToDo) || tc.done == (alb.lb("alb-1") != nil) {
			t.Errorf("answer %q: delete = %v", tc.answer, err)
		}

		h.rt.Stdin = strings.NewReader(tc.answer)
		err = h.run("alb", "acl", "delete", "office")
		if tc.done != (err == nil) || !tc.done && !errors.Is(err, platform.ErrNothingToDo) || tc.done == (alb.acl("acl-1") != nil) {
			t.Errorf("answer %q: acl delete = %v", tc.answer, err)
		}
	}
}

func TestALBACLEntryWritesWaitForAConfiguringACL(t *testing.T) {
	h, _, alb, _, _ := albHarness(t, app.Flags{})
	// An earlier write still configures the ACL.
	alb.addACL("acl-busy", "busy")["AclStatus"] = "Configuring"
	alb.pending["acl-busy"] = 2
	if err := h.run("alb", "acl", "entry", "add", "busy", "192.0.2.1"); err != nil {
		t.Fatalf("entry add: %v\n%s", err, h.stderr.String())
	}
	alb.acl("acl-busy")["AclStatus"] = "Configuring"
	alb.pending["acl-busy"] = 2
	if err := h.run("alb", "acl", "entry", "remove", "busy", "192.0.2.1"); err != nil {
		t.Fatalf("entry remove: %v\n%s", err, h.stderr.String())
	}
	if len(h.api.callsFor("AddEntriesToAcl")) != 1 || len(h.api.callsFor("RemoveEntriesFromAcl")) != 1 {
		t.Errorf("writes = %d add, %d remove", len(h.api.callsFor("AddEntriesToAcl")), len(h.api.callsFor("RemoveEntriesFromAcl")))
	}
}

func TestALBLoadBalancerUpdate(t *testing.T) {
	h, _, alb, _, clock := albHarness(t, app.Flags{})
	alb.addLB("alb-1", "lb-1", "vpc-site", "Active")
	alb.addLB("alb-2", "lb-taken", "vpc-site", "Active")
	writes := func() int {
		return len(h.api.callsFor("UpdateLoadBalancerAttribute")) + len(h.api.callsFor("EnableDeletionProtection")) +
			len(h.api.callsFor("DisableDeletionProtection"))
	}
	if err := h.run("alb", "load-balancer", "update", "lb-1", "--region", "cn-shanghai"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("no flag = %v", err)
	}
	if err := h.run("alb", "load-balancer", "update", "lb-1", "--region", "cn-shanghai", "--name", "alb-x"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("id-like name = %v", err)
	}

	// Dry run: both changes reported, nothing written.
	h.rt.Flags.DryRun = true
	if err := h.run("alb", "load-balancer", "update", "lb-1", "--region", "cn-shanghai", "--name", "lb-2", "--deletion-protection"); err != nil {
		t.Fatal(err)
	}
	rep := reportOf(t, h)
	if len(rep.Changes) != 2 || rep.Changes[0].Action != platform.WouldUpdate || rep.Changes[0].Resource != "load-balancer/lb-1/deletion-protection" ||
		rep.Changes[0].Detail != "false -> true" || rep.Changes[1].Resource != "load-balancer/lb-1/name" || rep.Changes[1].Detail != "lb-1 -> lb-2" {
		t.Errorf("dry run = %+v", rep.Changes)
	}
	if writes() != 0 {
		t.Error("dry run wrote")
	}
	h.rt.Flags.DryRun = false

	if err := h.run("alb", "load-balancer", "update", "lb-1", "--region", "cn-shanghai", "--name", "lb-2", "--deletion-protection"); err != nil {
		t.Fatalf("update: %v\n%s", err, h.stderr.String())
	}
	if q := h.api.callsFor("EnableDeletionProtection"); len(q) != 1 || q[0].Get("ResourceId") != "alb-1" {
		t.Errorf("EnableDeletionProtection = %v", q)
	}
	if q := h.api.callsFor("UpdateLoadBalancerAttribute"); len(q) != 1 || q[0].Get("LoadBalancerName") != "lb-2" || q[0].Get("LoadBalancerId") != "alb-1" {
		t.Errorf("UpdateLoadBalancerAttribute = %v", q)
	}
	// It waited until the load balancer was Active again.
	if l := alb.lb("alb-1"); l["LoadBalancerStatus"] != "Active" || l["LoadBalancerName"] != "lb-2" || len(clock.sleeps) != 2 {
		t.Errorf("after update: %v, sleeps %v", l, clock.sleeps)
	}

	// The same values again: unchanged, nothing written.
	before := writes()
	if err := h.run("alb", "load-balancer", "update", "alb-1", "--region", "cn-shanghai", "--name", "lb-2", "--deletion-protection"); err != nil {
		t.Fatal(err)
	}
	if rep := reportOf(t, h); writes() != before || len(rep.Changes) != 2 || rep.Changes[0].Action != platform.Unchanged || rep.Changes[1].Action != platform.Unchanged {
		t.Errorf("same values: %+v", rep.Changes)
	}

	// --deletion-protection=false switches it off; --no-wait does not wait.
	if err := h.run("alb", "load-balancer", "update", "lb-2", "--region", "cn-shanghai", "--deletion-protection=false", "--name", "lb-3", "--no-wait"); err != nil {
		t.Fatal(err)
	}
	if q := h.api.callsFor("DisableDeletionProtection"); len(q) != 1 || alb.lb("alb-1")["DeletionProtectionConfig"].(map[string]any)["Enabled"] != false {
		t.Errorf("DisableDeletionProtection = %v", q)
	}
	if len(clock.sleeps) != 2 || alb.lb("alb-1")["LoadBalancerStatus"] != "Configuring" {
		t.Errorf("--no-wait waited: %v", clock.sleeps)
	}

	// A name another load balancer holds is refused before any write.
	before = writes()
	if err := h.run("alb", "load-balancer", "update", "alb-1", "--region", "cn-shanghai", "--name", "lb-taken"); err == nil || errors.Is(err, app.ErrUsage) || writes() != before {
		t.Errorf("taken name = %v", err)
	}
	if err := h.run("alb", "load-balancer", "update", "lb-nosuch", "--region", "cn-shanghai", "--deletion-protection"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing = %v", err)
	}
	alb.addLB("alb-3", "lb-dup", "vpc-site", "Active")
	alb.addLB("alb-4", "lb-dup", "vpc-site", "Active")
	var ae *app.AmbiguousError
	if err := h.run("alb", "load-balancer", "update", "lb-dup", "--region", "cn-shanghai", "--deletion-protection"); !errors.As(err, &ae) {
		t.Errorf("ambiguous = %v", err)
	}
	// An unknown API error is a general failure.
	alb.addLB("alb-5", "lb-busy", "vpc-site", "Provisioning")
	alb.pending["alb-5"] = 100
	err := h.run("alb", "load-balancer", "update", "alb-5", "--region", "cn-shanghai", "--name", "lb-busy-2")
	if err == nil || !platform.HasErrorCode(err, "IncorrectStatus.LoadBalancer") || errors.Is(err, app.ErrUsage) || errors.Is(err, platform.ErrNotFound) {
		t.Errorf("busy = %v", err)
	}
}

func TestALBServerGroupUpdate(t *testing.T) {
	h, _, alb, _, _ := albHarness(t, app.Flags{})
	alb.addGroup("sgp-1", "web", "HTTP", "vpc-site")
	alb.addGroup("sgp-2", "web-taken", "HTTP", "vpc-site")
	calls := func() []url.Values { return h.api.callsFor("UpdateServerGroupAttribute") }
	for _, args := range [][]string{
		{},
		{"--scheduler", "rr"},
		{"--health-check-path", "healthz"},
		{"--health-check=false", "--health-check-path", "/healthz"},
		{"--name", "sgp-x"},
		// The health check is off: a path alone has nothing to apply to.
		{"--health-check-path", "/healthz"},
	} {
		if err := h.run(append([]string{"alb", "server-group", "update", "web"}, args...)...); !errors.Is(err, app.ErrUsage) {
			t.Errorf("%v = %v", args, err)
		}
	}
	if len(calls()) != 0 {
		t.Fatal("a usage error wrote")
	}

	h.rt.Flags.DryRun = true
	if err := h.run("alb", "server-group", "update", "web", "--name", "web-2", "--scheduler", "wlc"); err != nil {
		t.Fatal(err)
	}
	rep := reportOf(t, h)
	if len(rep.Changes) != 1 || rep.Changes[0].Action != platform.WouldUpdate || rep.Changes[0].Resource != "server-group/web" ||
		rep.Changes[0].Detail != "name web -> web-2; scheduler Wrr -> Wlc" || len(calls()) != 0 {
		t.Errorf("dry run = %+v", rep.Changes)
	}
	h.rt.Flags.DryRun = false

	if err := h.run("alb", "server-group", "update", "web", "--scheduler", "wlc", "--health-check", "--health-check-path", "/healthz", "--sticky-session"); err != nil {
		t.Fatalf("update: %v", err)
	}
	q := calls()
	if len(q) != 1 || q[0].Get("Scheduler") != "Wlc" || q[0].Get("HealthCheckConfig.HealthCheckEnabled") != "true" ||
		q[0].Get("HealthCheckConfig.HealthCheckPath") != "/healthz" || q[0].Get("StickySessionConfig.StickySessionEnabled") != "true" ||
		q[0].Get("StickySessionConfig.StickySessionType") != "Insert" || q[0].Has("ServerGroupName") {
		t.Errorf("UpdateServerGroupAttribute = %v", q)
	}
	if err := h.run("alb", "server-group", "get", "sgp-1"); err != nil {
		t.Fatal(err)
	}
	var g albSGDetail
	h.jsonOut(&g)
	if g.Scheduler != "Wlc" || !g.HealthCheck || g.HealthCheckPath != "/healthz" || !g.StickySession || g.Status != "Available" {
		t.Errorf("get = %+v", g)
	}

	// The same values again: unchanged, nothing written.
	if err := h.run("alb", "server-group", "update", "sgp-1", "--scheduler", "Wlc", "--health-check", "--health-check-path", "/healthz", "--sticky-session"); err != nil {
		t.Fatal(err)
	}
	if rep := reportOf(t, h); len(calls()) != 1 || rep.Changes[0].Action != platform.Unchanged {
		t.Errorf("same values: %+v", rep.Changes)
	}

	// A new path for a health check that is on keeps it on.
	if err := h.run("alb", "server-group", "update", "web", "--health-check-path", "/ready"); err != nil {
		t.Fatal(err)
	}
	if q := calls(); len(q) != 2 || q[1].Get("HealthCheckConfig.HealthCheckEnabled") != "true" || q[1].Get("HealthCheckConfig.HealthCheckPath") != "/ready" ||
		q[1].Has("Scheduler") || q[1].Has("StickySessionConfig.StickySessionEnabled") {
		t.Errorf("path only = %v", q)
	}
	if err := h.run("alb", "server-group", "update", "web", "--health-check=false", "--sticky-session=false", "--name", "web-2"); err != nil {
		t.Fatal(err)
	}
	if q := calls(); len(q) != 3 || q[2].Get("HealthCheckConfig.HealthCheckEnabled") != "false" || q[2].Has("HealthCheckConfig.HealthCheckPath") ||
		q[2].Get("StickySessionConfig.StickySessionEnabled") != "false" || q[2].Has("StickySessionConfig.StickySessionType") || q[2].Get("ServerGroupName") != "web-2" {
		t.Errorf("off = %v", q)
	}

	// A name another group of the VPC holds is refused before any write.
	if err := h.run("alb", "server-group", "update", "web-2", "--name", "web-taken"); err == nil || errors.Is(err, app.ErrUsage) || len(calls()) != 3 {
		t.Errorf("taken name = %v", err)
	}
	if err := h.run("alb", "server-group", "update", "nosuch", "--scheduler", "Sch"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing = %v", err)
	}
	alb.addGroup("sgp-3", "dup", "HTTP", "vpc-site")
	alb.addGroup("sgp-4", "dup", "HTTP", "vpc-site")
	var ae *app.AmbiguousError
	if err := h.run("alb", "server-group", "update", "dup", "--scheduler", "Sch"); !errors.As(err, &ae) {
		t.Errorf("ambiguous = %v", err)
	}
}
