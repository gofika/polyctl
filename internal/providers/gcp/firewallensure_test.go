package gcp

import (
	"context"
	"slices"
	"strings"
	"testing"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// lbRangesNetA are the ranges the health check rule of net-a needs in
// us-central1: the subnetwork, its secondary range, the three proxy-only
// subnetworks and the health check ranges (net-a-2 and europe-west1 left
// out).
var lbRangesNetA = []string{"10.0.0.0/24", "10.129.0.0/23", "10.130.0.0/23", "10.131.0.0/23", "10.4.0.0/14", "130.211.0.0/22", "35.191.0.0/16"}

// addNetAInstance adds the instance web-1 on net-a with the tag
// http-server.
func (f *fakeCompute) addNetAInstance(status string) *compute.Instance {
	in := f.addInstance("proj", "us-central1-a", "web-1", "10.0.0.5", "203.0.113.10")
	f.mu.Lock()
	defer f.mu.Unlock()
	in.NetworkInterfaces[0].Network = apiBase + "projects/proj/global/networks/net-a"
	in.Tags = &compute.Tags{Items: []string{"http-server"}}
	in.Status = status
	return in
}

func TestFirewallEnsurePresetCreates(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.gce.addVPCs()
	h.gce.addNetAInstance(statusTerminated)
	if err := h.run("compute", "firewall", "ensure", "--preset", "lb-health-check", "--instance", "web-1"); err != nil {
		t.Fatal(err)
	}
	fw := h.gce.firewall("allow-lb-health-check-net-a")
	if fw == nil || !slices.Equal(fw.SourceRanges, lbRangesNetA) || !slices.Equal(fw.TargetTags, []string{"lb-health-check"}) ||
		allowedLabel(fw.Allowed) != "tcp" || fw.Priority != 1000 || fw.Direction != dirIngress || lastSegment(fw.Network) != "net-a" ||
		fw.Description != "Allow health check and proxy traffic for load balancer on net-a" {
		t.Fatalf("rule = %+v", fw)
	}
	// The instance keeps its tag (stopped instances take tags too).
	if in := h.gce.instance("us-central1-a", "web-1"); !slices.Equal(in.Tags.Items, []string{"http-server", "lb-health-check"}) {
		t.Errorf("tags = %v", in.Tags.Items)
	}
	if w := h.gce.firewallWrites(); !slices.Equal(w, []string{"POST firewalls", "POST setTags"}) {
		t.Errorf("writes = %v", w)
	}
	rep := h.report()
	if got := rows(rep); !slices.Equal(got, []string{
		"firewall/allow-lb-health-check-net-a created tcp, 7 source ranges, tag lb-health-check",
		"instance/web-1/tag created lb-health-check"}) || rep.Target.Region != "us-central1" || rep.Target.Profile != "lab" ||
		rep.Changes[0].Attrs["source_ranges"] != strings.Join(lbRangesNetA, ",") {
		t.Errorf("report = %v %+v", got, rep)
	}
	// Run again: nothing to do.
	if err := h.run("compute", "firewall", "ensure", "--preset", "lb-health-check", "--instance", "web-1"); err != nil {
		t.Fatal(err)
	}
	if got := rows(h.report()); len(h.gce.firewallWrites()) != 0 || !strings.Contains(got[0], "unchanged") || got[1] != "instance/web-1/tag unchanged lb-health-check" {
		t.Errorf("second run = %v %v", got, h.gce.firewallWrites())
	}
}

func TestFirewallEnsurePresetDryRun(t *testing.T) {
	h := newGCPHarness(t, app.Flags{DryRun: true}, nil)
	h.gce.addVPCs()
	h.gce.addNetAInstance(statusRunning)
	if err := h.run("compute", "firewall", "ensure", "--preset", "lb-health-check", "--network", "net-a", "--region", "us-central1", "--instance", "web-1"); err != nil {
		t.Fatal(err)
	}
	rep := h.report()
	if got := rows(rep); !rep.DryRun || !slices.Equal(got, []string{
		"firewall/allow-lb-health-check-net-a would_create tcp, 7 source ranges, tag lb-health-check",
		"instance/web-1/tag would_create lb-health-check"}) {
		t.Errorf("dry run = %v", got)
	}
	if w := h.gce.firewallWrites(); len(w) != 0 || h.gce.firewall("allow-lb-health-check-net-a") != nil {
		t.Errorf("dry run wrote %v", w)
	}
	// An existing rule missing a range: would update.
	h.gce.addFirewall(&compute.Firewall{Name: "allow-lb-health-check-net-a", Network: "net-a", Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp"}},
		SourceRanges: lbRangesNetA[1:], TargetTags: []string{"lb-health-check"}})
	if err := h.run("compute", "firewall", "ensure", "--preset", "lb-health-check", "--network", "net-a", "--region", "us-central1"); err != nil {
		t.Fatal(err)
	}
	if got := rows(h.report()); !slices.Equal(got, []string{"firewall/allow-lb-health-check-net-a would_update +10.0.0.0/24 (now 7 ranges)"}) || len(h.gce.firewallWrites()) != 0 {
		t.Errorf("dry run update = %v", got)
	}
}

func TestFirewallEnsurePresetAddsOnly(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.gce.addVPCs()
	// The rule lacks one range and the tag, and has an extra range of a
	// deleted subnetwork, which stays.
	have := append([]string{"10.99.0.0/24"}, lbRangesNetA[1:]...)
	h.gce.addFirewall(&compute.Firewall{Name: "allow-lb-health-check-net-a", Network: "net-a", Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"80"}}},
		SourceRanges: have, TargetTags: []string{"web"}, Description: "custom"})
	if err := h.run("compute", "firewall", "ensure", "--preset", "lb-health-check", "--network", "net-a", "--region", "us-central1"); err != nil {
		t.Fatal(err)
	}
	fw := h.gce.firewall("allow-lb-health-check-net-a")
	want := append([]string{"10.0.0.0/24"}, lbRangesNetA[1:]...)
	want = append(want, "10.99.0.0/24")
	slices.Sort(want)
	if !slices.Equal(fw.SourceRanges, want) || !slices.Equal(fw.TargetTags, []string{"web", "lb-health-check"}) || allowedLabel(fw.Allowed) != "tcp:80" || fw.Description != "custom" {
		t.Errorf("rule = %+v", fw)
	}
	if w := h.gce.firewallWrites(); !slices.Equal(w, []string{"PATCH firewalls/allow-lb-health-check-net-a"}) {
		t.Errorf("writes = %v", w)
	}
	if got := rows(h.report()); !slices.Equal(got, []string{"firewall/allow-lb-health-check-net-a updated +10.0.0.0/24 (now 8 ranges); +tag lb-health-check"}) {
		t.Errorf("report = %v", got)
	}
	// A rule that lacks tcp gets it added.
	h.gce.addFirewall(&compute.Firewall{Name: "allow-lb-health-check-default", Network: "default", Allowed: []*compute.FirewallAllowed{{IPProtocol: "udp"}},
		SourceRanges: []string{"10.128.0.0/20", "130.211.0.0/22", "35.191.0.0/16"}, TargetTags: []string{"lb-health-check"}})
	if err := h.run("compute", "firewall", "ensure", "--preset", "lb-health-check", "--region", "us-central1"); err != nil {
		t.Fatal(err)
	}
	if fw := h.gce.firewall("allow-lb-health-check-default"); allowedLabel(fw.Allowed) != "udp tcp" {
		t.Errorf("tcp added = %v", allowedLabel(fw.Allowed))
	}
}

func TestFirewallEnsurePresetRefusesDisabledOrEgress(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.gce.addFirewall(&compute.Firewall{Name: "allow-lb-health-check-default", Network: "default", Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp"}},
		SourceRanges: []string{"10.0.0.0/8"}, Disabled: true})
	err := h.run("compute", "firewall", "ensure", "--preset", "lb-health-check", "--region", "us-central1")
	if exitClass(err) != "general" || !strings.Contains(err.Error(), "disabled") || len(h.gce.firewallWrites()) != 0 {
		t.Errorf("disabled = %v %v", err, h.gce.firewallWrites())
	}
	h.gce.addFirewall(&compute.Firewall{Name: "allow-lb-health-check-default", Network: "default", Direction: dirEgress, Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp"}},
		DestinationRanges: []string{"10.0.0.0/8"}})
	err = h.run("compute", "firewall", "ensure", "--preset", "lb-health-check", "--region", "us-central1")
	if exitClass(err) != "general" || !strings.Contains(err.Error(), "EGRESS") || len(h.gce.firewallWrites()) != 0 {
		t.Errorf("egress = %v %v", err, h.gce.firewallWrites())
	}
	h.gce.addFirewall(&compute.Firewall{Name: "allow-lb-health-check-default", Network: "net-x", Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp"}}, SourceRanges: []string{"10.0.0.0/8"}})
	if err := h.run("compute", "firewall", "ensure", "--preset", "lb-health-check", "--region", "us-central1"); exitClass(err) != "general" || !strings.Contains(err.Error(), "net-x") {
		t.Errorf("other network = %v", err)
	}
}

func TestFirewallEnsurePresetForbidden(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	forbidden := fakeErr{403, "forbidden", "Required 'compute.firewalls.create' permission for 'projects/proj'"}
	h.gce.fail["POST /projects/proj/global/firewalls"] = forbidden
	// The standalone ensure fails with the auth exit code.
	if err := h.run("compute", "firewall", "ensure", "--preset", "lb-health-check", "--region", "us-central1"); exitClass(err) != "auth" {
		t.Errorf("standalone = %v", err)
	}
	// Called by a load balancer ensure, the rule is skipped and the plan
	// goes on.
	c, _, err := openClient(context.Background(), h.rt)
	if err != nil {
		t.Fatal(err)
	}
	step, err := c.EnsureLBFirewall(context.Background(), LBFirewallOptions{Network: "default", Region: "us-central1", Wait: true, SkipForbidden: true})
	if err != nil {
		t.Fatal(err)
	}
	var plan platform.Plan
	plan.Add(step, platform.Step{Resource: "next", Action: platform.Unchanged})
	changes, err := plan.Run(context.Background(), false)
	if err != nil || len(changes) != 2 || changes[0].Action != platform.Skipped || changes[0].Resource != "firewall/allow-lb-health-check-default" {
		t.Errorf("skip on apply = %+v, %v", changes, err)
	}
	// A 403 while observing is skipped as well.
	h.gce.fail["GET /projects/proj/global/firewalls/"] = forbidden
	step, err = c.EnsureLBFirewall(context.Background(), LBFirewallOptions{Network: "default", Region: "us-central1", SkipForbidden: true})
	if err != nil || step.Action != platform.Skipped || step.Apply != nil {
		t.Errorf("skip on observe = %+v, %v", step, err)
	}
	// A disabled API is not skipped.
	h.gce.fail["GET /projects/proj/global/firewalls/"] = fakeErr{403, "accessNotConfigured", "Compute Engine API has not been used in project proj before or it is disabled."}
	if _, err := c.EnsureLBFirewall(context.Background(), LBFirewallOptions{Network: "default", Region: "us-central1", SkipForbidden: true}); exitClass(err) != "auth" {
		t.Errorf("disabled api = %v", err)
	}
}

func TestEnsureInstanceTag(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.gce.addVPCs()
	h.gce.addNetAInstance(statusRunning)
	c, _, err := openClient(context.Background(), h.rt)
	if err != nil {
		t.Fatal(err)
	}
	in, err := c.getInstance(context.Background(), "us-central1-a", "web-1")
	if err != nil {
		t.Fatal(err)
	}
	// The tags change between the read and the write: 412, read again,
	// retried once; the other tag is kept.
	h.gce.staleTags = 1
	var stored *compute.Instance
	step := c.EnsureInstanceTag("us-central1-a", in, "lb-health-check", true, 0, func(i *compute.Instance) { stored = i })
	var plan platform.Plan
	plan.Add(step)
	changes, err := plan.Run(context.Background(), false)
	if err != nil || changes[0].Action != platform.Created {
		t.Fatalf("set tags = %+v, %v", changes, err)
	}
	got := h.gce.instance("us-central1-a", "web-1").Tags.Items
	if !slices.Equal(got, []string{"http-server", "lb-health-check", "other"}) || stored == nil || !slices.Contains(stored.Tags.Items, "lb-health-check") {
		t.Errorf("tags = %v, stored %v", got, stored)
	}
	// Already tagged: no write.
	in, _ = c.getInstance(context.Background(), "us-central1-a", "web-1")
	if st := c.EnsureInstanceTag("us-central1-a", in, "lb-health-check", true, 0, nil); st.Action != platform.Unchanged || st.Apply != nil {
		t.Errorf("tagged = %+v", st)
	}
	// Two stale reads in a row: the second 412 is an error.
	h.gce.addInstance("proj", "us-central1-a", "web-2", "10.0.0.6", "")
	in, _ = c.getInstance(context.Background(), "us-central1-a", "web-2")
	h.gce.staleTags = 2
	plan = platform.Plan{}
	plan.Add(c.EnsureInstanceTag("us-central1-a", in, "lb-health-check", true, 0, nil))
	if _, err := plan.Run(context.Background(), false); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Errorf("twice stale = %v", err)
	}
}

func TestFirewallEnsurePresetFlags(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, map[string]any{"zone": "us-central1-b", "lb_network_tag": "hc"})
	h.gce.addVPCs()
	// --region defaults to the region of defaults.gcp.zone; the tag to
	// defaults.gcp.lb_network_tag; an explicit name and ports.
	if err := h.run("compute", "firewall", "ensure", "hc-default", "--preset", "lb-health-check", "--allow", "tcp:80,8080"); err != nil {
		t.Fatal(err)
	}
	fw := h.gce.firewall("hc-default")
	if fw == nil || !slices.Equal(fw.TargetTags, []string{"hc"}) || allowedLabel(fw.Allowed) != "tcp:80,8080" ||
		!slices.Equal(fw.SourceRanges, []string{"10.128.0.0/20", "130.211.0.0/22", "35.191.0.0/16"}) {
		t.Errorf("rule = %+v", fw)
	}
	// With explicit ports, a rule allowing other ports gets them added.
	if err := h.run("compute", "firewall", "ensure", "hc-default", "--preset", "lb-health-check", "--allow", "tcp:443"); err != nil {
		t.Fatal(err)
	}
	if fw := h.gce.firewall("hc-default"); allowedLabel(fw.Allowed) != "tcp:80,443,8080" {
		t.Errorf("ports = %v", allowedLabel(fw.Allowed))
	}
	for _, args := range [][]string{
		{"--preset", "lb-health-check", "--source-range", "10.0.0.0/8"},
		{"--preset", "lb-health-check", "--priority", "900"},
		{"--preset", "lb-health-check", "--direction", "egress"},
		{"--preset", "lb-health-check", "--target-tag", "a", "--target-tag", "b"},
		{"--preset", "lb-health-check", "--zone", "us-central1-a"},
		{"--preset", "bogus"},
		{"--preset", "lb-health-check", "--allow", "all:80"},
		{"Bad_Name", "--preset", "lb-health-check"},
		{"--allow", "tcp:22", "--source-range", "10.0.0.0/8"}, // no name without preset
		{"r", "--allow", "tcp:22", "--source-range", "10.0.0.0/8", "--region", "us-central1"},
		{"r", "--allow", "tcp:22"}, // ingress without a source
	} {
		if err := h.run(append([]string{"compute", "firewall", "ensure"}, args...)...); exitClass(err) != "usage" {
			t.Errorf("ensure %v = %v; want a usage error", args, err)
		}
	}
	// No region anywhere is a usage error.
	h2 := newGCPHarness(t, app.Flags{}, nil)
	if err := h2.run("compute", "firewall", "ensure", "--preset", "lb-health-check"); exitClass(err) != "usage" || !strings.Contains(err.Error(), "--region") {
		t.Errorf("no region = %v", err)
	}
	// A missing network is exit code 4.
	if err := h2.run("compute", "firewall", "ensure", "--preset", "lb-health-check", "--network", "nope", "--region", "us-central1"); exitClass(err) != "notfound" {
		t.Errorf("missing network = %v", err)
	}
	// An instance on another network than --network is a usage error.
	h2.gce.addVPCs()
	h2.gce.addNetAInstance(statusRunning)
	if err := h2.run("compute", "firewall", "ensure", "--preset", "lb-health-check", "--network", "default", "--instance", "web-1"); exitClass(err) != "usage" || len(h2.gce.firewallWrites()) != 0 {
		t.Errorf("instance on another network = %v", err)
	}
}

func TestFirewallEnsurePresetNaming(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	long := "net-" + strings.Repeat("x", 55)
	name := fitName("allow-lb-health-check-" + long)
	if len(name) > 63 || name != fitName("allow-lb-health-check-"+long) || !strings.HasPrefix(name, "allow-lb-health-check-net-xxx") ||
		name == fitName("allow-lb-health-check-"+long+"y") || checkFirewallName(name) != nil {
		t.Errorf("fitName = %q", name)
	}
	if fitName("allow-lb-health-check-short") != "allow-lb-health-check-short" {
		t.Error("short names are kept")
	}
	h.gce.mu.Lock()
	h.gce.networks["proj/"+long] = &compute.Network{Name: long}
	h.gce.mu.Unlock()
	if err := h.run("compute", "firewall", "ensure", "--preset", "lb-health-check", "--network", long, "--region", "us-central1"); err != nil {
		t.Fatal(err)
	}
	if h.gce.firewall(name) == nil {
		t.Errorf("rule %s not created", name)
	}
}

func TestFirewallEnsureNamingTemplate(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	cfg, err := h.rt.Config()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Naming = map[string]string{"gcp_lb_firewall": "hc-{network}-{region}"}
	if err := h.run("compute", "firewall", "ensure", "--preset", "lb-health-check", "--region", "us-central1"); err != nil {
		t.Fatal(err)
	}
	if h.gce.firewall("hc-default-us-central1") == nil {
		t.Errorf("templated name not used: %v", h.gce.firewallWrites())
	}
}

func TestFirewallEnsureCustom(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	args := []string{"compute", "firewall", "ensure", "allow-ssh", "--allow", "tcp:22", "--source-range", "10.0.0.0/8", "--target-tag", "ssh"}
	if err := h.run(args...); err != nil {
		t.Fatal(err)
	}
	if fw := h.gce.firewall("allow-ssh"); fw == nil || allowedLabel(fw.Allowed) != "tcp:22" || fw.Priority != 1000 {
		t.Fatalf("created = %+v", fw)
	}
	if err := h.run(args...); err != nil || len(h.gce.firewallWrites()) != 0 || !strings.Contains(rows(h.report())[0], "unchanged") {
		t.Errorf("again = %v %v", err, h.gce.firewallWrites())
	}
	// A union: the new range, tag and port are added, nothing is removed.
	if err := h.run("compute", "firewall", "ensure", "allow-ssh", "--allow", "tcp:2222", "--source-range", "192.168.0.0/16", "--target-tag", "bastion", "--priority", "900"); err != nil {
		t.Fatal(err)
	}
	fw := h.gce.firewall("allow-ssh")
	if !slices.Equal(fw.SourceRanges, []string{"10.0.0.0/8", "192.168.0.0/16"}) || !slices.Equal(fw.TargetTags, []string{"ssh", "bastion"}) ||
		allowedLabel(fw.Allowed) != "tcp:22,2222" || fw.Priority != 900 {
		t.Errorf("union = %+v", fw)
	}
	if got := rows(h.report()); len(got) != 1 || got[0] != "firewall/allow-ssh updated +192.168.0.0/16 (now 2 ranges); +tag bastion; +tcp:2222; priority 1000 -> 900" {
		t.Errorf("report = %v", got)
	}
	// Egress rules converge their destination ranges.
	if err := h.run("compute", "firewall", "ensure", "out", "--direction", "egress", "--allow", "udp:53", "--destination-range", "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if err := h.run("compute", "firewall", "ensure", "out", "--direction", "egress", "--allow", "udp:53", "--destination-range", "1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	if fw := h.gce.firewall("out"); !slices.Equal(fw.DestinationRanges, []string{"1.1.1.1/32", "8.8.8.8/32"}) {
		t.Errorf("egress = %+v", fw)
	}
	// The same name as an ingress rule: the direction is not changed.
	if err := h.run("compute", "firewall", "ensure", "out", "--allow", "udp:53", "--source-range", "1.1.1.1"); exitClass(err) != "general" {
		t.Errorf("direction = %v", err)
	}
}

func TestFirewallEnsurePresetUsesTheInstanceProfile(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.addProfile()
	cfg, err := h.rt.Config()
	if err != nil {
		t.Fatal(err)
	}
	cfg.CurrentProfile = "prod"
	h.gce.addInstance("proj", "us-central1-a", "web-1", "10.128.0.5", "")
	if err := h.run("compute", "firewall", "ensure", "--preset", "lb-health-check", "--instance", "web-1"); err != nil {
		t.Fatal(err)
	}
	rep := h.report()
	if rep.Target.Profile != "lab" || rep.Target.Region != "us-central1" || !strings.Contains(h.stderr.String(), "note: instance web-1 is in gcp/lab, not gcp/prod") ||
		h.gce.firewall("allow-lb-health-check-default") == nil {
		t.Errorf("report = %+v\n%s", rep, h.stderr.String())
	}
}

func TestFirewallEnsureKeepsRuleForEveryInstance(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	// No target tags: the rule already applies to every instance, and a
	// tag would narrow it.
	h.gce.addFirewall(&compute.Firewall{Name: "allow-ssh", Network: "default", Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"22"}}},
		SourceRanges: []string{"10.0.0.0/8"}})
	if err := h.run("compute", "firewall", "ensure", "allow-ssh", "--allow", "tcp:22", "--source-range", "10.0.0.0/8", "--target-tag", "ssh"); err != nil {
		t.Fatal(err)
	}
	if fw := h.gce.firewall("allow-ssh"); len(fw.TargetTags) != 0 || len(h.gce.firewallWrites()) != 0 || !strings.Contains(rows(h.report())[0], "unchanged") {
		t.Errorf("rule = %+v writes %v", fw, h.gce.firewallWrites())
	}
	// A rule targeting service accounts is left alone.
	h.gce.addFirewall(&compute.Firewall{Name: "by-sa", Network: "default", Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp"}},
		SourceRanges: []string{"10.0.0.0/8"}, TargetServiceAccounts: []string{"sa@example.iam.gserviceaccount.com"}})
	if err := h.run("compute", "firewall", "ensure", "by-sa", "--allow", "tcp", "--source-range", "10.0.0.0/8", "--target-tag", "web"); exitClass(err) != "general" || len(h.gce.firewallWrites()) != 0 {
		t.Errorf("service accounts = %v %v", err, h.gce.firewallWrites())
	}
}
