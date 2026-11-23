package gcp

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

func TestParseAllow(t *testing.T) {
	for in, want := range map[string]string{
		"tcp:80,443,8000-8100":  "tcp:80,443,8000-8100",
		"tcp:ssh":               "tcp:22",
		"TCP:https|tcp:80":      "tcp:80,443",
		"tcp|tcp:80":            "tcp",
		"udp:53|icmp":           "udp:53 icmp",
		"all":                   "all",
		"tcp:mysql,3306|udp":    "tcp:3306 udp",
		"tcp:8000-8100|tcp:22":  "tcp:22,8000-8100",
		"tcp:443|tcp:443,https": "tcp:443",
	} {
		got, err := parseAllow(strings.Split(in, "|"))
		if err != nil || allowedLabel(got) != want {
			t.Errorf("parseAllow(%q) = %q, %v; want %q", in, allowedLabel(got), err, want)
		}
	}
	for _, bad := range []string{"all:80", "icmp:8", "sctp", "tcp:", "tcp:70000", "tcp:bogus", "tcp:90-80", ""} {
		if _, err := parseAllow([]string{bad}); !errors.Is(err, app.ErrUsage) {
			t.Errorf("parseAllow(%q) = %v; want a usage error", bad, err)
		}
	}
}

func TestParseCIDRs(t *testing.T) {
	got, err := parseCIDRs("source-range", []string{"10.0.0.5/8", "203.0.113.7", "10.0.0.0/8", "2001:db8::1"})
	if err != nil || strings.Join(got, ",") != "10.0.0.0/8,2001:db8::1/128,203.0.113.7/32" {
		t.Errorf("parseCIDRs = %v, %v", got, err)
	}
	if _, err := parseCIDRs("source-range", []string{"sg-123"}); !errors.Is(err, app.ErrUsage) {
		t.Errorf("sg = %v", err)
	}
}

func TestFirewallListMatchesNetworkExactly(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.gce.addVPCs()
	h.gce.addFirewall(&compute.Firewall{Name: "a-ssh", Network: "net-a", Priority: 900, Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"22"}}}, SourceRanges: []string{"10.0.0.0/8"}})
	h.gce.addFirewall(&compute.Firewall{Name: "a-web", Network: "net-a", Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp"}}, SourceRanges: []string{"0.0.0.0/0"}, TargetTags: []string{"web"}})
	h.gce.addFirewall(&compute.Firewall{Name: "a2-web", Network: "net-a-2", Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp"}}, SourceRanges: []string{"0.0.0.0/0"}})
	h.gce.addFirewall(&compute.Firewall{Name: "default-deny", Network: "default", Priority: 100, Denied: []*compute.FirewallDenied{{IPProtocol: "all"}}, SourceRanges: []string{"0.0.0.0/0"}})
	names := func() string {
		t.Helper()
		var rows []firewallView
		h.jsonOut(&rows)
		var out []string
		for _, r := range rows {
			out = append(out, r.Name)
		}
		return strings.Join(out, ",")
	}
	if err := h.run("compute", "firewall", "list"); err != nil {
		t.Fatal(err)
	}
	// Every network, sorted by priority.
	if got := names(); got != "default-deny,a-ssh,a-web,a2-web" {
		t.Errorf("all = %s", got)
	}
	if err := h.run("compute", "firewall", "list", "--network", "net-a"); err != nil {
		t.Fatal(err)
	}
	if got := names(); got != "a-ssh,a-web" {
		t.Errorf("net-a = %s", got)
	}
	if err := h.run("compute", "firewall", "list", "--network", "nope"); err != nil || strings.TrimSpace(h.stdout.String()) != "[]" || !strings.Contains(h.stderr.String(), "no firewall rules") {
		t.Errorf("empty = %v %q", err, h.stdout.String())
	}
	ht := newGCPHarness(t, app.Flags{Output: "table"}, nil)
	ht.gce.addFirewall(&compute.Firewall{Name: "a-ssh", Network: "default", Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"22"}}}, SourceRanges: []string{"10.0.0.0/8", "10.1.0.0/16"}, TargetTags: []string{"ssh"}})
	if err := ht.run("compute", "firewall", "list"); err != nil {
		t.Fatal(err)
	}
	if out := ht.stdout.String(); !strings.Contains(out, "TARGET-TAGS") || !strings.Contains(out, "tcp:22") || !strings.Contains(out, "INGRESS") {
		t.Errorf("table:\n%s", out)
	}
}

func TestFirewallGet(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.gce.addFirewall(&compute.Firewall{Name: "web", Network: "default", Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp"}},
		SourceRanges: []string{"130.211.0.0/22"}, TargetTags: []string{"lb-health-check"}, Description: "d"})
	if err := h.run("compute", "firewall", "get", "web"); err != nil {
		t.Fatal(err)
	}
	if out := h.stdout.String(); !strings.Contains(out, `"ports": []`) || !strings.Contains(out, `"network": "default"`) || !strings.Contains(out, `"disabled": false`) {
		t.Errorf("get:\n%s", out)
	}
	if err := h.run("compute", "firewall", "get", "nope"); exitClass(err) != "notfound" || !strings.Contains(err.Error(), "gcp/lab") {
		t.Errorf("missing = %v", err)
	}
}

func TestFirewallCreate(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, map[string]any{"network": "net-a"})
	h.gce.addVPCs()
	err := h.run("compute", "firewall", "create", "allow-ssh-internal", "--allow", "tcp:ssh,2222", "--allow", "icmp",
		"--source-range", "10.0.0.0/8", "--target-tag", "ssh-internal", "--priority", "0", "--description", "ssh")
	if err != nil {
		t.Fatal(err)
	}
	fw := h.gce.firewall("allow-ssh-internal")
	if fw == nil || lastSegment(fw.Network) != "net-a" || fw.Direction != dirIngress || fw.Priority != 0 || allowedLabel(fw.Allowed) != "tcp:22,2222 icmp" ||
		!slices.Equal(fw.SourceRanges, []string{"10.0.0.0/8"}) || !slices.Equal(fw.TargetTags, []string{"ssh-internal"}) || fw.Description != "ssh" {
		t.Errorf("rule = %+v", fw)
	}
	if rep := h.report(); len(rep.Changes) != 1 || rep.Changes[0].Action != platform.Created || rep.Changes[0].Resource != "firewall/allow-ssh-internal" {
		t.Errorf("report = %+v", rep)
	}
	// Create is not ensure: an existing rule is exit code 1.
	if err := h.run("compute", "firewall", "create", "allow-ssh-internal", "--allow", "tcp:22", "--source-range", "10.0.0.0/8"); exitClass(err) != "general" || !strings.Contains(err.Error(), "ensure") {
		t.Errorf("exists = %v", err)
	}
	// Egress takes destination ranges.
	if err := h.run("compute", "firewall", "create", "out-dns", "--network", "default", "--direction", "egress", "--allow", "udp:53", "--destination-range", "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if fw := h.gce.firewall("out-dns"); fw == nil || fw.Direction != dirEgress || !slices.Equal(fw.DestinationRanges, []string{"8.8.8.8/32"}) || len(fw.SourceRanges) != 0 || fw.Priority != 1000 {
		t.Errorf("egress = %+v", fw)
	}
	for _, args := range [][]string{
		{"r1", "--allow", "tcp:22"},                                 // ingress without a source range
		{"r1", "--source-range", "10.0.0.0/8"},                      // no --allow
		{"r1", "--allow", "all:80", "--source-range", "10.0.0.0/8"}, // ports on all
		{"r1", "--allow", "tcp:22", "--source-range", "10.0.0.0/8", "--priority", "70000"},
		{"r1", "--allow", "tcp:22", "--direction", "egress", "--source-range", "10.0.0.0/8", "--destination-range", "10.0.0.0/8"},
		{"r1", "--allow", "tcp:22", "--direction", "egress"}, // egress without a destination
		{"r1", "--allow", "tcp:22", "--direction", "sideways", "--source-range", "10.0.0.0/8"},
		{"1rule", "--allow", "tcp:22", "--source-range", "10.0.0.0/8"}, // bad name
		{"r1", "--allow", "tcp:22", "--source-range", "10.0.0.0/8", "--target-tag", ""},
	} {
		if err := h.run(append([]string{"compute", "firewall", "create"}, args...)...); exitClass(err) != "usage" {
			t.Errorf("create %v = %v; want a usage error", args, err)
		}
		if w := h.gce.firewallWrites(); len(w) != 0 {
			t.Errorf("create %v wrote %v", args, w)
		}
	}
	if err := h.run("compute", "firewall", "create", "r2", "--network", "nope", "--allow", "tcp:22", "--source-range", "10.0.0.0/8"); exitClass(err) != "notfound" {
		t.Errorf("missing network = %v", err)
	}
	// Dry run: reads only, a would-create report.
	h.rt.Flags.DryRun = true
	if err := h.run("compute", "firewall", "create", "r3", "--allow", "tcp:80", "--source-range", "0.0.0.0/0"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); !rep.DryRun || rep.Changes[0].Action != platform.WouldCreate || len(h.gce.firewallWrites()) != 0 || h.gce.firewall("r3") != nil ||
		!strings.Contains(h.stderr.String(), "would create firewall/r3") {
		t.Errorf("dry run = %+v %v", rep, h.gce.firewallWrites())
	}
}

func TestFirewallUpdate(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.gce.addFirewall(&compute.Firewall{Name: "lb", Network: "default", Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp"}},
		SourceRanges: []string{"130.211.0.0/22", "35.191.0.0/16"}, TargetTags: []string{"lb-health-check"}, Description: "keep me"})
	// --add-source-range is a union.
	if err := h.run("compute", "firewall", "update", "lb", "--add-source-range", "10.20.0.0/24", "--add-source-range", "35.191.0.0/16"); err != nil {
		t.Fatal(err)
	}
	fw := h.gce.firewall("lb")
	if !slices.Equal(fw.SourceRanges, []string{"10.20.0.0/24", "130.211.0.0/22", "35.191.0.0/16"}) || fw.Description != "keep me" || !slices.Equal(fw.TargetTags, []string{"lb-health-check"}) {
		t.Errorf("after add = %+v", fw)
	}
	rep := h.report()
	if got := rows(rep); len(got) != 1 || got[0] != "firewall/lb updated +10.20.0.0/24 (now 3 ranges)" || rep.Changes[0].Attrs["source_ranges"] != "10.20.0.0/24,130.211.0.0/22,35.191.0.0/16" {
		t.Errorf("report = %v %+v", got, rep.Changes)
	}
	if w := h.gce.firewallWrites(); !slices.Equal(w, []string{"PATCH firewalls/lb"}) {
		t.Errorf("writes = %v", w)
	}
	// Already included: unchanged, nothing sent.
	if err := h.run("compute", "firewall", "update", "lb", "--add-source-range", "10.20.0.0/24"); err != nil {
		t.Fatal(err)
	}
	if got := rows(h.report()); len(got) != 1 || !strings.HasPrefix(got[0], "firewall/lb unchanged") || len(h.gce.firewallWrites()) != 0 {
		t.Errorf("unchanged = %v %v", got, h.gce.firewallWrites())
	}
	// --source-range replaces; --allow replaces; priority 0 is sent.
	if err := h.run("compute", "firewall", "update", "lb", "--source-range", "10.0.0.0/8", "--allow", "tcp:80,443", "--priority", "0"); err != nil {
		t.Fatal(err)
	}
	if fw := h.gce.firewall("lb"); !slices.Equal(fw.SourceRanges, []string{"10.0.0.0/8"}) || allowedLabel(fw.Allowed) != "tcp:80,443" || fw.Priority != 0 || fw.Description != "keep me" {
		t.Errorf("after replace = %+v", fw)
	}
	// Clearing the target tags goes through a full replacement that keeps
	// the other fields.
	if err := h.run("compute", "firewall", "update", "lb", "--target-tag", ""); err != nil {
		t.Fatal(err)
	}
	if fw := h.gce.firewall("lb"); len(fw.TargetTags) != 0 || fw.Description != "keep me" || !slices.Equal(fw.SourceRanges, []string{"10.0.0.0/8"}) ||
		!slices.Equal(h.gce.firewallWrites(), []string{"PUT firewalls/lb"}) || !strings.Contains(h.stderr.String(), "every instance") {
		t.Errorf("after clear = %+v %v", fw, h.gce.firewallWrites())
	}
	for _, args := range [][]string{
		{"lb"}, // nothing to change
		{"lb", "--network", "other"},
		{"lb", "--direction", "egress"},
		{"lb", "--source-range", "10.0.0.0/8", "--add-source-range", "10.1.0.0/16"},
		{"lb", "--destination-range", "10.0.0.0/8"}, // ingress rule
		{"lb", "--allow", "all:22"},
		{"lb", "--priority", "-1"},
	} {
		if err := h.run(append([]string{"compute", "firewall", "update"}, args...)...); exitClass(err) != "usage" {
			t.Errorf("update %v = %v; want a usage error", args, err)
		}
		if w := h.gce.firewallWrites(); len(w) != 0 {
			t.Errorf("update %v wrote %v", args, w)
		}
	}
	if err := h.run("compute", "firewall", "update", "nope", "--description", "x"); exitClass(err) != "notfound" {
		t.Errorf("missing = %v", err)
	}
	h.rt.Flags.DryRun = true
	if err := h.run("compute", "firewall", "update", "lb", "--add-source-range", "10.30.0.0/24"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); rep.Changes[0].Action != platform.WouldUpdate || len(h.gce.firewallWrites()) != 0 {
		t.Errorf("dry run = %+v %v", rep, h.gce.firewallWrites())
	}
}

func TestFirewallDelete(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.gce.addFirewall(&compute.Firewall{Name: "tmp", Network: "default", Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp"}}, SourceRanges: []string{"10.0.0.0/8"}})
	// Non-interactive without --yes: usage error, nothing deleted.
	if err := h.run("compute", "firewall", "delete", "tmp"); exitClass(err) != "usage" || h.gce.firewall("tmp") == nil {
		t.Errorf("without --yes = %v", err)
	}
	// --dry-run with --yes: only the dry run.
	h.rt.Flags.DryRun = true
	if err := h.run("compute", "firewall", "delete", "tmp", "--yes"); err != nil || h.gce.firewall("tmp") == nil || h.report().Changes[0].Action != platform.WouldDelete {
		t.Errorf("dry run = %v", err)
	}
	h.rt.Flags.DryRun = false
	if err := h.run("compute", "firewall", "delete", "tmp", "--yes"); err != nil || h.gce.firewall("tmp") != nil {
		t.Errorf("delete = %v", err)
	}
	if err := h.run("compute", "firewall", "delete", "tmp", "--yes"); exitClass(err) != "notfound" {
		t.Errorf("missing = %v", err)
	}
}

func TestFirewallDeleteInteractive(t *testing.T) {
	h := newGCPHarness(t, app.Flags{NonInteractiveSet: true}, nil)
	h.rt.Flags.NonInteractive = false
	h.rt.Picker = &scriptedPicker{t: t}
	h.gce.addFirewall(&compute.Firewall{Name: "tmp", Network: "default", Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp"}}, SourceRanges: []string{"10.0.0.0/8"}})
	h.rt.Stdin = strings.NewReader("n\n")
	if err := h.run("compute", "firewall", "delete", "tmp"); exitClass(err) != "nothing" || h.gce.firewall("tmp") == nil {
		t.Errorf("declined = %v", err)
	}
	h.rt.Stdin = strings.NewReader("y\n")
	if err := h.run("compute", "firewall", "delete", "tmp"); err != nil || h.gce.firewall("tmp") != nil || !slices.Equal(h.gce.firewallWrites(), []string{"DELETE firewalls/tmp"}) {
		t.Errorf("confirmed = %v %v", err, h.gce.firewallWrites())
	}
}

func TestFirewallWriteErrors(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.gce.fail["POST /projects/proj/global/firewalls"] = fakeErr{403, "forbidden", "Required 'compute.firewalls.create' permission for 'projects/proj'"}
	err := h.run("compute", "firewall", "create", "r", "--allow", "tcp:22", "--source-range", "10.0.0.0/8")
	if exitClass(err) != "auth" || !strings.Contains(err.Error(), "compute.firewalls") {
		t.Errorf("forbidden = %v", err)
	}
	delete(h.gce.fail, "POST /projects/proj/global/firewalls")
	h.gce.fail["POST /projects/proj/global/firewalls"] = fakeErr{403, "quotaExceeded", "Quota 'FIREWALLS' exceeded. Limit: 100.0 globally."}
	if err := h.run("compute", "firewall", "create", "r", "--allow", "tcp:22", "--source-range", "10.0.0.0/8"); exitClass(err) != "general" || !strings.Contains(err.Error(), "not a permission problem") {
		t.Errorf("quota = %v", err)
	}
}

func TestFirewallNoWaitOnlySubmits(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	if err := h.run("compute", "firewall", "create", "r", "--allow", "tcp:22", "--source-range", "10.0.0.0/8", "--no-wait"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); !strings.HasSuffix(rep.Changes[0].Detail, "(requested)") {
		t.Errorf("report = %+v", rep)
	}
	for _, c := range h.gce.calls {
		if strings.Contains(c, "/operations/") {
			t.Errorf("--no-wait waited: %s", c)
		}
	}
	// The operation still runs: a write to the same rule is not ready yet.
	if err := h.run("compute", "firewall", "update", "r", "--description", "x"); exitClass(err) != "general" || !strings.Contains(err.Error(), "not ready") {
		t.Errorf("overlapping write = %v", err)
	}
}

func TestFirewallUpdateAllowIgnoresOrder(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.gce.addFirewall(&compute.Firewall{Name: "dns", Network: "default", SourceRanges: []string{"10.0.0.0/8"},
		Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"53", "22"}}, {IPProtocol: "UDP", Ports: []string{"53"}}}})
	if err := h.run("compute", "firewall", "update", "dns", "--allow", "udp:53", "--allow", "tcp:ssh,53"); err != nil {
		t.Fatal(err)
	}
	if got := rows(h.report()); len(got) != 1 || !strings.HasPrefix(got[0], "firewall/dns unchanged") || len(h.gce.firewallWrites()) != 0 {
		t.Errorf("same allowed in another order = %v %v", got, h.gce.firewallWrites())
	}
	if a, b := allowedKey([]*compute.FirewallAllowed{{IPProtocol: "tcp"}, {IPProtocol: "tcp", Ports: []string{"80"}}}), "tcp"; a != b {
		t.Errorf("allowedKey every port = %q", a)
	}
}
