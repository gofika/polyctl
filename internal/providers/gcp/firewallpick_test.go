package gcp

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// get, update and delete without <name> offer the rules of the project;
// none is nothing to do; the non-interactive flow still needs <name>.
func TestFirewallPickRule(t *testing.T) {
	h, _ := interactiveGCP(t, nil)
	h.gce.addFirewall(&compute.Firewall{Name: "allow-ssh", Network: "default", SourceRanges: []string{"10.0.0.0/8"}, TargetTags: []string{"ssh"},
		Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"22"}}}})
	p := h.answer("allow-ssh")
	if err := h.run("compute", "firewall", "get"); err != nil || !strings.Contains(h.stdout.String(), `"allow-ssh"`) {
		t.Fatalf("get = %v\n%s", err, h.stdout.String())
	}
	if l := prompttest.Labels(p.Find("Firewall rule").Options); l != "allow-ssh  default  INGRESS  prio 1000  tcp:22  10.0.0.0/8  tags ssh" {
		t.Errorf("label %q", l)
	}

	h.answer("allow-ssh")
	if err := h.run("compute", "firewall", "delete", "--yes"); err != nil || h.gce.firewall("allow-ssh") != nil {
		t.Fatalf("delete = %v", err)
	}
	h.answer()
	if err := h.run("compute", "firewall", "get"); exitClass(err) != "nothing" {
		t.Errorf("no rules = %v", err)
	}
	h.nonInteractive()
	if err := h.run("compute", "firewall", "delete", "--yes"); err == nil || !strings.Contains(err.Error(), "arg") {
		t.Errorf("non-interactive = %v", err)
	}
}

// create without <name>, --allow and --source-range asks them: the name
// checked as typed, the common protocols, the subnet ranges (the IAP range
// for SSH, 0.0.0.0/0 offered but not preselected).
func TestFirewallCreateAsks(t *testing.T) {
	h, _ := interactiveGCP(t, nil)
	h.gce.addFirewall(&compute.Firewall{Name: "taken", Network: "default", SourceRanges: []string{"10.0.0.0/8"},
		Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp"}}})
	p := h.answer("taken", "allow-ssh", []string{"tcp:22", otherValue}, "udp:x", "udp:53", []string{"10.128.0.0/20", iapRange})
	if err := h.run("compute", "firewall", "create"); err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	ranges := p.Find("Source ranges of the rule on network default")
	if l := prompttest.Labels(ranges.Options); !strings.Contains(l, "10.128.0.0/20  subnet default  us-central1") || !strings.Contains(l, iapRange+"  IAP TCP forwarding") ||
		!strings.Contains(l, "0.0.0.0/0  anywhere") {
		t.Errorf("ranges offered:\n%s", l)
	}
	fw := h.gce.firewall("allow-ssh")
	if fw == nil || allowedLabel(fw.Allowed) != "tcp:22 udp:53" || strings.Join(fw.SourceRanges, ",") != "10.128.0.0/20,"+iapRange {
		t.Errorf("rule = %+v", fw)
	}

	// Leaving a question creates nothing.
	h.answer("new-rule", prompttest.Abort{})
	if err := h.run("compute", "firewall", "create"); !errors.Is(err, prompt.ErrAborted) || h.gce.firewall("new-rule") != nil {
		t.Errorf("abort = %v", err)
	}

	h.nonInteractive()
	if err := h.run("compute", "firewall", "create", "x-1", "--allow", "tcp:22"); exitClass(err) != "usage" || !strings.Contains(err.Error(), "--source-range") {
		t.Errorf("non-interactive = %v", err)
	}
}

// ensure without <name> and --preset offers the preset, the rules and a
// new rule; an existing rule gets what is ticked added, the current values
// shown; the preset without a region asks one.
func TestFirewallEnsurePicks(t *testing.T) {
	h, _ := interactiveGCP(t, nil)
	h.gce.addFirewall(&compute.Firewall{Name: "web", Network: "default", SourceRanges: []string{"10.0.0.0/8"},
		Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"80"}}}})
	h.gce.addFirewall(&compute.Firewall{Name: "off", Network: "default", Disabled: true, SourceRanges: []string{"10.0.0.0/8"},
		Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp"}}})
	p := h.answer("web", []string{"tcp:443"}, []string{})
	if err := h.run("compute", "firewall", "ensure"); err != nil {
		t.Fatalf("ensure: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if v := prompttest.Values(p.Asked[0].Options); strings.Contains(v, "off") || !strings.Contains(v, "web") || !strings.Contains(prompttest.Labels(p.Asked[0].Options), "Create a new rule...") {
		t.Errorf("rules offered: %s", prompttest.Labels(p.Asked[0].Options))
	}
	if !strings.Contains(p.Asked[1].Title, "(now tcp:80; none: keep)") {
		t.Errorf("title %q", p.Asked[1].Title)
	}
	if fw := h.gce.firewall("web"); fw == nil || allowedLabel(fw.Allowed) != "tcp:80,443" && allowedLabel(fw.Allowed) != "tcp:80 tcp:443" || strings.Join(fw.SourceRanges, ",") != "10.0.0.0/8" {
		t.Errorf("rule = %s %v", allowedLabel(fw.Allowed), fw.SourceRanges)
	}

	p = h.answer(prompttest.Label("--preset"), "us-central1")
	if err := h.run("compute", "firewall", "ensure"); err != nil {
		t.Fatalf("preset: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if h.gce.firewall("allow-lb-health-check-default") == nil {
		t.Errorf("no health check rule")
	}

	h.nonInteractive()
	if err := h.run("compute", "firewall", "ensure"); exitClass(err) != "usage" || !strings.Contains(err.Error(), "rule name is required") {
		t.Errorf("non-interactive = %v", err)
	}
}

// network get without <name> offers the networks of the project.
func TestNetworkGetPick(t *testing.T) {
	h, _ := interactiveGCP(t, nil)
	h.gce.networks["proj/prod"] = &compute.Network{Name: "prod"}
	p := h.answer("prod")
	if err := h.run("compute", "network", "get"); err != nil || !strings.Contains(h.stdout.String(), `"prod"`) {
		t.Fatalf("get = %v", err)
	}
	if l := prompttest.Labels(p.Find("VPC network").Options); l != "default  auto  0 subnets\nprod  custom  0 subnets" {
		t.Errorf("networks offered:\n%s", l)
	}
}

// ensure of an existing rule refuses what ensure does not do (a disabled
// rule, another --direction) before asking anything.
func TestFirewallEnsureRefusesBeforeAsking(t *testing.T) {
	h, _ := interactiveGCP(t, nil)
	h.gce.addFirewall(&compute.Firewall{Name: "off", Network: "default", Direction: "INGRESS", Disabled: true, SourceRanges: []string{"10.0.0.0/8"},
		Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp"}}})
	h.gce.addFirewall(&compute.Firewall{Name: "web", Network: "default", Direction: "INGRESS", SourceRanges: []string{"10.0.0.0/8"},
		Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"80"}}}})
	p := h.answer()
	if err := h.run("compute", "firewall", "ensure", "off"); err == nil || !strings.Contains(err.Error(), "is disabled") {
		t.Errorf("disabled = %v", err)
	}
	if err := h.run("compute", "firewall", "ensure", "web", "--direction", "egress"); err == nil || !strings.Contains(err.Error(), "not EGRESS") {
		t.Errorf("direction = %v", err)
	}
	if len(p.Asked) != 0 {
		t.Errorf("asked %d questions", len(p.Asked))
	}
}

// update without a field flag asks what to change (current values shown;
// no protocols for a deny rule), then its new value; leaving the question
// changes nothing; the non-interactive flow still needs a field flag.
func TestFirewallUpdateAsksWhatToChange(t *testing.T) {
	h, _ := interactiveGCP(t, nil)
	h.gce.addFirewall(&compute.Firewall{Name: "allow-ssh", Network: "default", SourceRanges: []string{"10.0.0.0/8"}, TargetTags: []string{"ssh"},
		Priority: 1000, Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"22"}}}})

	p := h.answer(prompttest.Label("Add source ranges"), []string{"10.128.0.0/20"})
	if err := h.run("compute", "firewall", "update", "allow-ssh"); err != nil {
		t.Fatalf("add ranges: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if l := prompttest.Labels(p.Find("What to change on rule allow-ssh").Options); !strings.Contains(l, "Allowed protocols and ports  now tcp:22") ||
		!strings.Contains(l, "Add source ranges  now 10.0.0.0/8") || !strings.Contains(l, "Target tags  now ssh") || !strings.Contains(l, "Priority  now 1000") {
		t.Errorf("options:\n%s", l)
	}
	if fw := h.gce.firewall("allow-ssh"); strings.Join(fw.SourceRanges, ",") != "10.0.0.0/8,10.128.0.0/20" {
		t.Errorf("ranges = %v", fw.SourceRanges)
	}

	h.answer(prompttest.Label("Allowed protocols"), []string{"tcp:22", "tcp:443"})
	if err := h.run("compute", "firewall", "update", "allow-ssh"); err != nil {
		t.Fatalf("allow: %v", err)
	}
	if fw := h.gce.firewall("allow-ssh"); allowedLabel(fw.Allowed) != "tcp:22,443" {
		t.Errorf("allowed = %s", allowedLabel(fw.Allowed))
	}

	h.answer(prompttest.Label("Priority"), "x", "900")
	if err := h.run("compute", "firewall", "update", "allow-ssh"); err != nil {
		t.Fatalf("priority: %v", err)
	}
	if fw := h.gce.firewall("allow-ssh"); fw.Priority != 900 {
		t.Errorf("priority = %d", fw.Priority)
	}

	h.answer(prompttest.Label("Target tags"), "web, ssh")
	if err := h.run("compute", "firewall", "update", "allow-ssh"); err != nil {
		t.Fatalf("tags: %v", err)
	}
	if fw := h.gce.firewall("allow-ssh"); strings.Join(fw.TargetTags, ",") != "web,ssh" {
		t.Errorf("tags = %v", fw.TargetTags)
	}

	// Leaving a question changes nothing; --dry-run asks but writes nothing.
	h.answer(prompttest.Abort{})
	if err := h.run("compute", "firewall", "update", "allow-ssh"); !errors.Is(err, prompt.ErrAborted) {
		t.Errorf("abort = %v", err)
	}
	h.answer(prompttest.Label("Description"), "ssh from the office")
	h.rt.Flags.DryRun = true
	err := h.run("compute", "firewall", "update", "allow-ssh")
	h.rt.Flags.DryRun = false
	if err != nil || h.gce.firewall("allow-ssh").Description != "" {
		t.Errorf("dry run = %v, description %q", err, h.gce.firewall("allow-ssh").Description)
	}

	// A deny rule is not offered its protocols.
	h.gce.addFirewall(&compute.Firewall{Name: "deny-all", Network: "default", SourceRanges: []string{"0.0.0.0/0"}, Priority: 1000,
		Denied: []*compute.FirewallDenied{{IPProtocol: "all"}}})
	p = h.answer(prompttest.Abort{})
	_ = h.run("compute", "firewall", "update", "deny-all")
	if l := prompttest.Labels(p.Find("What to change on rule deny-all").Options); strings.Contains(l, "Allowed protocols") {
		t.Errorf("deny rule options:\n%s", l)
	}

	h.nonInteractive()
	if err := h.run("compute", "firewall", "update", "allow-ssh"); exitClass(err) != "usage" || !strings.Contains(err.Error(), "nothing to update") {
		t.Errorf("non-interactive = %v", err)
	}
}
