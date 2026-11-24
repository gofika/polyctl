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
	if l := prompttest.Labels(ranges.Options); !strings.Contains(l, "10.128.0.0/20  subnet default (us-central1)") || !strings.Contains(l, iapRange+"  (IAP TCP forwarding)") ||
		!strings.Contains(l, "0.0.0.0/0  (anywhere)") {
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
