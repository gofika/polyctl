package aliyun

import (
	"errors"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// vpc get without <name|id> offers the VPCs of the region; vpc create
// without <name> proposes the naming.aliyun_vpc name when it is free and
// refuses a taken one as it is typed.
func TestVPCPicks(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, f, _ := netHarness(t, app.Flags{})
	h.rt.Picker = prompttest.New(t)
	if err := h.run("vpc", "vpc", "get"); !errors.Is(err, platform.ErrNothingToDo) {
		t.Errorf("no VPC = %v", err)
	}
	f.addVPCFull("vpc-1", "app", "10.0.0.0/16", true)
	p := prompttest.New(t, "vpc-1")
	h.rt.Picker = p
	if err := h.run("vpc", "vpc", "get"); err != nil {
		t.Fatal(err)
	}
	if l := prompttest.Labels(p.Asked[0].Options); !strings.Contains(l, "app  vpc-1  10.0.0.0/16") || !strings.Contains(l, "[default]") {
		t.Errorf("labels: %s", l)
	}

	p = prompttest.New(t, "app", prompttest.KeepDefault{})
	h.rt.Picker = p
	h.rt.Flags.DryRun = true
	if err := h.run("vpc", "vpc", "create"); err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if a := p.Asked[0]; a.Default != "cn-shanghai-vpc" {
		t.Errorf("proposed %q", a.Default)
	}
	if !strings.Contains(h.stdout.String(), "vpc/cn-shanghai-vpc") {
		t.Errorf("stdout = %s", h.stdout.String())
	}
}

// vswitch create without --vpc, --zone and <name> asks for the VPC, the
// zone (zones with stock; those holding a vSwitch of the VPC marked, the
// first default zone without one preselected) and the name (the naming
// template's proposed).
func TestVSwitchCreatePicks(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, f, _ := netHarness(t, app.Flags{DryRun: true})
	cat := sizeCatalog()
	cat.register(h.api)
	f.addVPCFull("vpc-1", "cn-shanghai-vpc", "172.16.0.0/12", false)
	f.addVSwitch("vsw-b", "cn-shanghai-switch-b", "vpc-1", "cn-shanghai-b", "172.16.0.0/22")
	p := prompttest.New(t, "vpc-1", prompttest.KeepDefault{}, prompttest.KeepDefault{})
	p.Answers[1] = "cn-shanghai-c"
	h.rt.Picker = p
	if err := h.run("vpc", "vswitch", "create"); err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	zone := p.Find("Zone (cn-shanghai)")
	if zone.Default != "cn-shanghai-c" || !strings.Contains(prompttest.Labels(zone.Options), "cn-shanghai-b  vSwitch cn-shanghai-switch-b\n") {
		t.Errorf("zones (default %q):\n%s", zone.Default, prompttest.Labels(zone.Options))
	}
	if !strings.Contains(h.stdout.String(), "vswitch/cn-shanghai-switch-c") {
		t.Errorf("stdout = %s", h.stdout.String())
	}
}
