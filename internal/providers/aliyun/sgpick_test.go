package aliyun

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// security-group get without <name|id> offers the groups of the region;
// none is nothing to do, and the non-interactive flow is unchanged.
func TestSGGetPick(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, f := sgHarness(t, app.Flags{})
	h.rt.Picker = prompttest.New(t)
	if err := h.run("ecs", "security-group", "get"); !errors.Is(err, platform.ErrNothingToDo) {
		t.Errorf("no group = %v", err)
	}
	f.addGroup("sg-1", "web", "vpc-main")
	f.addGroup("sg-2", "db", "vpc-other")
	p := prompttest.New(t, "sg-2")
	h.rt.Picker = p
	if err := h.run("ecs", "security-group", "get"); err != nil {
		t.Fatal(err)
	}
	p.Done()
	if !strings.Contains(h.stdout.String(), `"sg-2"`) {
		t.Errorf("stdout = %s", h.stdout.String())
	}
	if l := prompttest.Labels(p.Asked[0].Options); !strings.Contains(l, "web  sg-1  vpc-main") {
		t.Errorf("labels: %s", l)
	}
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("ecs", "security-group", "get"); err == nil {
		t.Error("non-interactive get without <name|id> succeeded")
	}
}

// rule add without --rule offers the common rules the group lacks and
// typed ones, checked as they are typed; rule remove without --rule /
// --rule-id offers the rules of the group.
func TestSGRulePicks(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, f := sgHarness(t, app.Flags{})
	f.addGroup("sg-1", "web", "vpc-main")
	f.addRule("sg-1", "tcp", "80/80", "0.0.0.0/0", "Accept")

	p := prompttest.New(t, []string{"tcp:ssh:0.0.0.0/0", otherRulesValue}, "tcp:bogus", "tcp:8080:10.0.0.0/8", "")
	h.rt.Picker = p
	if err := h.run("ecs", "security-group", "rule", "add", "web"); err != nil {
		t.Fatalf("rule add: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if v := prompttest.Values(p.Asked[0].Options); strings.Contains(v, "tcp:http:") || !strings.Contains(v, "tcp:ssh:0.0.0.0/0") {
		t.Errorf("offered %q: the present http rule must be left out", v)
	}
	if n := len(permissions(h.api.callsFor("AuthorizeSecurityGroup")[0])); n != 2 {
		t.Errorf("authorized %d rules, want 2", n)
	}

	p = prompttest.New(t, prompttest.Then{Do: func() {}, Answer: []string{}})
	h.rt.Picker = p
	if err := h.run("ecs", "security-group", "rule", "remove", "sg-1"); !errors.Is(err, platform.ErrNothingToDo) {
		t.Errorf("nothing ticked = %v", err)
	}
	if slices.Contains(f.writes, "RevokeSecurityGroup") {
		t.Errorf("writes = %v", f.writes)
	}
	h.rt.Picker = prompttest.New(t, prompttest.Abort{})
	if err := h.run("ecs", "security-group", "rule", "remove", "sg-1"); !errors.Is(err, prompt.ErrAborted) {
		t.Errorf("abort = %v", err)
	}
}

// create without --vpc and <name> asks for the VPC, then a name the VPC
// does not hold yet.
func TestSGCreatePick(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, f := sgHarness(t, app.Flags{})
	f.addGroup("sg-1", "web", "vpc-main")
	p := prompttest.New(t, "vpc-main", "web", "api")
	h.rt.Picker = p
	if err := h.run("ecs", "security-group", "create"); err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	c := h.api.callsFor("CreateSecurityGroup")[0]
	if c.Get("SecurityGroupName") != "api" || c.Get("VpcId") != "vpc-main" {
		t.Errorf("CreateSecurityGroup = %v", c)
	}
	if a := p.Asked[0]; a.Default != "vpc-main" {
		t.Errorf("VPC default %q, want the naming.aliyun_vpc one", a.Default)
	}
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("ecs", "security-group", "create", "x"); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--vpc") {
		t.Errorf("non-interactive = %v", err)
	}
}

// ensure without <name> offers the groups of the region or a new name
// (the default name sg-common reads as an id here, so none is proposed).
func TestSGEnsurePick(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, f := sgHarness(t, app.Flags{DryRun: true})
	f.addGroup("sg-1", "web", "vpc-main")
	p := prompttest.New(t, prompttest.Label("New security group"), "sg-x", "app")
	h.rt.Picker = p
	if err := h.run("ecs", "security-group", "ensure"); err != nil {
		t.Fatalf("ensure: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if !strings.Contains(h.stdout.String(), "security-group/app") {
		t.Errorf("stdout = %s", h.stdout.String())
	}
}
