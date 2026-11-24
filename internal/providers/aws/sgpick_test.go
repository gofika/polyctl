package aws

import (
	"errors"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// sgPickHarness is the security group harness in the interactive flow.
func sgPickHarness(t *testing.T, flags app.Flags) *awsHarness {
	t.Helper()
	flags.NonInteractive, flags.NonInteractiveSet = false, true
	h := newSGHarness(t, flags)
	h.rt.Picker = prompttest.New(t)
	return h
}

// get without the group offers the groups of the region; delete leaves the
// VPC's default group out; a name used in several VPCs is a pick.
func TestSGGetDeletePick(t *testing.T) {
	h := sgPickHarness(t, app.Flags{Yes: true})
	h.addSG("ap-east-1", &fakeSG{id: "sg-0ddd0000", name: "default"})
	h.addSG("ap-east-1", &fakeSG{id: "sg-0eee0000", name: "web", vpc: "vpc-0two", rules: []fakeRule{tcpRule(443, "0.0.0.0/0", "")}})
	h.addSG("ap-east-1", &fakeSG{id: "sg-0fff0000", name: "web", vpc: "vpc-0abc"})

	p := prompttest.New(t, "sg-0eee0000")
	h.rt.Picker = p
	if err := h.run("ec2", "security-group", "get"); err != nil {
		t.Fatalf("get: %v", err)
	}
	a := p.Find("Security group")
	if v := prompttest.Values(a.Options); v != "sg-0aaa0000 sg-0ddd0000 sg-0bbb0000 sg-0eee0000 sg-0fff0000" {
		t.Errorf("get offered %q", v)
	}
	if l := prompttest.Labels(a.Options); !strings.Contains(l, "web  sg-0eee0000  vpc-0two  1 rules  test group") {
		t.Errorf("labels: %s", l)
	}

	p = prompttest.New(t, prompttest.Abort{})
	h.rt.Picker = p
	if err := h.run("ec2", "security-group", "delete"); !errors.Is(err, prompt.ErrAborted) {
		t.Errorf("delete abort = %v", err)
	}
	if prompttest.HasValue(p.Asked[0].Options, "sg-0ddd0000") {
		t.Errorf("delete offered the default group")
	}

	p = prompttest.New(t, prompttest.Label("vpc-0two"))
	h.rt.Picker = p
	if err := h.run("ec2", "security-group", "get", "web"); err != nil || !strings.Contains(h.stdout.String(), "sg-0eee0000") {
		t.Errorf("ambiguous get = %v, %s", err, h.stdout.String())
	}
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	var amb *app.AmbiguousError
	if err := h.run("ec2", "security-group", "get", "web"); !errors.As(err, &amb) {
		t.Errorf("non-interactive ambiguous = %v", err)
	}
	if err := h.run("ec2", "security-group", "get"); err == nil || !strings.Contains(err.Error(), "arg") {
		t.Errorf("non-interactive missing = %v", err)
	}
}

// rule add without --rule offers the common rules the group lacks and
// typed ones; rule remove without --rule offers the group's rules.
func TestSGRulePicks(t *testing.T) {
	h := sgPickHarness(t, app.Flags{Yes: true})
	h.addSG("ap-east-1", &fakeSG{id: "sg-0ccc0000", name: "web", rules: []fakeRule{tcpRule(22, "0.0.0.0/0", "ssh")}})

	p := prompttest.New(t, []string{"tcp:https:0.0.0.0/0", otherRulesValue}, "bogus", "tcp:8080:10.0.0.0/8", "")
	h.rt.Picker = p
	if err := h.run("ec2", "security-group", "rule", "add", "web"); err != nil {
		t.Fatalf("rule add: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if v := prompttest.Values(p.Asked[0].Options); strings.Contains(v, "tcp:ssh") || !strings.Contains(v, "tcp:https:0.0.0.0/0") {
		t.Errorf("presets offered %q (the present ssh rule must be left out)", v)
	}
	if a := actions(h.report()); a["security-group/web/rule created"] != 2 {
		t.Errorf("report = %v", a)
	}

	p = prompttest.New(t, []string{"0"})
	h.rt.Picker = p
	if err := h.run("ec2", "security-group", "rule", "remove", "web"); err != nil {
		t.Fatalf("rule remove: %v", err)
	}
	if l := prompttest.Labels(p.Asked[0].Options); !strings.Contains(l, "tcp 22 0.0.0.0/0  ssh") {
		t.Errorf("rules offered: %s", l)
	}
	if a := actions(h.report()); a["security-group/web/rule deleted"] != 1 {
		t.Errorf("report = %v", a)
	}

	// A group without rules: nothing to remove.
	h.rt.Picker = prompttest.New(t)
	if err := h.run("ec2", "security-group", "rule", "remove", "sg-0aaa0000"); !errors.Is(err, platform.ErrNothingToDo) {
		t.Errorf("no rules = %v", err)
	}
	// The non-interactive flow still needs --rule.
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("ec2", "security-group", "rule", "add", "web"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("non-interactive = %v", err)
	}
}

// create without --vpc and <name> asks for the VPC (available ones, the
// default preselected) and the name (checked against that VPC); ensure
// offers the VPC's groups or a new one.
func TestSGCreateEnsureAsks(t *testing.T) {
	h := sgPickHarness(t, app.Flags{})
	h.ec2.mu.Lock()
	h.ec2.find.vpcs = map[string][]ec2types.Vpc{"ap-east-1": {
		{VpcId: awssdk.String("vpc-0two"), CidrBlock: awssdk.String("10.1.0.0/16")},
		{VpcId: awssdk.String("vpc-0abc"), CidrBlock: awssdk.String("10.0.0.0/16"), IsDefault: awssdk.Bool(true), Tags: []ec2types.Tag{{Key: awssdk.String("Name"), Value: awssdk.String("main")}}},
		{VpcId: awssdk.String("vpc-0gone"), State: ec2types.VpcStatePending},
	}}
	h.ec2.mu.Unlock()

	p := prompttest.New(t, "vpc-0abc", "base", "web")
	h.rt.Picker = p
	if err := h.run("ec2", "security-group", "create"); err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	v := p.Find("VPC")
	if prompttest.Values(v.Options) != "vpc-0abc vpc-0two" || v.Default != "vpc-0abc" {
		t.Errorf("VPCs offered %+v", v)
	}
	if l := prompttest.Labels(v.Options); !strings.Contains(l, "main  vpc-0abc  10.0.0.0/16  [default]") {
		t.Errorf("labels: %s", l)
	}
	if a := actions(h.report()); a["security-group/web created"] != 1 {
		t.Errorf("report = %v", a)
	}

	// A VPC without groups goes straight to the new name.
	p = prompttest.New(t, "vpc-0two", "api")
	h.rt.Picker = p
	if err := h.run("ec2", "security-group", "ensure"); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	p.Done()
	if a := actions(h.report()); a["security-group/api created"] != 1 {
		t.Errorf("report = %v", a)
	}
	p = prompttest.New(t, "vpc-0abc", "web")
	h.rt.Picker = p
	if err := h.run("ec2", "security-group", "ensure"); err != nil {
		t.Fatalf("ensure existing: %v", err)
	}
	if l := prompttest.Labels(p.Asked[1].Options); !strings.Contains(l, "Create a new security group...") {
		t.Errorf("ensure options: %s", l)
	}
	if a := actions(h.report()); a["security-group/web unchanged"] != 1 {
		t.Errorf("report = %v", a)
	}

	// The non-interactive flow names the VPC to pass.
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("ec2", "security-group", "create", "x"); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--vpc") {
		t.Errorf("non-interactive = %v", err)
	}
}
