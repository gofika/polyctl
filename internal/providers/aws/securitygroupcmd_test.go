package aws

import (
	"errors"
	"slices"
	"sort"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

const sgInstanceID = "i-0aaaaaaaaaaaaaaa1"

// newSGHarness is an AWS harness with the instance site-xz7 in vpc-0abc,
// which has the groups sg-0aaa0000 and sg-0bbb0000.
func newSGHarness(t *testing.T, flags app.Flags) *awsHarness {
	t.Helper()
	h := newAWSHarness(t, flags, map[string]any{"tags": map[string]any{"team": "ops"}})
	h.addSG("ap-east-1", &fakeSG{id: "sg-0aaa0000", name: "base"})
	h.addSG("ap-east-1", &fakeSG{id: "sg-0bbb0000", name: "ssh"})
	h.addInstance("ap-east-1", &fakeInstance{id: sgInstanceID, name: "site-xz7", typ: "t3.nano", state: stateRunning, sgs: []string{"sg-0aaa0000", "sg-0bbb0000"}})
	return h
}

func (h *awsHarness) instanceGroups() []string {
	h.ec2.mu.Lock()
	defer h.ec2.mu.Unlock()
	out := append([]string(nil), h.ec2.inst.find("ap-east-1", sgInstanceID).groupIDs()...)
	sort.Strings(out)
	return out
}

// actions counts the report rows by resource and action.
func actions(rep platform.Report) map[string]int {
	out := map[string]int{}
	for _, c := range rep.Changes {
		out[c.Resource+" "+string(c.Action)]++
	}
	return out
}

func TestSGEnsureFromScratch(t *testing.T) {
	h := newSGHarness(t, app.Flags{})
	err := h.run("ec2", "security-group", "ensure", "web", "--instance", "site-xz7",
		"--rule", "tcp:http:0.0.0.0/0", "--rule", "tcp:https:0.0.0.0/0", "--rule", "tcp:ssh:10.0.0.0/8", "--rule", "icmp:all:::/0")
	if err != nil {
		t.Fatalf("ensure: %v\n%s", err, h.stderr.String())
	}
	if w := h.writes(); strings.Join(w, ",") != "CreateSecurityGroup,AuthorizeSecurityGroupIngress,ModifyInstanceAttribute" {
		t.Fatalf("writes = %v", w)
	}
	rep := h.report()
	a := actions(rep)
	if a["security-group/web created"] != 1 || a["security-group/web/rule created"] != 4 || a["instance/site-xz7 updated"] != 1 {
		t.Errorf("report = %+v", rep.Changes)
	}
	g := h.sgByName("ap-east-1", "web", "vpc-0abc")
	if g == nil || g.desc != "auto created web" || len(g.rules) != 4 {
		t.Fatalf("group = %+v", g)
	}
	create := h.ec2.sg.creates[0]
	tags := map[string]string{}
	for _, tg := range create.TagSpecifications[0].Tags {
		tags[awssdk.ToString(tg.Key)] = awssdk.ToString(tg.Value)
	}
	if tags["Name"] != "web" || tags["polyctl:managed"] != "true" || tags["team"] != "ops" || awssdk.ToString(create.VpcId) != "vpc-0abc" {
		t.Errorf("create = %+v tags %v", create, tags)
	}
	// The IPv6 ICMP rule goes into Ipv6Ranges as ICMPv6.
	auth := h.ec2.sg.auths[0]
	v6 := 0
	for _, p := range auth.IpPermissions {
		if len(p.Ipv6Ranges) > 0 {
			v6++
			if awssdk.ToString(p.IpProtocol) != "58" || len(p.IpRanges) != 0 {
				t.Errorf("ipv6 permission = %+v", p)
			}
		}
	}
	if v6 != 1 || len(auth.IpPermissions) != 4 {
		t.Errorf("authorization = %+v", auth.IpPermissions)
	}
	if got := h.instanceGroups(); strings.Join(got, ",") != "sg-0aaa0000,sg-0bbb0000,"+g.id {
		t.Errorf("instance groups = %v", got)
	}
	var attach platform.Change
	for _, c := range rep.Changes {
		if c.Resource == "instance/site-xz7" {
			attach = c
		}
	}
	if attach.Detail != "attached "+g.id+" (kept 2 existing)" {
		t.Errorf("attach = %+v", attach)
	}

	// Running it again changes nothing, twice.
	for i := 0; i < 2; i++ {
		h.ec2.reset()
		if err := h.run("ec2", "security-group", "ensure", "web", "--instance", "site-xz7",
			"--rule", "tcp:http:0.0.0.0/0", "--rule", "tcp:https:0.0.0.0/0", "--rule", "tcp:ssh:10.0.0.0/8", "--rule", "icmp:all:::/0"); err != nil {
			t.Fatal(err)
		}
		if w := h.writes(); len(w) != 0 {
			t.Errorf("run %d: writes = %v", i+2, w)
		}
		for _, c := range h.report().Changes {
			if c.Action != platform.Unchanged {
				t.Errorf("run %d: %+v", i+2, c)
			}
		}
	}
}

func TestSGEnsurePartialAndDescriptions(t *testing.T) {
	h := newSGHarness(t, app.Flags{})
	h.addSG("ap-east-1", &fakeSG{id: "sg-0ccc0000", name: "web", rules: []fakeRule{
		tcpRule(80, "0.0.0.0/0", "http from anywhere"), tcpRule(443, "0.0.0.0/0", "")}})
	err := h.run("ec2", "security-group", "ensure", "web", "--vpc", "vpc-0abc",
		"--rule", "tcp:80:0.0.0.0/0", "--rule", "tcp:443:0.0.0.0/0", "--rule", "tcp:22:10.0.0.0/8", "--rule", "tcp:https:0.0.0.0/0", "--rule-description", "added")
	if err != nil {
		t.Fatal(err)
	}
	auths := h.ec2.sg.auths
	if len(auths) != 1 || len(auths[0].IpPermissions) != 1 || awssdk.ToInt32(auths[0].IpPermissions[0].FromPort) != 22 ||
		awssdk.ToString(auths[0].IpPermissions[0].IpRanges[0].Description) != "added" {
		t.Fatalf("authorizations = %+v", auths)
	}
	if w := h.writes(); strings.Join(w, ",") != "AuthorizeSecurityGroupIngress" {
		t.Errorf("writes = %v (no instance: no attach)", w)
	}
	a := actions(h.report())
	if a["security-group/web unchanged"] != 1 || a["security-group/web/rule unchanged"] != 2 || a["security-group/web/rule created"] != 1 {
		t.Errorf("report = %v", a)
	}
}

func TestSGEnsureDryRun(t *testing.T) {
	for _, yes := range []bool{false, true} {
		h := newSGHarness(t, app.Flags{DryRun: true, Yes: yes})
		if err := h.run("ec2", "security-group", "ensure", "web", "--instance", "site-xz7", "--rule", "tcp:443:0.0.0.0/0"); err != nil {
			t.Fatal(err)
		}
		if w := h.writes(); len(w) != 0 {
			t.Errorf("dry run wrote %v", w)
		}
		rep := h.report()
		if !rep.DryRun || len(rep.Changes) != 3 {
			t.Fatalf("report = %+v", rep)
		}
		sg, rule, inst := rep.Changes[0], rep.Changes[1], rep.Changes[2]
		if sg.Action != platform.WouldCreate || sg.ID != platform.Pending || sg.Detail != `vpc-0abc, description "auto created web"` {
			t.Errorf("sg = %+v", sg)
		}
		if rule.Action != platform.WouldCreate || rule.Detail != "tcp 443 0.0.0.0/0" {
			t.Errorf("rule = %+v", rule)
		}
		if inst.Action != platform.WouldUpdate || inst.Detail != "attach (pending) (keep: sg-0aaa0000, sg-0bbb0000)" {
			t.Errorf("instance = %+v", inst)
		}
	}
}

func TestSGEnsureDuplicateRulesAndBatchFallback(t *testing.T) {
	h := newSGHarness(t, app.Flags{})
	g := h.addSG("ap-east-1", &fakeSG{id: "sg-0ccc0000", name: "web"})
	if err := h.run("ec2", "security-group", "ensure", "web", "--vpc", "vpc-0abc", "--rule", "tcp:443:0.0.0.0/0", "--rule", "tcp:https:0.0.0.0/0"); err != nil {
		t.Fatal(err)
	}
	if len(h.ec2.sg.auths) != 1 || len(h.ec2.sg.auths[0].IpPermissions) != 1 {
		t.Errorf("repeated --rule: %+v", h.ec2.sg.auths)
	}
	// Another writer adds a rule between the comparison and the batch.
	h.ec2.sg.authDup = true
	h.ec2.sg.auths = nil
	if err := h.run("ec2", "security-group", "ensure", "web", "--vpc", "vpc-0abc", "--rule", "tcp:80:0.0.0.0/0", "--rule", "tcp:22:10.0.0.0/8"); err != nil {
		t.Fatal(err)
	}
	if len(h.ec2.sg.auths) != 3 || len(g.rules) != 3 {
		t.Errorf("fallback: %d authorizations, rules %+v", len(h.ec2.sg.auths), g.rules)
	}
	if a := actions(h.report()); a["security-group/web/rule created"] != 2 {
		t.Errorf("report = %v", a)
	}
}

func TestSGEnsureAttachExisting(t *testing.T) {
	h := newSGHarness(t, app.Flags{})
	h.addSG("ap-east-1", &fakeSG{id: "sg-0ccc0000", name: "existing-sg"})
	if err := h.run("ec2", "security-group", "ensure", "existing-sg", "--instance", sgInstanceID); err != nil {
		t.Fatal(err)
	}
	if w := h.writes(); strings.Join(w, ",") != "ModifyInstanceAttribute" {
		t.Errorf("writes = %v", w)
	}
	set := h.ec2.sg.groups[0]
	sort.Strings(set)
	if strings.Join(set, ",") != "sg-0aaa0000,sg-0bbb0000,sg-0ccc0000" {
		t.Errorf("Groups = %v (the existing groups must be kept)", h.ec2.sg.groups[0])
	}
}

func TestSGEnsureRefusals(t *testing.T) {
	h := newSGHarness(t, app.Flags{})
	h.ec2.mu.Lock()
	h.ec2.inst.byRegion["ap-east-1"] = append(h.ec2.inst.byRegion["ap-east-1"],
		&fakeInstance{id: "i-0aaaaaaaaaaaaaaa2", name: "full", typ: "t3.nano", state: stateRunning, az: "ap-east-1a",
			sgs: []string{"sg-01", "sg-02", "sg-03", "sg-04", "sg-05"}},
		&fakeInstance{id: "i-0aaaaaaaaaaaaaaa3", name: "multi", typ: "t3.nano", state: stateRunning, az: "ap-east-1a", nics: 2})
	h.ec2.mu.Unlock()
	cases := []struct {
		args []string
		is   error
		want string
	}{
		{[]string{"web", "--instance", "full", "--rule", "tcp:80:0.0.0.0/0"}, nil, "already has 5 security groups"},
		{[]string{"web", "--instance", "multi"}, platform.ErrNotSupported, "network interfaces"},
		{[]string{"web", "--rule", "tcp:80:0.0.0.0/0"}, app.ErrUsage, "--vpc"},
		{[]string{"web", "--instance", "site-xz7", "--vpc", "vpc-0def"}, app.ErrUsage, "differs"},
		{[]string{"web", "--vpc", "vpc-0abc", "--rule", "tcp:all:sg-0aaa0000x", "--rule", "tcp:80"}, platform.ErrInvalidInput, "three parts"},
		{[]string{"web", "--vpc", "vpc-0abc", "--rule", "icmp:80:0.0.0.0/0"}, platform.ErrInvalidInput, "icmp"},
		{[]string{"sg-web", "--vpc", "vpc-0abc"}, app.ErrUsage, "sg-"},
		{[]string{"web", "--vpc", "vpc-0abc", "--description", "Web \u670d\u52a1"}, app.ErrUsage, "does not accept"},
		{[]string{"web", "--vpc", "vpc-0abc", "--rule-description", "a|b"}, app.ErrUsage, "does not accept"},
	}
	for _, c := range cases {
		err := h.run(append([]string{"ec2", "security-group", "ensure"}, c.args...)...)
		if err == nil || c.is != nil && !errors.Is(err, c.is) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v = %v", c.args, err)
		}
	}
	if w := h.writes(); len(w) != 0 {
		t.Errorf("refusals wrote %v", w)
	}
}

func TestSGEnsureDefaultVPC(t *testing.T) {
	h := newAWSHarness(t, app.Flags{}, map[string]any{"vpc_id": "vpc-0def"})
	if err := h.run("ec2", "security-group", "ensure", "web"); err != nil {
		t.Fatal(err)
	}
	if g := h.sgByName("ap-east-1", "web", "vpc-0def"); g == nil {
		t.Error("the group must be created in defaults.aws.vpc_id")
	}
}

func TestSGCreate(t *testing.T) {
	h := newSGHarness(t, app.Flags{})
	if err := h.run("ec2", "security-group", "create", "web", "--vpc", "vpc-0abc", "--rule", "tcp:443:::/0", "--description", "public web"); err != nil {
		t.Fatal(err)
	}
	g := h.sgByName("ap-east-1", "web", "vpc-0abc")
	if g == nil || g.desc != "public web" || len(g.rules) != 1 || g.rules[0].kind != "ipv6" {
		t.Fatalf("group = %+v", g)
	}
	h.ec2.reset()
	err := h.run("ec2", "security-group", "create", "web", "--vpc", "vpc-0abc")
	if err == nil || errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "security-group ensure") || len(h.writes()) != 0 {
		t.Errorf("existing = %v (writes %v)", err, h.writes())
	}
	// Another VPC may hold the same name.
	if err := h.run("ec2", "security-group", "create", "web", "--vpc", "vpc-0def"); err != nil {
		t.Errorf("other vpc = %v", err)
	}
}

func TestSGAmbiguousName(t *testing.T) {
	h := newSGHarness(t, app.Flags{})
	h.addSG("ap-east-1", &fakeSG{id: "sg-0ccc0000", name: "web", vpc: "vpc-0abc"})
	h.addSG("ap-east-1", &fakeSG{id: "sg-0ddd0000", name: "web", vpc: "vpc-0def"})
	var amb *app.AmbiguousError
	if err := h.run("ec2", "security-group", "get", "web"); !errors.As(err, &amb) || !strings.Contains(err.Error(), "--vpc") {
		t.Errorf("ambiguous = %v", err)
	}
	if err := h.run("ec2", "security-group", "get", "web", "--vpc", "vpc-0def"); err != nil {
		t.Fatal(err)
	}
	var d sgDetail
	h.jsonOut(&d)
	if d.ID != "sg-0ddd0000" {
		t.Errorf("get = %+v", d)
	}
	if err := h.run("ec2", "security-group", "rule", "add", "web", "--rule", "tcp:80:0.0.0.0/0"); !errors.As(err, &amb) {
		t.Errorf("rule add = %v", err)
	}
	if err := h.run("ec2", "security-group", "get", "nothing"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing = %v", err)
	}
	if err := h.run("ec2", "security-group", "get", "sg-bogus"); !errors.Is(err, platform.ErrInvalidInput) {
		t.Errorf("malformed = %v", err)
	}
}

func TestSGGet(t *testing.T) {
	h := newSGHarness(t, app.Flags{})
	h.addSG("ap-east-1", &fakeSG{id: "sg-0ccc0000", name: "web", rules: []fakeRule{tcpRule(80, "0.0.0.0/0", ""),
		{proto: "tcp", from: awssdk.Int32(8080), to: awssdk.Int32(8080), source: "sg-0aaa0000", kind: "sg"},
		{proto: "icmpv6", from: awssdk.Int32(-1), to: awssdk.Int32(-1), source: "::/0", kind: "ipv6"}}})
	h.ec2.mu.Lock()
	h.ec2.inst.find("ap-east-1", sgInstanceID).sgs = []string{"sg-0aaa0000", "sg-0ccc0000"}
	h.ec2.mu.Unlock()
	if err := h.run("ec2", "security-group", "get", "sg-0ccc0000"); err != nil {
		t.Fatal(err)
	}
	var d sgDetail
	h.jsonOut(&d)
	if d.Name != "web" || d.VPC != "vpc-0abc" || d.Profile != "lab" || d.Region != "ap-east-1" || len(d.Ingress) != 3 ||
		!slices.Equal(d.Instances, []string{sgInstanceID}) {
		t.Errorf("get = %+v", d)
	}
	kinds := map[string]string{}
	for _, r := range d.Ingress {
		kinds[r.Source] = r.SourceType + " " + r.Protocol
	}
	if kinds["sg-0aaa0000"] != "sg tcp" || kinds["::/0"] != "ipv6 icmpv6" || kinds["0.0.0.0/0"] != "ipv4 tcp" {
		t.Errorf("rules = %v", kinds)
	}
}

func TestSGList(t *testing.T) {
	h := newSGHarness(t, app.Flags{})
	h.addSG("ap-east-1", &fakeSG{id: "sg-0ccc0000", name: "web", vpc: "vpc-0def", rules: []fakeRule{tcpRule(80, "0.0.0.0/0", ""), tcpRule(80, "10.0.0.0/8", "")}})
	if err := h.run("ec2", "security-group", "list", "--vpc", "vpc-0def"); err != nil {
		t.Fatal(err)
	}
	var sgs []platform.SecurityGroup
	h.jsonOut(&sgs)
	if len(sgs) != 1 || sgs[0].ID != "sg-0ccc0000" || len(sgs[0].Ingress) != 2 {
		t.Errorf("list --vpc = %+v", sgs)
	}
	if err := h.run("ec2", "security-group", "list", "--instance", "site-xz7"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&sgs)
	if len(sgs) != 2 {
		t.Errorf("list --instance = %+v", sgs)
	}
	// The cached list: synced once, then from the inventory.
	if err := h.run("ec2", "security-group", "list"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&sgs)
	if len(sgs) != 3 {
		t.Errorf("list = %+v", sgs)
	}
	h.ec2.reset()
	if err := h.run("ec2", "security-group", "list"); err != nil || h.ec2.count("DescribeSecurityGroups") != 0 {
		t.Errorf("cached list: %v, %v", err, h.ec2.calls())
	}
	if err := h.run("ec2", "security-group", "list", "--name", "nothing*"); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(h.stdout.String()) != "[]" || !strings.Contains(h.stderr.String(), "no security groups") {
		t.Errorf("empty list: %q / %q", h.stdout.String(), h.stderr.String())
	}
}

func TestSGRuleAddAndRemove(t *testing.T) {
	h := newSGHarness(t, app.Flags{})
	g := h.addSG("ap-east-1", &fakeSG{id: "sg-0123456789abcdef0", name: "web", rules: []fakeRule{tcpRule(22, "10.0.0.0/8", "office")}})
	if err := h.run("ec2", "security-group", "rule", "add", g.id, "--rule", "icmp:all:::/0", "--rule", "tcp:22:10.0.0.0/8", "--rule-description", "ping v6"); err != nil {
		t.Fatal(err)
	}
	a := actions(h.report())
	if a["security-group/web/rule created"] != 1 || a["security-group/web/rule unchanged"] != 1 || len(g.rules) != 2 || g.rules[1].desc != "ping v6" {
		t.Errorf("rule add = %v, rules %+v", a, g.rules)
	}
	if err := h.run("ec2", "security-group", "rule", "add", "nothing", "--rule", "tcp:80:0.0.0.0/0"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing group = %v", err)
	}
	if err := h.run("ec2", "security-group", "rule", "add", "web"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("no rule = %v", err)
	}

	// Non-interactive without --yes: usage error, nothing removed.
	h.ec2.reset()
	if err := h.run("ec2", "security-group", "rule", "remove", "web", "--vpc", "vpc-0abc", "--rule", "tcp:22:10.0.0.0/8"); !errors.Is(err, app.ErrUsage) || len(h.writes()) != 0 {
		t.Errorf("without --yes = %v (writes %v)", err, h.writes())
	}
	// Nothing to remove asks nothing.
	if err := h.run("ec2", "security-group", "rule", "remove", "web", "--rule", "tcp:80:0.0.0.0/0"); err != nil || len(h.writes()) != 0 {
		t.Errorf("absent rule = %v (writes %v)", err, h.writes())
	}
	if a := actions(h.report()); a["security-group/web/rule unchanged"] != 1 {
		t.Errorf("absent rule report = %v", a)
	}
	h.rt.Flags.Yes = true
	t.Cleanup(func() { h.rt.Flags.Yes = false })
	if err := h.run("ec2", "security-group", "rule", "remove", "web", "--rule", "tcp:22:10.0.0.0/8", "--rule", "udp:53:10.0.0.0/8"); err != nil {
		t.Fatal(err)
	}
	a = actions(h.report())
	if a["security-group/web/rule deleted"] != 1 || a["security-group/web/rule unchanged"] != 1 || len(g.rules) != 1 {
		t.Errorf("remove = %v, rules %+v", a, g.rules)
	}
}

func TestSGRuleRemoveUnknownPermissions(t *testing.T) {
	h := newSGHarness(t, app.Flags{Yes: true})
	g := h.addSG("ap-east-1", &fakeSG{id: "sg-0ccc0000", name: "web", rules: []fakeRule{tcpRule(443, "0.0.0.0/0", "")}})
	s := &sgScope{c: sgClient(h), profile: "lab", region: "ap-east-1"}
	sg, err := findSG(t.Context(), s, "web", "vpc-0abc")
	if err != nil || sg == nil {
		t.Fatal(sg, err)
	}
	// The rule disappears after the comparison: the revocation succeeds
	// with the rule in UnknownIpPermissions.
	h.ec2.mu.Lock()
	g.rules = nil
	h.ec2.mu.Unlock()
	res, err := s.c.RemoveIngressRules(t.Context(), "", sg.ID, []platform.IngressRule{mustRule(t, "tcp:443:0.0.0.0/0")})
	if err != nil || len(res) != 1 || res[0].Done {
		t.Errorf("unknown = %+v, %v", res, err)
	}
}

func TestSGDelete(t *testing.T) {
	h := newSGHarness(t, app.Flags{})
	h.addSG("ap-east-1", &fakeSG{id: "sg-0ccc0000", name: "web"})
	if err := h.run("ec2", "security-group", "delete", "web"); !errors.Is(err, app.ErrUsage) || len(h.writes()) != 0 {
		t.Errorf("without --yes = %v", err)
	}
	h.rt.Flags.DryRun = true
	if err := h.run("ec2", "security-group", "delete", "web"); err != nil || len(h.writes()) != 0 || h.report().Changes[0].Action != platform.WouldDelete {
		t.Errorf("dry run = %v (writes %v)", err, h.writes())
	}
	h.rt.Flags.DryRun = false
	h.rt.Flags.Yes = true
	t.Cleanup(func() { h.rt.Flags.Yes = false })
	err := h.run("ec2", "security-group", "delete", "base")
	if err == nil || errors.Is(err, app.ErrUsage) || errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "still in use") {
		t.Errorf("attached = %v", err)
	}
	if err := h.run("ec2", "security-group", "delete", "web"); err != nil {
		t.Fatal(err)
	}
	if c := h.report().Changes[0]; c.Action != platform.Deleted || c.ID != "sg-0ccc0000" || h.sgByName("ap-east-1", "web", "") != nil {
		t.Errorf("delete = %+v", c)
	}
	h.addSG("ap-east-1", &fakeSG{id: "sg-0eee0000", name: "gone"})
	h.ec2.inst.init()
	h.ec2.inst.errs["DeleteSecurityGroup"] = &fakeAPIError{"InvalidGroup.NotFound", "The security group 'sg-0eee0000' does not exist"}
	if err := h.run("ec2", "security-group", "delete", "gone"); err != nil || h.report().Changes[0].Action != platform.Unchanged {
		t.Errorf("gone meanwhile = %v", err)
	}
	delete(h.ec2.inst.errs, "DeleteSecurityGroup")
	h.addSG("ap-east-1", &fakeSG{id: "sg-0fff0000", name: "default", vpc: "vpc-0def"})
	if err := h.run("ec2", "security-group", "delete", "sg-0fff0000"); err == nil || !strings.Contains(err.Error(), "default group") {
		t.Errorf("default = %v", err)
	}
	if err := h.run("ec2", "security-group", "delete", "nothing"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing = %v", err)
	}
}

func TestSGOfflineWrites(t *testing.T) {
	h := newSGHarness(t, app.Flags{Offline: true})
	for _, args := range [][]string{
		{"ensure", "web", "--vpc", "vpc-0abc"}, {"create", "web", "--vpc", "vpc-0abc"}, {"delete", "web"},
		{"rule", "add", "web", "--rule", "tcp:80:0.0.0.0/0"}, {"rule", "remove", "web", "--rule", "tcp:80:0.0.0.0/0"},
	} {
		if err := h.run(append([]string{"ec2", "security-group"}, args...)...); !errors.Is(err, app.ErrOffline) {
			t.Errorf("%v offline = %v", args, err)
		}
	}
	if calls := h.ec2.calls(); len(calls) != 0 {
		t.Errorf("offline called the API: %v", calls)
	}
}

func TestSGTables(t *testing.T) {
	h := newSGHarness(t, app.Flags{Output: "table"})
	h.addSG("ap-east-1", &fakeSG{id: "sg-0ccc0000", name: "web", rules: []fakeRule{tcpRule(443, "0.0.0.0/0", "https"),
		{proto: "icmpv6", from: awssdk.Int32(-1), to: awssdk.Int32(-1), source: "::/0", kind: "ipv6"}}})
	if err := h.run("ec2", "security-group", "get", "web"); err != nil {
		t.Fatal(err)
	}
	out := h.stdout.String()
	for _, want := range []string{"sg-0ccc0000", "INGRESS", "PROTO", "tcp", "443", "https", "icmpv6", "all", "::/0"} {
		if !strings.Contains(out, want) {
			t.Errorf("get table lacks %q:\n%s", want, out)
		}
	}
	if err := h.run("ec2", "security-group", "list", "--vpc", "vpc-0abc"); err != nil {
		t.Fatal(err)
	}
	if out := h.stdout.String(); !strings.Contains(out, "RULES") || !strings.Contains(out, "sg-0ccc0000") {
		t.Errorf("list table:\n%s", out)
	}
}
