package aliyun

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// sgHarness is a harness with the fake ECS and one VPC.
func sgHarness(t *testing.T, flags app.Flags) (*harness, *fakeECS) {
	h := newHarness(t, flags)
	f := newFakeECS(t, h.api)
	f.addVPC("vpc-main", "cn-shanghai-vpc")
	f.addVPC("vpc-other", "other")
	return h, f
}

func reportOf(t *testing.T, h *harness) platform.Report {
	t.Helper()
	var rep platform.Report
	h.jsonOut(&rep)
	return rep
}

func countActions(rep platform.Report, a platform.Action) int {
	n := 0
	for _, c := range rep.Changes {
		if c.Action == a {
			n++
		}
	}
	return n
}

func TestSGEnsureCreatesThenAuthorizesOnce(t *testing.T) {
	h, f := sgHarness(t, app.Flags{})
	err := h.run("ecs", "security-group", "ensure", "web", "--vpc", "cn-shanghai-vpc",
		"--rule", "icmp:all:0.0.0.0/0", "--rule", "tcp:http:0.0.0.0/0", "--rule", "tcp:https:0.0.0.0/0", "--rule", "tcp:1-65535:203.0.113.7")
	if err != nil {
		t.Fatalf("ensure: %v\n%s", err, h.stderr.String())
	}
	if !slices.Equal(f.writes, []string{"CreateSecurityGroup", "AuthorizeSecurityGroup"}) {
		t.Fatalf("writes = %v, want CreateSecurityGroup then one AuthorizeSecurityGroup", f.writes)
	}
	auth := h.api.callsFor("AuthorizeSecurityGroup")[0]
	if n := len(permissions(auth)); n != 4 {
		t.Errorf("authorize carried %d permissions, want 4", n)
	}
	if auth.Get("Permissions.4.SourceCidrIp") != "203.0.113.7/32" && auth.Get("Permissions.1.SourceCidrIp") != "203.0.113.7/32" {
		found := false
		for _, p := range permissions(auth) {
			found = found || p["SourceCidrIp"] == "203.0.113.7/32"
		}
		if !found {
			t.Errorf("single address not sent with /32: %v", permissions(auth))
		}
	}
	if c := h.api.callsFor("CreateSecurityGroup")[0]; c.Get("VpcId") != "vpc-main" || c.Get("SecurityGroupName") != "web" {
		t.Errorf("create = %v", c)
	}
	rep := reportOf(t, h)
	if len(rep.Changes) != 5 || rep.Changes[0].Resource != "security-group/web" || rep.Changes[0].Action != platform.Created ||
		!strings.HasPrefix(rep.Changes[0].Detail, "sg-new") || countActions(rep, platform.Created) != 5 {
		t.Errorf("report = %+v", rep.Changes)
	}

	// Again: nothing to write, every row unchanged.
	f.writes = nil
	if err := h.run("ecs", "security-group", "ensure", "web", "--vpc", "vpc-main",
		"--rule", "icmp:all:0.0.0.0/0", "--rule", "tcp:http:0.0.0.0/0", "--rule", "tcp:https:0.0.0.0/0", "--rule", "tcp:1-65535:203.0.113.7/32"); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Errorf("second ensure wrote %v", f.writes)
	}
	if rep := reportOf(t, h); countActions(rep, platform.Unchanged) != 5 {
		t.Errorf("second report = %+v", rep.Changes)
	}
	for _, c := range h.api.callsFor("DescribeSecurityGroupAttribute") {
		if c.Get("Direction") != "ingress" {
			t.Errorf("rules read without Direction=ingress: %v", c)
		}
	}
}

func TestSGEnsureAddsOnlyMissingRules(t *testing.T) {
	h, f := sgHarness(t, app.Flags{})
	f.addGroup("sg-web", "web", "vpc-main")
	f.addRule("sg-web", "ICMP", "-1/-1", "0.0.0.0/0", "Accept")
	f.addRule("sg-web", "TCP", "80/80", "0.0.0.0/0", "Accept")
	f.addRule("sg-web", "TCP", "1/65535", "203.0.113.7", "Accept") // written without /32 by another tool
	// An egress rule with the same ports must not count as present.
	f.rules["sg-web"] = append(f.rules["sg-web"], map[string]any{"SecurityGroupRuleId": "sgr-out", "Direction": "egress", "IpProtocol": "TCP", "PortRange": "443/443", "DestCidrIp": "0.0.0.0/0", "Policy": "Accept"})
	err := h.run("ecs", "security-group", "ensure", "web", "--vpc", "vpc-main",
		"--rule", "icmp:all:0.0.0.0/0", "--rule", "tcp:80:0.0.0.0/0", "--rule", "tcp:443:0.0.0.0/0", "--rule", "tcp:1-65535:203.0.113.7", "--rule", "tcp:22:10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	calls := h.api.callsFor("AuthorizeSecurityGroup")
	if len(calls) != 1 || len(permissions(calls[0])) != 2 {
		t.Fatalf("authorize calls %v, want one with the 2 missing rules", calls)
	}
	got := []string{permissions(calls[0])[0]["PortRange"], permissions(calls[0])[1]["PortRange"]}
	slices.Sort(got)
	if !slices.Equal(got, []string{"22/22", "443/443"}) {
		t.Errorf("authorized %v", got)
	}
	rep := reportOf(t, h)
	if countActions(rep, platform.Unchanged) != 4 || countActions(rep, platform.Created) != 2 {
		t.Errorf("report = %+v", rep.Changes)
	}
}

// Rules are read page by page: a rule on the second page is present.
func TestSGRulesArePaged(t *testing.T) {
	h, f := sgHarness(t, app.Flags{})
	f.addGroup("sg-web", "web", "vpc-main")
	f.rulePage = 2
	f.addRule("sg-web", "TCP", "1/1", "0.0.0.0/0", "Accept")
	f.addRule("sg-web", "TCP", "2/2", "0.0.0.0/0", "Accept")
	f.addRule("sg-web", "TCP", "80/80", "0.0.0.0/0", "Accept")
	if err := h.run("ecs", "security-group", "rule", "add", "web", "--rule", "tcp:80:0.0.0.0/0"); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 || len(h.api.callsFor("DescribeSecurityGroupAttribute")) != 2 {
		t.Errorf("writes %v, attribute calls %d; want no write and two pages", f.writes, len(h.api.callsFor("DescribeSecurityGroupAttribute")))
	}
}

func TestSGNameLookups(t *testing.T) {
	h, f := sgHarness(t, app.Flags{})
	f.addGroup("sg-a", "web", "vpc-main")
	f.addGroup("sg-b", "web", "vpc-main")
	f.addGroup("sg-c", "api", "vpc-main")
	f.addGroup("sg-d", "api", "vpc-other")
	var amb *app.AmbiguousError
	// Same name twice in one VPC: ambiguous even with --vpc.
	if err := h.run("ecs", "security-group", "ensure", "web", "--vpc", "vpc-main"); !errors.As(err, &amb) {
		t.Errorf("ensure of a duplicated name = %v, want ambiguous", err)
	}
	if err := h.run("ecs", "security-group", "get", "api"); !errors.As(err, &amb) {
		t.Errorf("get api across VPCs = %v, want ambiguous", err)
	}
	if err := h.run("ecs", "security-group", "get", "api", "--vpc", "other"); err != nil {
		t.Fatal(err)
	}
	var d sgDetail
	h.jsonOut(&d)
	if d.ID != "sg-d" || d.VPC != "vpc-other" || d.Region != "cn-shanghai" || d.Type != "normal" {
		t.Errorf("get api --vpc other = %+v", d)
	}
	if err := h.run("ecs", "security-group", "get", "nosuch"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("get nosuch = %v, want not found", err)
	}
	if len(f.writes) != 0 {
		t.Errorf("lookups wrote %v", f.writes)
	}
}

func TestSGCreateAndEnsureNeedAVPC(t *testing.T) {
	h, f := sgHarness(t, app.Flags{})
	if err := h.run("ecs", "security-group", "create", "web"); !errors.Is(err, app.ErrUsage) || len(h.api.calls) != 0 {
		t.Errorf("create without --vpc = %v after %d call(s), want a usage error before any request", err, len(h.api.calls))
	}
	// The default VPC ({region}-vpc) does not exist in this region.
	f.vpcs = nil
	if err := h.run("ecs", "security-group", "ensure", "web", "--rule", "tcp:80:0.0.0.0/0"); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "cn-shanghai-vpc") {
		t.Errorf("ensure without a VPC = %v, want a usage error naming the default VPC", err)
	}
	if len(h.api.callsFor("CreateSecurityGroup")) != 0 {
		t.Error("CreateSecurityGroup was sent without a VPC")
	}
	f.addVPC("vpc-main", "cn-shanghai-vpc")
	// The default VPC is used when it exists.
	if err := h.run("ecs", "security-group", "ensure", "web"); err != nil {
		t.Fatal(err)
	}
	if c := h.api.callsFor("CreateSecurityGroup"); len(c) != 1 || c[0].Get("VpcId") != "vpc-main" {
		t.Errorf("create calls = %v", c)
	}
	// create refuses a name the VPC already has.
	if err := h.run("ecs", "security-group", "create", "web", "--vpc", "vpc-main"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("create of an existing name = %v", err)
	}
	if err := h.run("ecs", "security-group", "create", "web", "--vpc", "vpc-nosuch"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("create in a missing VPC = %v, want not found", err)
	}
}

func TestSGDryRunWritesNothing(t *testing.T) {
	h, f := sgHarness(t, app.Flags{DryRun: true})
	f.addGroup("sg-web", "web", "vpc-main")
	f.addRule("sg-web", "TCP", "80/80", "0.0.0.0/0", "Accept")
	f.addInstance("i-1", "site-1", "vpc-main")
	cases := [][]string{
		{"ecs", "security-group", "ensure", "new", "--vpc", "vpc-main", "--rule", "tcp:80:0.0.0.0/0", "--rule", "tcp:443:0.0.0.0/0", "--instance", "site-1"},
		{"ecs", "security-group", "ensure", "web", "--vpc", "vpc-main", "--rule", "tcp:80:0.0.0.0/0", "--rule", "tcp:443:0.0.0.0/0", "--instance", "i-1"},
		{"ecs", "security-group", "create", "other", "--vpc", "vpc-main"},
		{"ecs", "security-group", "rule", "add", "web", "--rule", "tcp:22:10.0.0.0/8"},
		{"ecs", "security-group", "rule", "remove", "web", "--rule", "tcp:80:0.0.0.0/0"},
		{"ecs", "security-group", "delete", "web"},
	}
	for _, args := range cases {
		if err := h.run(args...); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		rep := reportOf(t, h)
		if !rep.DryRun {
			t.Errorf("%v: not a dry-run report", args)
		}
		if strings.Contains(h.stderr.String(), "(y/N)") {
			t.Errorf("%v asked a question", args)
		}
		if args[3] == "new" {
			if rep.Changes[0].Action != platform.WouldCreate || rep.Changes[0].ID != platform.Pending ||
				countActions(rep, platform.WouldCreate) != 3 || rep.Changes[3].Action != platform.WouldUpdate || rep.Changes[3].Detail != "join (pending) to i-1" {
				t.Errorf("dry run of a new group = %+v", rep.Changes)
			}
		}
		if args[3] == "web" && args[2] == "ensure" {
			if countActions(rep, platform.Unchanged) != 2 || countActions(rep, platform.WouldCreate) != 1 || countActions(rep, platform.WouldUpdate) != 1 {
				t.Errorf("dry run of an existing group = %+v", rep.Changes)
			}
		}
	}
	if len(f.writes) != 0 {
		t.Errorf("dry runs wrote %v", f.writes)
	}
}

func TestSGEnsureJoinsInstance(t *testing.T) {
	h, f := sgHarness(t, app.Flags{})
	f.addGroup("sg-old", "old", "vpc-main")
	f.addInstance("i-1", "site-1", "vpc-main", "sg-old")
	if err := h.run("ecs", "security-group", "ensure", "web", "--instance", "site-1", "--rule", "tcp:80:0.0.0.0/0"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if !slices.Equal(f.writes, []string{"CreateSecurityGroup", "AuthorizeSecurityGroup", "JoinSecurityGroup"}) {
		t.Errorf("writes = %v", f.writes)
	}
	if c := h.api.callsFor("CreateSecurityGroup")[0]; c.Get("VpcId") != "vpc-main" {
		t.Errorf("group created in %q, want the instance's VPC", c.Get("VpcId"))
	}
	sgs := f.instances[0]["SecurityGroupIds"].(map[string]any)["SecurityGroupId"].([]string)
	if len(sgs) != 2 || sgs[0] != "sg-old" {
		t.Errorf("instance groups = %v, want the old one kept and the new one added", sgs)
	}
	f.writes = nil
	if err := h.run("ecs", "security-group", "ensure", "web", "--instance", "i-1", "--rule", "tcp:80:0.0.0.0/0"); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Errorf("second ensure wrote %v", f.writes)
	}
	if rep := reportOf(t, h); rep.Changes[len(rep.Changes)-1].Resource != "instance/site-1" || rep.Changes[len(rep.Changes)-1].Action != platform.Unchanged {
		t.Errorf("report = %+v", rep.Changes)
	}
	if err := h.run("ecs", "security-group", "ensure", "web", "--instance", "i-1", "--vpc", "vpc-other"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("--vpc other than the instance's = %v, want a usage error", err)
	}
}

// A group just created may not be found by the first authorize: it is
// retried, 2 seconds apart.
func TestSGAuthorizeRetriesAfterCreate(t *testing.T) {
	clock := &fakeSleepClock{}
	sgRetryClock = clock
	t.Cleanup(func() { sgRetryClock = nil })
	h, f := sgHarness(t, app.Flags{})
	f.authorizeNotFound = 2
	if err := h.run("ecs", "security-group", "ensure", "web", "--vpc", "vpc-main", "--rule", "tcp:80:0.0.0.0/0"); err != nil {
		t.Fatal(err)
	}
	if n := len(h.api.callsFor("AuthorizeSecurityGroup")); n != 3 || len(clock.sleeps) != 2 || clock.sleeps[0].Seconds() != 2 {
		t.Errorf("authorize calls %d, sleeps %v", n, clock.sleeps)
	}
	// An existing group is not retried.
	f.authorizeNotFound = 1
	if err := h.run("ecs", "security-group", "rule", "add", "web", "--rule", "tcp:81:0.0.0.0/0"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("rule add on a vanished group = %v", err)
	}
}

func TestSGRuleRemove(t *testing.T) {
	h, f := sgHarness(t, app.Flags{})
	f.addGroup("sg-web", "web", "vpc-main")
	f.addRule("sg-web", "TCP", "8000/8999", "10.0.0.0/8", "Accept")
	id2 := f.addRule("sg-web", "TCP", "22/22", "203.0.113.7", "Accept")
	f.addRule("sg-web", "TCP", "22/22", "203.0.113.7/32", "Accept")

	// Non-interactive without --yes: a usage error, nothing removed.
	if err := h.run("ecs", "security-group", "rule", "remove", "web", "--rule", "tcp:8000-8999:10.0.0.0/8"); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("remove without --yes = %v", err)
	}
	// A rule that is not there is unchanged, and asks nothing.
	if err := h.run("ecs", "security-group", "rule", "remove", "web", "--rule", "tcp:9999:10.0.0.0/8"); err != nil {
		t.Fatal(err)
	}
	if rep := reportOf(t, h); len(rep.Changes) != 1 || rep.Changes[0].Action != platform.Unchanged || len(f.writes) != 0 {
		t.Errorf("absent rule: %+v, writes %v", rep.Changes, f.writes)
	}
	h.rt.Flags.Yes = true
	if err := h.run("ecs", "security-group", "rule", "remove", "web", "--rule", "tcp:8000-8999:10.0.0.0/8", "--rule", "tcp:22:203.0.113.7", "--rule", "tcp:9:10.0.0.0/8"); err != nil {
		t.Fatal(err)
	}
	revokes := h.api.callsFor("RevokeSecurityGroup")
	if len(revokes) != 1 || revokes[0].Get("SecurityGroupRuleId.3") == "" {
		t.Errorf("revoke calls = %v, want one with the 3 stored rules (both forms of 203.0.113.7)", revokes)
	}
	if len(f.rules["sg-web"]) != 0 {
		t.Errorf("rules left: %v", f.rules["sg-web"])
	}
	rep := reportOf(t, h)
	if countActions(rep, platform.Deleted) != 2 || countActions(rep, platform.Unchanged) != 1 {
		t.Errorf("report = %+v", rep.Changes)
	}

	// --rule-id: by id; an id that is gone is unchanged.
	id := f.addRule("sg-web", "TCP", "80/80", "0.0.0.0/0", "Accept")
	if err := h.run("ecs", "security-group", "rule", "remove", "sg-web", "--rule-id", id, "--rule-id", id2); err != nil {
		t.Fatal(err)
	}
	rep = reportOf(t, h)
	if countActions(rep, platform.Deleted) != 1 || countActions(rep, platform.Unchanged) != 1 || len(f.rules["sg-web"]) != 0 {
		t.Errorf("--rule-id report = %+v, rules %v", rep.Changes, f.rules["sg-web"])
	}
	if err := h.run("ecs", "security-group", "rule", "remove", "web", "--rule", "tcp:80:0.0.0.0/0", "--rule-id", id); !errors.Is(err, app.ErrUsage) {
		t.Errorf("--rule with --rule-id = %v", err)
	}
	if err := h.run("ecs", "security-group", "rule", "remove", "web"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("remove without rules = %v", err)
	}
}

// A rule removed meanwhile makes ECS refuse the batch: the others are
// removed one by one and the vanished one is unchanged.
func TestRevokeRulesFallsBackOneByOne(t *testing.T) {
	h, f := sgHarness(t, app.Flags{})
	f.addGroup("sg-web", "web", "vpc-main")
	a := f.addRule("sg-web", "TCP", "1/1", "0.0.0.0/0", "Accept")
	s := &ecsScope{c: h.api.client(), profile: "ali", region: "cn-shanghai"}
	gone := map[string]bool{}
	if err := revokeRules(t.Context(), s, "sg-web", []string{a, "sgr-vanished"}, gone); err != nil {
		t.Fatal(err)
	}
	if !gone["sgr-vanished"] || gone[a] || len(f.rules["sg-web"]) != 0 {
		t.Errorf("gone %v, rules %v", gone, f.rules["sg-web"])
	}
}

func TestSGDelete(t *testing.T) {
	h, f := sgHarness(t, app.Flags{})
	f.addGroup("sg-web", "web", "vpc-main")
	f.addGroup("sg-used", "used", "vpc-main")
	f.addInstance("i-1", "site-1", "vpc-main", "sg-used")
	if err := h.run("ecs", "security-group", "delete", "web"); !errors.Is(err, app.ErrUsage) || len(h.api.calls) != 0 {
		t.Errorf("delete without --yes = %v after %d call(s), want a usage error before any request", err, len(h.api.calls))
	}
	h.rt.Flags.Yes = true
	if err := h.run("ecs", "security-group", "delete", "web"); err != nil {
		t.Fatal(err)
	}
	if rep := reportOf(t, h); rep.Changes[0].Action != platform.Deleted || rep.Changes[0].ID != "sg-web" || len(f.groups) != 1 {
		t.Errorf("delete report = %+v", rep.Changes)
	}
	err := h.run("ecs", "security-group", "delete", "used")
	if err == nil || errors.Is(err, platform.ErrNotFound) || errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "instances are still in the group") {
		t.Errorf("delete of a group in use = %v, want a general failure with a hint", err)
	}
	if err := h.run("ecs", "security-group", "delete", "sg-gone"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("delete of a missing group = %v", err)
	}
}

func TestSGListUsesInventoryPerRegion(t *testing.T) {
	h, f := sgHarness(t, app.Flags{})
	f.addGroup("sg-a", "web", "vpc-main")
	f.addGroup("sg-b", "api", "vpc-other")
	if err := h.run("ecs", "security-group", "list"); err != nil {
		t.Fatal(err)
	}
	var sgs []securityGroup
	h.jsonOut(&sgs)
	if len(sgs) != 2 || sgs[0].Name != "api" || sgs[0].Region != "cn-shanghai" {
		t.Errorf("list = %+v", sgs)
	}
	calls := len(h.api.callsFor("DescribeSecurityGroups"))
	if err := h.run("ecs", "security-group", "list", "--vpc", "vpc-main"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&sgs)
	if len(sgs) != 1 || sgs[0].ID != "sg-a" || len(h.api.callsFor("DescribeSecurityGroups")) != calls {
		t.Errorf("cached list --vpc = %+v (calls %d -> %d)", sgs, calls, len(h.api.callsFor("DescribeSecurityGroups")))
	}
	f.groups = nil
	if err := h.run("ecs", "security-group", "list", "--region", "cn-hongkong"); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(h.stdout.String()) != "[]" || !strings.Contains(h.stderr.String(), "no security groups") {
		t.Errorf("empty list: stdout %q, stderr %q", h.stdout.String(), h.stderr.String())
	}
}

// On a terminal, delete and rule remove ask (default no); declining is
// "nothing to do", not a failure.
func TestSGInteractiveConfirmations(t *testing.T) {
	for _, tc := range []struct {
		answer string
		done   bool
	}{{"y\n", true}, {"n\n", false}, {"\n", false}} {
		h, f := sgHarness(t, app.Flags{})
		f.addGroup("sg-web", "web", "vpc-main")
		f.addGroup("sg-api", "api", "vpc-main")
		f.addRule("sg-api", "TCP", "22/22", "10.0.0.0/8", "Accept")
		h.rt.Picker = terminalStub{t}

		h.rt.Stdin = strings.NewReader(tc.answer)
		err := h.run("ecs", "security-group", "delete", "web")
		if !strings.Contains(h.stderr.String(), "Delete security group web (sg-web)? (y/N)") {
			t.Errorf("delete question: %q", h.stderr.String())
		}
		if tc.done != (err == nil) || !tc.done && !errors.Is(err, platform.ErrNothingToDo) || tc.done == (f.group("sg-web") != nil) {
			t.Errorf("answer %q: delete = %v, group left %v", tc.answer, err, f.group("sg-web") != nil)
		}

		h.rt.Stdin = strings.NewReader(tc.answer)
		err = h.run("ecs", "security-group", "rule", "remove", "api", "--rule", "tcp:ssh:10.0.0.0/8")
		if !strings.Contains(h.stderr.String(), "tcp 22/22 10.0.0.0/8") || !strings.Contains(h.stderr.String(), "(y/N)") {
			t.Errorf("rule remove question: %q", h.stderr.String())
		}
		if tc.done != (err == nil) || !tc.done && !errors.Is(err, platform.ErrNothingToDo) || tc.done != (len(f.rules["sg-api"]) == 0) {
			t.Errorf("answer %q: rule remove = %v, rules %v", tc.answer, err, f.rules["sg-api"])
		}
	}
}

func TestSGEnsureByIDUsesTheGroupsVPC(t *testing.T) {
	h, f := sgHarness(t, app.Flags{})
	f.addGroup("sg-o", "api", "vpc-other")
	// The default VPC (cn-shanghai-vpc = vpc-main) is another VPC: a group
	// given by id keeps its own VPC.
	if err := h.run("ecs", "security-group", "ensure", "sg-o", "--rule", "tcp:80:0.0.0.0/0"); err != nil {
		t.Fatalf("ensure by id: %v", err)
	}
	if !slices.Equal(f.writes, []string{"AuthorizeSecurityGroup"}) {
		t.Errorf("writes = %v, want one AuthorizeSecurityGroup", f.writes)
	}
	// Without any default VPC it still works.
	f.vpcs = nil
	if err := h.run("ecs", "security-group", "ensure", "sg-o", "--rule", "tcp:80:0.0.0.0/0"); err != nil {
		t.Fatalf("ensure by id without a default VPC: %v", err)
	}
	if rep := reportOf(t, h); countActions(rep, platform.Unchanged) != 2 {
		t.Errorf("second run = %+v, want everything unchanged", rep.Changes)
	}
	// An explicit --vpc that is not the group's is still refused.
	f.addVPC("vpc-main", "cn-shanghai-vpc")
	err := h.run("ecs", "security-group", "ensure", "sg-o", "--vpc", "vpc-main")
	if err == nil || errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "cannot move") {
		t.Errorf("ensure by id with another --vpc = %v, want a general failure", err)
	}
}
