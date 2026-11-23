package aws

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

func mustRule(t *testing.T, s string) platform.IngressRule {
	t.Helper()
	r, err := platform.ParseIngressRule(s)
	if err != nil {
		t.Fatalf("ParseIngressRule(%q): %v", s, err)
	}
	return r
}

func TestToIpPermission(t *testing.T) {
	cases := []struct {
		rule, proto string
		from, to    *int32
		field       string
	}{
		{"tcp:80:0.0.0.0/0", "tcp", awssdk.Int32(80), awssdk.Int32(80), "v4"},
		{"tcp:8000-8999:10.0.0.0/8", "tcp", awssdk.Int32(8000), awssdk.Int32(8999), "v4"},
		{"udp:dns:10.0.0.0/8", "udp", awssdk.Int32(53), awssdk.Int32(53), "v4"},
		{"icmp:all:0.0.0.0/0", "icmp", awssdk.Int32(-1), awssdk.Int32(-1), "v4"},
		{"icmp:all:::/0", "58", awssdk.Int32(-1), awssdk.Int32(-1), "v6"},
		{"all:all:sg-0123456789abcdef0", "-1", nil, nil, "sg"},
		{"tcp:443:::/0", "tcp", awssdk.Int32(443), awssdk.Int32(443), "v6"},
		{"tcp:443:2001:db8::/32", "tcp", awssdk.Int32(443), awssdk.Int32(443), "v6"},
	}
	for _, c := range cases {
		p, err := toIpPermission(mustRule(t, c.rule), "web")
		if err != nil {
			t.Fatalf("%s: %v", c.rule, err)
		}
		if awssdk.ToString(p.IpProtocol) != c.proto || (p.FromPort == nil) != (c.from == nil) ||
			awssdk.ToInt32(p.FromPort) != awssdk.ToInt32(c.from) || awssdk.ToInt32(p.ToPort) != awssdk.ToInt32(c.to) {
			t.Errorf("%s: protocol %s ports %v-%v", c.rule, awssdk.ToString(p.IpProtocol), p.FromPort, p.ToPort)
		}
		got := map[string]int{"v4": len(p.IpRanges), "v6": len(p.Ipv6Ranges), "sg": len(p.UserIdGroupPairs)}
		for field, n := range got {
			if want := map[bool]int{true: 1, false: 0}[field == c.field]; n != want {
				t.Errorf("%s: %s sources = %d, want %d (regression: IPv6 CIDRs go into Ipv6Ranges)", c.rule, field, n, want)
			}
		}
	}
	p, _ := toIpPermission(mustRule(t, "tcp:22:10.0.0.0/8"), "")
	if p.IpRanges[0].Description != nil {
		t.Error("an empty description must not be sent")
	}
}

func TestRuleExists(t *testing.T) {
	existing := []ec2types.IpPermission{
		{IpProtocol: awssdk.String("tcp"), FromPort: awssdk.Int32(443), ToPort: awssdk.Int32(443),
			IpRanges: []ec2types.IpRange{{CidrIp: awssdk.String("10.0.0.0/8"), Description: awssdk.String("office")}, {CidrIp: awssdk.String("0.0.0.0/0")}}},
		{IpProtocol: awssdk.String("icmpv6"), FromPort: awssdk.Int32(-1), ToPort: awssdk.Int32(-1), Ipv6Ranges: []ec2types.Ipv6Range{{CidrIpv6: awssdk.String("::/0")}}},
		{IpProtocol: awssdk.String("-1"), UserIdGroupPairs: []ec2types.UserIdGroupPair{{GroupId: awssdk.String("sg-0aaa")}}},
	}
	for rule, want := range map[string]bool{
		"tcp:443:10.0.0.0/8":      true, // the existing description does not count
		"tcp:443:10.5.6.7/8":      true, // masked like AWS stores it
		"tcp:https:0.0.0.0/0":     true, // the second source of a merged permission
		"tcp:443:192.0.2.0/24":    false,
		"tcp:80:10.0.0.0/8":       false,
		"icmp:all:::/0":           true, // 58 is icmpv6
		"icmp:all:0.0.0.0/0":      false,
		"all:all:sg-0aaa":         true,
		"all:all:sg-0bbb":         false,
		"udp:443:0.0.0.0/0":       false,
		"tcp:443:::/0":            false,
		"tcp:1-65535:10.0.0.0/8":  false,
		"tcp:all:0.0.0.0/0":       false,
		"tcp:443:0.0.0.0/0":       true,
		"tcp:443:2001:db8::/32":   false,
		"icmp:all:2001:db8::1/48": false,
	} {
		p, err := toIpPermission(mustRule(t, rule), "a different description")
		if err != nil {
			t.Fatal(err)
		}
		got, err := ruleExists(existing, p)
		if err != nil || got != want {
			t.Errorf("ruleExists(%s) = %v, %v; want %v", rule, got, err, want)
		}
	}
	if _, err := ruleExists(existing, ec2types.IpPermission{IpProtocol: awssdk.String("tcp")}); err == nil {
		t.Error("a rule without a source must be an internal error, not a match")
	}
}

func TestFlattenPermissionNormalizes(t *testing.T) {
	rules := flattenPermissions([]ec2types.IpPermission{
		{IpProtocol: awssdk.String("-1"), FromPort: awssdk.Int32(0), ToPort: awssdk.Int32(65535), IpRanges: []ec2types.IpRange{{CidrIp: awssdk.String("10.1.2.3/8")}}},
		{IpProtocol: awssdk.String("58"), PrefixListIds: []ec2types.PrefixListId{{PrefixListId: awssdk.String("pl-0123")}}},
	})
	if len(rules) != 2 || rules[0].String() != "all all 10.0.0.0/8" || rules[1].Protocol != "icmpv6" || rules[1].SourceType != platform.SourcePrefixList {
		t.Errorf("flatten = %+v", rules)
	}
}

// sgClient is a client of the harness's fake account.
func sgClient(h *awsHarness) *client {
	return &client{region: "ap-east-1", ec2For: func(r string) ec2API { return newEC2(awssdk.Config{Region: r}) }}
}

func TestAddIngressRulesFallsBackOnDuplicate(t *testing.T) {
	h := newAWSHarness(t, app.Flags{}, nil)
	g := h.addSG("ap-east-1", &fakeSG{id: "sg-0123456789abcdef0", name: "web", rules: []fakeRule{tcpRule(443, "0.0.0.0/0", "")}})
	h.ec2.sg.authDup = true
	c := sgClient(h)
	rules := []platform.IngressRule{mustRule(t, "tcp:80:0.0.0.0/0"), mustRule(t, "tcp:443:0.0.0.0/0")}
	res, err := c.AddIngressRules(context.Background(), "", g.id, rules, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 || !res[0].Done || res[0].ID == "" || res[1].Done {
		t.Errorf("outcomes = %+v", res)
	}
	if n := len(h.ec2.sg.auths); n != 3 {
		t.Errorf("authorizations = %d, want the batch and two single ones", n)
	}
	if len(g.rules) != 2 {
		t.Errorf("rules = %+v", g.rules)
	}
}

func TestRemoveIngressRulesUnknown(t *testing.T) {
	for _, notFound := range []bool{false, true} {
		h := newAWSHarness(t, app.Flags{}, nil)
		g := h.addSG("ap-east-1", &fakeSG{id: "sg-0123456789abcdef0", name: "web", rules: []fakeRule{tcpRule(22, "10.0.0.0/8", "ssh from the office")}})
		h.ec2.sg.revokeNotFound = notFound
		res, err := sgClient(h).RemoveIngressRules(context.Background(), "", g.id, []platform.IngressRule{mustRule(t, "tcp:22:10.0.0.0/8"), mustRule(t, "tcp:80:0.0.0.0/0")})
		if err != nil {
			t.Fatalf("notFound=%v: %v", notFound, err)
		}
		if len(res) != 2 || !res[0].Done || res[1].Done || len(g.rules) != 0 {
			t.Errorf("notFound=%v: outcomes %+v, rules %+v", notFound, res, g.rules)
		}
		for _, in := range h.ec2.sg.revokes {
			for _, p := range in.IpPermissions {
				if len(p.IpRanges) > 0 && p.IpRanges[0].Description != nil {
					t.Error("a revocation must not send descriptions")
				}
			}
		}
	}
}

func TestFindSecurityGroups(t *testing.T) {
	h := newAWSHarness(t, app.Flags{}, nil)
	h.addSG("ap-east-1", &fakeSG{id: "sg-0123456789abcdef0", name: "web", vpc: "vpc-0abc"})
	h.addSG("ap-east-1", &fakeSG{id: "sg-0123456789abcdef1", name: "web", vpc: "vpc-0def"})
	h.addSG("ap-east-1", &fakeSG{id: "sg-0123456789abcdef2", name: "web-old", vpc: "vpc-0abc"})
	h.ec2.sg.pageSize = 1
	c := sgClient(h)
	ctx := context.Background()
	if out, err := c.FindSecurityGroups(ctx, "", "web", ""); err != nil || len(out) != 2 {
		t.Errorf("by name = %+v, %v", out, err)
	}
	if out, err := c.FindSecurityGroups(ctx, "", "web", "vpc-0def"); err != nil || len(out) != 1 || out[0].ID != "sg-0123456789abcdef1" {
		t.Errorf("by name in vpc = %+v, %v", out, err)
	}
	if out, err := c.FindSecurityGroups(ctx, "", "sg-0123456789abcdef9", ""); err != nil || len(out) != 0 {
		t.Errorf("missing id = %+v, %v", out, err)
	}
	if _, err := c.FindSecurityGroups(ctx, "", "sg-bogus", ""); !errors.Is(err, platform.ErrInvalidInput) {
		t.Errorf("malformed id = %v", err)
	}
	if out, err := c.FindSecurityGroups(ctx, "", "nothing", ""); err != nil || len(out) != 0 {
		t.Errorf("missing name = %+v, %v", out, err)
	}
	all, err := c.ListSecurityGroups(ctx, "", platform.SecurityGroupFilter{Name: "web*"})
	if err != nil || len(all) != 3 {
		t.Errorf("paginated list = %d, %v", len(all), err)
	}
}

func TestSetInstanceSecurityGroupsReplacesTheSet(t *testing.T) {
	h := newAWSHarness(t, app.Flags{}, nil)
	for _, id := range []string{"sg-0aaa0000", "sg-0bbb0000", "sg-0ccc0000"} {
		h.addSG("ap-east-1", &fakeSG{id: id, name: id})
	}
	h.ec2.inst.init()
	in := h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa1", name: "web", state: stateRunning, sgs: []string{"sg-0aaa0000", "sg-0bbb0000"}})
	c := sgClient(h)
	if err := c.SetInstanceSecurityGroups(context.Background(), "", in.id, []string{"sg-0aaa0000", "sg-0bbb0000", "sg-0ccc0000"}); err != nil {
		t.Fatal(err)
	}
	got := append([]string(nil), in.sgs...)
	sort.Strings(got)
	if strings.Join(got, ",") != "sg-0aaa0000,sg-0bbb0000,sg-0ccc0000" {
		t.Errorf("groups = %v", in.sgs)
	}
	if err := c.SetInstanceSecurityGroups(context.Background(), "", in.id, nil); !errors.Is(err, platform.ErrInvalidInput) {
		t.Errorf("empty set = %v", err)
	}
	ids, err := c.SecurityGroupInstances(context.Background(), "", "sg-0ccc0000")
	if err != nil || len(ids) != 1 || ids[0] != in.id {
		t.Errorf("instances = %v, %v", ids, err)
	}
}

func TestDeleteSecurityGroupErrors(t *testing.T) {
	h := newAWSHarness(t, app.Flags{}, nil)
	h.addSG("ap-east-1", &fakeSG{id: "sg-0aaa0000", name: "used"})
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa1", name: "web", state: stateRunning, sgs: []string{"sg-0aaa0000"}})
	c := sgClient(h)
	err := c.DeleteSecurityGroup(context.Background(), "", "sg-0aaa0000")
	if err == nil || errors.Is(err, platform.ErrInvalidInput) || errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "still in use") {
		t.Errorf("dependency = %v", err)
	}
	if err := c.DeleteSecurityGroup(context.Background(), "", "sg-0fff0000"); !platform.HasErrorCode(err, errGroupNotFound) {
		t.Errorf("missing = %v", err)
	}
}
