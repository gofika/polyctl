package aliyun

import (
	"errors"
	"testing"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"

	"github.com/gofika/polyctl/internal/platform"
)

func TestRuleMappingToECS(t *testing.T) {
	for _, tc := range []struct {
		spec                         string
		proto, ports, v4, v6, sgroup string
	}{
		{spec: "tcp:80:0.0.0.0/0", proto: "TCP", ports: "80/80", v4: "0.0.0.0/0"},
		{spec: "tcp:http:0.0.0.0/0", proto: "TCP", ports: "80/80", v4: "0.0.0.0/0"},
		{spec: "udp:dns:10.0.0.0/8", proto: "UDP", ports: "53/53", v4: "10.0.0.0/8"},
		{spec: "tcp:8000-8999:10.0.0.0/8", proto: "TCP", ports: "8000/8999", v4: "10.0.0.0/8"},
		{spec: "tcp:1-65535:203.0.113.7", proto: "TCP", ports: "1/65535", v4: "203.0.113.7/32"},
		{spec: "tcp:all:203.0.113.7/32", proto: "TCP", ports: "1/65535", v4: "203.0.113.7/32"},
		{spec: "icmp:all:0.0.0.0/0", proto: "ICMP", ports: "-1/-1", v4: "0.0.0.0/0"},
		{spec: "all:all:0.0.0.0/0", proto: "ALL", ports: "-1/-1", v4: "0.0.0.0/0"},
		{spec: "tcp:443:::/0", proto: "TCP", ports: "443/443", v6: "::/0"},
		{spec: "tcp:443:2001:0db8:0000::/32", proto: "TCP", ports: "443/443", v6: "2001:db8::/32"},
		{spec: "icmp:all:::/0", proto: "ICMPv6", ports: "-1/-1", v6: "::/0"},
		{spec: "tcp:22:sg-0123abcd", proto: "TCP", ports: "22/22", sgroup: "sg-0123abcd"},
	} {
		r, err := platform.ParseIngressRule(tc.spec)
		if err != nil {
			t.Fatalf("%s: %v", tc.spec, err)
		}
		p := toPermission(r, 7, "d")
		if p.IpProtocol != tc.proto || p.PortRange != tc.ports || p.SourceCidrIp != tc.v4 || p.Ipv6SourceCidrIp != tc.v6 || p.SourceGroupId != tc.sgroup {
			t.Errorf("%s -> %+v", tc.spec, p)
		}
		if p.Policy != "accept" || p.Priority != "7" || p.NicType != "intranet" || p.Description != "d" {
			t.Errorf("%s: fixed fields %+v", tc.spec, p)
		}
	}
	// What ECS refuses with misleading codes is refused before any request.
	for _, bad := range []string{"icmp:80:0.0.0.0/0", "tcp:99999:0.0.0.0/0", "tcp:90-80:0.0.0.0/0", "gre:all:0.0.0.0/0", "all:80:0.0.0.0/0", "tcp:80"} {
		if _, err := platform.ParseIngressRule(bad); !errors.Is(err, platform.ErrInvalidInput) {
			t.Errorf("%s = %v, want a usage error", bad, err)
		}
	}
	for _, p := range []int{0, 101, -1} {
		if err := checkPriority(p); !errors.Is(err, platform.ErrInvalidInput) {
			t.Errorf("priority %d = %v", p, err)
		}
	}
	if checkPriority(1) != nil || checkPriority(100) != nil {
		t.Error("priorities 1 and 100 must be accepted")
	}
}

// The comparison normalizes what ECS reads back: the protocol in upper case,
// the policy capitalized, a single IPv4 address without /32, IPv6
// compressed; the policy counts, the priority does not.
func TestRuleComparisonNormalizesReadBack(t *testing.T) {
	stored := []ecs.Permission{
		{SecurityGroupRuleId: "sgr-1", IpProtocol: "TCP", PortRange: "80/80", SourceCidrIp: "0.0.0.0/0", Policy: "Accept", Priority: "50"},
		{SecurityGroupRuleId: "sgr-2", IpProtocol: "TCP", PortRange: "1/65535", SourceCidrIp: "203.0.113.7", Policy: "Accept"},
		{SecurityGroupRuleId: "sgr-3", IpProtocol: "ICMP", PortRange: "-1/-1", SourceCidrIp: "0.0.0.0/0", Policy: "Accept"},
		{SecurityGroupRuleId: "sgr-4", IpProtocol: "TCP", PortRange: "443/443", Ipv6SourceCidrIp: "2001:db8::/32", Policy: "Accept"},
		{SecurityGroupRuleId: "sgr-5", IpProtocol: "TCP", PortRange: "22/22", SourceCidrIp: "10.0.0.0/8", Policy: "Drop"},
	}
	var have []sgRule
	for _, p := range stored {
		have = append(have, ruleFrom(p))
	}
	want, err := platform.ParseIngressRules([]string{"tcp:80:0.0.0.0/0", "tcp:1-65535:203.0.113.7/32", "icmp:all:0.0.0.0/0", "tcp:443:2001:0db8::/32", "tcp:22:10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	missing, present := splitRules(have, want)
	if len(present) != 4 || len(missing) != 1 || missing[0].Ports() != "22" {
		t.Errorf("missing %v, present %v; want only the accept rule on port 22 missing (a drop rule is another rule)", missing, present)
	}
	if have[1].Source != "203.0.113.7" || have[0].Protocol != "tcp" || have[0].Policy != "accept" || have[0].Priority != 50 {
		t.Errorf("stored rule shown as %+v / %+v", have[0], have[1])
	}
}
