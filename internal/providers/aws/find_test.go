package aws

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/platform"
)

func TestInstanceAllAddresses(t *testing.T) {
	in := ec2types.Instance{InstanceId: awssdk.String("i-0aaa"), State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
		PrivateIpAddress: awssdk.String("10.0.1.100"), PublicIpAddress: awssdk.String("203.0.113.10"), Ipv6Address: awssdk.String("2001:db8::10"),
		PublicDnsName: awssdk.String("ec2-203-0-113-10.ap-east-1.compute.amazonaws.com"), PrivateDnsName: awssdk.String("ip-10-0-1-100.ap-east-1.compute.internal"),
		VpcId: awssdk.String("vpc-0abc"), SubnetId: awssdk.String("subnet-1"),
		NetworkInterfaces: []ec2types.InstanceNetworkInterface{
			{NetworkInterfaceId: awssdk.String("eni-1"), SubnetId: awssdk.String("subnet-1"), VpcId: awssdk.String("vpc-0abc"),
				PrivateIpAddress: awssdk.String("10.0.1.100"), Association: &ec2types.InstanceNetworkInterfaceAssociation{PublicIp: awssdk.String("203.0.113.10")},
				PrivateIpAddresses: []ec2types.InstancePrivateIpAddress{
					{PrivateIpAddress: awssdk.String("10.0.1.100"), Association: &ec2types.InstanceNetworkInterfaceAssociation{PublicIp: awssdk.String("203.0.113.10")}},
					{PrivateIpAddress: awssdk.String("10.0.1.101")}},
				Ipv4Prefixes: []ec2types.InstanceIpv4Prefix{{Ipv4Prefix: awssdk.String("10.0.1.208/28")}}},
			{NetworkInterfaceId: awssdk.String("eni-2"), SubnetId: awssdk.String("subnet-2"), VpcId: awssdk.String("vpc-0abc"),
				PrivateIpAddress: awssdk.String("10.0.2.5"), Ipv6Addresses: []ec2types.InstanceIpv6Address{{Ipv6Address: awssdk.String("2001:db8::25")}}},
		}}
	info := instanceFrom("ap-east-1", in)
	got := strings.Join(func() (out []string) {
		for _, r := range info.resource().IPs {
			out = append(out, string(r.Kind)+":"+r.Value)
		}
		return
	}(), " ")
	want := "internal:10.0.1.100 external:203.0.113.10 internal:10.0.1.101 internal:2001:db8::10 internal:10.0.1.208/28 internal:10.0.2.5 internal:2001:db8::25 dns:ec2-203-0-113-10.ap-east-1.compute.amazonaws.com dns:ip-10-0-1-100.ap-east-1.compute.internal"
	if got != want {
		t.Errorf("ips =\n%s\nwant\n%s", got, want)
	}
	b, _ := json.Marshal(info)
	m := &platform.FindMatch{Type: platform.ResInstance, ID: "i-0aaa", Data: b, Matched: "2001:db8::25"}
	_ = (&provider{}).DescribeMatch(nil, m)
	if m.Subnet != "subnet-2" || m.Network != "vpc-0abc" || m.Region != "ap-east-1" || len(m.DNSNames) != 2 {
		t.Errorf("match = %+v", m)
	}
	// A terminated instance holds no address.
	in.State.Name = ec2types.InstanceStateNameTerminated
	if refs := instanceFrom("ap-east-1", in).resource().IPs; len(refs) != 0 {
		t.Errorf("terminated = %v", refs)
	}
}

func TestAWSConsoleURLs(t *testing.T) {
	p := &provider{}
	for _, tc := range []struct {
		m    platform.FindMatch
		want string
	}{
		{platform.FindMatch{Type: platform.ResInstance, ID: "i-0abc", Region: "ap-east-1", Zone: "ap-east-1a"}, "https://ap-east-1.console.aws.amazon.com/ec2/home?region=ap-east-1#InstanceDetails:instanceId=i-0abc"},
		{platform.FindMatch{Type: platform.ResInstance, ID: "i-0abc", Region: "us-west-2", Zone: "us-west-2-den-1a"}, "https://us-west-2.console.aws.amazon.com/ec2/home?region=us-west-2#InstanceDetails:instanceId=i-0abc"},
		{platform.FindMatch{Type: platform.ResDBInstance, ID: "mydb", Region: "ap-east-1"}, "https://ap-east-1.console.aws.amazon.com/rds/home?region=ap-east-1#database:id=mydb"},
		{platform.FindMatch{Type: platform.ResLoadBalancer, ID: "arn", Region: "ap-east-1"}, ""},
		{platform.FindMatch{Type: platform.ResEIP, ID: "eipalloc-1", Region: "ap-east-1"}, ""},
		{platform.FindMatch{Type: platform.ResInstance, ID: "i-0abc", Region: "cn-north-1"}, ""},
		{platform.FindMatch{Type: platform.ResInstance, ID: "i-0abc"}, ""},
	} {
		if got := p.ConsoleURL(nil, &tc.m); got != tc.want {
			t.Errorf("%s %s = %q, want %q", tc.m.Type, tc.m.Region, got, tc.want)
		}
	}
}

func TestELBDescription(t *testing.T) {
	if d := elbDescription("arn:aws:elasticloadbalancing:ap-east-1:123456789012:loadbalancer/net/web/0123456789abcdef"); d != "ELB net/web/0123456789abcdef" {
		t.Errorf("description = %q", d)
	}
	if d := elbDescription("nonsense"); d != "" {
		t.Errorf("bad arn = %q", d)
	}
}

func TestFindAWSSync(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{})
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa1", name: "web", typ: "t3.nano", state: stateRunning, priv: "10.0.1.100", pub: "203.0.113.10"})
	h.addInstance("eu-west-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa2", name: "far", typ: "t3.nano", state: stateRunning, priv: "10.0.1.100"})
	h.addInstance("eu-west-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa3", name: "gone", typ: "t3.nano", state: stateTerminated})
	lbARN := "arn:aws:elasticloadbalancing:ap-east-1:123456789012:loadbalancer/net/edge/0123456789abcdef"
	ff := &h.ec2.find
	ff.regions = []string{"ap-east-1", "eu-west-1", "me-south-1"}
	ff.regionErr = map[string]error{"me-south-1": errors.New("dial tcp: lookup ec2.me-south-1.amazonaws.com: no such host")}
	ff.eniPage = 1
	ff.lbs = map[string][]elbtypes.LoadBalancer{"ap-east-1": {{LoadBalancerArn: awssdk.String(lbARN), LoadBalancerName: awssdk.String("edge"),
		DNSName: awssdk.String("edge-0123.elb.ap-east-1.amazonaws.com"), Type: elbtypes.LoadBalancerTypeEnumNetwork, Scheme: elbtypes.LoadBalancerSchemeEnumInternetFacing,
		State: &elbtypes.LoadBalancerState{Code: elbtypes.LoadBalancerStateEnumActive}, VpcId: awssdk.String("vpc-0abc"),
		AvailabilityZones: []elbtypes.AvailabilityZone{{ZoneName: awssdk.String("ap-east-1a")}}}}}
	ff.enis = map[string][]ec2types.NetworkInterface{"ap-east-1": {
		{NetworkInterfaceId: awssdk.String("eni-lb"), Description: awssdk.String("ELB net/edge/0123456789abcdef"), InterfaceType: ec2types.NetworkInterfaceTypeNetworkLoadBalancer,
			RequesterManaged: awssdk.Bool(true), PrivateIpAddress: awssdk.String("10.0.0.50"), Association: &ec2types.NetworkInterfaceAssociation{PublicIp: awssdk.String("198.51.100.50")}},
		{NetworkInterfaceId: awssdk.String("eni-nat"), Description: awssdk.String("Interface for NAT Gateway nat-0abc"), InterfaceType: ec2types.NetworkInterfaceTypeNatGateway,
			PrivateIpAddress: awssdk.String("10.0.0.60"), Association: &ec2types.NetworkInterfaceAssociation{PublicIp: awssdk.String("198.51.100.60")}, VpcId: awssdk.String("vpc-0abc")},
		{NetworkInterfaceId: awssdk.String("eni-inst"), Attachment: &ec2types.NetworkInterfaceAttachment{InstanceId: awssdk.String("i-0aaaaaaaaaaaaaaa1")}, PrivateIpAddress: awssdk.String("10.0.1.100")},
	}}
	ff.addresses = map[string][]ec2types.Address{"ap-east-1": {
		{AllocationId: awssdk.String("eipalloc-1"), PublicIp: awssdk.String("198.51.100.9"), Domain: ec2types.DomainTypeVpc},
	}}
	ff.dbs = map[string][]rdstypes.DBInstance{"eu-west-1": {
		{DBInstanceIdentifier: awssdk.String("mydb"), DBInstanceStatus: awssdk.String("available"), Engine: awssdk.String("mysql"),
			Endpoint: &rdstypes.Endpoint{Address: awssdk.String("mydb.abc123.eu-west-1.rds.amazonaws.com"), Port: awssdk.Int32(3306)}},
		{DBInstanceIdentifier: awssdk.String("newdb"), DBInstanceStatus: awssdk.String("creating")},
	}}
	ff.subnets = map[string]ec2types.Subnet{"ap-east-1/subnet-0def": {SubnetId: awssdk.String("subnet-0def"), VpcId: awssdk.String("vpc-0abc"), CidrBlock: awssdk.String("10.0.1.0/24"),
		Ipv6CidrBlockAssociationSet: []ec2types.SubnetIpv6CidrBlockAssociation{{Ipv6CidrBlock: awssdk.String("2001:db8:1::/64")}}}}

	ctx := context.Background()
	reports, err := h.rt.SyncAccount(ctx, config.AccountRef{Profile: "lab", Platform: platform.AWS}, app.FindTypes)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[platform.ResourceType]int{}
	for _, r := range reports {
		counts[r.Type] = r.Count
		if r.Type == platform.ResInstance && r.Err == nil {
			continue // the fake DescribeInstances does not fail by region
		}
		rse := platform.AsRegionSyncError(r.Err)
		if rse == nil || len(rse.Failures) != 1 || rse.Failures[0].Region != "me-south-1" {
			t.Errorf("%s err = %v", r.Type, r.Err)
		}
		counts[r.Type] = r.Count
	}
	if counts[platform.ResInstance] != 3 || counts[platform.ResLoadBalancer] != 1 || counts[platform.ResEIP] != 2 || counts[platform.ResDBInstance] != 2 {
		t.Errorf("counts = %v", counts)
	}
	if ff.eniCalls < 3 {
		t.Errorf("network interfaces not paged: %d calls", ff.eniCalls)
	}

	find := func(s string, detail bool) *app.FindResult {
		t.Helper()
		q, err := platform.ParseFindQuery(s)
		if err != nil {
			t.Fatal(err)
		}
		res, err := h.rt.Find(ctx, app.FindRequest{Query: q, Detail: detail})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	// The same private address in two regions: both, with their regions.
	res := find("10.0.1.100", false)
	if len(res.Matches) != 2 || res.Matches[0].Region != "eu-west-1" || res.Matches[1].Region != "ap-east-1" ||
		!strings.Contains(res.Matches[1].URL, "ap-east-1.console.aws.amazon.com") {
		t.Errorf("private = %+v", res.Matches)
	}
	if res := find("198.51.100.50", false); len(res.Matches) != 1 || res.Matches[0].Type != platform.ResLoadBalancer || res.Matches[0].Name != "edge" {
		t.Errorf("nlb interface = %+v", res.Matches)
	}
	if res := find("EDGE-0123.elb.ap-east-1.amazonaws.com", false); len(res.Matches) != 1 || res.Matches[0].MatchedField != "dns_name" {
		t.Errorf("nlb dns = %+v", res.Matches)
	}
	if res := find("198.51.100.60", false); len(res.Matches) != 1 || res.Matches[0].Type != platform.ResEIP || !strings.Contains(res.Matches[0].Note, "NAT Gateway") {
		t.Errorf("nat = %+v", res.Matches)
	}
	if res := find("198.51.100.9", false); len(res.Matches) != 1 || res.Matches[0].ID != "eipalloc-1" {
		t.Errorf("eip = %+v", res.Matches)
	}
	if res := find("mydb.abc123.eu-west-1.rds.amazonaws.com", false); len(res.Matches) != 1 || res.Matches[0].MatchedField != "endpoint" ||
		res.Matches[0].URL != "https://eu-west-1.console.aws.amazon.com/rds/home?region=eu-west-1#database:id=mydb" {
		t.Errorf("rds = %+v", res.Matches)
	}

	// --detail reads the subnet in the instance's region.
	res = find("203.0.113.10", true)
	if len(res.Matches) != 1 || res.Matches[0].Detail == nil {
		t.Fatalf("detail = %+v %+v", res.Matches, res.Errors)
	}
	if d := res.Matches[0].Detail; d.SubnetCIDR != "10.0.1.0/24" || d.VPC != "vpc-0abc" || len(d.SubnetIPv6CIDR) != 1 {
		t.Errorf("detail = %+v", d)
	}

	// The cached instance list still shows the profile's region only.
	h.rt.Flags.Offline = true
	err = h.run("ec2", "instance", "list")
	h.rt.Flags.Offline = false
	if err != nil {
		t.Fatal(err)
	}
	if out := h.stdout.String(); !strings.Contains(out, "i-0aaaaaaaaaaaaaaa1") || strings.Contains(out, "i-0aaaaaaaaaaaaaaa2") {
		t.Errorf("list = %s", out)
	}
}
