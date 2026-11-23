package aliyun

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/platform"
)

// findFake answers the read calls of the find sync in two regions, with
// the data shapes observed on a real international-site account: VPC
// instances with empty classic address lists, an EIP in EipAddress only,
// secondary private addresses only in DescribeNetworkInterfaces (primary
// not first), and an ALB whose addresses are on GetLoadBalancerAttribute
// and on a Bond interface named "<id> CREATED_BY_ALB".
func findFake(t *testing.T, h *harness) {
	t.Helper()
	h.api.on("DescribeRegions", func(q url.Values) (int, any) {
		return 200, map[string]any{"Regions": map[string]any{"Region": []map[string]any{{"RegionId": "cn-hongkong"}, {"RegionId": "cn-shanghai"}, {"RegionId": "me-central-1"}}}}
	})
	instances := map[string][]map[string]any{
		"cn-hongkong": {{"InstanceId": "i-hk1", "InstanceName": "web", "Status": "Running", "RegionId": "cn-hongkong", "ZoneId": "cn-hongkong-b",
			"PublicIpAddress": map[string]any{"IpAddress": []string{}}, "InnerIpAddress": map[string]any{"IpAddress": []string{}},
			"EipAddress":    map[string]any{"IpAddress": "47.0.0.10", "AllocationId": "eip-hk1"},
			"VpcAttributes": map[string]any{"VpcId": "vpc-hk", "VSwitchId": "vsw-hk-b", "PrivateIpAddress": map[string]any{"IpAddress": []string{"172.16.0.10"}}},
			"NetworkInterfaces": map[string]any{"NetworkInterface": []map[string]any{
				{"NetworkInterfaceId": "eni-p", "Type": "Primary", "PrimaryIpAddress": "172.16.0.10", "PrivateIpSets": map[string]any{"PrivateIpSet": []map[string]any{{"PrivateIpAddress": "172.16.0.10", "Primary": true}}}},
				{"NetworkInterfaceId": "eni-s", "Type": "Secondary", "PrimaryIpAddress": "172.16.1.20"},
			}}}},
		"cn-shanghai": {{"InstanceId": "i-sh1", "InstanceName": "db", "Status": "Stopped", "RegionId": "cn-shanghai", "ZoneId": "cn-shanghai-b",
			"EipAddress":    map[string]any{"IpAddress": "", "AllocationId": ""},
			"VpcAttributes": map[string]any{"VpcId": "vpc-sh", "VSwitchId": "vsw-sh-b", "PrivateIpAddress": map[string]any{"IpAddress": []string{"172.16.0.10"}}},
		}},
	}
	h.api.on("DescribeInstances", func(q url.Values) (int, any) {
		if q.Get("RegionId") == "me-central-1" {
			return 503, map[string]any{"Code": "ServiceUnavailable", "Message": "connection reset"}
		}
		list := instances[q.Get("RegionId")]
		return 200, map[string]any{"TotalCount": len(list), "Instances": map[string]any{"Instance": list}}
	})
	enis := map[string][]map[string]any{"cn-hongkong": {
		{"NetworkInterfaceId": "eni-p", "Type": "Primary", "InstanceId": "i-hk1", "VSwitchId": "vsw-hk-b", "PrivateIpAddress": "172.16.0.10",
			"AssociatedPublicIp": map[string]any{"PublicIpAddress": "47.0.0.10"},
			"PrivateIpSets": map[string]any{"PrivateIpSet": []map[string]any{
				{"PrivateIpAddress": "172.16.0.11", "Primary": false}, {"PrivateIpAddress": "172.16.0.10", "Primary": true, "AssociatedPublicIp": map[string]any{"PublicIpAddress": "47.0.0.10"}}}}},
		{"NetworkInterfaceId": "eni-s", "Type": "Secondary", "InstanceId": "i-hk1", "VSwitchId": "vsw-hk-c", "PrivateIpAddress": "172.16.1.20",
			"AssociatedPublicIp": map[string]any{}, "PrivateIpSets": map[string]any{"PrivateIpSet": []map[string]any{{"PrivateIpAddress": "172.16.1.20", "Primary": true}, {"PrivateIpAddress": "172.16.1.21"}}}},
		{"NetworkInterfaceId": "eni-alb", "Type": "Bond", "InstanceId": "", "ServiceManaged": true, "NetworkInterfaceName": "alb-abc123 CREATED_BY_ALB",
			"Description": "created by alb", "PrivateIpAddress": "172.16.2.5", "AssociatedPublicIp": map[string]any{"PublicIpAddress": "47.0.0.30"},
			"PrivateIpSets": map[string]any{"PrivateIpSet": []map[string]any{{"PrivateIpAddress": "172.16.2.5", "Primary": true}, {"PrivateIpAddress": "172.16.2.6"}, {"PrivateIpAddress": "172.16.2.7"}}}},
	}}
	h.api.on("DescribeNetworkInterfaces", func(q url.Values) (int, any) {
		list := enis[q.Get("RegionId")]
		// Two pages, to check that NextToken is followed.
		if q.Get("NextToken") == "" && len(list) > 1 {
			return 200, map[string]any{"NextToken": "p2", "NetworkInterfaceSets": map[string]any{"NetworkInterfaceSet": list[:1]}}
		}
		if q.Get("NextToken") == "p2" {
			list = list[1:]
		}
		return 200, map[string]any{"NextToken": "", "NetworkInterfaceSets": map[string]any{"NetworkInterfaceSet": list}}
	})
	eips := map[string][]map[string]any{"cn-hongkong": {
		{"AllocationId": "eip-hk1", "IpAddress": "47.0.0.10", "Status": "InUse", "InstanceId": "i-hk1", "InstanceType": "EcsInstance", "RegionId": "cn-hongkong"},
		{"AllocationId": "eip-alb", "IpAddress": "47.0.0.30", "Status": "InUse", "InstanceId": "eni-alb", "InstanceType": "NetworkInterface", "ServiceManaged": 1, "RegionId": "cn-hongkong"},
		{"AllocationId": "eip-idle", "IpAddress": "47.0.0.99", "Status": "Available", "InstanceId": "", "InstanceType": "", "RegionId": "cn-hongkong"},
	}}
	h.api.on("DescribeEipAddresses", func(q url.Values) (int, any) {
		list := eips[q.Get("RegionId")]
		return 200, map[string]any{"TotalCount": len(list), "EipAddresses": map[string]any{"EipAddress": list}}
	})
	h.api.on("ListLoadBalancers", func(q url.Values) (int, any) {
		if q.Get("RegionId") != "cn-hongkong" {
			return 200, map[string]any{"NextToken": "", "LoadBalancers": []any{}}
		}
		return 200, map[string]any{"NextToken": "", "LoadBalancers": []map[string]any{{"LoadBalancerId": "alb-abc123", "LoadBalancerName": "lb-example-com"}}}
	})
	h.api.on("GetLoadBalancerAttribute", func(q url.Values) (int, any) {
		return 200, map[string]any{"LoadBalancerId": q.Get("LoadBalancerId"), "LoadBalancerName": "lb-example-com", "AddressType": "Internet", "AddressIpVersion": "IPv4",
			"DNSName": "alb-abc123.cn-hongkong.alb.aliyuncsslbintl.com", "LoadBalancerStatus": "Active", "VpcId": "vpc-hk",
			"ZoneMappings": []map[string]any{
				{"ZoneId": "cn-hongkong-c", "VSwitchId": "vsw-hk-c", "LoadBalancerAddresses": []map[string]any{{"Address": "47.0.0.31", "AllocationId": "eip-alb2", "EipType": "Common", "IntranetAddress": "172.16.2.8", "Ipv4LocalAddresses": []string{"172.16.2.9"}}}},
				{"ZoneId": "cn-hongkong-b", "VSwitchId": "vsw-hk-b", "LoadBalancerAddresses": []map[string]any{{"Address": "47.0.0.30", "AllocationId": "eip-alb", "EipType": "Common"}}},
			}}
	})
	h.api.on("DescribeVSwitches", func(q url.Values) (int, any) {
		list := []map[string]any{{"VSwitchId": "vsw-hk-c", "VpcId": "vpc-hk", "ZoneId": "cn-hongkong-c", "CidrBlock": "172.16.1.0/24", "Ipv6CidrBlock": "2408:4000::/64", "Status": "Available"}}
		if q.Get("VSwitchId") != "vsw-hk-c" {
			list = nil
		}
		return 200, map[string]any{"TotalCount": len(list), "VSwitches": map[string]any{"VSwitch": list}}
	})
}

func TestFindAliyunSync(t *testing.T) {
	h := newHarness(t, app.Flags{})
	findFake(t, h)
	cfg, _ := h.rt.Config()
	cfg.Profiles["ali"].Platforms[platform.Aliyun].Metadata[metaSite] = siteIntl

	ctx := context.Background()
	reports, err := h.rt.SyncAccount(ctx, config.AccountRef{Profile: "ali", Platform: platform.Aliyun}, app.FindTypes)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[platform.ResourceType]int{}
	for _, r := range reports {
		counts[r.Type] = r.Count
		if r.Type == platform.ResInstance {
			rse := platform.AsRegionSyncError(r.Err)
			if rse == nil || len(rse.Failures) != 1 || rse.Failures[0].Region != "me-central-1" {
				t.Errorf("instance err = %v", r.Err)
			}
		} else if r.Err != nil {
			t.Errorf("%s err = %v", r.Type, r.Err)
		}
	}
	if counts[platform.ResInstance] != 2 || counts[platform.ResEIP] != 3 || counts[platform.ResLoadBalancer] != 1 {
		t.Errorf("counts = %v", counts)
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
	// Overlapping private networks: both instances.
	res := find("172.16.0.10", false)
	if len(res.Matches) != 2 || res.Matches[0].Network == res.Matches[1].Network {
		t.Errorf("overlap = %+v", res.Matches)
	}
	// A secondary private address of the secondary interface.
	res = find("172.16.1.21", false)
	if len(res.Matches) != 1 || res.Matches[0].ID != "i-hk1" || res.Matches[0].Subnet != "vsw-hk-c" ||
		res.Matches[0].URL != "https://ecs.console.alibabacloud.com/server/i-hk1/detail?regionId=cn-hongkong" {
		t.Errorf("secondary = %+v", res.Matches)
	}
	// The EIP of the instance annotates it.
	res = find("47.0.0.10", false)
	if len(res.Matches) != 1 || res.Matches[0].ID != "i-hk1" || len(res.Matches[0].Addresses) != 1 {
		t.Errorf("eip of instance = %+v", res.Matches)
	}
	// The ALB: its zone address, its interface addresses, its DNS name.
	for _, q := range []string{"47.0.0.31", "172.16.2.7", "alb-abc123.cn-hongkong.alb.aliyuncsslbintl.com"} {
		res = find(q, false)
		if len(res.Matches) == 0 || res.Matches[0].Type != platform.ResLoadBalancer || res.Matches[0].URL != "" {
			t.Errorf("%s = %+v", q, res.Matches)
		}
	}
	if res := find("47.0.0.99", false); len(res.Matches) != 1 || res.Matches[0].Type != platform.ResEIP || res.Matches[0].Note != "EIP, not bound" {
		t.Errorf("idle eip = %+v", res.Matches)
	}

	// --detail reads the vSwitch of the interface holding the address.
	res = find("172.16.1.21", true)
	if len(res.Matches) != 1 || res.Matches[0].Detail == nil {
		t.Fatalf("detail = %+v %+v", res.Matches, res.Errors)
	}
	if d := res.Matches[0].Detail; d.SubnetCIDR != "172.16.1.0/24" || d.VPC != "vpc-hk" || len(d.SubnetIPv6CIDR) != 1 {
		t.Errorf("detail = %+v", d)
	}
}

func TestAliyunConsoleURL(t *testing.T) {
	p := &provider{}
	m := &platform.FindMatch{Type: platform.ResInstance, ID: "i-1", Region: "cn-hangzhou"}
	for site, want := range map[string]string{
		siteCN:   "https://ecs.console.aliyun.com/server/i-1/detail?regionId=cn-hangzhou",
		siteIntl: "https://ecs.console.alibabacloud.com/server/i-1/detail?regionId=cn-hangzhou",
		"":       "",
	} {
		if got := p.ConsoleURL(map[string]string{metaSite: site}, m); got != want {
			t.Errorf("site %q = %q, want %q", site, got, want)
		}
	}
	if got := p.ConsoleURL(map[string]string{metaSite: siteCN}, &platform.FindMatch{Type: platform.ResEIP, ID: "eip-1", Region: "cn-hangzhou"}); got != "" {
		t.Errorf("eip url = %q", got)
	}
}

func TestAliyunInstanceAddresses(t *testing.T) {
	in := Instance{ID: "i-c", Region: "cn-hangzhou", InnerIPs: []string{"10.1.1.1"}, PublicIPs: []string{"121.0.0.1"}, NatIP: "121.0.0.2",
		Interfaces: []netIface{{Type: "Primary", Private: []string{"10.1.1.1"}, IPv6: []string{"2408::1"}, Prefixes: []string{"10.1.2.0/28"}}}}
	var got []string
	for _, r := range instanceResource(in).IPs {
		got = append(got, string(r.Kind)+":"+r.Value)
	}
	if s := strings.Join(got, " "); s != "internal:10.1.1.1 internal:2408::1 internal:10.1.2.0/28 external:121.0.0.1 external:121.0.0.2" {
		t.Errorf("ips = %s", s)
	}
	b, _ := json.Marshal(in)
	m := &platform.FindMatch{Type: platform.ResInstance, Data: b, Matched: "10.1.2.0/28"}
	if err := (&provider{}).DescribeMatch(nil, m); err != nil || m.Region != "cn-hangzhou" || len(m.ExternalIPs) != 2 {
		t.Errorf("match = %+v, %v", m, err)
	}
}
