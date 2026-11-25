package aliyun

import (
	"testing"
	"time"
)

// TestOptionLabelsKeepTheirCells pins the cells of the selection lists: a
// fact keeps its position, and a fact a row does not have is "-" unless
// nothing follows it.
func TestOptionLabelsKeepTheirCells(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct{ name, got, want string }{
		{"vpc", vpcLabel(vpcInfo{Name: "app", ID: "vpc-1", CIDR: "10.0.0.0/16", Status: "Available", IsDefault: true}),
			"app  vpc-1  10.0.0.0/16  Available  [default]"},
		{"vpc without a name or status", vpcLabel(vpcInfo{ID: "vpc-1", CIDR: "10.0.0.0/16", IsDefault: true}),
			"vpc-1  vpc-1  10.0.0.0/16  -  [default]"},
		{"security group", sgLabel(securityGroup{Name: "web", ID: "sg-1", VPC: "vpc-1", Description: "front"}),
			"web  sg-1  vpc-1  front"},
		{"security group without a VPC", sgLabel(securityGroup{Name: "web", ID: "sg-1", Description: "front"}),
			"web  sg-1  -  front"},
		{"vSwitch", vswLabel(vSwitch{Name: "app", ID: "vsw-1", Zone: "cn-shanghai-b", CIDR: "172.16.0.0/22", VPC: "vpc-1", AvailableIPs: 1020}, map[string]string{"vpc-1": "main"}, "Available"),
			"app  vsw-1  cn-shanghai-b  172.16.0.0/22  main  vpc-1  1020 free IPs  Available"},
		{"vSwitch of an unnamed VPC without free IPs", vswLabel(vSwitch{Name: "app", ID: "vsw-1", Zone: "cn-shanghai-b", CIDR: "172.16.0.0/22", VPC: "vpc-1"}, nil, "Available"),
			"app  vsw-1  cn-shanghai-b  172.16.0.0/22  -  vpc-1  -  Available"},
		{"instance", instanceOptionLabel(Instance{Name: "site-a", ID: "i-1", Status: "Running", Type: "ecs.u1", Zone: "cn-shanghai-b", PrivateIP: "172.16.0.5", EIP: "203.0.113.9"}),
			"site-a  i-1  Running  ecs.u1  cn-shanghai-b  172.16.0.5  203.0.113.9"},
		{"instance without addresses, with its account", instanceOptionLabel(Instance{Name: "site-a", ID: "i-1", Status: "Stopped", Type: "ecs.u1", Zone: "cn-shanghai-b"}, "aliyun/ali"),
			"site-a  i-1  Stopped  ecs.u1  cn-shanghai-b  -  -  aliyun/ali"},
		{"load balancer", lbOptionLabel(albRef{Name: "web", ID: "alb-1", Status: "Active", VpcID: "vpc-1", DNSName: "web.alb.example"}),
			"web  alb-1  Active  vpc-1  web.alb.example"},
		{"load balancer without a status or VPC", lbOptionLabel(albRef{Name: "web", ID: "alb-1", DNSName: "web.alb.example"}),
			"web  alb-1  -  -  web.alb.example"},
		{"server group without a protocol", serverGroupLabel(albServerGroup{Name: "web", ID: "sgp-1", VpcID: "vpc-1", ServerCount: 2}),
			"web  sgp-1  -  vpc-1  2 servers"},
		{"ACL", aclLabel(albACL{Name: "office", ID: "acl-1", Status: "Available"}), "office  acl-1  Available"},
		{"listener", listenerLabel(albListener{Protocol: "HTTPS", Port: 443, ID: "lsn-1", Status: "Running", ServerGroups: []string{"sgp-1", "sgp-2"}}),
			"HTTPS:443  lsn-1  Running  sgp-1,sgp-2"},
		{"listener without a status", listenerLabel(albListener{Protocol: "HTTP", Port: 80, ID: "lsn-2", ServerGroups: []string{"sgp-1"}}),
			"HTTP:80  lsn-2  -  sgp-1"},
		{"EIP", eipLabel(eipAddress{IP: "203.0.113.9", AllocationID: "eip-1", Bandwidth: "5", ISP: "BGP", Name: "edge"}),
			"203.0.113.9  eip-1  5 Mbps  BGP  edge"},
		{"EIP without a bandwidth or ISP", eipLabel(eipAddress{IP: "203.0.113.9", AllocationID: "eip-1", Name: "edge"}),
			"203.0.113.9  eip-1  -  -  edge"},
		{"rule", ruleLabel(sgRule{Protocol: "tcp", Port: "22/22", Source: "0.0.0.0/0", Policy: "accept", Priority: 1, ID: "sgr-1", Description: "ssh"}),
			"tcp  22/22  0.0.0.0/0  -  prio 1  sgr-1  ssh"},
		{"rule that drops", ruleLabel(sgRule{Protocol: "tcp", Port: "22/22", Source: "0.0.0.0/0", Policy: "drop", Priority: 1, ID: "sgr-1"}),
			"tcp  22/22  0.0.0.0/0  drop  prio 1  sgr-1"},
		{"certificate", casCertLabel(casCertificate{Name: "site", ID: "1234567", CommonName: "example.com", Sans: "example.com,www.example.com", EndDate: "2027-01-01"}, now, "(current)"),
			"site  1234567  example.com,www.example.com  expires 2027-01-01  (current)"},
		{"certificate without a name", casCertLabel(casCertificate{ID: "1234567", CommonName: "example.com", EndDate: "2027-01-01"}, now, ""),
			"-  1234567  example.com  expires 2027-01-01"},
	} {
		if c.got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, c.got, c.want)
		}
	}
}
