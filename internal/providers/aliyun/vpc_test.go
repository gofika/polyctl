package aliyun

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/gofika/polyctl/internal/platform"
)

func TestAllocateCIDR(t *testing.T) {
	cases := []struct {
		name     string
		existing []string
		base     string
		mask, n  int
		want     []string
		err      error
	}{
		{"empty VPC", nil, "172.16.0.0/12", 22, 2, []string{"172.16.0.0/22", "172.16.4.0/22"}, nil},
		{"first block taken", []string{"172.16.0.0/22"}, "172.16.0.0/12", 22, 1, []string{"172.16.4.0/22"}, nil},
		{"gap is reused", []string{"172.16.0.0/22", "172.16.8.0/22"}, "172.16.0.0/12", 22, 2, []string{"172.16.4.0/22", "172.16.12.0/22"}, nil},
		{"smaller existing block overlaps", []string{"172.16.5.0/24"}, "172.16.0.0/12", 22, 1, []string{"172.16.0.0/22"}, nil},
		{"existing block in the middle", []string{"172.16.1.0/24"}, "172.16.0.0/12", 22, 1, []string{"172.16.4.0/22"}, nil},
		{"larger existing block", []string{"172.16.0.0/16"}, "172.16.0.0/12", 22, 1, []string{"172.17.0.0/22"}, nil},
		{"unaligned base is masked", nil, "192.168.1.7/24", 26, 1, []string{"192.168.1.0/26"}, nil},
		{"no room", []string{"192.168.0.0/25"}, "192.168.0.0/24", 25, 2, nil, errNoCIDRSpace},
		{"mask wider than base", nil, "192.168.0.0/24", 22, 1, nil, platform.ErrInvalidInput},
		{"not IPv4", nil, "fd00::/48", 64, 1, nil, platform.ErrInvalidInput},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := allocateCIDR(c.existing, c.base, c.mask, c.n)
			if c.err != nil {
				if !errors.Is(err, c.err) {
					t.Fatalf("err = %v, want %v", err, c.err)
				}
				return
			}
			if err != nil || !slices.Equal(got, c.want) {
				t.Fatalf("got %v, %v; want %v", got, err, c.want)
			}
		})
	}
}

// The two real shapes of an EIP (an idle one, one a load balancer holds)
// and the other states that must never be reused.
func TestPickIdleEIP(t *testing.T) {
	eips := []eipAddress{
		{AllocationID: "eip-1", Status: "InUse", InstanceID: "eni-1", InstanceType: "NetworkInterface", ServiceManaged: true, ISP: "BGP_PRO"},
		{AllocationID: "eip-2", Status: "Available", ServiceManaged: true, ISP: "BGP_PRO"}, // just released by a load balancer
		{AllocationID: "eip-3", Status: "Unassociating", ISP: "BGP_PRO"},
		{AllocationID: "eip-4", Status: "Available", ISP: "BGP"},
		{AllocationID: "eip-5", Status: "Available", ISP: "BGP_PRO"},
		{AllocationID: "eip-6", Status: "Available", ISP: "BGP_PRO"},
	}
	if e := pickIdleEIP(eips, "BGP_PRO", nil); e == nil || e.AllocationID != "eip-5" {
		t.Errorf("pick = %+v, want eip-5", e)
	}
	if e := pickIdleEIP(eips, "BGP_PRO", map[string]bool{"eip-5": true}); e == nil || e.AllocationID != "eip-6" {
		t.Errorf("pick with exclude = %+v, want eip-6", e)
	}
	if e := pickIdleEIP(eips, "BGP_PRO", map[string]bool{"eip-5": true, "eip-6": true}); e != nil {
		t.Errorf("pick = %+v, want none", e)
	}
	if e := pickIdleEIP(eips, "BGP", nil); e == nil || e.AllocationID != "eip-4" {
		t.Errorf("pick BGP = %+v, want eip-4", e)
	}
}

func TestVPCAndVSwitchListsUsePagesOf50(t *testing.T) {
	api := newFakeAPI(t)
	f := newFakeNet(t, api)
	for i := 0; i < 120; i++ {
		f.addVPCFull(fmt.Sprintf("vpc-%03d", i), fmt.Sprintf("v%03d", i), "10.0.0.0/8", i == 0)
		f.addVSwitch(fmt.Sprintf("vsw-%03d", i), "s", "vpc-001", "cn-shanghai-b", fmt.Sprintf("10.%d.0.0/16", i))
	}
	c := api.client()
	vpcs, err := c.listVPCs(context.Background(), "cn-shanghai", false)
	if err != nil || len(vpcs) != 119 {
		t.Fatalf("listVPCs = %d, %v; want the 119 VPCs that are not the default", len(vpcs), err)
	}
	if all, _ := c.listVPCs(context.Background(), "cn-shanghai", true); len(all) != 120 {
		t.Errorf("listVPCs all = %d", len(all))
	}
	for _, q := range api.callsFor("DescribeVpcs") {
		if q.Get("PageSize") != "50" {
			t.Errorf("DescribeVpcs PageSize = %s", q.Get("PageSize"))
		}
	}
	if q := api.callsFor("DescribeVpcs")[0]; q.Get("IsDefault") != "false" {
		t.Errorf("list without --all did not send IsDefault=false: %v", q)
	}
	vsw, err := c.listVSwitches(context.Background(), "cn-shanghai", "vpc-001", "", "")
	if err != nil || len(vsw) != 120 {
		t.Fatalf("listVSwitches = %d, %v", len(vsw), err)
	}
	for _, q := range api.callsFor("DescribeVSwitches") {
		if q.Get("PageSize") != "50" || q.Get("VpcId") != "vpc-001" {
			t.Errorf("DescribeVSwitches = %v", q)
		}
	}
}

// 100 EIPs fill one page of 100: no second page is asked for.
func TestEIPListStopsAtTotalCount(t *testing.T) {
	api := newFakeAPI(t)
	f := newFakeNet(t, api)
	for i := 0; i < 100; i++ {
		f.addEIP(fmt.Sprintf("eip-%03d", i), fmt.Sprintf("203.0.113.%d", i), "Available", "", "", 0, "BGP_PRO")
	}
	eips, err := api.client().listEIPs(context.Background(), "cn-shanghai", eipFilter{})
	if err != nil || len(eips) != 100 {
		t.Fatalf("listEIPs = %d, %v", len(eips), err)
	}
	calls := api.callsFor("DescribeEipAddresses")
	if len(calls) != 1 || calls[0].Get("PageSize") != "100" {
		t.Errorf("calls = %v, want one page of 100", calls)
	}
	// An unknown allocation id is an empty answer, not an error.
	if e, err := api.client().getEIP(context.Background(), "cn-shanghai", "eip-missing"); e != nil || err != nil {
		t.Errorf("getEIP missing = %+v, %v", e, err)
	}
	if e, err := api.client().getEIP(context.Background(), "cn-shanghai", "203.0.113.7"); err != nil || e == nil || e.AllocationID != "eip-007" {
		t.Errorf("getEIP by address = %+v, %v", e, err)
	}
	if q := api.callsFor("DescribeEipAddresses"); q[len(q)-1].Get("EipAddress") != "203.0.113.7" {
		t.Errorf("lookup by address did not filter by EipAddress: %v", q[len(q)-1])
	}
}

// The real answers of an EIP list: the misspelled duplicate Descritpion is
// a fallback, ServiceManaged is 0/1.
func TestEIPFromSDKShapes(t *testing.T) {
	api := newFakeAPI(t)
	f := newFakeNet(t, api)
	nlb := f.addEIP("eip-nlb", "203.0.113.20", "InUse", "eni-0123", "NetworkInterface", 1, "BGP_PRO")
	nlb["Name"], nlb["Description"] = "CREATE_BY_NLB.nlb-0123", "CREATE_BY_NLB.nlb-0123"
	f.addEIP("eip-idle", "203.0.113.10", "Available", "", "", 0, "BGP_PRO")["Descritpion"] = "spare"
	eips, err := api.client().listEIPs(context.Background(), "cn-shanghai", eipFilter{})
	if err != nil || len(eips) != 2 {
		t.Fatal(eips, err)
	}
	idle, nlbEIP := eips[0], eips[1]
	if idle.AllocationID != "eip-idle" || idle.Description != "spare" || idle.ServiceManaged || !idle.idle("BGP_PRO") || idle.boundTo() != "-" {
		t.Errorf("idle = %+v", idle)
	}
	if !nlbEIP.ServiceManaged || nlbEIP.idle("BGP_PRO") || nlbEIP.boundTo() != "eni-0123 (NetworkInterface)" || nlbEIP.Bandwidth != "200" {
		t.Errorf("nlb = %+v", nlbEIP)
	}
}

func TestAllocateEIPRequest(t *testing.T) {
	api := newFakeAPI(t)
	newFakeNet(t, api)
	id, ip, err := api.client().allocateEIP(context.Background(), "cn-shanghai", eipSpec{Bandwidth: "200", ISP: "BGP_PRO", ResourceGroup: "rg-default0001"})
	if err != nil || id == "" || ip == "" {
		t.Fatal(id, ip, err)
	}
	q := api.callsFor("AllocateEipAddress")[0]
	for k, want := range map[string]string{"Bandwidth": "200", "ISP": "BGP_PRO", "InternetChargeType": "PayByTraffic", "InstanceChargeType": "PostPaid",
		"Netmode": "public", "AutoPay": "true", "ResourceGroupId": "rg-default0001"} {
		if q.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
	if q.Get("Zone") != "" || q.Get("ClientToken") == "" {
		t.Errorf("Zone %q (refused by the API), ClientToken %q", q.Get("Zone"), q.Get("ClientToken"))
	}
}
