package aliyun

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"testing"
)

// newFakeNet is the fake ECS plus the VPC service: VPCs that stay Pending
// for a few reads after they were created, vSwitches, EIPs and resource
// groups, answering as verified on real accounts (page sizes of 50 and
// 100, exact name filters that the fake applies like the real API does,
// overlapping CIDR blocks refused).
func newFakeNet(t *testing.T, api *fakeAPI) *fakeECS {
	f := newFakeECS(t, api)
	f.pending = map[string]int{}
	f.unlisted = map[string]int{}
	f.vpcPending = 2
	f.zones = []string{"cn-shanghai-b", "cn-shanghai-c", "cn-shanghai-d"}
	f.resourceGroups = []map[string]any{{"Id": "rg-default0001", "Name": "default", "DisplayName": "default resource group", "Status": "OK"}}
	api.on("DescribeVpcs", f.netDescribeVpcs)
	api.on("CreateVpc", f.write(f.createVpc))
	api.on("DescribeVSwitches", f.describeVSwitches)
	api.on("DescribeVSwitchAttributes", f.describeVSwitchAttributes)
	api.on("CreateVSwitch", f.write(f.createVSwitch))
	api.on("DescribeEipAddresses", f.describeEips)
	api.on("AllocateEipAddress", f.write(f.allocateEip))
	api.on("AssociateEipAddress", f.write(f.associateEip))
	api.on("ListResourceGroups", f.listResourceGroups)
	return f
}

func (f *fakeECS) addVPCFull(id, name, cidr string, isDefault bool) {
	f.vpcs = append(f.vpcs, map[string]any{"VpcId": id, "VpcName": name, "CidrBlock": cidr, "Status": "Available", "IsDefault": isDefault})
}

func (f *fakeECS) addVSwitch(id, name, vpc, zone, cidr string) {
	f.vswitches = append(f.vswitches, map[string]any{"VSwitchId": id, "VSwitchName": name, "VpcId": vpc, "ZoneId": zone, "CidrBlock": cidr,
		"Status": "Available", "AvailableIpAddressCount": 1020})
}

// addEIP stores an EIP; instance "" is an idle one.
func (f *fakeECS) addEIP(id, ip, status, instance, instanceType string, serviceManaged int, isp string) map[string]any {
	e := map[string]any{"AllocationId": id, "IpAddress": ip, "Status": status, "InstanceId": instance, "InstanceType": instanceType,
		"Name": "", "Description": "", "ServiceManaged": serviceManaged, "Bandwidth": "200", "ISP": isp,
		"InternetChargeType": "PayByTraffic", "ChargeType": "PostPaid", "Netmode": "public", "RegionId": "cn-shanghai"}
	f.eips = append(f.eips, e)
	return e
}

// hidden reports whether a new resource is still missing from listings
// (counting one read).
func (f *fakeECS) hidden(id string) bool {
	if f.unlisted[id] > 0 {
		f.unlisted[id]--
		return true
	}
	return false
}

// settle answers the status of a resource that may still be transitional.
func (f *fakeECS) settle(id string, m map[string]any, transitional, final string) {
	if f.pending[id] > 0 {
		f.pending[id]--
		m["Status"] = transitional
		return
	}
	if m["Status"] == transitional {
		m["Status"] = final
	}
}

func (f *fakeECS) netDescribeVpcs(q url.Values) (int, any) {
	if s, _ := strconv.Atoi(q.Get("PageSize")); s > 50 {
		return 400, apiErr("InvalidParameter", "The specified parameter PageSize is not valid.")
	}
	var out []map[string]any
	for _, v := range f.vpcs {
		if id := q.Get("VpcId"); id != "" && v["VpcId"] != id {
			continue
		}
		if n := q.Get("VpcName"); n != "" && v["VpcName"] != n {
			continue
		}
		if q.Get("IsDefault") == "false" && v["IsDefault"] == true {
			continue
		}
		if f.hidden(v["VpcId"].(string)) {
			continue
		}
		f.settle(v["VpcId"].(string), v, "Pending", "Available")
		out = append(out, v)
	}
	s, e := page(q, len(out))
	return 200, map[string]any{"TotalCount": len(out), "Vpcs": map[string]any{"Vpc": out[s:e]}}
}

func (f *fakeECS) createVpc(q url.Values) (int, any) {
	if q.Get("ClientToken") == "" {
		f.t.Errorf("CreateVpc without ClientToken")
	}
	id := f.id("vpc-new")
	f.vpcs = append(f.vpcs, map[string]any{"VpcId": id, "VpcName": q.Get("VpcName"), "CidrBlock": q.Get("CidrBlock"), "Status": "Pending", "IsDefault": false})
	f.pending[id] = f.vpcPending
	f.unlisted[id] = f.newUnlisted
	return 200, map[string]any{"VpcId": id, "VRouterId": "vrt-1", "RouteTableId": "vtb-1", "ResourceGroupId": "rg-default0001", "RequestId": "r"}
}

func (f *fakeECS) vpc(id string) map[string]any {
	for _, v := range f.vpcs {
		if v["VpcId"] == id {
			return v
		}
	}
	return nil
}

func (f *fakeECS) describeVSwitches(q url.Values) (int, any) {
	if s, _ := strconv.Atoi(q.Get("PageSize")); s > 50 {
		return 400, apiErr("InvalidParameter", "The specified parameter PageSize is not valid.")
	}
	var out []map[string]any
	for _, v := range f.vswitches {
		if x := q.Get("VpcId"); x != "" && v["VpcId"] != x {
			continue
		}
		if x := q.Get("VSwitchName"); x != "" && v["VSwitchName"] != x {
			continue
		}
		if x := q.Get("VSwitchId"); x != "" && v["VSwitchId"] != x {
			continue
		}
		if x := q.Get("ZoneId"); x != "" && v["ZoneId"] != x {
			continue
		}
		out = append(out, v)
	}
	s, e := page(q, len(out))
	return 200, map[string]any{"TotalCount": len(out), "VSwitches": map[string]any{"VSwitch": out[s:e]}}
}

func (f *fakeECS) describeVSwitchAttributes(q url.Values) (int, any) {
	for _, v := range f.vswitches {
		if v["VSwitchId"] == q.Get("VSwitchId") {
			f.settle(v["VSwitchId"].(string), v, "Pending", "Available")
			return 200, v
		}
	}
	return 404, apiErr("IncorrectVSwitchId", "The specified vswitch does not exist.")
}

func (f *fakeECS) createVSwitch(q url.Values) (int, any) {
	if q.Get("ClientToken") == "" {
		f.t.Errorf("CreateVSwitch without ClientToken")
	}
	v := f.vpc(q.Get("VpcId"))
	if v == nil {
		return 404, apiErr("InvalidVpcId.NotFound", "The specified VPC does not exist.")
	}
	if f.pending[q.Get("VpcId")] > 0 || v["Status"] == "Pending" {
		return 400, apiErr("IncorrectVpcStatus", "The current status of the VPC does not support this operation.")
	}
	if !contains(f.zones, q.Get("ZoneId")) {
		return 400, apiErr("ResourceNotAvailable", "Resource you requested is not available in this region or zone.")
	}
	cidr, err := netip.ParsePrefix(q.Get("CidrBlock"))
	if err != nil || cidr.Masked() != cidr {
		return 400, apiErr("IllegalParam.CidrBlock", "The specified CidrBlock is invalid.")
	}
	base := netip.MustParsePrefix(v["CidrBlock"].(string))
	if !base.Contains(cidr.Addr()) || cidr.Bits() < base.Bits() {
		return 400, apiErr("InvalidParameter", "Specified CIDR block is not valid in VPC")
	}
	for _, s := range f.vswitches {
		if s["VpcId"] == q.Get("VpcId") && netip.MustParsePrefix(s["CidrBlock"].(string)).Overlaps(cidr) {
			return 400, apiErr("InvalidCidrBlock.Overlapped", "Specified CIDR block overlapped with other subnet.")
		}
	}
	id := f.id("vsw-new")
	f.vswitches = append(f.vswitches, map[string]any{"VSwitchId": id, "VSwitchName": q.Get("VSwitchName"), "VpcId": q.Get("VpcId"),
		"ZoneId": q.Get("ZoneId"), "CidrBlock": cidr.String(), "Status": "Pending", "AvailableIpAddressCount": 1020})
	f.pending[id] = 1
	return 200, map[string]any{"VSwitchId": id, "RequestId": "r"}
}

func (f *fakeECS) eip(id string) map[string]any {
	for _, e := range f.eips {
		if e["AllocationId"] == id {
			return e
		}
	}
	return nil
}

func (f *fakeECS) describeEips(q url.Values) (int, any) {
	if s, _ := strconv.Atoi(q.Get("PageSize")); s > 100 {
		return 400, apiErr("InvalidParameter", "The specified parameter PageSize is not valid.")
	}
	var out []map[string]any
	for _, e := range f.eips {
		if x := q.Get("AllocationId"); x != "" && e["AllocationId"] != x {
			continue
		}
		if x := q.Get("EipAddress"); x != "" && e["IpAddress"] != x {
			continue
		}
		if f.hidden(e["AllocationId"].(string)) {
			continue
		}
		f.settle(e["AllocationId"].(string), e, "Associating", "InUse")
		out = append(out, e)
	}
	s, e := page(q, len(out))
	return 200, map[string]any{"TotalCount": len(out), "PageNumber": q.Get("PageNumber"), "EipAddresses": map[string]any{"EipAddress": out[s:e]}}
}

func (f *fakeECS) allocateEip(q url.Values) (int, any) {
	if f.allocateErr != nil {
		return 400, f.allocateErr
	}
	if q.Get("ResourceGroupId") != "" && q.Get("ResourceGroupId") != "rg-default0001" {
		return 400, apiErr("InvalidResourceGroupId", "The specified resource group id is invalid.")
	}
	id := f.id("eip-new")
	ip := fmt.Sprintf("203.0.113.%d", 100+f.nextID)
	f.addEIP(id, ip, "Available", "", "", 0, q.Get("ISP"))["Bandwidth"] = q.Get("Bandwidth")
	f.unlisted[id] = f.newUnlisted
	return 200, map[string]any{"AllocationId": id, "EipAddress": ip, "ResourceGroupId": "rg-default0001", "RequestId": "r"}
}

func (f *fakeECS) associateEip(q url.Values) (int, any) {
	e := f.eip(q.Get("AllocationId"))
	if e == nil {
		return 404, apiErr("InvalidAllocationId.NotFound", "The specified allocation id does not exist.")
	}
	if e["Status"] != "Available" {
		return 400, apiErr("IncorrectEipStatus", "The current status of the EIP does not support this operation.")
	}
	for _, in := range f.instances {
		if in["InstanceId"] == q.Get("InstanceId") {
			e["Status"], e["InstanceId"], e["InstanceType"] = "Associating", in["InstanceId"], "EcsInstance"
			f.pending[e["AllocationId"].(string)] = 1
			in["EipAddress"] = map[string]any{"IpAddress": e["IpAddress"], "AllocationId": e["AllocationId"]}
			return 200, map[string]any{"RequestId": "r"}
		}
	}
	return 404, apiErr("InvalidInstanceId.NotFound", "The specified instance does not exist.")
}

func (f *fakeECS) listResourceGroups(q url.Values) (int, any) {
	var out []map[string]any
	for _, g := range f.resourceGroups {
		if n := q.Get("Name"); n != "" && g["Name"] != n {
			continue
		}
		out = append(out, g)
	}
	return 200, map[string]any{"TotalCount": len(out), "ResourceGroups": map[string]any{"ResourceGroup": out}}
}
