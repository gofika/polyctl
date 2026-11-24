package aliyun

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/app"
)

// newFakeCompute is the fake network plus the ECS instance lifecycle,
// answering as verified on real accounts: a name filter that matches whole
// names without regard to case, a status list that is empty for an unknown
// id, Running instances that cannot be deleted without Force nor resized,
// a reboot of a Stopped instance refused, and an idempotent ClientToken.
// seq queues the statuses DescribeInstanceStatus answers next for an
// instance (each read takes one; the last one stays).
func newFakeCompute(t *testing.T, api *fakeAPI) *fakeECS {
	f := newFakeNet(t, api)
	f.seq = map[string][]string{}
	f.tokens = map[string]string{}
	f.initializing = map[string]int{}
	f.disks = map[string]int{}
	api.on("DescribeInstances", f.computeDescribeInstances)
	api.on("DescribeInstanceStatus", f.describeInstanceStatus)
	api.on("RunInstances", f.write(f.runInstances))
	api.on("DeleteInstance", f.write(f.deleteInstance))
	api.on("StopInstance", f.write(f.stopInstance))
	api.on("StartInstance", f.write(f.startInstance))
	api.on("RebootInstance", f.write(f.rebootInstance))
	api.on("ModifyInstanceSpec", f.write(f.modifySpec))
	api.on("DescribeDisks", f.describeDisks)
	api.on("DescribeInstanceTypes", f.describeInstanceTypes)
	api.on("AssociateEipAddress", f.write(f.associateEipFlaky))
	return f
}

// addVM stores an instance with the full shape of a VPC instance.
func (f *fakeECS) addVM(id, name, status, typ, vpc, vsw string) map[string]any {
	in := map[string]any{"InstanceId": id, "InstanceName": name, "Status": status, "RegionId": "cn-shanghai", "ZoneId": "cn-shanghai-b",
		"InstanceType": typ, "HostName": name, "KeyPairName": "ops", "CreationTime": "2026-11-17T16:10Z",
		"VpcAttributes":     map[string]any{"VpcId": vpc, "VSwitchId": vsw, "PrivateIpAddress": map[string]any{"IpAddress": []string{"172.16.0.10"}}},
		"InnerIpAddress":    map[string]any{"IpAddress": []string{}},
		"PublicIpAddress":   map[string]any{"IpAddress": []string{}},
		"NetworkInterfaces": map[string]any{"NetworkInterface": []map[string]any{{"Type": "Primary", "PrimaryIpAddress": "172.16.0.10", "NetworkInterfaceId": "eni-1"}}},
		"EipAddress":        map[string]any{"AllocationId": "", "InternetChargeType": "", "IpAddress": ""},
		"SecurityGroupIds":  map[string]any{"SecurityGroupId": []string{"sg-1"}},
	}
	f.instances = append(f.instances, in)
	return in
}

func (f *fakeECS) vm(id string) map[string]any {
	for _, in := range f.instances {
		if in["InstanceId"] == id {
			return in
		}
	}
	return nil
}

func (f *fakeECS) computeDescribeInstances(q url.Values) (int, any) {
	if s, _ := strconv.Atoi(q.Get("PageSize")); s > 100 {
		return 400, apiErr("InvalidParameter", "PageSize")
	}
	var ids []string
	if v := q.Get("InstanceIds"); v != "" {
		if err := json.Unmarshal([]byte(v), &ids); err != nil {
			return 400, apiErr("InvalidParameter", "InstanceIds")
		}
	}
	var out []map[string]any
	for _, in := range f.instances {
		if len(ids) > 0 && !contains(ids, in["InstanceId"].(string)) {
			continue
		}
		if n := q.Get("InstanceName"); n != "" && !strings.EqualFold(n, in["InstanceName"].(string)) {
			continue
		}
		out = append(out, in)
	}
	s, e := page(q, len(out))
	return 200, map[string]any{"TotalCount": len(out), "Instances": map[string]any{"Instance": out[s:e]}}
}

func (f *fakeECS) describeInstanceStatus(q url.Values) (int, any) {
	id := q.Get("InstanceId.1")
	in := f.vm(id)
	if in == nil {
		return 200, map[string]any{"TotalCount": 0, "InstanceStatuses": map[string]any{"InstanceStatus": []any{}}}
	}
	if s := f.seq[id]; len(s) > 0 {
		in["Status"] = s[0]
		if len(s) > 1 {
			f.seq[id] = s[1:]
		}
	}
	if in["Status"] == statusNotFound {
		return 200, map[string]any{"TotalCount": 0, "InstanceStatuses": map[string]any{"InstanceStatus": []any{}}}
	}
	return 200, map[string]any{"TotalCount": 1, "InstanceStatuses": map[string]any{"InstanceStatus": []any{
		map[string]any{"InstanceId": id, "Status": in["Status"]}}}}
}

func (f *fakeECS) runInstances(q url.Values) (int, any) {
	if f.runGhost > 0 {
		f.runGhost--
		return 200, map[string]any{"InstanceIdSets": map[string]any{"InstanceIdSet": []string{"i-ghost"}}, "RequestId": "r"}
	}
	code, body := f.runInstancesAnswer(q)
	if code == 200 && f.runLost > 0 {
		f.runLost--
		return 503, apiErr("ServiceUnavailable", "The request has failed due to a temporary failure of the server.")
	}
	return code, body
}

func (f *fakeECS) runInstancesAnswer(q url.Values) (int, any) {
	token := q.Get("ClientToken")
	if id, ok := f.tokens[token]; ok && token != "" {
		return 200, map[string]any{"InstanceIdSets": map[string]any{"InstanceIdSet": []string{id}}, "RequestId": "r"}
	}
	if q.Get("KeyPairName") != "" {
		found := false
		for _, kp := range f.keyPairs {
			found = found || kp["KeyPairName"] == q.Get("KeyPairName")
		}
		if !found {
			return 404, apiErr("InvalidKeyPairName.NotFound", "The specified KeyPairName does not exist.")
		}
	}
	g := f.group(q.Get("SecurityGroupId"))
	if g == nil {
		return 404, apiErr("InvalidSecurityGroupId.NotFound", "The specified security group does not exist.")
	}
	var vsw map[string]any
	for _, v := range f.vswitches {
		if v["VSwitchId"] == q.Get("VSwitchId") {
			vsw = v
		}
	}
	if vsw == nil {
		return 404, apiErr("InvalidVSwitchId.NotExist", "The specified vSwitch does not exist.")
	}
	if vsw["VpcId"] != g.VPC {
		return 400, apiErr("InvalidParameter.Mismatch", "Specified security group and vswitch are not in the same VPC.")
	}
	if strings.Contains(q.Get("HostName"), "_") {
		return 400, apiErr("InvalidHostName.Malformed", "The specified parameter HostName is not valid.")
	}
	id := f.id("i-new")
	in := f.addVM(id, q.Get("InstanceName"), instPending, q.Get("InstanceType"), g.VPC, vsw["VSwitchId"].(string))
	in["HostName"], in["KeyPairName"], in["ZoneId"] = q.Get("HostName"), q.Get("KeyPairName"), vsw["ZoneId"]
	in["SecurityGroupIds"] = map[string]any{"SecurityGroupId": []string{g.ID}}
	f.seq[id] = []string{instPending, instStopped, instStarting, instRunning}
	f.disks[id], _ = strconv.Atoi(q.Get("SystemDisk.Size"))
	if token != "" {
		f.tokens[token] = id
	}
	return 200, map[string]any{"InstanceIdSets": map[string]any{"InstanceIdSet": []string{id}}, "RequestId": "r"}
}

func (f *fakeECS) deleteInstance(q url.Values) (int, any) {
	id := q.Get("InstanceId")
	in := f.vm(id)
	if in == nil {
		return 404, apiErr("InvalidInstanceId.NotFound", "The specified InstanceId does not exist.")
	}
	if in["DeletionProtection"] == true {
		return 403, apiErr("InvalidOperation.DeletionProtection", "The instance is protected from deletion.")
	}
	if f.initializing[id] > 0 {
		f.initializing[id]--
		return 403, apiErr("IncorrectInstanceStatus.Initializing", "The specified instance status does not support this operation.")
	}
	if in["Status"] != instStopped && q.Get("Force") != "true" {
		return 403, apiErr("IncorrectInstanceStatus", "The current status of the resource does not support this operation.")
	}
	var keep []map[string]any
	for _, x := range f.instances {
		if x["InstanceId"] != id {
			keep = append(keep, x)
		}
	}
	f.instances = keep
	for _, e := range f.eips {
		if e["InstanceId"] == id {
			e["InstanceId"], e["InstanceType"], e["Status"] = "", "", "Available"
		}
	}
	return 200, map[string]any{"RequestId": "r"}
}

func (f *fakeECS) stopInstance(q url.Values) (int, any) {
	id := q.Get("InstanceId")
	in := f.vm(id)
	if in == nil {
		return 404, apiErr("InvalidInstanceId.NotFound", "no instance")
	}
	if in["Status"] == instRunning {
		f.seq[id] = []string{instStopping, instStopped}
	}
	return 200, map[string]any{"RequestId": "r"}
}

func (f *fakeECS) startInstance(q url.Values) (int, any) {
	id := q.Get("InstanceId")
	in := f.vm(id)
	if in == nil {
		return 404, apiErr("InvalidInstanceId.NotFound", "no instance")
	}
	if in["Status"] == instStopped {
		f.seq[id] = []string{instStarting, instRunning}
	}
	return 200, map[string]any{"RequestId": "r"}
}

func (f *fakeECS) rebootInstance(q url.Values) (int, any) {
	id := q.Get("InstanceId")
	in := f.vm(id)
	if in == nil {
		return 404, apiErr("InvalidInstanceId.NotFound", "no instance")
	}
	if in["Status"] != instRunning {
		return 403, apiErr("IncorrectInstanceStatus", "Status of the specified instance is "+in["Status"].(string)+" but the expected status is in (Running;Paused)")
	}
	// The first read may still say Running.
	f.seq[id] = []string{instRunning, instStopping, instStarting, instRunning}
	return 200, map[string]any{"RequestId": "r"}
}

func (f *fakeECS) modifySpec(q url.Values) (int, any) {
	in := f.vm(q.Get("InstanceId"))
	if in == nil {
		return 404, apiErr("InvalidInstanceId.NotFound", "no instance")
	}
	if in["Status"] != instStopped {
		return 400, apiErr("InvalidInstanceStatus.NotStopped", "The specified Instance status is not stopped.")
	}
	in["InstanceType"] = q.Get("InstanceType")
	return 200, map[string]any{"RequestId": "r"}
}

func (f *fakeECS) describeDisks(q url.Values) (int, any) {
	size, ok := f.disks[q.Get("InstanceId")]
	if !ok {
		size = 20
	}
	return 200, map[string]any{"TotalCount": 1, "Disks": map[string]any{"Disk": []map[string]any{{"DiskId": "d-1", "Type": "system", "Size": size, "Category": "cloud_essd_entry"}}}}
}

// associateEipFlaky refuses the first associateFails bindings as ECS may
// while an EIP or an instance is not ready.
func (f *fakeECS) associateEipFlaky(q url.Values) (int, any) {
	if f.associateFails > 0 {
		f.associateFails--
		return 400, apiErr("IncorrectInstanceStatus", "The current status of the instance does not support this operation.")
	}
	return f.associateEip(q)
}

// computeHarness is a harness on the fake compute API with an instant
// clock.
func computeHarness(t *testing.T, flags app.Flags) (*harness, *fakeECS, *fakeSleepClock) {
	h := newHarness(t, flags)
	f := newFakeCompute(t, h.api)
	clock := &fakeSleepClock{now: time.Unix(1_700_000_000, 0)}
	netWaitClock = clock
	t.Cleanup(func() { netWaitClock = nil })
	return h, f, clock
}

// describeInstanceTypes answers the architecture of the types in
// typeArch (DescribeInstanceTypes values: X86, ARM); other types are not
// listed.
func (f *fakeECS) describeInstanceTypes(q url.Values) (int, any) {
	var out []map[string]any
	for i := 1; q.Get(fmt.Sprintf("InstanceTypes.%d", i)) != ""; i++ {
		n := q.Get(fmt.Sprintf("InstanceTypes.%d", i))
		if a, ok := f.typeArch[n]; ok {
			out = append(out, map[string]any{"InstanceTypeId": n, "CpuArchitecture": a})
		}
	}
	return 200, map[string]any{"RequestId": "r", "InstanceTypes": map[string]any{"InstanceType": out}}
}
