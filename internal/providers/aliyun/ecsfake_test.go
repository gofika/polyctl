package aliyun

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// fakeECS keeps security groups, rules, VPCs, instances and key pairs in
// memory behind a fakeAPI, answering like ECS does (as verified on real
// accounts): exact name filters, rules read back with an upper-case
// protocol and a capitalized policy, a duplicate authorize that succeeds
// without adding a rule, sources kept as written.
type fakeECS struct {
	t   *testing.T
	api *fakeAPI

	groups    []fakeGroup
	rules     map[string][]map[string]any
	vpcs      []map[string]any
	instances []map[string]any
	keyPairs  []map[string]any
	images    []map[string]any

	// rulePage is the page size of DescribeSecurityGroupAttribute (0: the
	// request's MaxResults).
	rulePage int
	// authorizeNotFound makes the next n AuthorizeSecurityGroup calls answer
	// that the group does not exist yet.
	authorizeNotFound int
	nextID            int
	writes            []string
}

type fakeGroup struct {
	ID, Name, VPC, Desc string
}

func newFakeECS(t *testing.T, api *fakeAPI) *fakeECS {
	f := &fakeECS{t: t, api: api, rules: map[string][]map[string]any{}}
	api.on("DescribeSecurityGroups", f.describeGroups)
	api.on("DescribeSecurityGroupAttribute", f.describeAttribute)
	api.on("CreateSecurityGroup", f.write(f.createGroup))
	api.on("AuthorizeSecurityGroup", f.write(f.authorize))
	api.on("RevokeSecurityGroup", f.write(f.revoke))
	api.on("DeleteSecurityGroup", f.write(f.deleteGroup))
	api.on("JoinSecurityGroup", f.write(f.join))
	api.on("DescribeVpcs", f.describeVpcs)
	api.on("DescribeInstances", f.describeInstances)
	api.on("DescribeKeyPairs", f.describeKeyPairs)
	api.on("ImportKeyPair", f.write(f.importKeyPair))
	api.on("DescribeImages", f.describeImages)
	return f
}

func (f *fakeECS) write(h func(q url.Values) (int, any)) func(q url.Values) (int, any) {
	return func(q url.Values) (int, any) {
		f.writes = append(f.writes, q.Get("Action"))
		return h(q)
	}
}

func (f *fakeECS) id(prefix string) string {
	f.nextID++
	return fmt.Sprintf("%s%04d", prefix, f.nextID)
}

func (f *fakeECS) addVPC(id, name string) {
	f.vpcs = append(f.vpcs, map[string]any{"VpcId": id, "VpcName": name, "CidrBlock": "172.16.0.0/12", "Status": "Available"})
}

func (f *fakeECS) addGroup(id, name, vpc string) {
	f.groups = append(f.groups, fakeGroup{ID: id, Name: name, VPC: vpc})
}

// addRule stores a rule as ECS reads it back.
func (f *fakeECS) addRule(sg, proto, ports, source, policy string) string {
	id := f.id("sgr-")
	p := map[string]any{"SecurityGroupRuleId": id, "Direction": "ingress", "IpProtocol": strings.ToUpper(proto), "PortRange": ports,
		"Policy": policy, "Priority": "1", "NicType": "intranet"}
	switch {
	case strings.HasPrefix(source, "sg-"):
		p["SourceGroupId"] = source
	case strings.Contains(source, ":"):
		p["Ipv6SourceCidrIp"] = source
	default:
		p["SourceCidrIp"] = source
	}
	f.rules[sg] = append(f.rules[sg], p)
	return id
}

func (f *fakeECS) addInstance(id, name, vpc string, groups ...string) {
	f.instances = append(f.instances, map[string]any{"InstanceId": id, "InstanceName": name, "Status": "Running", "RegionId": "cn-shanghai",
		"ZoneId": "cn-shanghai-b", "VpcAttributes": map[string]any{"VpcId": vpc}, "SecurityGroupIds": map[string]any{"SecurityGroupId": groups}})
}

func (f *fakeECS) group(id string) *fakeGroup {
	for i := range f.groups {
		if f.groups[i].ID == id {
			return &f.groups[i]
		}
	}
	return nil
}

func page(q url.Values, n int) (start, end int) {
	size, _ := strconv.Atoi(q.Get("PageSize"))
	num, _ := strconv.Atoi(q.Get("PageNumber"))
	if size <= 0 {
		size = 10
	}
	if num <= 0 {
		num = 1
	}
	start = (num - 1) * size
	if start > n {
		start = n
	}
	end = start + size
	if end > n {
		end = n
	}
	return start, end
}

func (f *fakeECS) describeGroups(q url.Values) (int, any) {
	if s, _ := strconv.Atoi(q.Get("PageSize")); s > 100 {
		return 400, apiErr("InvalidParameter", "PageSize")
	}
	var ids []string
	if v := q.Get("SecurityGroupIds"); v != "" {
		_ = json.Unmarshal([]byte(v), &ids)
	}
	var out []map[string]any
	for _, g := range f.groups {
		if v := q.Get("VpcId"); v != "" && g.VPC != v {
			continue
		}
		if v := q.Get("SecurityGroupName"); v != "" && g.Name != v {
			continue
		}
		if len(ids) > 0 && !contains(ids, g.ID) {
			continue
		}
		out = append(out, map[string]any{"SecurityGroupId": g.ID, "SecurityGroupName": g.Name, "VpcId": g.VPC, "Description": g.Desc,
			"SecurityGroupType": "normal", "RuleCount": len(f.rules[g.ID])})
	}
	s, e := page(q, len(out))
	return 200, map[string]any{"TotalCount": len(out), "SecurityGroups": map[string]any{"SecurityGroup": out[s:e]}}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func (f *fakeECS) describeAttribute(q url.Values) (int, any) {
	g := f.group(q.Get("SecurityGroupId"))
	if g == nil {
		return 404, apiErr("InvalidSecurityGroupId.NotFound", "The specified security group does not exist.")
	}
	var perms []map[string]any
	for _, p := range f.rules[g.ID] {
		if d := q.Get("Direction"); d != "" && d != "all" && p["Direction"] != d {
			continue
		}
		perms = append(perms, p)
	}
	size := f.rulePage
	if size == 0 {
		size, _ = strconv.Atoi(q.Get("MaxResults"))
	}
	if size <= 0 {
		size = 500
	}
	start, _ := strconv.Atoi(q.Get("NextToken"))
	end := start + size
	next := ""
	if end < len(perms) {
		next = strconv.Itoa(end)
	} else {
		end = len(perms)
	}
	if start > len(perms) {
		start = len(perms)
	}
	return 200, map[string]any{"SecurityGroupId": g.ID, "SecurityGroupName": g.Name, "VpcId": g.VPC, "NextToken": next,
		"Permissions": map[string]any{"Permission": perms[start:end]}}
}

func (f *fakeECS) createGroup(q url.Values) (int, any) {
	if q.Get("VpcId") == "" {
		f.t.Errorf("CreateSecurityGroup without VpcId")
		return 400, apiErr("IncorrectVpcStatus", "no vpc")
	}
	id := f.id("sg-new")
	f.groups = append(f.groups, fakeGroup{ID: id, Name: q.Get("SecurityGroupName"), VPC: q.Get("VpcId"), Desc: q.Get("Description")})
	return 200, map[string]any{"SecurityGroupId": id, "RequestId": "r"}
}

// permissions reads the repeated Permissions.N.* parameters.
func permissions(q url.Values) []map[string]string {
	var out []map[string]string
	for n := 1; ; n++ {
		prefix := fmt.Sprintf("Permissions.%d.", n)
		p := map[string]string{}
		for k, v := range q {
			if strings.HasPrefix(k, prefix) {
				p[strings.TrimPrefix(k, prefix)] = v[0]
			}
		}
		if len(p) == 0 {
			return out
		}
		out = append(out, p)
	}
}

func (f *fakeECS) authorize(q url.Values) (int, any) {
	if f.authorizeNotFound > 0 {
		f.authorizeNotFound--
		return 404, apiErr("InvalidSecurityGroupId.NotFound", "The specified security group does not exist.")
	}
	g := f.group(q.Get("SecurityGroupId"))
	if g == nil {
		return 404, apiErr("InvalidSecurityGroupId.NotFound", "The specified security group does not exist.")
	}
	for _, p := range permissions(q) {
		policy := strings.ToUpper(p["Policy"][:1]) + strings.ToLower(p["Policy"][1:])
		src := p["SourceCidrIp"] + p["Ipv6SourceCidrIp"] + p["SourceGroupId"]
		dup := false
		for _, have := range f.rules[g.ID] {
			hs := fmt.Sprint(have["SourceCidrIp"], have["Ipv6SourceCidrIp"], have["SourceGroupId"])
			hs = strings.ReplaceAll(hs, "<nil>", "")
			if have["IpProtocol"] == strings.ToUpper(p["IpProtocol"]) && have["PortRange"] == p["PortRange"] && hs == src && have["Policy"] == policy {
				dup = true
			}
		}
		if dup {
			continue
		}
		id := f.addRule(g.ID, p["IpProtocol"], p["PortRange"], src, policy)
		last := f.rules[g.ID][len(f.rules[g.ID])-1]
		last["Priority"], last["Description"] = p["Priority"], p["Description"]
		_ = id
	}
	return 200, map[string]any{"RequestId": "r"}
}

func (f *fakeECS) revoke(q url.Values) (int, any) {
	sg := q.Get("SecurityGroupId")
	var ids []string
	for n := 1; ; n++ {
		v := q.Get(fmt.Sprintf("SecurityGroupRuleId.%d", n))
		if v == "" {
			break
		}
		ids = append(ids, v)
	}
	for _, id := range ids {
		found := false
		for _, p := range f.rules[sg] {
			found = found || p["SecurityGroupRuleId"] == id
		}
		if !found {
			return 400, apiErr("InvalidParam.SecurityGroupRuleId", "The specified rule id is invalid.")
		}
	}
	var keep []map[string]any
	for _, p := range f.rules[sg] {
		if !contains(ids, p["SecurityGroupRuleId"].(string)) {
			keep = append(keep, p)
		}
	}
	f.rules[sg] = keep
	return 200, map[string]any{"RequestId": "r"}
}

func (f *fakeECS) deleteGroup(q url.Values) (int, any) {
	id := q.Get("SecurityGroupId")
	for i, g := range f.groups {
		if g.ID == id {
			for _, in := range f.instances {
				if contains(in["SecurityGroupIds"].(map[string]any)["SecurityGroupId"].([]string), id) {
					return 403, apiErr("DependencyViolation", "There is still instance(s) in the specified security group.")
				}
			}
			f.groups = append(f.groups[:i], f.groups[i+1:]...)
			return 200, map[string]any{"RequestId": "r"}
		}
	}
	return 404, apiErr("InvalidSecurityGroup.NotFound", "The specified security group does not exist.")
}

func (f *fakeECS) join(q url.Values) (int, any) {
	for _, in := range f.instances {
		if in["InstanceId"] == q.Get("InstanceId") {
			g := f.group(q.Get("SecurityGroupId"))
			if g == nil {
				return 404, apiErr("InvalidSecurityGroupId.NotFound", "no group")
			}
			if g.VPC != in["VpcAttributes"].(map[string]any)["VpcId"] {
				return 400, apiErr("InvalidInstanceId.Mismatch", "Specified instance and security group are not in the same VPC.")
			}
			sgs := in["SecurityGroupIds"].(map[string]any)
			list := sgs["SecurityGroupId"].([]string)
			if !contains(list, g.ID) {
				sgs["SecurityGroupId"] = append(list, g.ID)
			}
			return 200, map[string]any{"RequestId": "r"}
		}
	}
	return 404, apiErr("InvalidInstanceId.NotFound", "no instance")
}

func (f *fakeECS) describeVpcs(q url.Values) (int, any) {
	var out []map[string]any
	for _, v := range f.vpcs {
		if id := q.Get("VpcId"); id != "" && v["VpcId"] != id {
			continue
		}
		if n := q.Get("VpcName"); n != "" && v["VpcName"] != n {
			continue
		}
		out = append(out, v)
	}
	s, e := page(q, len(out))
	return 200, map[string]any{"TotalCount": len(out), "Vpcs": map[string]any{"Vpc": out[s:e]}}
}

func (f *fakeECS) describeInstances(q url.Values) (int, any) {
	var ids []string
	if v := q.Get("InstanceIds"); v != "" {
		_ = json.Unmarshal([]byte(v), &ids)
	}
	var out []map[string]any
	for _, in := range f.instances {
		if len(ids) > 0 && !contains(ids, in["InstanceId"].(string)) {
			continue
		}
		out = append(out, in)
	}
	return 200, map[string]any{"TotalCount": len(out), "Instances": map[string]any{"Instance": out}}
}

func (f *fakeECS) describeKeyPairs(q url.Values) (int, any) {
	if s, _ := strconv.Atoi(q.Get("PageSize")); s > 50 {
		return 400, apiErr("InvalidParameter", "The specified parameter PageSize is not valid.")
	}
	var out []map[string]any
	for _, kp := range f.keyPairs {
		if n := q.Get("KeyPairName"); n != "" && kp["KeyPairName"] != n {
			continue
		}
		if fp := q.Get("KeyPairFingerPrint"); fp != "" && !strings.EqualFold(kp["KeyPairFingerPrint"].(string), fp) {
			continue
		}
		out = append(out, kp)
	}
	s, e := page(q, len(out))
	return 200, map[string]any{"TotalCount": len(out), "PageNumber": q.Get("PageNumber"), "KeyPairs": map[string]any{"KeyPair": out[s:e]}}
}

func (f *fakeECS) addKeyPair(name, fp, created string) {
	f.keyPairs = append(f.keyPairs, map[string]any{"KeyPairName": name, "KeyPairFingerPrint": fp, "CreationTime": created, "PublicKey": ""})
}

func (f *fakeECS) importKeyPair(q url.Values) (int, any) {
	name := q.Get("KeyPairName")
	if len(name) < 2 {
		return 400, apiErr("InvalidKeyPairName.Malformed", "The specified key pair name is not valid.")
	}
	for _, kp := range f.keyPairs {
		if kp["KeyPairName"] == name {
			return 400, apiErr("KeyPair.AlreadyExist", "The key pair already exists.")
		}
	}
	key := strings.Fields(q.Get("PublicKeyBody"))
	if len(key) < 2 {
		f.t.Errorf("ImportKeyPair without a public key body: %q", q.Get("PublicKeyBody"))
	}
	fp := md5Hex(f.t, q.Get("PublicKeyBody"))
	f.addKeyPair(name, fp, time.Now().UTC().Format("2006-01-02T15:04Z"))
	return 200, map[string]any{"KeyPairName": name, "KeyPairFingerPrint": fp, "RequestId": "r"}
}

func (f *fakeECS) describeImages(q url.Values) (int, any) {
	if s, _ := strconv.Atoi(q.Get("PageSize")); s > 100 {
		return 400, apiErr("InvalidParameter", "PageSize")
	}
	var out []map[string]any
	for _, im := range f.images {
		if v := q.Get("ImageFamily"); v != "" && im["ImageFamily"] != v {
			continue
		}
		if v := q.Get("Architecture"); v != "" && im["Architecture"] != v {
			continue
		}
		out = append(out, im)
	}
	if q.Get("ImageFamily") != "" {
		// A family query returns its newest image only.
		sort.Slice(out, func(i, j int) bool { return out[i]["CreationTime"].(string) > out[j]["CreationTime"].(string) })
		if len(out) > 1 {
			out = out[:1]
		}
	}
	s, e := page(q, len(out))
	return 200, map[string]any{"TotalCount": len(out), "Images": map[string]any{"Image": out[s:e]}}
}

// fakeSleepClock is a clock whose Sleep returns at once.
type fakeSleepClock struct {
	now    time.Time
	sleeps []time.Duration
}

func (c *fakeSleepClock) Now() time.Time { return c.now }
func (c *fakeSleepClock) Sleep(ctx context.Context, d time.Duration) error {
	c.sleeps = append(c.sleeps, d)
	c.now = c.now.Add(d)
	return ctx.Err()
}

// md5Hex is the fingerprint ECS computes for an imported key: the MD5 of
// the key's wire bytes in lower-case hexadecimal (of the text itself when
// it does not parse: ECS does not check public keys).
func md5Hex(t *testing.T, body string) string {
	t.Helper()
	data := []byte(body)
	if k, _, _, _, err := ssh.ParseAuthorizedKey(data); err == nil {
		data = k.Marshal()
	}
	sum := md5.Sum(data)
	return hex.EncodeToString(sum[:])
}
