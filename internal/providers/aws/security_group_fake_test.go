package aws

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// fakeRule is one stored ingress rule of a fake security group, in the
// form AWS stores it: icmpv6 for 58, -1 without ports for every protocol.
type fakeRule struct {
	proto    string
	from, to *int32
	source   string
	kind     string // ipv4, ipv6, sg
	desc     string
	id       string
}

func (r fakeRule) key() string {
	return fmt.Sprintf("%s|%d|%d|%s", r.proto, awssdk.ToInt32(r.from), awssdk.ToInt32(r.to), r.source)
}

// fakeSG is a security group of the fake EC2 API.
type fakeSG struct {
	id, name, vpc, desc string
	tags                []ec2types.Tag
	rules               []fakeRule
}

// fakeSGs is the security group part of the shared fake state, with the
// behaviour verified on the real API: names are unique per VPC, a batch
// authorization with one present rule fails as a whole, a revocation of a
// missing rule succeeds and lists it in UnknownIpPermissions.
type fakeSGs struct {
	byRegion map[string][]*fakeSG
	creates  []*ec2.CreateSecurityGroupInput
	auths    []*ec2.AuthorizeSecurityGroupIngressInput
	revokes  []*ec2.RevokeSecurityGroupIngressInput
	groups   [][]string // Groups of each ModifyInstanceAttribute
	pageSize int
	nextID   int
	nextRule int
	// authDup makes the next batch authorization fail with
	// InvalidPermission.Duplicate once (a race with another writer).
	authDup bool
	// revokeNotFound makes revocations of missing rules fail with
	// InvalidPermission.NotFound (the older behaviour).
	revokeNotFound bool
}

func (fs *fakeSGs) init() {
	if fs.byRegion == nil {
		fs.byRegion = map[string][]*fakeSG{}
	}
}

func (fs *fakeSGs) find(region, id string) *fakeSG {
	for _, g := range fs.byRegion[region] {
		if g.id == id {
			return g
		}
	}
	return nil
}

var fakeGroupID = regexp.MustCompile(`^sg-([0-9a-f]{8}|[0-9a-f]{17})$`)

// fakeRulesOf converts a request permission to stored rules.
func fakeRulesOf(p ec2types.IpPermission) []fakeRule {
	proto := strings.ToLower(awssdk.ToString(p.IpProtocol))
	switch proto {
	case "58":
		proto = "icmpv6"
	case "all":
		proto = "-1"
	}
	base := fakeRule{proto: proto, from: p.FromPort, to: p.ToPort}
	if proto == "-1" {
		base.from, base.to = nil, nil
	}
	var out []fakeRule
	for _, r := range p.IpRanges {
		x := base
		x.source, x.kind, x.desc = normalizeCIDR(awssdk.ToString(r.CidrIp)), "ipv4", awssdk.ToString(r.Description)
		out = append(out, x)
	}
	for _, r := range p.Ipv6Ranges {
		x := base
		x.source, x.kind, x.desc = normalizeCIDR(awssdk.ToString(r.CidrIpv6)), "ipv6", awssdk.ToString(r.Description)
		out = append(out, x)
	}
	for _, g := range p.UserIdGroupPairs {
		x := base
		x.source, x.kind, x.desc = awssdk.ToString(g.GroupId), "sg", awssdk.ToString(g.Description)
		out = append(out, x)
	}
	return out
}

// ec2 describes the group, merging the rules of one protocol and port range
// into one permission as AWS does.
func (g *fakeSG) ec2() ec2types.SecurityGroup {
	out := ec2types.SecurityGroup{GroupId: awssdk.String(g.id), GroupName: awssdk.String(g.name), VpcId: awssdk.String(g.vpc),
		Description: awssdk.String(g.desc), Tags: g.tags,
		IpPermissionsEgress: []ec2types.IpPermission{{IpProtocol: awssdk.String("-1"), IpRanges: []ec2types.IpRange{{CidrIp: awssdk.String("0.0.0.0/0")}}}}}
	index := map[string]int{}
	for _, r := range g.rules {
		k := fmt.Sprintf("%s|%d|%d|%v", r.proto, awssdk.ToInt32(r.from), awssdk.ToInt32(r.to), r.from == nil)
		i, ok := index[k]
		if !ok {
			i = len(out.IpPermissions)
			index[k] = i
			out.IpPermissions = append(out.IpPermissions, ec2types.IpPermission{IpProtocol: awssdk.String(r.proto), FromPort: r.from, ToPort: r.to})
		}
		p := &out.IpPermissions[i]
		var d *string
		if r.desc != "" {
			d = awssdk.String(r.desc)
		}
		switch r.kind {
		case "ipv4":
			p.IpRanges = append(p.IpRanges, ec2types.IpRange{CidrIp: awssdk.String(r.source), Description: d})
		case "ipv6":
			p.Ipv6Ranges = append(p.Ipv6Ranges, ec2types.Ipv6Range{CidrIpv6: awssdk.String(r.source), Description: d})
		case "sg":
			p.UserIdGroupPairs = append(p.UserIdGroupPairs, ec2types.UserIdGroupPair{GroupId: awssdk.String(r.source), Description: d})
		}
	}
	return out
}

// sgCall records a call and returns its injected error.
func (f *fakeEC2) sgCall(call string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.callErr(call)
}

func (f *fakeEC2) DescribeSecurityGroups(_ context.Context, in *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	if err := f.sgCall("DescribeSecurityGroups"); err != nil {
		return nil, err
	}
	s := f.shared
	s.mu.Lock()
	defer s.mu.Unlock()
	fs := &s.sg
	fs.init()
	for _, id := range in.GroupIds {
		if !fakeGroupID.MatchString(id) {
			return nil, &fakeAPIError{"InvalidGroupId.Malformed", "Invalid id: \"" + id + "\""}
		}
		if fs.find(f.region, id) == nil {
			return nil, &fakeAPIError{"InvalidGroup.NotFound", "The security group '" + id + "' does not exist"}
		}
	}
	var match []*fakeSG
	for _, g := range fs.byRegion[f.region] {
		ok := len(in.GroupIds) == 0 || containsStr(in.GroupIds, g.id)
		for _, flt := range in.Filters {
			hit := false
			for _, v := range flt.Values {
				switch awssdk.ToString(flt.Name) {
				case "group-name":
					if strings.Contains(v, "*") {
						re := regexp.MustCompile("^" + strings.ReplaceAll(regexp.QuoteMeta(v), `\*`, ".*") + "$")
						hit = hit || re.MatchString(g.name)
					} else {
						hit = hit || v == g.name
					}
				case "vpc-id":
					hit = hit || v == g.vpc
				}
			}
			ok = ok && hit
		}
		if ok {
			match = append(match, g)
		}
	}
	start := 0
	if in.NextToken != nil {
		start, _ = strconv.Atoi(*in.NextToken)
	}
	end := len(match)
	out := &ec2.DescribeSecurityGroupsOutput{}
	if fs.pageSize > 0 && start+fs.pageSize < end {
		end = start + fs.pageSize
		out.NextToken = awssdk.String(strconv.Itoa(end))
	}
	for _, g := range match[start:end] {
		out.SecurityGroups = append(out.SecurityGroups, g.ec2())
	}
	return out, nil
}

func (f *fakeEC2) CreateSecurityGroup(_ context.Context, in *ec2.CreateSecurityGroupInput, _ ...func(*ec2.Options)) (*ec2.CreateSecurityGroupOutput, error) {
	if err := f.sgCall("CreateSecurityGroup"); err != nil {
		return nil, err
	}
	s := f.shared
	s.mu.Lock()
	defer s.mu.Unlock()
	fs := &s.sg
	fs.init()
	fs.creates = append(fs.creates, in)
	name, vpc := awssdk.ToString(in.GroupName), awssdk.ToString(in.VpcId)
	if awssdk.ToString(in.Description) == "" {
		return nil, &fakeAPIError{"MissingParameter", "The request must contain the parameter groupDescription"}
	}
	if strings.HasPrefix(name, "sg-") {
		return nil, &fakeAPIError{"InvalidParameterValue", "Group names may not be in the format sg-*"}
	}
	if vpc == "" {
		vpc = "vpc-0default"
	}
	for _, g := range fs.byRegion[f.region] {
		if g.name == name && g.vpc == vpc {
			return nil, &fakeAPIError{"InvalidGroup.Duplicate", "The security group '" + name + "' already exists for VPC '" + vpc + "'"}
		}
	}
	fs.nextID++
	g := &fakeSG{id: fmt.Sprintf("sg-0new%013d", fs.nextID), name: name, vpc: vpc, desc: awssdk.ToString(in.Description)}
	for _, ts := range in.TagSpecifications {
		g.tags = append(g.tags, ts.Tags...)
	}
	fs.byRegion[f.region] = append(fs.byRegion[f.region], g)
	return &ec2.CreateSecurityGroupOutput{GroupId: awssdk.String(g.id)}, nil
}

func (f *fakeEC2) DeleteSecurityGroup(_ context.Context, in *ec2.DeleteSecurityGroupInput, _ ...func(*ec2.Options)) (*ec2.DeleteSecurityGroupOutput, error) {
	if err := f.sgCall("DeleteSecurityGroup"); err != nil {
		return nil, err
	}
	s := f.shared
	s.mu.Lock()
	defer s.mu.Unlock()
	fs := &s.sg
	fs.init()
	id := awssdk.ToString(in.GroupId)
	g := fs.find(f.region, id)
	if g == nil {
		return nil, &fakeAPIError{"InvalidGroup.NotFound", "The security group '" + id + "' does not exist"}
	}
	if g.name == "default" {
		return nil, &fakeAPIError{"CannotDelete", "the specified group: \"" + id + "\" name: \"default\" cannot be deleted by a user"}
	}
	for _, inst := range s.inst.byRegion[f.region] {
		if inst.state != stateTerminated && containsStr(inst.groupIDs(), id) {
			return nil, &fakeAPIError{"DependencyViolation", "resource " + id + " has a dependent object"}
		}
	}
	list := fs.byRegion[f.region][:0]
	for _, x := range fs.byRegion[f.region] {
		if x != g {
			list = append(list, x)
		}
	}
	fs.byRegion[f.region] = list
	return &ec2.DeleteSecurityGroupOutput{}, nil
}

func (f *fakeEC2) AuthorizeSecurityGroupIngress(_ context.Context, in *ec2.AuthorizeSecurityGroupIngressInput, _ ...func(*ec2.Options)) (*ec2.AuthorizeSecurityGroupIngressOutput, error) {
	if err := f.sgCall("AuthorizeSecurityGroupIngress"); err != nil {
		return nil, err
	}
	s := f.shared
	s.mu.Lock()
	defer s.mu.Unlock()
	fs := &s.sg
	fs.init()
	fs.auths = append(fs.auths, in)
	id := awssdk.ToString(in.GroupId)
	g := fs.find(f.region, id)
	if g == nil {
		return nil, &fakeAPIError{"InvalidGroup.NotFound", "The security group '" + id + "' does not exist"}
	}
	if fs.authDup && len(in.IpPermissions) > 1 {
		fs.authDup = false
		return nil, &fakeAPIError{"InvalidPermission.Duplicate", "the specified rule already exists"}
	}
	var add []fakeRule
	seen := map[string]bool{}
	for _, p := range in.IpPermissions {
		for _, r := range fakeRulesOf(p) {
			if seen[r.key()] {
				return nil, &fakeAPIError{"InvalidParameterValue", "The same permission must not appear multiple times"}
			}
			seen[r.key()] = true
			add = append(add, r)
		}
	}
	for _, r := range add {
		for _, have := range g.rules {
			if have.key() == r.key() {
				return nil, &fakeAPIError{"InvalidPermission.Duplicate", "the specified rule already exists"}
			}
		}
	}
	out := &ec2.AuthorizeSecurityGroupIngressOutput{Return: awssdk.Bool(true)}
	for _, r := range add {
		fs.nextRule++
		r.id = fmt.Sprintf("sgr-%017d", fs.nextRule)
		g.rules = append(g.rules, r)
		sr := ec2types.SecurityGroupRule{SecurityGroupRuleId: awssdk.String(r.id), GroupId: awssdk.String(id), IpProtocol: awssdk.String(r.proto),
			FromPort: r.from, ToPort: r.to, IsEgress: awssdk.Bool(false)}
		if r.from == nil {
			sr.FromPort, sr.ToPort = awssdk.Int32(-1), awssdk.Int32(-1)
		}
		switch r.kind {
		case "ipv4":
			sr.CidrIpv4 = awssdk.String(r.source)
		case "ipv6":
			sr.CidrIpv6 = awssdk.String(r.source)
		case "sg":
			sr.ReferencedGroupInfo = &ec2types.ReferencedSecurityGroup{GroupId: awssdk.String(r.source)}
		}
		out.SecurityGroupRules = append(out.SecurityGroupRules, sr)
	}
	return out, nil
}

func (f *fakeEC2) RevokeSecurityGroupIngress(_ context.Context, in *ec2.RevokeSecurityGroupIngressInput, _ ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupIngressOutput, error) {
	if err := f.sgCall("RevokeSecurityGroupIngress"); err != nil {
		return nil, err
	}
	s := f.shared
	s.mu.Lock()
	defer s.mu.Unlock()
	fs := &s.sg
	fs.init()
	fs.revokes = append(fs.revokes, in)
	id := awssdk.ToString(in.GroupId)
	g := fs.find(f.region, id)
	if g == nil {
		return nil, &fakeAPIError{"InvalidGroup.NotFound", "The security group '" + id + "' does not exist"}
	}
	if fs.revokeNotFound {
		// The older behaviour fails the whole batch.
		for _, p := range in.IpPermissions {
			for _, r := range fakeRulesOf(p) {
				found := false
				for _, have := range g.rules {
					found = found || have.key() == r.key()
				}
				if !found {
					return nil, &fakeAPIError{"InvalidPermission.NotFound", "The specified rule does not exist in this security group."}
				}
			}
		}
	}
	out := &ec2.RevokeSecurityGroupIngressOutput{Return: awssdk.Bool(true)}
	for _, p := range in.IpPermissions {
		for _, r := range fakeRulesOf(p) {
			idx := -1
			for i, have := range g.rules {
				if have.key() == r.key() {
					idx = i
				}
			}
			if idx < 0 {
				out.UnknownIpPermissions = append(out.UnknownIpPermissions, p)
				continue
			}
			out.RevokedSecurityGroupRules = append(out.RevokedSecurityGroupRules, ec2types.RevokedSecurityGroupRule{SecurityGroupRuleId: awssdk.String(g.rules[idx].id)})
			g.rules = append(g.rules[:idx], g.rules[idx+1:]...)
		}
	}
	return out, nil
}

// setGroups is the Groups form of ModifyInstanceAttribute: the whole set is
// replaced, and AWS keeps its own order (here: reversed).
func (fi *fakeInstances) setGroups(fs *fakeSGs, region string, inst *fakeInstance, groups []string) error {
	if len(groups) == 0 {
		return &fakeAPIError{"InvalidParameterCombination", "No attributes specified."}
	}
	if len(groups) > 5 {
		return &fakeAPIError{"SecurityGroupsPerInstanceLimitExceeded", "The maximum number of security groups per interface has been reached."}
	}
	for _, id := range groups {
		g := fs.find(region, id)
		if g == nil {
			return &fakeAPIError{"InvalidGroup.NotFound", "The security group '" + id + "' does not exist"}
		}
		if g.vpc != inst.vpcID() {
			return &fakeAPIError{"InvalidGroup.NotFound", "You have specified two resources that belong to different networks."}
		}
	}
	fs.groups = append(fs.groups, append([]string(nil), groups...))
	inst.sgs = nil
	for i := len(groups) - 1; i >= 0; i-- {
		inst.sgs = append(inst.sgs, groups[i])
	}
	return nil
}

// addSG puts a security group into the fake account.
func (h *awsHarness) addSG(region string, g *fakeSG) *fakeSG {
	h.ec2.mu.Lock()
	defer h.ec2.mu.Unlock()
	h.ec2.sg.init()
	if g.vpc == "" {
		g.vpc = "vpc-0abc"
	}
	if g.desc == "" {
		g.desc = "test group"
	}
	h.ec2.sg.byRegion[region] = append(h.ec2.sg.byRegion[region], g)
	return g
}

// sgByName returns a fake group by name and VPC.
func (h *awsHarness) sgByName(region, name, vpc string) *fakeSG {
	h.ec2.mu.Lock()
	defer h.ec2.mu.Unlock()
	for _, g := range h.ec2.sg.byRegion[region] {
		if g.name == name && (vpc == "" || g.vpc == vpc) {
			return g
		}
	}
	return nil
}

// tcpRule is a stored tcp rule from an IPv4 source.
func tcpRule(port int32, cidr, desc string) fakeRule {
	return fakeRule{proto: "tcp", from: awssdk.Int32(port), to: awssdk.Int32(port), source: cidr, kind: "ipv4", desc: desc}
}
