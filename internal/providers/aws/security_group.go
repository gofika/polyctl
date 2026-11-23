package aws

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/gofika/polyctl/internal/platform"
)

var _ platform.SecurityGroupService = (*client)(nil)

// Error codes of the security group calls.
const (
	errGroupNotFound      = "InvalidGroup.NotFound"
	errGroupIDMalformed   = "InvalidGroupId.Malformed"
	errGroupDuplicate     = "InvalidGroup.Duplicate"
	errPermDuplicate      = "InvalidPermission.Duplicate"
	errPermNotFound       = "InvalidPermission.NotFound"
	errDependency         = "DependencyViolation"
	errSGPerInstanceLimit = "SecurityGroupsPerInstanceLimitExceeded"
)

// maxGroupsPerInterface is the default quota of security groups per network
// interface.
const maxGroupsPerInterface = 5

// sgErr wraps an error of a security group call: a malformed group id is a
// usage error, the rest maps like every EC2 call.
func sgErr(action, region string, err error) error {
	if platform.HasErrorCode(err, errGroupIDMalformed) {
		return fmt.Errorf("%w: ec2:%s in %s: the security group id is malformed (expected sg- followed by 8 or 17 hexadecimal characters): %w", platform.ErrInvalidInput, action, region, err)
	}
	return ec2Err(action, region, err)
}

// looksLikeGroupID reports whether ref names a security group by id.
func looksLikeGroupID(ref string) bool { return strings.HasPrefix(ref, "sg-") }

// normalizeProtocol turns an IpProtocol into the form polyctl shows and
// compares: AWS reports icmpv6 for rules written with 58 and keeps -1 for
// every protocol; numbers of named protocols are named.
func normalizeProtocol(p string) string {
	switch p = strings.ToLower(strings.TrimSpace(p)); p {
	case "-1", "all":
		return "all"
	case "58", "icmpv6":
		return "icmpv6"
	case "6":
		return "tcp"
	case "17":
		return "udp"
	case "1":
		return "icmp"
	}
	return p
}

// normalizeCIDR masks a CIDR the way AWS stores it; text that does not
// parse is kept as it is.
func normalizeCIDR(s string) string {
	if p, err := netip.ParsePrefix(strings.TrimSpace(s)); err == nil {
		return p.Masked().String()
	}
	return s
}

// rulePorts returns the ports of a stored rule: -1 when the protocol has
// none (all) or AWS left them unset.
func rulePorts(proto string, from, to *int32) (int, int) {
	if proto == "all" {
		return -1, -1
	}
	f, t := -1, -1
	if from != nil {
		f = int(*from)
	}
	if to != nil {
		t = int(*to)
	}
	return f, t
}

// flattenPermission returns one rule per source of an IpPermission: AWS
// merges the rules of one protocol and port range into one permission.
func flattenPermission(p ec2types.IpPermission) []platform.SecurityGroupRule {
	proto := normalizeProtocol(awssdk.ToString(p.IpProtocol))
	from, to := rulePorts(proto, p.FromPort, p.ToPort)
	base := platform.SecurityGroupRule{Protocol: proto, FromPort: from, ToPort: to}
	var out []platform.SecurityGroupRule
	add := func(source, kind string, desc *string) {
		r := base
		r.Source, r.SourceType, r.Description = source, kind, awssdk.ToString(desc)
		out = append(out, r)
	}
	for _, r := range p.IpRanges {
		add(normalizeCIDR(awssdk.ToString(r.CidrIp)), platform.SourceIPv4, r.Description)
	}
	for _, r := range p.Ipv6Ranges {
		add(normalizeCIDR(awssdk.ToString(r.CidrIpv6)), platform.SourceIPv6, r.Description)
	}
	for _, g := range p.UserIdGroupPairs {
		add(awssdk.ToString(g.GroupId), platform.SourceGroup, g.Description)
	}
	for _, pl := range p.PrefixListIds {
		add(awssdk.ToString(pl.PrefixListId), platform.SourcePrefixList, pl.Description)
	}
	return out
}

// flattenPermissions flattens every permission.
func flattenPermissions(perms []ec2types.IpPermission) []platform.SecurityGroupRule {
	var out []platform.SecurityGroupRule
	for _, p := range perms {
		out = append(out, flattenPermission(p)...)
	}
	return out
}

// toIpPermission converts a parsed rule: icmp from an IPv6 source becomes
// ICMPv6 (58), the protocol all becomes -1 without ports, and the source
// goes into the field of its kind.
func toIpPermission(r platform.IngressRule, desc string) (ec2types.IpPermission, error) {
	var p ec2types.IpPermission
	switch r.Protocol {
	case "tcp", "udp":
		p.IpProtocol = awssdk.String(r.Protocol)
		p.FromPort, p.ToPort = awssdk.Int32(int32(r.FromPort)), awssdk.Int32(int32(r.ToPort))
	case "icmp":
		p.IpProtocol = awssdk.String("icmp")
		if r.SourceKind == platform.SourceIPv6 {
			p.IpProtocol = awssdk.String("58")
		}
		p.FromPort, p.ToPort = awssdk.Int32(-1), awssdk.Int32(-1)
	case "all":
		p.IpProtocol = awssdk.String("-1")
	default:
		return p, fmt.Errorf("%w: rule %s: unknown protocol %q", platform.ErrInvalidInput, r, r.Protocol)
	}
	var d *string
	if desc != "" {
		d = awssdk.String(desc)
	}
	switch r.SourceKind {
	case platform.SourceIPv4:
		p.IpRanges = []ec2types.IpRange{{CidrIp: awssdk.String(r.Source), Description: d}}
	case platform.SourceIPv6:
		p.Ipv6Ranges = []ec2types.Ipv6Range{{CidrIpv6: awssdk.String(r.Source), Description: d}}
	case platform.SourceGroup:
		if strings.Contains(r.Source, "/") {
			return p, fmt.Errorf("%w: rule %s: security groups of other accounts (account/sg-...) are not supported", platform.ErrInvalidInput, r)
		}
		p.UserIdGroupPairs = []ec2types.UserIdGroupPair{{GroupId: awssdk.String(r.Source), Description: d}}
	default:
		return p, fmt.Errorf("%w: rule %s: unknown source kind %q", platform.ErrInvalidInput, r, r.SourceKind)
	}
	return p, nil
}

// storedRule is the rule as AWS stores (and later describes) it.
func storedRule(r platform.IngressRule) (platform.SecurityGroupRule, error) {
	p, err := toIpPermission(r, "")
	if err != nil {
		return platform.SecurityGroupRule{}, err
	}
	return flattenPermission(p)[0], nil
}

// ruleExists reports whether want is among the existing permissions:
// protocol (58 and icmpv6 alike), ports and source must be equal; the
// description never counts, as AWS does not count it either. A want
// without any source is an internal error, never a match.
func ruleExists(existing []ec2types.IpPermission, want ec2types.IpPermission) (bool, error) {
	wants := flattenPermission(want)
	if len(wants) == 0 {
		return false, errors.New("internal error: a rule without a source cannot be compared")
	}
	have := map[string]bool{}
	for _, r := range flattenPermissions(existing) {
		have[r.Key()] = true
	}
	for _, w := range wants {
		if have[w.Key()] {
			return true, nil
		}
	}
	return false, nil
}

// securityGroupFrom converts an EC2 security group (its ingress rules only).
func securityGroupFrom(region string, g ec2types.SecurityGroup) platform.SecurityGroup {
	sg := platform.SecurityGroup{
		ID:          awssdk.ToString(g.GroupId),
		Name:        awssdk.ToString(g.GroupName),
		VPC:         awssdk.ToString(g.VpcId),
		Description: awssdk.ToString(g.Description),
		Region:      region,
		Tags:        map[string]string{},
		Ingress:     flattenPermissions(g.IpPermissions),
	}
	for _, t := range g.Tags {
		sg.Tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	if sg.Ingress == nil {
		sg.Ingress = []platform.SecurityGroupRule{}
	}
	return sg
}

func sgResource(sg platform.SecurityGroup) platform.Resource {
	return platform.Resource{Type: platform.ResSecurityGroup, ID: sg.ID, Name: sg.Name, Data: sg}
}

// describeSecurityGroups runs a paginated DescribeSecurityGroups.
func (c *client) describeSecurityGroups(ctx context.Context, region string, in *ec2.DescribeSecurityGroupsInput) ([]platform.SecurityGroup, error) {
	region = c.regionOr(region)
	var out []platform.SecurityGroup
	pg := ec2.NewDescribeSecurityGroupsPaginator(c.ec2For(region), in)
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, g := range page.SecurityGroups {
			out = append(out, securityGroupFrom(region, g))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// ListSecurityGroups lists the security groups of a region that match f.
func (c *client) ListSecurityGroups(ctx context.Context, region string, f platform.SecurityGroupFilter) ([]platform.SecurityGroup, error) {
	region = c.regionOr(region)
	in := &ec2.DescribeSecurityGroupsInput{}
	if len(f.IDs) > 0 {
		in.GroupIds = f.IDs
	}
	if f.VPC != "" {
		in.Filters = append(in.Filters, ec2types.Filter{Name: awssdk.String("vpc-id"), Values: []string{f.VPC}})
	}
	if f.Name != "" {
		in.Filters = append(in.Filters, ec2types.Filter{Name: awssdk.String("group-name"), Values: []string{f.Name}})
	}
	out, err := c.describeSecurityGroups(ctx, region, in)
	if err != nil {
		return nil, sgErr("DescribeSecurityGroups", region, err)
	}
	return out, nil
}

// securityGroupResources lists the groups of a region as inventory resources.
func (c *client) securityGroupResources(ctx context.Context, region string) ([]platform.Resource, error) {
	sgs, err := c.ListSecurityGroups(ctx, region, platform.SecurityGroupFilter{})
	if err != nil {
		return nil, err
	}
	out := make([]platform.Resource, 0, len(sgs))
	for _, sg := range sgs {
		out = append(out, sgResource(sg))
	}
	return out, nil
}

// FindSecurityGroups returns the groups ref names: an sg- id (a missing
// one is no match, a malformed one a usage error), or a group name, exact,
// within vpc when it is not "" (names are unique per VPC only).
func (c *client) FindSecurityGroups(ctx context.Context, region, ref, vpc string) ([]platform.SecurityGroup, error) {
	region = c.regionOr(region)
	if looksLikeGroupID(ref) {
		out, err := c.describeSecurityGroups(ctx, region, &ec2.DescribeSecurityGroupsInput{GroupIds: []string{ref}})
		if err != nil {
			if platform.HasErrorCode(err, errGroupNotFound) {
				return nil, nil
			}
			return nil, sgErr("DescribeSecurityGroups", region, err)
		}
		return out, nil
	}
	in := &ec2.DescribeSecurityGroupsInput{Filters: []ec2types.Filter{{Name: awssdk.String("group-name"), Values: []string{ref}}}}
	if vpc != "" {
		in.Filters = append(in.Filters, ec2types.Filter{Name: awssdk.String("vpc-id"), Values: []string{vpc}})
	}
	all, err := c.describeSecurityGroups(ctx, region, in)
	if err != nil {
		return nil, sgErr("DescribeSecurityGroups", region, err)
	}
	// The filter takes wildcards: keep the exact name.
	var out []platform.SecurityGroup
	for _, sg := range all {
		if sg.Name == ref && (vpc == "" || sg.VPC == vpc) {
			out = append(out, sg)
		}
	}
	return out, nil
}

// CreateSecurityGroup creates a group with its tags in one call.
func (c *client) CreateSecurityGroup(ctx context.Context, spec platform.SecurityGroupSpec) (string, error) {
	region := c.regionOr(spec.Region)
	in := &ec2.CreateSecurityGroupInput{
		GroupName:   awssdk.String(spec.Name),
		Description: awssdk.String(spec.Description),
	}
	if spec.VPC != "" {
		in.VpcId = awssdk.String(spec.VPC)
	}
	if len(spec.Tags) > 0 {
		in.TagSpecifications = []ec2types.TagSpecification{{ResourceType: ec2types.ResourceTypeSecurityGroup, Tags: sortedTags(spec.Tags)}}
	}
	out, err := c.ec2For(region).CreateSecurityGroup(ctx, in)
	if err != nil {
		return "", sgErr("CreateSecurityGroup", region, err)
	}
	if awssdk.ToString(out.GroupId) == "" {
		return "", fmt.Errorf("ec2:CreateSecurityGroup in %s returned no group id", region)
	}
	return awssdk.ToString(out.GroupId), nil
}

// DeleteSecurityGroup deletes a group. The error keeps the AWS code, so
// that the command can tell a missing group from one still in use.
func (c *client) DeleteSecurityGroup(ctx context.Context, region, id string) error {
	region = c.regionOr(region)
	if _, err := c.ec2For(region).DeleteSecurityGroup(ctx, &ec2.DeleteSecurityGroupInput{GroupId: awssdk.String(id)}); err != nil {
		if platform.HasErrorCode(err, errDependency) {
			return fmt.Errorf("security group %s is still in use by an instance, a network interface or a rule of another security group; detach it or remove the references first: ec2:DeleteSecurityGroup in %s: %w", id, region, err)
		}
		return sgErr("DeleteSecurityGroup", region, err)
	}
	return nil
}

// MissingIngressRules splits want into the rules sg lacks and the ones it
// has, comparing each rule in the form AWS stores it.
func (c *client) MissingIngressRules(sg platform.SecurityGroup, want []platform.IngressRule) (missing, present []platform.IngressRule, err error) {
	have := map[string]bool{}
	for _, r := range sg.Ingress {
		have[r.Key()] = true
	}
	for _, w := range want {
		s, err := storedRule(w)
		if err != nil {
			return nil, nil, err
		}
		if have[s.Key()] {
			present = append(present, w)
		} else {
			missing = append(missing, w)
		}
	}
	return missing, present, nil
}

// authorize sends one AuthorizeSecurityGroupIngress.
func (c *client) authorize(ctx context.Context, region, id string, perms []ec2types.IpPermission) (*ec2.AuthorizeSecurityGroupIngressOutput, error) {
	return c.ec2For(region).AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{GroupId: awssdk.String(id), IpPermissions: perms})
}

// AddIngressRules adds rules in one call. AWS refuses the whole batch when
// one rule is present already (InvalidPermission.Duplicate, a race or a
// rule the comparison missed): the rules are then added one by one, and a
// duplicate one is reported as not done. Repeated rules must be dropped
// before: AWS refuses a batch that holds one rule twice.
func (c *client) AddIngressRules(ctx context.Context, region, id string, rules []platform.IngressRule, description string) ([]platform.RuleOutcome, error) {
	region = c.regionOr(region)
	if len(rules) == 0 {
		return nil, nil
	}
	perms := make([]ec2types.IpPermission, 0, len(rules))
	for _, r := range rules {
		p, err := toIpPermission(r, description)
		if err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	out, err := c.authorize(ctx, region, id, perms)
	if err == nil {
		ids := addedRuleIDs(out)
		res := make([]platform.RuleOutcome, 0, len(rules))
		for _, r := range rules {
			s, _ := storedRule(r)
			res = append(res, platform.RuleOutcome{Rule: r, Done: true, ID: ids[s.Key()]})
		}
		return res, nil
	}
	if !platform.HasErrorCode(err, errPermDuplicate) {
		return nil, sgErr("AuthorizeSecurityGroupIngress", region, err)
	}
	res := make([]platform.RuleOutcome, 0, len(rules))
	for i, r := range rules {
		out, err := c.authorize(ctx, region, id, perms[i:i+1])
		switch {
		case err == nil:
			s, _ := storedRule(r)
			res = append(res, platform.RuleOutcome{Rule: r, Done: true, ID: addedRuleIDs(out)[s.Key()]})
		case platform.HasErrorCode(err, errPermDuplicate):
			res = append(res, platform.RuleOutcome{Rule: r})
		default:
			return res, sgErr("AuthorizeSecurityGroupIngress", region, err)
		}
	}
	return res, nil
}

// addedRuleIDs maps the rules an authorization added (by their key) to
// their security group rule ids.
func addedRuleIDs(out *ec2.AuthorizeSecurityGroupIngressOutput) map[string]string {
	ids := map[string]string{}
	if out == nil {
		return ids
	}
	for _, sr := range out.SecurityGroupRules {
		if awssdk.ToBool(sr.IsEgress) {
			continue
		}
		proto := normalizeProtocol(awssdk.ToString(sr.IpProtocol))
		from, to := rulePorts(proto, sr.FromPort, sr.ToPort)
		r := platform.SecurityGroupRule{Protocol: proto, FromPort: from, ToPort: to}
		switch {
		case sr.CidrIpv4 != nil:
			r.Source = normalizeCIDR(*sr.CidrIpv4)
		case sr.CidrIpv6 != nil:
			r.Source = normalizeCIDR(*sr.CidrIpv6)
		case sr.ReferencedGroupInfo != nil:
			r.Source = awssdk.ToString(sr.ReferencedGroupInfo.GroupId)
		case sr.PrefixListId != nil:
			r.Source = *sr.PrefixListId
		default:
			continue
		}
		ids[r.Key()] = awssdk.ToString(sr.SecurityGroupRuleId)
	}
	return ids
}

// RemoveIngressRules revokes rules in one call, without their descriptions
// (AWS does not need them). A rule that is not there does not fail the
// call: AWS returns it in UnknownIpPermissions, and it is reported as not
// done. Should AWS answer InvalidPermission.NotFound instead (an older
// behaviour), the rules are revoked one by one.
func (c *client) RemoveIngressRules(ctx context.Context, region, id string, rules []platform.IngressRule) ([]platform.RuleOutcome, error) {
	region = c.regionOr(region)
	if len(rules) == 0 {
		return nil, nil
	}
	perms := make([]ec2types.IpPermission, 0, len(rules))
	for _, r := range rules {
		p, err := toIpPermission(r, "")
		if err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	revoke := func(perms []ec2types.IpPermission) (map[string]bool, error) {
		out, err := c.ec2For(region).RevokeSecurityGroupIngress(ctx, &ec2.RevokeSecurityGroupIngressInput{GroupId: awssdk.String(id), IpPermissions: perms})
		if err != nil {
			return nil, err
		}
		unknown := map[string]bool{}
		for _, r := range flattenPermissions(out.UnknownIpPermissions) {
			unknown[r.Key()] = true
		}
		return unknown, nil
	}
	unknown, err := revoke(perms)
	if err == nil {
		res := make([]platform.RuleOutcome, 0, len(rules))
		for _, r := range rules {
			s, _ := storedRule(r)
			res = append(res, platform.RuleOutcome{Rule: r, Done: !unknown[s.Key()]})
		}
		return res, nil
	}
	if !platform.HasErrorCode(err, errPermNotFound) {
		return nil, sgErr("RevokeSecurityGroupIngress", region, err)
	}
	res := make([]platform.RuleOutcome, 0, len(rules))
	for i, r := range rules {
		unknown, err := revoke(perms[i : i+1])
		switch {
		case err == nil:
			s, _ := storedRule(r)
			res = append(res, platform.RuleOutcome{Rule: r, Done: !unknown[s.Key()]})
		case platform.HasErrorCode(err, errPermNotFound):
			res = append(res, platform.RuleOutcome{Rule: r})
		default:
			return res, sgErr("RevokeSecurityGroupIngress", region, err)
		}
	}
	return res, nil
}

// SetInstanceSecurityGroups replaces the groups of an instance: AWS takes
// the whole set (the groups left out are detached) and cannot take an
// empty one.
func (c *client) SetInstanceSecurityGroups(ctx context.Context, region, instanceID string, groups []string) error {
	region = c.regionOr(region)
	if len(groups) == 0 {
		return fmt.Errorf("%w: an instance keeps at least one security group", platform.ErrInvalidInput)
	}
	_, err := c.ec2For(region).ModifyInstanceAttribute(ctx, &ec2.ModifyInstanceAttributeInput{InstanceId: awssdk.String(instanceID), Groups: groups})
	if err != nil {
		if platform.HasErrorCode(err, errSGPerInstanceLimit) {
			return fmt.Errorf("instance %s cannot take %d security groups (the quota of security groups per network interface is reached): ec2:ModifyInstanceAttribute in %s: %w", instanceID, len(groups), region, err)
		}
		return sgErr("ModifyInstanceAttribute", region, err)
	}
	return nil
}

// SecurityGroupInstances returns the ids of the instances (terminated ones
// left out) the group is attached to.
func (c *client) SecurityGroupInstances(ctx context.Context, region, id string) ([]string, error) {
	region = c.regionOr(region)
	all, err := c.describeInstancesWith(ctx, region, &ec2.DescribeInstancesInput{
		Filters: []ec2types.Filter{{Name: awssdk.String("instance.group-id"), Values: []string{id}}},
	})
	if err != nil {
		return nil, ec2Err("DescribeInstances", region, err)
	}
	var out []string
	for _, in := range liveInstances(all) {
		out = append(out, awssdk.ToString(in.InstanceId))
	}
	sort.Strings(out)
	return out, nil
}

// instanceGroupIDs returns the ids of the groups attached to an instance.
func instanceGroupIDs(in ec2types.Instance) []string {
	var out []string
	for _, g := range in.SecurityGroups {
		if id := awssdk.ToString(g.GroupId); id != "" {
			out = append(out, id)
		}
	}
	return out
}
