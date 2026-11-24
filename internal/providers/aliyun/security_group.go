package aliyun

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"

	"github.com/gofika/polyctl/internal/platform"
)

// Page sizes and limits of the security group calls (verified on real
// accounts): DescribeSecurityGroups takes at most 100 per page, and
// DescribeSecurityGroupAttribute pages its rules with MaxResults 10-1000.
const (
	sgPageSize        = 100
	sgRulePage        = 1000
	sgPriorityDefault = 1
	sgPriorityMin     = 1
	sgPriorityMax     = 100
	sgNameMaxLength   = 128
)

// Error codes of the security group calls. Describe answers an unknown
// group with InvalidSecurityGroupId.NotFound, Delete with
// InvalidSecurityGroup.NotFound: both mean the group is gone.
const (
	errSGIDNotFound     = "InvalidSecurityGroupId.NotFound"
	errSGNotFound       = "InvalidSecurityGroup.NotFound"
	errSGDependency     = "DependencyViolation"
	errRuleIDNotFound   = "InvalidParam.SecurityGroupRuleId"
	errInstanceMismatch = "InvalidInstanceId.Mismatch"
)

// sgRetryClock is the clock of the short retry after a group was created
// (nil is the real clock; tests replace it).
var sgRetryClock platform.Clock

// securityGroup is the inventory and output form of an ECS security group.
type securityGroup struct {
	Name        string `json:"name" yaml:"name"`
	ID          string `json:"id" yaml:"id"`
	VPC         string `json:"vpc_id" yaml:"vpc_id"`
	Region      string `json:"region" yaml:"region"`
	Type        string `json:"type" yaml:"type"`
	Description string `json:"description" yaml:"description"`
	// RuleCount counts the rules of both directions, as ECS reports it.
	RuleCount int    `json:"rule_count" yaml:"rule_count"`
	Created   string `json:"created,omitempty" yaml:"created,omitempty"`
}

func (sg securityGroup) resource() platform.Resource {
	name := sg.Name
	if name == "" {
		name = sg.ID
	}
	return platform.Resource{Type: platform.ResSecurityGroup, ID: sg.ID, Name: name, ParentID: sg.Region, Data: sg}
}

func securityGroupFrom(region string, g ecs.SecurityGroup) securityGroup {
	typ := g.SecurityGroupType
	if typ == "" {
		typ = "normal"
	}
	return securityGroup{Name: g.SecurityGroupName, ID: g.SecurityGroupId, VPC: g.VpcId, Region: region, Type: typ,
		Description: g.Description, RuleCount: g.RuleCount, Created: g.CreationTime}
}

// sgRule is an ingress rule as ECS stores it. Protocol and Policy are shown
// in lower case (ECS reads them back as TCP and Accept); Port is the ECS
// PortRange ("80/80", "-1/-1").
type sgRule struct {
	ID          string `json:"id" yaml:"id"`
	Direction   string `json:"direction" yaml:"direction"`
	Protocol    string `json:"protocol" yaml:"protocol"`
	Port        string `json:"port" yaml:"port"`
	Source      string `json:"source" yaml:"source"`
	Policy      string `json:"policy" yaml:"policy"`
	Priority    int    `json:"priority" yaml:"priority"`
	Description string `json:"description" yaml:"description"`

	// key compares the rule with the rules asked for ("" matches nothing).
	key string
}

// String renders the rule as a change report shows it ("tcp 80/80 0.0.0.0/0").
func (r sgRule) String() string {
	s := r.Protocol + " " + r.Port + " " + r.Source
	if r.Policy != "" && r.Policy != "accept" {
		s += " " + r.Policy
	}
	return s
}

// ruleKey is what two rules are compared by: protocol, ports, source and
// policy. Priority and description never count (decision: the platform
// stores rules that differ in them only as one rule).
func ruleKey(protocol string, from, to int, source, policy string) string {
	return fmt.Sprintf("%s|%d|%d|%s|%s", protocol, from, to, source, policy)
}

// wantKey is the key of a rule polyctl writes: policy accept.
func wantKey(r platform.IngressRule) string {
	return ruleKey(r.Protocol, r.FromPort, r.ToPort, r.Source, "accept")
}

// aliPortRange renders the ports of a rule as ECS writes them: "80/80",
// "8000/8999", and "-1/-1" for icmp and all.
func aliPortRange(r platform.IngressRule) string {
	if r.FromPort < 0 {
		return "-1/-1"
	}
	return fmt.Sprintf("%d/%d", r.FromPort, r.ToPort)
}

// aliProtocol is the IpProtocol of a rule. ICMP from an IPv6 source is
// ICMPv6.
func aliProtocol(r platform.IngressRule) string {
	if r.Protocol == "icmp" && r.SourceKind == platform.SourceIPv6 {
		return "ICMPv6"
	}
	return strings.ToUpper(r.Protocol)
}

// aliRuleString is the rule in the ECS notation ("tcp 80/80 0.0.0.0/0").
func aliRuleString(r platform.IngressRule) string {
	return r.Protocol + " " + aliPortRange(r) + " " + r.Source
}

// checkPriority refuses a priority ECS refuses (1-100).
func checkPriority(p int) error {
	if p < sgPriorityMin || p > sgPriorityMax {
		return fmt.Errorf("%w: --priority %d is out of range %d-%d", platform.ErrInvalidInput, p, sgPriorityMin, sgPriorityMax)
	}
	return nil
}

// toPermission maps a rule to its AuthorizeSecurityGroup permission. A
// single IPv4 address always carries /32 (the parser adds it): ECS does not
// normalize sources, and 1.2.3.4 next to 1.2.3.4/32 would be two rules.
func toPermission(r platform.IngressRule, priority int, desc string) ecs.AuthorizeSecurityGroupPermissions {
	p := ecs.AuthorizeSecurityGroupPermissions{
		IpProtocol:  aliProtocol(r),
		PortRange:   aliPortRange(r),
		Policy:      "accept",
		Priority:    strconv.Itoa(priority),
		NicType:     "intranet",
		Description: desc,
	}
	switch r.SourceKind {
	case platform.SourceIPv6:
		p.Ipv6SourceCidrIp = r.Source
	case platform.SourceGroup:
		p.SourceGroupId = r.Source
	default:
		p.SourceCidrIp = r.Source
	}
	return p
}

// parsePortRange reads an ECS PortRange ("80/80", "-1/-1"); ok is false
// for anything else.
func parsePortRange(s string) (from, to int, ok bool) {
	a, b, found := strings.Cut(strings.TrimSpace(s), "/")
	if !found {
		// Tolerate "80-80" and "80", which ECS does not write.
		if a2, b2, f2 := strings.Cut(a, "-"); f2 && a2 != "" {
			a, b = a2, b2
		} else {
			b = a
		}
	}
	f, err1 := strconv.Atoi(strings.TrimSpace(a))
	t, err2 := strconv.Atoi(strings.TrimSpace(b))
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return f, t, true
}

// ruleFrom maps a stored permission; the key normalizes what ECS keeps as
// it was written: the protocol's case, IPv4 sources without a mask, host
// bits, and the policy's case (Accept).
func ruleFrom(p ecs.Permission) sgRule {
	r := sgRule{ID: p.SecurityGroupRuleId, Direction: strings.ToLower(p.Direction), Protocol: strings.ToLower(strings.TrimSpace(p.IpProtocol)),
		Port: p.PortRange, Policy: strings.ToLower(strings.TrimSpace(p.Policy)), Description: p.Description}
	if r.Direction == "" {
		r.Direction = "ingress"
	}
	if r.Policy == "" {
		r.Policy = "accept"
	}
	r.Priority, _ = strconv.Atoi(strings.TrimSpace(p.Priority))
	var raw string
	switch {
	case p.SourceCidrIp != "":
		raw = p.SourceCidrIp
	case p.Ipv6SourceCidrIp != "":
		raw = p.Ipv6SourceCidrIp
	case p.SourceGroupId != "":
		raw = p.SourceGroupId
	case p.SourcePrefixListId != "":
		// Prefix lists are shown, never written or matched.
		r.Source = p.SourcePrefixListId
		return r
	}
	// The source is shown as ECS stores it; only the key is normalized.
	r.Source = raw
	src, _, err := platform.ParseRuleSource(raw)
	if err != nil {
		return r
	}
	proto := r.Protocol
	if proto == "icmpv6" {
		proto = "icmp"
	}
	from, to, ok := parsePortRange(p.PortRange)
	switch proto {
	case "icmp", "all":
		from, to, ok = -1, -1, true
	case "tcp", "udp":
	default:
		return r
	}
	if ok {
		r.key = ruleKey(proto, from, to, src, r.Policy)
	}
	return r
}

// splitRules splits want into the rules have lacks and the ones it holds.
func splitRules(have []sgRule, want []platform.IngressRule) (missing, present []platform.IngressRule) {
	set := map[string]bool{}
	for _, r := range have {
		if r.key != "" {
			set[r.key] = true
		}
	}
	for _, r := range want {
		if set[wantKey(r)] {
			present = append(present, r)
		} else {
			missing = append(missing, r)
		}
	}
	return missing, present
}

// matchingRules returns the stored rules equal to r (ECS may hold several:
// 1.2.3.4 and 1.2.3.4/32 written by another tool are two rules).
func matchingRules(have []sgRule, r platform.IngressRule) []sgRule {
	var out []sgRule
	k := wantKey(r)
	for _, h := range have {
		if h.key == k {
			out = append(out, h)
		}
	}
	return out
}

// looksLikeGroupID reports whether ref names a security group by id.
func looksLikeGroupID(ref string) bool { return strings.HasPrefix(ref, "sg-") && len(ref) > 3 }

func (c *client) regionOr(region string) string {
	if region == "" {
		return c.region
	}
	return region
}

// listSecurityGroups lists the security groups of a region, of one VPC
// when vpc is not "", of one exact name when name is not "", or the groups
// ids names (a JSON array) when ids is not "".
func (c *client) listSecurityGroups(ctx context.Context, region, vpc, name, ids string) ([]securityGroup, error) {
	region = c.regionOr(region)
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return nil, err
	}
	var out []securityGroup
	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := ecs.CreateDescribeSecurityGroupsRequest()
		c.route(req, endpointECS)
		req.RegionId = region
		req.PageNumber = requests.NewInteger(page)
		req.PageSize = requests.NewInteger(sgPageSize)
		req.VpcId = vpc
		req.SecurityGroupName = name
		req.SecurityGroupIds = ids
		resp, err := cl.DescribeSecurityGroups(req)
		if err != nil {
			return nil, wrapErr("ecs DescribeSecurityGroups "+region, err)
		}
		for _, g := range resp.SecurityGroups.SecurityGroup {
			out = append(out, securityGroupFrom(region, g))
		}
		if len(resp.SecurityGroups.SecurityGroup) == 0 || len(out) >= resp.TotalCount {
			break
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

// findSecurityGroups returns the groups ref names: the group of that id,
// or the groups of that exact name (in vpc when it is not ""). None is not
// an error.
func (c *client) findSecurityGroups(ctx context.Context, region, ref, vpc string) ([]securityGroup, error) {
	var found []securityGroup
	var err error
	if looksLikeGroupID(ref) {
		found, err = c.listSecurityGroups(ctx, region, "", "", fmt.Sprintf("[%q]", ref))
		if err != nil {
			if platform.HasErrorCode(err, errSGIDNotFound, errSGNotFound) {
				return nil, nil
			}
			return nil, err
		}
		var out []securityGroup
		for _, g := range found {
			if g.ID == ref {
				out = append(out, g)
			}
		}
		return out, nil
	}
	if found, err = c.listSecurityGroups(ctx, region, vpc, ref, ""); err != nil {
		return nil, err
	}
	// SecurityGroupName is an exact match; checked again in case a region
	// answers it as a prefix.
	var out []securityGroup
	for _, g := range found {
		if g.Name == ref && (vpc == "" || g.VPC == vpc) {
			out = append(out, g)
		}
	}
	return out, nil
}

// securityGroupRules reads every ingress rule of a group, page by page:
// a group with more rules than one page would otherwise look like it lacks
// the rules of the next pages.
func (c *client) securityGroupRules(ctx context.Context, region, id string) ([]sgRule, error) {
	region = c.regionOr(region)
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return nil, err
	}
	var out []sgRule
	token := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := ecs.CreateDescribeSecurityGroupAttributeRequest()
		c.route(req, endpointECS)
		req.RegionId = region
		req.SecurityGroupId = id
		req.Direction = "ingress"
		req.MaxResults = requests.NewInteger(sgRulePage)
		req.NextToken = token
		resp, err := cl.DescribeSecurityGroupAttribute(req)
		if err != nil {
			return nil, wrapErr("ecs DescribeSecurityGroupAttribute "+id, err)
		}
		for _, p := range resp.Permissions.Permission {
			if d := strings.ToLower(p.Direction); d != "" && d != "ingress" {
				continue
			}
			out = append(out, ruleFrom(p))
		}
		if resp.NextToken == "" || resp.NextToken == token {
			break
		}
		token = resp.NextToken
	}
	return out, nil
}

// createSecurityGroup creates a normal security group in a VPC. It never
// sends a request without a VPC: ECS then creates a default VPC nobody
// asked for.
func (c *client) createSecurityGroup(ctx context.Context, region, name, vpc, desc string) (string, error) {
	if vpc == "" {
		return "", fmt.Errorf("%w: a security group needs a VPC", platform.ErrInvalidInput)
	}
	region = c.regionOr(region)
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return "", err
	}
	req := ecs.CreateCreateSecurityGroupRequest()
	c.route(req, endpointECS)
	req.RegionId = region
	req.SecurityGroupName = name
	req.VpcId = vpc
	req.Description = desc
	req.ClientToken = clientToken()
	resp, err := cl.CreateSecurityGroup(req)
	if err != nil {
		return "", wrapErr("ecs CreateSecurityGroup "+name, err)
	}
	return resp.SecurityGroupId, nil
}

// deleteSecurityGroup deletes a group.
func (c *client) deleteSecurityGroup(ctx context.Context, region, id string) error {
	region = c.regionOr(region)
	cl, err := c.ecsClient(sendOnce(ctx), region)
	if err != nil {
		return err
	}
	req := ecs.CreateDeleteSecurityGroupRequest()
	c.route(req, endpointECS)
	req.RegionId = region
	req.SecurityGroupId = id
	if _, err := cl.DeleteSecurityGroup(req); err != nil {
		return wrapErr("ecs DeleteSecurityGroup "+id, err)
	}
	return nil
}

// authorizeIngress adds rules in one AuthorizeSecurityGroup call (ECS
// applies a batch as a whole or not at all). justCreated retries a group
// that is not found yet a few times, 2 seconds apart: a group may not be
// visible right after CreateSecurityGroup.
func (c *client) authorizeIngress(ctx context.Context, region, id string, rules []platform.IngressRule, priority int, desc string, justCreated bool) error {
	if len(rules) == 0 {
		return nil
	}
	region = c.regionOr(region)
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return err
	}
	perms := make([]ecs.AuthorizeSecurityGroupPermissions, 0, len(rules))
	for _, r := range rules {
		perms = append(perms, toPermission(r, priority, desc))
	}
	call := func(ctx context.Context) error {
		req := ecs.CreateAuthorizeSecurityGroupRequest()
		c.route(req, endpointECS)
		req.RegionId = region
		req.SecurityGroupId = id
		req.Permissions = &perms
		req.ClientToken = clientToken()
		if _, err := cl.AuthorizeSecurityGroup(req); err != nil {
			return wrapErr("ecs AuthorizeSecurityGroup "+id, err)
		}
		return nil
	}
	if !justCreated {
		return call(ctx)
	}
	return platform.Retry(ctx, platform.RetryPolicy{Codes: []string{errSGIDNotFound, errSGNotFound},
		Initial: 2 * time.Second, Max: 2 * time.Second, Multiplier: 1, MaxAttempts: 5, Clock: sgRetryClock}, call)
}

// revokeIngress removes rules by their SecurityGroupRuleId.
func (c *client) revokeIngress(ctx context.Context, region, id string, ruleIDs []string) error {
	if len(ruleIDs) == 0 {
		return nil
	}
	region = c.regionOr(region)
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return err
	}
	req := ecs.CreateRevokeSecurityGroupRequest()
	c.route(req, endpointECS)
	req.RegionId = region
	req.SecurityGroupId = id
	ids := append([]string(nil), ruleIDs...)
	req.SecurityGroupRuleId = &ids
	req.ClientToken = clientToken()
	if _, err := cl.RevokeSecurityGroup(req); err != nil {
		return wrapErr("ecs RevokeSecurityGroup "+id, err)
	}
	return nil
}

// joinSecurityGroup adds a group to an instance (the instance keeps its
// other groups).
func (c *client) joinSecurityGroup(ctx context.Context, region, instanceID, sgID string) error {
	region = c.regionOr(region)
	cl, err := c.ecsClient(sendOnce(ctx), region)
	if err != nil {
		return err
	}
	req := ecs.CreateJoinSecurityGroupRequest()
	c.route(req, endpointECS)
	req.RegionId = region
	req.InstanceId = instanceID
	req.SecurityGroupId = sgID
	if _, err := cl.JoinSecurityGroup(req); err != nil {
		return wrapErr("ecs JoinSecurityGroup "+instanceID, err)
	}
	return nil
}

// securityGroupResources lists the groups of a region for the inventory.
func (c *client) securityGroupResources(ctx context.Context, region string) ([]platform.Resource, error) {
	sgs, err := c.listSecurityGroups(ctx, region, "", "", "")
	if err != nil {
		return nil, err
	}
	out := make([]platform.Resource, 0, len(sgs))
	for _, sg := range sgs {
		out = append(out, sg.resource())
	}
	return out, nil
}
