package aws

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/gofika/polyctl/internal/platform"
)

// elbAPI is the part of the Elastic Load Balancing v2 API polyctl uses.
type elbAPI interface {
	DescribeLoadBalancers(ctx context.Context, in *elb.DescribeLoadBalancersInput, optFns ...func(*elb.Options)) (*elb.DescribeLoadBalancersOutput, error)
	CreateLoadBalancer(ctx context.Context, in *elb.CreateLoadBalancerInput, optFns ...func(*elb.Options)) (*elb.CreateLoadBalancerOutput, error)
	DeleteLoadBalancer(ctx context.Context, in *elb.DeleteLoadBalancerInput, optFns ...func(*elb.Options)) (*elb.DeleteLoadBalancerOutput, error)
	SetSecurityGroups(ctx context.Context, in *elb.SetSecurityGroupsInput, optFns ...func(*elb.Options)) (*elb.SetSecurityGroupsOutput, error)
	SetSubnets(ctx context.Context, in *elb.SetSubnetsInput, optFns ...func(*elb.Options)) (*elb.SetSubnetsOutput, error)
	SetIpAddressType(ctx context.Context, in *elb.SetIpAddressTypeInput, optFns ...func(*elb.Options)) (*elb.SetIpAddressTypeOutput, error)
	DescribeLoadBalancerAttributes(ctx context.Context, in *elb.DescribeLoadBalancerAttributesInput, optFns ...func(*elb.Options)) (*elb.DescribeLoadBalancerAttributesOutput, error)
	ModifyLoadBalancerAttributes(ctx context.Context, in *elb.ModifyLoadBalancerAttributesInput, optFns ...func(*elb.Options)) (*elb.ModifyLoadBalancerAttributesOutput, error)
	DescribeTargetGroups(ctx context.Context, in *elb.DescribeTargetGroupsInput, optFns ...func(*elb.Options)) (*elb.DescribeTargetGroupsOutput, error)
	CreateTargetGroup(ctx context.Context, in *elb.CreateTargetGroupInput, optFns ...func(*elb.Options)) (*elb.CreateTargetGroupOutput, error)
	ModifyTargetGroup(ctx context.Context, in *elb.ModifyTargetGroupInput, optFns ...func(*elb.Options)) (*elb.ModifyTargetGroupOutput, error)
	DeleteTargetGroup(ctx context.Context, in *elb.DeleteTargetGroupInput, optFns ...func(*elb.Options)) (*elb.DeleteTargetGroupOutput, error)
	DescribeTargetHealth(ctx context.Context, in *elb.DescribeTargetHealthInput, optFns ...func(*elb.Options)) (*elb.DescribeTargetHealthOutput, error)
	RegisterTargets(ctx context.Context, in *elb.RegisterTargetsInput, optFns ...func(*elb.Options)) (*elb.RegisterTargetsOutput, error)
	DeregisterTargets(ctx context.Context, in *elb.DeregisterTargetsInput, optFns ...func(*elb.Options)) (*elb.DeregisterTargetsOutput, error)
	DescribeListeners(ctx context.Context, in *elb.DescribeListenersInput, optFns ...func(*elb.Options)) (*elb.DescribeListenersOutput, error)
	CreateListener(ctx context.Context, in *elb.CreateListenerInput, optFns ...func(*elb.Options)) (*elb.CreateListenerOutput, error)
	ModifyListener(ctx context.Context, in *elb.ModifyListenerInput, optFns ...func(*elb.Options)) (*elb.ModifyListenerOutput, error)
	DeleteListener(ctx context.Context, in *elb.DeleteListenerInput, optFns ...func(*elb.Options)) (*elb.DeleteListenerOutput, error)
}

var _ platform.LoadBalancerService = (*client)(nil)

// The waits and retries of the load balancer commands; tests replace them.
var (
	elbClock platform.Clock = platform.RealClock
	// lookupHost resolves the DNS name of a load balancer.
	lookupHost = net.DefaultResolver.LookupHost
)

const (
	// lbActivePoll is the pause between two reads of a load balancer that
	// is provisioning (one becomes active in about 2 to 2.5 minutes).
	lbActivePoll = 15 * time.Second
	// lbGonePoll is the pause between two reads of a deleted load balancer.
	lbGonePoll = 5 * time.Second
	// lbDNSRetry and lbDNSTimeout bound the resolution of the DNS name of a
	// new load balancer, which answers no such host for a while.
	lbDNSRetry   = 5 * time.Second
	lbDNSTimeout = 60 * time.Second
	// tgInUseRetry and tgInUseTimeout bound the retries of the deletion of a
	// target group that the deleted load balancer may still hold.
	tgInUseRetry   = 5 * time.Second
	tgInUseTimeout = 60 * time.Second
	// elbPageSize is the largest page Describe* accepts (1-400).
	elbPageSize = 400
)

// Error codes of the Elastic Load Balancing v2 API.
const (
	errLBNotFound          = "LoadBalancerNotFound"
	errTGNotFound          = "TargetGroupNotFound"
	errListenerNotFound    = "ListenerNotFound"
	errDuplicateLBName     = "DuplicateLoadBalancerName"
	errDuplicateTGName     = "DuplicateTargetGroupName"
	errDuplicateListener   = "DuplicateListener"
	errResourceInUse       = "ResourceInUse"
	errOperationNotAllowed = "OperationNotPermitted"
	errInvalidConfig       = "InvalidConfigurationRequest"
	errELBValidation       = "ValidationError"
)

// elbGeneralCodes are errors that are neither the caller's syntax nor the
// credentials: the state of the account or of a resource. They keep the
// general exit code whatever HTTP status they come with.
var elbGeneralCodes = map[string]bool{
	errDuplicateLBName: true, errDuplicateTGName: true, errDuplicateListener: true,
	errResourceInUse: true, errOperationNotAllowed: true, errInvalidConfig: true,
	"TooManyLoadBalancers": true, "TooManyTargets": true, "TooManyTargetGroups": true, "TooManyListeners": true,
	"TooManyTags": true, "TooManyCertificates": true, "TooManyRegistrationsForTargetId": true,
	"InvalidTarget": true, "InvalidSubnet": true, "InvalidSecurityGroup": true, "SubnetNotFound": true,
	"AllocationIdNotFound": true, "AvailabilityZoneNotSupported": true, "CertificateNotFound": true,
	"UnsupportedProtocol": true, "IncompatibleProtocols": true, "PriorityInUse": true,
	"HealthUnavailable": true, "InvalidScheme": true, "SSLPolicyNotFound": true,
}

// elbServerValidation are the calls whose ValidationError depends on what
// exists on the platform (a target id that is no instance, an address
// outside the VPC), not on the syntax of the request: they keep the general
// exit code instead of the usage code.
var elbServerValidation = map[string]bool{
	"RegisterTargets": true, "DeregisterTargets": true, "SetIpAddressType": true,
}

// elbNotFound reports whether err says that a load balancer, a target group
// or a listener does not exist. The typed exceptions are matched first;
// the code is compared too for errors that carry only the code.
func elbNotFound(err error) bool {
	var lb *elbtypes.LoadBalancerNotFoundException
	var tg *elbtypes.TargetGroupNotFoundException
	var ls *elbtypes.ListenerNotFoundException
	if errors.As(err, &lb) || errors.As(err, &tg) || errors.As(err, &ls) {
		return true
	}
	return platform.HasErrorCode(err, errLBNotFound, errTGNotFound, errListenerNotFound)
}

// elbErr wraps an error of the call action in region: a missing resource
// is ErrNotFound, a ValidationError the caller could have avoided is a
// usage error, the state of a resource (in use, protected, duplicate, a
// quota) the general failure, and a denial names the IAM action.
func elbErr(action, region string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	where := fmt.Sprintf("elasticloadbalancing:%s in %s", action, region)
	code := platform.ErrorCode(err)
	switch {
	case elbNotFound(err):
		return fmt.Errorf("%w: %s: %w", platform.ErrNotFound, where, err)
	case code == errELBValidation && !elbServerValidation[action]:
		return fmt.Errorf("%w: %s: %w", platform.ErrInvalidInput, where, err)
	case code == errELBValidation, elbGeneralCodes[code]:
		return fmt.Errorf("%s: %w", where, err)
	}
	m := mapErr(err)
	if errors.Is(m, platform.ErrUnauthorized) {
		return fmt.Errorf("%s (the credentials need the IAM action elasticloadbalancing:%s): %w", where, action, m)
	}
	return fmt.Errorf("%s: %w", where, m)
}

// ------------------------------------------------------------ names

// checkELBName refuses a load balancer or target group name AWS would
// refuse: 1 to 32 letters, digits and hyphens, no hyphen first or last;
// a load balancer name may not start with "internal-".
func checkELBName(what, name string, lb bool) error {
	hint := ""
	switch what {
	case "load balancer":
		hint = " (shorten the name, or override naming.aws_elbv2_load_balancer in config.yaml)"
	case "target group":
		hint = " (shorten the name, or override naming.aws_elbv2_target_group in config.yaml)"
	}
	switch {
	case name == "":
		return fmt.Errorf("%w: the %s name is empty", platform.ErrInvalidInput, what)
	case len(name) > 32:
		return fmt.Errorf("%w: %s name %q has %d characters; AWS allows at most 32%s", platform.ErrInvalidInput, what, name, len(name), hint)
	case strings.HasPrefix(name, "-") || strings.HasSuffix(name, "-"):
		return fmt.Errorf("%w: %s name %q may not begin or end with a hyphen%s", platform.ErrInvalidInput, what, name, hint)
	case lb && strings.HasPrefix(strings.ToLower(name), "internal-"):
		return fmt.Errorf("%w: %s name %q may not begin with \"internal-\"%s", platform.ErrInvalidInput, what, name, hint)
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
			return fmt.Errorf("%w: %s name %q holds %q; AWS allows letters, digits and hyphens only%s", platform.ErrInvalidInput, what, name, r, hint)
		}
	}
	return nil
}

// ------------------------------------------------------------ ARNs

// elbARN is the parsed form of an Elastic Load Balancing ARN:
// arn:<partition>:elasticloadbalancing:<region>:<account>:<kind>/<rest>.
type elbARN struct {
	Region, Account, Kind, Name string
}

// parseELBARN parses an ELBv2 ARN; ok is false for anything else.
func parseELBARN(s string) (elbARN, bool) {
	parts := strings.SplitN(s, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "elasticloadbalancing" || parts[3] == "" {
		return elbARN{}, false
	}
	kind, rest, ok := strings.Cut(parts[5], "/")
	if !ok {
		return elbARN{}, false
	}
	a := elbARN{Region: parts[3], Account: parts[4], Kind: kind}
	segs := strings.Split(rest, "/")
	switch kind {
	case "loadbalancer", "listener":
		// loadbalancer/net/<name>/<id>, listener/net/<name>/<lb-id>/<id>
		if len(segs) >= 2 {
			a.Name = segs[1]
		}
	case "targetgroup":
		a.Name = segs[0]
	}
	return a, true
}

// isELBARN reports whether s is an ELBv2 ARN of the given kind.
func isELBARN(s, kind string) bool {
	a, ok := parseELBARN(s)
	return ok && a.Kind == kind
}

// arnName returns the name an ARN holds, or the ARN itself.
func arnName(arn string) string {
	if a, ok := parseELBARN(arn); ok && a.Name != "" {
		return a.Name
	}
	return arn
}

// ------------------------------------------------------- conversions

func lbFrom(region string, in elbtypes.LoadBalancer) platform.LoadBalancer {
	out := platform.LoadBalancer{ID: awssdk.ToString(in.LoadBalancerArn), Name: awssdk.ToString(in.LoadBalancerName), Type: string(in.Type),
		Scheme: string(in.Scheme), VPC: awssdk.ToString(in.VpcId), DNSName: awssdk.ToString(in.DNSName),
		IPAddressType: string(in.IpAddressType), SecurityGroups: append([]string{}, in.SecurityGroups...), Region: region, Zones: []platform.LBZone{}}
	if in.State != nil {
		out.State = string(in.State.Code)
	}
	for _, z := range in.AvailabilityZones {
		lz := platform.LBZone{Zone: awssdk.ToString(z.ZoneName), Subnet: awssdk.ToString(z.SubnetId)}
		for _, a := range z.LoadBalancerAddresses {
			lz.Addresses = appendNew(lz.Addresses, awssdk.ToString(a.IpAddress), awssdk.ToString(a.PrivateIPv4Address), awssdk.ToString(a.IPv6Address))
		}
		out.Zones = append(out.Zones, lz)
	}
	return out
}

func tgFrom(region string, in elbtypes.TargetGroup) platform.LBTargetGroup {
	return platform.LBTargetGroup{ID: awssdk.ToString(in.TargetGroupArn), Name: awssdk.ToString(in.TargetGroupName), Protocol: string(in.Protocol),
		Port: awssdk.ToInt32(in.Port), VPC: awssdk.ToString(in.VpcId), TargetType: string(in.TargetType),
		LoadBalancers: append([]string{}, in.LoadBalancerArns...), Region: region,
		HealthCheck: platform.LBHealthCheck{Enabled: awssdk.ToBool(in.HealthCheckEnabled), Protocol: string(in.HealthCheckProtocol),
			Port: awssdk.ToString(in.HealthCheckPort), Path: awssdk.ToString(in.HealthCheckPath),
			IntervalSeconds: awssdk.ToInt32(in.HealthCheckIntervalSeconds), TimeoutSeconds: awssdk.ToInt32(in.HealthCheckTimeoutSeconds),
			HealthyThreshold: awssdk.ToInt32(in.HealthyThresholdCount), UnhealthyThreshold: awssdk.ToInt32(in.UnhealthyThresholdCount)}}
}

func listenerFrom(in elbtypes.Listener) platform.LBListener {
	out := platform.LBListener{ID: awssdk.ToString(in.ListenerArn), LoadBalancer: awssdk.ToString(in.LoadBalancerArn),
		Protocol: string(in.Protocol), Port: awssdk.ToInt32(in.Port), TargetGroups: []string{}, Certificates: []string{}}
	if len(in.DefaultActions) > 0 {
		// The first action in order is the one that applies.
		acts := slices.Clone(in.DefaultActions)
		slices.SortStableFunc(acts, func(a, b elbtypes.Action) int { return int(awssdk.ToInt32(a.Order)) - int(awssdk.ToInt32(b.Order)) })
		a := acts[0]
		for _, x := range acts {
			if x.Type == elbtypes.ActionTypeEnumForward {
				a = x
				break
			}
		}
		out.DefaultAction = string(a.Type)
		// Both forms are reported (observed: TargetGroupArn and a
		// ForwardConfig of one group at once); either may be alone.
		if v := awssdk.ToString(a.TargetGroupArn); v != "" {
			out.TargetGroups = appendNew(out.TargetGroups, v)
		}
		if a.ForwardConfig != nil {
			for _, t := range a.ForwardConfig.TargetGroups {
				out.TargetGroups = appendNew(out.TargetGroups, awssdk.ToString(t.TargetGroupArn))
			}
		}
	}
	for _, c := range in.Certificates {
		out.Certificates = appendNew(out.Certificates, awssdk.ToString(c.CertificateArn))
	}
	return out
}

func elbTags(tags map[string]string) []elbtypes.Tag {
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var out []elbtypes.Tag
	for _, k := range keys {
		out = append(out, elbtypes.Tag{Key: awssdk.String(k), Value: awssdk.String(tags[k])})
	}
	return out
}

func targetDescriptions(targets []platform.LBTargetSpec) []elbtypes.TargetDescription {
	out := make([]elbtypes.TargetDescription, 0, len(targets))
	for _, t := range targets {
		d := elbtypes.TargetDescription{Id: awssdk.String(t.ID)}
		if t.Port != 0 {
			d.Port = awssdk.Int32(t.Port)
		}
		out = append(out, d)
	}
	return out
}

func forwardTo(tg string) []elbtypes.Action {
	return []elbtypes.Action{{Type: elbtypes.ActionTypeEnumForward, TargetGroupArn: awssdk.String(tg)}}
}

// ------------------------------------------------------ load balancers

// describeLBs runs DescribeLoadBalancers page by page.
func (c *client) describeLBs(ctx context.Context, region string, in *elb.DescribeLoadBalancersInput) ([]platform.LoadBalancer, error) {
	var out []platform.LoadBalancer
	pg := elb.NewDescribeLoadBalancersPaginator(c.elbFor(region), in)
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, lb := range page.LoadBalancers {
			out = append(out, lbFrom(region, lb))
		}
	}
	return out, nil
}

// ListLoadBalancers lists the load balancers of a region, every page.
func (c *client) ListLoadBalancers(ctx context.Context, region string) ([]platform.LoadBalancer, error) {
	region = c.regionOr(region)
	out, err := c.describeLBs(ctx, region, &elb.DescribeLoadBalancersInput{PageSize: awssdk.Int32(elbPageSize)})
	if err != nil {
		return nil, elbErr("DescribeLoadBalancers", region, err)
	}
	return out, nil
}

// FindLoadBalancer finds a load balancer by name or ARN. A name or ARN that
// does not exist, or that is malformed (ValidationError), is nil.
func (c *client) FindLoadBalancer(ctx context.Context, region, ref string) (*platform.LoadBalancer, error) {
	region = c.regionOr(region)
	in := &elb.DescribeLoadBalancersInput{Names: []string{ref}}
	if isELBARN(ref, "loadbalancer") {
		in = &elb.DescribeLoadBalancersInput{LoadBalancerArns: []string{ref}}
	}
	out, err := c.describeLBs(ctx, region, in)
	if err != nil {
		if elbNotFound(err) || platform.HasErrorCode(err, errELBValidation) {
			return nil, nil
		}
		return nil, elbErr("DescribeLoadBalancers", region, err)
	}
	for i := range out {
		if out[i].ID == ref || out[i].Name == ref {
			return &out[i], nil
		}
	}
	return nil, nil
}

// normalizeDNS compares DNS names without case and trailing dot.
func normalizeDNS(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// looksLikeDNSName reports whether ref is a DNS name: load balancer names
// hold no dots.
func looksLikeDNSName(ref string) bool {
	return strings.Contains(ref, ".") && !strings.HasPrefix(ref, "arn:")
}

var regionLabel = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d+$`)

// dnsRegion returns the region a load balancer DNS name holds
// (name-id.elb.<region>.amazonaws.com, name-id.<region>.elb.amazonaws.com),
// or "".
func dnsRegion(dns string) string {
	labels := strings.Split(normalizeDNS(dns), ".")
	for i, l := range labels {
		if l != "elb" {
			continue
		}
		if i+1 < len(labels) && regionLabel.MatchString(labels[i+1]) {
			return labels[i+1]
		}
		if i > 0 && regionLabel.MatchString(labels[i-1]) {
			return labels[i-1]
		}
	}
	return ""
}

// FindLoadBalancerByDNS finds the load balancer of a region whose DNS name
// is dns (compared without case and trailing dot).
func (c *client) FindLoadBalancerByDNS(ctx context.Context, region, dns string) (*platform.LoadBalancer, error) {
	all, err := c.ListLoadBalancers(ctx, region)
	if err != nil {
		return nil, err
	}
	for i := range all {
		if normalizeDNS(all[i].DNSName) == normalizeDNS(dns) {
			return &all[i], nil
		}
	}
	return nil, nil
}

// CreateLoadBalancer creates a load balancer. An empty list of security
// groups is left out of the request: a Network Load Balancer created so has
// none, and can never get any.
func (c *client) CreateLoadBalancer(ctx context.Context, spec platform.LoadBalancerSpec) (platform.LoadBalancer, error) {
	region := c.regionOr(spec.Region)
	in := &elb.CreateLoadBalancerInput{Name: awssdk.String(spec.Name), Subnets: spec.Subnets,
		Type: elbtypes.LoadBalancerTypeEnum(spec.Type), Scheme: elbtypes.LoadBalancerSchemeEnum(spec.Scheme),
		IpAddressType: elbtypes.IpAddressType(spec.IPAddressType), Tags: elbTags(spec.Tags)}
	if len(spec.SecurityGroups) > 0 {
		in.SecurityGroups = spec.SecurityGroups
	}
	out, err := c.elbFor(region).CreateLoadBalancer(ctx, in)
	if err != nil {
		return platform.LoadBalancer{}, elbErr("CreateLoadBalancer", region, err)
	}
	if len(out.LoadBalancers) == 0 {
		return platform.LoadBalancer{}, fmt.Errorf("elasticloadbalancing:CreateLoadBalancer in %s returned no load balancer", region)
	}
	return lbFrom(region, out.LoadBalancers[0]), nil
}

// DeleteLoadBalancer deletes a load balancer; its listeners go with it,
// its target groups stay. Deleting one that is gone succeeds.
func (c *client) DeleteLoadBalancer(ctx context.Context, region, id string) error {
	region = c.regionOr(region)
	_, err := c.elbFor(region).DeleteLoadBalancer(ctx, &elb.DeleteLoadBalancerInput{LoadBalancerArn: awssdk.String(id)})
	return elbErr("DeleteLoadBalancer", region, err)
}

// SetLoadBalancerSecurityGroups replaces the security groups of a load
// balancer.
func (c *client) SetLoadBalancerSecurityGroups(ctx context.Context, region, id string, groups []string) error {
	region = c.regionOr(region)
	_, err := c.elbFor(region).SetSecurityGroups(ctx, &elb.SetSecurityGroupsInput{LoadBalancerArn: awssdk.String(id), SecurityGroups: groups})
	return elbErr("SetSecurityGroups", region, err)
}

// SetLoadBalancerSubnets replaces the subnets of a load balancer.
func (c *client) SetLoadBalancerSubnets(ctx context.Context, region, id string, subnets []string) error {
	region = c.regionOr(region)
	_, err := c.elbFor(region).SetSubnets(ctx, &elb.SetSubnetsInput{LoadBalancerArn: awssdk.String(id), Subnets: subnets})
	return elbErr("SetSubnets", region, err)
}

// SetLoadBalancerIPAddressType sets ipv4 or dualstack.
func (c *client) SetLoadBalancerIPAddressType(ctx context.Context, region, id, ipType string) error {
	region = c.regionOr(region)
	_, err := c.elbFor(region).SetIpAddressType(ctx, &elb.SetIpAddressTypeInput{LoadBalancerArn: awssdk.String(id), IpAddressType: elbtypes.IpAddressType(ipType)})
	return elbErr("SetIpAddressType", region, err)
}

// The attribute keys of LoadBalancerAttributes.
const (
	attrDeletionProtection = "deletion_protection.enabled"
	attrCrossZone          = "load_balancing.cross_zone.enabled"
)

// LoadBalancerAttributes reads the deletion protection and cross-zone
// attributes (both false by default).
func (c *client) LoadBalancerAttributes(ctx context.Context, region, id string) (platform.LoadBalancerAttributes, error) {
	region = c.regionOr(region)
	out, err := c.elbFor(region).DescribeLoadBalancerAttributes(ctx, &elb.DescribeLoadBalancerAttributesInput{LoadBalancerArn: awssdk.String(id)})
	if err != nil {
		return platform.LoadBalancerAttributes{}, elbErr("DescribeLoadBalancerAttributes", region, err)
	}
	var a platform.LoadBalancerAttributes
	for _, kv := range out.Attributes {
		v := strings.EqualFold(awssdk.ToString(kv.Value), "true")
		switch awssdk.ToString(kv.Key) {
		case attrDeletionProtection:
			a.DeletionProtection = v
		case attrCrossZone:
			a.CrossZone = v
		}
	}
	return a, nil
}

// ModifyLoadBalancerAttributes writes the attributes the change sets.
func (c *client) ModifyLoadBalancerAttributes(ctx context.Context, region, id string, change platform.LoadBalancerAttributeChange) error {
	region = c.regionOr(region)
	var attrs []elbtypes.LoadBalancerAttribute
	if change.DeletionProtection != nil {
		attrs = append(attrs, elbtypes.LoadBalancerAttribute{Key: awssdk.String(attrDeletionProtection), Value: awssdk.String(strconv.FormatBool(*change.DeletionProtection))})
	}
	if change.CrossZone != nil {
		attrs = append(attrs, elbtypes.LoadBalancerAttribute{Key: awssdk.String(attrCrossZone), Value: awssdk.String(strconv.FormatBool(*change.CrossZone))})
	}
	if len(attrs) == 0 {
		return nil
	}
	_, err := c.elbFor(region).ModifyLoadBalancerAttributes(ctx, &elb.ModifyLoadBalancerAttributesInput{LoadBalancerArn: awssdk.String(id), Attributes: attrs})
	return elbErr("ModifyLoadBalancerAttributes", region, err)
}

// lbStateWait classifies the state of a load balancer that should become
// active. active_impaired (an Application Load Balancer that routes traffic
// but lacks the resources to scale) routes traffic too: waiting longer would
// only run into the timeout.
func lbStateWait(state string) platform.WaitState {
	switch state {
	case string(elbtypes.LoadBalancerStateEnumActive), string(elbtypes.LoadBalancerStateEnumActiveImpaired):
		return platform.WaitDone
	case string(elbtypes.LoadBalancerStateEnumFailed):
		return platform.WaitFailed
	}
	return platform.KeepWaiting
}

// waitLoadBalancerActive waits until a load balancer is active (15 second
// polls); failed is a failure at once.
func (c *client) waitLoadBalancerActive(ctx context.Context, region, id, name string, timeout time.Duration) (platform.LoadBalancer, error) {
	region = c.regionOr(region)
	var last platform.LoadBalancer
	err := platform.WaitUntil(ctx, platform.WaitOptions{Resource: "load-balancer/" + name, Want: "active", Timeout: timeout, Interval: lbActivePoll, Clock: elbClock},
		func(ctx context.Context) (platform.WaitState, string, error) {
			lb, err := c.FindLoadBalancer(ctx, region, id)
			if err != nil {
				return 0, "", err
			}
			if lb == nil {
				return 0, "", fmt.Errorf("%w: load balancer %s disappeared while waiting for it to become active", platform.ErrNotFound, name)
			}
			last = *lb
			return lbStateWait(lb.State), lb.State, nil
		})
	return last, err
}

// waitLoadBalancerGone waits until a deleted load balancer is no longer
// listed.
func (c *client) waitLoadBalancerGone(ctx context.Context, region, id, name string, timeout time.Duration) error {
	region = c.regionOr(region)
	return platform.WaitUntil(ctx, platform.WaitOptions{Resource: "load-balancer/" + name, Want: "deleted", Timeout: timeout, Interval: lbGonePoll, Clock: elbClock},
		func(ctx context.Context) (platform.WaitState, string, error) {
			lb, err := c.FindLoadBalancer(ctx, region, id)
			if err != nil {
				return 0, "", err
			}
			if lb == nil {
				return platform.WaitDone, "deleted", nil
			}
			return platform.KeepWaiting, lb.State, nil
		})
}

// resolveLBIPs resolves the DNS name of a load balancer, retrying every 5
// seconds for up to a minute while it does not resolve yet (a new load
// balancer answers no such host for a while). IPv4 addresses come first.
func resolveLBIPs(ctx context.Context, dns string) ([]string, error) {
	var ips []string
	err := platform.WaitUntil(ctx, platform.WaitOptions{Resource: dns, Want: "resolvable", Timeout: lbDNSTimeout, Interval: lbDNSRetry, Clock: elbClock},
		func(ctx context.Context) (platform.WaitState, string, error) {
			addrs, err := lookupHost(ctx, dns)
			if err != nil || len(addrs) == 0 {
				status := "no addresses"
				if err != nil {
					status = err.Error()
				}
				return platform.KeepWaiting, status, nil
			}
			ips = sortIPs(addrs)
			return platform.WaitDone, "", nil
		})
	return ips, err
}

// sortIPs sorts addresses, IPv4 before IPv6.
func sortIPs(addrs []string) []string {
	out := slices.Clone(addrs)
	slices.SortFunc(out, func(a, b string) int {
		pa, ea := netip.ParseAddr(a)
		pb, eb := netip.ParseAddr(b)
		if ea != nil || eb != nil {
			return strings.Compare(a, b)
		}
		if pa.Is4() != pb.Is4() {
			if pa.Is4() {
				return -1
			}
			return 1
		}
		return pa.Compare(pb)
	})
	return slices.Compact(out)
}

// ------------------------------------------------------- target groups

func (c *client) describeTGs(ctx context.Context, region string, in *elb.DescribeTargetGroupsInput) ([]platform.LBTargetGroup, error) {
	var out []platform.LBTargetGroup
	pg := elb.NewDescribeTargetGroupsPaginator(c.elbFor(region), in)
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, tg := range page.TargetGroups {
			out = append(out, tgFrom(region, tg))
		}
	}
	return out, nil
}

// ListTargetGroups lists the target groups of a region, or of the load
// balancer lb. Names, ARNs and a load balancer cannot be combined in one
// request, so only one is ever sent.
func (c *client) ListTargetGroups(ctx context.Context, region, lb string) ([]platform.LBTargetGroup, error) {
	region = c.regionOr(region)
	in := &elb.DescribeTargetGroupsInput{PageSize: awssdk.Int32(elbPageSize)}
	if lb != "" {
		in.LoadBalancerArn = awssdk.String(lb)
	}
	out, err := c.describeTGs(ctx, region, in)
	if err != nil {
		return nil, elbErr("DescribeTargetGroups", region, err)
	}
	return out, nil
}

// FindTargetGroup finds a target group by name or ARN; a missing or
// malformed one is nil.
func (c *client) FindTargetGroup(ctx context.Context, region, ref string) (*platform.LBTargetGroup, error) {
	region = c.regionOr(region)
	in := &elb.DescribeTargetGroupsInput{Names: []string{ref}}
	if isELBARN(ref, "targetgroup") {
		in = &elb.DescribeTargetGroupsInput{TargetGroupArns: []string{ref}}
	}
	out, err := c.describeTGs(ctx, region, in)
	if err != nil {
		if elbNotFound(err) || platform.HasErrorCode(err, errELBValidation) {
			return nil, nil
		}
		return nil, elbErr("DescribeTargetGroups", region, err)
	}
	for i := range out {
		if out[i].ID == ref || out[i].Name == ref {
			return &out[i], nil
		}
	}
	return nil, nil
}

// CreateTargetGroup creates a target group. Creating one that exists with
// the same settings returns it; other settings are DuplicateTargetGroupName.
func (c *client) CreateTargetGroup(ctx context.Context, spec platform.TargetGroupSpec) (platform.LBTargetGroup, error) {
	region := c.regionOr(spec.Region)
	in := &elb.CreateTargetGroupInput{Name: awssdk.String(spec.Name), Protocol: elbtypes.ProtocolEnum(spec.Protocol), Port: awssdk.Int32(spec.Port),
		VpcId: awssdk.String(spec.VPC), TargetType: elbtypes.TargetTypeEnum(spec.TargetType), Tags: elbTags(spec.Tags)}
	if spec.HealthCheckProtocol != "" {
		in.HealthCheckProtocol = elbtypes.ProtocolEnum(spec.HealthCheckProtocol)
	}
	if spec.HealthCheckPort != "" {
		in.HealthCheckPort = awssdk.String(spec.HealthCheckPort)
	}
	if spec.HealthCheckInterval > 0 {
		in.HealthCheckIntervalSeconds = awssdk.Int32(spec.HealthCheckInterval)
	}
	out, err := c.elbFor(region).CreateTargetGroup(ctx, in)
	if err != nil {
		return platform.LBTargetGroup{}, elbErr("CreateTargetGroup", region, err)
	}
	if len(out.TargetGroups) == 0 {
		return platform.LBTargetGroup{}, fmt.Errorf("elasticloadbalancing:CreateTargetGroup in %s returned no target group", region)
	}
	return tgFrom(region, out.TargetGroups[0]), nil
}

// ModifyTargetGroupHealthCheck changes the health check of a group.
func (c *client) ModifyTargetGroupHealthCheck(ctx context.Context, region, id string, change platform.HealthCheckChange) error {
	region = c.regionOr(region)
	in := &elb.ModifyTargetGroupInput{TargetGroupArn: awssdk.String(id)}
	if change.Protocol != "" {
		in.HealthCheckProtocol = elbtypes.ProtocolEnum(change.Protocol)
	}
	if change.Interval > 0 {
		in.HealthCheckIntervalSeconds = awssdk.Int32(change.Interval)
	}
	_, err := c.elbFor(region).ModifyTargetGroup(ctx, in)
	return elbErr("ModifyTargetGroup", region, err)
}

// DeleteTargetGroup deletes a target group; deleting one that is gone
// succeeds, one a listener forwards to is ResourceInUse.
func (c *client) DeleteTargetGroup(ctx context.Context, region, id string) error {
	region = c.regionOr(region)
	_, err := c.elbFor(region).DeleteTargetGroup(ctx, &elb.DeleteTargetGroupInput{TargetGroupArn: awssdk.String(id)})
	return elbErr("DeleteTargetGroup", region, err)
}

// TargetHealth lists the targets of a group with their health.
func (c *client) TargetHealth(ctx context.Context, region, id string) ([]platform.LBTarget, error) {
	region = c.regionOr(region)
	out, err := c.elbFor(region).DescribeTargetHealth(ctx, &elb.DescribeTargetHealthInput{TargetGroupArn: awssdk.String(id)})
	if err != nil {
		return nil, elbErr("DescribeTargetHealth", region, err)
	}
	targets := []platform.LBTarget{}
	for _, d := range out.TargetHealthDescriptions {
		var t platform.LBTarget
		if d.Target != nil {
			t.ID, t.Port, t.Zone = awssdk.ToString(d.Target.Id), awssdk.ToInt32(d.Target.Port), awssdk.ToString(d.Target.AvailabilityZone)
		}
		if d.TargetHealth != nil {
			t.State, t.Reason, t.Description = string(d.TargetHealth.State), string(d.TargetHealth.Reason), awssdk.ToString(d.TargetHealth.Description)
		}
		targets = append(targets, t)
	}
	return targets, nil
}

// RegisterTargets registers targets; registering one twice succeeds.
func (c *client) RegisterTargets(ctx context.Context, region, id string, targets []platform.LBTargetSpec) error {
	region = c.regionOr(region)
	_, err := c.elbFor(region).RegisterTargets(ctx, &elb.RegisterTargetsInput{TargetGroupArn: awssdk.String(id), Targets: targetDescriptions(targets)})
	return elbErr("RegisterTargets", region, err)
}

// DeregisterTargets deregisters targets (they drain first); deregistering
// one that is not registered succeeds.
func (c *client) DeregisterTargets(ctx context.Context, region, id string, targets []platform.LBTargetSpec) error {
	region = c.regionOr(region)
	_, err := c.elbFor(region).DeregisterTargets(ctx, &elb.DeregisterTargetsInput{TargetGroupArn: awssdk.String(id), Targets: targetDescriptions(targets)})
	return elbErr("DeregisterTargets", region, err)
}

// ----------------------------------------------------------- listeners

func (c *client) describeListeners(ctx context.Context, region string, in *elb.DescribeListenersInput) ([]platform.LBListener, error) {
	var out []platform.LBListener
	pg := elb.NewDescribeListenersPaginator(c.elbFor(region), in)
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, l := range page.Listeners {
			out = append(out, listenerFrom(l))
		}
	}
	return out, nil
}

// ListListeners lists the listeners of a load balancer, every page, by
// port.
func (c *client) ListListeners(ctx context.Context, region, lb string) ([]platform.LBListener, error) {
	region = c.regionOr(region)
	out, err := c.describeListeners(ctx, region, &elb.DescribeListenersInput{LoadBalancerArn: awssdk.String(lb), PageSize: awssdk.Int32(elbPageSize)})
	if err != nil {
		return nil, elbErr("DescribeListeners", region, err)
	}
	slices.SortFunc(out, func(a, b platform.LBListener) int { return int(a.Port) - int(b.Port) })
	if out == nil {
		out = []platform.LBListener{}
	}
	return out, nil
}

// FindListener finds a listener by ARN; a missing or malformed one is nil.
func (c *client) FindListener(ctx context.Context, region, id string) (*platform.LBListener, error) {
	region = c.regionOr(region)
	out, err := c.describeListeners(ctx, region, &elb.DescribeListenersInput{ListenerArns: []string{id}})
	if err != nil {
		if elbNotFound(err) || platform.HasErrorCode(err, errELBValidation) {
			return nil, nil
		}
		return nil, elbErr("DescribeListeners", region, err)
	}
	for i := range out {
		if out[i].ID == id {
			return &out[i], nil
		}
	}
	return nil, nil
}

// CreateListener creates a listener that forwards to a target group.
func (c *client) CreateListener(ctx context.Context, spec platform.ListenerCreateSpec) (platform.LBListener, error) {
	region := c.regionOr(spec.Region)
	in := &elb.CreateListenerInput{LoadBalancerArn: awssdk.String(spec.LoadBalancer), Protocol: elbtypes.ProtocolEnum(spec.Protocol),
		Port: awssdk.Int32(spec.Port), DefaultActions: forwardTo(spec.TargetGroup)}
	if spec.Certificate != "" {
		in.Certificates = []elbtypes.Certificate{{CertificateArn: awssdk.String(spec.Certificate)}}
	}
	out, err := c.elbFor(region).CreateListener(ctx, in)
	if err != nil {
		return platform.LBListener{}, elbErr("CreateListener", region, err)
	}
	if len(out.Listeners) == 0 {
		return platform.LBListener{}, fmt.Errorf("elasticloadbalancing:CreateListener in %s returned no listener", region)
	}
	return listenerFrom(out.Listeners[0]), nil
}

// ModifyListener changes a listener in place (no interruption, unlike a
// delete and create).
func (c *client) ModifyListener(ctx context.Context, region, id, protocol, targetGroup string) (platform.LBListener, error) {
	region = c.regionOr(region)
	in := &elb.ModifyListenerInput{ListenerArn: awssdk.String(id)}
	if protocol != "" {
		in.Protocol = elbtypes.ProtocolEnum(protocol)
	}
	if targetGroup != "" {
		in.DefaultActions = forwardTo(targetGroup)
	}
	out, err := c.elbFor(region).ModifyListener(ctx, in)
	if err != nil {
		return platform.LBListener{}, elbErr("ModifyListener", region, err)
	}
	if len(out.Listeners) == 0 {
		return platform.LBListener{}, nil
	}
	return listenerFrom(out.Listeners[0]), nil
}

// DeleteListener deletes a listener.
func (c *client) DeleteListener(ctx context.Context, region, id string) error {
	region = c.regionOr(region)
	_, err := c.elbFor(region).DeleteListener(ctx, &elb.DeleteListenerInput{ListenerArn: awssdk.String(id)})
	return elbErr("DeleteListener", region, err)
}
