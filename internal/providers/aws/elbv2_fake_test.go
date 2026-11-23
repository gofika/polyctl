package aws

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

// fakeLB is a load balancer of the fake ELBv2 API. A new one is
// provisioning for polls DescribeLoadBalancers answers, then active (or
// failed when fail is set).
type fakeLB struct {
	lb    elbtypes.LoadBalancer
	polls int
	fail  bool
	attrs map[string]string
}

type fakeTarget struct {
	id    string
	port  int32
	state string
}

type fakeTG struct {
	tg      elbtypes.TargetGroup
	targets []*fakeTarget
}

// fakeELBs is the ELBv2 part of the shared fake state, with the behaviour
// observed on the real API (see the comments of elbv2.go): Names lookups of
// missing resources are NotFound errors, duplicate creates with the same
// settings return the existing resource, a Network Load Balancer created
// without security groups never gets any.
type fakeELBs struct {
	lbs       map[string][]*fakeLB
	tgs       map[string][]*fakeTG
	listeners map[string][]elbtypes.Listener
	// subnetAZ maps a subnet to its zone; others are in <region>a.
	subnetAZ map[string]string
	calls    []string
	// errs fail the next calls of a name, one error per call.
	errs map[string][]error
	// hooks run once, at the next call of a name, before it is answered
	// (another writer acting meanwhile).
	hooks map[string]func(e *fakeELBs, region string)
	// lbPolls is how many describes a new load balancer stays provisioning.
	lbPolls  int
	lbPage   int
	creates  []*elb.CreateLoadBalancerInput
	tgInputs []*elb.CreateTargetGroupInput
	nextID   int
}

func (e *fakeELBs) init() {
	if e.lbs == nil {
		e.lbs, e.tgs, e.listeners = map[string][]*fakeLB{}, map[string][]*fakeTG{}, map[string][]elbtypes.Listener{}
		e.errs = map[string][]error{}
		e.hooks = map[string]func(e *fakeELBs, region string){}
		e.subnetAZ = map[string]string{}
		e.lbPolls = 1
	}
}

// call records a call and returns its injected error, if any.
func (f *fakeELB) call(name string) (*fakeELBs, error) {
	e := &f.shared.elb
	e.init()
	e.calls = append(e.calls, f.region+":"+name)
	if h := e.hooks[name]; h != nil {
		delete(e.hooks, name)
		h(e, f.region)
	}
	if q := e.errs[name]; len(q) > 0 {
		e.errs[name] = q[1:]
		if q[0] != nil {
			return e, q[0]
		}
	}
	if err := f.shared.find.regionErr[f.region]; err != nil {
		return e, err
	}
	return e, nil
}

func (e *fakeELBs) id() string {
	e.nextID++
	return fmt.Sprintf("%016x", 0xabc000+e.nextID)
}

func validation(msg string) error { return &fakeAPIError{"ValidationError", msg} }

func (e *fakeELBs) findLB(region, ref string) *fakeLB {
	for _, l := range e.lbs[region] {
		if awssdk.ToString(l.lb.LoadBalancerArn) == ref || awssdk.ToString(l.lb.LoadBalancerName) == ref {
			return l
		}
	}
	return nil
}

func (e *fakeELBs) findTG(region, ref string) *fakeTG {
	for _, t := range e.tgs[region] {
		if awssdk.ToString(t.tg.TargetGroupArn) == ref || awssdk.ToString(t.tg.TargetGroupName) == ref {
			return t
		}
	}
	return nil
}

func (e *fakeELBs) zoneOf(region, subnet string) string {
	if z, ok := e.subnetAZ[subnet]; ok {
		return z
	}
	return region + "a"
}

func lbNotFound(what string) error {
	return &elbtypes.LoadBalancerNotFoundException{Message: awssdk.String("Load balancers '[" + what + "]' not found")}
}

func tgNotFound(what string) error {
	return &elbtypes.TargetGroupNotFoundException{Message: awssdk.String("Target groups '[" + what + "]' not found")}
}

func (f *fakeELB) DescribeLoadBalancers(_ context.Context, in *elb.DescribeLoadBalancersInput, _ ...func(*elb.Options)) (*elb.DescribeLoadBalancersOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	e, err := f.call("DescribeLoadBalancers")
	if err != nil {
		return nil, err
	}
	if len(in.Names) > 0 && len(in.LoadBalancerArns) > 0 {
		return nil, validation("Load balancer names and load balancer ARNs cannot be specified at the same time")
	}
	if ps := awssdk.ToInt32(in.PageSize); ps < 0 || ps > 400 {
		return nil, validation("PageSize out of range")
	}
	var match []elbtypes.LoadBalancer
	refs := append(slices.Clone(in.Names), in.LoadBalancerArns...)
	if len(refs) == 0 {
		match = append(match, f.shared.find.lbs[f.region]...)
	}
	for _, l := range e.lbs[f.region] {
		if len(refs) > 0 && !slices.Contains(refs, awssdk.ToString(l.lb.LoadBalancerName)) && !slices.Contains(refs, awssdk.ToString(l.lb.LoadBalancerArn)) {
			continue
		}
		if l.lb.State.Code == elbtypes.LoadBalancerStateEnumProvisioning {
			if l.polls <= 0 {
				l.lb.State.Code = elbtypes.LoadBalancerStateEnumActive
				if l.fail {
					l.lb.State.Code = elbtypes.LoadBalancerStateEnumFailed
				}
			}
			l.polls--
		}
		match = append(match, l.lb)
	}
	if len(refs) > 0 && len(match) == 0 {
		return nil, lbNotFound(strings.Join(refs, ", "))
	}
	start := 0
	if in.Marker != nil {
		start, _ = strconv.Atoi(*in.Marker)
	}
	end := len(match)
	out := &elb.DescribeLoadBalancersOutput{}
	if e.lbPage > 0 && start+e.lbPage < end {
		end = start + e.lbPage
		out.NextMarker = awssdk.String(strconv.Itoa(end))
	}
	out.LoadBalancers = match[start:end]
	return out, nil
}

func (f *fakeELB) CreateLoadBalancer(_ context.Context, in *elb.CreateLoadBalancerInput, _ ...func(*elb.Options)) (*elb.CreateLoadBalancerOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	e, err := f.call("CreateLoadBalancer")
	if err != nil {
		return nil, err
	}
	e.creates = append(e.creates, in)
	name := awssdk.ToString(in.Name)
	if l := e.findLB(f.region, name); l != nil {
		var subnets []string
		for _, z := range l.lb.AvailabilityZones {
			subnets = append(subnets, awssdk.ToString(z.SubnetId))
		}
		if l.lb.Type == in.Type && l.lb.Scheme == in.Scheme && slices.Equal(subnets, in.Subnets) {
			return &elb.CreateLoadBalancerOutput{LoadBalancers: []elbtypes.LoadBalancer{l.lb}}, nil
		}
		return nil, &elbtypes.DuplicateLoadBalancerNameException{Message: awssdk.String("A load balancer with the same name '" + name + "' exists, but with different settings")}
	}
	id := e.id()
	kind := "net"
	if in.Type == elbtypes.LoadBalancerTypeEnumApplication {
		kind = "app"
	}
	lb := elbtypes.LoadBalancer{LoadBalancerArn: awssdk.String(fmt.Sprintf("arn:aws:elasticloadbalancing:%s:123456789012:loadbalancer/%s/%s/%s", f.region, kind, name, id)),
		LoadBalancerName: in.Name, Type: in.Type, Scheme: in.Scheme, IpAddressType: in.IpAddressType, VpcId: awssdk.String("vpc-0abc"),
		DNSName:        awssdk.String(fmt.Sprintf("%s-%s.elb.%s.amazonaws.com", name, id, f.region)),
		State:          &elbtypes.LoadBalancerState{Code: elbtypes.LoadBalancerStateEnumProvisioning},
		SecurityGroups: in.SecurityGroups}
	for _, sn := range in.Subnets {
		lb.AvailabilityZones = append(lb.AvailabilityZones, elbtypes.AvailabilityZone{SubnetId: awssdk.String(sn), ZoneName: awssdk.String(e.zoneOf(f.region, sn))})
	}
	e.lbs[f.region] = append(e.lbs[f.region], &fakeLB{lb: lb, polls: e.lbPolls, attrs: map[string]string{}})
	return &elb.CreateLoadBalancerOutput{LoadBalancers: []elbtypes.LoadBalancer{lb}}, nil
}

func (f *fakeELB) DeleteLoadBalancer(_ context.Context, in *elb.DeleteLoadBalancerInput, _ ...func(*elb.Options)) (*elb.DeleteLoadBalancerOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	e, err := f.call("DeleteLoadBalancer")
	if err != nil {
		return nil, err
	}
	arn := awssdk.ToString(in.LoadBalancerArn)
	l := e.findLB(f.region, arn)
	if l == nil {
		return &elb.DeleteLoadBalancerOutput{}, nil
	}
	if l.attrs[attrDeletionProtection] == "true" {
		return nil, &elbtypes.OperationNotPermittedException{Message: awssdk.String("Load balancer '" + arn + "' cannot be deleted because deletion protection is enabled")}
	}
	e.lbs[f.region] = slices.DeleteFunc(e.lbs[f.region], func(x *fakeLB) bool { return x == l })
	e.listeners[f.region] = slices.DeleteFunc(e.listeners[f.region], func(x elbtypes.Listener) bool { return awssdk.ToString(x.LoadBalancerArn) == arn })
	for _, t := range e.tgs[f.region] {
		t.tg.LoadBalancerArns = slices.DeleteFunc(t.tg.LoadBalancerArns, func(x string) bool { return x == arn })
	}
	return &elb.DeleteLoadBalancerOutput{}, nil
}

func (f *fakeELB) SetSecurityGroups(_ context.Context, in *elb.SetSecurityGroupsInput, _ ...func(*elb.Options)) (*elb.SetSecurityGroupsOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	e, err := f.call("SetSecurityGroups")
	if err != nil {
		return nil, err
	}
	l := e.findLB(f.region, awssdk.ToString(in.LoadBalancerArn))
	if l == nil {
		return nil, lbNotFound(awssdk.ToString(in.LoadBalancerArn))
	}
	if len(l.lb.SecurityGroups) == 0 && l.lb.Type == elbtypes.LoadBalancerTypeEnumNetwork {
		return nil, &elbtypes.InvalidConfigurationRequestException{Message: awssdk.String("You cannot set security groups on a Network Load Balancer which was created without any security groups.")}
	}
	if len(in.SecurityGroups) == 0 {
		return nil, validation("A security group must be specified")
	}
	l.lb.SecurityGroups = in.SecurityGroups
	return &elb.SetSecurityGroupsOutput{SecurityGroupIds: in.SecurityGroups}, nil
}

func (f *fakeELB) SetSubnets(_ context.Context, in *elb.SetSubnetsInput, _ ...func(*elb.Options)) (*elb.SetSubnetsOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	e, err := f.call("SetSubnets")
	if err != nil {
		return nil, err
	}
	l := e.findLB(f.region, awssdk.ToString(in.LoadBalancerArn))
	if l == nil {
		return nil, lbNotFound(awssdk.ToString(in.LoadBalancerArn))
	}
	l.lb.AvailabilityZones = nil
	for _, sn := range in.Subnets {
		l.lb.AvailabilityZones = append(l.lb.AvailabilityZones, elbtypes.AvailabilityZone{SubnetId: awssdk.String(sn), ZoneName: awssdk.String(e.zoneOf(f.region, sn))})
	}
	return &elb.SetSubnetsOutput{}, nil
}

func (f *fakeELB) SetIpAddressType(_ context.Context, in *elb.SetIpAddressTypeInput, _ ...func(*elb.Options)) (*elb.SetIpAddressTypeOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	e, err := f.call("SetIpAddressType")
	if err != nil {
		return nil, err
	}
	l := e.findLB(f.region, awssdk.ToString(in.LoadBalancerArn))
	if l == nil {
		return nil, lbNotFound(awssdk.ToString(in.LoadBalancerArn))
	}
	if in.IpAddressType == elbtypes.IpAddressTypeDualstack {
		return nil, validation("You must specify subnets with an associated IPv6 CIDR block.")
	}
	l.lb.IpAddressType = in.IpAddressType
	return &elb.SetIpAddressTypeOutput{IpAddressType: in.IpAddressType}, nil
}

func (f *fakeELB) DescribeLoadBalancerAttributes(_ context.Context, in *elb.DescribeLoadBalancerAttributesInput, _ ...func(*elb.Options)) (*elb.DescribeLoadBalancerAttributesOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	e, err := f.call("DescribeLoadBalancerAttributes")
	if err != nil {
		return nil, err
	}
	l := e.findLB(f.region, awssdk.ToString(in.LoadBalancerArn))
	if l == nil {
		return nil, lbNotFound(awssdk.ToString(in.LoadBalancerArn))
	}
	out := &elb.DescribeLoadBalancerAttributesOutput{}
	for _, k := range []string{attrDeletionProtection, attrCrossZone} {
		v := l.attrs[k]
		if v == "" {
			v = "false"
		}
		out.Attributes = append(out.Attributes, elbtypes.LoadBalancerAttribute{Key: awssdk.String(k), Value: awssdk.String(v)})
	}
	return out, nil
}

func (f *fakeELB) ModifyLoadBalancerAttributes(_ context.Context, in *elb.ModifyLoadBalancerAttributesInput, _ ...func(*elb.Options)) (*elb.ModifyLoadBalancerAttributesOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	e, err := f.call("ModifyLoadBalancerAttributes")
	if err != nil {
		return nil, err
	}
	l := e.findLB(f.region, awssdk.ToString(in.LoadBalancerArn))
	if l == nil {
		return nil, lbNotFound(awssdk.ToString(in.LoadBalancerArn))
	}
	for _, a := range in.Attributes {
		l.attrs[awssdk.ToString(a.Key)] = awssdk.ToString(a.Value)
	}
	return &elb.ModifyLoadBalancerAttributesOutput{}, nil
}

func (f *fakeELB) DescribeTargetGroups(_ context.Context, in *elb.DescribeTargetGroupsInput, _ ...func(*elb.Options)) (*elb.DescribeTargetGroupsOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	e, err := f.call("DescribeTargetGroups")
	if err != nil {
		return nil, err
	}
	n := 0
	for _, set := range []bool{len(in.Names) > 0, len(in.TargetGroupArns) > 0, in.LoadBalancerArn != nil} {
		if set {
			n++
		}
	}
	if n > 1 {
		return nil, validation("Target group names, target group ARNs, and a load balancer ARN cannot be specified at the same time")
	}
	lbArn := awssdk.ToString(in.LoadBalancerArn)
	if lbArn != "" && e.findLB(f.region, lbArn) == nil {
		return nil, lbNotFound(lbArn)
	}
	refs := append(slices.Clone(in.Names), in.TargetGroupArns...)
	out := &elb.DescribeTargetGroupsOutput{}
	for _, t := range e.tgs[f.region] {
		if len(refs) > 0 && !slices.Contains(refs, awssdk.ToString(t.tg.TargetGroupName)) && !slices.Contains(refs, awssdk.ToString(t.tg.TargetGroupArn)) {
			continue
		}
		if lbArn != "" && !slices.Contains(t.tg.LoadBalancerArns, lbArn) {
			continue
		}
		out.TargetGroups = append(out.TargetGroups, t.tg)
	}
	if len(refs) > 0 && len(out.TargetGroups) == 0 {
		return nil, tgNotFound(strings.Join(refs, ", "))
	}
	return out, nil
}

func (f *fakeELB) CreateTargetGroup(_ context.Context, in *elb.CreateTargetGroupInput, _ ...func(*elb.Options)) (*elb.CreateTargetGroupOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	e, err := f.call("CreateTargetGroup")
	if err != nil {
		return nil, err
	}
	e.tgInputs = append(e.tgInputs, in)
	name := awssdk.ToString(in.Name)
	if t := e.findTG(f.region, name); t != nil {
		if t.tg.Protocol == in.Protocol && awssdk.ToInt32(t.tg.Port) == awssdk.ToInt32(in.Port) && awssdk.ToString(t.tg.VpcId) == awssdk.ToString(in.VpcId) && t.tg.TargetType == in.TargetType {
			return &elb.CreateTargetGroupOutput{TargetGroups: []elbtypes.TargetGroup{t.tg}}, nil
		}
		return nil, &elbtypes.DuplicateTargetGroupNameException{Message: awssdk.String("A target group with the same name '" + name + "' exists, but with different settings")}
	}
	tg := elbtypes.TargetGroup{TargetGroupArn: awssdk.String(fmt.Sprintf("arn:aws:elasticloadbalancing:%s:123456789012:targetgroup/%s/%s", f.region, name, e.id())),
		TargetGroupName: in.Name, Protocol: in.Protocol, Port: in.Port, VpcId: in.VpcId, TargetType: in.TargetType,
		HealthCheckEnabled: awssdk.Bool(true), HealthCheckProtocol: elbtypes.ProtocolEnumTcp, HealthCheckPort: awssdk.String("traffic-port"),
		HealthCheckIntervalSeconds: awssdk.Int32(30), HealthCheckTimeoutSeconds: awssdk.Int32(10), HealthyThresholdCount: awssdk.Int32(5), UnhealthyThresholdCount: awssdk.Int32(2)}
	if in.HealthCheckProtocol != "" {
		tg.HealthCheckProtocol = in.HealthCheckProtocol
	}
	if in.HealthCheckPort != nil {
		tg.HealthCheckPort = in.HealthCheckPort
	}
	if in.HealthCheckIntervalSeconds != nil {
		tg.HealthCheckIntervalSeconds = in.HealthCheckIntervalSeconds
	}
	e.tgs[f.region] = append(e.tgs[f.region], &fakeTG{tg: tg})
	return &elb.CreateTargetGroupOutput{TargetGroups: []elbtypes.TargetGroup{tg}}, nil
}

func (f *fakeELB) ModifyTargetGroup(_ context.Context, in *elb.ModifyTargetGroupInput, _ ...func(*elb.Options)) (*elb.ModifyTargetGroupOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	e, err := f.call("ModifyTargetGroup")
	if err != nil {
		return nil, err
	}
	t := e.findTG(f.region, awssdk.ToString(in.TargetGroupArn))
	if t == nil {
		return nil, tgNotFound(awssdk.ToString(in.TargetGroupArn))
	}
	if in.HealthCheckProtocol != "" {
		t.tg.HealthCheckProtocol = in.HealthCheckProtocol
	}
	if in.HealthCheckIntervalSeconds != nil {
		t.tg.HealthCheckIntervalSeconds = in.HealthCheckIntervalSeconds
	}
	return &elb.ModifyTargetGroupOutput{TargetGroups: []elbtypes.TargetGroup{t.tg}}, nil
}

func (f *fakeELB) DeleteTargetGroup(_ context.Context, in *elb.DeleteTargetGroupInput, _ ...func(*elb.Options)) (*elb.DeleteTargetGroupOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	e, err := f.call("DeleteTargetGroup")
	if err != nil {
		return nil, err
	}
	arn := awssdk.ToString(in.TargetGroupArn)
	t := e.findTG(f.region, arn)
	if t == nil {
		return &elb.DeleteTargetGroupOutput{}, nil
	}
	if len(t.tg.LoadBalancerArns) > 0 {
		return nil, &elbtypes.ResourceInUseException{Message: awssdk.String("Target group '" + arn + "' is currently in use by a listener or a rule")}
	}
	e.tgs[f.region] = slices.DeleteFunc(e.tgs[f.region], func(x *fakeTG) bool { return x == t })
	return &elb.DeleteTargetGroupOutput{}, nil
}

func (f *fakeELB) DescribeTargetHealth(_ context.Context, in *elb.DescribeTargetHealthInput, _ ...func(*elb.Options)) (*elb.DescribeTargetHealthOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	e, err := f.call("DescribeTargetHealth")
	if err != nil {
		return nil, err
	}
	t := e.findTG(f.region, awssdk.ToString(in.TargetGroupArn))
	if t == nil {
		return nil, tgNotFound(awssdk.ToString(in.TargetGroupArn))
	}
	out := &elb.DescribeTargetHealthOutput{}
	for _, x := range t.targets {
		state := x.state
		if state == "" {
			state = "initial"
			if len(t.tg.LoadBalancerArns) == 0 {
				state = "unused"
			}
		}
		out.TargetHealthDescriptions = append(out.TargetHealthDescriptions, elbtypes.TargetHealthDescription{
			Target:       &elbtypes.TargetDescription{Id: awssdk.String(x.id), Port: awssdk.Int32(x.port), AvailabilityZone: awssdk.String(f.region + "a")},
			TargetHealth: &elbtypes.TargetHealth{State: elbtypes.TargetHealthStateEnum(state)}})
	}
	return out, nil
}

func (f *fakeELB) RegisterTargets(_ context.Context, in *elb.RegisterTargetsInput, _ ...func(*elb.Options)) (*elb.RegisterTargetsOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	e, err := f.call("RegisterTargets")
	if err != nil {
		return nil, err
	}
	t := e.findTG(f.region, awssdk.ToString(in.TargetGroupArn))
	if t == nil {
		return nil, tgNotFound(awssdk.ToString(in.TargetGroupArn))
	}
	for _, d := range in.Targets {
		id := awssdk.ToString(d.Id)
		if t.tg.TargetType == elbtypes.TargetTypeEnumInstance && !strings.HasPrefix(id, "i-") {
			return nil, validation("Instance ID '" + id + "' is not valid")
		}
		port := awssdk.ToInt32(d.Port)
		if port == 0 {
			port = awssdk.ToInt32(t.tg.Port)
		}
		found := false
		for _, x := range t.targets {
			if x.id == id && x.port == port {
				x.state, found = "", true
			}
		}
		if !found {
			t.targets = append(t.targets, &fakeTarget{id: id, port: port})
		}
	}
	return &elb.RegisterTargetsOutput{}, nil
}

func (f *fakeELB) DeregisterTargets(_ context.Context, in *elb.DeregisterTargetsInput, _ ...func(*elb.Options)) (*elb.DeregisterTargetsOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	e, err := f.call("DeregisterTargets")
	if err != nil {
		return nil, err
	}
	t := e.findTG(f.region, awssdk.ToString(in.TargetGroupArn))
	if t == nil {
		return nil, tgNotFound(awssdk.ToString(in.TargetGroupArn))
	}
	for _, d := range in.Targets {
		port := awssdk.ToInt32(d.Port)
		if port == 0 {
			port = awssdk.ToInt32(t.tg.Port)
		}
		for _, x := range t.targets {
			if x.id == awssdk.ToString(d.Id) && x.port == port {
				x.state = "draining"
			}
		}
	}
	return &elb.DeregisterTargetsOutput{}, nil
}

func (f *fakeELB) DescribeListeners(_ context.Context, in *elb.DescribeListenersInput, _ ...func(*elb.Options)) (*elb.DescribeListenersOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	e, err := f.call("DescribeListeners")
	if err != nil {
		return nil, err
	}
	lbArn := awssdk.ToString(in.LoadBalancerArn)
	if lbArn != "" && e.findLB(f.region, lbArn) == nil {
		return nil, lbNotFound(lbArn)
	}
	out := &elb.DescribeListenersOutput{}
	for _, l := range e.listeners[f.region] {
		if lbArn != "" && awssdk.ToString(l.LoadBalancerArn) != lbArn {
			continue
		}
		if len(in.ListenerArns) > 0 && !slices.Contains(in.ListenerArns, awssdk.ToString(l.ListenerArn)) {
			continue
		}
		out.Listeners = append(out.Listeners, l)
	}
	if len(in.ListenerArns) > 0 && len(out.Listeners) == 0 {
		return nil, &elbtypes.ListenerNotFoundException{Message: awssdk.String("One or more listeners not found")}
	}
	return out, nil
}

// fakeForward is a forward action as the real API reports it: both the
// target group ARN and a forward config of one group.
func fakeForward(tg string) []elbtypes.Action {
	return []elbtypes.Action{{Type: elbtypes.ActionTypeEnumForward, Order: awssdk.Int32(1), TargetGroupArn: awssdk.String(tg),
		ForwardConfig: &elbtypes.ForwardActionConfig{TargetGroups: []elbtypes.TargetGroupTuple{{TargetGroupArn: awssdk.String(tg), Weight: awssdk.Int32(1)}}}}}
}

func (e *fakeELBs) attach(region, lbArn, tgArn string) {
	if t := e.findTG(region, tgArn); t != nil && !slices.Contains(t.tg.LoadBalancerArns, lbArn) {
		t.tg.LoadBalancerArns = append(t.tg.LoadBalancerArns, lbArn)
	}
}

// detachUnused drops the load balancer of the groups no listener of it
// forwards to any more.
func (e *fakeELBs) detachUnused(region, lbArn string) {
	for _, t := range e.tgs[region] {
		used := false
		for _, l := range e.listeners[region] {
			if awssdk.ToString(l.LoadBalancerArn) == lbArn && awssdk.ToString(l.DefaultActions[0].TargetGroupArn) == awssdk.ToString(t.tg.TargetGroupArn) {
				used = true
			}
		}
		if !used {
			t.tg.LoadBalancerArns = slices.DeleteFunc(t.tg.LoadBalancerArns, func(x string) bool { return x == lbArn })
		}
	}
}

func (f *fakeELB) CreateListener(_ context.Context, in *elb.CreateListenerInput, _ ...func(*elb.Options)) (*elb.CreateListenerOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	e, err := f.call("CreateListener")
	if err != nil {
		return nil, err
	}
	lbArn := awssdk.ToString(in.LoadBalancerArn)
	l := e.findLB(f.region, lbArn)
	if l == nil {
		return nil, lbNotFound(lbArn)
	}
	if (in.Protocol == elbtypes.ProtocolEnumTls || in.Protocol == elbtypes.ProtocolEnumHttps) && len(in.Certificates) == 0 {
		return nil, validation("A certificate must be specified for TLS listeners")
	}
	tgArn := awssdk.ToString(in.DefaultActions[0].TargetGroupArn)
	if e.findTG(f.region, tgArn) == nil {
		return nil, tgNotFound(tgArn)
	}
	for _, x := range e.listeners[f.region] {
		if awssdk.ToString(x.LoadBalancerArn) == lbArn && awssdk.ToInt32(x.Port) == awssdk.ToInt32(in.Port) {
			if x.Protocol == in.Protocol && awssdk.ToString(x.DefaultActions[0].TargetGroupArn) == tgArn {
				return &elb.CreateListenerOutput{Listeners: []elbtypes.Listener{x}}, nil
			}
			return nil, &elbtypes.DuplicateListenerException{Message: awssdk.String("A listener already exists on this port for this load balancer '" + lbArn + "'")}
		}
	}
	lsArn := strings.Replace(lbArn, ":loadbalancer/", ":listener/", 1) + "/" + e.id()
	ls := elbtypes.Listener{ListenerArn: awssdk.String(lsArn), LoadBalancerArn: in.LoadBalancerArn, Port: in.Port, Protocol: in.Protocol,
		DefaultActions: fakeForward(tgArn), Certificates: in.Certificates}
	e.listeners[f.region] = append(e.listeners[f.region], ls)
	e.attach(f.region, lbArn, tgArn)
	return &elb.CreateListenerOutput{Listeners: []elbtypes.Listener{ls}}, nil
}

func (f *fakeELB) ModifyListener(_ context.Context, in *elb.ModifyListenerInput, _ ...func(*elb.Options)) (*elb.ModifyListenerOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	e, err := f.call("ModifyListener")
	if err != nil {
		return nil, err
	}
	for i, x := range e.listeners[f.region] {
		if awssdk.ToString(x.ListenerArn) != awssdk.ToString(in.ListenerArn) {
			continue
		}
		if in.Protocol != "" {
			x.Protocol = in.Protocol
		}
		if len(in.DefaultActions) > 0 {
			tgArn := awssdk.ToString(in.DefaultActions[0].TargetGroupArn)
			x.DefaultActions = fakeForward(tgArn)
			e.listeners[f.region][i] = x
			e.attach(f.region, awssdk.ToString(x.LoadBalancerArn), tgArn)
			e.detachUnused(f.region, awssdk.ToString(x.LoadBalancerArn))
		}
		e.listeners[f.region][i] = x
		return &elb.ModifyListenerOutput{Listeners: []elbtypes.Listener{x}}, nil
	}
	return nil, &elbtypes.ListenerNotFoundException{Message: awssdk.String("Listener not found")}
}

func (f *fakeELB) DeleteListener(_ context.Context, in *elb.DeleteListenerInput, _ ...func(*elb.Options)) (*elb.DeleteListenerOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	e, err := f.call("DeleteListener")
	if err != nil {
		return nil, err
	}
	arn := awssdk.ToString(in.ListenerArn)
	var lbArn string
	before := len(e.listeners[f.region])
	e.listeners[f.region] = slices.DeleteFunc(e.listeners[f.region], func(x elbtypes.Listener) bool {
		if awssdk.ToString(x.ListenerArn) == arn {
			lbArn = awssdk.ToString(x.LoadBalancerArn)
			return true
		}
		return false
	})
	if before == len(e.listeners[f.region]) {
		return nil, &elbtypes.ListenerNotFoundException{Message: awssdk.String("Listener not found")}
	}
	e.detachUnused(f.region, lbArn)
	return &elb.DeleteListenerOutput{}, nil
}
