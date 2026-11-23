package aws

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

const lbInstanceID = "i-0aaaaaaaaaaaaaaa1"

// newELBHarness is an AWS harness with the running instance site-xz7
// (vpc-0abc, subnet-0def in ap-east-1a, 10.0.1.23) and instant waits.
func newELBHarness(t *testing.T, flags app.Flags, defaults map[string]any) (*awsHarness, *fakeClock) {
	t.Helper()
	h := newAWSHarness(t, flags, defaults)
	useFakeClock(t)
	clk := useFakeELBClock(t)
	h.addInstance("ap-east-1", running(lbInstanceID, "site-xz7"))
	return h, clk
}

// elb returns the fake ELB state; callers hold no lock (tests are serial).
func (h *awsHarness) elb() *fakeELBs {
	h.ec2.mu.Lock()
	defer h.ec2.mu.Unlock()
	h.ec2.elb.init()
	return &h.ec2.elb
}

var elbWriteCalls = []string{"CreateLoadBalancer", "DeleteLoadBalancer", "SetSecurityGroups", "SetSubnets", "SetIpAddressType", "ModifyLoadBalancerAttributes",
	"CreateTargetGroup", "ModifyTargetGroup", "DeleteTargetGroup", "RegisterTargets", "DeregisterTargets", "CreateListener", "ModifyListener", "DeleteListener"}

// elbWrites lists the ELB write calls made since the last reset.
func (h *awsHarness) elbWrites() []string {
	var out []string
	for _, c := range h.elb().calls {
		_, call, _ := strings.Cut(c, ":")
		if slices.Contains(elbWriteCalls, call) {
			out = append(out, call)
		}
	}
	return out
}

func (h *awsHarness) resetELB() { h.elb().calls = nil }

type ensureOut struct {
	platform.Report
	LoadBalancer lbEnsureResult `json:"load_balancer"`
}

func (h *awsHarness) ensureOut() ensureOut {
	h.t.Helper()
	var out ensureOut
	h.jsonOut(&out)
	return out
}

func TestLBEnsureFromScratch(t *testing.T) {
	h, _ := newELBHarness(t, app.Flags{}, map[string]any{"tags": map[string]any{"team": "ops"}})
	if err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7"); err != nil {
		t.Fatalf("ensure: %v\n%s", err, h.stderr.String())
	}
	want := "CreateTargetGroup,RegisterTargets,CreateTargetGroup,RegisterTargets,CreateLoadBalancer,CreateListener,CreateListener"
	if w := strings.Join(h.elbWrites(), ","); w != want {
		t.Fatalf("writes = %s\nwant     %s", w, want)
	}
	out := h.ensureOut()
	a := actions(out.Report)
	for _, k := range []string{"target-group/site-xz7-80-target created", "target-group/site-xz7-80-target/target created", "target-group/site-xz7-443-target created",
		"load-balancer/site-xz7-lb created", "listener/site-xz7-lb:80 created", "listener/site-xz7-lb:443 created"} {
		if a[k] != 1 {
			t.Errorf("missing %q in %v", k, a)
		}
	}
	lb := out.LoadBalancer
	if lb.Name != "site-xz7-lb" || lb.State != "active" || !strings.HasSuffix(lb.DNSName, ".elb.ap-east-1.amazonaws.com") || strings.Join(lb.IPs, ",") != "203.0.113.10" ||
		len(lb.Listeners) != 2 || lb.Listeners[1].TargetGroup != "site-xz7-443-target" || lb.VPC != "vpc-0abc" {
		t.Errorf("load_balancer = %+v", lb)
	}
	e := h.elb()
	create := e.creates[0]
	if create.SecurityGroups != nil || create.Type != "network" || create.Scheme != "internet-facing" || strings.Join(create.Subnets, ",") != "subnet-0def" {
		t.Errorf("create = %+v", create)
	}
	tags := map[string]string{}
	for _, tg := range create.Tags {
		tags[awssdk.ToString(tg.Key)] = awssdk.ToString(tg.Value)
	}
	if tags["polyctl:managed"] != "true" || tags["team"] != "ops" {
		t.Errorf("tags = %v", tags)
	}
	tgIn := e.tgInputs[0]
	if tgIn.Protocol != "TCP" || awssdk.ToInt32(tgIn.Port) != 80 || awssdk.ToString(tgIn.VpcId) != "vpc-0abc" || tgIn.TargetType != "instance" ||
		tgIn.HealthCheckProtocol != "TCP" || awssdk.ToString(tgIn.HealthCheckPort) != "traffic-port" || tgIn.HealthCheckIntervalSeconds != nil {
		t.Errorf("target group input = %+v", tgIn)
	}
	t443 := e.findTG("ap-east-1", "site-xz7-443-target")
	if len(t443.targets) != 1 || t443.targets[0].id != lbInstanceID || t443.targets[0].port != 443 {
		t.Errorf("443 targets = %+v", t443.targets)
	}
	if !strings.Contains(h.stderr.String(), "created without any") || !strings.Contains(h.stderr.String(), "security-group ensure") {
		t.Errorf("stderr = %s", h.stderr.String())
	}

	// A second run writes nothing.
	h.resetELB()
	if err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7"); err != nil {
		t.Fatal(err)
	}
	if w := h.elbWrites(); len(w) != 0 {
		t.Errorf("second run writes = %v", w)
	}
	for _, c := range h.ensureOut().Changes {
		if c.Action != platform.Unchanged {
			t.Errorf("second run: %+v", c)
		}
	}
	if !strings.Contains(h.stderr.String(), "all unchanged") {
		t.Errorf("stderr = %s", h.stderr.String())
	}
	// The table ends with the DNS name and the addresses.
	h.rt.Flags.Output = "table"
	if err := h.rt.Init(); err != nil {
		t.Fatal(err)
	}
	if err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7"); err != nil {
		t.Fatal(err)
	}
	if s := h.stdout.String(); !strings.Contains(s, "RESOURCE") || !strings.Contains(s, "# load balancer\nsite-xz7-lb-") || !strings.HasSuffix(s, "\n203.0.113.10\n") {
		t.Errorf("table = %s", s)
	}
}

func TestLBEnsurePartial(t *testing.T) {
	h, _ := newELBHarness(t, app.Flags{}, nil)
	if err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7", "--skip-https"); err != nil {
		t.Fatal(err)
	}
	if lb := h.ensureOut().LoadBalancer; len(lb.Listeners) != 1 || lb.Listeners[0].Port != 80 {
		t.Errorf("skip-https = %+v", lb)
	}
	// The load balancer and port 80 are there: only 443 is added.
	h.resetELB()
	if err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7"); err != nil {
		t.Fatal(err)
	}
	if w := strings.Join(h.elbWrites(), ","); w != "CreateTargetGroup,RegisterTargets,CreateListener" {
		t.Errorf("443 writes = %s", w)
	}

	// A listener that forwards elsewhere is modified in place.
	e := h.elb()
	other := &fakeTG{tg: elbtypes.TargetGroup{TargetGroupArn: awssdk.String("arn:aws:elasticloadbalancing:ap-east-1:123456789012:targetgroup/other/1"),
		TargetGroupName: awssdk.String("other"), Protocol: "TCP", Port: awssdk.Int32(80), VpcId: awssdk.String("vpc-0abc"), TargetType: "instance"}}
	e.tgs["ap-east-1"] = append(e.tgs["ap-east-1"], other)
	for i, l := range e.listeners["ap-east-1"] {
		if awssdk.ToInt32(l.Port) == 80 {
			e.listeners["ap-east-1"][i].DefaultActions = fakeForward(awssdk.ToString(other.tg.TargetGroupArn))
		}
	}
	h.resetELB()
	if err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7"); err != nil {
		t.Fatal(err)
	}
	if w := strings.Join(h.elbWrites(), ","); w != "ModifyListener" {
		t.Errorf("modify writes = %s", w)
	}
	for _, c := range h.ensureOut().Changes {
		if c.Resource == "listener/site-xz7-lb:80" && (c.Action != platform.Updated || !strings.Contains(c.Detail, "tcp:80 -> other -> tcp:80 -> site-xz7-80-target")) {
			t.Errorf("listener row = %+v", c)
		}
	}

	// A draining target, or one on another port, is registered again.
	t80 := e.findTG("ap-east-1", "site-xz7-80-target")
	t80.targets[0].state = "draining"
	t443 := e.findTG("ap-east-1", "site-xz7-443-target")
	t443.targets[0].port = 8443
	h.resetELB()
	if err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7"); err != nil {
		t.Fatal(err)
	}
	if w := strings.Join(h.elbWrites(), ","); w != "RegisterTargets,RegisterTargets" {
		t.Errorf("register writes = %s", w)
	}
}

func TestLBEnsureDryRun(t *testing.T) {
	for _, yes := range []bool{false, true} {
		h, _ := newELBHarness(t, app.Flags{DryRun: true, Yes: yes}, nil)
		if err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7"); err != nil {
			t.Fatal(err)
		}
		if w := h.elbWrites(); len(w) != 0 {
			t.Errorf("dry run writes = %v", w)
		}
		out := h.ensureOut()
		if !out.DryRun || out.LoadBalancer.ARN != platform.Pending || out.LoadBalancer.DNSName != "" || len(out.LoadBalancer.IPs) != 0 {
			t.Errorf("dry run result = %+v", out.LoadBalancer)
		}
		for _, c := range out.Changes {
			if c.Action != platform.WouldCreate {
				t.Errorf("dry run row = %+v", c)
			}
			if c.Resource == "load-balancer/site-xz7-lb" && c.ID != platform.Pending {
				t.Errorf("lb row = %+v", c)
			}
		}
	}
	// An existing load balancer shows its DNS name in a dry run too.
	h, _ := newELBHarness(t, app.Flags{}, nil)
	if err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7", "--skip-https"); err != nil {
		t.Fatal(err)
	}
	h.rt.Flags.DryRun = true
	h.resetELB()
	if err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7"); err != nil {
		t.Fatal(err)
	}
	out := h.ensureOut()
	if w := h.elbWrites(); len(w) != 0 || out.LoadBalancer.DNSName == "" || len(out.LoadBalancer.IPs) != 1 {
		t.Errorf("dry run with lb: writes %v, %+v", w, out.LoadBalancer)
	}
	a := actions(out.Report)
	if a["listener/site-xz7-lb:443 would_create"] != 1 || a["listener/site-xz7-lb:80 unchanged"] != 1 || a["target-group/site-xz7-443-target/target would_create"] != 1 {
		t.Errorf("dry run rows = %v", a)
	}
}

func TestLBEnsureChecksBeforeWriting(t *testing.T) {
	h, _ := newELBHarness(t, app.Flags{}, nil)
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0bbbbbbbbbbbbbbb2", name: "abcdefghijklmnopqrstuvwxy", typ: "t3.nano", state: stateRunning, priv: "10.0.1.24"})
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0ccccccccccccccc3", name: "under_score", typ: "t3.nano", state: stateRunning})
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0ddddddddddddddd4", name: "stopped", typ: "t3.nano", state: stateStopped})
	cases := []struct {
		args []string
		code error // nil: general failure
		msg  string
	}{
		// 25 characters: the 443 target group would have 36.
		{[]string{"abcdefghijklmnopqrstuvwxy", "--instance", "abcdefghijklmnopqrstuvwxy"}, platform.ErrInvalidInput, "at most 32"},
		{[]string{"under_score", "--instance", "under_score"}, platform.ErrInvalidInput, "letters, digits and hyphens"},
		{[]string{"stopped", "--instance", "stopped"}, nil, "not running"},
		{[]string{"x", "--instance", "site-xz7", "--type", "application"}, platform.ErrNotSupported, "Network Load Balancers only"},
		{[]string{"x", "--instance", "site-xz7", "--listener", "tls:443"}, platform.ErrNotSupported, "tcp listeners only"},
		{[]string{"x", "--instance", "site-xz7", "--listener", "tcp"}, platform.ErrInvalidInput, "listener"},
		{[]string{"x", "--instance", "site-xz7", "--skip-https", "--listener", "tcp:80"}, app.ErrUsage, "contradict"},
		{[]string{"x"}, app.ErrUsage, "--instance is required"},
		{[]string{"x", "--instance", "site-xz7", "--no-wait", "--wait-healthy"}, app.ErrUsage, "--wait-healthy"},
	}
	for _, c := range cases {
		err := h.run(append([]string{"elbv2", "load-balancer", "ensure"}, c.args...)...)
		if err == nil || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%v = %v, want %q", c.args, err, c.msg)
			continue
		}
		if c.code != nil && !errors.Is(err, c.code) {
			t.Errorf("%v = %v, want %v", c.args, err, c.code)
		}
		if c.code == nil {
			for _, s := range []error{platform.ErrInvalidInput, app.ErrUsage, platform.ErrNotSupported, platform.ErrNotFound} {
				if errors.Is(err, s) {
					t.Errorf("%v = %v, want the general failure", c.args, err)
				}
			}
		}
		if w := h.elbWrites(); len(w) != 0 {
			t.Errorf("%v wrote %v", c.args, w)
		}
	}

	// A target group of the name with other settings: exit code 1, nothing written.
	e := h.elb()
	e.tgs["ap-east-1"] = append(e.tgs["ap-east-1"], &fakeTG{tg: elbtypes.TargetGroup{
		TargetGroupArn:  awssdk.String("arn:aws:elasticloadbalancing:ap-east-1:123456789012:targetgroup/site-xz7-443-target/9"),
		TargetGroupName: awssdk.String("site-xz7-443-target"), Protocol: "HTTP", Port: awssdk.Int32(8443), VpcId: awssdk.String("vpc-0other"), TargetType: "instance"}})
	err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7")
	if err == nil || !strings.Contains(err.Error(), "protocol HTTP (want TCP)") || !strings.Contains(err.Error(), "port 8443 (want 443)") || !strings.Contains(err.Error(), "VPC vpc-0other") {
		t.Errorf("mismatch = %v", err)
	}
	if w := h.elbWrites(); len(w) != 0 {
		t.Errorf("mismatch wrote %v", w)
	}

	// --subnet must hold one of the instance's zone.
	h.ec2.mu.Lock()
	h.ec2.find.subnets = map[string]ec2types.Subnet{
		"ap-east-1/subnet-0bbb": {SubnetId: awssdk.String("subnet-0bbb"), VpcId: awssdk.String("vpc-0abc"), AvailabilityZone: awssdk.String("ap-east-1b")},
	}
	h.ec2.mu.Unlock()
	err = h.run("elbv2", "load-balancer", "ensure", "other", "--instance", "site-xz7", "--subnet", "subnet-0bbb")
	if err == nil || !strings.Contains(err.Error(), "ap-east-1a") || errors.Is(err, platform.ErrInvalidInput) {
		t.Errorf("subnet in another zone = %v", err)
	}
	if w := h.elbWrites(); len(w) != 0 {
		t.Errorf("zone mismatch wrote %v", w)
	}
}

func TestLBEnsureRaces(t *testing.T) {
	h, _ := newELBHarness(t, app.Flags{}, nil)
	e := h.elb()
	// Another writer creates the 80 target group (same settings) between
	// the lookup and the create: DuplicateTargetGroupName, then reused.
	e.hooks["CreateTargetGroup"] = func(e *fakeELBs, region string) {
		e.tgs[region] = append(e.tgs[region], &fakeTG{tg: elbtypes.TargetGroup{
			TargetGroupArn:  awssdk.String("arn:aws:elasticloadbalancing:ap-east-1:123456789012:targetgroup/site-xz7-80-target/race"),
			TargetGroupName: awssdk.String("site-xz7-80-target"), Protocol: "TCP", Port: awssdk.Int32(80), VpcId: awssdk.String("vpc-0abc"), TargetType: "instance"}})
	}
	e.errs["CreateTargetGroup"] = []error{&elbtypes.DuplicateTargetGroupNameException{Message: awssdk.String("exists")}}
	// ... and the load balancer, with other subnets.
	e.hooks["CreateLoadBalancer"] = func(e *fakeELBs, region string) {
		e.lbs[region] = append(e.lbs[region], &fakeLB{attrs: map[string]string{}, lb: elbtypes.LoadBalancer{
			LoadBalancerArn: awssdk.String("arn:aws:elasticloadbalancing:ap-east-1:123456789012:loadbalancer/net/site-xz7-lb/race"), LoadBalancerName: awssdk.String("site-xz7-lb"),
			Type: "network", Scheme: "internet-facing", VpcId: awssdk.String("vpc-0abc"), DNSName: awssdk.String("site-xz7-lb-race.elb.ap-east-1.amazonaws.com"),
			State:             &elbtypes.LoadBalancerState{Code: "active"},
			AvailabilityZones: []elbtypes.AvailabilityZone{{ZoneName: awssdk.String("ap-east-1a"), SubnetId: awssdk.String("subnet-0zzz")}}}})
	}
	// ... and a listener on 80 that forwards elsewhere.
	e.hooks["CreateListener"] = func(e *fakeELBs, region string) {
		e.listeners[region] = append(e.listeners[region], elbtypes.Listener{ListenerArn: awssdk.String("arn:aws:elasticloadbalancing:ap-east-1:123456789012:listener/net/site-xz7-lb/race/l80"),
			LoadBalancerArn: awssdk.String("arn:aws:elasticloadbalancing:ap-east-1:123456789012:loadbalancer/net/site-xz7-lb/race"), Port: awssdk.Int32(80), Protocol: "TCP",
			DefaultActions: fakeForward("arn:aws:elasticloadbalancing:ap-east-1:123456789012:targetgroup/elsewhere/1")})
	}
	if err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7", "--skip-https"); err != nil {
		t.Fatalf("ensure: %v\n%s", err, h.stderr.String())
	}
	a := actions(h.ensureOut().Report)
	if a["target-group/site-xz7-80-target unchanged"] != 1 || a["load-balancer/site-xz7-lb unchanged"] != 1 || a["listener/site-xz7-lb:80 updated"] != 1 {
		t.Errorf("race rows = %v", a)
	}
	if w := strings.Join(h.elbWrites(), ","); w != "CreateTargetGroup,RegisterTargets,CreateLoadBalancer,CreateListener,ModifyListener" {
		t.Errorf("race writes = %s", w)
	}
}

func TestLBEnsureWaits(t *testing.T) {
	h, clk := newELBHarness(t, app.Flags{}, nil)
	h.elb().lbPolls = 3
	if err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7", "--skip-https"); err != nil {
		t.Fatal(err)
	}
	if h.ensureOut().LoadBalancer.State != "active" || len(clk.slept) == 0 || clk.slept[0] != 15*time.Second {
		t.Errorf("provisioning -> active: slept %v", clk.slept)
	}

	// A timeout names the load balancer and its last state.
	h2, _ := newELBHarness(t, app.Flags{}, nil)
	h2.elb().lbPolls = 1000
	err := h2.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7", "--skip-https", "--timeout", "2m")
	var wt *platform.WaitTimeoutError
	if !errors.As(err, &wt) || wt.LastStatus != "provisioning" || !strings.Contains(err.Error(), "load-balancer/site-xz7-lb") {
		t.Errorf("timeout = %v", err)
	}
	if a := actions(h2.ensureOut().Report); a["load-balancer/site-xz7-lb failed"] != 1 {
		t.Errorf("timeout report = %v", a)
	}

	// failed is a failure at once.
	h3, _ := newELBHarness(t, app.Flags{}, nil)
	h3.elb().hooks["CreateLoadBalancer"] = func(e *fakeELBs, region string) {
		e.hooks["DescribeLoadBalancers"] = func(e *fakeELBs, region string) {
			for _, l := range e.lbs[region] {
				l.fail = true
			}
		}
	}
	if err := h3.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7", "--skip-https"); err == nil || !strings.Contains(err.Error(), "failed") || errors.As(err, &wt) {
		t.Errorf("failed = %v", err)
	}

	// --no-wait returns at once and resolves nothing.
	h4, clk4 := newELBHarness(t, app.Flags{}, nil)
	h4.elb().lbPolls = 1000
	if err := h4.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7", "--skip-https", "--no-wait"); err != nil {
		t.Fatal(err)
	}
	if out := h4.ensureOut().LoadBalancer; out.State != "provisioning" || len(out.IPs) != 0 || len(clk4.slept) != 0 {
		t.Errorf("no wait = %+v, slept %v", out, clk4.slept)
	}
}

func TestLBEnsureDNS(t *testing.T) {
	h, _ := newELBHarness(t, app.Flags{}, nil)
	calls := 0
	lookupHost = func(ctx context.Context, host string) ([]string, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("no such host")
		}
		return []string{"203.0.113.10"}, nil
	}
	if err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7", "--skip-https"); err != nil {
		t.Fatal(err)
	}
	if ips := h.ensureOut().LoadBalancer.IPs; len(ips) != 1 || calls != 2 {
		t.Errorf("ips = %v after %d lookups", ips, calls)
	}
	lookupHost = func(ctx context.Context, host string) ([]string, error) { return nil, errors.New("no such host") }
	if err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7", "--skip-https"); err != nil {
		t.Errorf("unresolvable is not a failure: %v", err)
	}
	if out := h.ensureOut().LoadBalancer; len(out.IPs) != 0 || out.DNSName == "" || !strings.Contains(h.stderr.String(), "cannot resolve") {
		t.Errorf("unresolvable = %+v\n%s", out, h.stderr.String())
	}
}

func TestLBEnsureSecurityGroups(t *testing.T) {
	h, _ := newELBHarness(t, app.Flags{}, map[string]any{"elb_security_group_ids": []any{"sg-0eee0000"}})
	if err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7", "--skip-https"); err != nil {
		t.Fatal(err)
	}
	if sgs := h.elb().creates[0].SecurityGroups; strings.Join(sgs, ",") != "sg-0eee0000" {
		t.Errorf("config security groups = %v", sgs)
	}
	// A load balancer created without security groups: --sg is skipped.
	h2, _ := newELBHarness(t, app.Flags{}, nil)
	if err := h2.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7", "--skip-https"); err != nil {
		t.Fatal(err)
	}
	h2.resetELB()
	if err := h2.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7", "--skip-https", "--sg", "sg-0eee0000"); err != nil {
		t.Fatal(err)
	}
	if a := actions(h2.ensureOut().Report); a["load-balancer/site-xz7-lb/security-groups skipped"] != 1 || len(h2.elbWrites()) != 0 {
		t.Errorf("skipped = %v, writes %v", a, h2.elbWrites())
	}
	// update --sg refuses it before writing.
	if err := h2.run("elbv2", "load-balancer", "update", "site-xz7-lb", "--sg", "sg-0eee0000"); err == nil || !strings.Contains(err.Error(), "created without security groups") || len(h2.elbWrites()) != 0 {
		t.Errorf("update --sg = %v, writes %v", err, h2.elbWrites())
	}
}

func TestLBEnsureIPTargetAndHealth(t *testing.T) {
	h, _ := newELBHarness(t, app.Flags{}, nil)
	// The target stays initial: the health wait runs out of time.
	err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7", "--skip-https", "--target-type", "ip", "--wait-healthy", "--timeout", "1m")
	var wt *platform.WaitTimeoutError
	if !errors.As(err, &wt) || !strings.Contains(wt.LastStatus, "initial") {
		t.Errorf("never healthy = %v", err)
	}
	t80 := h.elb().findTG("ap-east-1", "site-xz7-80-target")
	if t80.tg.TargetType != "ip" || t80.targets[0].id != "10.0.1.23" {
		t.Errorf("ip target = %+v", t80.targets)
	}
	t80.targets[0].state = "healthy"
	if err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7", "--skip-https", "--target-type", "ip", "--wait-healthy"); err != nil {
		t.Errorf("healthy = %v", err)
	}
}

func TestLBPagination(t *testing.T) {
	h, _ := newELBHarness(t, app.Flags{}, nil)
	for _, n := range []string{"a-lb", "b-lb"} {
		if err := h.run("elbv2", "load-balancer", "create", n, "--type", "network", "--subnet", "subnet-0def", "--region", "ap-east-1"); err != nil {
			t.Fatal(err)
		}
	}
	h.elb().lbPage = 1
	c := &client{region: "ap-east-1", elbFor: func(r string) elbAPI { return newELB(awssdk.Config{Region: r}) }}
	all, err := c.ListLoadBalancers(context.Background(), "")
	if err != nil || len(all) != 2 {
		t.Fatalf("list = %v, %v", all, err)
	}
	dns := all[1].DNSName
	lb, err := c.FindLoadBalancerByDNS(context.Background(), "", strings.ToUpper(dns)+".")
	if err != nil || lb == nil || lb.Name != "b-lb" {
		t.Errorf("by dns on page 2 = %+v, %v", lb, err)
	}
	if lb, err := c.FindLoadBalancer(context.Background(), "", "nosuch"); lb != nil || err != nil {
		t.Errorf("missing = %+v, %v", lb, err)
	}
	if lb, err := c.FindLoadBalancer(context.Background(), "", "arn:aws:elasticloadbalancing:ap-east-1:1:loadbalancer/net/x/1"); lb != nil || err != nil {
		t.Errorf("missing arn = %+v, %v", lb, err)
	}
}

func TestLBGetListAndRouting(t *testing.T) {
	h, _ := newELBHarness(t, app.Flags{}, nil)
	if err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7"); err != nil {
		t.Fatal(err)
	}
	dns := h.ensureOut().LoadBalancer.DNSName
	// By name (through the inventory), and by DNS name.
	for _, ref := range []string{"site-xz7-lb", dns} {
		if err := h.run("elbv2", "load-balancer", "get", ref); err != nil {
			t.Fatalf("get %s: %v", ref, err)
		}
		var d lbDetail
		h.jsonOut(&d)
		if d.Name != "site-xz7-lb" || len(d.Listeners) != 2 || len(d.TargetGroups) != 2 || len(d.TargetGroups[0].Targets) != 1 || d.Profile != "lab" ||
			d.TargetGroups[0].Targets[0].State != "initial" {
			t.Errorf("get %s = %+v", ref, d)
		}
	}
	if err := h.run("elbv2", "load-balancer", "get", "nosuch-lb"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing = %v", err)
	}
	// The list comes from the inventory.
	if err := h.run("elbv2", "load-balancer", "list", "--type", "network", "--name", "site-*"); err != nil {
		t.Fatal(err)
	}
	var rows []lbRow
	h.jsonOut(&rows)
	if len(rows) != 1 || rows[0].Name != "site-xz7-lb" || rows[0].DNSName != dns {
		t.Errorf("list = %+v", rows)
	}
	if err := h.run("elbv2", "load-balancer", "list", "--type", "application"); err != nil || strings.TrimSpace(h.stdout.String()) != "[]" {
		t.Errorf("empty list = %v %q", err, h.stdout.String())
	}
	if err := h.run("elbv2", "load-balancer", "list", "--type", "gateway"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("bad type = %v", err)
	}
	// Listeners and target groups.
	if err := h.run("elbv2", "listener", "list", "site-xz7-lb"); err != nil {
		t.Fatal(err)
	}
	var ls []lbListenerView
	h.jsonOut(&ls)
	if len(ls) != 2 || ls[0].Port != 80 || ls[0].TargetGroups[0] != "site-xz7-80-target" {
		t.Errorf("listeners = %+v", ls)
	}
	if err := h.run("elbv2", "listener", "get", "site-xz7-lb:443"); err != nil {
		t.Fatal(err)
	}
	var l lbListenerView
	h.jsonOut(&l)
	if l.Port != 443 || l.LoadBalancer != "site-xz7-lb" {
		t.Errorf("listener get = %+v", l)
	}
	if err := h.run("elbv2", "listener", "get", ls[0].ARN); err != nil {
		t.Errorf("listener get by arn = %v", err)
	}
	if err := h.run("elbv2", "listener", "get", "site-xz7-lb:8080"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("no listener = %v", err)
	}
	if err := h.run("elbv2", "listener", "get", "site-xz7-lb"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("no port = %v", err)
	}
	if err := h.run("elbv2", "target-group", "list", "--lb", "site-xz7-lb"); err != nil {
		t.Fatal(err)
	}
	var tgs []platform.LBTargetGroup
	h.jsonOut(&tgs)
	if len(tgs) != 2 {
		t.Errorf("target groups = %+v", tgs)
	}
	if err := h.run("elbv2", "target-group", "list", "--vpc", "vpc-0other"); err != nil || strings.TrimSpace(h.stdout.String()) != "[]" {
		t.Errorf("vpc filter = %v %q", err, h.stdout.String())
	}
	if err := h.run("elbv2", "target-group", "get", "site-xz7-80-target"); err != nil {
		t.Fatal(err)
	}
	var tg tgView
	h.jsonOut(&tg)
	if tg.Name != "site-xz7-80-target" || len(tg.Targets) != 1 || tg.HealthCheck.Port != "traffic-port" {
		t.Errorf("target group get = %+v", tg)
	}
	if err := h.run("elbv2", "target-group", "get", "nosuch"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing group = %v", err)
	}
	// The table forms render.
	h.rt.Flags.Output = "table"
	if err := h.rt.Init(); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"load-balancer", "get", "site-xz7-lb"}, {"load-balancer", "list"}, {"target-group", "get", "site-xz7-80-target"},
		{"target-group", "list"}, {"listener", "list", "site-xz7-lb"}, {"listener", "get", "site-xz7-lb:80"}} {
		if err := h.run(append([]string{"elbv2"}, args...)...); err != nil || h.stdout.Len() == 0 {
			t.Errorf("%v table = %v", args, err)
		}
	}
}

func TestLBCreateUpdate(t *testing.T) {
	h, clk := newELBHarness(t, app.Flags{}, nil)
	if err := h.run("elbv2", "load-balancer", "create", "web-lb", "--type", "network", "--subnet", "subnet-0def", "--sg", "sg-0eee0000", "--wait"); err != nil {
		t.Fatal(err)
	}
	if a := actions(h.report()); a["load-balancer/web-lb created"] != 1 || len(clk.slept) == 0 {
		t.Errorf("create = %v", a)
	}
	if err := h.run("elbv2", "load-balancer", "create", "web-lb", "--type", "network", "--subnet", "subnet-0def"); err == nil || !strings.Contains(err.Error(), "ensure") {
		t.Errorf("create twice = %v", err)
	}
	for _, args := range [][]string{{"x-lb", "--subnet", "subnet-0def"}, {"x-lb", "--type", "network"}, {"internal-x", "--type", "network", "--subnet", "subnet-0def"},
		{"x-lb", "--type", "network", "--subnet", "subnet-0def", "--scheme", "public"}} {
		if err := h.run(append([]string{"elbv2", "load-balancer", "create"}, args...)...); ExitUsageErr(err) {
			continue
		} else {
			t.Errorf("create %v = %v, want a usage error", args, err)
		}
	}
	h.resetELB()
	if err := h.run("elbv2", "load-balancer", "update", "web-lb", "--deletion-protection", "--cross-zone=false", "--sg", "sg-0eee0000", "--sg", "sg-0fff0000"); err != nil {
		t.Fatal(err)
	}
	a := actions(h.report())
	if a["load-balancer/web-lb/deletion-protection updated"] != 1 || a["load-balancer/web-lb/cross-zone unchanged"] != 1 || a["load-balancer/web-lb/security-groups updated"] != 1 {
		t.Errorf("update = %v", a)
	}
	if w := strings.Join(h.elbWrites(), ","); w != "SetSecurityGroups,ModifyLoadBalancerAttributes" {
		t.Errorf("update writes = %s", w)
	}
	if err := h.run("elbv2", "load-balancer", "update", "web-lb"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("nothing to update = %v", err)
	}
	// Whether the subnets have IPv6 blocks only AWS knows: the general failure.
	if err := h.run("elbv2", "load-balancer", "update", "web-lb", "--ip-address-type", "dualstack"); err == nil || ExitUsageErr(err) || !strings.Contains(err.Error(), "IPv6") {
		t.Errorf("dualstack without IPv6 = %v", err)
	}
	// Dry run.
	h.rt.Flags.DryRun = true
	h.resetELB()
	if err := h.run("elbv2", "load-balancer", "update", "web-lb", "--deletion-protection=false"); err != nil || len(h.elbWrites()) != 0 {
		t.Errorf("dry run update = %v, %v", err, h.elbWrites())
	}
	if a := actions(h.report()); a["load-balancer/web-lb/deletion-protection would_update"] != 1 {
		t.Errorf("dry run update = %v", a)
	}
}

// ExitUsageErr reports a usage error (exit code 2).
func ExitUsageErr(err error) bool {
	return errors.Is(err, app.ErrUsage) || errors.Is(err, platform.ErrInvalidInput)
}

func TestLBDelete(t *testing.T) {
	h, _ := newELBHarness(t, app.Flags{}, nil)
	if err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7"); err != nil {
		t.Fatal(err)
	}
	// Non-interactive without --yes: usage error, nothing deleted.
	if err := h.run("elbv2", "load-balancer", "delete", "site-xz7-lb"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("no --yes = %v", err)
	}
	// Dry run.
	h.rt.Flags.DryRun = true
	h.resetELB()
	if err := h.run("elbv2", "load-balancer", "delete", "site-xz7-lb", "--cascade"); err != nil || len(h.elbWrites()) != 0 {
		t.Errorf("dry run = %v, %v", err, h.elbWrites())
	}
	if a := actions(h.report()); a["load-balancer/site-xz7-lb would_delete"] != 1 || a["target-group/site-xz7-80-target would_delete"] != 1 {
		t.Errorf("dry run rows = %v", a)
	}
	h.rt.Flags.DryRun = false
	h.rt.Flags.Yes = true
	// Deletion protection: exit code 1 with the command that turns it off.
	e := h.elb()
	e.findLB("ap-east-1", "site-xz7-lb").attrs[attrDeletionProtection] = "true"
	err := h.run("elbv2", "load-balancer", "delete", "site-xz7-lb")
	if err == nil || !strings.Contains(err.Error(), "--deletion-protection=false") || errors.Is(err, platform.ErrUnauthorized) || errors.Is(err, app.ErrUsage) {
		t.Errorf("protected = %v", err)
	}
	if e.findLB("ap-east-1", "site-xz7-lb") == nil {
		t.Fatal("protected load balancer deleted")
	}
	e.findLB("ap-east-1", "site-xz7-lb").attrs[attrDeletionProtection] = "false"
	// --cascade retries a target group still in use.
	e.errs["DeleteTargetGroup"] = []error{&elbtypes.ResourceInUseException{Message: awssdk.String("in use")}, &elbtypes.ResourceInUseException{Message: awssdk.String("in use")}}
	h.resetELB()
	if err := h.run("elbv2", "load-balancer", "delete", "site-xz7-lb", "--cascade", "--wait"); err != nil {
		t.Fatalf("delete: %v\n%s", err, h.stderr.String())
	}
	a := actions(h.report())
	if a["load-balancer/site-xz7-lb deleted"] != 1 || a["target-group/site-xz7-80-target deleted"] != 1 || a["target-group/site-xz7-443-target deleted"] != 1 {
		t.Errorf("cascade rows = %v", a)
	}
	if n := strings.Count(strings.Join(h.elbWrites(), ","), "DeleteTargetGroup"); n != 4 {
		t.Errorf("DeleteTargetGroup calls = %d, want 4 (2 retries)", n)
	}
	if len(e.lbs["ap-east-1"]) != 0 || len(e.tgs["ap-east-1"]) != 0 || len(e.listeners["ap-east-1"]) != 0 {
		t.Errorf("left: %d lbs, %d tgs, %d listeners", len(e.lbs["ap-east-1"]), len(e.tgs["ap-east-1"]), len(e.listeners["ap-east-1"]))
	}
	// The inventory forgot it.
	if err := h.run("elbv2", "load-balancer", "list"); err != nil || strings.TrimSpace(h.stdout.String()) != "[]" {
		t.Errorf("list after delete = %v %q", err, h.stdout.String())
	}
}

func TestLBDeleteCascadeKeepsGroupInUse(t *testing.T) {
	h, _ := newELBHarness(t, app.Flags{Yes: true}, nil)
	if err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7", "--skip-https"); err != nil {
		t.Fatal(err)
	}
	e := h.elb()
	inUse := []error{}
	for i := 0; i < 20; i++ {
		inUse = append(inUse, &elbtypes.ResourceInUseException{Message: awssdk.String("in use")})
	}
	e.errs["DeleteTargetGroup"] = inUse
	if err := h.run("elbv2", "load-balancer", "delete", "site-xz7-lb", "--cascade"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if a := actions(h.report()); a["target-group/site-xz7-80-target skipped"] != 1 || !strings.Contains(h.stderr.String(), "still in use") {
		t.Errorf("in use = %v\n%s", a, h.stderr.String())
	}
}

func TestLBDeleteInteractive(t *testing.T) {
	h, _ := newELBHarness(t, app.Flags{NonInteractiveSet: true}, nil)
	h.rt.Flags.NonInteractive = false
	h.rt.Picker = &scriptedPicker{t: t}
	if err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7", "--skip-https"); err != nil {
		t.Fatal(err)
	}
	h.resetELB()
	h.rt.Stdin = strings.NewReader("\n")
	if err := h.run("elbv2", "load-balancer", "delete", "site-xz7-lb"); err != nil && !errors.Is(err, platform.ErrNothingToDo) {
		t.Errorf("declined = %v", err)
	}
	if len(h.elbWrites()) != 0 {
		t.Errorf("declined wrote %v", h.elbWrites())
	}
	h.rt.Stdin = strings.NewReader("y\n")
	if err := h.run("elbv2", "listener", "delete", "site-xz7-lb:80"); err != nil {
		t.Fatal(err)
	}
	if a := actions(h.report()); a["listener/site-xz7-lb:80 deleted"] != 1 {
		t.Errorf("listener delete = %v", a)
	}
	h.rt.Stdin = strings.NewReader("y\n")
	if err := h.run("elbv2", "target-group", "delete", "site-xz7-80-target"); err != nil {
		t.Fatal(err)
	}
	h.rt.Stdin = strings.NewReader("y\n")
	if err := h.run("elbv2", "load-balancer", "delete", "site-xz7-lb"); err != nil {
		t.Fatal(err)
	}
	if w := strings.Join(h.elbWrites(), ","); w != "DeleteListener,DeleteTargetGroup,DeleteLoadBalancer" {
		t.Errorf("writes = %s", w)
	}
}

func TestTargetGroupCommands(t *testing.T) {
	h, _ := newELBHarness(t, app.Flags{}, map[string]any{"vpc_id": "vpc-0abc"})
	if err := h.run("elbv2", "target-group", "create", "db-target", "--protocol", "tcp", "--port", "3306", "--target-type", "ip",
		"--health-check-interval", "300", "--target", "10.0.1.25", "--target", "10.0.1.26:3307"); err != nil {
		t.Fatal(err)
	}
	if a := actions(h.report()); a["target-group/db-target created"] != 1 || a["target-group/db-target/target created"] != 2 {
		t.Errorf("create = %v", a)
	}
	e := h.elb()
	in := e.tgInputs[0]
	if awssdk.ToInt32(in.HealthCheckIntervalSeconds) != 300 || in.TargetType != "ip" || awssdk.ToString(in.VpcId) != "vpc-0abc" || in.HealthCheckProtocol != "" {
		t.Errorf("create input = %+v", in)
	}
	for _, args := range [][]string{
		{"x", "--port", "80"}, {"x", "--protocol", "TCP"}, {"x", "--protocol", "FTP", "--port", "21"}, {"x", "--protocol", "TCP", "--port", "70000"},
		{"x", "--protocol", "TCP", "--port", "80", "--health-check-interval", "4"}, {"x", "--protocol", "TCP", "--port", "80", "--target", "10.0.0.1"},
		{"x", "--protocol", "TCP", "--port", "80", "--health-check-port", "nope"}, {"x_y", "--protocol", "TCP", "--port", "80"},
	} {
		if err := h.run(append([]string{"elbv2", "target-group", "create"}, args...)...); !ExitUsageErr(err) {
			t.Errorf("create %v = %v, want a usage error", args, err)
		}
	}
	if err := h.run("elbv2", "target-group", "create", "db-target", "--protocol", "TCP", "--port", "3306"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("create twice = %v", err)
	}

	// --set-target: extra targets on the named port go, other ports stay.
	tg := e.findTG("ap-east-1", "db-target")
	tg.targets = append(tg.targets, &fakeTarget{id: "10.0.1.27", port: 3306}, &fakeTarget{id: "10.0.1.28", port: 3307})
	h.resetELB()
	if err := h.run("elbv2", "target-group", "update", "db-target", "--set-target", "10.0.1.25", "--set-target", "10.0.1.29"); err != nil {
		t.Fatal(err)
	}
	a := actions(h.report())
	if a["target-group/db-target/target deleted"] != 1 || a["target-group/db-target/target created"] != 1 || a["target-group/db-target/target unchanged"] != 1 {
		t.Errorf("set-target = %v", a)
	}
	states := map[string]string{}
	for _, x := range tg.targets {
		states[platform.LBTargetSpec{ID: x.id, Port: x.port}.String()] = x.state
	}
	if states["10.0.1.27:3306"] != "draining" || states["10.0.1.26:3307"] != "" || states["10.0.1.28:3307"] != "" || states["10.0.1.25:3306"] != "" {
		t.Errorf("states = %v", states)
	}
	if _, ok := states["10.0.1.29:3306"]; !ok {
		t.Errorf("10.0.1.29 not registered: %v", states)
	}
	// add / remove, and the health check.
	h.resetELB()
	if err := h.run("elbv2", "target-group", "update", "db-target", "--add-target", "10.0.1.25", "--remove-target", "10.0.1.99", "--remove-target", "10.0.1.26:3307",
		"--health-check-interval", "30", "--health-check-protocol", "tcp"); err != nil {
		t.Fatal(err)
	}
	a = actions(h.report())
	if a["target-group/db-target/target unchanged"] != 2 || a["target-group/db-target/target deleted"] != 1 || a["target-group/db-target/health-check updated"] != 1 ||
		a["target-group/db-target/health-check unchanged"] != 1 {
		t.Errorf("update = %v", a)
	}
	if w := strings.Join(h.elbWrites(), ","); w != "DeregisterTargets,ModifyTargetGroup" {
		t.Errorf("update writes = %s", w)
	}
	for _, args := range [][]string{{"db-target"}, {"db-target", "--set-target", "10.0.1.1", "--add-target", "10.0.1.2"}, {"db-target", "--add-target", "i-0123456789abcdef0"}} {
		if err := h.run(append([]string{"elbv2", "target-group", "update"}, args...)...); !ExitUsageErr(err) {
			t.Errorf("update %v = %v, want a usage error", args, err)
		}
	}
	// A group a listener uses cannot be deleted.
	if err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7", "--skip-https"); err != nil {
		t.Fatal(err)
	}
	h.rt.Flags.Yes = true
	if err := h.run("elbv2", "target-group", "delete", "site-xz7-80-target"); err == nil || !strings.Contains(err.Error(), "in use") || ExitUsageErr(err) {
		t.Errorf("in use = %v", err)
	}
	if err := h.run("elbv2", "target-group", "delete", "db-target"); err != nil {
		t.Errorf("delete = %v", err)
	}
}

func TestListenerCommands(t *testing.T) {
	h, _ := newELBHarness(t, app.Flags{}, map[string]any{"vpc_id": "vpc-0abc"})
	if err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7", "--skip-https"); err != nil {
		t.Fatal(err)
	}
	if err := h.run("elbv2", "target-group", "create", "db-target", "--protocol", "TCP", "--port", "3306", "--target-type", "ip"); err != nil {
		t.Fatal(err)
	}
	h.resetELB()
	if err := h.run("elbv2", "listener", "create", "site-xz7-lb", "--protocol", "TCP", "--port", "30001", "--target-group", "db-target"); err != nil {
		t.Fatal(err)
	}
	if a := actions(h.report()); a["listener/site-xz7-lb:30001 created"] != 1 {
		t.Errorf("create = %v", a)
	}
	for _, args := range [][]string{
		{"site-xz7-lb", "--protocol", "TLS", "--port", "443", "--target-group", "db-target"},
		{"site-xz7-lb", "--protocol", "TCP", "--port", "443", "--target-group", "db-target", "--cert", "arn:aws:acm:ap-east-1:1:certificate/x"},
		{"site-xz7-lb", "--port", "443", "--target-group", "db-target"},
		{"site-xz7-lb", "--protocol", "TCP", "--target-group", "db-target"},
		{"site-xz7-lb", "--protocol", "TCP", "--port", "443"},
	} {
		if err := h.run(append([]string{"elbv2", "listener", "create"}, args...)...); !ExitUsageErr(err) {
			t.Errorf("create %v = %v, want a usage error", args, err)
		}
	}
	if err := h.run("elbv2", "listener", "create", "site-xz7-lb", "--protocol", "TCP", "--port", "80", "--target-group", "db-target"); err == nil || !strings.Contains(err.Error(), "listener update") {
		t.Errorf("taken port = %v", err)
	}
	if err := h.run("elbv2", "listener", "create", "site-xz7-lb", "--protocol", "TLS", "--port", "443", "--target-group", "db-target", "--cert", "arn:aws:acm:ap-east-1:1:certificate/x"); err != nil {
		t.Errorf("tls = %v", err)
	}
	h.resetELB()
	if err := h.run("elbv2", "listener", "update", "site-xz7-lb:30001", "--target-group", "site-xz7-80-target"); err != nil {
		t.Fatal(err)
	}
	if w := strings.Join(h.elbWrites(), ","); w != "ModifyListener" {
		t.Errorf("update writes = %s", w)
	}
	h.resetELB()
	if err := h.run("elbv2", "listener", "update", "site-xz7-lb:30001", "--target-group", "site-xz7-80-target", "--protocol", "tcp"); err != nil {
		t.Fatal(err)
	}
	if a := actions(h.report()); a["listener/site-xz7-lb:30001 unchanged"] != 1 || len(h.elbWrites()) != 0 {
		t.Errorf("unchanged update = %v, %v", a, h.elbWrites())
	}
	if err := h.run("elbv2", "listener", "update", "site-xz7-lb:30001", "--protocol", "TLS"); !ExitUsageErr(err) {
		t.Errorf("tls without cert = %v", err)
	}
	if err := h.run("elbv2", "listener", "update", "site-xz7-lb:30001"); !ExitUsageErr(err) {
		t.Errorf("nothing = %v", err)
	}
	if err := h.run("elbv2", "listener", "delete", "site-xz7-lb:30001"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("delete without --yes = %v", err)
	}
	h.rt.Flags.Yes = true
	if err := h.run("elbv2", "listener", "delete", "site-xz7-lb:30001"); err != nil {
		t.Errorf("delete = %v", err)
	}
}

func TestLBRoutingAcrossAccounts(t *testing.T) {
	h, _ := newELBHarness(t, app.Flags{}, nil)
	h.addProfile(t)
	for _, p := range []string{"lab", "prod"} {
		h.rt.Flags.Profile = p
		if err := h.run("elbv2", "load-balancer", "create", "web-lb", "--type", "network", "--subnet", "subnet-0def"); err != nil {
			t.Fatalf("create in %s: %v", p, err)
		}
	}
	h.rt.Flags.Profile = ""
	var amb *app.AmbiguousError
	if err := h.run("elbv2", "load-balancer", "get", "web-lb"); !errors.As(err, &amb) || !strings.Contains(err.Error(), "--profile") {
		t.Errorf("two accounts = %v", err)
	}
	h.rt.Flags.Profile = "prod"
	if err := h.run("elbv2", "load-balancer", "get", "web-lb"); err != nil {
		t.Fatal(err)
	}
	var d lbDetail
	h.jsonOut(&d)
	if d.Profile != "prod" || d.Region != "us-west-2" {
		t.Errorf("prod = %+v", d)
	}
	if err := h.run("elbv2", "load-balancer", "get", d.ID); err != nil {
		t.Errorf("by arn = %v", err)
	}
	if err := h.run("elbv2", "load-balancer", "get", d.ID, "--region", "ap-east-1"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("arn with another region = %v", err)
	}
}

func TestLBEnsureExistingInAnotherZone(t *testing.T) {
	h, _ := newELBHarness(t, app.Flags{}, nil)
	h.elb().subnetAZ["subnet-0bbb"] = "ap-east-1b"
	if err := h.run("elbv2", "load-balancer", "create", "site-xz7-lb", "--type", "network", "--subnet", "subnet-0bbb"); err != nil {
		t.Fatal(err)
	}
	h.resetELB()
	err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7")
	if err == nil || !strings.Contains(err.Error(), "not enabled in ap-east-1a") || len(h.elbWrites()) != 0 {
		t.Errorf("other zone = %v, writes %v", err, h.elbWrites())
	}
	// Adding the instance's subnet fixes it.
	if err := h.run("elbv2", "load-balancer", "update", "site-xz7-lb", "--subnet", "subnet-0bbb", "--subnet", "subnet-0def"); err != nil {
		t.Fatal(err)
	}
	if a := actions(h.report()); a["load-balancer/site-xz7-lb/subnets updated"] != 1 {
		t.Errorf("update subnets = %v", a)
	}
	if err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7"); err != nil {
		t.Errorf("after update = %v", err)
	}
	// An application load balancer of the name is refused.
	if err := h.run("elbv2", "load-balancer", "create", "app-lb", "--type", "application", "--subnet", "subnet-0def", "--subnet", "subnet-0bbb"); err != nil {
		t.Fatal(err)
	}
	if err := h.run("elbv2", "load-balancer", "ensure", "app", "--instance", "site-xz7"); err == nil || !strings.Contains(err.Error(), "type application") {
		t.Errorf("application = %v", err)
	}
}

func TestParseTargetsForGroup(t *testing.T) {
	ts, err := parseGroupTargets("target", []string{"i-0123456789abcdef0", "i-0123456789abcdef0:8080", "i-0123456789abcdef0:80"}, "instance", 80)
	if err != nil || len(ts) != 2 || ts[0].Port != 80 || ts[1].Port != 8080 {
		t.Errorf("instance targets = %+v, %v", ts, err)
	}
	if _, err := parseGroupTargets("target", []string{"10.0.0.1"}, "instance", 80); err == nil {
		t.Error("an address in an instance group")
	}
	if _, err := parseGroupTargets("target", []string{"i-0123456789abcdef0"}, "ip", 80); err == nil {
		t.Error("an instance in an ip group")
	}
	if ts, err := parseGroupTargets("target", []string{"[2001:db8::1]:443", "10.0.0.1"}, "ip", 80); err != nil || ts[0].Port != 443 || ts[1].Port != 80 {
		t.Errorf("ip targets = %+v, %v", ts, err)
	}
}
