package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/gofika/polyctl/internal/platform"
)

// useFakeELBClock makes the load balancer waits instant and the DNS
// resolution answer 203.0.113.10.
func useFakeELBClock(t *testing.T) *fakeClock {
	t.Helper()
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	oldClock, oldLookup := elbClock, lookupHost
	elbClock = clk
	lookupHost = func(ctx context.Context, host string) ([]string, error) { return []string{"203.0.113.10"}, nil }
	t.Cleanup(func() { elbClock, lookupHost = oldClock, oldLookup })
	return clk
}

func TestCheckELBName(t *testing.T) {
	ok := []struct {
		name string
		lb   bool
	}{{"site-xz7-lb", true}, {strings.Repeat("a", 32), true}, {"internal-web", false}, {"A1-b2", false}}
	for _, c := range ok {
		if err := checkELBName("x", c.name, c.lb); err != nil {
			t.Errorf("%q: %v", c.name, err)
		}
	}
	bad := []struct {
		name string
		lb   bool
	}{{"", true}, {strings.Repeat("a", 33), false}, {"-web", true}, {"web-", false}, {"internal-web", true}, {"web_1", false}, {"web.1", true}}
	for _, c := range bad {
		if err := checkELBName("x", c.name, c.lb); !errors.Is(err, platform.ErrInvalidInput) {
			t.Errorf("%q: %v, want a usage error", c.name, err)
		}
	}
}

func TestParseELBARN(t *testing.T) {
	a, ok := parseELBARN("arn:aws:elasticloadbalancing:ap-east-1:123456789012:loadbalancer/net/site-lb/0123456789abcdef")
	if !ok || a.Region != "ap-east-1" || a.Account != "123456789012" || a.Kind != "loadbalancer" || a.Name != "site-lb" {
		t.Errorf("lb arn = %+v %v", a, ok)
	}
	a, ok = parseELBARN("arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/site-80-target/abc")
	if !ok || a.Kind != "targetgroup" || a.Name != "site-80-target" {
		t.Errorf("tg arn = %+v", a)
	}
	a, ok = parseELBARN("arn:aws:elasticloadbalancing:us-west-2:123456789012:listener/net/site-lb/abc/def")
	if !ok || a.Kind != "listener" || a.Name != "site-lb" || !isELBARN("arn:aws:elasticloadbalancing:us-west-2:1:listener/net/x/a/b", "listener") {
		t.Errorf("listener arn = %+v", a)
	}
	for _, s := range []string{"site-lb", "arn:aws:ec2:us-west-2:1:instance/i-1", "arn:aws:elasticloadbalancing::1:loadbalancer/net/x/y"} {
		if _, ok := parseELBARN(s); ok {
			t.Errorf("%q parsed", s)
		}
	}
	if arnName("site-lb") != "site-lb" {
		t.Error("arnName of a name")
	}
}

func TestDNSRegion(t *testing.T) {
	for dns, want := range map[string]string{
		"site-lb-0123.elb.ap-east-1.amazonaws.com":     "ap-east-1",
		"site-alb-123.us-west-2.elb.amazonaws.com.":    "us-west-2",
		"internal-x-1.cn-north-1.elb.amazonaws.com.cn": "cn-north-1",
		"example.com": "",
		"SITE-LB-0123.ELB.EU-CENTRAL-1.AMAZONAWS.COM":     "eu-central-1",
		"site-lb-0123.elb.us-gov-west-1.amazonaws.com":    "us-gov-west-1",
		"site-lb-0123.elb.not_a_region.amazonaws.com.foo": "",
	} {
		if got := dnsRegion(dns); got != want {
			t.Errorf("dnsRegion(%q) = %q, want %q", dns, got, want)
		}
	}
	if !looksLikeDNSName("a.b") || looksLikeDNSName("site-lb") || looksLikeDNSName("arn:aws:x.y") {
		t.Error("looksLikeDNSName")
	}
}

// statusErr is an API error with an HTTP status, the shape of the real
// errors.
type statusErr struct {
	fakeAPIError
	status int
}

func (e *statusErr) HTTPStatusCode() int { return e.status }

func TestELBErrMapping(t *testing.T) {
	cases := []struct {
		action string
		err    error
		want   error // nil: the general failure
	}{
		{"DescribeLoadBalancers", &elbtypes.LoadBalancerNotFoundException{Message: awssdk.String("x")}, platform.ErrNotFound},
		{"DescribeTargetGroups", fmt.Errorf("wrapped: %w", &elbtypes.TargetGroupNotFoundException{}), platform.ErrNotFound},
		{"DescribeListeners", &fakeAPIError{"ListenerNotFound", "x"}, platform.ErrNotFound},
		{"CreateTargetGroup", &fakeAPIError{"ValidationError", "Target group name cannot be longer than '32' characters"}, platform.ErrInvalidInput},
		{"RegisterTargets", &fakeAPIError{"ValidationError", "The following targets are not valid instances"}, nil},
		{"SetSecurityGroups", &statusErr{fakeAPIError{"InvalidConfigurationRequest", "created without any security groups"}, 400}, nil},
		{"DeleteLoadBalancer", &statusErr{fakeAPIError{"OperationNotPermitted", "deletion protection is enabled"}, 403}, nil},
		{"DeleteTargetGroup", &elbtypes.ResourceInUseException{Message: awssdk.String("in use")}, nil},
		{"CreateLoadBalancer", &elbtypes.TooManyLoadBalancersException{}, nil},
		{"CreateLoadBalancer", &fakeAPIError{"AccessDenied", "not authorized"}, platform.ErrUnauthorized},
	}
	for _, c := range cases {
		err := elbErr(c.action, "ap-east-1", c.err)
		for _, s := range []error{platform.ErrNotFound, platform.ErrInvalidInput, platform.ErrUnauthorized} {
			if errors.Is(err, s) != (s == c.want) {
				t.Errorf("%s %v: %v; want %v", c.action, c.err, err, c.want)
			}
		}
		if !strings.Contains(err.Error(), "elasticloadbalancing:"+c.action) {
			t.Errorf("%v does not name the action", err)
		}
		if platform.ErrorCode(err) == "" {
			t.Errorf("%v lost its code", err)
		}
	}
	if elbErr("X", "r", nil) != nil {
		t.Error("nil error")
	}
	if err := elbErr("CreateLoadBalancer", "r", &fakeAPIError{"AccessDenied", "x"}); !strings.Contains(err.Error(), "IAM action elasticloadbalancing:CreateLoadBalancer") {
		t.Errorf("denied = %v", err)
	}
}

func TestListenerFromShapes(t *testing.T) {
	tg := "arn:aws:elasticloadbalancing:r:1:targetgroup/t/1"
	both := listenerFrom(elbtypes.Listener{Protocol: "TCP", Port: awssdk.Int32(80), DefaultActions: fakeForward(tg)})
	only := listenerFrom(elbtypes.Listener{Protocol: "TCP", Port: awssdk.Int32(80), DefaultActions: []elbtypes.Action{{Type: elbtypes.ActionTypeEnumForward,
		ForwardConfig: &elbtypes.ForwardActionConfig{TargetGroups: []elbtypes.TargetGroupTuple{{TargetGroupArn: awssdk.String(tg)}}}}}})
	plain := listenerFrom(elbtypes.Listener{Protocol: "TCP", Port: awssdk.Int32(80), DefaultActions: forwardTo(tg)})
	for _, l := range []platform.LBListener{both, only, plain} {
		if !l.ForwardsTo(tg) {
			t.Errorf("%+v does not forward to %s", l, tg)
		}
	}
	weighted := listenerFrom(elbtypes.Listener{DefaultActions: []elbtypes.Action{{Type: elbtypes.ActionTypeEnumForward,
		ForwardConfig: &elbtypes.ForwardActionConfig{TargetGroups: []elbtypes.TargetGroupTuple{{TargetGroupArn: awssdk.String(tg)}, {TargetGroupArn: awssdk.String("other")}}}}}})
	redirect := listenerFrom(elbtypes.Listener{DefaultActions: []elbtypes.Action{{Type: elbtypes.ActionTypeEnumRedirect}}})
	if weighted.ForwardsTo(tg) || redirect.ForwardsTo(tg) || redirect.DefaultAction != "redirect" {
		t.Errorf("weighted %+v, redirect %+v", weighted, redirect)
	}
}

func TestSortIPs(t *testing.T) {
	got := sortIPs([]string{"2001:db8::1", "203.0.113.20", "203.0.113.3", "203.0.113.3"})
	if strings.Join(got, ",") != "203.0.113.3,203.0.113.20,2001:db8::1" {
		t.Errorf("sortIPs = %v", got)
	}
}

func TestResolveLBIPsRetries(t *testing.T) {
	clk := useFakeELBClock(t)
	calls := 0
	lookupHost = func(ctx context.Context, host string) ([]string, error) {
		calls++
		if calls < 3 {
			return nil, errors.New("no such host")
		}
		return []string{"203.0.113.10"}, nil
	}
	ips, err := resolveLBIPs(context.Background(), "x.elb.ap-east-1.amazonaws.com")
	if err != nil || strings.Join(ips, ",") != "203.0.113.10" || calls != 3 {
		t.Errorf("ips = %v, %v after %d calls", ips, err, calls)
	}
	for _, d := range clk.slept {
		if d != 5*time.Second {
			t.Errorf("slept %s, want 5s", d)
		}
	}
	lookupHost = func(ctx context.Context, host string) ([]string, error) { return nil, errors.New("no such host") }
	clk.slept = nil
	if _, err := resolveLBIPs(context.Background(), "x"); err == nil || len(clk.slept) != 12 {
		t.Errorf("never resolves = %v after %d sleeps", err, len(clk.slept))
	}
}

func TestLBStateWait(t *testing.T) {
	cases := map[string]platform.WaitState{
		"active": platform.WaitDone, "active_impaired": platform.WaitDone,
		"failed": platform.WaitFailed, "provisioning": platform.KeepWaiting,
	}
	for state, want := range cases {
		if got := lbStateWait(state); got != want {
			t.Errorf("lbStateWait(%s) = %v, want %v", state, got, want)
		}
	}
}
