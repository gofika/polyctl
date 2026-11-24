package aws

import (
	"errors"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// elbPickHarness builds site-xz7-lb (a network load balancer with a tcp:80
// listener to site-xz7-80-target) and the free target group db-target
// (TCP 3306, vpc-0abc) in the non-interactive flow, then switches to the
// interactive flow.
func elbPickHarness(t *testing.T) *awsHarness {
	t.Helper()
	h, _ := newELBHarness(t, app.Flags{}, map[string]any{"vpc_id": "vpc-0abc"})
	if err := h.run("elbv2", "load-balancer", "ensure", "site-xz7", "--instance", "site-xz7", "--skip-https"); err != nil {
		t.Fatal(err)
	}
	if err := h.run("elbv2", "target-group", "create", "db-target", "--protocol", "TCP", "--port", "3306", "--target-type", "ip"); err != nil {
		t.Fatal(err)
	}
	h.resetELB()
	h.rt.Flags.NonInteractive = false
	h.rt.Picker = prompttest.New(t)
	return h
}

// get and delete without the load balancer offer the load balancers of the
// inventory.
func TestLBPicks(t *testing.T) {
	h := elbPickHarness(t)
	p := prompttest.New(t, prompttest.Label("site-xz7-lb"))
	h.rt.Picker = p
	if err := h.run("elbv2", "load-balancer", "get"); err != nil {
		t.Fatalf("get: %v", err)
	}
	if l := prompttest.Labels(p.Asked[0].Options); !strings.Contains(l, "site-xz7-lb  network  internet-facing  active  vpc-0abc") || !strings.Contains(l, "aws/lab/ap-east-1") {
		t.Errorf("labels: %s", l)
	}
	h.rt.Picker = prompttest.New(t, prompttest.Abort{})
	if err := h.run("elbv2", "load-balancer", "delete"); !errors.Is(err, prompt.ErrAborted) || len(h.elbWrites()) != 0 {
		t.Errorf("delete abort = %v, writes %v", err, h.elbWrites())
	}

	// update without a change: what to change, then its value.
	p = prompttest.New(t, prompttest.Label("site-xz7-lb"), "deletion-protection", "on")
	h.rt.Picker = p
	if err := h.run("elbv2", "load-balancer", "update"); err != nil {
		t.Fatalf("update: %v", err)
	}
	p.Done()
	if p.Asked[2].Default != "on" {
		t.Errorf("toggle default = %q, want the opposite of off", p.Asked[2].Default)
	}
	if a := actions(h.report()); a["load-balancer/site-xz7-lb/deletion-protection updated"] != 1 {
		t.Errorf("update = %v", a)
	}

	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("elbv2", "load-balancer", "update", "site-xz7-lb"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("non-interactive update = %v", err)
	}
}

// listener create without the flags asks for an active load balancer, the
// protocol of its type, a free port, a target group that fits and, for
// TLS, an issued certificate.
func TestListenerCreateAsks(t *testing.T) {
	h := elbPickHarness(t)
	exp := time.Now().Add(90 * 24 * time.Hour)
	h.addCert(&fakeCert{region: "ap-east-1", domain: "example.com", status: acmIssued, notAfter: &exp})
	h.addCert(&fakeCert{region: "ap-east-1", domain: "pending.example.com", status: "PENDING_VALIDATION"})

	p := prompttest.New(t, prompttest.Label("site-xz7-lb"), "TLS", "80", "443", prompttest.Label("db-target"), prompttest.Label("example.com"))
	h.rt.Picker = p
	if err := h.run("elbv2", "listener", "create"); err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if v := prompttest.Values(p.Asked[1].Options); v != "TCP TLS UDP TCP_UDP" {
		t.Errorf("protocols offered %q", v)
	}
	if l := prompttest.Labels(p.Find("Certificate").Options); strings.Contains(l, "pending") {
		t.Errorf("certificates offered: %s", l)
	}
	if a := actions(h.report()); a["listener/site-xz7-lb:443 created"] != 1 {
		t.Errorf("create = %v", a)
	}

	// update without a change: the listener, then another target group.
	p = prompttest.New(t, prompttest.Label("site-xz7-lb"), prompttest.Label("80  TCP"), prompttest.Label("db-target"))
	h.rt.Picker = p
	if err := h.run("elbv2", "listener", "update"); err != nil {
		t.Fatalf("update: %v", err)
	}
	p.Done()
	if a := actions(h.report()); a["listener/site-xz7-lb:80 updated"] != 1 {
		t.Errorf("update = %v", a)
	}

	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("elbv2", "listener", "create", "site-xz7-lb", "--protocol", "TCP", "--port", "9"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("non-interactive = %v", err)
	}
}

// target-group create asks the name (checked against the region), the
// protocol and the port; the VPC comes from defaults.aws.vpc_id. update
// without a change offers registering or deregistering targets.
func TestTGAsks(t *testing.T) {
	h := elbPickHarness(t)
	p := prompttest.New(t, "db-target", "api-target", "HTTP", "0", "8080")
	h.rt.Picker = p
	if err := h.run("elbv2", "target-group", "create"); err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if a := actions(h.report()); a["target-group/api-target created"] != 1 {
		t.Errorf("create = %v", a)
	}

	p = prompttest.New(t, prompttest.Label("api-target"), "add", []string{lbInstanceID})
	h.rt.Picker = p
	if err := h.run("elbv2", "target-group", "update"); err != nil {
		t.Fatalf("update: %v", err)
	}
	p.Done()
	if a := actions(h.report()); a["target-group/api-target/target created"] != 1 {
		t.Errorf("update = %v", a)
	}

	h.rt.Picker = prompttest.New(t, prompttest.Abort{})
	if err := h.run("elbv2", "target-group", "delete"); !errors.Is(err, prompt.ErrAborted) {
		t.Errorf("delete abort = %v", err)
	}
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("elbv2", "target-group", "create", "x", "--port", "80"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("non-interactive = %v", err)
	}
}

// load-balancer create asks the name, the type and the subnets of the VPC
// (one per zone, asked again on a clash); ensure without --instance offers
// the running instances.
func TestLBCreateEnsureAsks(t *testing.T) {
	h := elbPickHarness(t)
	h.ec2.mu.Lock()
	h.ec2.find.subnets = map[string]ec2types.Subnet{
		"ap-east-1/subnet-0def": {SubnetId: awssdk.String("subnet-0def"), VpcId: awssdk.String("vpc-0abc"), AvailabilityZone: awssdk.String("ap-east-1a")},
		"ap-east-1/subnet-0dup": {SubnetId: awssdk.String("subnet-0dup"), VpcId: awssdk.String("vpc-0abc"), AvailabilityZone: awssdk.String("ap-east-1a")},
		"ap-east-1/subnet-0b":   {SubnetId: awssdk.String("subnet-0b"), VpcId: awssdk.String("vpc-0abc"), AvailabilityZone: awssdk.String("ap-east-1b")},
		"ap-east-1/subnet-0x":   {SubnetId: awssdk.String("subnet-0x"), VpcId: awssdk.String("vpc-0other"), AvailabilityZone: awssdk.String("ap-east-1b")},
	}
	h.ec2.mu.Unlock()
	p := prompttest.New(t, "web-lb", "network", []string{"subnet-0def", "subnet-0dup"}, []string{"subnet-0def", "subnet-0b"})
	h.rt.Picker = p
	h.rt.Flags.DryRun = true
	if err := h.run("elbv2", "load-balancer", "create"); err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if v := prompttest.Values(p.Asked[2].Options); strings.Contains(v, "subnet-0x") {
		t.Errorf("subnets of another VPC offered: %s", v)
	}
	if rep := h.report(); !strings.Contains(rep.Changes[0].Detail, "subnet-0def,subnet-0b") {
		t.Errorf("report = %+v", rep)
	}

	// An empty name is refused as typed; leaving the question changes
	// nothing.
	h.rt.Picker = prompttest.New(t, lbInstanceID, "", prompttest.Abort{})
	if err := h.run("elbv2", "load-balancer", "ensure"); !errors.Is(err, prompt.ErrAborted) {
		t.Fatalf("ensure = %v", err)
	}
	p = prompttest.New(t, lbInstanceID, prompttest.KeepDefault{})
	h.rt.Picker = p
	if err := h.run("elbv2", "load-balancer", "ensure"); err != nil {
		t.Fatalf("ensure: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if p.Asked[1].Default != "site-xz7" {
		t.Errorf("name proposed %q", p.Asked[1].Default)
	}
}
