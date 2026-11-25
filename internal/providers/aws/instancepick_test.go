package aws

import (
	"errors"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// interactiveHarness is an instance harness whose runtime runs the
// interactive flow with the scripted picker p.
func interactiveHarness(t *testing.T, flags app.Flags) *awsHarness {
	t.Helper()
	flags.NonInteractive, flags.NonInteractiveSet = false, true
	h := newInstanceHarness(t, flags)
	h.rt.Picker = prompttest.New(t)
	return h
}

// On a terminal, start without <name|id> offers the stopped instances of
// the inventory (synced first); stop offers the running ones, and none is
// nothing to do.
func TestInstanceStartStopPick(t *testing.T) {
	h := interactiveHarness(t, app.Flags{})
	h.addInstance("ap-east-1", running("i-0aaaaaaaaaaaaaaa1", "web-01"))
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa2", name: "web-02", typ: "t3.nano", state: stateStopped, priv: "10.0.1.5"})
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa3", name: "gone", typ: "t3.nano", state: stateTerminated})

	p := prompttest.New(t, "i-0aaaaaaaaaaaaaaa2")
	h.rt.Picker = p
	if err := h.run("ec2", "instance", "start", "--no-wait"); err != nil {
		t.Fatalf("start: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	a := p.Find("Instance")
	if v := prompttest.Values(a.Options); v != "i-0aaaaaaaaaaaaaaa2" {
		t.Errorf("start offered %q, want the stopped instance only", v)
	}
	if l := prompttest.Labels(a.Options); !strings.Contains(l, "web-02  i-0aaaaaaaaaaaaaaa2  stopped  t3.nano  ap-east-1a  10.0.1.5  -  aws/lab") {
		t.Errorf("label: %s", l)
	}
	if st, _ := h.instState("ap-east-1", "i-0aaaaaaaaaaaaaaa2"); st == stateStopped {
		t.Errorf("instance not started")
	}

	// Leaving the pick stops nothing.
	h.rt.Picker = prompttest.New(t, prompttest.Abort{})
	if err := h.run("ec2", "instance", "stop"); !errors.Is(err, prompt.ErrAborted) {
		t.Errorf("abort = %v", err)
	}
	for _, w := range h.writes() {
		if w == "StopInstances" {
			t.Errorf("an aborted stop stopped something: %v", h.writes())
		}
	}
}

// Without anything to choose from, start is nothing to do; the
// non-interactive flow still needs the argument.
func TestInstanceStartPickEmpty(t *testing.T) {
	h := interactiveHarness(t, app.Flags{})
	h.addInstance("ap-east-1", running("i-0aaaaaaaaaaaaaaa1", "web-01"))
	err := h.run("ec2", "instance", "start")
	if !errors.Is(err, platform.ErrNothingToDo) || !strings.Contains(err.Error(), "stopped AWS instance") {
		t.Errorf("start = %v, want nothing to do", err)
	}

	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("ec2", "instance", "start"); err == nil || !strings.Contains(err.Error(), "arg") {
		t.Errorf("non-interactive = %v, want the argument required", err)
	}
}

// get and delete offer every instance that still exists; a name held by
// several live instances is a pick in the interactive flow and exit code 5
// otherwise.
func TestInstanceGetPickAndAmbiguous(t *testing.T) {
	h := interactiveHarness(t, app.Flags{})
	h.addInstance("ap-east-1", running("i-0aaaaaaaaaaaaaaa1", "web"))
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa2", name: "web", typ: "t3.nano", state: stateStopped, priv: "10.0.1.5"})
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa3", name: "gone", typ: "t3.nano", state: stateTerminated})

	p := prompttest.New(t, "i-0aaaaaaaaaaaaaaa1")
	h.rt.Picker = p
	if err := h.run("ec2", "instance", "get"); err != nil {
		t.Fatalf("get: %v", err)
	}
	if v := prompttest.Values(p.Find("Instance").Options); v != "i-0aaaaaaaaaaaaaaa1 i-0aaaaaaaaaaaaaaa2" {
		t.Errorf("get offered %q, want no terminated instance", v)
	}

	p = prompttest.New(t, prompttest.Label("i-0aaaaaaaaaaaaaaa2"))
	h.rt.Picker = p
	if err := h.run("ec2", "instance", "get", "web"); err != nil {
		t.Fatalf("ambiguous get: %v", err)
	}
	p.Done()
	if !strings.Contains(h.stdout.String(), "i-0aaaaaaaaaaaaaaa2") {
		t.Errorf("stdout = %s", h.stdout.String())
	}
	if l := prompttest.Labels(p.Asked[0].Options); !strings.Contains(l, "web  i-0aaaaaaaaaaaaaaa2  stopped  t3.nano  ap-east-1a  10.0.1.5  -  aws/lab/ap-east-1") {
		t.Errorf("labels: %s", l)
	}

	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	var amb *app.AmbiguousError
	if err := h.run("ec2", "instance", "get", "web"); !errors.As(err, &amb) {
		t.Errorf("non-interactive ambiguous = %v, want exit code 5", err)
	}
}

// resize without --type offers the T3 sizes offered in the instance's zone
// (its own type left out, 2H4G preselected), resolved as --type <size>.
func TestInstanceResizeTypePick(t *testing.T) {
	h := interactiveHarness(t, app.Flags{DryRun: true})
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa1", name: "web", typ: "t3.small", state: stateStopped})

	p := prompttest.New(t, "i-0aaaaaaaaaaaaaaa1", "2H8G")
	h.rt.Picker = p
	if err := h.run("ec2", "instance", "resize"); err != nil {
		t.Fatalf("resize: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	a := p.Asked[1]
	if a.Default != "2H4G" || prompttest.HasValue(a.Options, "2H2G") {
		t.Errorf("size pick = %+v (want 2H4G preselected, no current t3.small)", a)
	}
	if l := prompttest.Labels(a.Options); !strings.Contains(l, "2H4G  t3.medium  2 vCPU  4 GiB") || !strings.Contains(l, "Other size or exact instance type...") {
		t.Errorf("labels: %s", l)
	}
	if rep := h.report(); !strings.Contains(rep.Changes[0].Detail, "t3.large") {
		t.Errorf("report = %+v", rep)
	}

	// "Other ..." takes a typed size or type, checked as typed.
	p = prompttest.New(t, prompttest.Label("Other size"), "not a type", "c6a.large")
	h.rt.Picker = p
	if err := h.run("ec2", "instance", "resize", "web"); err != nil {
		t.Fatalf("resize other: %v", err)
	}
	p.Done()
	if rep := h.report(); !strings.Contains(rep.Changes[0].Detail, "c6a.large") {
		t.Errorf("report = %+v", rep)
	}

	// The non-interactive flow still needs --type, before any call.
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("ec2", "instance", "resize", "web"); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--type") {
		t.Errorf("non-interactive = %v", err)
	}
}

// addSubnets puts subnets into the fake account: the default subnet of
// ap-east-1a, another of ap-east-1b, and a pending one never offered.
func (h *awsHarness) addSubnets() {
	h.ec2.mu.Lock()
	defer h.ec2.mu.Unlock()
	if h.ec2.find.subnets == nil {
		h.ec2.find.subnets = map[string]ec2types.Subnet{}
	}
	h.ec2.find.subnets["ap-east-1/subnet-0def"] = ec2types.Subnet{SubnetId: awssdk.String("subnet-0def"), AvailabilityZone: awssdk.String("ap-east-1a"), VpcId: awssdk.String("vpc-0abc"),
		CidrBlock: awssdk.String("10.0.1.0/24"), DefaultForAz: awssdk.Bool(true), AvailableIpAddressCount: awssdk.Int32(250), Tags: []ec2types.Tag{{Key: awssdk.String("Name"), Value: awssdk.String("public-a")}}}
	h.ec2.find.subnets["ap-east-1/subnet-0b"] = ec2types.Subnet{SubnetId: awssdk.String("subnet-0b"), AvailabilityZone: awssdk.String("ap-east-1b"), VpcId: awssdk.String("vpc-0abc"), CidrBlock: awssdk.String("10.0.2.0/24")}
	h.ec2.find.subnets["ap-east-1/subnet-0p"] = ec2types.Subnet{SubnetId: awssdk.String("subnet-0p"), AvailabilityZone: awssdk.String("ap-east-1a"), VpcId: awssdk.String("vpc-0abc"), State: ec2types.SubnetStatePending}
}

// create without <name>, --subnet and --type asks for the name (checked
// against the live instances), the subnet (available ones, the zone's
// default preselected) and the size offered in the subnet's zone.
func TestInstanceCreateAsks(t *testing.T) {
	useFakeClock(t)
	h := newAWSHarness(t, app.Flags{NonInteractiveSet: true}, map[string]any{"security_group_ids": []any{"sg-0aaa"}, "key_name": "site-key"})
	h.add("ap-east-1", newFakeKeyPair("site-key", genED25519(t)))
	h.addSubnets()
	h.addInstance("ap-east-1", running("i-0aaaaaaaaaaaaaaa1", "web-01"))

	p := prompttest.New(t, "web-01", "site-new", "subnet-0b", "2H4G")
	h.rt.Picker = p
	if err := h.run("ec2", "instance", "create", "--no-wait"); err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	sub := p.Find("Subnet")
	if v := prompttest.Values(sub.Options); v != "subnet-0def subnet-0b" || sub.Default != "subnet-0def" {
		t.Errorf("subnets offered %q (default %q), want the available ones", v, sub.Default)
	}
	if l := prompttest.Labels(sub.Options); !strings.Contains(l, "public-a  subnet-0def  ap-east-1a  10.0.1.0/24  vpc-0abc  250 free IPs  [default for zone]") {
		t.Errorf("subnet labels: %s", l)
	}
	if size := p.Asked[3]; !strings.Contains(size.Title, "ap-east-1b") {
		t.Errorf("size pick %q is not of the subnet's zone", size.Title)
	}
	in := h.ec2.inst.runs[0]
	if in.InstanceType != "t3.medium" || awssdk.ToString(in.NetworkInterfaces[0].SubnetId) != "subnet-0b" || tagValue(in.TagSpecifications[0].Tags, "Name") != "site-new" {
		t.Errorf("run input = %+v", in)
	}

	// The non-interactive flow names the missing setting, before any write.
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("ec2", "instance", "create", "x", "--type", "t3.nano"); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--subnet") {
		t.Errorf("non-interactive = %v", err)
	}
}

// Without an available subnet, create is a usage error naming --subnet:
// polyctl creates no subnets.
func TestInstanceCreateNoSubnet(t *testing.T) {
	useFakeClock(t)
	h := newAWSHarness(t, app.Flags{NonInteractiveSet: true}, map[string]any{"key_name": "site-key", "instance_type": "t3.nano"})
	h.add("ap-east-1", newFakeKeyPair("site-key", genED25519(t)))
	h.rt.Picker = prompttest.New(t)
	if err := h.run("ec2", "instance", "create", "x"); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--subnet") {
		t.Errorf("create = %v", err)
	}
	if w := h.writes(); len(w) != 0 {
		t.Errorf("writes = %v", w)
	}
}
