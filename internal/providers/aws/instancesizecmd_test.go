package aws

import (
	"errors"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// addSubnet puts subnet-0def in ap-east-1a into the fake account.
func (h *awsHarness) addSubnet() {
	h.ec2.mu.Lock()
	defer h.ec2.mu.Unlock()
	if h.ec2.find.subnets == nil {
		h.ec2.find.subnets = map[string]ec2types.Subnet{}
	}
	h.ec2.find.subnets["ap-east-1/subnet-0def"] = ec2types.Subnet{SubnetId: awssdk.String("subnet-0def"), AvailabilityZone: awssdk.String("ap-east-1a"), VpcId: awssdk.String("vpc-0abc")}
}

func TestInstanceCreateSize(t *testing.T) {
	for _, nonInteractive := range []bool{false, true} {
		h := newInstanceHarness(t, app.Flags{NonInteractive: nonInteractive, NonInteractiveSet: true})
		h.addSubnet()
		if err := h.run("ec2", "instance", "create", "site-new", "--type", "2H4G", "--no-wait"); err != nil {
			t.Fatalf("%v\n%s", err, h.stderr.String())
		}
		if !strings.Contains(h.stderr.String(), "2H4G -> t3.medium (ap-east-1a, T3 preset)") {
			t.Errorf("stderr lacks the choice: %s", h.stderr.String())
		}
		in := h.ec2.inst.runs[0]
		if in.InstanceType != "t3.medium" || awssdk.ToString(in.ImageId) != "ami-0x86" {
			t.Errorf("run input = %+v", in)
		}
		rep := h.report()
		if c := rep.Changes[0]; c.Action != platform.Created || !strings.Contains(c.Detail, "type=t3.medium(2H4G)") ||
			c.Attrs["instance_type"] != "t3.medium" || c.Attrs["size"] != "2H4G" {
			t.Errorf("report = %+v", rep)
		}
	}
}

func TestInstanceCreateSizeDryRunAndDefault(t *testing.T) {
	useFakeClock(t)
	h := newAWSHarness(t, app.Flags{DryRun: true}, map[string]any{"subnet_id": "subnet-0def", "security_group_ids": []any{"sg-0aaa"}, "instance_type": "4h8g"})
	h.addSubnet()
	if err := h.run("ec2", "instance", "create", "site-new"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	rep := h.report()
	c := rep.Changes[0]
	if !rep.DryRun || c.Action != platform.WouldCreate || !strings.Contains(c.Detail, "type=c6a.xlarge(4h8g)") || c.Attrs["instance_type"] != "c6a.xlarge" {
		t.Errorf("report = %+v", rep)
	}
	if !strings.Contains(h.stderr.String(), "4h8g -> c6a.xlarge (ap-east-1a, family preference)") || len(h.writes()) != 0 {
		t.Errorf("stderr %s, writes %v", h.stderr.String(), h.writes())
	}
}

func TestInstanceCreateSizeErrors(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{})
	h.addSubnet()
	// No type of that size: exit code 4, nothing written.
	err := h.run("ec2", "instance", "create", "x", "--type", "3H5G")
	if !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "3H5G") {
		t.Errorf("no fit = %v", err)
	}
	// A size of 0 vCPUs or 0 GiB: exit code 2, before any call.
	h.ec2.reset()
	for _, v := range []string{"0H2G", "2H0G"} {
		if err := h.run("ec2", "instance", "create", "x", "--type", v); !errors.Is(err, platform.ErrInvalidInput) {
			t.Errorf("%s = %v", v, err)
		}
	}
	if n := len(h.ec2.calls()); n != 0 {
		t.Errorf("malformed sizes called %v", h.ec2.calls())
	}
	// An arm64 --arch with a size (x86_64 types only): usage error.
	if err := h.run("ec2", "instance", "create", "x", "--type", "2H2G", "--arch", "arm64"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("arm64 size = %v", err)
	}
	if w := h.writes(); len(w) != 0 {
		t.Errorf("errors wrote: %v", w)
	}

	// An exact type is used as it is: no subnet or size lookup.
	h.ec2.reset()
	if err := h.run("ec2", "instance", "create", "x", "--type", "c6a.large", "--no-wait"); err != nil {
		t.Fatal(err)
	}
	if h.ec2.count("DescribeSubnets") != 0 || h.ec2.count("DescribeInstanceTypeOfferings") != 0 || h.ec2.inst.runs[0].InstanceType != "c6a.large" {
		t.Errorf("exact type calls = %v", h.ec2.calls())
	}
}

func TestInstanceResizeSize(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{Yes: true, DryRun: true})
	h.addInstance("ap-east-1", running("i-0aaaaaaaaaaaaaaa1", "web"))

	// c6a.large already is 2H4G: unchanged, nothing resolved.
	if err := h.run("ec2", "instance", "resize", "web", "--type", "2H4G"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); rep.Changes[0].Action != platform.Unchanged || rep.Changes[0].Detail != "type c6a.large(2H4G)" ||
		rep.Changes[0].Attrs["instance_type"] != "c6a.large" || rep.Changes[0].Attrs["size"] != "2H4G" ||
		h.ec2.count("DescribeInstanceTypeOfferings") != 0 || !strings.Contains(h.stderr.String(), "already is 2H4G (c6a.large)") {
		t.Errorf("same size = %+v / %s", rep, h.stderr.String())
	}

	// Dry run of another size: resolved in the instance's zone, reported.
	h.ec2.reset()
	if err := h.run("ec2", "instance", "resize", "web", "--type", "2H8G"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	rep := h.report()
	if len(rep.Changes) != 3 || rep.Changes[1].Detail != "modify-type c6a.large -> t3.large(2H8G)" || rep.Changes[1].Attrs["instance_type"] != "t3.large" || len(h.writes()) != 0 {
		t.Errorf("dry run = %+v, writes %v", rep, h.writes())
	}
	if !strings.Contains(h.stderr.String(), "2H8G -> t3.large (ap-east-1a, T3 preset)") {
		t.Errorf("stderr = %s", h.stderr.String())
	}

	// A real run changes to the resolved type.
	h.rt.Flags.DryRun = false
	h.ec2.reset()
	if err := h.run("ec2", "instance", "resize", "web", "--type", "2H8G"); err != nil {
		t.Fatal(err)
	}
	if _, typ := h.instState("ap-east-1", "i-0aaaaaaaaaaaaaaa1"); typ != "t3.large" {
		t.Errorf("type = %s", typ)
	}

	// No fit in the zone: exit code 4, nothing written.
	h.ec2.reset()
	if err := h.run("ec2", "instance", "resize", "web", "--type", "3H5G"); !errors.Is(err, platform.ErrNotFound) || len(h.writes()) != 0 {
		t.Errorf("no fit = %v, writes %v", err, h.writes())
	}
	if err := h.run("ec2", "instance", "resize", "web", "--type", "0H4G"); !errors.Is(err, platform.ErrInvalidInput) {
		t.Errorf("0 vCPUs = %v", err)
	}
}

func TestInstanceResizeSizeArm(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{Yes: true})
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa2", name: "arm", typ: "t4g.nano", state: stateStopped, arch: "arm64"})
	// A size resolves to x86_64: the architecture check refuses it.
	err := h.run("ec2", "instance", "resize", "arm", "--type", "2H2G")
	if err == nil || !strings.Contains(err.Error(), "cannot be swapped") || len(h.writes()) != 0 {
		t.Errorf("arm64 = %v, writes %v", err, h.writes())
	}
}
