package aws

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/platform"
)

// fakeVolume is an EBS volume attached to a fake instance.
type fakeVolume struct {
	id, device, typ string
	size            int32
	deleteOnTerm    bool
}

// fakeInstance is an instance of the fake EC2 API. Every DescribeInstances
// that returns it moves it one step along next: that is how a poll sees
// pending become running.
type fakeInstance struct {
	id, name, typ, state, az, arch, platform string
	pub, priv, rootDevice, keyName           string
	vols                                     []fakeVolume
	protected                                bool
	next                                     []string
	tags                                     []ec2types.Tag
	vpc                                      string   // "" is vpc-0abc
	sgs                                      []string // nil is [sg-0aaa]
	nics                                     int      // network interfaces; 0 is 1
}

// fakeInstances is the instance part of the shared fake state.
type fakeInstances struct {
	byRegion  map[string][]*fakeInstance
	archs     map[string][]string // instance type -> architectures
	offerings map[string][]string // instance type -> zones
	images    map[string][]ec2types.Image
	ssmValue  map[string]string // parameter -> value
	ssmErr    error
	volErr    error
	errs      map[string]error // call -> error of that call
	runs      []*ec2.RunInstancesInput
	filters   [][]ec2types.Filter
	pageSize  int
	nextIP    int
	nextID    int
}

func (fi *fakeInstances) init() {
	if fi.byRegion == nil {
		fi.byRegion = map[string][]*fakeInstance{}
		fi.archs = map[string][]string{
			"t3.nano": {"x86_64"}, "t3.micro": {"x86_64"}, "c6a.large": {"x86_64"}, "c6a.xlarge": {"x86_64"},
			"t4g.nano": {"arm64"}, "t4g.small": {"arm64"},
		}
		fi.offerings = map[string][]string{}
		for t := range fi.archs {
			fi.offerings[t] = []string{"ap-east-1a", "ap-east-1b", "us-west-2a"}
		}
		fi.offerings["t3.micro"] = []string{"ap-east-1b"}
		fi.images = map[string][]ec2types.Image{}
		fi.ssmValue = map[string]string{
			al2023Parameter("x86_64"): "ami-0x86",
			al2023Parameter("arm64"):  "ami-0arm",
		}
		fi.errs = map[string]error{}
		for _, r := range []string{"ap-east-1", "us-west-2"} {
			fi.images[r] = []ec2types.Image{
				{ImageId: awssdk.String("ami-0x86"), Name: awssdk.String("al2023-ami-2023.9-kernel-6.18-x86_64"), Architecture: "x86_64", RootDeviceName: awssdk.String("/dev/xvda"), CreationDate: awssdk.String("2026-11-01T00:00:00.000Z")},
				{ImageId: awssdk.String("ami-0arm"), Name: awssdk.String("al2023-ami-2023.9-kernel-6.18-arm64"), Architecture: "arm64", RootDeviceName: awssdk.String("/dev/xvda"), CreationDate: awssdk.String("2026-11-01T00:00:00.000Z")},
			}
		}
	}
}

func (fi *fakeInstances) ip() string {
	fi.nextIP++
	return "203.0.113." + strconv.Itoa(fi.nextIP)
}

// advance moves an instance one step along its schedule.
func (fi *fakeInstances) advance(in *fakeInstance) {
	if len(in.next) == 0 {
		return
	}
	in.state, in.next = in.next[0], in.next[1:]
	switch in.state {
	case stateRunning:
		if in.pub == "" {
			in.pub = fi.ip()
		}
	case stateStopped, stateTerminated:
		in.pub = ""
	}
}

func (fi *fakeInstances) find(region, id string) *fakeInstance {
	for _, in := range fi.byRegion[region] {
		if in.id == id {
			return in
		}
	}
	return nil
}

func (in *fakeInstance) ec2() ec2types.Instance {
	out := ec2types.Instance{
		InstanceId: awssdk.String(in.id), InstanceType: ec2types.InstanceType(in.typ),
		State:        &ec2types.InstanceState{Name: ec2types.InstanceStateName(in.state)},
		Placement:    &ec2types.Placement{AvailabilityZone: awssdk.String(in.az)},
		Architecture: ec2types.ArchitectureValues(in.arch), RootDeviceName: awssdk.String(in.rootDevice),
		VpcId: awssdk.String(in.vpcID()), SubnetId: awssdk.String("subnet-0def"),
		LaunchTime: awssdk.Time(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)),
	}
	for _, g := range in.groupIDs() {
		out.SecurityGroups = append(out.SecurityGroups, ec2types.GroupIdentifier{GroupId: awssdk.String(g)})
	}
	for i := 0; i < max(in.nics, 1); i++ {
		out.NetworkInterfaces = append(out.NetworkInterfaces, ec2types.InstanceNetworkInterface{NetworkInterfaceId: awssdk.String(fmt.Sprintf("eni-0%d", i))})
	}
	if in.platform == "windows" {
		out.Platform = ec2types.PlatformValuesWindows
	}
	if in.pub != "" {
		out.PublicIpAddress = awssdk.String(in.pub)
	}
	if in.priv != "" {
		out.PrivateIpAddress = awssdk.String(in.priv)
	}
	if in.keyName != "" {
		out.KeyName = awssdk.String(in.keyName)
	}
	if in.name != "" {
		out.Tags = append(out.Tags, ec2types.Tag{Key: awssdk.String("Name"), Value: awssdk.String(in.name)})
	}
	for _, v := range in.vols {
		out.BlockDeviceMappings = append(out.BlockDeviceMappings, ec2types.InstanceBlockDeviceMapping{
			DeviceName: awssdk.String(v.device), Ebs: &ec2types.EbsInstanceBlockDevice{VolumeId: awssdk.String(v.id), DeleteOnTermination: awssdk.Bool(v.deleteOnTerm)}})
	}
	return out
}

// vpcID is the VPC of a fake instance.
func (in *fakeInstance) vpcID() string {
	if in.vpc == "" {
		return "vpc-0abc"
	}
	return in.vpc
}

// groupIDs are the security groups of a fake instance.
func (in *fakeInstance) groupIDs() []string {
	if in.sgs == nil {
		return []string{"sg-0aaa"}
	}
	return in.sgs
}

func matchPattern(pattern, s string) bool {
	if !strings.ContainsAny(pattern, "*?") {
		return pattern == s
	}
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") && !strings.ContainsAny(pattern[1:len(pattern)-1], "*?") {
		return strings.Contains(s, strings.ReplaceAll(pattern[1:len(pattern)-1], `\\`, `\`))
	}
	return false
}

func (f *fakeEC2) callErr(call string) error {
	f.record(call)
	return f.shared.inst.errs[call]
}

func (f *fakeEC2) DescribeInstances(_ context.Context, in *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	f.mu.Lock()
	err := f.callErr("DescribeInstances")
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	s := f.shared
	s.mu.Lock()
	defer s.mu.Unlock()
	fi := &s.inst
	fi.init()
	if len(in.Filters) > 0 {
		fi.filters = append(fi.filters, in.Filters)
	}
	var match []*fakeInstance
	for _, inst := range fi.byRegion[f.region] {
		ok := true
		if len(in.InstanceIds) > 0 && !containsStr(in.InstanceIds, inst.id) {
			ok = false
		}
		for _, flt := range in.Filters {
			name := awssdk.ToString(flt.Name)
			hit := false
			for _, v := range flt.Values {
				switch name {
				case "tag:Name":
					hit = hit || matchPattern(v, inst.name)
				case "instance-state-name":
					hit = hit || v == inst.state
				case "instance-type":
					hit = hit || v == inst.typ
				case "instance.group-id":
					hit = hit || containsStr(inst.groupIDs(), v)
				}
			}
			ok = ok && hit
		}
		if ok {
			match = append(match, inst)
		}
	}
	if len(in.InstanceIds) > 0 && len(match) == 0 {
		return nil, &fakeAPIError{"InvalidInstanceID.NotFound", "The instance ID does not exist"}
	}
	start := 0
	if in.NextToken != nil {
		start, _ = strconv.Atoi(*in.NextToken)
	}
	end := len(match)
	out := &ec2.DescribeInstancesOutput{}
	if fi.pageSize > 0 && start+fi.pageSize < end {
		end = start + fi.pageSize
		out.NextToken = awssdk.String(strconv.Itoa(end))
	}
	for _, inst := range match[start:end] {
		out.Reservations = append(out.Reservations, ec2types.Reservation{Instances: []ec2types.Instance{inst.ec2()}})
		fi.advance(inst)
	}
	return out, nil
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// write records a write call and runs fn on the instance it names.
func (f *fakeEC2) write(call, id string, fn func(fi *fakeInstances, in *fakeInstance) error) error {
	f.mu.Lock()
	err := f.callErr(call)
	f.mu.Unlock()
	if err != nil {
		return err
	}
	s := f.shared
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inst.init()
	in := s.inst.find(f.region, id)
	if in == nil {
		return &fakeAPIError{"InvalidInstanceID.NotFound", "The instance ID '" + id + "' does not exist"}
	}
	return fn(&s.inst, in)
}

func (f *fakeEC2) StartInstances(_ context.Context, in *ec2.StartInstancesInput, _ ...func(*ec2.Options)) (*ec2.StartInstancesOutput, error) {
	id := in.InstanceIds[0]
	out := &ec2.StartInstancesOutput{}
	err := f.write("StartInstances", id, func(fi *fakeInstances, inst *fakeInstance) error {
		prev := inst.state
		if inst.state == stateStopped {
			inst.state, inst.next = statePending, []string{stateRunning}
		}
		out.StartingInstances = []ec2types.InstanceStateChange{{InstanceId: awssdk.String(id),
			PreviousState: &ec2types.InstanceState{Name: ec2types.InstanceStateName(prev)}, CurrentState: &ec2types.InstanceState{Name: ec2types.InstanceStateName(inst.state)}}}
		return nil
	})
	return out, err
}

func (f *fakeEC2) StopInstances(_ context.Context, in *ec2.StopInstancesInput, _ ...func(*ec2.Options)) (*ec2.StopInstancesOutput, error) {
	id := in.InstanceIds[0]
	out := &ec2.StopInstancesOutput{}
	err := f.write("StopInstances", id, func(fi *fakeInstances, inst *fakeInstance) error {
		prev := inst.state
		switch inst.state {
		case statePending:
			return &fakeAPIError{"IncorrectInstanceState", "has never reached the 'running' state"}
		case stateRunning:
			inst.state, inst.next = stateStopping, []string{stateStopping, stateStopped}
		}
		out.StoppingInstances = []ec2types.InstanceStateChange{{InstanceId: awssdk.String(id),
			PreviousState: &ec2types.InstanceState{Name: ec2types.InstanceStateName(prev)}, CurrentState: &ec2types.InstanceState{Name: ec2types.InstanceStateName(inst.state)}}}
		return nil
	})
	return out, err
}

func (f *fakeEC2) RunInstances(_ context.Context, in *ec2.RunInstancesInput, _ ...func(*ec2.Options)) (*ec2.RunInstancesOutput, error) {
	f.mu.Lock()
	err := f.callErr("RunInstances")
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	s := f.shared
	s.mu.Lock()
	defer s.mu.Unlock()
	fi := &s.inst
	fi.init()
	fi.runs = append(fi.runs, in)
	fi.nextID++
	inst := &fakeInstance{id: fmt.Sprintf("i-0000000000000%04d", fi.nextID), typ: string(in.InstanceType), state: statePending,
		next: []string{statePending, stateRunning}, az: "ap-east-1a", arch: "x86_64", priv: "10.0.1." + strconv.Itoa(fi.nextID), rootDevice: "/dev/xvda"}
	for _, ts := range in.TagSpecifications {
		if ts.ResourceType == ec2types.ResourceTypeInstance {
			for _, t := range ts.Tags {
				if awssdk.ToString(t.Key) == "Name" {
					inst.name = awssdk.ToString(t.Value)
				}
			}
		}
	}
	fi.byRegion[f.region] = append(fi.byRegion[f.region], inst)
	return &ec2.RunInstancesOutput{Instances: []ec2types.Instance{inst.ec2()}}, nil
}

func (f *fakeEC2) TerminateInstances(_ context.Context, in *ec2.TerminateInstancesInput, _ ...func(*ec2.Options)) (*ec2.TerminateInstancesOutput, error) {
	err := f.write("TerminateInstances", in.InstanceIds[0], func(fi *fakeInstances, inst *fakeInstance) error {
		if inst.protected {
			return &fakeAPIError{"OperationNotPermitted", "The instance may not be terminated. Modify its 'disableApiTermination' instance attribute and try again."}
		}
		if inst.state != stateTerminated {
			inst.state, inst.next = stateShuttingDown, []string{stateShuttingDown, stateTerminated}
		}
		return nil
	})
	return &ec2.TerminateInstancesOutput{}, err
}

func (f *fakeEC2) RebootInstances(_ context.Context, in *ec2.RebootInstancesInput, _ ...func(*ec2.Options)) (*ec2.RebootInstancesOutput, error) {
	err := f.write("RebootInstances", in.InstanceIds[0], func(fi *fakeInstances, inst *fakeInstance) error {
		if inst.state != stateRunning {
			return &fakeAPIError{"IncorrectState", "not running"}
		}
		return nil
	})
	return &ec2.RebootInstancesOutput{}, err
}

func (f *fakeEC2) ModifyInstanceAttribute(_ context.Context, in *ec2.ModifyInstanceAttributeInput, _ ...func(*ec2.Options)) (*ec2.ModifyInstanceAttributeOutput, error) {
	err := f.write("ModifyInstanceAttribute", awssdk.ToString(in.InstanceId), func(fi *fakeInstances, inst *fakeInstance) error {
		if in.Groups != nil {
			return fi.setGroups(&f.shared.sg, f.region, inst, in.Groups)
		}
		if inst.state != stateStopped {
			return &fakeAPIError{"IncorrectInstanceState", "is not in the 'stopped' state"}
		}
		inst.typ = awssdk.ToString(in.InstanceType.Value)
		return nil
	})
	return &ec2.ModifyInstanceAttributeOutput{}, err
}

func (f *fakeEC2) DescribeInstanceTypes(_ context.Context, in *ec2.DescribeInstanceTypesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstanceTypesOutput, error) {
	f.mu.Lock()
	err := f.callErr("DescribeInstanceTypes")
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	f.shared.inst.init()
	out := &ec2.DescribeInstanceTypesOutput{}
	for _, t := range in.InstanceTypes {
		archs, ok := f.shared.inst.archs[string(t)]
		if !ok {
			return nil, &fakeAPIError{"InvalidInstanceType", "The following supplied instance types do not exist: [" + string(t) + "]"}
		}
		pi := &ec2types.ProcessorInfo{}
		for _, a := range archs {
			pi.SupportedArchitectures = append(pi.SupportedArchitectures, ec2types.ArchitectureType(a))
		}
		out.InstanceTypes = append(out.InstanceTypes, ec2types.InstanceTypeInfo{InstanceType: t, ProcessorInfo: pi})
	}
	return out, nil
}

func (f *fakeEC2) DescribeInstanceTypeOfferings(_ context.Context, in *ec2.DescribeInstanceTypeOfferingsInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstanceTypeOfferingsOutput, error) {
	f.mu.Lock()
	err := f.callErr("DescribeInstanceTypeOfferings")
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	f.shared.inst.init()
	out := &ec2.DescribeInstanceTypeOfferingsOutput{}
	for _, flt := range in.Filters {
		for _, t := range flt.Values {
			for _, z := range f.shared.inst.offerings[t] {
				if strings.HasPrefix(z, f.region) {
					out.InstanceTypeOfferings = append(out.InstanceTypeOfferings, ec2types.InstanceTypeOffering{InstanceType: ec2types.InstanceType(t), Location: awssdk.String(z), LocationType: in.LocationType})
				}
			}
		}
	}
	return out, nil
}

func (f *fakeEC2) DescribeImages(_ context.Context, in *ec2.DescribeImagesInput, _ ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error) {
	f.mu.Lock()
	err := f.callErr("DescribeImages")
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	f.shared.inst.init()
	out := &ec2.DescribeImagesOutput{}
	for _, im := range f.shared.inst.images[f.region] {
		if len(in.ImageIds) > 0 {
			if containsStr(in.ImageIds, awssdk.ToString(im.ImageId)) {
				out.Images = append(out.Images, im)
			}
			continue
		}
		ok := true
		for _, flt := range in.Filters {
			v := flt.Values[0]
			switch awssdk.ToString(flt.Name) {
			case "name":
				prefix, suffix, _ := strings.Cut(v, "*")
				ok = ok && strings.HasPrefix(awssdk.ToString(im.Name), prefix) && strings.HasSuffix(awssdk.ToString(im.Name), suffix)
			case "architecture":
				ok = ok && string(im.Architecture) == v
			}
		}
		if ok {
			out.Images = append(out.Images, im)
		}
	}
	return out, nil
}

func (f *fakeEC2) DescribeVolumes(_ context.Context, in *ec2.DescribeVolumesInput, _ ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	f.mu.Lock()
	f.record("DescribeVolumes")
	f.mu.Unlock()
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	if f.shared.inst.volErr != nil {
		return nil, f.shared.inst.volErr
	}
	out := &ec2.DescribeVolumesOutput{}
	id := in.Filters[0].Values[0]
	inst := f.shared.inst.find(f.region, id)
	if inst == nil {
		return out, nil
	}
	for _, v := range inst.vols {
		out.Volumes = append(out.Volumes, ec2types.Volume{VolumeId: awssdk.String(v.id), Size: awssdk.Int32(v.size), State: ec2types.VolumeStateInUse,
			VolumeType: ec2types.VolumeType(v.typ), Attachments: []ec2types.VolumeAttachment{{InstanceId: awssdk.String(id), Device: awssdk.String(v.device)}}})
	}
	return out, nil
}

// fakeSSM serves the public AMI parameters.
type fakeSSM struct {
	shared *fakeEC2s
	region string
}

func (s *fakeSSM) GetParameter(_ context.Context, in *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	s.shared.mu.Lock()
	defer s.shared.mu.Unlock()
	s.shared.inst.init()
	if s.shared.inst.ssmErr != nil {
		return nil, s.shared.inst.ssmErr
	}
	v, ok := s.shared.inst.ssmValue[awssdk.ToString(in.Name)]
	if !ok {
		return nil, &fakeAPIError{"ParameterNotFound", "not found"}
	}
	return &ssm.GetParameterOutput{Parameter: &ssmtypes.Parameter{Name: in.Name, Value: awssdk.String(v)}}, nil
}

// fakeClock advances instantly.
type fakeClock struct {
	now   time.Time
	slept []time.Duration
}

func (c *fakeClock) Now() time.Time { return c.now }
func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.slept = append(c.slept, d)
	c.now = c.now.Add(d)
	return nil
}

// useFakeClock makes the instance waits use a fake clock.
func useFakeClock(t *testing.T) *fakeClock {
	t.Helper()
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	old := instanceClock
	instanceClock = clk
	t.Cleanup(func() { instanceClock = old })
	return clk
}

// newInstanceHarness is an AWS harness with the fake clock and default
// subnet and instance type.
func newInstanceHarness(t *testing.T, flags app.Flags) *awsHarness {
	t.Helper()
	useFakeClock(t)
	return newAWSHarness(t, flags, map[string]any{"subnet_id": "subnet-0def", "security_group_ids": []any{"sg-0aaa"}})
}

// addInstance puts an instance into the fake account.
func (h *awsHarness) addInstance(region string, in *fakeInstance) *fakeInstance {
	h.ec2.mu.Lock()
	defer h.ec2.mu.Unlock()
	h.ec2.inst.init()
	if in.az == "" {
		in.az = region + "a"
	}
	if in.arch == "" {
		in.arch = "x86_64"
	}
	if in.rootDevice == "" {
		in.rootDevice = "/dev/xvda"
	}
	h.ec2.inst.byRegion[region] = append(h.ec2.inst.byRegion[region], in)
	return in
}

// instState returns the state and type of a fake instance.
func (h *awsHarness) instState(region, id string) (string, string) {
	h.ec2.mu.Lock()
	defer h.ec2.mu.Unlock()
	in := h.ec2.inst.find(region, id)
	return in.state, in.typ
}

// writes lists the write calls made so far, in order.
func (h *awsHarness) writes() []string {
	var out []string
	for _, c := range h.ec2.calls() {
		_, call, _ := strings.Cut(c, ":")
		switch call {
		case "RunInstances", "TerminateInstances", "RebootInstances", "StartInstances", "StopInstances", "ModifyInstanceAttribute", "ImportKeyPair",
			"CreateSecurityGroup", "DeleteSecurityGroup", "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress":
			out = append(out, call)
		}
	}
	return out
}

// running is a running instance with a root volume and a kept data volume.
func running(id, name string) *fakeInstance {
	return &fakeInstance{id: id, name: name, typ: "c6a.large", state: stateRunning, pub: "198.51.100.7", priv: "10.0.1.23",
		vols: []fakeVolume{{id: "vol-0111", device: "/dev/xvda", typ: "gp3", size: 30, deleteOnTerm: true}, {id: "vol-0222", device: "/dev/sdb", typ: "gp3", size: 400}}}
}

func TestNamePattern(t *testing.T) {
	for in, want := range map[string]string{"web": "*web*", "web*": "web*", "a?c": "a?c", `back\slash`: `*back\\slash*`} {
		if got := namePattern(in); got != want {
			t.Errorf("namePattern(%q) = %q, want %q", in, got, want)
		}
	}
}

// addProfile adds a second AWS account ("prod", region us-west-2).
func (h *awsHarness) addProfile(t *testing.T) {
	t.Helper()
	cfg, err := config.Load(h.dir + "/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Profiles["prod"] = &config.Profile{Platforms: map[platform.ID]*config.Account{
		platform.AWS: {Metadata: map[string]string{metaMethod: methodKeys, metaRegion: "us-west-2"}},
	}}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if err := creds.NewFile(h.dir).Set(creds.Key("prod", string(platform.AWS)), map[string]string{secretAccessKeyID: "AKIATESTFAKEKEY00001", secretSecretAccessKey: "test-secret"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.rt.ReloadConfig(); err != nil {
		t.Fatal(err)
	}
}

func TestInstanceCreateWaitTimeout(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{})
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa1", name: "slow", typ: "t3.nano", state: statePending})
	c := &client{region: "ap-east-1", ec2For: func(r string) ec2API { return newEC2(awssdk.Config{Region: r}) }}
	_, err := c.waitInstanceState(context.Background(), "", "i-0aaaaaaaaaaaaaaa1", "slow", stateRunning, time.Minute)
	var wt *platform.WaitTimeoutError
	if !errors.As(err, &wt) || wt.LastStatus != statePending || !strings.Contains(err.Error(), "instance/slow") {
		t.Errorf("wait = %v", err)
	}
}

func TestBuildRunInstancesInputIO2(t *testing.T) {
	in := buildRunInstancesInput(platform.CreateSpec{Subnet: "s", Disk: &platform.InstanceDisk{SizeGB: 10, Device: "/dev/sdc", Type: "io2", IOPS: 5000}})
	ebs := in.BlockDeviceMappings[0].Ebs
	if awssdk.ToInt32(ebs.Iops) != 5000 || ebs.Throughput != nil || len(in.NetworkInterfaces[0].Groups) != 0 {
		t.Errorf("io2 = %+v", ebs)
	}
}

func TestWaitInstanceStateTimeout(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{})
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa1", name: "web", typ: "t3.nano", state: stateStopping})
	c := &client{region: "ap-east-1", ec2For: func(r string) ec2API { return newEC2(awssdk.Config{Region: r}) }}
	clk := instanceClock.(*fakeClock)
	_, err := c.waitInstanceState(context.Background(), "", "i-0aaaaaaaaaaaaaaa1", "web", stateStopped, time.Minute)
	var wt *platform.WaitTimeoutError
	if !errors.As(err, &wt) || wt.LastStatus != stateStopping {
		t.Fatalf("wait = %v", err)
	}
	for _, d := range clk.slept {
		if d > 5*time.Second {
			t.Errorf("slept %s, want polls of 5s", d)
		}
	}
	if len(clk.slept) != 12 {
		t.Errorf("polls = %d, want 12 in a minute", len(clk.slept))
	}
	// A wait for running fails once a started instance falls back to stopped.
	h.ec2.mu.Lock()
	in := h.ec2.inst.find("ap-east-1", "i-0aaaaaaaaaaaaaaa1")
	in.state, in.next = statePending, []string{stateStopped}
	h.ec2.mu.Unlock()
	if _, err := c.waitInstanceState(context.Background(), "", "i-0aaaaaaaaaaaaaaa1", "web", stateRunning, time.Minute); err == nil || errors.As(err, &wt) {
		t.Errorf("fallback to stopped = %v", err)
	}
}

func TestEC2ErrMapping(t *testing.T) {
	if err := ec2Err("RunInstances", "r", &fakeAPIError{"InvalidParameterCombination", "x"}); !errors.Is(err, platform.ErrInvalidInput) {
		t.Errorf("combination = %v", err)
	}
	if err := ec2Err("RunInstances", "r", &fakeAPIError{"OptInRequired", "x"}); !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("opt in = %v", err)
	}
	if err := ec2Err("RunInstances", "r", &fakeAPIError{"UnauthorizedOperation", "x"}); !errors.Is(err, platform.ErrUnauthorized) || !strings.Contains(err.Error(), "ec2:RunInstances") {
		t.Errorf("denied = %v", err)
	}
	if err := runError("r", &fakeAPIError{"VcpuLimitExceeded", "x"}); errors.Is(err, platform.ErrInvalidInput) || !strings.Contains(err.Error(), "quota") {
		t.Errorf("quota = %v", err)
	}
	if !looksLikeInstanceID("i-0123456789abcdef0") || looksLikeInstanceID("i-web") || looksLikeInstanceID("web") {
		t.Error("looksLikeInstanceID")
	}
	if archFor([]string{"arm64"}) != "arm64" || archFor([]string{"x86_64", "arm64"}) != "x86_64" || archFor(nil) != "x86_64" {
		t.Error("archFor")
	}
}

// protectedErr is OperationNotPermitted with an HTTP 403 status: an
// unverified shape that must still be the general failure, not exit code 3.
type protectedErr struct{ fakeAPIError }

func (protectedErr) HTTPStatusCode() int { return 403 }

func TestDeleteProtectedIsNotAuth(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{Yes: true})
	h.addInstance("ap-east-1", running("i-0aaaaaaaaaaaaaaa1", "web"))
	h.ec2.inst.init()
	h.ec2.inst.errs["TerminateInstances"] = &protectedErr{fakeAPIError{"OperationNotPermitted", "disableApiTermination"}}
	err := h.run("ec2", "instance", "delete", "web")
	if err == nil || errors.Is(err, platform.ErrUnauthorized) || !strings.Contains(err.Error(), "termination protection") {
		t.Errorf("protected = %v", err)
	}
}
