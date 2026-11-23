package aws

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/gofika/polyctl/internal/platform"
)

var _ platform.ComputeService = (*client)(nil)

// EC2 instance states.
const (
	statePending      = string(ec2types.InstanceStateNamePending)
	stateRunning      = string(ec2types.InstanceStateNameRunning)
	stateStopping     = string(ec2types.InstanceStateNameStopping)
	stateStopped      = string(ec2types.InstanceStateNameStopped)
	stateShuttingDown = string(ec2types.InstanceStateNameShuttingDown)
	stateTerminated   = string(ec2types.InstanceStateNameTerminated)
)

// instanceStates are the values --state accepts.
var instanceStates = []string{stateRunning, stateStopped, stateStopping, statePending, stateTerminated, stateShuttingDown}

// The waits of the instance commands poll every 5 seconds (the SDK
// waiters start at 15): small instances reach running within one poll.
// Tests replace the clock so that nothing really sleeps.
var (
	instancePollInterval                = 5 * time.Second
	instanceClock        platform.Clock = platform.RealClock
)

// defaultInstanceTimeout bounds the waits of the instance commands.
const defaultInstanceTimeout = 5 * time.Minute

// dialTCP opens and closes one TCP connection (resize --wait-port); tests
// replace it.
var dialTCP = func(ctx context.Context, addr string, timeout time.Duration) error {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

// newClientToken returns a fresh idempotency token for one RunInstances
// of one command run: a retry inside the run reuses it, a second run of
// the command never does.
var newClientToken = func() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("polyctl-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func (c *client) regionOr(region string) string {
	if region == "" {
		return c.region
	}
	return region
}

// Error codes of the EC2 instance calls that are the caller's to correct.
var ec2UsageCodes = map[string]bool{
	"InvalidInstanceType":         true,
	"InvalidParameterCombination": true,
	"InvalidParameterValue":       true,
	"MissingParameter":            true,
}

// ec2Err wraps an error of the EC2 call action ("RunInstances") in region:
// usage errors map to exit code 2, OptInRequired to the authentication
// code, and a denial names the IAM action the call needs.
func ec2Err(action, region string, err error) error {
	code := platform.ErrorCode(err)
	switch {
	case ec2UsageCodes[code]:
		return fmt.Errorf("%w: ec2:%s in %s: %w", platform.ErrInvalidInput, action, region, err)
	case code == "OptInRequired":
		return fmt.Errorf("%w: ec2:%s in %s (the account is not subscribed to EC2 in this region): %w", platform.ErrUnauthorized, action, region, err)
	}
	m := mapErr(err)
	if errors.Is(m, platform.ErrUnauthorized) {
		return fmt.Errorf("ec2:%s in %s (the credentials need the IAM action ec2:%s): %w", action, region, action, m)
	}
	return fmt.Errorf("ec2:%s in %s: %w", action, region, m)
}

// instanceState returns the state name of an instance.
func instanceState(in ec2types.Instance) string {
	if in.State == nil {
		return ""
	}
	return string(in.State.Name)
}

// instanceName returns the Name tag of an instance.
func instanceName(in ec2types.Instance) string {
	for _, t := range in.Tags {
		if awssdk.ToString(t.Key) == "Name" {
			return awssdk.ToString(t.Value)
		}
	}
	return ""
}

// instanceLabel names an instance in messages: "name (id)", or the id.
func instanceLabel(in ec2types.Instance) string {
	id := awssdk.ToString(in.InstanceId)
	if n := instanceName(in); n != "" {
		return n + " (" + id + ")"
	}
	return id
}

// looksLikeInstanceID reports whether ref is an EC2 instance id.
func looksLikeInstanceID(ref string) bool {
	if !strings.HasPrefix(ref, "i-") || len(ref) < 10 {
		return false
	}
	for _, r := range ref[2:] {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// describeInstancesWith runs a paginated DescribeInstances.
func (c *client) describeInstancesWith(ctx context.Context, region string, in *ec2.DescribeInstancesInput) ([]ec2types.Instance, error) {
	region = c.regionOr(region)
	var out []ec2types.Instance
	pg := ec2.NewDescribeInstancesPaginator(c.ec2For(region), in)
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, r := range page.Reservations {
			out = append(out, r.Instances...)
		}
	}
	return out, nil
}

// findInstances returns the instances of region that ref names, in every
// state (terminated ones included): ref is an instance id, or the value of
// the Name tag. An id that matches nothing is also tried as a name.
func (c *client) findInstances(ctx context.Context, region, ref string) ([]ec2types.Instance, error) {
	region = c.regionOr(region)
	if looksLikeInstanceID(ref) {
		out, err := c.describeInstancesWith(ctx, region, &ec2.DescribeInstancesInput{InstanceIds: []string{ref}})
		switch {
		case err == nil && len(out) > 0:
			return out, nil
		case err != nil && !platform.HasErrorCode(err, "InvalidInstanceID.NotFound", "InvalidInstanceID.Malformed"):
			return nil, ec2Err("DescribeInstances", region, err)
		}
	}
	out, err := c.describeInstancesWith(ctx, region, &ec2.DescribeInstancesInput{
		Filters: []ec2types.Filter{{Name: awssdk.String("tag:Name"), Values: []string{ref}}},
	})
	if err != nil {
		return nil, ec2Err("DescribeInstances", region, err)
	}
	// The filter is a pattern: keep the exact names.
	exact := out[:0]
	for _, in := range out {
		if instanceName(in) == ref {
			exact = append(exact, in)
		}
	}
	return exact, nil
}

// liveInstances drops terminated instances: they stay visible for a while
// after their termination, Name tag included.
func liveInstances(all []ec2types.Instance) []ec2types.Instance {
	var out []ec2types.Instance
	for _, in := range all {
		if instanceState(in) != stateTerminated {
			out = append(out, in)
		}
	}
	return out
}

// describeInstance reads one instance by id; a missing one is ErrNotFound.
func (c *client) describeInstance(ctx context.Context, region, id string) (ec2types.Instance, error) {
	region = c.regionOr(region)
	out, err := c.describeInstancesWith(ctx, region, &ec2.DescribeInstancesInput{InstanceIds: []string{id}})
	if err != nil {
		if platform.HasErrorCode(err, "InvalidInstanceID.NotFound") {
			return ec2types.Instance{}, fmt.Errorf("%w: instance %s in %s", platform.ErrNotFound, id, region)
		}
		return ec2types.Instance{}, ec2Err("DescribeInstances", region, err)
	}
	for _, in := range out {
		if awssdk.ToString(in.InstanceId) == id {
			return in, nil
		}
	}
	return ec2types.Instance{}, fmt.Errorf("%w: instance %s in %s", platform.ErrNotFound, id, region)
}

// instanceVolume is one EBS volume attached to an instance.
type instanceVolume struct {
	VolumeID            string `json:"volume_id" yaml:"volume_id"`
	Size                int32  `json:"size" yaml:"size"`
	Device              string `json:"device" yaml:"device"`
	State               string `json:"state" yaml:"state"`
	VolumeType          string `json:"volume_type" yaml:"volume_type"`
	DeleteOnTermination bool   `json:"delete_on_termination" yaml:"delete_on_termination"`
}

// instanceVolumes lists the volumes attached to an instance. Whether a
// volume goes with the instance comes from the instance's block device
// mappings, by device name.
func (c *client) instanceVolumes(ctx context.Context, region string, in ec2types.Instance) ([]instanceVolume, error) {
	region = c.regionOr(region)
	id := awssdk.ToString(in.InstanceId)
	dot := map[string]bool{}
	for _, m := range in.BlockDeviceMappings {
		if m.Ebs != nil {
			dot[awssdk.ToString(m.DeviceName)] = awssdk.ToBool(m.Ebs.DeleteOnTermination)
		}
	}
	var out []instanceVolume
	pg := ec2.NewDescribeVolumesPaginator(c.ec2For(region), &ec2.DescribeVolumesInput{
		Filters: []ec2types.Filter{{Name: awssdk.String("attachment.instance-id"), Values: []string{id}}},
	})
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, ec2Err("DescribeVolumes", region, err)
		}
		for _, v := range page.Volumes {
			for _, a := range v.Attachments {
				if awssdk.ToString(a.InstanceId) != id {
					continue
				}
				dev := awssdk.ToString(a.Device)
				del, ok := dot[dev]
				if !ok {
					del = awssdk.ToBool(a.DeleteOnTermination)
				}
				out = append(out, instanceVolume{VolumeID: awssdk.ToString(v.VolumeId), Size: awssdk.ToInt32(v.Size), Device: dev,
					State: string(v.State), VolumeType: string(v.VolumeType), DeleteOnTermination: del})
			}
		}
	}
	// The root volume first, then by device name.
	root := awssdk.ToString(in.RootDeviceName)
	sort.Slice(out, func(i, j int) bool {
		if (out[i].Device == root) != (out[j].Device == root) {
			return out[i].Device == root
		}
		return out[i].Device < out[j].Device
	})
	return out, nil
}

// instanceTypeArchs returns the architectures an instance type supports.
// An unknown type is a usage error.
func (c *client) instanceTypeArchs(ctx context.Context, region, typ string) ([]string, error) {
	region = c.regionOr(region)
	out, err := c.ec2For(region).DescribeInstanceTypes(ctx, &ec2.DescribeInstanceTypesInput{InstanceTypes: []ec2types.InstanceType{ec2types.InstanceType(typ)}})
	if err != nil {
		if platform.HasErrorCode(err, "InvalidInstanceType") {
			return nil, fmt.Errorf("%w: unknown instance type %q in %s", platform.ErrInvalidInput, typ, region)
		}
		return nil, ec2Err("DescribeInstanceTypes", region, err)
	}
	for _, it := range out.InstanceTypes {
		if string(it.InstanceType) != typ || it.ProcessorInfo == nil {
			continue
		}
		var archs []string
		for _, a := range it.ProcessorInfo.SupportedArchitectures {
			archs = append(archs, string(a))
		}
		return archs, nil
	}
	return nil, fmt.Errorf("%w: unknown instance type %q in %s", platform.ErrInvalidInput, typ, region)
}

// archFor picks the architecture of an image for an instance type: arm64
// when the type runs arm64 and not x86_64, else x86_64.
func archFor(archs []string) string {
	arm, x86 := false, false
	for _, a := range archs {
		switch a {
		case "arm64":
			arm = true
		case "x86_64":
			x86 = true
		}
	}
	if arm && !x86 {
		return "arm64"
	}
	return "x86_64"
}

// typeOffered reports whether typ is offered in the availability zone az,
// and the zones of the region that offer it.
func (c *client) typeOffered(ctx context.Context, region, typ, az string) (bool, []string, error) {
	region = c.regionOr(region)
	pg := ec2.NewDescribeInstanceTypeOfferingsPaginator(c.ec2For(region), &ec2.DescribeInstanceTypeOfferingsInput{
		LocationType: ec2types.LocationTypeAvailabilityZone,
		Filters:      []ec2types.Filter{{Name: awssdk.String("instance-type"), Values: []string{typ}}},
	})
	var zones []string
	offered := false
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return false, nil, ec2Err("DescribeInstanceTypeOfferings", region, err)
		}
		for _, o := range page.InstanceTypeOfferings {
			if string(o.InstanceType) != typ {
				continue
			}
			loc := awssdk.ToString(o.Location)
			zones = append(zones, loc)
			if loc == az {
				offered = true
			}
		}
	}
	sort.Strings(zones)
	return offered, zones, nil
}

// imageInfo is what create needs to know of a machine image.
type imageInfo struct {
	ID, Name, Arch, RootDevice, Created string
}

func imageFrom(im ec2types.Image) imageInfo {
	return imageInfo{ID: awssdk.ToString(im.ImageId), Name: awssdk.ToString(im.Name), Arch: string(im.Architecture),
		RootDevice: awssdk.ToString(im.RootDeviceName), Created: awssdk.ToString(im.CreationDate)}
}

// describeImage reads one image by id.
func (c *client) describeImage(ctx context.Context, region, id string) (imageInfo, error) {
	region = c.regionOr(region)
	out, err := c.ec2For(region).DescribeImages(ctx, &ec2.DescribeImagesInput{ImageIds: []string{id}})
	if err != nil {
		if platform.HasErrorCode(err, "InvalidAMIID.Malformed") {
			return imageInfo{}, fmt.Errorf("%w: %q is not an image id", platform.ErrInvalidInput, id)
		}
		return imageInfo{}, ec2Err("DescribeImages", region, err)
	}
	for _, im := range out.Images {
		if awssdk.ToString(im.ImageId) == id {
			return imageFrom(im), nil
		}
	}
	return imageInfo{}, fmt.Errorf("%w: image %s in %s", platform.ErrNotFound, id, region)
}

// al2023Parameter is the SSM public parameter that holds the latest
// Amazon Linux 2023 image of an architecture.
func al2023Parameter(arch string) string {
	return "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-" + arch
}

// latestAL2023AMI returns the latest Amazon Linux 2023 image of arch: the
// SSM public parameter first (deterministic), else, when it cannot be read
// (no ssm:GetParameter permission, ...), the newest image named
// al2023-ami-2023.*-kernel-6.1-<arch> owned by Amazon. note receives a
// line about the fallback.
func (c *client) latestAL2023AMI(ctx context.Context, region, arch string, note func(string)) (imageInfo, error) {
	region = c.regionOr(region)
	out, err := c.ssmFor(region).GetParameter(ctx, &ssm.GetParameterInput{Name: awssdk.String(al2023Parameter(arch))})
	if err == nil && out.Parameter != nil && strings.HasPrefix(awssdk.ToString(out.Parameter.Value), "ami-") {
		return c.describeImage(ctx, region, awssdk.ToString(out.Parameter.Value))
	}
	if err == nil {
		err = errors.New("the parameter holds no image id")
	}
	if note != nil {
		note(fmt.Sprintf("note: cannot read %s (%v); picking the newest al2023 kernel-6.1 image instead", al2023Parameter(arch), mapErr(err)))
	}
	pg := ec2.NewDescribeImagesPaginator(c.ec2For(region), &ec2.DescribeImagesInput{
		Owners: []string{"amazon"},
		Filters: []ec2types.Filter{
			{Name: awssdk.String("name"), Values: []string{"al2023-ami-2023.*-kernel-6.1-" + arch}},
			{Name: awssdk.String("state"), Values: []string{"available"}},
			{Name: awssdk.String("architecture"), Values: []string{arch}},
			{Name: awssdk.String("virtualization-type"), Values: []string{"hvm"}},
			{Name: awssdk.String("root-device-type"), Values: []string{"ebs"}},
		},
	})
	var best *imageInfo
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return imageInfo{}, ec2Err("DescribeImages", region, err)
		}
		for _, im := range page.Images {
			info := imageFrom(im)
			if best == nil || info.Created > best.Created || info.Created == best.Created && info.Name > best.Name {
				best = &info
			}
		}
	}
	if best == nil {
		return imageInfo{}, fmt.Errorf("no Amazon Linux 2023 image for %s found in %s; pass --ami <ami-id>", arch, region)
	}
	return *best, nil
}

// sortedTags returns tags as EC2 tags, sorted by key.
func sortedTags(tags map[string]string) []ec2types.Tag {
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]ec2types.Tag, 0, len(keys))
	for _, k := range keys {
		out = append(out, ec2types.Tag{Key: awssdk.String(k), Value: awssdk.String(tags[k])})
	}
	return out
}

// buildRunInstancesInput assembles RunInstances. The network goes into
// NetworkInterfaces only: SubnetId or SecurityGroupIds at the top level
// together with NetworkInterfaces is InvalidParameterCombination.
func buildRunInstancesInput(spec platform.CreateSpec) *ec2.RunInstancesInput {
	nic := ec2types.InstanceNetworkInterfaceSpecification{
		DeviceIndex:              awssdk.Int32(0),
		SubnetId:                 awssdk.String(spec.Subnet),
		AssociatePublicIpAddress: awssdk.Bool(spec.PublicIP),
	}
	if len(spec.SecurityGroups) > 0 {
		nic.Groups = append([]string(nil), spec.SecurityGroups...)
	}
	tags := sortedTags(spec.Tags)
	in := &ec2.RunInstancesInput{
		ImageId:           awssdk.String(spec.Image),
		InstanceType:      ec2types.InstanceType(spec.Type),
		MinCount:          awssdk.Int32(1),
		MaxCount:          awssdk.Int32(1),
		NetworkInterfaces: []ec2types.InstanceNetworkInterfaceSpecification{nic},
		TagSpecifications: []ec2types.TagSpecification{
			{ResourceType: ec2types.ResourceTypeInstance, Tags: tags},
			{ResourceType: ec2types.ResourceTypeVolume, Tags: tags},
		},
	}
	if spec.ClientToken != "" {
		in.ClientToken = awssdk.String(spec.ClientToken)
	}
	if spec.KeyPair != "" {
		in.KeyName = awssdk.String(spec.KeyPair)
	}
	if d := spec.Disk; d != nil {
		ebs := &ec2types.EbsBlockDevice{
			VolumeSize:          awssdk.Int32(d.SizeGB),
			VolumeType:          ec2types.VolumeType(d.Type),
			DeleteOnTermination: awssdk.Bool(d.DeleteOnTermination),
		}
		if d.IOPS > 0 {
			ebs.Iops = awssdk.Int32(d.IOPS)
		}
		if d.Throughput > 0 {
			ebs.Throughput = awssdk.Int32(d.Throughput)
		}
		in.BlockDeviceMappings = []ec2types.BlockDeviceMapping{{DeviceName: awssdk.String(d.Device), Ebs: ebs}}
	}
	return in
}

// CreateInstance runs one instance.
func (c *client) CreateInstance(ctx context.Context, spec platform.CreateSpec) (string, error) {
	region := c.regionOr(spec.Region)
	out, err := c.ec2For(region).RunInstances(ctx, buildRunInstancesInput(spec))
	if err != nil {
		return "", runError(region, err)
	}
	if len(out.Instances) == 0 || awssdk.ToString(out.Instances[0].InstanceId) == "" {
		return "", fmt.Errorf("ec2:RunInstances in %s returned no instance", region)
	}
	return awssdk.ToString(out.Instances[0].InstanceId), nil
}

// runError explains the RunInstances and StartInstances failures whose
// codes say what to do.
func runError(region string, err error) error {
	action := "RunInstances"
	switch platform.ErrorCode(err) {
	case "InsufficientInstanceCapacity":
		return fmt.Errorf("the availability zone has no capacity for this instance type right now; retry later or choose another type: %w", ec2Err(action, region, err))
	case "VcpuLimitExceeded", "InstanceLimitExceeded":
		return fmt.Errorf("the account's EC2 quota is exhausted in %s; request a quota increase or choose a smaller type: %w", region, ec2Err(action, region, err))
	}
	return ec2Err(action, region, err)
}

// DeleteInstance terminates an instance. Termination protection
// (OperationNotPermitted) is explained, never switched off.
func (c *client) DeleteInstance(ctx context.Context, region, id string) error {
	region = c.regionOr(region)
	_, err := c.ec2For(region).TerminateInstances(ctx, &ec2.TerminateInstancesInput{InstanceIds: []string{id}})
	if err != nil {
		if platform.HasErrorCode(err, "OperationNotPermitted") {
			// Not mapped by HTTP status: termination protection is the
			// general failure code, never an authentication problem.
			return fmt.Errorf("instance %s has termination protection; switch it off in AWS first (aws ec2 modify-instance-attribute --instance-id %s --no-disable-api-termination): ec2:TerminateInstances in %s: %w", id, id, region, err)
		}
		return ec2Err("TerminateInstances", region, err)
	}
	return nil
}

// RebootInstance reboots a running instance.
func (c *client) RebootInstance(ctx context.Context, region, id string) error {
	region = c.regionOr(region)
	if _, err := c.ec2For(region).RebootInstances(ctx, &ec2.RebootInstancesInput{InstanceIds: []string{id}}); err != nil {
		return ec2Err("RebootInstances", region, err)
	}
	return nil
}

// ResizeInstance changes the type of a stopped instance.
func (c *client) ResizeInstance(ctx context.Context, region, id string, spec platform.ResizeSpec) error {
	region = c.regionOr(region)
	_, err := c.ec2For(region).ModifyInstanceAttribute(ctx, &ec2.ModifyInstanceAttributeInput{
		InstanceId:   awssdk.String(id),
		InstanceType: &ec2types.AttributeValue{Value: awssdk.String(spec.Type)},
	})
	if err != nil {
		return ec2Err("ModifyInstanceAttribute", region, err)
	}
	return nil
}

// startInstanceChecked starts an instance, explaining capacity failures.
func (c *client) startInstanceChecked(ctx context.Context, region, id string) error {
	region = c.regionOr(region)
	if _, err := c.ec2For(region).StartInstances(ctx, &ec2.StartInstancesInput{InstanceIds: []string{id}}); err != nil {
		if platform.HasErrorCode(err, "InsufficientInstanceCapacity") {
			return fmt.Errorf("the availability zone has no capacity for this instance type right now; retry later with `instance start`, or choose another type: %w", ec2Err("StartInstances", region, err))
		}
		return ec2Err("StartInstances", region, err)
	}
	return nil
}

// stopInstanceChecked stops an instance; force skips the clean shutdown.
func (c *client) stopInstanceChecked(ctx context.Context, region, id string, force bool) error {
	region = c.regionOr(region)
	in := &ec2.StopInstancesInput{InstanceIds: []string{id}}
	if force {
		in.Force = awssdk.Bool(true)
	}
	if _, err := c.ec2For(region).StopInstances(ctx, in); err != nil {
		return ec2Err("StopInstances", region, err)
	}
	return nil
}

// waitInstanceState polls an instance every instancePollInterval until it
// is in state want, and returns it as last read. A wait for running fails
// when the instance falls back to stopped after it was seen starting, or
// is terminated; a missing instance counts as terminated (and as not yet
// visible while waiting for anything else).
func (c *client) waitInstanceState(ctx context.Context, region, id, label, want string, timeout time.Duration) (ec2types.Instance, error) {
	region = c.regionOr(region)
	var last ec2types.Instance
	started := false
	err := platform.WaitUntil(ctx, platform.WaitOptions{
		Resource: "instance/" + label, Want: want, Timeout: timeout, Interval: instancePollInterval, Clock: instanceClock,
	}, func(ctx context.Context) (platform.WaitState, string, error) {
		in, err := c.describeInstance(ctx, region, id)
		if err != nil {
			if errors.Is(err, platform.ErrNotFound) {
				if want == stateTerminated {
					return platform.WaitDone, stateTerminated, nil
				}
				return platform.KeepWaiting, "not visible yet", nil
			}
			return platform.KeepWaiting, "", err
		}
		last = in
		st := instanceState(in)
		if st == want {
			return platform.WaitDone, st, nil
		}
		switch want {
		case stateRunning:
			switch st {
			case statePending:
				started = true
			case stateShuttingDown, stateTerminated:
				return platform.WaitFailed, st, nil
			case stateStopping, stateStopped:
				if started {
					return platform.WaitFailed, st, nil
				}
			}
		case stateStopped:
			if st == stateShuttingDown || st == stateTerminated {
				return platform.WaitFailed, st, nil
			}
		}
		return platform.KeepWaiting, st, nil
	})
	return last, err
}

// waitTCPPort waits until a TCP connection to addr succeeds, trying every
// instancePollInterval with a 5 second connect timeout.
func waitTCPPort(ctx context.Context, addr, label string, timeout time.Duration) error {
	return platform.WaitUntil(ctx, platform.WaitOptions{
		Resource: "instance/" + label, Want: "reachable on " + addr, Timeout: timeout, Interval: instancePollInterval, Clock: instanceClock,
	}, func(ctx context.Context) (platform.WaitState, string, error) {
		if err := dialTCP(ctx, addr, 5*time.Second); err != nil {
			return platform.KeepWaiting, "not reachable", nil
		}
		return platform.WaitDone, "reachable", nil
	})
}

// instanceFilters are the server-side filters of `instance list`.
type instanceFilters struct {
	States, Types []string
	Name          string
}

func (f instanceFilters) empty() bool { return len(f.States) == 0 && len(f.Types) == 0 && f.Name == "" }

// namePattern turns --name into a tag:Name pattern: a plain value matches
// names containing it (*value*, with a backslash escaped); a value holding
// * or ? is used as the pattern it is.
func namePattern(name string) string {
	if strings.ContainsAny(name, "*?") {
		return name
	}
	return "*" + strings.ReplaceAll(name, `\`, `\\`) + "*"
}

func (f instanceFilters) ec2() []ec2types.Filter {
	var out []ec2types.Filter
	if len(f.States) > 0 {
		out = append(out, ec2types.Filter{Name: awssdk.String("instance-state-name"), Values: f.States})
	}
	if len(f.Types) > 0 {
		out = append(out, ec2types.Filter{Name: awssdk.String("instance-type"), Values: f.Types})
	}
	if f.Name != "" {
		out = append(out, ec2types.Filter{Name: awssdk.String("tag:Name"), Values: []string{namePattern(f.Name)}})
	}
	return out
}

// listInstancesFiltered lists the instances of a region that match f.
func (c *client) listInstancesFiltered(ctx context.Context, region string, f instanceFilters) ([]instanceInfo, error) {
	region = c.regionOr(region)
	all, err := c.describeInstancesWith(ctx, region, &ec2.DescribeInstancesInput{Filters: f.ec2()})
	if err != nil {
		return nil, ec2Err("DescribeInstances", region, err)
	}
	out := make([]instanceInfo, 0, len(all))
	for _, in := range all {
		out = append(out, instanceFrom(region, in))
	}
	sortInstances(out)
	return out, nil
}

func sortInstances(out []instanceInfo) {
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
}
