package aliyun

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// ECS instance status values.
const (
	instRunning  = "Running"
	instStopped  = "Stopped"
	instPending  = "Pending"
	instStarting = "Starting"
	instStopping = "Stopping"
)

// Error codes of the ECS instance API (verified on real accounts).
const (
	errInstanceInitializing = "IncorrectInstanceStatus.Initializing"
	errDeletionProtection   = "InvalidOperation.DeletionProtection"
	errVSwitchNotExist      = "InvalidVSwitchId.NotExist"
)

// The fixed settings of an instance polyctl creates: pay as you go, pay by
// traffic, and no public address of its own (outbound bandwidth 0): the
// public address is an EIP bound afterwards.
const (
	instanceChargeType     = "PostPaid"
	instanceInternetCharge = "PayByTraffic"
	instanceBandwidthOut   = 0
	defaultInstanceType    = "ecs.u1-c1m1.large"
	defaultSystemDiskGiB   = 20
	defaultSystemDiskCat   = "cloud_essd_entry"
	instanceNameMin        = 2
	instanceNameMax        = 128
	hostNameMin            = 2
	hostNameMax            = 64
	instancePageSize       = 100
	describeDisksPageSize  = 100
	instanceTypeSystemDisk = "system"
	instanceNameIDPrefix   = "i-"
)

var _ platform.ComputeService = (*client)(nil)

// runSpec is the request of RunInstances.
type runSpec struct {
	Name, HostName, Type, Image string
	SecurityGroup, VSwitch      string
	KeyPair                     string
	DiskGiB                     int
	DiskCategory                string
	ClientToken                 string
}

// token derives the ClientToken of the request from its content: a retried
// request returns the instance the first attempt made, and a request that
// differs in anything gets another token (the same token with other
// parameters is IdempotentParameterMismatch).
func (s runSpec) token(profile, region string) string {
	return platform.ClientToken("aliyun.ecs.RunInstances", profile, region, s.Name, s.HostName, s.Type, s.Image,
		s.SecurityGroup, s.VSwitch, s.KeyPair, s.DiskGiB, s.DiskCategory)
}

// runInstance creates one instance and returns its id.
func (c *client) runInstance(ctx context.Context, region string, s runSpec) (string, error) {
	region = c.regionOr(region)
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return "", err
	}
	req := ecs.CreateRunInstancesRequest()
	c.route(req, endpointECS)
	req.RegionId = region
	req.InstanceName = s.Name
	req.HostName = s.HostName
	req.InstanceType = s.Type
	req.InstanceChargeType = instanceChargeType
	req.InternetChargeType = instanceInternetCharge
	req.InternetMaxBandwidthOut = requests.NewInteger(instanceBandwidthOut)
	req.ImageId = s.Image
	req.SecurityGroupId = s.SecurityGroup
	req.VSwitchId = s.VSwitch
	req.KeyPairName = s.KeyPair
	req.SystemDiskCategory = s.DiskCategory
	req.SystemDiskSize = strconv.Itoa(s.DiskGiB)
	req.Amount = requests.NewInteger(1)
	req.ClientToken = s.ClientToken
	resp, err := cl.RunInstances(req)
	if err != nil {
		return "", runInstanceError(wrapErr("ecs RunInstances "+s.Name, err))
	}
	if len(resp.InstanceIdSets.InstanceIdSet) == 0 || resp.InstanceIdSets.InstanceIdSet[0] == "" {
		return "", fmt.Errorf("ecs RunInstances %s: the answer holds no instance id (request %s)", s.Name, resp.RequestId)
	}
	return resp.InstanceIdSets.InstanceIdSet[0], nil
}

// runInstanceError adds what to do to the RunInstances errors that have a
// remedy. A missing key pair, group, vSwitch or image already maps to
// "not found" by its code.
func runInstanceError(err error) error {
	code := platform.ErrorCode(err)
	switch {
	case strings.Contains(code, "NoStock"), strings.Contains(code, "OutOfStock"):
		return fmt.Errorf("%w (the zone has no stock of this type: pass --vswitch in another zone, or another --type)", err)
	case code == "InvalidSystemDiskSize.LessThanImageSize":
		return fmt.Errorf("%w (pass a larger --disk: the system disk cannot be smaller than the image)", err)
	case code == "InvalidParameter.Mismatch":
		return fmt.Errorf("%w (the security group and the vSwitch must be in the same VPC)", err)
	}
	return err
}

// findInstances returns the instances of a region named exactly name. The
// name filter of DescribeInstances matches whole names without regard to
// case, so the answer is compared case-sensitively here.
func (c *client) findInstances(ctx context.Context, region, name string) ([]Instance, error) {
	region = c.regionOr(region)
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return nil, err
	}
	var out []Instance
	seen := 0
	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := ecs.CreateDescribeInstancesRequest()
		c.route(req, endpointECS)
		req.RegionId = region
		req.InstanceName = name
		req.PageNumber = requests.NewInteger(page)
		req.PageSize = requests.NewInteger(instancePageSize)
		resp, err := cl.DescribeInstances(req)
		if err != nil {
			return nil, wrapErr("ecs DescribeInstances "+region, err)
		}
		for _, i := range resp.Instances.Instance {
			if i.InstanceName != name {
				continue
			}
			in := instanceFromECS(i)
			if in.Region == "" {
				in.Region = region
			}
			out = append(out, in)
		}
		seen += len(resp.Instances.Instance)
		if len(resp.Instances.Instance) == 0 || seen >= resp.TotalCount {
			break
		}
	}
	return out, nil
}

// instanceStatus returns the status of an instance from
// DescribeInstanceStatus; "" when it is not listed (the API answers an
// empty list, not an error, for an unknown id).
func (c *client) instanceStatus(ctx context.Context, region, id string) (string, error) {
	region = c.regionOr(region)
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return "", err
	}
	req := ecs.CreateDescribeInstanceStatusRequest()
	c.route(req, endpointECS)
	req.RegionId = region
	req.InstanceId = &[]string{id}
	resp, err := cl.DescribeInstanceStatus(req)
	if err != nil {
		return "", wrapErr("ecs DescribeInstanceStatus "+id, err)
	}
	for _, st := range resp.InstanceStatuses.InstanceStatus {
		if st.InstanceId == id || st.InstanceId == "" {
			return st.Status, nil
		}
	}
	return "", nil
}

// deleteInstance deletes an instance; force deletes a running one.
func (c *client) deleteInstance(ctx context.Context, region, id string, force bool) error {
	region = c.regionOr(region)
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return err
	}
	req := ecs.CreateDeleteInstanceRequest()
	c.route(req, endpointECS)
	req.RegionId = region
	req.InstanceId = id
	if force {
		req.Force = requests.NewBoolean(true)
	}
	if _, err := cl.DeleteInstance(req); err != nil {
		return wrapErr("ecs DeleteInstance "+id, err)
	}
	return nil
}

// rebootInstance restarts a running instance; force is ForceStop (the
// API has no ForceReboot).
func (c *client) rebootInstance(ctx context.Context, region, id string, force bool) error {
	region = c.regionOr(region)
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return err
	}
	req := ecs.CreateRebootInstanceRequest()
	c.route(req, endpointECS)
	req.RegionId = region
	req.InstanceId = id
	if force {
		req.ForceStop = requests.NewBoolean(true)
	}
	if _, err := cl.RebootInstance(req); err != nil {
		return wrapErr("ecs RebootInstance "+id, err)
	}
	return nil
}

// modifyInstanceSpec changes the type of a stopped instance.
func (c *client) modifyInstanceSpec(ctx context.Context, region, id, typ string) error {
	region = c.regionOr(region)
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return err
	}
	req := ecs.CreateModifyInstanceSpecRequest()
	c.route(req, endpointECS)
	req.RegionId = region
	req.InstanceId = id
	req.InstanceType = typ
	req.ClientToken = platform.ClientToken("aliyun.ecs.ModifyInstanceSpec", region, id, typ)
	if _, err := cl.ModifyInstanceSpec(req); err != nil {
		return wrapErr("ecs ModifyInstanceSpec "+id, err)
	}
	return nil
}

// systemDiskSize returns the size in GiB of an instance's system disk, 0
// when it has none listed.
func (c *client) systemDiskSize(ctx context.Context, region, id string) (int, error) {
	region = c.regionOr(region)
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return 0, err
	}
	req := ecs.CreateDescribeDisksRequest()
	c.route(req, endpointECS)
	req.RegionId = region
	req.InstanceId = id
	req.DiskType = instanceTypeSystemDisk
	req.PageSize = requests.NewInteger(describeDisksPageSize)
	resp, err := cl.DescribeDisks(req)
	if err != nil {
		return 0, wrapErr("ecs DescribeDisks "+id, err)
	}
	for _, d := range resp.Disks.Disk {
		if d.Type == "" || d.Type == instanceTypeSystemDisk {
			return d.Size, nil
		}
	}
	return 0, nil
}

// CreateInstance creates an instance from a platform spec
// (platform.ComputeService): Subnet is the vSwitch, the first security
// group is used, the disk is the system disk.
func (c *client) CreateInstance(ctx context.Context, spec platform.CreateSpec) (string, error) {
	s := runSpec{Name: spec.Name, HostName: spec.Name, Type: spec.Type, Image: spec.Image, VSwitch: spec.Subnet,
		KeyPair: spec.KeyPair, DiskGiB: defaultSystemDiskGiB, DiskCategory: defaultSystemDiskCat, ClientToken: spec.ClientToken}
	if h, _, err := normalizeHostName(spec.Name); err == nil {
		s.HostName = h
	}
	if len(spec.SecurityGroups) > 0 {
		s.SecurityGroup = spec.SecurityGroups[0]
	}
	if spec.Disk != nil {
		if spec.Disk.SizeGB > 0 {
			s.DiskGiB = int(spec.Disk.SizeGB)
		}
		if spec.Disk.Type != "" {
			s.DiskCategory = spec.Disk.Type
		}
	}
	if s.ClientToken == "" {
		s.ClientToken = s.token("", spec.Region)
	}
	return c.runInstance(ctx, spec.Region, s)
}

// DeleteInstance deletes a stopped instance (platform.ComputeService).
func (c *client) DeleteInstance(ctx context.Context, region, id string) error {
	return c.deleteInstance(ctx, region, id, false)
}

// RebootInstance restarts a running instance (platform.ComputeService).
func (c *client) RebootInstance(ctx context.Context, region, id string) error {
	return c.rebootInstance(ctx, region, id, false)
}

// ResizeInstance changes the type of a stopped instance
// (platform.ComputeService).
func (c *client) ResizeInstance(ctx context.Context, region, id string, spec platform.ResizeSpec) error {
	return c.modifyInstanceSpec(ctx, region, id, spec.Type)
}

// checkInstanceName refuses a name ECS refuses (a 1-character name, *), or
// that polyctl would read as an instance id.
func checkInstanceName(name string) error {
	switch n := len([]rune(name)); {
	case strings.TrimSpace(name) == "":
		return app.UsageErrf("the instance name is empty")
	case strings.HasPrefix(name, instanceNameIDPrefix):
		return app.UsageErrf("instance name %q: names may not start with i- (that is how ids are written)", name)
	case strings.Contains(name, "*"):
		return app.UsageErrf("instance name %q holds *, which Alibaba Cloud refuses in names", name)
	case n < instanceNameMin:
		return app.UsageErrf("instance name %q is too short (at least %d characters)", name, instanceNameMin)
	case n > instanceNameMax:
		return app.UsageErrf("instance name %q is longer than %d characters", name, instanceNameMax)
	}
	return nil
}

// normalizeHostName derives the host name of an instance from its name:
// every character other than a letter, a digit, a dot or a hyphen
// (underscores included) becomes a hyphen, the result is cut to 64
// characters, and leading and trailing hyphens and dots are dropped.
// changed reports a host name that differs from the name; fewer than 2
// characters left is a usage error.
func normalizeHostName(name string) (host string, changed bool, err error) {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	host = b.String()
	if len(host) > hostNameMax {
		host = host[:hostNameMax]
	}
	host = strings.Trim(host, "-.")
	if len(host) < hostNameMin {
		return "", false, app.UsageErrf("instance name %q gives no usable host name (letters, digits, hyphens and dots, at least %d characters)", name, hostNameMin)
	}
	return host, host != name, nil
}

// looksLikeInstanceID reports a reference written as an instance id.
func looksLikeInstanceID(ref string) bool {
	return strings.HasPrefix(ref, instanceNameIDPrefix) && len(ref) > len(instanceNameIDPrefix)
}
