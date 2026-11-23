package aliyun

import (
	"context"
	"fmt"
	"sort"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"

	"github.com/gofika/polyctl/internal/platform"
)

// Instance is the inventory representation of an ECS instance.
type Instance struct {
	ID           string `json:"id" yaml:"id"`
	Name         string `json:"name" yaml:"name"`
	Status       string `json:"status" yaml:"status"`
	Type         string `json:"type" yaml:"type"`
	Zone         string `json:"zone" yaml:"zone"`
	Region       string `json:"region" yaml:"region"`
	PrivateIP    string `json:"private_ip,omitempty" yaml:"private_ip,omitempty"`
	PublicIP     string `json:"public_ip,omitempty" yaml:"public_ip,omitempty"`
	CreationTime string `json:"creation_time,omitempty" yaml:"creation_time,omitempty"`
	OS           string `json:"os,omitempty" yaml:"os,omitempty"`
	CPU          int    `json:"cpu,omitempty" yaml:"cpu,omitempty"`
	MemoryMB     int    `json:"memory_mb,omitempty" yaml:"memory_mb,omitempty"`
	ChargeType   string `json:"charge_type,omitempty" yaml:"charge_type,omitempty"`
	VpcID        string `json:"vpc_id,omitempty" yaml:"vpc_id,omitempty"`
	VSwitchID    string `json:"vswitch_id,omitempty" yaml:"vswitch_id,omitempty"`
	ImageID      string `json:"image_id,omitempty" yaml:"image_id,omitempty"`
	HostName     string `json:"host_name,omitempty" yaml:"host_name,omitempty"`
	KeyPair      string `json:"key_pair,omitempty" yaml:"key_pair,omitempty"`
	// DeletionProtection refuses every DeleteInstance, forced or not.
	DeletionProtection bool `json:"deletion_protection,omitempty" yaml:"deletion_protection,omitempty"`
	// EIP and EIPAllocationID are the elastic IP address bound to the
	// instance, if any.
	EIP             string `json:"eip,omitempty" yaml:"eip,omitempty"`
	EIPAllocationID string `json:"eip_allocation_id,omitempty" yaml:"eip_allocation_id,omitempty"`
	// SecurityGroupIDs are the security groups the instance is in.
	SecurityGroupIDs []string          `json:"security_group_ids,omitempty" yaml:"security_group_ids,omitempty"`
	Tags             map[string]string `json:"tags,omitempty" yaml:"tags,omitempty"`
}

// instanceFromECS flattens the SDK instance.
func instanceFromECS(i ecs.Instance) Instance {
	out := Instance{
		ID:           i.InstanceId,
		Name:         i.InstanceName,
		Status:       i.Status,
		Type:         i.InstanceType,
		Zone:         i.ZoneId,
		Region:       i.RegionId,
		CreationTime: i.CreationTime,
		OS:           i.OSNameEn,
		CPU:          i.Cpu,
		MemoryMB:     i.Memory,
		ChargeType:   i.InstanceChargeType,
		VpcID:        i.VpcAttributes.VpcId,
		VSwitchID:    i.VpcAttributes.VSwitchId,
		ImageID:      i.ImageId,
		HostName:     i.HostName,
		KeyPair:      i.KeyPairName,

		DeletionProtection: i.DeletionProtection,
		EIP:                i.EipAddress.IpAddress,
		// An address without an allocation id is no EIP of the account.
		EIPAllocationID: i.EipAddress.AllocationId,
	}
	if len(i.SecurityGroupIds.SecurityGroupId) > 0 {
		out.SecurityGroupIDs = append([]string(nil), i.SecurityGroupIds.SecurityGroupId...)
	}
	if out.OS == "" {
		out.OS = i.OSName
	}
	if out.CPU == 0 {
		out.CPU = i.CPU
	}
	out.PrivateIP = privateIP(i)
	out.PublicIP = publicIP(i)
	if len(i.Tags.Tag) > 0 {
		out.Tags = map[string]string{}
		for _, t := range i.Tags.Tag {
			k, v := t.TagKey, t.TagValue
			if k == "" {
				k, v = t.Key, t.Value
			}
			if k != "" {
				out.Tags[k] = v
			}
		}
	}
	return out
}

// publicIP is the public address of an instance: its own public address
// (an instance created with outbound bandwidth), else its EIP. A VPC
// instance created with InternetMaxBandwidthOut=0 has an empty
// PublicIpAddress list, and its EipAddress is an object of empty strings
// until an EIP is bound.
func publicIP(i ecs.Instance) string {
	for _, ip := range i.PublicIpAddress.IpAddress {
		if ip != "" {
			return ip
		}
	}
	return i.EipAddress.IpAddress
}

// privateIP is the private address of an instance: the classic network
// address, else the primary address of its primary network interface (VPC
// instances), else the first VPC private address (the same value).
func privateIP(i ecs.Instance) string {
	for _, ip := range i.InnerIpAddress.IpAddress {
		if ip != "" {
			return ip
		}
	}
	nics := i.NetworkInterfaces.NetworkInterface
	for _, n := range nics {
		if n.Type == "Primary" && n.PrimaryIpAddress != "" {
			return n.PrimaryIpAddress
		}
	}
	if len(nics) > 0 && nics[0].PrimaryIpAddress != "" {
		return nics[0].PrimaryIpAddress
	}
	for _, ip := range i.VpcAttributes.PrivateIpAddress.IpAddress {
		if ip != "" {
			return ip
		}
	}
	return ""
}

func instanceResource(in Instance) platform.Resource {
	name := in.Name
	if name == "" {
		name = in.ID
	}
	return platform.Resource{Type: platform.ResInstance, ID: in.ID, Name: name, ParentID: in.Region, Data: in}
}

// ListInstances lists the ECS instances of a region ("" = profile region).
func (c *client) ListInstances(ctx context.Context, region string) ([]platform.Resource, error) {
	if region == "" {
		region = c.region
	}
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return nil, err
	}
	var out []platform.Resource
	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := ecs.CreateDescribeInstancesRequest()
		c.route(req, endpointECS)
		req.RegionId = region
		req.PageNumber = requests.NewInteger(page)
		req.PageSize = requests.NewInteger(pageSize)
		resp, err := cl.DescribeInstances(req)
		if err != nil {
			return nil, wrapErr("ecs DescribeInstances "+region, err)
		}
		for _, i := range resp.Instances.Instance {
			in := instanceFromECS(i)
			if in.Region == "" {
				in.Region = region
			}
			out = append(out, instanceResource(in))
		}
		if len(resp.Instances.Instance) == 0 || len(out) >= resp.TotalCount {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// StartInstance starts a stopped instance.
func (c *client) StartInstance(ctx context.Context, region, id string) error {
	if region == "" {
		region = c.region
	}
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return err
	}
	req := ecs.CreateStartInstanceRequest()
	c.route(req, endpointECS)
	req.InstanceId = id
	if _, err := cl.StartInstance(req); err != nil {
		return wrapErr("ecs StartInstance "+id, err)
	}
	return nil
}

// StopInstance stops a running instance.
func (c *client) StopInstance(ctx context.Context, region, id string, force bool) error {
	if region == "" {
		region = c.region
	}
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return err
	}
	req := ecs.CreateStopInstanceRequest()
	c.route(req, endpointECS)
	req.InstanceId = id
	if force {
		req.ForceStop = requests.NewBoolean(true)
	}
	if _, err := cl.StopInstance(req); err != nil {
		return wrapErr("ecs StopInstance "+id, err)
	}
	return nil
}

// describeInstance returns one instance by id, for post-action status.
func (c *client) describeInstance(ctx context.Context, region, id string) (*Instance, error) {
	if region == "" {
		region = c.region
	}
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return nil, err
	}
	req := ecs.CreateDescribeInstancesRequest()
	c.route(req, endpointECS)
	req.RegionId = region
	req.InstanceIds = fmt.Sprintf("[%q]", id)
	resp, err := cl.DescribeInstances(req)
	if err != nil {
		return nil, wrapErr("ecs DescribeInstances "+id, err)
	}
	if len(resp.Instances.Instance) == 0 {
		return nil, fmt.Errorf("instance %s in %s: %w", id, region, platform.ErrNotFound)
	}
	in := instanceFromECS(resp.Instances.Instance[0])
	return &in, nil
}
