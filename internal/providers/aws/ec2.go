package aws

import (
	"context"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/gofika/polyctl/internal/platform"
)

// instanceInfo is the inventory representation of an EC2 instance.
type instanceInfo struct {
	ID         string            `json:"id" yaml:"id"`
	Name       string            `json:"name" yaml:"name"`
	State      string            `json:"state" yaml:"state"`
	Type       string            `json:"type" yaml:"type"`
	AZ         string            `json:"az" yaml:"az"`
	Region     string            `json:"region" yaml:"region"`
	PrivateIP  string            `json:"private_ip" yaml:"private_ip"`
	PublicIP   string            `json:"public_ip" yaml:"public_ip"`
	LaunchTime string            `json:"launch_time" yaml:"launch_time"`
	Tags       map[string]string `json:"tags,omitempty" yaml:"tags,omitempty"`
	VpcID      string            `json:"vpc_id,omitempty" yaml:"vpc_id,omitempty"`
	SubnetID   string            `json:"subnet_id,omitempty" yaml:"subnet_id,omitempty"`
	PublicDNS  string            `json:"public_dns,omitempty" yaml:"public_dns,omitempty"`
	PrivateDNS string            `json:"private_dns,omitempty" yaml:"private_dns,omitempty"`
	// Interfaces are every network interface with all its addresses
	// (polyctl find).
	Interfaces []netIface `json:"interfaces,omitempty" yaml:"interfaces,omitempty"`
}

// instanceFrom converts an EC2 instance.
func instanceFrom(region string, in ec2types.Instance) instanceInfo {
	info := instanceInfo{
		ID:        awssdk.ToString(in.InstanceId),
		Type:      string(in.InstanceType),
		Region:    region,
		PrivateIP: awssdk.ToString(in.PrivateIpAddress),
		PublicIP:  awssdk.ToString(in.PublicIpAddress),
	}
	if in.State != nil {
		info.State = string(in.State.Name)
	}
	if in.Placement != nil {
		info.AZ = awssdk.ToString(in.Placement.AvailabilityZone)
	}
	if in.LaunchTime != nil {
		info.LaunchTime = in.LaunchTime.UTC().Format(time.RFC3339)
	}
	info.VpcID, info.SubnetID = awssdk.ToString(in.VpcId), awssdk.ToString(in.SubnetId)
	info.PublicDNS, info.PrivateDNS = awssdk.ToString(in.PublicDnsName), awssdk.ToString(in.PrivateDnsName)
	for _, ni := range in.NetworkInterfaces {
		info.Interfaces = append(info.Interfaces, netIfaceFromInstance(ni))
	}
	if v := awssdk.ToString(in.Ipv6Address); v != "" && len(info.Interfaces) > 0 && !containsString(info.Interfaces[0].IPv6, v) {
		info.Interfaces[0].IPv6 = append(info.Interfaces[0].IPv6, v)
	}
	if len(in.Tags) > 0 {
		info.Tags = make(map[string]string, len(in.Tags))
		for _, t := range in.Tags {
			k := awssdk.ToString(t.Key)
			info.Tags[k] = awssdk.ToString(t.Value)
			if k == "Name" {
				info.Name = awssdk.ToString(t.Value)
			}
		}
	}
	return info
}

func (i instanceInfo) resource() platform.Resource {
	return platform.Resource{Type: platform.ResInstance, ID: i.ID, Name: i.Name, ParentID: i.Region, Data: i, IPs: i.ipSet().Refs()}
}

// describeInstances lists every instance of a region.
func (c *client) describeInstances(ctx context.Context, region string) ([]instanceInfo, error) {
	return c.listInstancesFiltered(ctx, region, instanceFilters{})
}

// listInstances returns the instances of a region as inventory resources.
func (c *client) listInstances(ctx context.Context, region string) ([]platform.Resource, error) {
	instances, err := c.describeInstances(ctx, region)
	if err != nil {
		return nil, err
	}
	out := make([]platform.Resource, 0, len(instances))
	for _, i := range instances {
		out = append(out, i.resource())
	}
	return out, nil
}
