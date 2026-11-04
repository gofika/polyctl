package aws

import (
	"context"
	"fmt"
	"sort"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
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
	return platform.Resource{Type: platform.ResInstance, ID: i.ID, Name: i.Name, Data: i}
}

// describeInstances lists every instance of a region.
func (c *client) describeInstances(ctx context.Context, region string) ([]instanceInfo, error) {
	if region == "" {
		region = c.region
	}
	var out []instanceInfo
	pg := ec2.NewDescribeInstancesPaginator(c.ec2For(region), &ec2.DescribeInstancesInput{})
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe instances in %s: %w", region, mapErr(err))
		}
		for _, r := range page.Reservations {
			for _, in := range r.Instances {
				out = append(out, instanceFrom(region, in))
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
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

// instanceStateChange is the result of start/stop.
type instanceStateChange struct {
	ID            string `json:"id" yaml:"id"`
	PreviousState string `json:"previous_state" yaml:"previous_state"`
	CurrentState  string `json:"current_state" yaml:"current_state"`
}

func stateChanges(changes []ec2types.InstanceStateChange) []instanceStateChange {
	out := make([]instanceStateChange, 0, len(changes))
	for _, ch := range changes {
		sc := instanceStateChange{ID: awssdk.ToString(ch.InstanceId)}
		if ch.PreviousState != nil {
			sc.PreviousState = string(ch.PreviousState.Name)
		}
		if ch.CurrentState != nil {
			sc.CurrentState = string(ch.CurrentState.Name)
		}
		out = append(out, sc)
	}
	return out
}

// startInstance starts one instance.
func (c *client) startInstance(ctx context.Context, region, id string) ([]instanceStateChange, error) {
	if region == "" {
		region = c.region
	}
	out, err := c.ec2For(region).StartInstances(ctx, &ec2.StartInstancesInput{InstanceIds: []string{id}})
	if err != nil {
		return nil, fmt.Errorf("start instance %s in %s: %w", id, region, mapErr(err))
	}
	return stateChanges(out.StartingInstances), nil
}

// stopInstance stops one instance.
func (c *client) stopInstance(ctx context.Context, region, id string, force bool) ([]instanceStateChange, error) {
	if region == "" {
		region = c.region
	}
	in := &ec2.StopInstancesInput{InstanceIds: []string{id}}
	if force {
		in.Force = awssdk.Bool(true)
	}
	out, err := c.ec2For(region).StopInstances(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("stop instance %s in %s: %w", id, region, mapErr(err))
	}
	return stateChanges(out.StoppingInstances), nil
}
