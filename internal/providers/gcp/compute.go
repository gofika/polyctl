package gcp

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/platform"
)

// Instance is the inventory representation of a Compute Engine instance.
type Instance struct {
	Name              string            `json:"name" yaml:"name"`
	ID                string            `json:"id" yaml:"id"`
	Zone              string            `json:"zone" yaml:"zone"`
	MachineType       string            `json:"machine_type" yaml:"machine_type"`
	Status            string            `json:"status" yaml:"status"`
	InternalIP        string            `json:"internal_ip,omitempty" yaml:"internal_ip,omitempty"`
	ExternalIP        string            `json:"external_ip,omitempty" yaml:"external_ip,omitempty"`
	CreationTimestamp string            `json:"creation_timestamp,omitempty" yaml:"creation_timestamp,omitempty"`
	Labels            map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
}

// lastSegment returns the final path element of a resource URL
// ("https://.../zones/us-central1-a" -> "us-central1-a").
func lastSegment(u string) string {
	if i := strings.LastIndex(u, "/"); i >= 0 {
		return u[i+1:]
	}
	return u
}

// instanceFromAPI flattens a Compute Engine instance.
func instanceFromAPI(in *compute.Instance) Instance {
	out := Instance{
		Name:              in.Name,
		ID:                strconv.FormatUint(in.Id, 10),
		Zone:              lastSegment(in.Zone),
		MachineType:       lastSegment(in.MachineType),
		Status:            in.Status,
		CreationTimestamp: in.CreationTimestamp,
		Labels:            in.Labels,
	}
	for _, ni := range in.NetworkInterfaces {
		if out.InternalIP == "" {
			out.InternalIP = ni.NetworkIP
		}
		for _, ac := range ni.AccessConfigs {
			if out.ExternalIP == "" && ac.NatIP != "" {
				out.ExternalIP = ac.NatIP
			}
		}
	}
	return out
}

// instanceResource wraps an Instance for the inventory.
func instanceResource(i Instance) platform.Resource {
	return platform.Resource{Type: platform.ResInstance, ID: i.ID, Name: i.Name, Data: i}
}

// ListInstances lists every instance of the project across all zones.
func (c *client) ListInstances(ctx context.Context) ([]platform.Resource, error) {
	var out []platform.Resource
	err := c.compute.Instances.AggregatedList(c.project).Pages(ctx, func(resp *compute.InstanceAggregatedList) error {
		for _, scoped := range resp.Items {
			for _, in := range scoped.Instances {
				out = append(out, instanceResource(instanceFromAPI(in)))
			}
		}
		return nil
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

// OperationResult summarises a zonal operation for output.
type OperationResult struct {
	Instance  string `json:"instance" yaml:"instance"`
	Zone      string `json:"zone" yaml:"zone"`
	Operation string `json:"operation" yaml:"operation"`
	Type      string `json:"type" yaml:"type"`
	Status    string `json:"status" yaml:"status"`
	Error     string `json:"error,omitempty" yaml:"error,omitempty"`
}

func opResult(instance, zone string, op *compute.Operation) *OperationResult {
	r := &OperationResult{Instance: instance, Zone: zone, Operation: op.Name, Type: op.OperationType, Status: op.Status}
	if op.Error != nil {
		var msgs []string
		for _, e := range op.Error.Errors {
			msgs = append(msgs, e.Code+": "+e.Message)
		}
		r.Error = strings.Join(msgs, "; ")
	}
	return r
}

// StartInstance starts an instance; with wait it blocks until the operation completes.
func (c *client) StartInstance(ctx context.Context, zone, instance string, wait bool) (*OperationResult, error) {
	op, err := c.compute.Instances.Start(c.project, zone, instance).Context(ctx).Do()
	if err != nil {
		return nil, mapErr(err)
	}
	return c.finishOp(ctx, zone, instance, op, wait)
}

// StopInstance stops an instance; with wait it blocks until the operation completes.
func (c *client) StopInstance(ctx context.Context, zone, instance string, wait bool) (*OperationResult, error) {
	op, err := c.compute.Instances.Stop(c.project, zone, instance).Context(ctx).Do()
	if err != nil {
		return nil, mapErr(err)
	}
	return c.finishOp(ctx, zone, instance, op, wait)
}

func (c *client) finishOp(ctx context.Context, zone, instance string, op *compute.Operation, wait bool) (*OperationResult, error) {
	for wait && op.Status != "DONE" {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		next, err := c.compute.ZoneOperations.Wait(c.project, zone, op.Name).Context(ctx).Do()
		if err != nil {
			return nil, mapErr(err)
		}
		op = next
	}
	res := opResult(instance, zone, op)
	if res.Error != "" {
		return res, fmt.Errorf("operation %s failed: %s", op.Name, res.Error)
	}
	return res, nil
}
