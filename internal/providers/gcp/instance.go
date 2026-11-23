package gcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/platform"
)

// Instance statuses.
const (
	statusProvisioning = "PROVISIONING"
	statusStaging      = "STAGING"
	statusRunning      = "RUNNING"
	statusStopping     = "STOPPING"
	statusStopped      = "STOPPED"
	statusTerminated   = "TERMINATED"
	statusSuspended    = "SUSPENDED"
)

// The waits of the instance commands poll every 5 seconds; tests replace
// the clock so that nothing really sleeps.
var (
	instancePollInterval                = 5 * time.Second
	instanceClock        platform.Clock = platform.RealClock
)

// dialTCP opens and closes one TCP connection (resize --wait-ssh); tests
// replace it.
var dialTCP = func(ctx context.Context, addr string, timeout time.Duration) error {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

// regionOf returns the region of a zone: the zone without its last
// "-<letter>" part ("us-central1-a" -> "us-central1").
func regionOf(zone string) string {
	if i := strings.LastIndex(zone, "-"); i > 0 {
		return zone[:i]
	}
	return zone
}

// stopped reports the statuses of an instance that does not run: an
// instance stops in TERMINATED; STOPPED is listed by the API too.
func stopped(status string) bool { return status == statusTerminated || status == statusStopped }

// waitOp polls an operation with wait until it is DONE and returns its
// error. ctx bounds the wait.
func waitOp(ctx context.Context, op *compute.Operation, wait func(name string) (*compute.Operation, error)) error {
	for op.Status != "DONE" {
		if err := ctx.Err(); err != nil {
			return err
		}
		next, err := wait(op.Name)
		if err != nil {
			return computeErr(err)
		}
		op = next
	}
	return opError(op)
}

func (c *client) waitZoneOp(ctx context.Context, zone string, op *compute.Operation) error {
	return waitOp(ctx, op, func(name string) (*compute.Operation, error) {
		return c.compute.ZoneOperations.Wait(c.project, zone, name).Context(ctx).Do()
	})
}

func (c *client) waitRegionOp(ctx context.Context, region string, op *compute.Operation) error {
	return waitOp(ctx, op, func(name string) (*compute.Operation, error) {
		return c.compute.RegionOperations.Wait(c.project, region, name).Context(ctx).Do()
	})
}

// deadline bounds ctx by timeout and returns a function that turns the
// context error of a wait that ran out of time into a WaitTimeoutError.
func deadline(ctx context.Context, timeout time.Duration, resource, want string) (context.Context, context.CancelFunc, func(error) error) {
	if timeout <= 0 {
		return ctx, func() {}, func(err error) error { return err }
	}
	wctx, cancel := context.WithTimeout(ctx, timeout)
	return wctx, cancel, func(err error) error {
		if err != nil && wctx.Err() != nil && ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
			return &platform.WaitTimeoutError{Resource: resource, Want: want, Timeout: timeout}
		}
		return err
	}
}

// getInstance reads an instance; a missing one is ErrNotFound.
func (c *client) getInstance(ctx context.Context, zone, name string) (*compute.Instance, error) {
	in, err := c.compute.Instances.Get(c.project, zone, name).Context(ctx).Do()
	if err != nil {
		return nil, computeErr(err)
	}
	return in, nil
}

// findInstance reads an instance, returning nil (no error) when it does
// not exist.
func (c *client) findInstance(ctx context.Context, zone, name string) (*compute.Instance, error) {
	in, err := c.getInstance(ctx, zone, name)
	if errors.Is(err, platform.ErrNotFound) {
		return nil, nil
	}
	return in, err
}

// insertInstance creates an instance; with wait it waits for the
// operation (not for RUNNING: see waitStatus).
func (c *client) insertInstance(ctx context.Context, zone string, in *compute.Instance, wait bool) error {
	op, err := c.compute.Instances.Insert(c.project, zone, in).Context(ctx).Do()
	if err != nil {
		return computeErr(err)
	}
	if !wait {
		return opError(op)
	}
	return c.waitZoneOp(ctx, zone, op)
}

// deleteInstance deletes an instance; with wait it waits for the operation.
func (c *client) deleteInstance(ctx context.Context, zone, name string, wait bool) error {
	op, err := c.compute.Instances.Delete(c.project, zone, name).Context(ctx).Do()
	if err != nil {
		return computeErr(err)
	}
	if !wait {
		return opError(op)
	}
	return c.waitZoneOp(ctx, zone, op)
}

// resetInstance hard-resets a running instance (no OS shutdown).
func (c *client) resetInstance(ctx context.Context, zone, name string, wait bool) error {
	op, err := c.compute.Instances.Reset(c.project, zone, name).Context(ctx).Do()
	if err != nil {
		if isReason(err, "resourceNotReady") {
			return fmt.Errorf("instance %s is not running, and a reset only applies to a running instance: %w", name, err)
		}
		return computeErr(err)
	}
	if !wait {
		return opError(op)
	}
	return c.waitZoneOp(ctx, zone, op)
}

// stopInstance stops an instance and waits for the operation.
func (c *client) stopInstance(ctx context.Context, zone, name string) error {
	op, err := c.compute.Instances.Stop(c.project, zone, name).Context(ctx).Do()
	if err != nil {
		return computeErr(err)
	}
	return c.waitZoneOp(ctx, zone, op)
}

// startInstance starts an instance and waits for the operation.
func (c *client) startInstance(ctx context.Context, zone, name string) error {
	op, err := c.compute.Instances.Start(c.project, zone, name).Context(ctx).Do()
	if err != nil {
		return computeErr(err)
	}
	return c.waitZoneOp(ctx, zone, op)
}

// machineTypeURL is the zonal machine type path Insert and SetMachineType take.
func machineTypeURL(zone, typ string) string { return "zones/" + zone + "/machineTypes/" + typ }

// setMachineType changes the machine type of a stopped instance and waits
// for the operation (which fails with UNSUPPORTED_OPERATION on a running
// one).
func (c *client) setMachineType(ctx context.Context, zone, name, typ string) error {
	op, err := c.compute.Instances.SetMachineType(c.project, zone, name, &compute.InstancesSetMachineTypeRequest{MachineType: machineTypeURL(zone, typ)}).Context(ctx).Do()
	if err != nil {
		return computeErr(err)
	}
	return c.waitZoneOp(ctx, zone, op)
}

// setIPForward changes CanIpForward in place: the instance as read is sent
// back whole (its fingerprint included) with that field changed, allowing
// a REFRESH at most (NO_EFFECT is refused for this field, RESTART could
// restart it). A stale fingerprint (the instance changed in between) is
// retried once on a fresh read. It returns the instance read afterwards.
func (c *client) setIPForward(ctx context.Context, zone string, in *compute.Instance, want bool) (*compute.Instance, error) {
	for attempt := 0; ; attempt++ {
		body := *in
		body.CanIpForward = want
		body.ForceSendFields = append(append([]string(nil), in.ForceSendFields...), "CanIpForward")
		op, err := c.compute.Instances.Update(c.project, zone, in.Name, &body).MostDisruptiveAllowedAction("REFRESH").Context(ctx).Do()
		if err != nil {
			if attempt == 0 && isFingerprintMismatch(err) {
				if in, err = c.getInstance(ctx, zone, in.Name); err != nil {
					return nil, err
				}
				if in.CanIpForward == want {
					return in, nil
				}
				continue
			}
			return nil, computeErr(err)
		}
		if err := c.waitZoneOp(ctx, zone, op); err != nil {
			return nil, err
		}
		after, err := c.getInstance(ctx, zone, in.Name)
		if err != nil {
			return nil, err
		}
		if after.CanIpForward != want {
			return after, fmt.Errorf("instance %s still reports ip forwarding %v after the update", in.Name, after.CanIpForward)
		}
		return after, nil
	}
}

// machineType reads a machine type of a zone; a missing one is ErrNotFound.
func (c *client) machineType(ctx context.Context, zone, typ string) (*compute.MachineType, error) {
	mt, err := c.compute.MachineTypes.Get(c.project, zone, typ).Context(ctx).Do()
	if err != nil {
		err = computeErr(err)
		if errors.Is(err, platform.ErrNotFound) {
			return nil, fmt.Errorf("%w: machine type %s does not exist in zone %s of project %s (the equivalent of `gcloud compute machine-types list --zones %s`)", platform.ErrNotFound, typ, zone, c.project, zone)
		}
		return nil, err
	}
	return mt, nil
}

// projectMetadata reads the project-wide instance metadata.
func (c *client) projectMetadata(ctx context.Context) (*compute.Metadata, error) {
	p, err := c.compute.Projects.Get(c.project).Context(ctx).Do()
	if err != nil {
		return nil, computeErr(err)
	}
	return p.CommonInstanceMetadata, nil
}

// network reads a VPC network.
func (c *client) network(ctx context.Context, name string) (*compute.Network, error) {
	n, err := c.compute.Networks.Get(c.project, name).Context(ctx).Do()
	if err != nil {
		err = computeErr(err)
		if errors.Is(err, platform.ErrNotFound) {
			return nil, fmt.Errorf("%w: network %s in project %s", platform.ErrNotFound, name, c.project)
		}
		return nil, err
	}
	return n, nil
}

// subnetwork reads a subnetwork of a region.
func (c *client) subnetwork(ctx context.Context, region, name string) (*compute.Subnetwork, error) {
	s, err := c.compute.Subnetworks.Get(c.project, region, name).Context(ctx).Do()
	if err != nil {
		err = computeErr(err)
		if errors.Is(err, platform.ErrNotFound) {
			return nil, fmt.Errorf("%w: subnetwork %s in region %s of project %s", platform.ErrNotFound, name, region, c.project)
		}
		return nil, err
	}
	return s, nil
}

// subnetworksOf lists the subnetworks of a region that belong to network,
// matching the last segment of their network URL exactly.
func (c *client) subnetworksOf(ctx context.Context, region, network string) ([]*compute.Subnetwork, error) {
	var out []*compute.Subnetwork
	err := c.compute.Subnetworks.List(c.project, region).Pages(ctx, func(l *compute.SubnetworkList) error {
		for _, s := range l.Items {
			if lastSegment(s.Network) == network {
				out = append(out, s)
			}
		}
		return nil
	})
	if err != nil {
		return nil, computeErr(err)
	}
	return out, nil
}

// disk reads a zonal disk.
func (c *client) disk(ctx context.Context, zone, name string) (*compute.Disk, error) {
	d, err := c.compute.Disks.Get(c.project, zone, name).Context(ctx).Do()
	if err != nil {
		return nil, computeErr(err)
	}
	return d, nil
}

// waitStatus polls an instance every 5 seconds until it reports want.
// Waiting for RUNNING, TERMINATED or STOPPED is a failure (a Spot instance
// reclaimed, a start that failed: the status message is quoted), and so is
// an instance that disappears. timeout bounds the wait.
func (c *client) waitStatus(ctx context.Context, zone, name, want string, timeout time.Duration) (*compute.Instance, error) {
	var last *compute.Instance
	err := platform.WaitUntil(ctx, platform.WaitOptions{
		Resource: "instance/" + name, Want: want, Timeout: timeout, Interval: instancePollInterval, Clock: instanceClock,
	}, func(ctx context.Context) (platform.WaitState, string, error) {
		in, err := c.getInstance(ctx, zone, name)
		if err != nil {
			return platform.KeepWaiting, "", err
		}
		last = in
		st := in.Status
		if st == want || (want == statusTerminated && stopped(st)) {
			return platform.WaitDone, st, nil
		}
		if want == statusRunning && stopped(st) {
			if in.StatusMessage != "" {
				st += " (" + in.StatusMessage + ")"
			}
			return platform.WaitFailed, st, nil
		}
		return platform.KeepWaiting, st, nil
	})
	return last, err
}
