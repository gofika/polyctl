package gcp

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// sshWaitTimeout bounds resize --wait-ssh.
const sshWaitTimeout = 5 * time.Minute

// waitSSH waits until port 22 accepts connections on the internal IP, or
// on the external one where the internal network is out of reach, trying
// every 5 seconds for at most 5 minutes.
func waitSSH(ctx context.Context, name, internal, external string) (string, error) {
	var hosts []string
	for _, h := range []string{internal, external} {
		if h != "" {
			hosts = append(hosts, net.JoinHostPort(h, "22"))
		}
	}
	if len(hosts) == 0 {
		return "", fmt.Errorf("instance %s has no address to check port 22 on", name)
	}
	reached := ""
	err := platform.WaitUntil(ctx, platform.WaitOptions{
		Resource: "instance/" + name, Want: "reachable on port 22", Timeout: sshWaitTimeout, Interval: instancePollInterval, Clock: instanceClock,
	}, func(ctx context.Context) (platform.WaitState, string, error) {
		for _, addr := range hosts {
			if err := dialTCP(ctx, addr, 5*time.Second); err == nil {
				reached = addr
				return platform.WaitDone, "reachable", nil
			}
		}
		return platform.KeepWaiting, "not reachable", nil
	})
	return reached, err
}

func computeResizeCmd(rt *app.Runtime) *cobra.Command {
	var zone, typ string
	var waitSSHFlag bool
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "resize <name|id>",
		Short: "Change the machine type of a Compute Engine instance: stop, change, start",
		Long: `Change the machine type of a Compute Engine instance, found like get finds it.
The new type is checked first: one that does not exist in the instance's
zone is exit code 4, and nothing is written. The same type is unchanged.

A RUNNING instance is stopped after a confirmation (default no; --yes skips
it, and the non-interactive flow needs --yes). Before it is stopped, its
ephemeral IPs are made static, since a stopped instance loses its ephemeral
external IP: an address that already holds the IP is reused, otherwise the
IP is reserved as {name}-external-ip / {name}-internal-ip (a failure for the
external IP stops the command before the instance is stopped; for the
internal IP it is a warning). Then the instance is stopped, the type
changed, and the instance started again, each step waiting (5 second polls,
--timeout each). A TERMINATED instance is not started: the instance ends in
the power state it had. A failed type change leaves the instance stopped
with its old type.

An address that changed anyway is reported on stderr. --wait-ssh then waits
up to 5 minutes until port 22 accepts connections (on the internal IP, or
the external one).`,
		Example: "  polyctl gcp compute instance resize web-1 --machine-type e2-standard-8 --yes",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if typ == "" {
				return app.UsageErrf("--machine-type is required")
			}
			if timeout <= 0 {
				return app.UsageErrf("--timeout must be a positive duration, got %s", timeout)
			}
			l, err := resolveInstance(ctx, rt, args[0], zone, false)
			if err != nil {
				return err
			}
			target := l.target()
			cur, orig := lastSegment(l.inst.MachineType), l.inst.Status
			if cur == typ {
				rt.Infof("instance %s already is %s", l.name(), typ)
				return rt.RenderReport(platform.Report{Target: target, DryRun: rt.DryRun(), Changes: []platform.Change{
					{Resource: l.resource() + "/machine-type", Action: platform.Unchanged, Detail: typ}}})
			}
			switch {
			case orig == statusRunning, orig == statusStopping, stopped(orig):
			default:
				return fmt.Errorf("instance %s is %s: resize it once it is RUNNING or TERMINATED", l.label(), orig)
			}
			if _, err := l.c.machineType(ctx, l.zone, typ); err != nil {
				return err
			}
			region := l.region()
			origInt, origExt := ips(l.inst)
			warn := func(s string) { rt.Infof("%s", s) }
			var plan platform.Plan
			if orig == statusRunning {
				extName, intName, err := instanceAddressNames(rt, l.name(), l.zone)
				if err != nil {
					return err
				}
				list, err := l.c.listAddresses(ctx, region)
				if err != nil {
					return err
				}
				find := func(n string) *compute.Address {
					for _, a := range list {
						if a.Name == n {
							return a
						}
					}
					return nil
				}
				subnet := ""
				if len(l.inst.NetworkInterfaces) > 0 {
					subnet = l.inst.NetworkInterfaces[0].Subnetwork
				}
				for _, p := range []promoteSpec{
					{Region: region, Name: extName, IP: origExt, Type: addrExternal, Fatal: true, List: list, ByName: find(extName), Warn: warn},
					{Region: region, Name: intName, IP: origInt, Type: addrInternal, SubnetURL: subnet, List: list, ByName: find(intName), Warn: warn},
				} {
					step, ok, err := l.c.promoteStep(p)
					if err != nil {
						return err
					}
					if ok {
						plan.Add(step)
					}
				}
			}
			name := l.name()
			if !stopped(orig) {
				plan.Add(platform.Step{Resource: l.resource() + "/stop", Action: platform.Updated, Desc: "stop", Apply: func(ctx context.Context) (platform.Change, error) {
					if orig != statusStopping {
						wctx, cancel, conv := deadline(ctx, timeout, l.resource(), "stopped")
						err := l.c.stopInstance(wctx, l.zone, name)
						cancel()
						if err != nil {
							return platform.Change{}, conv(err)
						}
					}
					in, err := l.c.waitStatus(ctx, l.zone, name, statusTerminated, timeout)
					if in != nil {
						l.inst = in
						storeInstance(ctx, rt, l.profile, in)
					}
					if err != nil {
						return platform.Change{}, err
					}
					return platform.Change{Detail: "stop; " + in.Status}, nil
				}})
			}
			plan.Add(platform.Step{Resource: l.resource() + "/machine-type", Action: platform.Updated, Desc: cur + " -> " + typ, Apply: func(ctx context.Context) (platform.Change, error) {
				wctx, cancel, conv := deadline(ctx, timeout, l.resource(), "machine type "+typ)
				defer cancel()
				if err := l.c.setMachineType(wctx, l.zone, name, typ); err != nil {
					return platform.Change{}, fmt.Errorf("%w; instance %s is stopped and still %s: run the same command again to continue", conv(err), name, cur)
				}
				return platform.Change{}, nil
			}})
			if orig == statusRunning {
				plan.Add(platform.Step{Resource: l.resource() + "/start", Action: platform.Updated, Desc: "start", Apply: func(ctx context.Context) (platform.Change, error) {
					wctx, cancel, conv := deadline(ctx, timeout, l.resource(), "started")
					err := l.c.startInstance(wctx, l.zone, name)
					cancel()
					if err != nil {
						return platform.Change{}, fmt.Errorf("instance %s is stopped with machine type %s: %w", name, typ, conv(err))
					}
					in, err := l.c.waitStatus(ctx, l.zone, name, statusRunning, timeout)
					if in != nil {
						l.inst = in
						storeInstance(ctx, rt, l.profile, in)
					}
					if err != nil {
						return platform.Change{}, err
					}
					return platform.Change{Detail: "start; RUNNING"}, nil
				}})
			} else {
				rt.Infof("note: instance %s is %s and stays stopped (start it with `polyctl gcp compute instance start %s`)", name, orig, name)
			}
			if orig == statusRunning && !rt.DryRun() {
				ok, err := rt.Confirm(ctx, fmt.Sprintf("Stop instance %s to change its machine type from %s to %s? It is unavailable until it runs again.", l.label(), cur, typ), false)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("%w: cancelled; instance %s was not changed", platform.ErrNothingToDo, name)
				}
			}
			began := time.Now()
			if err := rt.Ensure(ctx, "gcp.compute.instance.resize", target, &plan); err != nil || rt.DryRun() {
				return err
			}
			l.reread(ctx, rt)
			newInt, newExt := ips(l.inst)
			if origExt != "" && newExt != origExt {
				rt.Infof("warning: IP changed: %s -> %s (external); update the DNS records and allow lists that use it", origExt, orNone(newExt))
			}
			if origInt != "" && newInt != origInt {
				rt.Infof("warning: IP changed: %s -> %s (internal)", origInt, orNone(newInt))
			}
			rt.Infof("instance %s resized %s -> %s (%s) in %s", name, cur, typ, l.inst.Status, time.Since(began).Round(time.Second))
			if waitSSHFlag {
				if l.inst.Status != statusRunning {
					rt.Infof("note: --wait-ssh skipped: instance %s is %s", name, l.inst.Status)
					return nil
				}
				addr, err := waitSSH(ctx, name, newInt, newExt)
				if err != nil {
					return err
				}
				rt.Infof("port 22 of %s accepts connections", addr)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&typ, "machine-type", "", "new machine type (required)")
	cmd.Flags().StringVar(&zone, "zone", "", "zone of the instance (default: from the inventory)")
	cmd.Flags().BoolVar(&waitSSHFlag, "wait-ssh", false, "after the start, wait up to 5 minutes until port 22 accepts connections")
	cmd.Flags().DurationVar(&timeout, "timeout", app.DefaultWaitTimeout, "upper bound of each wait (a Go duration such as 90s or 10m)")
	return cmd
}
