package aws

import (
	"context"
	"fmt"
	"slices"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// locateInstanceVolume finds the volume attached to an instance as device
// (default: the instance's root device, read from the instance). When no
// volume has that device, a single volume is taken only when the device
// was not given; otherwise the volumes are listed and the choice is the
// user's (exit code 2): polyctl does not guess which disk is meant.
func locateInstanceVolume(ctx context.Context, rt *app.Runtime, ref, device, region string) (*locatedVolume, error) {
	li, err := resolveInstance(ctx, rt, ref, region, false)
	if err != nil {
		return nil, err
	}
	dev := device
	if dev == "" {
		dev = awssdk.ToString(li.inst.RootDeviceName)
	}
	if dev != "" {
		vols, err := li.c.listVolumes(ctx, li.region, volumeFilters{InstanceID: li.id(), Device: dev})
		if err != nil {
			return nil, err
		}
		if len(vols) == 1 {
			return &locatedVolume{c: li.c, profile: li.profile, region: li.region, vol: vols[0]}, nil
		}
	}
	all, err := li.c.listVolumes(ctx, li.region, volumeFilters{InstanceID: li.id()})
	if err != nil {
		return nil, err
	}
	switch {
	case len(all) == 0:
		return nil, fmt.Errorf("%w: instance %s has no EBS volumes", platform.ErrNotFound, instanceLabel(li.inst))
	case len(all) == 1 && device == "":
		return &locatedVolume{c: li.c, profile: li.profile, region: li.region, vol: all[0]}, nil
	}
	var cands []string
	for _, v := range all {
		dev := ""
		if a := volumeAttached(v); a != nil {
			dev = awssdk.ToString(a.Device)
		}
		cands = append(cands, fmt.Sprintf("%s %s %dGB", dev, awssdk.ToString(v.VolumeId), awssdk.ToInt32(v.Size)))
	}
	return nil, app.UsageErrf("instance %s has no volume attached as %s; its volumes are: %s. Pass --device <dev> or the volume id",
		instanceLabel(li.inst), orNone(dev), strings.Join(cands, ", "))
}

// isIOType reports a provisioned-IOPS volume type.
func isIOType(t string) bool { return t == "io1" || t == "io2" }

// resizeDiff compares what resize asks for with the volume: the changes as
// "size 300 -> 500" parts, and the fields already as asked.
func resizeDiff(v ec2types.Volume, m volumeChange) (diffs, same []string) {
	cmp := func(field string, cur, want any, given bool) {
		if !given {
			return
		}
		if fmt.Sprint(cur) == fmt.Sprint(want) {
			same = append(same, fmt.Sprintf("%s %v", field, cur))
			return
		}
		diffs = append(diffs, fmt.Sprintf("%s %v -> %v", field, cur, want))
	}
	cmp("size", awssdk.ToInt32(v.Size), awssdk.ToInt32(m.Size), m.Size != nil)
	cmp("type", string(v.VolumeType), m.Type, m.Type != "")
	cmp("iops", awssdk.ToInt32(v.Iops), awssdk.ToInt32(m.Iops), m.Iops != nil)
	cmp("throughput", awssdk.ToInt32(v.Throughput), awssdk.ToInt32(m.Throughput), m.Throughput != nil)
	return diffs, same
}

// growHint tells how to grow the file system after a size change: polyctl
// does not touch the inside of the instance.
func growHint(rt *app.Runtime, id string, effective bool) {
	if effective {
		rt.Infof("the new size is in effect in AWS; grow the partition and file system inside the instance yourself (polyctl does not):")
	} else {
		rt.Infof("once the modification is optimizing or completed (`polyctl aws ec2 volume get %s`), grow the partition and file system inside the instance yourself (polyctl does not):", id)
	}
	rt.Infof("  data disk (NVMe /dev/nvme1n1, ext4): sudo resize2fs /dev/nvme1n1")
	rt.Infof("  root disk (xfs):                     sudo growpart /dev/nvme0n1 1 && sudo xfs_growfs /")
}

func volumeResizeCmd(rt *app.Runtime) *cobra.Command {
	var size, iops, throughput int32
	var typ, instance, device, region string
	var complete bool
	var wf app.WaitFlags
	cmd := &cobra.Command{
		Use:   "resize [<vol-id|name>] [--size <GB>] [--iops <n>] [--throughput <n>] [--type <t>]",
		Short: "Grow an EBS volume or change its type, IOPS or throughput",
		Long: `Change an EBS volume in AWS: --size grows it (EBS volumes cannot shrink: a
smaller size is exit code 2), --type, --iops and --throughput change its
performance. Only the fields given are sent. The volume is named by its id
or Name tag, or, without it, by --instance and --device (default: the
instance's root device): a volume is never guessed when the instance has
several and none is attached as that device (exit code 2).

When every field given is as asked already, the volume is reported
unchanged and nothing is sent: AWS accepts such a request and counts it
against the modification rate limit. A modification still modifying or
optimizing is exit code 1 (also with --dry-run). The rate limit
(VolumeModificationRateExceeded) is exit code 1 with the time AWS names for
the next modification. AWS checks the IOPS and throughput ranges.

resize waits until the modification is optimizing or completed, when the
new size is visible inside the instance (5 second polls, --timeout 10m;
--no-wait returns at once); --wait-complete waits for completed, which can
take hours for large volumes (--timeout defaults to 6h then). polyctl does
not grow the partition or file system: the commands to run inside the
instance are printed.`,
		Example: "  polyctl aws ec2 volume resize vol-0222 --size 500 --dry-run\n  polyctl aws ec2 volume resize --instance site-xz7 --device /dev/sdb --size 500",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			flags := cmd.Flags()
			var change volumeChange
			if flags.Changed("size") {
				if size <= 0 {
					return app.UsageErrf("--size must be a positive number of GB")
				}
				change.Size = awssdk.Int32(size)
			}
			if flags.Changed("iops") {
				if iops < 0 {
					return app.UsageErrf("--iops must not be negative")
				}
				change.Iops = awssdk.Int32(iops)
			}
			if flags.Changed("throughput") {
				if throughput < 0 {
					return app.UsageErrf("--throughput must not be negative")
				}
				change.Throughput = awssdk.Int32(throughput)
			}
			if typ != "" {
				if !slices.Contains(volumeTypes, typ) {
					return app.UsageErrf("--type %q: expected one of %s", typ, strings.Join(volumeTypes, ", "))
				}
				change.Type = typ
			}
			if change.empty() {
				return app.UsageErrf("resize needs at least one of --size, --type, --iops or --throughput")
			}
			switch {
			case len(args) == 1 && instance != "":
				return app.UsageErrf("name the volume, or --instance (with --device) to find it, not both")
			case len(args) == 0 && instance == "":
				return app.UsageErrf("resize needs the volume id or name, or --instance <name|id> [--device <dev>]")
			case device != "" && instance == "":
				return app.UsageErrf("--device needs --instance")
			}
			wait, timeout, err := wf.Resolve(cmd)
			if err != nil {
				return err
			}
			if complete {
				if !wait {
					return app.UsageErrf("--wait-complete and --no-wait contradict each other")
				}
				if !flags.Changed("timeout") {
					timeout = volumeCompleteTimeout
				}
			}
			var l *locatedVolume
			if len(args) == 1 {
				l, err = resolveVolume(ctx, rt, args[0], region)
			} else {
				if rt.Flags.Offline {
					return app.ErrOffline
				}
				l, err = locateInstanceVolume(ctx, rt, instance, device, region)
			}
			if err != nil {
				return err
			}
			l.store(ctx, rt)
			target := l.target()
			cur := string(l.vol.VolumeType)
			if change.Size != nil && *change.Size < awssdk.ToInt32(l.vol.Size) {
				return app.UsageErrf("volume %s is %dGB: EBS volumes cannot shrink (--size %d); create a smaller volume and copy the data instead",
					l.id(), awssdk.ToInt32(l.vol.Size), *change.Size)
			}
			if isIOType(change.Type) && change.Iops == nil && !isIOType(cur) {
				return app.UsageErrf("--type %s needs --iops (volume %s is %s now)", change.Type, l.id(), cur)
			}
			diffs, same := resizeDiff(l.vol, change)
			if len(diffs) == 0 {
				rt.Infof("volume %s is as asked already: nothing sent (AWS would count a request without a change against the modification rate limit)", l.id())
				return rt.RenderReport(platform.Report{Target: target, DryRun: rt.DryRun(), Changes: []platform.Change{
					{Resource: l.resource(), Action: platform.Unchanged, ID: l.id(), Detail: strings.Join(same, ", ")}}})
			}
			m, err := l.c.latestModification(ctx, l.region, l.id())
			if err != nil {
				return err
			}
			if m != nil {
				if st := string(m.ModificationState); st == modModifying || st == modOptimizing {
					return fmt.Errorf("volume %s is being modified (%s): wait until the modification is completed, then retry (`polyctl aws ec2 volume get %s` shows it)",
						l.id(), modProgress(m), l.id())
				}
			}
			detail := strings.Join(diffs, ", ")
			ch := platform.Change{Resource: l.resource(), Action: platform.Updated, ID: l.id(), Detail: detail}
			if done, err := rt.WouldWrite(target, ch); done || err != nil {
				return err
			}
			if _, err := l.c.modifyVolume(ctx, l.region, l.id(), change); err != nil {
				return err
			}
			grown := change.Size != nil && *change.Size > awssdk.ToInt32(l.vol.Size)
			if !wait {
				if err := l.reread(ctx); err != nil {
					rt.Verbosef("re-read volume %s: %v", l.id(), err)
				}
				l.store(ctx, rt)
				ch.Detail = detail + " (modifying)"
				rt.Infof("modification of volume %s requested", l.id())
				if grown {
					growHint(rt, l.id(), false)
				}
				return rt.RenderReport(platform.Report{Target: target, Changes: []platform.Change{ch}})
			}
			rt.Infof("modification of volume %s requested; waiting until it is %s...", l.id(), map[bool]string{true: "completed", false: "optimizing or completed"}[complete])
			got, err := l.c.waitModification(ctx, l.region, l.id(), complete, timeout)
			if rerr := l.reread(ctx); rerr != nil {
				rt.Verbosef("re-read volume %s: %v", l.id(), rerr)
			}
			l.store(ctx, rt)
			if err != nil {
				return fmt.Errorf("modification of volume %s (%s) was requested: %w", l.id(), detail, err)
			}
			ch.Detail = fmt.Sprintf("%s (%s)", detail, string(got.ModificationState))
			if grown {
				growHint(rt, l.id(), true)
			}
			return rt.RenderReport(platform.Report{Target: target, Changes: []platform.Change{ch}})
		},
	}
	cmd.Flags().Int32Var(&size, "size", 0, "new size in GB (grow only)")
	cmd.Flags().Int32Var(&iops, "iops", 0, "new IOPS (gp3, io1, io2)")
	cmd.Flags().Int32Var(&throughput, "throughput", 0, "new throughput in MiB/s (gp3)")
	cmd.Flags().StringVar(&typ, "type", "", "new volume type ("+strings.Join(volumeTypes, ", ")+"; default: unchanged)")
	cmd.Flags().StringVar(&instance, "instance", "", "find the volume on this instance (name or id) instead of naming it")
	cmd.Flags().StringVar(&device, "device", "", "with --instance: the device of the volume (default: the instance's root device)")
	cmd.Flags().BoolVar(&complete, "wait-complete", false, "wait until the modification is completed, not only optimizing (can take hours)")
	cmd.Flags().StringVar(&region, "region", "", "region of the volume or instance (default: looked up)")
	app.AddWaitFlags(cmd, &wf, true, volumeResizeTimeout)
	return cmd
}
