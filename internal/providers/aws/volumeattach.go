package aws

import (
	"errors"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// ---------------------------------------------------------------- attach

func volumeAttachCmd(rt *app.Runtime) *cobra.Command {
	var instance, device, region string
	var wf app.WaitFlags
	cmd := &cobra.Command{
		Use:   "attach <vol-id|name> --instance <name|id>",
		Short: "Attach an EBS volume to an instance",
		Long: `Attach an EBS volume to an instance as --device (default /dev/sdb). The
volume and the instance must be in one account, region and availability zone
(exit code 1 otherwise). A volume being created is waited for until it is
available first. A volume attached to that instance as that device already
is reported unchanged; one attached elsewhere is exit code 1 (detach it
first). A device the instance uses already is exit code 2. attach waits
until the attachment is attached (5 second polls, --timeout 5m; --no-wait
returns at once).

Inside the instance the volume shows up under its NVMe name (/dev/sdb is
/dev/nvme1n1 or the like on Nitro instances); mounting it is up to you. A
volume restored from a snapshot loads its blocks from S3 on first access,
which makes the first reads slow.`,
		Example: "  polyctl aws ec2 volume attach site-xz7-data --instance site-tmp --device /dev/sdb",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			region := region
			if strings.TrimSpace(instance) == "" && !rt.Interactive() {
				return app.UsageErrf("attach needs --instance <name|id>")
			}
			if len(args) == 0 || strings.TrimSpace(instance) == "" {
				// The interactive flow: an available volume, then a running
				// or stopped instance of its account and zone.
				var h volumeHit
				if len(args) == 0 {
					var err error
					if h, err = pickVolume(ctx, rt, region, "available EBS volume", volumeStatesIn(volAvailable)); err != nil {
						return err
					}
					args = []string{h.v.ID}
				} else {
					// The instances offered are those of the volume's zone.
					l, err := resolveVolume(ctx, rt, args[0], region)
					if err != nil {
						return err
					}
					h = volumeHit{profile: l.profile, v: volumeFrom(l.region, l.vol)}
				}
				if strings.TrimSpace(instance) == "" {
					what := "running or stopped AWS instance"
					keep := statesIn(stateRunning, stateStopped)
					if h.v.ID != "" {
						what += " in " + h.v.AZ
						keep = func(in instanceInfo) bool { return in.AZ == h.v.AZ && statesIn(stateRunning, stateStopped)(in) }
					}
					id, err := pickInstanceRef(ctx, rt, "--instance", h.profile, region, what, true, keep)
					if err != nil {
						return err
					}
					instance = id
				}
				if h.v.ID != "" {
					region = h.v.Region
				}
			}
			if device = strings.TrimSpace(device); device == "" {
				return app.UsageErrf("--device must not be empty")
			}
			wait, timeout, err := wf.Resolve(cmd)
			if err != nil {
				return err
			}
			li, err := resolveInstance(ctx, rt, instance, region, false)
			if err != nil {
				return err
			}
			// The volume must be in the instance's region: a name is looked
			// up there (an id is found wherever the inventory has it, and a
			// mismatch is reported below).
			volRegion := region
			if volRegion == "" && !isVolumeID(strings.TrimSpace(args[0])) {
				volRegion = li.region
			}
			l, err := resolveVolume(ctx, rt, args[0], volRegion)
			if err != nil {
				if rt.DryRun() && errors.Is(err, platform.ErrNotFound) && !isVolumeID(strings.TrimSpace(args[0])) {
					// A volume an earlier step of the same dry run would create.
					rt.Infof("volume %q does not exist (yet): reporting the attachment a run after its creation would make", args[0])
					_, werr := rt.WouldWrite(li.target(), platform.Change{Resource: "volume/" + args[0], Action: platform.Updated, ID: platform.Pending,
						Detail: fmt.Sprintf("attach %s -> %s as %s", platform.Pending, li.id(), device)})
					return werr
				}
				return err
			}
			l.store(ctx, rt)
			target := l.target()
			if l.profile != li.profile || l.region != li.region {
				return fmt.Errorf("volume %s is in aws/%s/%s and instance %s in aws/%s/%s: EBS volumes attach only within one account and region",
					l.id(), l.profile, l.region, instanceLabel(li.inst), li.profile, li.region)
			}
			instAZ := ""
			if li.inst.Placement != nil {
				instAZ = awssdk.ToString(li.inst.Placement.AvailabilityZone)
			}
			if volAZ := awssdk.ToString(l.vol.AvailabilityZone); instAZ != "" && volAZ != instAZ {
				return fmt.Errorf("volume %s is in %s and instance %s in %s: a volume attaches only to instances of its availability zone (create one from a snapshot in %s)",
					l.id(), volAZ, instanceLabel(li.inst), instAZ, instAZ)
			}
			ch := platform.Change{Resource: l.resource(), Action: platform.Updated, ID: l.id(), Detail: fmt.Sprintf("attach %s -> %s as %s", l.id(), li.id(), device)}
			switch l.state() {
			case volInUse:
				a := volumeAttached(l.vol)
				if a == nil {
					break
				}
				onInst, dev := awssdk.ToString(a.InstanceId), awssdk.ToString(a.Device)
				switch {
				case onInst == li.id() && dev == device:
					unchanged := platform.Change{Resource: l.resource(), Action: platform.Unchanged, ID: l.id(), Detail: fmt.Sprintf("attached to %s as %s", li.id(), device)}
					if wait && !rt.DryRun() && string(a.State) != "attached" {
						got, err := l.c.waitVolume(ctx, l.region, l.id(), "attached to "+li.id(), timeout, false, volumeAttachedTo(li.id()))
						if awssdk.ToString(got.VolumeId) != "" {
							l.vol = got
							l.store(ctx, rt)
						}
						if err != nil {
							return err
						}
					}
					return rt.RenderReport(platform.Report{Target: target, DryRun: rt.DryRun(), Changes: []platform.Change{unchanged}})
				case onInst == li.id():
					return fmt.Errorf("volume %s is attached to instance %s as %s already, not as %s", l.id(), instanceLabel(li.inst), dev, device)
				}
				return fmt.Errorf("volume %s is attached to instance %s as %s: detach it first (`polyctl aws ec2 volume detach %s`)", l.id(), onInst, dev, l.id())
			case volCreating:
				if rt.DryRun() {
					ch.Detail += " (after waiting for the volume to be available; now creating)"
					_, err := rt.WouldWrite(target, ch)
					return err
				}
				rt.Infof("volume %s is being created; waiting until it is available...", l.id())
				got, err := l.c.waitVolume(ctx, l.region, l.id(), volAvailable, timeout, false, volumeIn(volAvailable))
				if awssdk.ToString(got.VolumeId) != "" {
					l.vol = got
					l.store(ctx, rt)
				}
				if err != nil {
					return err
				}
			case volAvailable:
			default:
				return fmt.Errorf("volume %s is %s: only an available volume can be attached", l.id(), l.state())
			}
			// The device must be free on the instance.
			used := map[string]string{}
			for _, m := range li.inst.BlockDeviceMappings {
				id := ""
				if m.Ebs != nil {
					id = awssdk.ToString(m.Ebs.VolumeId)
				}
				used[awssdk.ToString(m.DeviceName)] = id
			}
			attached, err := li.c.listVolumes(ctx, li.region, volumeFilters{InstanceID: li.id()})
			if err != nil {
				return err
			}
			for _, v := range attached {
				for _, a := range v.Attachments {
					if awssdk.ToString(a.InstanceId) == li.id() {
						used[awssdk.ToString(a.Device)] = awssdk.ToString(v.VolumeId)
					}
				}
			}
			if holder, ok := used[device]; ok {
				return fmt.Errorf("%w: instance %s uses %s already (%s): pass another --device", platform.ErrInvalidInput, instanceLabel(li.inst), device, orNone(holder))
			}
			if done, err := rt.WouldWrite(target, ch); done || err != nil {
				return err
			}
			if err := l.c.attachVolume(ctx, l.region, l.id(), li.id(), device); err != nil {
				return err
			}
			if wait {
				got, err := l.c.waitVolume(ctx, l.region, l.id(), "attached to "+li.id(), timeout, false, volumeAttachedTo(li.id()))
				if awssdk.ToString(got.VolumeId) != "" {
					l.vol = got
				}
				l.store(ctx, rt)
				if err != nil {
					return fmt.Errorf("attachment of volume %s to %s was requested: %w", l.id(), instanceLabel(li.inst), err)
				}
				ch.Detail += "; attached"
				rt.Infof("volume %s is attached to %s as %s", l.id(), instanceLabel(li.inst), device)
			} else {
				_ = l.reread(ctx)
				l.store(ctx, rt)
				rt.Infof("attachment of volume %s to %s requested", l.id(), instanceLabel(li.inst))
			}
			rt.Infof("note: inside the instance the volume shows up under its NVMe name (%s is /dev/nvme1n1 or the like on Nitro instances); mount it yourself", device)
			if awssdk.ToString(l.vol.SnapshotId) != "" {
				rt.Infof("note: the volume comes from snapshot %s: its blocks load from S3 on first access, so the first reads are slow", awssdk.ToString(l.vol.SnapshotId))
			}
			return rt.RenderReport(platform.Report{Target: target, Changes: []platform.Change{ch}})
		},
	}
	cmd.Flags().StringVar(&instance, "instance", "", "the instance to attach the volume to (name or id; required)")
	cmd.Flags().StringVar(&device, "device", volumeDefaultDevice, "device name of the volume on the instance")
	cmd.Flags().StringVar(&region, "region", "", "region of the volume and instance (default: looked up)")
	app.AddWaitFlags(cmd, &wf, true, volumeWaitTimeout)
	return cmd
}

// ---------------------------------------------------------------- detach

func volumeDetachCmd(rt *app.Runtime) *cobra.Command {
	var region string
	var force bool
	var wf app.WaitFlags
	cmd := &cobra.Command{
		Use:   "detach <vol-id|name>",
		Short: "Detach an EBS volume from its instance (asks first)",
		Long: `Detach an EBS volume from its instance. Unmount it inside the instance first:
detaching a mounted file system can corrupt it. The volume and its instance
are shown, then a confirmation is asked (default no; --yes skips it, and the
non-interactive flow needs --yes). A volume attached to nothing is reported
unchanged, as is one being detached already (detach waits for it). The root volume of an instance is exit code 1 (stop or terminate
the instance instead). --force detaches forcibly, which can lose data: use
it only when a normal detach is stuck; it always needs --yes. detach waits
until the volume is available (5 second polls, --timeout 5m; --no-wait
returns at once).`,
		Example: "  polyctl aws ec2 volume detach site-xz7-data --yes",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if force && !rt.Flags.Yes {
				return app.UsageErrf("--force can lose data and needs --yes")
			}
			wait, timeout, err := wf.Resolve(cmd)
			if err != nil {
				return err
			}
			region := region
			if len(args) == 0 {
				h, err := pickVolume(ctx, rt, region, "in-use EBS volume", volumeStatesIn(volInUse))
				if err != nil {
					return err
				}
				args, region = []string{h.v.ID}, ""
			}
			l, err := resolveVolume(ctx, rt, args[0], region)
			if err != nil {
				return err
			}
			l.store(ctx, rt)
			target := l.target()
			a := volumeAttached(l.vol)
			if l.state() != volInUse || a == nil {
				rt.Infof("volume %s is not attached (%s)", l.id(), l.state())
				return rt.RenderReport(platform.Report{Target: target, DryRun: rt.DryRun(), Changes: []platform.Change{
					{Resource: l.resource(), Action: platform.Unchanged, ID: l.id(), Detail: "not attached (" + l.state() + ")"}}})
			}
			instID, dev := awssdk.ToString(a.InstanceId), awssdk.ToString(a.Device)
			if a.State == ec2types.VolumeAttachmentStateDetaching && !force {
				// Requested already: wait for it instead of asking again;
				// --force is what a stuck detach needs.
				unchanged := platform.Change{Resource: l.resource(), Action: platform.Unchanged, ID: l.id(), Detail: fmt.Sprintf("detaching from %s (%s) already", instID, dev)}
				if wait && !rt.DryRun() {
					rt.Infof("volume %s is being detached already; waiting until it is available...", l.id())
					got, err := l.c.waitVolume(ctx, l.region, l.id(), volAvailable, timeout, false, volumeIn(volAvailable))
					if awssdk.ToString(got.VolumeId) != "" {
						l.vol = got
						l.store(ctx, rt)
					}
					if err != nil {
						return fmt.Errorf("volume %s is being detached: %w (if it stays detaching, unmount it inside the instance, or retry with --force --yes)", l.id(), err)
					}
					unchanged.Detail = fmt.Sprintf("detached from %s (%s); available", instID, dev)
				}
				return rt.RenderReport(platform.Report{Target: target, DryRun: rt.DryRun(), Changes: []platform.Change{unchanged}})
			}
			instLabel := instID
			if in, err := l.c.describeInstance(ctx, l.region, instID); err == nil {
				instLabel = instanceLabel(in)
				if root := awssdk.ToString(in.RootDeviceName); root != "" && root == dev {
					return fmt.Errorf("volume %s is the root volume of instance %s (%s): it cannot be detached while the instance runs; stop or terminate the instance instead",
						l.id(), instLabel, dev)
				}
			} else {
				rt.Verbosef("read instance %s: %v", instID, err)
			}
			rt.Infof("volume %s in aws/%s/%s", volumeLabel(l.vol), l.profile, l.region)
			rt.Infof("  attached to  %s as %s (%s)", instLabel, dev, a.State)
			rt.Infof("Unmount the volume inside the instance first: detaching a mounted file system can corrupt it.")
			if force {
				rt.Infof("WARNING: --force detaches without the instance's cooperation and can lose data; use it only when a normal detach is stuck.")
			}
			detail := fmt.Sprintf("detach from %s (%s)", instID, dev)
			if force {
				detail += ", forced"
			}
			ch := platform.Change{Resource: l.resource(), Action: platform.Updated, ID: l.id(), Detail: detail}
			if done, err := rt.WouldWrite(target, ch); done || err != nil {
				return err
			}
			ok, err := rt.Confirm(ctx, fmt.Sprintf("Detach volume %s from instance %s?", volumeLabel(l.vol), instLabel), false)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("%w: cancelled; volume %s was not detached", platform.ErrNothingToDo, l.id())
			}
			if err := l.c.detachVolume(ctx, l.region, l.id(), force); err != nil {
				return err
			}
			if wait {
				got, err := l.c.waitVolume(ctx, l.region, l.id(), volAvailable, timeout, false, volumeIn(volAvailable))
				if awssdk.ToString(got.VolumeId) != "" {
					l.vol = got
				}
				l.store(ctx, rt)
				if err != nil {
					return fmt.Errorf("detachment of volume %s was requested: %w (if it stays detaching, unmount it inside the instance, or retry with --force --yes)", l.id(), err)
				}
				ch.Detail += "; available"
				rt.Infof("volume %s is detached and available", l.id())
			} else {
				_ = l.reread(ctx)
				l.store(ctx, rt)
				rt.Infof("detachment of volume %s requested", l.id())
			}
			return rt.RenderReport(platform.Report{Target: target, Changes: []platform.Change{ch}})
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "detach forcibly (can lose data; needs --yes)")
	cmd.Flags().StringVar(&region, "region", "", "region of the volume (default: looked up)")
	app.AddWaitFlags(cmd, &wf, true, volumeWaitTimeout)
	return cmd
}

// ---------------------------------------------------------------- delete

func volumeDeleteCmd(rt *app.Runtime) *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:   "delete <vol-id|name>",
		Short: "Delete an EBS volume (asks first)",
		Long: `Delete an EBS volume. This cannot be undone. The volume (name, size, type,
zone, source snapshot) and its latest completed snapshot are shown, with a
warning when it has no snapshot at all, then a confirmation is asked
(default no; --yes skips it, and the non-interactive flow needs --yes). An
attached volume is exit code 1: detach it first (after an instance
termination, the instance's data volumes stay in use until the instance is
terminated). A volume being deleted, or one that is gone, is reported
unchanged. Snapshots of the volume are kept.`,
		Example: "  polyctl aws ec2 volume delete site-xz7-data --yes",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			region := region
			if len(args) == 0 {
				// An attached volume cannot be deleted: available ones only.
				h, err := pickVolume(ctx, rt, region, "available EBS volume", volumeStatesIn(volAvailable))
				if err != nil {
					return err
				}
				args, region = []string{h.v.ID}, ""
			}
			l, err := resolveVolume(ctx, rt, args[0], region)
			if err != nil {
				var gone *volumeGoneError
				if errors.As(err, &gone) {
					rt.Infof("volume %s is deleted already", gone.id)
					return rt.RenderReport(platform.Report{Target: platform.Target{Platform: platform.AWS, Profile: gone.profile, Region: gone.region},
						DryRun: rt.DryRun(), Changes: []platform.Change{{Resource: "volume/" + gone.id, Action: platform.Unchanged, ID: gone.id, Detail: "deleted already"}}})
				}
				return err
			}
			target := l.target()
			switch l.state() {
			case volDeleting, volDeleted:
				l.store(ctx, rt)
				return rt.RenderReport(platform.Report{Target: target, DryRun: rt.DryRun(), Changes: []platform.Change{
					{Resource: l.resource(), Action: platform.Unchanged, ID: l.id(), Detail: "being deleted already"}}})
			case volInUse:
				l.store(ctx, rt)
				where := ""
				if a := volumeAttached(l.vol); a != nil {
					where = fmt.Sprintf(" to instance %s as %s", awssdk.ToString(a.InstanceId), awssdk.ToString(a.Device))
				}
				return fmt.Errorf("volume %s is attached%s: detach it first (`polyctl aws ec2 volume detach %s`); after an instance termination wait until the instance is terminated",
					l.id(), where, l.id())
			}
			snaps, serr := l.c.listSnapshots(ctx, l.region, snapshotFilters{VolumeID: l.id()})
			rt.Infof("volume %s in aws/%s/%s", volumeLabel(l.vol), l.profile, l.region)
			rt.Infof("  size           %dGB %s", awssdk.ToInt32(l.vol.Size), l.vol.VolumeType)
			rt.Infof("  zone           %s", awssdk.ToString(l.vol.AvailabilityZone))
			rt.Infof("  state          %s", l.state())
			rt.Infof("  from snapshot  %s", orNone(awssdk.ToString(l.vol.SnapshotId)))
			switch latest := latestCompleted(snaps); {
			case serr != nil:
				rt.Infof("  warning: cannot list the snapshots of the volume: %v", serr)
			case latest != nil:
				rt.Infof("  latest snapshot %s (%s)", awssdk.ToString(latest.SnapshotId), awssdk.ToTime(latest.StartTime).UTC().Format("2006-01-02T15:04:05Z"))
			default:
				rt.Infof("  WARNING: the volume has no snapshot: its data is gone for good once it is deleted")
			}
			rt.Infof("This cannot be undone! To keep the data, take a snapshot first: polyctl aws ec2 snapshot create %s --wait", l.id())
			ch := platform.Change{Resource: l.resource(), Action: platform.Deleted, ID: l.id(), Detail: fmt.Sprintf("%dGB %s", awssdk.ToInt32(l.vol.Size), l.vol.VolumeType)}
			if done, err := rt.WouldWrite(target, ch); done || err != nil {
				return err
			}
			ok, err := rt.Confirm(ctx, fmt.Sprintf("Delete volume %s?", volumeLabel(l.vol)), false)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("%w: cancelled; volume %s was not deleted", platform.ErrNothingToDo, l.id())
			}
			gone, err := l.c.deleteVolume(ctx, l.region, l.id())
			if err != nil {
				return err
			}
			dropVolume(ctx, rt, l.profile, l.id())
			if gone {
				ch = platform.Change{Resource: l.resource(), Action: platform.Unchanged, ID: l.id(), Detail: "deleted already"}
			} else {
				rt.Infof("volume %s is being deleted", l.id())
			}
			return rt.RenderReport(platform.Report{Target: target, Changes: []platform.Change{ch}})
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region of the volume (default: looked up)")
	return cmd
}
