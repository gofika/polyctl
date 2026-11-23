package aws

import (
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

func snapshotCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "snapshot",
		Short: "EBS snapshots: list, create",
		Long: `EBS snapshots of the account's own volumes (other accounts' public snapshots
are never listed). Snapshots are read live; the inventory does not cache
them.`,
	}
	cmd.AddCommand(snapshotListCmd(rt), snapshotCreateCmd(rt))
	return cmd
}

func snapshotListGrid(rows []snapshotInfo) output.Grid {
	g := output.Grid{Headers: []string{"ID", "VOLUME", "SIZE", "STATE", "PROGRESS", "STARTED", "DESCRIPTION", "NAME"}, Empty: "no snapshots"}
	for _, r := range rows {
		g.Rows = append(g.Rows, []string{r.ID, dashIfEmpty(r.VolumeID), strconv.Itoa(int(r.Size)), r.State, dashIfEmpty(r.Progress),
			dashIfEmpty(r.StartTime), dashIfEmpty(r.Description), dashIfEmpty(r.Name)})
	}
	return g
}

func snapshotListCmd(rt *app.Runtime) *cobra.Command {
	var volume, state, name, region string
	var latest bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the account's EBS snapshots, newest first",
		Long: `List the EBS snapshots the account owns in the profile's region (--region
another one), newest first. --volume keeps the snapshots of that volume (its
id or Name tag; its account and region are found like volume get finds
them), --state those in that state (completed, pending, error), --name those
whose Name tag matches the value (* and ? are wildcards). --latest shows
only the newest completed snapshot. No match is an empty list and exit code
0.`,
		Example: "  polyctl aws ec2 snapshot list --volume vol-0222 --latest -o json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if state != "" && !slices.Contains(snapshotStates, state) {
				return app.UsageErrf("--state %q: expected one of %s", state, strings.Join(snapshotStates, ", "))
			}
			if name != "" {
				if _, err := path.Match(name, ""); err != nil {
					return app.UsageErrf("--name %q: malformed pattern", name)
				}
			}
			if region != "" && !validRegionName(region) {
				return app.UsageErrf("--region %q: expected a region name such as us-east-1", region)
			}
			if rt.Flags.Offline {
				return fmt.Errorf("%w: snapshots are not cached in the inventory", app.ErrOffline)
			}
			f := snapshotFilters{State: state, Name: name}
			var c *client
			var profile string
			if volume != "" {
				l, err := resolveVolume(ctx, rt, volume, region)
				if err != nil {
					return err
				}
				l.store(ctx, rt)
				c, profile, region, f.VolumeID = l.c, l.profile, l.region, l.id()
			} else {
				var err error
				if profile, err = rt.ProfileFor(platform.AWS); err != nil {
					return err
				}
				if c, err = openProfile(ctx, rt, profile); err != nil {
					return err
				}
				region = c.regionOr(region)
			}
			snaps, err := c.listSnapshots(ctx, region, f)
			if err != nil {
				return err
			}
			if latest {
				if s := latestCompleted(snaps); s != nil {
					snaps = []ec2types.Snapshot{*s}
				} else {
					snaps = nil
				}
			}
			rows := []snapshotInfo{}
			for _, s := range snaps {
				r := snapshotFrom(region, s)
				r.Profile = profile
				rows = append(rows, r)
			}
			if len(rows) == 0 {
				rt.Infof("no matching snapshots in %s via aws/%s", region, profile)
			}
			return rt.Render(rows, func() output.Grid { return snapshotListGrid(rows) })
		},
	}
	cmd.Flags().StringVar(&volume, "volume", "", "only the snapshots of this volume (id or name)")
	cmd.Flags().StringVar(&state, "state", "", "only snapshots in this state ("+strings.Join(snapshotStates, ", ")+")")
	cmd.Flags().BoolVar(&latest, "latest", false, "only the newest completed snapshot")
	cmd.Flags().StringVar(&name, "name", "", "only snapshots whose Name tag matches this value (* and ? are wildcards)")
	cmd.Flags().StringVar(&region, "region", "", "region to list (default: the profile's region)")
	return cmd
}

// snapshotName is the default Name tag of a snapshot: the volume's name
// (or id) and the UTC time, 20260102T0304Z.
func snapshotName(v ec2types.Volume) string {
	base := volumeName(v)
	if base == "" {
		base = awssdk.ToString(v.VolumeId)
	}
	return base + "-" + instanceClock.Now().UTC().Format("20060102T1504Z")
}

func snapshotCreateCmd(rt *app.Runtime) *cobra.Command {
	var description, region string
	var tagArgs []string
	var wf app.WaitFlags
	cmd := &cobra.Command{
		Use:   "create <vol-id|name>",
		Short: "Snapshot an EBS volume",
		Long: `Take a snapshot of an EBS volume. Its Name tag is the volume's name (or id)
and the UTC time, <name>-20260102T0304Z, unless --tag Name=...; the tags of
defaults.aws.tags and --tag go on it. A snapshot is crash-consistent: stop
the writes or unmount the file system first for an application-consistent
copy. A snapshot of the volume still in progress is exit code 1 (AWS takes
one at a time per volume). --wait waits until the snapshot is completed (15
second polls, --timeout 30m; large volumes take long; the error state
fails).`,
		Example: `  polyctl aws ec2 snapshot create vol-0222 --description "before resize" --wait`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			wait, timeout, err := wf.Resolve(cmd)
			if err != nil {
				return err
			}
			extra, err := parseVolumeTags(tagArgs)
			if err != nil {
				return err
			}
			l, err := resolveVolume(ctx, rt, args[0], region)
			if err != nil {
				return err
			}
			l.store(ctx, rt)
			tags, err := keyPairTags(rt, l.profile)
			if err != nil {
				return err
			}
			if tags == nil {
				tags = map[string]string{}
			}
			tags["Name"] = snapshotName(l.vol)
			for k, v := range extra {
				tags[k] = v
			}
			name := tags["Name"]
			target := l.target()
			rt.Infof("note: a snapshot is crash-consistent; stop the writes or unmount the file system first for an application-consistent copy")
			detail := "snapshot of " + l.id()
			ch := platform.Change{Resource: "snapshot/" + name, Action: platform.Created, ID: platform.Pending, Detail: detail}
			if done, err := rt.WouldWrite(target, ch); done || err != nil {
				return err
			}
			snap, err := l.c.createSnapshot(ctx, l.region, l.id(), description, tags)
			if err != nil {
				return err
			}
			id := awssdk.ToString(snap.SnapshotId)
			ch.ID = id
			if wait {
				rt.Infof("snapshot %s of volume %s started; waiting until it is completed...", id, l.id())
				if _, err := l.c.waitSnapshot(ctx, l.region, id, timeout); err != nil {
					return fmt.Errorf("snapshot %s of volume %s was started: %w", id, l.id(), err)
				}
				ch.Detail = detail + "; completed"
				rt.Infof("snapshot %s is completed", id)
			} else {
				ch.Detail = detail + "; " + string(snap.State)
				rt.Infof("snapshot %s of volume %s started; `polyctl aws ec2 snapshot list --volume %s` shows its progress", id, l.id(), l.id())
			}
			return rt.RenderReport(platform.Report{Target: target, Changes: []platform.Change{ch}})
		},
	}
	cmd.Flags().StringVar(&description, "description", "", "description of the snapshot")
	cmd.Flags().StringArrayVar(&tagArgs, "tag", nil, "extra tag key=value (repeatable; Name=... replaces the default name)")
	cmd.Flags().StringVar(&region, "region", "", "region of the volume (default: looked up)")
	app.AddWaitFlags(cmd, &wf, false, snapshotWaitTimeout)
	return cmd
}
