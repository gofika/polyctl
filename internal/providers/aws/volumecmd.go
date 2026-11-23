package aws

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// Defaults of the volume commands.
const (
	volumeDefaultType       = "gp3"
	volumeDefaultIops       = 3000
	volumeDefaultThroughput = 125
	volumeDefaultDevice     = "/dev/sdb"
	volumeWaitTimeout       = 5 * time.Minute
	volumeResizeTimeout     = 10 * time.Minute
	volumeCompleteTimeout   = 6 * time.Hour
	snapshotWaitTimeout     = 30 * time.Minute
)

func volumeCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "volume",
		Short: "EBS volumes: list, get, create, resize, attach, detach, delete",
		Long: `EBS volumes. A volume is named by its id (vol-...) or its Name tag. An id is
looked up in the inventory (volume), which holds the volumes of every
enabled region of every selected account (synced once when it does not know
the id); --region asks the selected profile's account in that region
directly. A Name tag is looked up live in the region of each selected
account (the profile's region, or --region); several volumes of one name
are ambiguous (exit code 5).`,
	}
	cmd.AddCommand(volumeListCmd(rt), volumeGetCmd(rt), volumeCreateCmd(rt), volumeResizeCmd(rt), volumeAttachCmd(rt), volumeDetachCmd(rt), volumeDeleteCmd(rt))
	return cmd
}

// ------------------------------------------------------------ routing

// locatedVolume is a volume found for a command, with the client of the
// account that holds it.
type locatedVolume struct {
	c       *client
	profile string
	region  string
	vol     ec2types.Volume
}

func (l *locatedVolume) id() string       { return awssdk.ToString(l.vol.VolumeId) }
func (l *locatedVolume) state() string    { return string(l.vol.State) }
func (l *locatedVolume) resource() string { return "volume/" + l.id() }
func (l *locatedVolume) target() platform.Target {
	return platform.Target{Platform: platform.AWS, Profile: l.profile, Region: l.region}
}

// reread reads the volume again; on failure it is kept as known.
func (l *locatedVolume) reread(ctx context.Context) error {
	v, err := l.c.describeVolume(ctx, l.region, l.id())
	if err != nil {
		return err
	}
	l.vol = v
	return nil
}

// store writes the volume as known to the inventory.
func (l *locatedVolume) store(ctx context.Context, rt *app.Runtime) {
	storeVolume(ctx, rt, l.profile, l.region, l.vol)
}

// storeVolume writes a volume to the inventory.
func storeVolume(ctx context.Context, rt *app.Runtime, profile, region string, v ec2types.Volume) {
	if awssdk.ToString(v.VolumeId) == "" {
		return
	}
	db, err := rt.DB()
	if err != nil {
		return
	}
	cfg, _ := rt.Config()
	_ = db.Upsert(ctx, inventory.Set{Platform: platform.AWS, Profile: profile, Type: platform.ResVolume}, volumeFrom(region, v).resource(), cfg.TTLFor(platform.ResVolume))
}

// dropVolume removes a volume from the inventory.
func dropVolume(ctx context.Context, rt *app.Runtime, profile, id string) {
	if db, err := rt.DB(); err == nil {
		_ = db.Delete(ctx, inventory.Set{Platform: platform.AWS, Profile: profile, Type: platform.ResVolume}, platform.ResVolume, id)
	}
}

// volumeGoneError is a volume the inventory knew that AWS no longer has.
type volumeGoneError struct{ profile, region, id string }

func (e *volumeGoneError) Error() string {
	return fmt.Sprintf("volume %s is gone from aws/%s/%s", e.id, e.profile, e.region)
}

func (e *volumeGoneError) Unwrap() error { return platform.ErrNotFound }

// volumeHit is a volume of the inventory and the profile that holds it.
type volumeHit struct {
	profile string
	v       volumeInfo
}

// volumeInventoryHits returns the cached volumes of the accounts that
// match. With sync, a miss syncs the volume sets of the accounts once and
// repeats the lookup; an account that could not be synced is returned as
// the error when still nothing matches. With --offline nothing is synced,
// and an inventory that never held the volumes is ErrNeverSynced.
func volumeInventoryHits(ctx context.Context, rt *app.Runtime, accounts []config.AccountRef, what string, sync bool, match func(volumeInfo) bool) ([]volumeHit, error) {
	db, err := rt.DB()
	if err != nil {
		return nil, err
	}
	lookup := func() ([]volumeHit, error) {
		var out []volumeHit
		for _, a := range accounts {
			rows, err := db.List(ctx, inventory.Query{Platform: platform.AWS, Profile: a.Profile, Type: platform.ResVolume})
			if err != nil {
				return nil, err
			}
			for _, r := range rows {
				var v volumeInfo
				if r.Decode(&v) != nil || v.ID == "" || !match(v) {
					continue
				}
				out = append(out, volumeHit{profile: a.Profile, v: v})
			}
		}
		return out, nil
	}
	hits, err := lookup()
	if err != nil || len(hits) > 0 {
		return hits, err
	}
	if rt.Flags.Offline || !sync {
		for _, a := range accounts {
			st, err := db.GetState(ctx, inventory.Set{Platform: a.Platform, Profile: a.Profile, Type: platform.ResVolume})
			if err != nil {
				return nil, err
			}
			if st != nil {
				return nil, nil
			}
		}
		return nil, fmt.Errorf("%w: the EBS volumes of the selected AWS accounts are not in the local inventory", inventory.ErrNeverSynced)
	}
	// A volume created since the last sync is found without --refresh.
	rt.Infof("looking up %s: syncing the EBS volumes of %d account(s)...", what, len(accounts))
	var syncErr error
	for _, a := range accounts {
		if err := syncSet(ctx, rt, a, platform.ResVolume); err != nil {
			rt.Infof("warning: sync %s: %v", a.Label(), err)
			if syncErr == nil {
				syncErr = fmt.Errorf("sync %s: %w", a.Label(), err)
			}
		}
	}
	if hits, err = lookup(); err != nil {
		return nil, err
	}
	if len(hits) == 0 && syncErr != nil {
		return nil, fmt.Errorf("cannot tell where %s is: %w", what, syncErr)
	}
	return hits, nil
}

// syncSet syncs one resource type of one account.
func syncSet(ctx context.Context, rt *app.Runtime, a config.AccountRef, typ platform.ResourceType) error {
	reps, err := rt.SyncAccount(ctx, a, []platform.ResourceType{typ})
	if err != nil {
		return err
	}
	for _, r := range reps {
		if r.Err != nil {
			return r.Err
		}
	}
	return nil
}

// pickVolumeHit chooses among inventory hits: one is the answer, several
// are ambiguous (exit code 5), none is not found (exit code 4).
func pickVolumeHit(rt *app.Runtime, ref string, hits []volumeHit) (volumeHit, error) {
	switch len(hits) {
	case 0:
		hint := "pass --profile and --region for a volume outside the inventory, or retry with --refresh"
		if rt.Flags.Offline {
			hint = "it is not in the local inventory; retry without --offline"
		}
		return volumeHit{}, fmt.Errorf("%w: volume %q in the selected AWS accounts (%s)", platform.ErrNotFound, ref, hint)
	case 1:
		return hits[0], nil
	}
	var names []string
	for _, h := range hits {
		names = append(names, fmt.Sprintf("aws/%s/%s (%s, %s)", h.profile, h.v.Region, h.v.ID, h.v.State))
	}
	return volumeHit{}, &app.AmbiguousError{What: fmt.Sprintf("volume %q", ref), Candidates: names, Hint: "pass --profile <name> and/or --region <r> to choose"}
}

// volumeMatcher matches inventory volumes by id, or by Name tag; region,
// when set, restricts the match.
func volumeMatcher(ref, region string) func(volumeInfo) bool {
	byID := isVolumeID(ref)
	return func(v volumeInfo) bool {
		if region != "" && v.Region != region {
			return false
		}
		if byID {
			return v.ID == ref
		}
		return v.Name == ref
	}
}

// resolveVolume finds the volume ref names and reads it live. An id with
// --region is asked of the selected profile's account directly; an id
// without it is looked up in the inventory (synced once on a miss). A
// Name tag is looked up live in the region of every selected account (the
// profile's region, or --region). A volume the inventory knew that AWS no
// longer has is a *volumeGoneError (not found).
func resolveVolume(ctx context.Context, rt *app.Runtime, ref, region string) (*locatedVolume, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, app.UsageErrf("the volume id or name is empty")
	}
	if region != "" && !validRegionName(region) {
		return nil, app.UsageErrf("--region %q: expected a region name such as us-east-1", region)
	}
	if rt.Flags.Offline {
		return nil, app.ErrOffline
	}
	if isVolumeID(ref) {
		if region != "" {
			profile, err := rt.ProfileFor(platform.AWS)
			if err != nil {
				return nil, err
			}
			c, err := openProfile(ctx, rt, profile)
			if err != nil {
				return nil, err
			}
			v, err := c.describeVolume(ctx, region, ref)
			if err != nil {
				if errors.Is(err, platform.ErrNotFound) {
					dropVolume(ctx, rt, profile, ref)
					return nil, fmt.Errorf("%w: volume %s in aws/%s/%s", platform.ErrNotFound, ref, profile, region)
				}
				return nil, err
			}
			return &locatedVolume{c: c, profile: profile, region: region, vol: v}, nil
		}
		accounts, err := awsAccounts(rt)
		if err != nil {
			return nil, err
		}
		hits, err := volumeInventoryHits(ctx, rt, accounts, "volume "+ref, true, volumeMatcher(ref, ""))
		if err != nil {
			return nil, err
		}
		h, err := pickVolumeHit(rt, ref, hits)
		if err != nil {
			return nil, err
		}
		c, err := openProfile(ctx, rt, h.profile)
		if err != nil {
			return nil, err
		}
		v, err := c.describeVolume(ctx, h.v.Region, ref)
		if err != nil {
			if errors.Is(err, platform.ErrNotFound) {
				dropVolume(ctx, rt, h.profile, ref)
				return nil, &volumeGoneError{profile: h.profile, region: h.v.Region, id: ref}
			}
			return nil, err
		}
		return &locatedVolume{c: c, profile: h.profile, region: h.v.Region, vol: v}, nil
	}
	accounts, err := awsAccounts(rt)
	if err != nil {
		return nil, err
	}
	var found []*locatedVolume
	var failure error
	for _, a := range accounts {
		c, err := openProfile(ctx, rt, a.Profile)
		if err == nil {
			r := c.regionOr(region)
			var vols []ec2types.Volume
			if vols, err = c.findVolumes(ctx, r, ref); err == nil {
				for _, v := range vols {
					found = append(found, &locatedVolume{c: c, profile: a.Profile, region: r, vol: v})
				}
				continue
			}
		}
		rt.Infof("warning: looking up volume %q in aws/%s: %v", ref, a.Profile, err)
		if failure == nil {
			failure = fmt.Errorf("aws/%s: %w", a.Profile, err)
		}
	}
	switch {
	case len(found) == 1:
		return found[0], nil
	case len(found) > 1:
		var names []string
		accts := map[string]bool{}
		for _, l := range found {
			names = append(names, fmt.Sprintf("aws/%s/%s (%s, %s)", l.profile, l.region, l.id(), l.state()))
			accts[l.profile] = true
		}
		hint := "pass --profile <name> to choose"
		if len(accts) == 1 {
			hint = "the account holds several volumes with this name; pass the volume id"
		}
		return nil, &app.AmbiguousError{What: fmt.Sprintf("volume %q", ref), Candidates: names, Hint: hint}
	case failure != nil:
		return nil, fmt.Errorf("cannot tell where volume %q is: %w", ref, failure)
	}
	return nil, fmt.Errorf("%w: volume named %q in the selected AWS accounts (a name is looked up in the profile's region; pass --region for another one)", platform.ErrNotFound, ref)
}

// regionOfAZ returns the region of an availability zone: the zone name
// without its trailing letter (ap-east-1a -> ap-east-1).
func regionOfAZ(az string) string {
	return strings.TrimRightFunc(az, func(r rune) bool { return r >= 'a' && r <= 'z' })
}

// --------------------------------------------------------------- views

// volumeRow is a row of `volume list`.
type volumeRow struct {
	ID           string `json:"volume_id" yaml:"volume_id"`
	Name         string `json:"name" yaml:"name"`
	Profile      string `json:"profile" yaml:"profile"`
	Region       string `json:"region" yaml:"region"`
	AZ           string `json:"availability_zone" yaml:"availability_zone"`
	Size         int32  `json:"size" yaml:"size"`
	Type         string `json:"volume_type" yaml:"volume_type"`
	Iops         int32  `json:"iops" yaml:"iops"`
	Throughput   int32  `json:"throughput" yaml:"throughput"`
	State        string `json:"state" yaml:"state"`
	InstanceID   string `json:"instance_id" yaml:"instance_id"`
	InstanceName string `json:"instance_name" yaml:"instance_name"`
	Device       string `json:"device" yaml:"device"`
}

func volumeRowOf(profile string, v volumeInfo, names map[string]string) volumeRow {
	r := volumeRow{ID: v.ID, Name: v.Name, Profile: profile, Region: v.Region, AZ: v.AZ, Size: v.Size, Type: v.Type, Iops: v.Iops,
		Throughput: v.Throughput, State: v.State}
	for _, a := range v.Attachments {
		if a.State == string(ec2types.VolumeAttachmentStateDetached) {
			continue
		}
		r.InstanceID, r.Device, r.InstanceName = a.InstanceID, a.Device, names[a.InstanceID]
		break
	}
	return r
}

func intOrDash(n int32) string {
	if n == 0 {
		return "-"
	}
	return strconv.Itoa(int(n))
}

func volumeListGrid(rows []volumeRow) output.Grid {
	g := output.Grid{Headers: []string{"ID", "NAME", "SIZE", "TYPE", "IOPS", "THROUGHPUT", "STATE", "AZ", "INSTANCE", "DEVICE"}, Empty: "no volumes"}
	for _, r := range rows {
		inst := r.InstanceName
		if inst == "" {
			inst = r.InstanceID
		}
		g.Rows = append(g.Rows, []string{r.ID, dashIfEmpty(r.Name), strconv.Itoa(int(r.Size)), r.Type, intOrDash(r.Iops), intOrDash(r.Throughput),
			r.State, r.AZ, dashIfEmpty(inst), dashIfEmpty(r.Device)})
	}
	return g
}

// attachmentView is an attachment in `volume get`.
type attachmentView struct {
	InstanceID          string `json:"instance_id" yaml:"instance_id"`
	InstanceName        string `json:"instance_name" yaml:"instance_name"`
	Device              string `json:"device" yaml:"device"`
	State               string `json:"state" yaml:"state"`
	DeleteOnTermination bool   `json:"delete_on_termination" yaml:"delete_on_termination"`
}

// modificationView is the latest modification in `volume get`.
type modificationView struct {
	State              string `json:"state" yaml:"state"`
	Progress           int64  `json:"progress" yaml:"progress"`
	OriginalSize       int32  `json:"original_size" yaml:"original_size"`
	TargetSize         int32  `json:"target_size" yaml:"target_size"`
	OriginalVolumeType string `json:"original_volume_type" yaml:"original_volume_type"`
	TargetVolumeType   string `json:"target_volume_type" yaml:"target_volume_type"`
	StartTime          string `json:"start_time" yaml:"start_time"`
}

func modificationViewOf(m *ec2types.VolumeModification) *modificationView {
	if m == nil {
		return nil
	}
	mv := &modificationView{State: string(m.ModificationState), Progress: awssdk.ToInt64(m.Progress), OriginalSize: awssdk.ToInt32(m.OriginalSize),
		TargetSize: awssdk.ToInt32(m.TargetSize), OriginalVolumeType: string(m.OriginalVolumeType), TargetVolumeType: string(m.TargetVolumeType)}
	if m.StartTime != nil {
		mv.StartTime = m.StartTime.UTC().Format(time.RFC3339)
	}
	return mv
}

// volumeDetail is the output of `volume get`.
type volumeDetail struct {
	VolumeID         string            `json:"volume_id" yaml:"volume_id"`
	Name             string            `json:"name" yaml:"name"`
	Profile          string            `json:"profile" yaml:"profile"`
	Region           string            `json:"region" yaml:"region"`
	AvailabilityZone string            `json:"availability_zone" yaml:"availability_zone"`
	Size             int32             `json:"size" yaml:"size"`
	VolumeType       string            `json:"volume_type" yaml:"volume_type"`
	Iops             int32             `json:"iops" yaml:"iops"`
	Throughput       int32             `json:"throughput" yaml:"throughput"`
	State            string            `json:"state" yaml:"state"`
	Encrypted        bool              `json:"encrypted" yaml:"encrypted"`
	SnapshotID       string            `json:"snapshot_id" yaml:"snapshot_id"`
	Attachments      []attachmentView  `json:"attachments" yaml:"attachments"`
	Modification     *modificationView `json:"modification,omitempty" yaml:"modification,omitempty"`
}

func volumeDetailOf(profile string, v volumeInfo, names map[string]string, m *ec2types.VolumeModification) volumeDetail {
	d := volumeDetail{VolumeID: v.ID, Name: v.Name, Profile: profile, Region: v.Region, AvailabilityZone: v.AZ, Size: v.Size, VolumeType: v.Type,
		Iops: v.Iops, Throughput: v.Throughput, State: v.State, Encrypted: v.Encrypted, SnapshotID: v.SnapshotID, Attachments: []attachmentView{},
		Modification: modificationViewOf(m)}
	for _, a := range v.Attachments {
		d.Attachments = append(d.Attachments, attachmentView{InstanceID: a.InstanceID, InstanceName: names[a.InstanceID], Device: a.Device,
			State: a.State, DeleteOnTermination: a.DeleteOnTermination})
	}
	return d
}

func volumeDetailGrid(d volumeDetail) output.Grid {
	var atts []string
	for _, a := range d.Attachments {
		inst := a.InstanceID
		if a.InstanceName != "" {
			inst = a.InstanceName + " (" + a.InstanceID + ")"
		}
		atts = append(atts, fmt.Sprintf("%s %s %s delete_on_termination=%v", inst, a.Device, a.State, a.DeleteOnTermination))
	}
	mod := "-"
	if m := d.Modification; m != nil {
		mod = fmt.Sprintf("%s %d%% (%dGB %s -> %dGB %s, started %s)", m.State, m.Progress, m.OriginalSize, m.OriginalVolumeType, m.TargetSize, m.TargetVolumeType, m.StartTime)
	}
	return output.KV(
		"volume_id", d.VolumeID, "name", dashIfEmpty(d.Name), "profile", d.Profile, "region", d.Region, "availability_zone", d.AvailabilityZone,
		"size", fmt.Sprintf("%dGB", d.Size), "volume_type", d.VolumeType, "iops", intOrDash(d.Iops), "throughput", intOrDash(d.Throughput),
		"state", d.State, "encrypted", strconv.FormatBool(d.Encrypted), "snapshot_id", dashIfEmpty(d.SnapshotID),
		"attachments", dashIfEmpty(strings.Join(atts, "; ")), "modification", mod)
}

// attachedInstanceIDs returns the instance ids the volumes are attached to.
func attachedInstanceIDs(vols ...volumeInfo) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range vols {
		for _, a := range v.Attachments {
			if a.InstanceID != "" && !seen[a.InstanceID] {
				seen[a.InstanceID] = true
				out = append(out, a.InstanceID)
			}
		}
	}
	sort.Strings(out)
	return out
}

// instanceNamesOf reads the Name tags of the instances the volumes are
// attached to; a failure only means ids are shown.
func instanceNamesOf(ctx context.Context, rt *app.Runtime, c *client, region string, vols ...volumeInfo) map[string]string {
	names, err := c.instanceNames(ctx, region, attachedInstanceIDs(vols...))
	if err != nil {
		rt.Verbosef("instance names: %v", err)
	}
	return names
}

// ---------------------------------------------------------------- list

func volumeListCmd(rt *app.Runtime) *cobra.Command {
	var instance, state, az, name, region string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List EBS volumes",
		Long: `List the EBS volumes of the profile's region (--region another one), read
live from AWS. --instance keeps the volumes attached to that instance (its
name or id; its account and region are found like instance get finds them),
--state those in that state (available, in-use, creating, deleting, error;
available lists the volumes attached to nothing), --az those of that
availability zone, --name those whose Name tag matches the value (* and ?
are wildcards). Several filters must all match. With --offline the volumes
come from the inventory. No match is an empty list and exit code 0.`,
		Example: "  polyctl aws ec2 volume list --instance site-xz7\n  polyctl aws ec2 volume list --state available -o json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if state != "" && !slices.Contains(volumeStates, state) {
				return app.UsageErrf("--state %q: expected one of %s", state, strings.Join(volumeStates, ", "))
			}
			if name != "" {
				if _, err := path.Match(name, ""); err != nil {
					return app.UsageErrf("--name %q: malformed pattern", name)
				}
			}
			if region != "" && !validRegionName(region) {
				return app.UsageErrf("--region %q: expected a region name such as us-east-1", region)
			}
			filters := volumeFilters{State: state, AZ: az, Name: name}
			if rt.Flags.Offline {
				if instance != "" {
					return fmt.Errorf("%w: --instance needs AWS", app.ErrOffline)
				}
				return volumeListOffline(ctx, rt, region, filters)
			}
			var c *client
			var profile string
			if instance != "" {
				l, err := resolveInstance(ctx, rt, instance, region, false)
				if err != nil {
					return err
				}
				c, profile, region = l.c, l.profile, l.region
				filters.InstanceID = l.id()
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
			vols, err := c.listVolumes(ctx, region, filters)
			if err != nil {
				return err
			}
			infos := make([]volumeInfo, 0, len(vols))
			for _, v := range vols {
				storeVolume(ctx, rt, profile, region, v)
				infos = append(infos, volumeFrom(region, v))
			}
			names := instanceNamesOf(ctx, rt, c, region, infos...)
			rows := []volumeRow{}
			for _, v := range infos {
				rows = append(rows, volumeRowOf(profile, v, names))
			}
			if len(rows) == 0 {
				rt.Infof("no matching volumes in %s via aws/%s", region, profile)
			}
			return rt.Render(rows, func() output.Grid { return volumeListGrid(rows) })
		},
	}
	cmd.Flags().StringVar(&instance, "instance", "", "only the volumes attached to this instance (name or id)")
	cmd.Flags().StringVar(&state, "state", "", "only volumes in this state ("+strings.Join(volumeStates, ", ")+")")
	cmd.Flags().StringVar(&az, "az", "", "only volumes of this availability zone")
	cmd.Flags().StringVar(&name, "name", "", "only volumes whose Name tag matches this value (* and ? are wildcards)")
	cmd.Flags().StringVar(&region, "region", "", "region to list (default: the profile's region)")
	return cmd
}

// volumeListOffline lists the volumes of the inventory.
func volumeListOffline(ctx context.Context, rt *app.Runtime, region string, f volumeFilters) error {
	profile, err := rt.ProfileFor(platform.AWS)
	if err != nil {
		return err
	}
	if region == "" {
		region = profileRegion(rt, profile)
	}
	accounts := []config.AccountRef{{Profile: profile, Platform: platform.AWS}}
	hits, err := volumeInventoryHits(ctx, rt, accounts, "volumes", false, func(v volumeInfo) bool {
		if region != "" && v.Region != region || f.State != "" && v.State != f.State || f.AZ != "" && v.AZ != f.AZ {
			return false
		}
		if f.Name != "" {
			if ok, _ := path.Match(f.Name, v.Name); !ok {
				return false
			}
		}
		return true
	})
	if err != nil {
		if errors.Is(err, inventory.ErrNeverSynced) {
			return fmt.Errorf("%w: %v", app.ErrOffline, err)
		}
		return err
	}
	rows := []volumeRow{}
	for _, h := range hits {
		rows = append(rows, volumeRowOf(profile, h.v, nil))
	}
	slices.SortFunc(rows, func(a, b volumeRow) int { return strings.Compare(a.ID, b.ID) })
	where := "aws/" + profile
	if region != "" {
		where += "/" + region
	}
	rt.Infof("volumes via %s (local inventory)", where)
	if len(rows) == 0 {
		rt.Infof("no matching volumes via %s", where)
	}
	return rt.Render(rows, func() output.Grid { return volumeListGrid(rows) })
}

// ----------------------------------------------------------------- get

func volumeGetCmd(rt *app.Runtime) *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:   "get <vol-id|name>",
		Short: "Show an EBS volume and its latest modification",
		Long: `Show an EBS volume: size, type, IOPS, throughput, state, encryption, source
snapshot, attachments (with the instance names) and, when AWS still keeps
one, the latest modification (state, progress, original and target size and
type). AWS keeps only the latest modification of a volume, for a limited
time. With --offline the inventory's copy is shown, without the
modification.`,
		Example: "  polyctl aws ec2 volume get vol-0222\n  polyctl aws ec2 volume get site-xz7-data -o json",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if rt.Flags.Offline {
				accounts, err := awsAccounts(rt)
				if err != nil {
					return err
				}
				ref := strings.TrimSpace(args[0])
				hits, err := volumeInventoryHits(ctx, rt, accounts, "volume "+ref, false, volumeMatcher(ref, region))
				if err != nil {
					if errors.Is(err, inventory.ErrNeverSynced) {
						return fmt.Errorf("%w: %v", app.ErrOffline, err)
					}
					return err
				}
				h, err := pickVolumeHit(rt, ref, hits)
				if err != nil {
					return err
				}
				rt.Infof("volume %s via aws/%s/%s (local inventory)", h.v.ID, h.profile, h.v.Region)
				d := volumeDetailOf(h.profile, h.v, nil, nil)
				return rt.Render(d, func() output.Grid { return volumeDetailGrid(d) })
			}
			l, err := resolveVolume(ctx, rt, args[0], region)
			if err != nil {
				return err
			}
			l.store(ctx, rt)
			m, err := l.c.latestModification(ctx, l.region, l.id())
			if err != nil {
				return err
			}
			info := volumeFrom(l.region, l.vol)
			d := volumeDetailOf(l.profile, info, instanceNamesOf(ctx, rt, l.c, l.region, info), m)
			return rt.Render(d, func() output.Grid { return volumeDetailGrid(d) })
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region of the volume (default: an id is looked up in the inventory, a name in the profile's region)")
	return cmd
}

// --------------------------------------------------------------- create

// parseVolumeTags parses --tag key=value flags; Name may be given (it
// overrides the default Name tag).
func parseVolumeTags(args []string) (map[string]string, error) {
	out := map[string]string{}
	for _, a := range args {
		k, v, ok := strings.Cut(a, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return nil, app.UsageErrf("--tag %q: expected key=value", a)
		}
		out[k] = v
	}
	return out, nil
}

// checkPerformance validates --iops and --throughput for a volume type:
// io1 and io2 need IOPS, throughput is gp3 only, gp2, st1 and sc1 take
// neither.
func checkPerformance(cmd *cobra.Command, typ string) error {
	iops, tp := cmd.Flags().Changed("iops"), cmd.Flags().Changed("throughput")
	switch typ {
	case "gp3":
	case "io1", "io2":
		if !iops {
			return app.UsageErrf("--type %s needs --iops", typ)
		}
		if tp {
			return app.UsageErrf("--throughput applies to gp3 volumes only")
		}
	default:
		if iops || tp {
			return app.UsageErrf("--type %s takes neither --iops nor --throughput", typ)
		}
	}
	return nil
}

func volumeCreateDesc(s volumeSpec) string {
	parts := []string{fmt.Sprintf("size=%s", sizeOrSnapshot(s.Size)), "type=" + s.Type}
	if s.Iops > 0 {
		parts = append(parts, fmt.Sprintf("iops=%d", s.Iops))
	}
	if s.Throughput > 0 {
		parts = append(parts, fmt.Sprintf("throughput=%d", s.Throughput))
	}
	parts = append(parts, "az="+s.AZ)
	d := strings.Join(parts, " ")
	if s.Snapshot != "" {
		d += " from snapshot " + s.Snapshot
	}
	return d
}

func sizeOrSnapshot(n int32) string {
	if n == 0 {
		return "(snapshot)"
	}
	return strconv.Itoa(int(n))
}

func volumeCreateCmd(rt *app.Runtime) *cobra.Command {
	var snapshot, az, instance, typ, region string
	var size, iops, throughput int32
	var tagArgs []string
	var wf app.WaitFlags
	cmd := &cobra.Command{
		Use:   "create [<name>] (--from-snapshot <snap-id> | --size <GB>) [--az <az> | --instance <name|id>]",
		Short: "Create an EBS volume, empty or from a snapshot",
		Long: `Create an EBS volume, named <name> (its Name tag; without it the volume has
no Name tag). --size makes an empty volume of that size in GB; --from-snapshot
restores a snapshot, as large as the snapshot unless --size asks for more (a
smaller --size is a usage error: AWS would silently use the snapshot's size).
The availability zone is --az, or the zone of --instance (whose account and
region are found like instance get finds them); a volume attaches only to
instances of its zone. Without --instance the volume goes to the selected
profile's account, in the region of --az.

The type is gp3 by default, with 3000 IOPS and 125 MiB/s; IOPS and
throughput are sent for gp3 only, io1 and io2 need --iops, gp2, st1 and sc1
take neither. Encryption follows the snapshot or the account's EBS default.
A volume of that name that is not deleted in the region is exit code 1. The
tags of defaults.aws.tags and --tag go on the volume (--tag Name=... is the
name). --wait waits until the volume is available (5 second polls; a volume
in the error state fails).`,
		Example: "  polyctl aws ec2 volume create site-xz7-data --from-snapshot snap-0aaa --instance site-tmp --wait\n  polyctl aws ec2 volume create scratch --size 100 --az ap-east-1a --dry-run",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name := ""
			if len(args) == 1 {
				if name = strings.TrimSpace(args[0]); name == "" || len(name) > 256 {
					return app.UsageErrf("the volume name must be 1 to 256 characters")
				}
			}
			wait, timeout, err := wf.Resolve(cmd)
			if err != nil {
				return err
			}
			if snapshot == "" && size <= 0 {
				return app.UsageErrf("create needs --size <GB> for an empty volume, or --from-snapshot <snap-id>")
			}
			if cmd.Flags().Changed("size") && size <= 0 {
				return app.UsageErrf("--size must be a positive number of GB")
			}
			if snapshot != "" && !isSnapshotID(snapshot) {
				return app.UsageErrf("--from-snapshot %q: expected a snapshot id (snap-...)", snapshot)
			}
			if az != "" && instance != "" {
				return app.UsageErrf("--az and --instance are mutually exclusive: the volume goes to the zone of --instance")
			}
			if az == "" && instance == "" {
				return app.UsageErrf("create needs --az <zone>, or --instance <name|id> to use the instance's zone")
			}
			if !slices.Contains(volumeTypes, typ) {
				return app.UsageErrf("--type %q: expected one of %s", typ, strings.Join(volumeTypes, ", "))
			}
			if err := checkPerformance(cmd, typ); err != nil {
				return err
			}
			extra, err := parseVolumeTags(tagArgs)
			if err != nil {
				return err
			}
			if region != "" && !validRegionName(region) {
				return app.UsageErrf("--region %q: expected a region name such as us-east-1", region)
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			var c *client
			var profile string
			if instance != "" {
				l, err := resolveInstance(ctx, rt, instance, region, false)
				if err != nil {
					return err
				}
				c, profile, region = l.c, l.profile, l.region
				if l.inst.Placement != nil {
					az = awssdk.ToString(l.inst.Placement.AvailabilityZone)
				}
				if az == "" {
					return fmt.Errorf("instance %s has no availability zone", instanceLabel(l.inst))
				}
			} else {
				if region == "" {
					region = regionOfAZ(az)
				}
				if !validRegionName(region) || !strings.HasPrefix(az, region) {
					return app.UsageErrf("--az %q: expected an availability zone such as us-east-1a (pass --region for a zone whose region is not its name without the last letter)", az)
				}
				if profile, err = rt.ProfileFor(platform.AWS); err != nil {
					return err
				}
				if c, err = openProfile(ctx, rt, profile); err != nil {
					return err
				}
			}
			target := platform.Target{Platform: platform.AWS, Profile: profile, Region: region}
			spec := volumeSpec{AZ: az, Snapshot: snapshot, Type: typ, ClientToken: newClientToken()}
			if cmd.Flags().Changed("size") {
				spec.Size = size
			}
			switch typ {
			case "gp3":
				spec.Iops, spec.Throughput = iops, throughput
			case "io1", "io2":
				spec.Iops = iops
			}
			if snapshot != "" {
				snap, err := c.describeSnapshot(ctx, region, snapshot)
				if err != nil {
					return err
				}
				snapSize := awssdk.ToInt32(snap.VolumeSize)
				if spec.Size > 0 && spec.Size < snapSize {
					return app.UsageErrf("--size %d is smaller than snapshot %s (%dGB): a volume from it is at least %dGB", spec.Size, snapshot, snapSize, snapSize)
				}
				if spec.Size == 0 {
					spec.Size = snapSize
				}
			}
			tags, err := keyPairTags(rt, profile)
			if err != nil {
				return err
			}
			if tags == nil {
				tags = map[string]string{}
			}
			if name != "" {
				tags["Name"] = name
			}
			for k, v := range extra {
				tags[k] = v
			}
			name = tags["Name"]
			if name != "" {
				existing, err := c.findVolumes(ctx, region, name)
				if err != nil {
					return err
				}
				if len(existing) > 0 {
					return fmt.Errorf("volume %q already exists in %s (%s, %s): use `polyctl aws ec2 volume get %s`, or choose another name",
						name, region, awssdk.ToString(existing[0].VolumeId), existing[0].State, awssdk.ToString(existing[0].VolumeId))
				}
			}
			spec.Tags = tags
			resName := name
			if resName == "" {
				resName = platform.Pending
			}
			desc := volumeCreateDesc(spec)
			var plan platform.Plan
			plan.Add(platform.Step{Resource: "volume/" + resName, Action: platform.Created, Desc: desc, Apply: func(ctx context.Context) (platform.Change, error) {
				v, err := c.createVolume(ctx, region, spec)
				if err != nil {
					return platform.Change{}, err
				}
				id := awssdk.ToString(v.VolumeId)
				storeVolume(ctx, rt, profile, region, v)
				ch := platform.Change{ID: id, Detail: desc}
				if !wait {
					rt.Infof("volume %s is being created in %s", id, az)
					return ch, nil
				}
				got, err := c.waitVolume(ctx, region, id, volAvailable, timeout, false, volumeIn(volAvailable))
				if awssdk.ToString(got.VolumeId) != "" {
					storeVolume(ctx, rt, profile, region, got)
				}
				if err != nil {
					return platform.Change{ID: id}, fmt.Errorf("volume %s was created but did not become available: %w", id, err)
				}
				ch.Detail = desc + "; available"
				rt.Infof("volume %s is available in %s", id, az)
				return ch, nil
			}})
			return rt.Ensure(ctx, "aws.ec2.volume.create", target, &plan)
		},
	}
	cmd.Flags().StringVar(&snapshot, "from-snapshot", "", "restore this snapshot (snap-...)")
	cmd.Flags().Int32Var(&size, "size", 0, "size in GB (required for an empty volume; from a snapshot at least the snapshot's size)")
	cmd.Flags().StringVar(&az, "az", "", "availability zone of the volume")
	cmd.Flags().StringVar(&instance, "instance", "", "put the volume in the availability zone of this instance (name or id)")
	cmd.Flags().StringVar(&typ, "type", volumeDefaultType, "volume type ("+strings.Join(volumeTypes, ", ")+")")
	cmd.Flags().Int32Var(&iops, "iops", volumeDefaultIops, "IOPS (gp3, io1, io2; required for io1 and io2)")
	cmd.Flags().Int32Var(&throughput, "throughput", volumeDefaultThroughput, "throughput in MiB/s (gp3 only)")
	cmd.Flags().StringArrayVar(&tagArgs, "tag", nil, "extra tag key=value (repeatable)")
	cmd.Flags().StringVar(&region, "region", "", "region (default: the region of --az, or of --instance)")
	app.AddWaitFlags(cmd, &wf, false, volumeWaitTimeout)
	return cmd
}
