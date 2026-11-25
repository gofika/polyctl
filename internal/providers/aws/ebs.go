package aws

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/gofika/polyctl/internal/platform"
)

// EBS volume states.
const (
	volCreating  = string(ec2types.VolumeStateCreating)
	volAvailable = string(ec2types.VolumeStateAvailable)
	volInUse     = string(ec2types.VolumeStateInUse)
	volDeleting  = string(ec2types.VolumeStateDeleting)
	volDeleted   = string(ec2types.VolumeStateDeleted)
	volError     = string(ec2types.VolumeStateError)
)

// volumeStates are the values `volume list --state` accepts.
var volumeStates = []string{volAvailable, volInUse, volCreating, volDeleting, volError}

// volumeTypes are the EBS volume types create and resize accept.
var volumeTypes = []string{"gp3", "gp2", "io1", "io2", "st1", "sc1"}

// Volume modification states.
const (
	modModifying  = string(ec2types.VolumeModificationStateModifying)
	modOptimizing = string(ec2types.VolumeModificationStateOptimizing)
	modCompleted  = string(ec2types.VolumeModificationStateCompleted)
	modFailed     = string(ec2types.VolumeModificationStateFailed)
)

// Snapshot states.
const (
	snapPending   = string(ec2types.SnapshotStatePending)
	snapCompleted = string(ec2types.SnapshotStateCompleted)
	snapError     = string(ec2types.SnapshotStateError)
)

// snapshotStates are the values `snapshot list --state` accepts.
var snapshotStates = []string{snapCompleted, snapPending, snapError}

// Poll intervals of the EBS waits: volumes change within seconds (create
// about 3, detach about 6, a small resize about 5), snapshots take minutes.
// The waits use instanceClock, which tests replace.
var (
	volumePollInterval   = 5 * time.Second
	snapshotPollInterval = 15 * time.Second
)

// waitErrorBudget is how many polls in a row may fail before a wait gives
// up: a single transient failure is retried.
const waitErrorBudget = 3

// isVolumeID reports whether ref names a volume by id.
func isVolumeID(ref string) bool { return strings.HasPrefix(ref, "vol-") && len(ref) > 4 }

// isSnapshotID reports whether ref names a snapshot by id.
func isSnapshotID(ref string) bool { return strings.HasPrefix(ref, "snap-") && len(ref) > 5 }

// ---------------------------------------------------------- conversion

// volumeAttachment is one attachment of a volume.
type volumeAttachment struct {
	InstanceID          string `json:"instance_id" yaml:"instance_id"`
	Device              string `json:"device" yaml:"device"`
	State               string `json:"state" yaml:"state"`
	DeleteOnTermination bool   `json:"delete_on_termination" yaml:"delete_on_termination"`
}

// volumeInfo is the inventory form of an EBS volume.
type volumeInfo struct {
	ID          string             `json:"id" yaml:"id"`
	Name        string             `json:"name,omitempty" yaml:"name,omitempty"`
	Region      string             `json:"region" yaml:"region"`
	AZ          string             `json:"az,omitempty" yaml:"az,omitempty"`
	Size        int32              `json:"size" yaml:"size"`
	Type        string             `json:"type,omitempty" yaml:"type,omitempty"`
	Iops        int32              `json:"iops,omitempty" yaml:"iops,omitempty"`
	Throughput  int32              `json:"throughput,omitempty" yaml:"throughput,omitempty"`
	State       string             `json:"state,omitempty" yaml:"state,omitempty"`
	Encrypted   bool               `json:"encrypted,omitempty" yaml:"encrypted,omitempty"`
	SnapshotID  string             `json:"snapshot_id,omitempty" yaml:"snapshot_id,omitempty"`
	CreateTime  string             `json:"create_time,omitempty" yaml:"create_time,omitempty"`
	Attachments []volumeAttachment `json:"attachments,omitempty" yaml:"attachments,omitempty"`
	Tags        map[string]string  `json:"tags,omitempty" yaml:"tags,omitempty"`
}

// volumeFrom converts a volume of the API.
func volumeFrom(region string, v ec2types.Volume) volumeInfo {
	info := volumeInfo{
		ID: awssdk.ToString(v.VolumeId), Region: region, AZ: awssdk.ToString(v.AvailabilityZone), Size: awssdk.ToInt32(v.Size),
		Type: string(v.VolumeType), Iops: awssdk.ToInt32(v.Iops), Throughput: awssdk.ToInt32(v.Throughput), State: string(v.State),
		Encrypted: awssdk.ToBool(v.Encrypted), SnapshotID: awssdk.ToString(v.SnapshotId),
	}
	if v.CreateTime != nil {
		info.CreateTime = v.CreateTime.UTC().Format(time.RFC3339)
	}
	for _, a := range v.Attachments {
		info.Attachments = append(info.Attachments, volumeAttachment{InstanceID: awssdk.ToString(a.InstanceId), Device: awssdk.ToString(a.Device),
			State: string(a.State), DeleteOnTermination: awssdk.ToBool(a.DeleteOnTermination)})
	}
	for _, t := range v.Tags {
		if info.Tags == nil {
			info.Tags = map[string]string{}
		}
		k := awssdk.ToString(t.Key)
		info.Tags[k] = awssdk.ToString(t.Value)
		if k == "Name" {
			info.Name = awssdk.ToString(t.Value)
		}
	}
	return info
}

func (v volumeInfo) resource() platform.Resource {
	return platform.Resource{Type: platform.ResVolume, ID: v.ID, Name: v.Name, ParentID: v.Region, Data: v}
}

// volumeName returns the Name tag of a volume.
func volumeName(v ec2types.Volume) string {
	for _, t := range v.Tags {
		if awssdk.ToString(t.Key) == "Name" {
			return awssdk.ToString(t.Value)
		}
	}
	return ""
}

// volumeLabel names a volume in messages: "id (name)", or the id.
func volumeLabel(v ec2types.Volume) string {
	id := awssdk.ToString(v.VolumeId)
	if n := volumeName(v); n != "" {
		return id + " (" + n + ")"
	}
	return id
}

// volumeAttached returns the attachment of a volume (EBS Multi-Attach
// aside a volume has at most one), or nil.
func volumeAttached(v ec2types.Volume) *ec2types.VolumeAttachment {
	for i := range v.Attachments {
		if s := v.Attachments[i].State; s != ec2types.VolumeAttachmentStateDetached {
			return &v.Attachments[i]
		}
	}
	return nil
}

// snapshotInfo is a row of `snapshot list`.
type snapshotInfo struct {
	ID          string `json:"id" yaml:"id"`
	VolumeID    string `json:"volume_id" yaml:"volume_id"`
	Size        int32  `json:"size" yaml:"size"`
	State       string `json:"state" yaml:"state"`
	Progress    string `json:"progress" yaml:"progress"`
	StartTime   string `json:"start_time" yaml:"start_time"`
	Description string `json:"description" yaml:"description"`
	Name        string `json:"name" yaml:"name"`
	Encrypted   bool   `json:"encrypted" yaml:"encrypted"`
	Profile     string `json:"profile" yaml:"profile"`
	Region      string `json:"region" yaml:"region"`
}

func snapshotFrom(region string, s ec2types.Snapshot) snapshotInfo {
	info := snapshotInfo{ID: awssdk.ToString(s.SnapshotId), VolumeID: awssdk.ToString(s.VolumeId), Size: awssdk.ToInt32(s.VolumeSize),
		State: string(s.State), Progress: awssdk.ToString(s.Progress), Description: awssdk.ToString(s.Description),
		Encrypted: awssdk.ToBool(s.Encrypted), Region: region}
	if s.StartTime != nil {
		info.StartTime = s.StartTime.UTC().Format(time.RFC3339)
	}
	for _, t := range s.Tags {
		if awssdk.ToString(t.Key) == "Name" {
			info.Name = awssdk.ToString(t.Value)
		}
	}
	return info
}

// ---------------------------------------------------------------- reads

// describeVolumesWith runs a paginated DescribeVolumes; errors are raw.
func (c *client) describeVolumesWith(ctx context.Context, region string, in *ec2.DescribeVolumesInput) ([]ec2types.Volume, error) {
	region = c.regionOr(region)
	var out []ec2types.Volume
	pg := ec2.NewDescribeVolumesPaginator(c.ec2For(region), in)
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Volumes...)
	}
	return out, nil
}

// describeVolume reads one volume by id; a missing one is ErrNotFound.
func (c *client) describeVolume(ctx context.Context, region, id string) (ec2types.Volume, error) {
	region = c.regionOr(region)
	out, err := c.describeVolumesWith(ctx, region, &ec2.DescribeVolumesInput{VolumeIds: []string{id}})
	if err != nil {
		if platform.HasErrorCode(err, "InvalidVolume.NotFound", "InvalidVolume.Malformed") {
			return ec2types.Volume{}, fmt.Errorf("%w: volume %s in %s", platform.ErrNotFound, id, region)
		}
		return ec2types.Volume{}, ec2Err("DescribeVolumes", region, err)
	}
	for _, v := range out {
		if awssdk.ToString(v.VolumeId) == id {
			return v, nil
		}
	}
	return ec2types.Volume{}, fmt.Errorf("%w: volume %s in %s", platform.ErrNotFound, id, region)
}

// findVolumes returns the volumes of region whose Name tag is name exactly.
func (c *client) findVolumes(ctx context.Context, region, name string) ([]ec2types.Volume, error) {
	region = c.regionOr(region)
	all, err := c.describeVolumesWith(ctx, region, &ec2.DescribeVolumesInput{
		Filters: []ec2types.Filter{{Name: awssdk.String("tag:Name"), Values: []string{name}}},
	})
	if err != nil {
		return nil, ec2Err("DescribeVolumes", region, err)
	}
	var out []ec2types.Volume
	for _, v := range all {
		if volumeName(v) == name && string(v.State) != volDeleted {
			out = append(out, v)
		}
	}
	return out, nil
}

// volumeFilters are the server-side filters of `volume list`.
type volumeFilters struct {
	InstanceID, Device, State, AZ, Name string
}

func (f volumeFilters) ec2() []ec2types.Filter {
	var out []ec2types.Filter
	add := func(name, value string) {
		if value != "" {
			out = append(out, ec2types.Filter{Name: awssdk.String(name), Values: []string{value}})
		}
	}
	add("attachment.instance-id", f.InstanceID)
	add("attachment.device", f.Device)
	add("status", f.State)
	add("availability-zone", f.AZ)
	add("tag:Name", f.Name)
	return out
}

// listVolumes lists the volumes of a region that match f, by id.
func (c *client) listVolumes(ctx context.Context, region string, f volumeFilters) ([]ec2types.Volume, error) {
	region = c.regionOr(region)
	out, err := c.describeVolumesWith(ctx, region, &ec2.DescribeVolumesInput{Filters: f.ec2()})
	if err != nil {
		return nil, ec2Err("DescribeVolumes", region, err)
	}
	sort.Slice(out, func(i, j int) bool { return awssdk.ToString(out[i].VolumeId) < awssdk.ToString(out[j].VolumeId) })
	return out, nil
}

// volumeResources lists the volumes of a region as inventory resources.
func (c *client) volumeResources(ctx context.Context, region string) ([]platform.Resource, error) {
	vols, err := c.listVolumes(ctx, region, volumeFilters{})
	if err != nil {
		return nil, err
	}
	out := make([]platform.Resource, 0, len(vols))
	for _, v := range vols {
		out = append(out, volumeFrom(region, v).resource())
	}
	return out, nil
}

// instanceNames returns the Name tag (or "") of each instance id, read in
// one batch. The instance-id filter never fails on an id that is gone; a
// failed read is returned with what is known.
func (c *client) instanceNames(ctx context.Context, region string, ids []string) (map[string]string, error) {
	out := map[string]string{}
	if len(ids) == 0 {
		return out, nil
	}
	all, err := c.describeInstancesWith(ctx, region, &ec2.DescribeInstancesInput{
		Filters: []ec2types.Filter{{Name: awssdk.String("instance-id"), Values: ids}},
	})
	if err != nil {
		return out, ec2Err("DescribeInstances", c.regionOr(region), err)
	}
	for _, in := range all {
		out[awssdk.ToString(in.InstanceId)] = instanceName(in)
	}
	return out, nil
}

// latestModification returns the most recent modification of a volume, or
// nil when AWS keeps none: DescribeVolumesModifications answers a volume
// that was never modified with InvalidVolumeModification.NotFound, not
// with an empty list.
func (c *client) latestModification(ctx context.Context, region, id string) (*ec2types.VolumeModification, error) {
	region = c.regionOr(region)
	pg := ec2.NewDescribeVolumesModificationsPaginator(c.ec2For(region), &ec2.DescribeVolumesModificationsInput{VolumeIds: []string{id}})
	var latest *ec2types.VolumeModification
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			if platform.HasErrorCode(err, "InvalidVolumeModification.NotFound") {
				return nil, nil
			}
			return nil, ec2Err("DescribeVolumesModifications", region, err)
		}
		for i := range page.VolumesModifications {
			m := page.VolumesModifications[i]
			if awssdk.ToString(m.VolumeId) != "" && awssdk.ToString(m.VolumeId) != id {
				continue
			}
			if latest == nil || awssdk.ToTime(m.StartTime).After(awssdk.ToTime(latest.StartTime)) {
				latest = &m
			}
		}
	}
	return latest, nil
}

// describeSnapshot reads one snapshot by id; a missing one is ErrNotFound.
func (c *client) describeSnapshot(ctx context.Context, region, id string) (ec2types.Snapshot, error) {
	region = c.regionOr(region)
	out, err := c.ec2For(region).DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{SnapshotIds: []string{id}})
	if err != nil {
		if platform.HasErrorCode(err, "InvalidSnapshot.NotFound", "InvalidSnapshot.Malformed", "InvalidSnapshotID.Malformed") {
			return ec2types.Snapshot{}, fmt.Errorf("%w: snapshot %s in %s", platform.ErrNotFound, id, region)
		}
		return ec2types.Snapshot{}, ec2Err("DescribeSnapshots", region, err)
	}
	for _, s := range out.Snapshots {
		if awssdk.ToString(s.SnapshotId) == id {
			return s, nil
		}
	}
	return ec2types.Snapshot{}, fmt.Errorf("%w: snapshot %s in %s", platform.ErrNotFound, id, region)
}

// snapshotFilters are the server-side filters of `snapshot list`.
type snapshotFilters struct {
	VolumeID, State, Name string
}

// listSnapshots lists the account's own snapshots of a region that match
// f, newest first. OwnerIds self keeps the public snapshots out.
func (c *client) listSnapshots(ctx context.Context, region string, f snapshotFilters) ([]ec2types.Snapshot, error) {
	region = c.regionOr(region)
	in := &ec2.DescribeSnapshotsInput{OwnerIds: []string{"self"}, MaxResults: awssdk.Int32(1000)}
	add := func(name, value string) {
		if value != "" {
			in.Filters = append(in.Filters, ec2types.Filter{Name: awssdk.String(name), Values: []string{value}})
		}
	}
	add("volume-id", f.VolumeID)
	add("status", f.State)
	add("tag:Name", f.Name)
	var out []ec2types.Snapshot
	pg := ec2.NewDescribeSnapshotsPaginator(c.ec2For(region), in)
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, ec2Err("DescribeSnapshots", region, err)
		}
		out = append(out, page.Snapshots...)
	}
	sortSnapshots(out)
	return out, nil
}

// sortSnapshots orders snapshots newest first (by start time, then id).
func sortSnapshots(out []ec2types.Snapshot) {
	sort.SliceStable(out, func(i, j int) bool {
		ti, tj := awssdk.ToTime(out[i].StartTime), awssdk.ToTime(out[j].StartTime)
		if !ti.Equal(tj) {
			return ti.After(tj)
		}
		return awssdk.ToString(out[i].SnapshotId) > awssdk.ToString(out[j].SnapshotId)
	})
}

// latestCompleted returns the newest completed snapshot of a list sorted
// newest first, or nil.
func latestCompleted(snaps []ec2types.Snapshot) *ec2types.Snapshot {
	for i := range snaps {
		if string(snaps[i].State) == snapCompleted {
			return &snaps[i]
		}
	}
	return nil
}

// --------------------------------------------------------------- writes

// volumeSpec is what `volume create` asks for.
type volumeSpec struct {
	AZ, Snapshot, Type string
	Size               int32 // 0: the snapshot's size
	Iops, Throughput   int32 // 0: not sent
	Tags               map[string]string
	ClientToken        string
}

// createInput builds the CreateVolume request: IOPS and throughput only
// when set (the command sets them for gp3, and IOPS for io1 and io2), and
// Encrypted never (the snapshot or the account's default decides).
func (s volumeSpec) createInput() *ec2.CreateVolumeInput {
	in := &ec2.CreateVolumeInput{AvailabilityZone: awssdk.String(s.AZ), VolumeType: ec2types.VolumeType(s.Type)}
	if s.Snapshot != "" {
		in.SnapshotId = awssdk.String(s.Snapshot)
	}
	if s.Size > 0 {
		in.Size = awssdk.Int32(s.Size)
	}
	if s.Iops > 0 {
		in.Iops = awssdk.Int32(s.Iops)
	}
	if s.Throughput > 0 {
		in.Throughput = awssdk.Int32(s.Throughput)
	}
	if s.ClientToken != "" {
		in.ClientToken = awssdk.String(s.ClientToken)
	}
	if len(s.Tags) > 0 {
		in.TagSpecifications = []ec2types.TagSpecification{{ResourceType: ec2types.ResourceTypeVolume, Tags: sortedTags(s.Tags)}}
	}
	return in
}

// createVolume creates a volume and returns it as the API answered
// (state creating).
func (c *client) createVolume(ctx context.Context, region string, s volumeSpec) (ec2types.Volume, error) {
	region = c.regionOr(region)
	out, err := c.ec2For(region).CreateVolume(ctx, s.createInput())
	if err != nil {
		if platform.HasErrorCode(err, "VolumeLimitExceeded") {
			return ec2types.Volume{}, fmt.Errorf("the account's EBS volume quota is exhausted in %s; request a quota increase or delete unused volumes: %w", region, ec2Err("CreateVolume", region, err))
		}
		return ec2types.Volume{}, ec2Err("CreateVolume", region, err)
	}
	return ec2types.Volume{VolumeId: out.VolumeId, AvailabilityZone: out.AvailabilityZone, Size: out.Size, VolumeType: out.VolumeType,
		Iops: out.Iops, Throughput: out.Throughput, State: out.State, Encrypted: out.Encrypted, SnapshotId: out.SnapshotId,
		CreateTime: out.CreateTime, Tags: out.Tags}, nil
}

// volumeChange is what `volume resize` asks for: nil is "not given", so
// that a given 0 is never dropped.
type volumeChange struct {
	Size, Iops, Throughput *int32
	Type                   string
}

func (m volumeChange) empty() bool {
	return m.Size == nil && m.Iops == nil && m.Throughput == nil && m.Type == ""
}

// rateLimitPattern finds the time AWS names in VolumeModificationRateExceeded:
// "... Wait until 2026-01-02T03:04:05.000Z before you can issue ...".
var rateLimitPattern = regexp.MustCompile(`(?i)wait until\s+(\S+)`)

// rateLimitUntil returns the earliest time of the next modification named
// in the message of VolumeModificationRateExceeded.
func rateLimitUntil(msg string) (time.Time, bool) {
	m := rateLimitPattern.FindStringSubmatch(msg)
	if m == nil {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimRight(m[1], ".,;"))
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// apiMessage returns the message of an API error, or the error text.
func apiMessage(err error) string {
	var ae apiError
	if errors.As(err, &ae) {
		return ae.ErrorMessage()
	}
	return err.Error()
}

// modifyVolume sends ModifyVolume with the fields given. The failures that
// say when or how to retry are explained.
func (c *client) modifyVolume(ctx context.Context, region, id string, m volumeChange) (*ec2types.VolumeModification, error) {
	region = c.regionOr(region)
	in := &ec2.ModifyVolumeInput{VolumeId: awssdk.String(id), Size: m.Size, Iops: m.Iops, Throughput: m.Throughput}
	if m.Type != "" {
		in.VolumeType = ec2types.VolumeType(m.Type)
	}
	out, err := c.ec2For(region).ModifyVolume(ctx, in)
	if err != nil {
		return nil, modifyErr(id, region, err)
	}
	return out.VolumeModification, nil
}

// modifyErr explains the ModifyVolume failures.
func modifyErr(id, region string, err error) error {
	wrapped := ec2Err("ModifyVolume", region, err)
	switch platform.ErrorCode(err) {
	case "VolumeModificationRateExceeded":
		if t, ok := rateLimitUntil(apiMessage(err)); ok {
			return fmt.Errorf("volume %s has reached the EBS modification rate limit: AWS accepts the next modification after %s: %w", id, t.Format(time.RFC3339), wrapped)
		}
		return fmt.Errorf("volume %s has reached the EBS modification rate limit (AWS names no time; see the message): %w", id, wrapped)
	case "IncorrectModificationState":
		return fmt.Errorf("volume %s is being modified: wait until its modification is completed, then retry: %w", id, wrapped)
	case "UnsupportedOperation":
		return fmt.Errorf("volume %s cannot be modified while attached to this instance type: stop the instance first (polyctl does not stop it): %w", id, wrapped)
	}
	return wrapped
}

// attachVolume attaches a volume to an instance as device.
func (c *client) attachVolume(ctx context.Context, region, volID, instanceID, device string) error {
	region = c.regionOr(region)
	_, err := c.ec2For(region).AttachVolume(ctx, &ec2.AttachVolumeInput{VolumeId: awssdk.String(volID), InstanceId: awssdk.String(instanceID), Device: awssdk.String(device)})
	if err != nil {
		switch platform.ErrorCode(err) {
		case "InvalidVolume.ZoneMismatch":
			return fmt.Errorf("volume %s and instance %s are in different availability zones: %w", volID, instanceID, ec2Err("AttachVolume", region, err))
		case "VolumeInUse":
			return fmt.Errorf("volume %s is attached already; detach it first: %w", volID, ec2Err("AttachVolume", region, err))
		}
		return ec2Err("AttachVolume", region, err)
	}
	return nil
}

// detachVolume detaches a volume (forcibly with force).
func (c *client) detachVolume(ctx context.Context, region, volID string, force bool) error {
	region = c.regionOr(region)
	in := &ec2.DetachVolumeInput{VolumeId: awssdk.String(volID)}
	if force {
		in.Force = awssdk.Bool(true)
	}
	if _, err := c.ec2For(region).DetachVolume(ctx, in); err != nil {
		if platform.HasErrorCode(err, "VolumeInUse") {
			return fmt.Errorf("volume %s is still in use inside the instance: unmount it there first, or retry with --force --yes (may lose data): %w", volID, ec2Err("DetachVolume", region, err))
		}
		return ec2Err("DetachVolume", region, err)
	}
	return nil
}

// deleteVolume deletes a volume. A volume that is gone already is
// reported as gone (true), not as an error.
func (c *client) deleteVolume(ctx context.Context, region, volID string) (bool, error) {
	region = c.regionOr(region)
	if _, err := c.ec2For(region).DeleteVolume(ctx, &ec2.DeleteVolumeInput{VolumeId: awssdk.String(volID)}); err != nil {
		switch platform.ErrorCode(err) {
		case "InvalidVolume.NotFound":
			return true, nil
		case "VolumeInUse":
			return false, fmt.Errorf("volume %s is attached to an instance: detach it first (`polyctl aws ec2 volume detach %s`; after an instance termination wait until the instance is terminated): %w", volID, volID, ec2Err("DeleteVolume", region, err))
		}
		return false, ec2Err("DeleteVolume", region, err)
	}
	return false, nil
}

// createSnapshot snapshots a volume.
func (c *client) createSnapshot(ctx context.Context, region, volID, description string, tags map[string]string) (ec2types.Snapshot, error) {
	region = c.regionOr(region)
	in := &ec2.CreateSnapshotInput{VolumeId: awssdk.String(volID)}
	if description != "" {
		in.Description = awssdk.String(description)
	}
	if len(tags) > 0 {
		in.TagSpecifications = []ec2types.TagSpecification{{ResourceType: ec2types.ResourceTypeSnapshot, Tags: sortedTags(tags)}}
	}
	out, err := c.ec2For(region).CreateSnapshot(ctx, in, ec2NoUnsafeRetry)
	if err != nil {
		if platform.HasErrorCode(err, "SnapshotCreationPerVolumeRateExceeded") {
			return ec2types.Snapshot{}, fmt.Errorf("volume %s has a snapshot in progress already: wait until it is completed, then retry: %w", volID, ec2Err("CreateSnapshot", region, err))
		}
		if platform.OutcomeUnknown(err) && ctx.Err() == nil {
			return ec2types.Snapshot{}, fmt.Errorf("the snapshot of volume %s may have been created in %s: list the snapshots of the volume before creating another: %w", volID, region, ec2Err("CreateSnapshot", region, err))
		}
		return ec2types.Snapshot{}, ec2Err("CreateSnapshot", region, err)
	}
	return ec2types.Snapshot{SnapshotId: out.SnapshotId, VolumeId: out.VolumeId, VolumeSize: out.VolumeSize, State: out.State,
		Progress: out.Progress, StartTime: out.StartTime, Description: out.Description, Encrypted: out.Encrypted, Tags: out.Tags}, nil
}

// ---------------------------------------------------------------- waits

// tolerant counts failed polls: an error is retried until waitErrorBudget
// polls in a row failed. Credential errors and missing resources are
// never retried.
type tolerant struct{ failures int }

func (t *tolerant) check(err error) error {
	if err == nil {
		t.failures = 0
		return nil
	}
	if errors.Is(err, platform.ErrUnauthorized) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	t.failures++
	if t.failures >= waitErrorBudget {
		return err
	}
	return nil
}

// waitVolume polls a volume every volumePollInterval until done says so,
// and returns it as last read. A volume in the error state, or one that
// disappears after it was seen, fails the wait (unless goneIsDone); one not
// seen yet (EC2 is eventually consistent right after CreateVolume) is
// waited for.
func (c *client) waitVolume(ctx context.Context, region, id, want string, timeout time.Duration, goneIsDone bool, done func(ec2types.Volume) bool) (ec2types.Volume, error) {
	region = c.regionOr(region)
	var last ec2types.Volume
	var tol tolerant
	err := platform.WaitUntil(ctx, platform.WaitOptions{
		Resource: "volume/" + id, Want: want, Timeout: timeout, Interval: volumePollInterval, Clock: instanceClock,
	}, func(ctx context.Context) (platform.WaitState, string, error) {
		v, err := c.describeVolume(ctx, region, id)
		if err != nil {
			if errors.Is(err, platform.ErrNotFound) {
				if goneIsDone {
					return platform.WaitDone, "deleted", nil
				}
				if last.VolumeId == nil {
					return platform.KeepWaiting, "not visible yet", tol.check(nil)
				}
				return platform.WaitFailed, "gone", nil
			}
			return platform.KeepWaiting, "", tol.check(err)
		}
		tol.check(nil)
		last = v
		st := string(v.State)
		if done(v) {
			return platform.WaitDone, st, nil
		}
		if st == volError {
			return platform.WaitFailed, st, nil
		}
		if a := volumeAttached(v); a != nil && st == volInUse {
			st += ", attachment " + string(a.State)
		}
		return platform.KeepWaiting, st, nil
	})
	return last, err
}

// volumeIn returns a wait condition: the volume is in state.
func volumeIn(state string) func(ec2types.Volume) bool {
	return func(v ec2types.Volume) bool { return string(v.State) == state }
}

// volumeAttachedTo returns a wait condition: the volume is in use and its
// attachment to the instance is attached (the volume reads in-use while
// the attachment is still attaching).
func volumeAttachedTo(instanceID string) func(ec2types.Volume) bool {
	return func(v ec2types.Volume) bool {
		if string(v.State) != volInUse {
			return false
		}
		for _, a := range v.Attachments {
			if awssdk.ToString(a.InstanceId) == instanceID && a.State == ec2types.VolumeAttachmentStateAttached {
				return true
			}
		}
		return false
	}
}

// modProgress formats the state of a modification: "optimizing 40%".
func modProgress(m *ec2types.VolumeModification) string {
	if m == nil {
		return "no modification"
	}
	s := string(m.ModificationState)
	if m.Progress != nil {
		s += fmt.Sprintf(" %d%%", *m.Progress)
	}
	return s
}

// waitModification polls the latest modification of a volume until it is
// optimizing or completed (completed only with complete). A modification
// that is not visible yet right after ModifyVolume is waited for; failed
// fails the wait.
func (c *client) waitModification(ctx context.Context, region, id string, complete bool, timeout time.Duration) (*ec2types.VolumeModification, error) {
	region = c.regionOr(region)
	want := "optimizing or completed"
	if complete {
		want = modCompleted
	}
	var last *ec2types.VolumeModification
	var tol tolerant
	err := platform.WaitUntil(ctx, platform.WaitOptions{
		Resource: "volume/" + id + " modification", Want: want, Timeout: timeout, Interval: volumePollInterval, Clock: instanceClock,
	}, func(ctx context.Context) (platform.WaitState, string, error) {
		m, err := c.latestModification(ctx, region, id)
		if err != nil {
			return platform.KeepWaiting, modProgress(last), tol.check(err)
		}
		tol.check(nil)
		if m == nil {
			return platform.KeepWaiting, "not visible yet", nil
		}
		last = m
		switch string(m.ModificationState) {
		case modCompleted:
			return platform.WaitDone, modProgress(m), nil
		case modOptimizing:
			if !complete {
				return platform.WaitDone, modProgress(m), nil
			}
		case modFailed:
			msg := modProgress(m)
			if r := awssdk.ToString(m.StatusMessage); r != "" {
				msg += ": " + r
			}
			return platform.WaitFailed, msg, nil
		}
		return platform.KeepWaiting, modProgress(m), nil
	})
	return last, err
}

// waitSnapshot polls a snapshot every snapshotPollInterval until it is
// completed; error fails the wait.
func (c *client) waitSnapshot(ctx context.Context, region, id string, timeout time.Duration) (ec2types.Snapshot, error) {
	region = c.regionOr(region)
	var last ec2types.Snapshot
	var tol tolerant
	err := platform.WaitUntil(ctx, platform.WaitOptions{
		Resource: "snapshot/" + id, Want: snapCompleted, Timeout: timeout, Interval: snapshotPollInterval, Clock: instanceClock,
	}, func(ctx context.Context) (platform.WaitState, string, error) {
		s, err := c.describeSnapshot(ctx, region, id)
		if err != nil {
			if errors.Is(err, platform.ErrNotFound) {
				// Not visible yet right after CreateSnapshot.
				return platform.KeepWaiting, "not visible yet", tol.check(nil)
			}
			return platform.KeepWaiting, "", tol.check(err)
		}
		tol.check(nil)
		last = s
		st := string(s.State)
		status := st
		if p := awssdk.ToString(s.Progress); p != "" {
			status += " " + p
		}
		switch st {
		case snapCompleted:
			return platform.WaitDone, status, nil
		case snapError:
			if m := awssdk.ToString(s.StateMessage); m != "" {
				status += ": " + m
			}
			return platform.WaitFailed, status, nil
		}
		return platform.KeepWaiting, status, nil
	})
	return last, err
}
