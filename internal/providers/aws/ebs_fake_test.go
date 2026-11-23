package aws

import (
	"context"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// fakeVol is an EBS volume of the fake EC2 API. Every DescribeVolumes that
// returns it moves its state one step along next, and its attachment one
// step along attachNext: that is how a poll sees creating become
// available. The state "gone" removes the volume.
type fakeVol struct {
	id, name, az, typ, state string
	size, iops, throughput   int32
	snapshot                 string
	instance, device         string // the attachment, "" when detached
	attachState              string
	dot                      bool
	next, attachNext         []string
	tags                     []ec2types.Tag
	hidden                   int // reads that do not see it yet
}

// fakeMod is the latest modification of a volume.
type fakeMod struct {
	state                string
	progress             int64
	origSize, targetSize int32
	origType, targetType string
	start                time.Time
	next                 []string
	hidden               int // polls that do not see it yet
}

// fakeSnap is a snapshot of the fake EC2 API.
type fakeSnap struct {
	id, volID, state, progress, desc string
	size                             int32
	start                            time.Time
	tags                             []ec2types.Tag
	next                             []string
}

// fakeEBS is the volume and snapshot part of the shared fake state.
type fakeEBS struct {
	vols         map[string][]*fakeVol // region -> volumes
	mods         map[string]*fakeMod   // volume id -> latest modification
	snaps        map[string][]*fakeSnap
	errs         map[string]error // call -> error of that call
	createNext   []string         // states of a new volume after creating
	modNext      []string         // states of a new modification after modifying
	modHidden    int              // polls that do not see a new modification
	createHidden int              // reads that do not see a new volume
	snapNext     []string         // states of a new snapshot after pending
	creates      []*ec2.CreateVolumeInput
	modifies     []*ec2.ModifyVolumeInput
	attaches     []*ec2.AttachVolumeInput
	detaches     []*ec2.DetachVolumeInput
	snapCreates  []*ec2.CreateSnapshotInput
	snapOwners   [][]string
	snapPage     int
	nextID       int
}

func (e *fakeEBS) init() {
	if e.vols == nil {
		e.vols, e.mods, e.snaps, e.errs = map[string][]*fakeVol{}, map[string]*fakeMod{}, map[string][]*fakeSnap{}, map[string]error{}
	}
}

func (e *fakeEBS) find(region, id string) *fakeVol {
	for _, v := range e.vols[region] {
		if v.id == id {
			return v
		}
	}
	return nil
}

func (e *fakeEBS) advance(region string, v *fakeVol) {
	if len(v.attachNext) > 0 {
		v.attachState, v.attachNext = v.attachNext[0], v.attachNext[1:]
	}
	if len(v.next) == 0 {
		return
	}
	v.state, v.next = v.next[0], v.next[1:]
	switch v.state {
	case volAvailable:
		v.instance, v.device, v.attachState = "", "", ""
	case "gone":
		list := e.vols[region]
		for i, x := range list {
			if x == v {
				e.vols[region] = append(list[:i], list[i+1:]...)
				break
			}
		}
	}
}

func (v *fakeVol) ec2() ec2types.Volume {
	out := ec2types.Volume{VolumeId: awssdk.String(v.id), AvailabilityZone: awssdk.String(v.az), Size: awssdk.Int32(v.size),
		VolumeType: ec2types.VolumeType(v.typ), State: ec2types.VolumeState(v.state), Encrypted: awssdk.Bool(false),
		CreateTime: awssdk.Time(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))}
	if v.iops > 0 {
		out.Iops = awssdk.Int32(v.iops)
	}
	if v.throughput > 0 {
		out.Throughput = awssdk.Int32(v.throughput)
	}
	if v.snapshot != "" {
		out.SnapshotId = awssdk.String(v.snapshot)
	}
	if v.instance != "" {
		out.Attachments = []ec2types.VolumeAttachment{{InstanceId: awssdk.String(v.instance), Device: awssdk.String(v.device),
			State: ec2types.VolumeAttachmentState(v.attachState), DeleteOnTermination: awssdk.Bool(v.dot), VolumeId: awssdk.String(v.id)}}
	}
	if v.name != "" {
		out.Tags = append(out.Tags, ec2types.Tag{Key: awssdk.String("Name"), Value: awssdk.String(v.name)})
	}
	out.Tags = append(out.Tags, v.tags...)
	return out
}

func (m *fakeMod) ec2(id string) ec2types.VolumeModification {
	return ec2types.VolumeModification{VolumeId: awssdk.String(id), ModificationState: ec2types.VolumeModificationState(m.state),
		Progress: awssdk.Int64(m.progress), OriginalSize: awssdk.Int32(m.origSize), TargetSize: awssdk.Int32(m.targetSize),
		OriginalVolumeType: ec2types.VolumeType(m.origType), TargetVolumeType: ec2types.VolumeType(m.targetType), StartTime: awssdk.Time(m.start)}
}

func (s *fakeSnap) ec2() ec2types.Snapshot {
	out := ec2types.Snapshot{SnapshotId: awssdk.String(s.id), VolumeId: awssdk.String(s.volID), VolumeSize: awssdk.Int32(s.size),
		State: ec2types.SnapshotState(s.state), Progress: awssdk.String(s.progress), StartTime: awssdk.Time(s.start),
		Description: awssdk.String(s.desc), Tags: s.tags, Encrypted: awssdk.Bool(false)}
	return out
}

func tagValue(tags []ec2types.Tag, key string) string {
	for _, t := range tags {
		if awssdk.ToString(t.Key) == key {
			return awssdk.ToString(t.Value)
		}
	}
	return ""
}

// globMatch matches an EC2 filter value (* and ? wildcards) against s.
func globMatch(pattern, s string) bool {
	ok, _ := path.Match(pattern, s)
	return ok
}

// ebsCall records a call and returns its configured error.
func (f *fakeEC2) ebsCall(call string) error {
	f.mu.Lock()
	f.record(call)
	f.mu.Unlock()
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	f.shared.ebs.init()
	return f.shared.ebs.errs[call]
}

func (f *fakeEC2) DescribeVolumes(_ context.Context, in *ec2.DescribeVolumesInput, _ ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	if err := f.ebsCall("DescribeVolumes"); err != nil {
		return nil, err
	}
	s := f.shared
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inst.volErr != nil {
		return nil, s.inst.volErr
	}
	type cand struct {
		v   ec2types.Volume
		vol *fakeVol
	}
	var all []cand
	// The volumes of the fake instances.
	for _, inst := range s.inst.byRegion[f.region] {
		for _, v := range inst.vols {
			all = append(all, cand{v: ec2types.Volume{VolumeId: awssdk.String(v.id), Size: awssdk.Int32(v.size), State: ec2types.VolumeStateInUse,
				VolumeType: ec2types.VolumeType(v.typ), AvailabilityZone: awssdk.String(inst.az),
				Attachments: []ec2types.VolumeAttachment{{InstanceId: awssdk.String(inst.id), Device: awssdk.String(v.device), State: ec2types.VolumeAttachmentStateAttached}}}})
		}
	}
	for _, v := range s.ebs.vols[f.region] {
		if v.hidden > 0 {
			v.hidden--
			continue
		}
		all = append(all, cand{v: v.ec2(), vol: v})
	}
	var match []cand
	for _, c := range all {
		v := c.v
		id := awssdk.ToString(v.VolumeId)
		if len(in.VolumeIds) > 0 && !containsStr(in.VolumeIds, id) {
			continue
		}
		ok := true
		for _, flt := range in.Filters {
			hit := false
			for _, want := range flt.Values {
				switch awssdk.ToString(flt.Name) {
				case "attachment.instance-id":
					for _, a := range v.Attachments {
						hit = hit || awssdk.ToString(a.InstanceId) == want
					}
				case "attachment.device":
					for _, a := range v.Attachments {
						hit = hit || awssdk.ToString(a.Device) == want
					}
				case "status":
					hit = hit || string(v.State) == want
				case "availability-zone":
					hit = hit || awssdk.ToString(v.AvailabilityZone) == want
				case "tag:Name":
					hit = hit || globMatch(want, tagValue(v.Tags, "Name"))
				case "volume-id":
					hit = hit || id == want
				default:
					panic("fake DescribeVolumes: unsupported filter " + awssdk.ToString(flt.Name))
				}
			}
			ok = ok && hit
		}
		if ok {
			match = append(match, c)
		}
	}
	if len(in.VolumeIds) > 0 && len(match) == 0 {
		return nil, &fakeAPIError{"InvalidVolume.NotFound", fmt.Sprintf("The volume '%s' does not exist.", in.VolumeIds[0])}
	}
	out := &ec2.DescribeVolumesOutput{}
	start := 0
	if in.NextToken != nil {
		start, _ = strconv.Atoi(*in.NextToken)
	}
	end := len(match)
	if s.inst.pageSize > 0 && start+s.inst.pageSize < end {
		end = start + s.inst.pageSize
		out.NextToken = awssdk.String(strconv.Itoa(end))
	}
	for _, c := range match[start:end] {
		out.Volumes = append(out.Volumes, c.v)
		if c.vol != nil {
			s.ebs.advance(f.region, c.vol)
		}
	}
	return out, nil
}

func (f *fakeEC2) DescribeVolumesModifications(_ context.Context, in *ec2.DescribeVolumesModificationsInput, _ ...func(*ec2.Options)) (*ec2.DescribeVolumesModificationsOutput, error) {
	if err := f.ebsCall("DescribeVolumesModifications"); err != nil {
		return nil, err
	}
	s := f.shared
	s.mu.Lock()
	defer s.mu.Unlock()
	id := in.VolumeIds[0]
	m := s.ebs.mods[id]
	if m == nil || m.hidden > 0 {
		if m != nil {
			m.hidden--
		}
		return nil, &fakeAPIError{"InvalidVolumeModification.NotFound", "Modification for volume '" + id + "' does not exist."}
	}
	out := &ec2.DescribeVolumesModificationsOutput{VolumesModifications: []ec2types.VolumeModification{m.ec2(id)}}
	if len(m.next) > 0 {
		m.state, m.next = m.next[0], m.next[1:]
		if m.state == modOptimizing {
			m.progress = 40
		}
		if m.state == modCompleted {
			m.progress = 100
		}
	}
	return out, nil
}

func (f *fakeEC2) CreateVolume(_ context.Context, in *ec2.CreateVolumeInput, _ ...func(*ec2.Options)) (*ec2.CreateVolumeOutput, error) {
	if err := f.ebsCall("CreateVolume"); err != nil {
		return nil, err
	}
	s := f.shared
	s.mu.Lock()
	defer s.mu.Unlock()
	e := &s.ebs
	e.creates = append(e.creates, in)
	e.nextID++
	v := &fakeVol{id: fmt.Sprintf("vol-0new%d", e.nextID), az: awssdk.ToString(in.AvailabilityZone), typ: string(in.VolumeType),
		state: volCreating, size: awssdk.ToInt32(in.Size), iops: awssdk.ToInt32(in.Iops), throughput: awssdk.ToInt32(in.Throughput),
		snapshot: awssdk.ToString(in.SnapshotId), next: append([]string{}, e.createNext...), hidden: e.createHidden}
	if len(v.next) == 0 {
		v.next = []string{volAvailable}
	}
	if v.snapshot != "" {
		for _, sn := range e.snaps[f.region] {
			if sn.id == v.snapshot && v.size < sn.size {
				v.size = sn.size // AWS silently takes the snapshot's size
			}
		}
	}
	for _, spec := range in.TagSpecifications {
		for _, t := range spec.Tags {
			if awssdk.ToString(t.Key) == "Name" {
				v.name = awssdk.ToString(t.Value)
			} else {
				v.tags = append(v.tags, t)
			}
		}
	}
	e.init()
	e.vols[f.region] = append(e.vols[f.region], v)
	ev := v.ec2()
	return &ec2.CreateVolumeOutput{VolumeId: ev.VolumeId, AvailabilityZone: ev.AvailabilityZone, Size: ev.Size, VolumeType: ev.VolumeType,
		Iops: ev.Iops, Throughput: ev.Throughput, State: ev.State, SnapshotId: ev.SnapshotId, Tags: ev.Tags, Encrypted: ev.Encrypted}, nil
}

func (f *fakeEC2) ModifyVolume(_ context.Context, in *ec2.ModifyVolumeInput, _ ...func(*ec2.Options)) (*ec2.ModifyVolumeOutput, error) {
	if err := f.ebsCall("ModifyVolume"); err != nil {
		return nil, err
	}
	s := f.shared
	s.mu.Lock()
	defer s.mu.Unlock()
	e := &s.ebs
	e.modifies = append(e.modifies, in)
	id := awssdk.ToString(in.VolumeId)
	v := e.find(f.region, id)
	if v == nil {
		return nil, &fakeAPIError{"InvalidVolume.NotFound", "The volume '" + id + "' does not exist."}
	}
	if m := e.mods[id]; m != nil && (m.state == modModifying || m.state == modOptimizing) {
		return nil, &fakeAPIError{"IncorrectModificationState", "Volume '" + id + "' cannot be modified in modification state " + strings.ToUpper(m.state)}
	}
	if in.Size != nil && *in.Size < v.size {
		return nil, &fakeAPIError{"InvalidParameterValue", "New size cannot be smaller than existing size"}
	}
	m := &fakeMod{state: modModifying, origSize: v.size, targetSize: v.size, origType: v.typ, targetType: v.typ,
		start: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), next: append([]string{}, e.modNext...), hidden: e.modHidden}
	if len(m.next) == 0 {
		m.next = []string{modCompleted}
	}
	if in.Size != nil {
		v.size, m.targetSize = *in.Size, *in.Size
	}
	if in.VolumeType != "" {
		v.typ, m.targetType = string(in.VolumeType), string(in.VolumeType)
	}
	if in.Iops != nil {
		v.iops = *in.Iops
	}
	if in.Throughput != nil {
		v.throughput = *in.Throughput
	}
	e.mods[id] = m
	vm := m.ec2(id)
	return &ec2.ModifyVolumeOutput{VolumeModification: &vm}, nil
}

func (f *fakeEC2) AttachVolume(_ context.Context, in *ec2.AttachVolumeInput, _ ...func(*ec2.Options)) (*ec2.AttachVolumeOutput, error) {
	if err := f.ebsCall("AttachVolume"); err != nil {
		return nil, err
	}
	s := f.shared
	s.mu.Lock()
	defer s.mu.Unlock()
	e := &s.ebs
	e.attaches = append(e.attaches, in)
	id := awssdk.ToString(in.VolumeId)
	v := e.find(f.region, id)
	switch {
	case v == nil:
		return nil, &fakeAPIError{"InvalidVolume.NotFound", "The volume '" + id + "' does not exist."}
	case v.state == volInUse:
		return nil, &fakeAPIError{"VolumeInUse", "vol is already attached to an instance"}
	case v.state != volAvailable:
		return nil, &fakeAPIError{"IncorrectState", "vol is not 'available'"}
	}
	v.state, v.instance, v.device, v.attachState = volInUse, awssdk.ToString(in.InstanceId), awssdk.ToString(in.Device), "attaching"
	v.attachNext = []string{"attaching", "attached"}
	return &ec2.AttachVolumeOutput{State: ec2types.VolumeAttachmentStateAttaching}, nil
}

func (f *fakeEC2) DetachVolume(_ context.Context, in *ec2.DetachVolumeInput, _ ...func(*ec2.Options)) (*ec2.DetachVolumeOutput, error) {
	if err := f.ebsCall("DetachVolume"); err != nil {
		return nil, err
	}
	s := f.shared
	s.mu.Lock()
	defer s.mu.Unlock()
	e := &s.ebs
	e.detaches = append(e.detaches, in)
	id := awssdk.ToString(in.VolumeId)
	v := e.find(f.region, id)
	switch {
	case v == nil:
		return nil, &fakeAPIError{"InvalidVolume.NotFound", "The volume '" + id + "' does not exist."}
	case v.state != volInUse:
		return nil, &fakeAPIError{"IncorrectState", "Volume '" + id + "' is in the 'available' state."}
	}
	v.attachState = "detaching"
	v.next = []string{volInUse, volAvailable}
	return &ec2.DetachVolumeOutput{State: ec2types.VolumeAttachmentStateDetaching}, nil
}

func (f *fakeEC2) DeleteVolume(_ context.Context, in *ec2.DeleteVolumeInput, _ ...func(*ec2.Options)) (*ec2.DeleteVolumeOutput, error) {
	if err := f.ebsCall("DeleteVolume"); err != nil {
		return nil, err
	}
	s := f.shared
	s.mu.Lock()
	defer s.mu.Unlock()
	id := awssdk.ToString(in.VolumeId)
	v := s.ebs.find(f.region, id)
	switch {
	case v == nil:
		return nil, &fakeAPIError{"InvalidVolume.NotFound", "The volume '" + id + "' does not exist."}
	case v.state == volInUse:
		return nil, &fakeAPIError{"VolumeInUse", "Volume " + id + " is currently attached to " + v.instance}
	}
	v.state, v.next = volDeleting, []string{"gone"}
	return &ec2.DeleteVolumeOutput{}, nil
}

func (f *fakeEC2) DescribeSnapshots(_ context.Context, in *ec2.DescribeSnapshotsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	if err := f.ebsCall("DescribeSnapshots"); err != nil {
		return nil, err
	}
	s := f.shared
	s.mu.Lock()
	defer s.mu.Unlock()
	e := &s.ebs
	e.snapOwners = append(e.snapOwners, in.OwnerIds)
	var match []*fakeSnap
	for _, sn := range e.snaps[f.region] {
		if len(in.SnapshotIds) > 0 && !containsStr(in.SnapshotIds, sn.id) {
			continue
		}
		ok := true
		for _, flt := range in.Filters {
			hit := false
			for _, want := range flt.Values {
				switch awssdk.ToString(flt.Name) {
				case "volume-id":
					hit = hit || sn.volID == want
				case "status":
					hit = hit || sn.state == want
				case "tag:Name":
					hit = hit || globMatch(want, tagValue(sn.tags, "Name"))
				default:
					panic("fake DescribeSnapshots: unsupported filter " + awssdk.ToString(flt.Name))
				}
			}
			ok = ok && hit
		}
		if ok {
			match = append(match, sn)
		}
	}
	if len(in.SnapshotIds) > 0 && len(match) == 0 {
		return nil, &fakeAPIError{"InvalidSnapshot.NotFound", "The snapshot '" + in.SnapshotIds[0] + "' does not exist."}
	}
	out := &ec2.DescribeSnapshotsOutput{}
	start := 0
	if in.NextToken != nil {
		start, _ = strconv.Atoi(*in.NextToken)
	}
	end := len(match)
	if e.snapPage > 0 && start+e.snapPage < end {
		end = start + e.snapPage
		out.NextToken = awssdk.String(strconv.Itoa(end))
	}
	for _, sn := range match[start:end] {
		out.Snapshots = append(out.Snapshots, sn.ec2())
		if len(sn.next) > 0 {
			sn.state, sn.next = sn.next[0], sn.next[1:]
			if sn.state == snapCompleted {
				sn.progress = "100%"
			}
		}
	}
	return out, nil
}

func (f *fakeEC2) CreateSnapshot(_ context.Context, in *ec2.CreateSnapshotInput, _ ...func(*ec2.Options)) (*ec2.CreateSnapshotOutput, error) {
	if err := f.ebsCall("CreateSnapshot"); err != nil {
		return nil, err
	}
	s := f.shared
	s.mu.Lock()
	defer s.mu.Unlock()
	e := &s.ebs
	e.snapCreates = append(e.snapCreates, in)
	id := awssdk.ToString(in.VolumeId)
	v := e.find(f.region, id)
	if v == nil {
		return nil, &fakeAPIError{"InvalidVolume.NotFound", "The volume '" + id + "' does not exist."}
	}
	for _, sn := range e.snaps[f.region] {
		if sn.volID == id && sn.state == snapPending {
			return nil, &fakeAPIError{"SnapshotCreationPerVolumeRateExceeded", "The maximum per volume CreateSnapshot request rate has been exceeded."}
		}
	}
	e.nextID++
	sn := &fakeSnap{id: fmt.Sprintf("snap-0new%d", e.nextID), volID: id, state: snapPending, size: v.size, desc: awssdk.ToString(in.Description),
		start: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), next: append([]string{}, e.snapNext...)}
	if len(sn.next) == 0 {
		sn.next = []string{snapCompleted}
	}
	for _, spec := range in.TagSpecifications {
		sn.tags = append(sn.tags, spec.Tags...)
	}
	e.snaps[f.region] = append(e.snaps[f.region], sn)
	es := sn.ec2()
	return &ec2.CreateSnapshotOutput{SnapshotId: es.SnapshotId, VolumeId: es.VolumeId, VolumeSize: es.VolumeSize, State: es.State,
		Progress: es.Progress, StartTime: es.StartTime, Description: es.Description, Tags: es.Tags, Encrypted: es.Encrypted}, nil
}

// addVolume puts a volume into the fake account.
func (h *awsHarness) addVolume(region string, v *fakeVol) *fakeVol {
	h.ec2.mu.Lock()
	defer h.ec2.mu.Unlock()
	h.ec2.ebs.init()
	if v.az == "" {
		v.az = region + "a"
	}
	if v.typ == "" {
		v.typ = "gp3"
	}
	if v.state == "" {
		v.state = volAvailable
		if v.instance != "" {
			v.state = volInUse
		}
	}
	if v.instance != "" && v.attachState == "" {
		v.attachState = "attached"
	}
	h.ec2.ebs.vols[region] = append(h.ec2.ebs.vols[region], v)
	return v
}

// addSnap puts a snapshot into the fake account.
func (h *awsHarness) addSnap(region string, s *fakeSnap) *fakeSnap {
	h.ec2.mu.Lock()
	defer h.ec2.mu.Unlock()
	h.ec2.ebs.init()
	if s.state == "" {
		s.state, s.progress = snapCompleted, "100%"
	}
	h.ec2.ebs.snaps[region] = append(h.ec2.ebs.snaps[region], s)
	return s
}

// setMod sets the latest modification of a volume.
func (h *awsHarness) setMod(id string, m *fakeMod) {
	h.ec2.mu.Lock()
	defer h.ec2.mu.Unlock()
	h.ec2.ebs.init()
	h.ec2.ebs.mods[id] = m
}

// ebsSetErr makes a call of the fake fail.
func (h *awsHarness) ebsSetErr(call string, err error) {
	h.ec2.mu.Lock()
	defer h.ec2.mu.Unlock()
	h.ec2.ebs.init()
	h.ec2.ebs.errs[call] = err
}

// ebs returns the EBS part of the fake state (lock h.ec2.mu to read it
// while a command runs).
func (h *awsHarness) ebs() *fakeEBS { return &h.ec2.ebs }

// ebsWrites lists the EBS write calls made so far, in order.
func (h *awsHarness) ebsWrites() []string {
	var out []string
	for _, c := range h.ec2.calls() {
		_, call, _ := strings.Cut(c, ":")
		switch call {
		case "CreateVolume", "ModifyVolume", "AttachVolume", "DetachVolume", "DeleteVolume", "CreateSnapshot":
			out = append(out, call)
		}
	}
	return out
}

// vol returns a fake volume (nil when gone).
func (h *awsHarness) vol(region, id string) *fakeVol {
	h.ec2.mu.Lock()
	defer h.ec2.mu.Unlock()
	return h.ec2.ebs.find(region, id)
}
