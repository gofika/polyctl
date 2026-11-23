package aws

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/gofika/polyctl/internal/app"
)

// fakeDB is an instance of the fake RDS. Every read of it by identifier
// first applies the next queued step, so a test scripts the statuses an
// action goes through.
type fakeDB struct {
	region string
	db     rdstypes.DBInstance
	steps  []func(*rdstypes.DBInstance)
	// hidden reads answer DBInstanceNotFound before the instance shows up.
	hidden int
	// goneAfter, when > 0, removes the instance after that many reads.
	goneAfter int
	gone      bool
}

// fakeRDSs is the state of the fake RDS of every region.
type fakeRDSs struct {
	dbs      []*fakeDB
	calls    []string
	creates  []*rds.CreateDBInstanceInput
	modifies []*rds.ModifyDBInstanceInput
	deletes  []*rds.DeleteDBInstanceInput
	// versions is the full list of engine versions; majorFamily makes a
	// major version (8.0) answer its family, as RDS does.
	versions    []rdstypes.DBEngineVersion
	noFamily    bool
	subnetZones map[string][]string
	orderable   []rdstypes.OrderableDBInstanceOption
	snapshots   map[string]bool
	// errs fail an action every time, errOnce the next time only.
	errs    map[string]error
	errOnce map[string][]error
	// pageSize pages DescribeDBInstances and DescribeDBEngineVersions.
	pageSize int
	// createSteps are the statuses a new instance reads as, one per read;
	// the endpoint shows from the first status that is not creating.
	createSteps []string
	// createHidden reads miss a new instance.
	createHidden int
	// stopSteps / startSteps are the statuses after StopDBInstance /
	// StartDBInstance (default: one read in the transition, then done).
	stopSteps, startSteps []string
	// modifyLag is the number of reads that still show the old class as
	// available after ModifyDBInstance.
	modifyLag int
	// deleteReads is the number of reads that show deleting.
	deleteReads int
}

type fakeRDS struct {
	shared *fakeEC2s
	region string
}

func (h *awsHarness) rds() *fakeRDSs { return &h.ec2.rds }

func (f *fakeRDS) state() *fakeRDSs { return &f.shared.rds }

func (f *fakeRDS) call(action string) error {
	s := f.state()
	s.calls = append(s.calls, f.region+":"+action)
	if q := s.errOnce[action]; len(q) > 0 {
		s.errOnce[action] = q[1:]
		return q[0]
	}
	return s.errs[action]
}

// writes lists the write calls made.
func (s *fakeRDSs) writes() []string {
	var out []string
	for _, c := range s.calls {
		_, a, _ := strings.Cut(c, ":")
		switch a {
		case "CreateDBInstance", "StartDBInstance", "StopDBInstance", "ModifyDBInstance", "DeleteDBInstance":
			out = append(out, c)
		}
	}
	return out
}

func (s *fakeRDSs) count(action string) int {
	n := 0
	for _, c := range s.calls {
		if strings.HasSuffix(c, ":"+action) {
			n++
		}
	}
	return n
}

func notFoundDB(id string) error {
	return &rdstypes.DBInstanceNotFoundFault{Message: awssdk.String("DBInstance " + id + " not found.")}
}

func invalidState(msg string) error {
	return &rdstypes.InvalidDBInstanceStateFault{Message: awssdk.String(msg)}
}

func (f *fakeRDS) find(id string) *fakeDB {
	for _, d := range f.state().dbs {
		if d.region == f.region && !d.gone && strings.EqualFold(awssdk.ToString(d.db.DBInstanceIdentifier), id) {
			return d
		}
	}
	return nil
}

// addDB puts an instance into the fake account.
func (h *awsHarness) addDB(region, id, status string, mods ...func(*rdstypes.DBInstance)) *fakeDB {
	h.ec2.mu.Lock()
	defer h.ec2.mu.Unlock()
	d := &fakeDB{region: region, db: rdstypes.DBInstance{
		DBInstanceIdentifier: awssdk.String(id), DBInstanceStatus: awssdk.String(status), Engine: awssdk.String("mysql"),
		EngineVersion: awssdk.String("8.0.36"), DBInstanceClass: awssdk.String("db.t3.micro"), AllocatedStorage: awssdk.Int32(20),
		StorageType: awssdk.String("gp3"), AvailabilityZone: awssdk.String(region + "a"),
		DBInstanceArn: awssdk.String("arn:aws:rds:" + region + ":" + fakeAccountID + ":db:" + id),
		Endpoint:      &rdstypes.Endpoint{Address: awssdk.String(id + ".abc123." + region + ".rds.amazonaws.com"), Port: awssdk.Int32(3306)},
	}}
	for _, m := range mods {
		m(&d.db)
	}
	h.ec2.rds.dbs = append(h.ec2.rds.dbs, d)
	return d
}

func status(s string) func(*rdstypes.DBInstance) {
	return func(db *rdstypes.DBInstance) { db.DBInstanceStatus = awssdk.String(s) }
}

func (f *fakeRDS) DescribeDBInstances(_ context.Context, in *rds.DescribeDBInstancesInput, _ ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	if err := f.shared.find.regionErr[f.region]; err != nil {
		return nil, err
	}
	if err := f.call("DescribeDBInstances"); err != nil {
		return nil, err
	}
	s := f.state()
	if id := awssdk.ToString(in.DBInstanceIdentifier); id != "" {
		d := f.find(id)
		if d == nil {
			return nil, notFoundDB(id)
		}
		if d.hidden > 0 {
			d.hidden--
			return nil, notFoundDB(id)
		}
		if len(d.steps) > 0 {
			d.steps[0](&d.db)
			d.steps = d.steps[1:]
		}
		if d.goneAfter > 0 {
			d.goneAfter--
			if d.goneAfter == 0 {
				d.gone = true
			}
		}
		return &rds.DescribeDBInstancesOutput{DBInstances: []rdstypes.DBInstance{d.db}}, nil
	}
	// Listing: the instances of the find tests, then those of the fake.
	all := append([]rdstypes.DBInstance{}, f.shared.find.dbs[f.region]...)
	for _, d := range s.dbs {
		if d.region == f.region && !d.gone {
			all = append(all, d.db)
		}
	}
	return pageOf(all, in.Marker, s.pageSize, func(items []rdstypes.DBInstance, next *string) *rds.DescribeDBInstancesOutput {
		return &rds.DescribeDBInstancesOutput{DBInstances: items, Marker: next}
	}), nil
}

func pageOf[T, O any](all []T, marker *string, size int, out func([]T, *string) O) O {
	start := 0
	if marker != nil {
		start, _ = strconv.Atoi(*marker)
	}
	end := len(all)
	var next *string
	if size > 0 && start+size < end {
		end = start + size
		next = awssdk.String(strconv.Itoa(end))
	}
	return out(all[start:end], next)
}

var fakeMajor = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)

func (f *fakeRDS) DescribeDBEngineVersions(_ context.Context, in *rds.DescribeDBEngineVersionsInput, _ ...func(*rds.Options)) (*rds.DescribeDBEngineVersionsOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	s := f.state()
	action := "DescribeDBEngineVersions"
	if in.EngineVersion != nil {
		action += "(" + *in.EngineVersion + ")"
	}
	if err := f.call(action); err != nil {
		return nil, err
	}
	var match []rdstypes.DBEngineVersion
	want := awssdk.ToString(in.EngineVersion)
	for _, v := range s.versions {
		got := awssdk.ToString(v.EngineVersion)
		switch {
		case want == "":
		case got == want:
		case !s.noFamily && fakeMajor.MatchString(want) && strings.HasPrefix(got, want+"."):
		default:
			continue
		}
		match = append(match, v)
	}
	return pageOf(match, in.Marker, s.pageSize, func(items []rdstypes.DBEngineVersion, next *string) *rds.DescribeDBEngineVersionsOutput {
		return &rds.DescribeDBEngineVersionsOutput{DBEngineVersions: items, Marker: next}
	}), nil
}

func (f *fakeRDS) DescribeDBSubnetGroups(_ context.Context, in *rds.DescribeDBSubnetGroupsInput, _ ...func(*rds.Options)) (*rds.DescribeDBSubnetGroupsOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	if err := f.call("DescribeDBSubnetGroups"); err != nil {
		return nil, err
	}
	name := awssdk.ToString(in.DBSubnetGroupName)
	zones, ok := f.state().subnetZones[name]
	if !ok {
		return nil, &rdstypes.DBSubnetGroupNotFoundFault{Message: awssdk.String("DBSubnetGroup " + name + " not found.")}
	}
	g := rdstypes.DBSubnetGroup{DBSubnetGroupName: awssdk.String(name)}
	for _, z := range zones {
		g.Subnets = append(g.Subnets, rdstypes.Subnet{SubnetAvailabilityZone: &rdstypes.AvailabilityZone{Name: awssdk.String(z)}})
	}
	return &rds.DescribeDBSubnetGroupsOutput{DBSubnetGroups: []rdstypes.DBSubnetGroup{g}}, nil
}

func (f *fakeRDS) DescribeOrderableDBInstanceOptions(_ context.Context, in *rds.DescribeOrderableDBInstanceOptionsInput, _ ...func(*rds.Options)) (*rds.DescribeOrderableDBInstanceOptionsOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	if err := f.call("DescribeOrderableDBInstanceOptions"); err != nil {
		return nil, err
	}
	var out []rdstypes.OrderableDBInstanceOption
	for _, o := range f.state().orderable {
		if awssdk.ToString(o.DBInstanceClass) == awssdk.ToString(in.DBInstanceClass) {
			out = append(out, o)
		}
	}
	return &rds.DescribeOrderableDBInstanceOptionsOutput{OrderableDBInstanceOptions: out}, nil
}

func (f *fakeRDS) DescribeDBSnapshots(_ context.Context, in *rds.DescribeDBSnapshotsInput, _ ...func(*rds.Options)) (*rds.DescribeDBSnapshotsOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	if err := f.call("DescribeDBSnapshots"); err != nil {
		return nil, err
	}
	name := awssdk.ToString(in.DBSnapshotIdentifier)
	if !f.state().snapshots[name] {
		return nil, &rdstypes.DBSnapshotNotFoundFault{Message: awssdk.String("DBSnapshot " + name + " not found.")}
	}
	return &rds.DescribeDBSnapshotsOutput{DBSnapshots: []rdstypes.DBSnapshot{{DBSnapshotIdentifier: awssdk.String(name), Status: awssdk.String("available")}}}, nil
}

func (f *fakeRDS) CreateDBInstance(_ context.Context, in *rds.CreateDBInstanceInput, _ ...func(*rds.Options)) (*rds.CreateDBInstanceOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	s := f.state()
	s.creates = append(s.creates, in)
	if err := f.call("CreateDBInstance"); err != nil {
		return nil, err
	}
	id := strings.ToLower(awssdk.ToString(in.DBInstanceIdentifier))
	if f.find(id) != nil {
		return nil, &rdstypes.DBInstanceAlreadyExistsFault{Message: awssdk.String("DB instance already exists")}
	}
	d := &fakeDB{region: f.region, hidden: s.createHidden, db: rdstypes.DBInstance{
		DBInstanceIdentifier: awssdk.String(id), DBInstanceStatus: awssdk.String(dbCreating), Engine: in.Engine,
		EngineVersion: in.EngineVersion, DBInstanceClass: in.DBInstanceClass, AllocatedStorage: in.AllocatedStorage,
		StorageType: in.StorageType, AvailabilityZone: in.AvailabilityZone, MasterUsername: in.MasterUsername,
	}}
	steps := s.createSteps
	if steps == nil {
		steps = []string{dbCreating, "backing-up", dbAvailable}
	}
	for _, st := range steps {
		st := st
		d.steps = append(d.steps, func(db *rdstypes.DBInstance) {
			db.DBInstanceStatus = awssdk.String(st)
			if st != dbCreating {
				db.Endpoint = &rdstypes.Endpoint{Address: awssdk.String(id + ".abc123." + f.region + ".rds.amazonaws.com"), Port: awssdk.Int32(3306)}
				db.InstanceCreateTime = awssdk.Time(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			}
		})
	}
	s.dbs = append(s.dbs, d)
	out := d.db
	return &rds.CreateDBInstanceOutput{DBInstance: &out}, nil
}

func (f *fakeRDS) power(action string, id, from, going string, steps []string, final string) (*rdstypes.DBInstance, error) {
	if err := f.call(action); err != nil {
		return nil, err
	}
	d := f.find(id)
	if d == nil {
		return nil, notFoundDB(id)
	}
	if awssdk.ToString(d.db.DBInstanceStatus) != from {
		return nil, invalidState("Instance " + id + " is not in " + from + " state.")
	}
	d.db.DBInstanceStatus = awssdk.String(going)
	if steps == nil {
		steps = []string{going, final}
	}
	for _, st := range steps {
		d.steps = append(d.steps, status(st))
	}
	out := d.db
	return &out, nil
}

func (f *fakeRDS) StartDBInstance(_ context.Context, in *rds.StartDBInstanceInput, _ ...func(*rds.Options)) (*rds.StartDBInstanceOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	db, err := f.power("StartDBInstance", awssdk.ToString(in.DBInstanceIdentifier), dbStopped, dbStarting, f.state().startSteps, dbAvailable)
	if err != nil {
		return nil, err
	}
	return &rds.StartDBInstanceOutput{DBInstance: db}, nil
}

func (f *fakeRDS) StopDBInstance(_ context.Context, in *rds.StopDBInstanceInput, _ ...func(*rds.Options)) (*rds.StopDBInstanceOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	db, err := f.power("StopDBInstance", awssdk.ToString(in.DBInstanceIdentifier), dbAvailable, dbStopping, f.state().stopSteps, dbStopped)
	if err != nil {
		return nil, err
	}
	return &rds.StopDBInstanceOutput{DBInstance: db}, nil
}

func (f *fakeRDS) ModifyDBInstance(_ context.Context, in *rds.ModifyDBInstanceInput, _ ...func(*rds.Options)) (*rds.ModifyDBInstanceOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	s := f.state()
	s.modifies = append(s.modifies, in)
	if err := f.call("ModifyDBInstance"); err != nil {
		return nil, err
	}
	id := awssdk.ToString(in.DBInstanceIdentifier)
	d := f.find(id)
	if d == nil {
		return nil, notFoundDB(id)
	}
	if in.DeletionProtection != nil {
		d.db.DeletionProtection = in.DeletionProtection
	}
	if class := awssdk.ToString(in.DBInstanceClass); class != "" {
		if st := awssdk.ToString(d.db.DBInstanceStatus); st != dbAvailable && st != dbStopped {
			return nil, invalidState("Database instance is not in available state.")
		}
		if awssdk.ToString(d.db.DBInstanceStatus) == dbStopped {
			d.db.DBInstanceClass = awssdk.String(class)
		} else {
			d.db.PendingModifiedValues = &rdstypes.PendingModifiedValues{DBInstanceClass: awssdk.String(class)}
			for i := 0; i < s.modifyLag; i++ {
				d.steps = append(d.steps, func(*rdstypes.DBInstance) {})
			}
			d.steps = append(d.steps,
				status(dbModifying),
				func(db *rdstypes.DBInstance) {
					db.DBInstanceClass = awssdk.String(class)
					db.PendingModifiedValues = &rdstypes.PendingModifiedValues{}
				},
				status("configuring-enhanced-monitoring"),
				status(dbAvailable))
		}
	}
	out := d.db
	return &rds.ModifyDBInstanceOutput{DBInstance: &out}, nil
}

func (f *fakeRDS) DeleteDBInstance(_ context.Context, in *rds.DeleteDBInstanceInput, _ ...func(*rds.Options)) (*rds.DeleteDBInstanceOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	s := f.state()
	s.deletes = append(s.deletes, in)
	if err := f.call("DeleteDBInstance"); err != nil {
		return nil, err
	}
	id := awssdk.ToString(in.DBInstanceIdentifier)
	d := f.find(id)
	if d == nil {
		return nil, notFoundDB(id)
	}
	if awssdk.ToString(d.db.DBInstanceStatus) == dbDeleting {
		return nil, invalidState("Instance " + id + " is already being deleted.")
	}
	if awssdk.ToBool(d.db.DeletionProtection) {
		return nil, &fakeAPIError{"InvalidParameterCombination", "Cannot delete protected DB Instance, please disable deletion protection and try again."}
	}
	skip := awssdk.ToBool(in.SkipFinalSnapshot)
	if skip && in.FinalDBSnapshotIdentifier != nil {
		return nil, &fakeAPIError{"InvalidParameterCombination", "Only one of SkipFinalSnapshot and FinalDBSnapshotIdentifier can be specified"}
	}
	if !skip && in.FinalDBSnapshotIdentifier == nil {
		return nil, &fakeAPIError{"InvalidParameterCombination", "FinalDBSnapshotIdentifier is required unless SkipFinalSnapshot is specified."}
	}
	if !skip {
		name := awssdk.ToString(in.FinalDBSnapshotIdentifier)
		if s.snapshots[name] {
			return nil, &rdstypes.DBSnapshotAlreadyExistsFault{Message: awssdk.String("Cannot create the snapshot because a snapshot with the identifier " + name + " already exists.")}
		}
		if s.snapshots == nil {
			s.snapshots = map[string]bool{}
		}
		s.snapshots[name] = true
	}
	d.db.DBInstanceStatus = awssdk.String(dbDeleting)
	d.steps = nil
	d.goneAfter = s.deleteReads
	if s.deleteReads == 0 {
		d.gone = true
	}
	out := d.db
	return &rds.DeleteDBInstanceOutput{DBInstance: &out}, nil
}

// useFakeRDSClock makes the RDS waits use a fake clock.
func useFakeRDSClock(t *testing.T) *fakeClock {
	t.Helper()
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	old := rdsClock
	rdsClock = clk
	t.Cleanup(func() { rdsClock = old })
	return clk
}

// newRDSHarness is an AWS harness with the fake RDS clock.
func newRDSHarness(t *testing.T, flags app.Flags, defaults map[string]any) (*awsHarness, *fakeClock) {
	t.Helper()
	h := newAWSHarness(t, flags, defaults)
	return h, useFakeRDSClock(t)
}
