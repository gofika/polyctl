package aws

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/gofika/polyctl/internal/platform"
)

// rdsAPI is the part of the RDS API polyctl uses, so tests can substitute
// a fake.
type rdsAPI interface {
	DescribeDBInstances(ctx context.Context, in *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
	DescribeDBEngineVersions(ctx context.Context, in *rds.DescribeDBEngineVersionsInput, optFns ...func(*rds.Options)) (*rds.DescribeDBEngineVersionsOutput, error)
	DescribeDBSubnetGroups(ctx context.Context, in *rds.DescribeDBSubnetGroupsInput, optFns ...func(*rds.Options)) (*rds.DescribeDBSubnetGroupsOutput, error)
	DescribeOrderableDBInstanceOptions(ctx context.Context, in *rds.DescribeOrderableDBInstanceOptionsInput, optFns ...func(*rds.Options)) (*rds.DescribeOrderableDBInstanceOptionsOutput, error)
	DescribeDBSnapshots(ctx context.Context, in *rds.DescribeDBSnapshotsInput, optFns ...func(*rds.Options)) (*rds.DescribeDBSnapshotsOutput, error)
	CreateDBInstance(ctx context.Context, in *rds.CreateDBInstanceInput, optFns ...func(*rds.Options)) (*rds.CreateDBInstanceOutput, error)
	StartDBInstance(ctx context.Context, in *rds.StartDBInstanceInput, optFns ...func(*rds.Options)) (*rds.StartDBInstanceOutput, error)
	StopDBInstance(ctx context.Context, in *rds.StopDBInstanceInput, optFns ...func(*rds.Options)) (*rds.StopDBInstanceOutput, error)
	ModifyDBInstance(ctx context.Context, in *rds.ModifyDBInstanceInput, optFns ...func(*rds.Options)) (*rds.ModifyDBInstanceOutput, error)
	DeleteDBInstance(ctx context.Context, in *rds.DeleteDBInstanceInput, optFns ...func(*rds.Options)) (*rds.DeleteDBInstanceOutput, error)
}

// newRDS creates the regional RDS client; tests replace it.
var newRDS = func(cfg awssdk.Config) rdsAPI { return rds.NewFromConfig(cfg) }

// rdsClock is the clock of the RDS waits; tests replace it.
var rdsClock platform.Clock = platform.RealClock

// The RDS instance statuses polyctl acts on.
const (
	dbAvailable = "available"
	dbStopped   = "stopped"
	dbStopping  = "stopping"
	dbStarting  = "starting"
	dbCreating  = "creating"
	dbDeleting  = "deleting"
	dbModifying = "modifying"
)

// Poll intervals of the RDS waits (measured: create about 7 minutes, stop
// and start about 4, a class change about 5, a delete about 8).
var (
	dbCreatePoll = 30 * time.Second
	dbPowerPoll  = 15 * time.Second
	dbResizePoll = 15 * time.Second
	dbDeletePoll = 30 * time.Second
	dbSettlePoll = 30 * time.Second
)

// dbFatal reports the statuses an instance does not come back from by
// itself: a wait for anything else ends at once on them.
func dbFatal(status string) bool {
	switch status {
	case "failed", dbDeleting, "delete-failed", "storage-full", "restore-error",
		"inaccessible-encryption-credentials", "inaccessible-encryption-credentials-recoverable":
		return true
	}
	return strings.HasPrefix(status, "incompatible-")
}

// dbKey is the inventory id of an RDS instance: identifiers are unique per
// account and region only.
func dbKey(region, id string) string { return region + "/" + id }

// rdsErr wraps an error of the RDS call action in region. A missing
// instance maps to the not-found exit code, a denial to the
// authentication code (naming the IAM action the call needs); every other
// error, parameter errors included, keeps the general code and the AWS
// error code and message.
func rdsErr(action, region string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var nf *rdstypes.DBInstanceNotFoundFault
	if errors.As(err, &nf) {
		return fmt.Errorf("%w: rds:%s in %s: %w", platform.ErrNotFound, action, region, err)
	}
	denied := unauthorizedCodes[platform.ErrorCode(err)]
	var he httpStatusError
	if !denied && errors.As(err, &he) {
		// Any 401 or 403 is a credentials problem (SignatureDoesNotMatch,
		// ExpiredToken, ...), as mapErr has it for the other services.
		denied = he.HTTPStatusCode() == 401 || he.HTTPStatusCode() == 403
	}
	if denied {
		return fmt.Errorf("%w: rds:%s in %s (the credentials need the IAM action rds:%s): %w", platform.ErrUnauthorized, action, region, action, err)
	}
	return fmt.Errorf("rds:%s in %s: %w", action, region, err)
}

// isDBNotFound reports a missing instance, typed or by its code.
func isDBNotFound(err error) bool {
	var nf *rdstypes.DBInstanceNotFoundFault
	return errors.As(err, &nf) || platform.HasErrorCode(err, "DBInstanceNotFound")
}

// isInvalidDBState reports InvalidDBInstanceState: the instance is not in a
// status that allows the call.
func isInvalidDBState(err error) bool {
	var f *rdstypes.InvalidDBInstanceStateFault
	return errors.As(err, &f) || platform.HasErrorCode(err, "InvalidDBInstanceState")
}

// ---------------------------------------------------------- conversion

// dbInstance is the inventory form of an RDS instance. It holds what list
// and get show; the master password is never part of it (AWS does not
// return it).
type dbInstance struct {
	ID       string `json:"id" yaml:"id"`
	Status   string `json:"status,omitempty" yaml:"status,omitempty"`
	Engine   string `json:"engine,omitempty" yaml:"engine,omitempty"`
	Class    string `json:"class,omitempty" yaml:"class,omitempty"`
	Endpoint string `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`
	Port     int32  `json:"port,omitempty" yaml:"port,omitempty"`
	Zone     string `json:"zone,omitempty" yaml:"zone,omitempty"`
	VpcID    string `json:"vpc_id,omitempty" yaml:"vpc_id,omitempty"`
	Region   string `json:"region" yaml:"region"`

	ARN                string            `json:"arn,omitempty" yaml:"arn,omitempty"`
	EngineVersion      string            `json:"engine_version,omitempty" yaml:"engine_version,omitempty"`
	Storage            int32             `json:"allocated_storage_gb,omitempty" yaml:"allocated_storage_gb,omitempty"`
	MaxStorage         int32             `json:"max_allocated_storage_gb,omitempty" yaml:"max_allocated_storage_gb,omitempty"`
	StorageType        string            `json:"storage_type,omitempty" yaml:"storage_type,omitempty"`
	MultiAZ            bool              `json:"multi_az,omitempty" yaml:"multi_az,omitempty"`
	DeletionProtection bool              `json:"deletion_protection,omitempty" yaml:"deletion_protection,omitempty"`
	SubnetGroup        string            `json:"subnet_group,omitempty" yaml:"subnet_group,omitempty"`
	SecurityGroups     []string          `json:"security_groups,omitempty" yaml:"security_groups,omitempty"`
	CreatedAt          time.Time         `json:"created_at,omitzero" yaml:"created_at,omitempty"`
	ParameterGroup     string            `json:"parameter_group,omitempty" yaml:"parameter_group,omitempty"`
	BackupRetention    int32             `json:"backup_retention,omitempty" yaml:"backup_retention,omitempty"`
	Public             bool              `json:"publicly_accessible,omitempty" yaml:"publicly_accessible,omitempty"`
	Tags               map[string]string `json:"tags,omitempty" yaml:"tags,omitempty"`
	ClusterID          string            `json:"cluster_id,omitempty" yaml:"cluster_id,omitempty"`
	PendingClass       string            `json:"pending_class,omitempty" yaml:"pending_class,omitempty"`
}

// dbFrom converts an instance of the API. Every pointer may be nil (a new
// instance has no endpoint and possibly no creation time yet).
func dbFrom(region string, db rdstypes.DBInstance) dbInstance {
	d := dbInstance{
		ID: awssdk.ToString(db.DBInstanceIdentifier), Status: awssdk.ToString(db.DBInstanceStatus),
		Engine: awssdk.ToString(db.Engine), Class: awssdk.ToString(db.DBInstanceClass), Zone: awssdk.ToString(db.AvailabilityZone),
		Region: region, ARN: awssdk.ToString(db.DBInstanceArn), EngineVersion: awssdk.ToString(db.EngineVersion),
		Storage: awssdk.ToInt32(db.AllocatedStorage), MaxStorage: awssdk.ToInt32(db.MaxAllocatedStorage),
		StorageType: awssdk.ToString(db.StorageType), MultiAZ: awssdk.ToBool(db.MultiAZ),
		DeletionProtection: awssdk.ToBool(db.DeletionProtection), BackupRetention: awssdk.ToInt32(db.BackupRetentionPeriod),
		Public: awssdk.ToBool(db.PubliclyAccessible), ClusterID: awssdk.ToString(db.DBClusterIdentifier),
	}
	if db.Endpoint != nil {
		d.Endpoint, d.Port = awssdk.ToString(db.Endpoint.Address), awssdk.ToInt32(db.Endpoint.Port)
	}
	if db.DBSubnetGroup != nil {
		d.VpcID, d.SubnetGroup = awssdk.ToString(db.DBSubnetGroup.VpcId), awssdk.ToString(db.DBSubnetGroup.DBSubnetGroupName)
	}
	for _, g := range db.VpcSecurityGroups {
		if id := awssdk.ToString(g.VpcSecurityGroupId); id != "" {
			d.SecurityGroups = append(d.SecurityGroups, id)
		}
	}
	if db.InstanceCreateTime != nil {
		d.CreatedAt = db.InstanceCreateTime.UTC()
	}
	if len(db.DBParameterGroups) > 0 {
		d.ParameterGroup = awssdk.ToString(db.DBParameterGroups[0].DBParameterGroupName)
	}
	for _, t := range db.TagList {
		if d.Tags == nil {
			d.Tags = map[string]string{}
		}
		d.Tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	if db.PendingModifiedValues != nil {
		d.PendingClass = awssdk.ToString(db.PendingModifiedValues.DBInstanceClass)
	}
	return d
}

func (d dbInstance) resource() platform.Resource {
	var s platform.IPSet
	s.AddDNS(d.Endpoint)
	return platform.Resource{Type: platform.ResDBInstance, ID: dbKey(d.Region, d.ID), Name: d.ID, ParentID: d.Region, Data: d, IPs: s.Refs()}
}

// dbInstanceResources lists the RDS instances of a region. RDS gives no
// addresses: an instance is found by its endpoint, and one without an
// endpoint yet (being created) is stored without one.
func (c *client) dbInstanceResources(ctx context.Context, region string) ([]platform.Resource, error) {
	dbs, err := c.listDBInstances(ctx, region)
	if err != nil {
		return nil, err
	}
	res := make([]platform.Resource, 0, len(dbs))
	for _, db := range dbs {
		res = append(res, dbFrom(region, db).resource())
	}
	return res, nil
}

// ------------------------------------------------------------ describe

// listDBInstances lists every instance of a region (100 per page, the
// largest page RDS accepts).
func (c *client) listDBInstances(ctx context.Context, region string) ([]rdstypes.DBInstance, error) {
	var out []rdstypes.DBInstance
	pg := rds.NewDescribeDBInstancesPaginator(c.rdsFor(region), &rds.DescribeDBInstancesInput{MaxRecords: awssdk.Int32(100)})
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, rdsErr("DescribeDBInstances", region, err)
		}
		out = append(out, page.DBInstances...)
	}
	return out, nil
}

// describeDB reads one instance (a single page: the identifier names one).
// A missing instance is platform.ErrNotFound.
func (c *client) describeDB(ctx context.Context, region, id string) (rdstypes.DBInstance, error) {
	out, err := c.rdsFor(region).DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{DBInstanceIdentifier: awssdk.String(id)})
	if err != nil {
		return rdstypes.DBInstance{}, rdsErr("DescribeDBInstances", region, err)
	}
	for _, db := range out.DBInstances {
		if strings.EqualFold(awssdk.ToString(db.DBInstanceIdentifier), id) {
			return db, nil
		}
	}
	return rdstypes.DBInstance{}, fmt.Errorf("%w: RDS instance %s in %s", platform.ErrNotFound, id, region)
}

// ------------------------------------------------------- engine version

// majorPattern is the accepted form of --major: X.Y.
var majorPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)

// engineVersion is a parsed RDS engine version: the numeric core
// ("8.0.46") and an optional build suffix ("rds.20260908").
type engineVersion struct {
	raw    string
	core   []int
	suffix string
}

// parseEngineVersion splits a version at its first "-" into the core,
// compared number by number, and the suffix. A core that is not numeric
// is not a version polyctl can order.
func parseEngineVersion(v string) (engineVersion, bool) {
	core, suffix, _ := strings.Cut(v, "-")
	ev := engineVersion{raw: v, suffix: suffix}
	for _, part := range strings.Split(core, ".") {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return ev, false
		}
		ev.core = append(ev.core, n)
	}
	return ev, len(ev.core) > 0
}

// suffixDate returns the number after "rds." of a build suffix
// ("rds.20260908"), or -1.
func (v engineVersion) suffixDate() int64 {
	s, ok := strings.CutPrefix(v.suffix, "rds.")
	if !ok {
		return -1
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return -1
	}
	return n
}

// compareEngineVersions orders versions: by the core, number by number (a
// missing number is 0), then a plain version before a build of the same
// core, then the later build date.
func compareEngineVersions(a, b engineVersion) int {
	for i := 0; i < max(len(a.core), len(b.core)); i++ {
		x, y := 0, 0
		if i < len(a.core) {
			x = a.core[i]
		}
		if i < len(b.core) {
			y = b.core[i]
		}
		if x != y {
			return x - y
		}
	}
	switch {
	case a.suffix == b.suffix:
		return 0
	case a.suffix == "":
		return 1
	case b.suffix == "":
		return -1
	}
	if da, db := a.suffixDate(), b.suffixDate(); da != db {
		if da < db {
			return -1
		}
		return 1
	}
	return strings.Compare(a.suffix, b.suffix)
}

// latestEngineVersion returns the newest available version of versions
// in the major version major ("8.0"). Versions whose status is not
// "available" (deprecated) are skipped; a missing status is taken as
// available.
func latestEngineVersion(versions []rdstypes.DBEngineVersion, major string) (string, bool) {
	var best *engineVersion
	for _, v := range versions {
		if s := awssdk.ToString(v.Status); s != "" && s != "available" {
			continue
		}
		raw := awssdk.ToString(v.EngineVersion)
		if raw != major && !strings.HasPrefix(raw, major+".") {
			continue
		}
		ev, ok := parseEngineVersion(raw)
		if !ok {
			continue
		}
		if best == nil || compareEngineVersions(ev, *best) > 0 {
			best = &ev
		}
	}
	if best == nil {
		return "", false
	}
	return best.raw, true
}

// describeEngineVersions lists the versions of engine, of one major
// version when version is set.
func (c *client) describeEngineVersions(ctx context.Context, region, engine, version string) ([]rdstypes.DBEngineVersion, error) {
	in := &rds.DescribeDBEngineVersionsInput{Engine: awssdk.String(engine)}
	if version != "" {
		in.EngineVersion = awssdk.String(version)
	}
	var out []rdstypes.DBEngineVersion
	pg := rds.NewDescribeDBEngineVersionsPaginator(c.rdsFor(region), in)
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, rdsErr("DescribeDBEngineVersions", region, err)
		}
		out = append(out, page.DBEngineVersions...)
	}
	return out, nil
}

// resolveLatestVersion finds the newest available version of engine in
// major. RDS answers a major version ("8.0") with its whole family; when
// that yields nothing, the full list is filtered by prefix instead. None
// is an error (general failure).
func (c *client) resolveLatestVersion(ctx context.Context, region, engine, major string) (string, error) {
	versions, err := c.describeEngineVersions(ctx, region, engine, major)
	if err != nil {
		return "", err
	}
	if v, ok := latestEngineVersion(versions, major); ok {
		return v, nil
	}
	if versions, err = c.describeEngineVersions(ctx, region, engine, ""); err != nil {
		return "", err
	}
	if v, ok := latestEngineVersion(versions, major); ok {
		return v, nil
	}
	return "", fmt.Errorf("no available %s %s version found in %s", engineLabel(engine), major, region)
}

func engineLabel(engine string) string {
	if engine == "mysql" {
		return "MySQL"
	}
	return engine
}

// -------------------------------------------------------------- create

// dbCreateSpec is what `rds instance create` asks for.
type dbCreateSpec struct {
	ID, Class, Engine, EngineVersion, MasterUser string
	// Password is held in memory only: never logged, stored or printed.
	Password                                     string
	Size, MaxSize                                int32
	StorageType, AZ, SubnetGroup, ParameterGroup string
	SecurityGroups                               []string
	BackupRetention                              int32
	BackupWindow, MaintenanceWindow              string
	Public                                       bool
	Tags                                         map[string]string
}

// createInput builds the CreateDBInstance request. Empty optional values
// are left out, so AWS applies its defaults (the default VPC's subnet
// group, its default security group, the engine's default parameter
// group); MaxSize 0 leaves storage autoscaling off.
func (s dbCreateSpec) createInput() *rds.CreateDBInstanceInput {
	in := &rds.CreateDBInstanceInput{
		DBInstanceIdentifier: awssdk.String(s.ID), DBInstanceClass: awssdk.String(s.Class), Engine: awssdk.String(s.Engine),
		EngineVersion: awssdk.String(s.EngineVersion), MasterUsername: awssdk.String(s.MasterUser),
		MasterUserPassword: awssdk.String(s.Password), AllocatedStorage: awssdk.Int32(s.Size),
		StorageType: awssdk.String(s.StorageType), AvailabilityZone: awssdk.String(s.AZ),
		PubliclyAccessible: awssdk.Bool(s.Public), BackupRetentionPeriod: awssdk.Int32(s.BackupRetention),
	}
	if s.MaxSize > 0 {
		in.MaxAllocatedStorage = awssdk.Int32(s.MaxSize)
	}
	if len(s.SecurityGroups) > 0 {
		in.VpcSecurityGroupIds = slices.Clone(s.SecurityGroups)
	}
	if s.SubnetGroup != "" {
		in.DBSubnetGroupName = awssdk.String(s.SubnetGroup)
	}
	if s.ParameterGroup != "" {
		in.DBParameterGroupName = awssdk.String(s.ParameterGroup)
	}
	if s.BackupWindow != "" {
		in.PreferredBackupWindow = awssdk.String(s.BackupWindow)
	}
	if s.MaintenanceWindow != "" {
		in.PreferredMaintenanceWindow = awssdk.String(s.MaintenanceWindow)
	}
	keys := make([]string, 0, len(s.Tags))
	for k := range s.Tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		in.Tags = append(in.Tags, rdstypes.Tag{Key: awssdk.String(k), Value: awssdk.String(s.Tags[k])})
	}
	return in
}

// createDB sends CreateDBInstance and returns the new instance. Its
// errors carry the explanation of createError.
func (c *client) createDB(ctx context.Context, region string, s dbCreateSpec, debugf func(string, ...any)) (rdstypes.DBInstance, error) {
	out, err := c.rdsFor(region).CreateDBInstance(ctx, s.createInput())
	if err != nil {
		return rdstypes.DBInstance{}, c.createError(ctx, region, s, err, debugf)
	}
	if out.DBInstance == nil {
		return rdstypes.DBInstance{DBInstanceIdentifier: awssdk.String(s.ID), DBInstanceStatus: awssdk.String(dbCreating)}, nil
	}
	return *out.DBInstance, nil
}

// createError explains a failed CreateDBInstance. The AWS error always
// stays in the message; the hint after it comes from what was seen fail
// before: a subnet group without a subnet in the zone, a class the zone
// does not offer, capacity, parameters.
func (c *client) createError(ctx context.Context, region string, s dbCreateSpec, err error, debugf func(string, ...any)) error {
	var exists *rdstypes.DBInstanceAlreadyExistsFault
	var vpc *rdstypes.InvalidVPCNetworkStateFault
	var capacity *rdstypes.InsufficientDBInstanceCapacityFault
	base := rdsErr("CreateDBInstance", region, err)
	switch {
	case errors.As(err, &exists) || platform.HasErrorCode(err, "DBInstanceAlreadyExists"):
		return fmt.Errorf("RDS instance %s already exists in %s: %w", s.ID, region, base)
	case errors.As(err, &vpc) || platform.HasErrorCode(err, "InvalidVPCNetworkStateFault", "InvalidVPCNetworkState"):
		return fmt.Errorf("%w; %s", base, c.diagnoseVPC(ctx, region, s, debugf))
	case errors.As(err, &capacity) || platform.HasErrorCode(err, "InsufficientDBInstanceCapacity"):
		return fmt.Errorf("%w; class %s has no capacity in the selected zone: try another availability zone or class", base, s.Class)
	}
	code := platform.ErrorCode(err)
	switch {
	case strings.Contains(code, "InvalidParameterValue"):
		return fmt.Errorf("%w; check the parameter values", base)
	case strings.Contains(code, "InvalidParameterCombination"):
		return fmt.Errorf("%w; check that the parameters can be combined", base)
	}
	return base
}

// diagnoseVPC tells why the subnet group cannot hold the instance in the
// zone: the zones of the subnet group, then whether the class is offered
// in the zone. A diagnosis that fails itself is only a debug line: the
// AWS error stays the answer.
func (c *client) diagnoseVPC(ctx context.Context, region string, s dbCreateSpec, debugf func(string, ...any)) string {
	group := s.SubnetGroup
	if group == "" {
		group = "default"
	}
	zones, err := c.subnetGroupZones(ctx, region, group)
	if err != nil {
		debugf("diagnose subnet group %s: %v", group, err)
	}
	if len(zones) == 0 {
		return fmt.Sprintf("check that the subnet group %s is set up correctly", group)
	}
	if !slices.Contains(zones, s.AZ) {
		return fmt.Sprintf("availability zone %s is not in the subnet group %s; use one of: %s", s.AZ, group, strings.Join(zones, ", "))
	}
	offered, err := c.classOffered(ctx, region, s.Engine, s.Class, s.StorageType, s.AZ)
	if err != nil {
		debugf("diagnose orderable options of %s: %v", s.Class, err)
		return "AWS may be short of capacity for now; retry later"
	}
	if !offered {
		return fmt.Sprintf("class %s (%s storage) is not offered in %s; try db.t3.micro, db.t3.small or db.m6i.large", s.Class, s.StorageType, s.AZ)
	}
	return "AWS may be short of capacity for now; retry later"
}

// subnetGroupZones returns the availability zones of the subnets of a
// subnet group, sorted.
func (c *client) subnetGroupZones(ctx context.Context, region, group string) ([]string, error) {
	out, err := c.rdsFor(region).DescribeDBSubnetGroups(ctx, &rds.DescribeDBSubnetGroupsInput{DBSubnetGroupName: awssdk.String(group)})
	if err != nil {
		return nil, rdsErr("DescribeDBSubnetGroups", region, err)
	}
	var zones []string
	for _, g := range out.DBSubnetGroups {
		for _, sn := range g.Subnets {
			if sn.SubnetAvailabilityZone != nil {
				zones = appendNew(zones, awssdk.ToString(sn.SubnetAvailabilityZone.Name))
			}
		}
	}
	sort.Strings(zones)
	return zones, nil
}

// classOffered reports whether engine offers class with storageType in az.
func (c *client) classOffered(ctx context.Context, region, engine, class, storageType, az string) (bool, error) {
	pg := rds.NewDescribeOrderableDBInstanceOptionsPaginator(c.rdsFor(region), &rds.DescribeOrderableDBInstanceOptionsInput{
		Engine: awssdk.String(engine), DBInstanceClass: awssdk.String(class)})
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return false, rdsErr("DescribeOrderableDBInstanceOptions", region, err)
		}
		for _, o := range page.OrderableDBInstanceOptions {
			if awssdk.ToString(o.StorageType) != storageType {
				continue
			}
			for _, z := range o.AvailabilityZones {
				if awssdk.ToString(z.Name) == az {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// ------------------------------------------------------ power, modify

// startDB sends StartDBInstance and returns the status AWS answers with.
func (c *client) startDB(ctx context.Context, region, id string) (string, error) {
	out, err := c.rdsFor(region).StartDBInstance(ctx, &rds.StartDBInstanceInput{DBInstanceIdentifier: awssdk.String(id)})
	if err != nil {
		return "", stateErr(rdsErr("StartDBInstance", region, err), err)
	}
	if out.DBInstance != nil && out.DBInstance.DBInstanceStatus != nil {
		return *out.DBInstance.DBInstanceStatus, nil
	}
	return dbStarting, nil
}

// stopDB sends StopDBInstance (no snapshot) and returns the status AWS
// answers with.
func (c *client) stopDB(ctx context.Context, region, id string) (string, error) {
	out, err := c.rdsFor(region).StopDBInstance(ctx, &rds.StopDBInstanceInput{DBInstanceIdentifier: awssdk.String(id)})
	if err != nil {
		return "", stateErr(rdsErr("StopDBInstance", region, err), err)
	}
	if out.DBInstance != nil && out.DBInstance.DBInstanceStatus != nil {
		return *out.DBInstance.DBInstanceStatus, nil
	}
	return dbStopping, nil
}

// stateErr adds the hint of InvalidDBInstanceState: the status changed
// since it was read, or the instance cannot do this at all (read
// replicas, instances with read replicas, SQL Server Multi-AZ).
func stateErr(wrapped, raw error) error {
	if isInvalidDBState(raw) {
		return fmt.Errorf("%w; the instance is not in a status that allows this (it may have changed meanwhile: check it with get and retry)", wrapped)
	}
	return wrapped
}

// modifyClass changes the class at once (ApplyImmediately: without it the
// change waits for the maintenance window and the instance never enters
// modifying).
func (c *client) modifyClass(ctx context.Context, region, id, class string) (rdstypes.DBInstance, error) {
	out, err := c.rdsFor(region).ModifyDBInstance(ctx, &rds.ModifyDBInstanceInput{
		DBInstanceIdentifier: awssdk.String(id), DBInstanceClass: awssdk.String(class), ApplyImmediately: awssdk.Bool(true)})
	if err != nil {
		return rdstypes.DBInstance{}, rdsErr("ModifyDBInstance", region, err)
	}
	if out.DBInstance == nil {
		return rdstypes.DBInstance{}, nil
	}
	return *out.DBInstance, nil
}

// disableProtection switches deletion protection off (at once).
func (c *client) disableProtection(ctx context.Context, region, id string) error {
	_, err := c.rdsFor(region).ModifyDBInstance(ctx, &rds.ModifyDBInstanceInput{
		DBInstanceIdentifier: awssdk.String(id), DeletionProtection: awssdk.Bool(false), ApplyImmediately: awssdk.Bool(true)})
	return rdsErr("ModifyDBInstance", region, err)
}

// ---------------------------------------------------------------- delete

// snapshotExists reports whether a manual snapshot of that name exists
// (in any status: a snapshot being created blocks the name too).
func (c *client) snapshotExists(ctx context.Context, region, name string) (bool, error) {
	out, err := c.rdsFor(region).DescribeDBSnapshots(ctx, &rds.DescribeDBSnapshotsInput{DBSnapshotIdentifier: awssdk.String(name)})
	if err != nil {
		var nf *rdstypes.DBSnapshotNotFoundFault
		if errors.As(err, &nf) || platform.HasErrorCode(err, "DBSnapshotNotFound") {
			return false, nil
		}
		return false, rdsErr("DescribeDBSnapshots", region, err)
	}
	for _, s := range out.DBSnapshots {
		if strings.EqualFold(awssdk.ToString(s.DBSnapshotIdentifier), name) {
			return true, nil
		}
	}
	return false, nil
}

// deleteDB sends DeleteDBInstance. The final snapshot name is sent only
// when the snapshot is not skipped (AWS refuses both, and requires the
// name unless skipping). Automated backups follow the AWS default: they
// are deleted with the instance.
func (c *client) deleteDB(ctx context.Context, region, id string, skipSnapshot bool, snapshot string) (string, error) {
	in := &rds.DeleteDBInstanceInput{DBInstanceIdentifier: awssdk.String(id), SkipFinalSnapshot: awssdk.Bool(skipSnapshot)}
	if !skipSnapshot {
		in.FinalDBSnapshotIdentifier = awssdk.String(snapshot)
	}
	out, err := c.rdsFor(region).DeleteDBInstance(ctx, in)
	if err != nil {
		return "", deleteErr(rdsErr("DeleteDBInstance", region, err), err, snapshot)
	}
	if out.DBInstance != nil && out.DBInstance.DBInstanceStatus != nil {
		return *out.DBInstance.DBInstanceStatus, nil
	}
	return dbDeleting, nil
}

func deleteErr(wrapped, raw error, snapshot string) error {
	var exists *rdstypes.DBSnapshotAlreadyExistsFault
	var quota *rdstypes.SnapshotQuotaExceededFault
	switch {
	case errors.As(raw, &exists) || platform.HasErrorCode(raw, "DBSnapshotAlreadyExists"):
		return fmt.Errorf("%w; a snapshot named %s exists already: pass another --final-snapshot, or delete the old snapshot", wrapped, snapshot)
	case errors.As(raw, &quota) || platform.HasErrorCode(raw, "SnapshotQuotaExceeded"):
		return fmt.Errorf("%w; the snapshot quota is used up: delete old snapshots first", wrapped)
	case isInvalidDBState(raw):
		return fmt.Errorf("%w; the instance is not in a status that allows deleting it", wrapped)
	case platform.HasErrorCode(raw, "InvalidParameterCombination") && strings.Contains(strings.ToLower(raw.Error()), "protect"):
		return fmt.Errorf("%w; deletion protection is on", wrapped)
	}
	return wrapped
}

// ----------------------------------------------------------------- wait

// dbWait describes one wait for an instance.
type dbWait struct {
	region, id string
	// want names the awaited state in messages.
	want     string
	interval time.Duration
	timeout  time.Duration
	// done says whether the instance as read is there.
	done func(db rdstypes.DBInstance) bool
	// goneIsDone ends the wait when the instance is gone (delete);
	// otherwise a missing instance is not visible yet (create), unless
	// goneFails.
	goneIsDone, goneFails bool
	// fatal overrides dbFatal (delete waits through "deleting").
	fatal func(status string) bool
}

// waitDB polls the instance until w.done, and returns it as last read.
func (c *client) waitDB(ctx context.Context, w dbWait) (rdstypes.DBInstance, error) {
	var last rdstypes.DBInstance
	var tol tolerant
	fatal := w.fatal
	if fatal == nil {
		fatal = dbFatal
	}
	err := platform.WaitUntil(ctx, platform.WaitOptions{Resource: "db-instance/" + w.id, Want: w.want, Timeout: w.timeout, Interval: w.interval, Clock: rdsClock},
		func(ctx context.Context) (platform.WaitState, string, error) {
			db, err := c.describeDB(ctx, w.region, w.id)
			if err != nil {
				if errors.Is(err, platform.ErrNotFound) {
					switch {
					case w.goneIsDone:
						return platform.WaitDone, "deleted", nil
					case w.goneFails:
						return platform.KeepWaiting, "", err
					}
					return platform.KeepWaiting, "not visible yet", tol.check(nil)
				}
				return platform.KeepWaiting, "", tol.check(err)
			}
			tol.check(nil)
			last = db
			st := awssdk.ToString(db.DBInstanceStatus)
			if w.done != nil && w.done(db) {
				return platform.WaitDone, st, nil
			}
			if fatal(st) {
				return platform.WaitFailed, st, nil
			}
			return platform.KeepWaiting, st, nil
		})
	return last, err
}

// statusIs returns a done func for one status.
func statusIs(status string) func(rdstypes.DBInstance) bool {
	return func(db rdstypes.DBInstance) bool { return awssdk.ToString(db.DBInstanceStatus) == status }
}

// classApplied is the done func of a class change: the new class is in
// place, nothing is pending and the instance is available again. Right
// after ModifyDBInstance the instance still reads available with the old
// class (and the new one pending), so the class alone is not enough, and
// neither is the status.
func classApplied(class string) func(rdstypes.DBInstance) bool {
	return func(db rdstypes.DBInstance) bool {
		pending := ""
		if db.PendingModifiedValues != nil {
			pending = awssdk.ToString(db.PendingModifiedValues.DBInstanceClass)
		}
		return awssdk.ToString(db.DBInstanceClass) == class && pending == "" && awssdk.ToString(db.DBInstanceStatus) == dbAvailable
	}
}
