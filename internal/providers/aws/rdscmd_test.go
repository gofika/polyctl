package aws

import (
	"context"
	"errors"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

func isUsage(err error) bool { return errors.Is(err, app.ErrUsage) }

// dbRows returns the inventory rows of the db_instance set of a profile.
func (h *awsHarness) dbRows(profile string) []inventory.Resource {
	h.t.Helper()
	db, err := h.rt.DB()
	if err != nil {
		h.t.Fatal(err)
	}
	rows, err := db.List(context.Background(), inventory.Query{Platform: platform.AWS, Profile: profile, Type: platform.ResDBInstance})
	if err != nil {
		h.t.Fatal(err)
	}
	return rows
}

func viewIDs(rows []dbView) string {
	var out []string
	for _, r := range rows {
		out = append(out, r.ID+"@"+r.Region)
	}
	return strings.Join(out, ",")
}

func TestRDSList(t *testing.T) {
	h, _ := newRDSHarness(t, app.Flags{}, nil)
	h.ec2.find.regions = []string{"ap-east-1", "eu-west-1"}
	h.rds().pageSize = 1 // every instance on a page of its own
	h.addDB("ap-east-1", "db-a", dbAvailable)
	h.addDB("ap-east-1", "db-b", dbStopped, func(db *rdstypes.DBInstance) { db.DBInstanceClass = awssdk.String("db.m5.large") })
	h.addDB("ap-east-1", "web", dbAvailable)
	h.addDB("eu-west-1", "db-c", dbAvailable)

	if err := h.run("rds", "instance", "list"); err != nil {
		t.Fatalf("list: %v\n%s", err, h.stderr.String())
	}
	var rows []dbView
	h.jsonOut(&rows)
	if got := viewIDs(rows); got != "db-a@ap-east-1,db-b@ap-east-1,web@ap-east-1" {
		t.Errorf("profile region = %s", got)
	}
	if r := rows[0]; r.Profile != "lab" || r.Endpoint != "db-a.abc123.ap-east-1.rds.amazonaws.com" || r.Port != 3306 || r.EngineVersion != "8.0.36" ||
		r.AllocatedStorageGB != 20 || r.SecurityGroups == nil {
		t.Errorf("row = %+v", r)
	}
	// Four pages in ap-east-1 (three instances, one per page) were read.
	if n := h.rds().count("DescribeDBInstances"); n < 4 {
		t.Errorf("pages read = %d", n)
	}
	if n := len(h.dbRows("lab")); n != 4 {
		t.Errorf("inventory rows = %d", n)
	}
	calls := len(h.rds().calls)
	for args, want := range map[string]string{
		"--region all":                  "db-a@ap-east-1,db-b@ap-east-1,db-c@eu-west-1,web@ap-east-1",
		"--region eu-west-1":            "db-c@eu-west-1",
		"--state stopped":               "db-b@ap-east-1",
		"--class db.m5.large":           "db-b@ap-east-1",
		"--name db-*":                   "db-a@ap-east-1,db-b@ap-east-1",
		"--name db-* --state stopped":   "db-b@ap-east-1",
		"--name nothing-* --region all": "",
	} {
		if err := h.run(append([]string{"rds", "instance", "list"}, strings.Fields(args)...)...); err != nil {
			t.Fatalf("list %s: %v", args, err)
		}
		var rows []dbView
		h.jsonOut(&rows)
		if got := viewIDs(rows); got != want {
			t.Errorf("list %s = %q, want %q", args, got, want)
		}
	}
	// The filters read the inventory, not AWS.
	if len(h.rds().calls) != calls {
		t.Errorf("filters called AWS: %v", h.rds().calls[calls:])
	}
	// No match: [], a note, exit code 0.
	if err := h.run("rds", "instance", "list", "--state", "creating"); err != nil || strings.TrimSpace(h.stdout.String()) != "[]" ||
		!strings.Contains(h.stderr.String(), "no RDS instances") {
		t.Errorf("empty = %v %q %q", err, h.stdout.String(), h.stderr.String())
	}
	if err := h.run("rds", "instance", "list", "--name", "["); !isUsage(err) {
		t.Errorf("bad pattern = %v", err)
	}
}

func TestRDSListOfflineNeverSynced(t *testing.T) {
	h, _ := newRDSHarness(t, app.Flags{Offline: true}, nil)
	if err := h.run("rds", "instance", "list"); !errors.Is(err, app.ErrOffline) || errors.Is(err, platform.ErrNotFound) || errors.Is(err, inventory.ErrNeverSynced) {
		t.Errorf("offline = %v", err)
	}
	if len(h.rds().calls) != 0 {
		t.Errorf("offline called AWS: %v", h.rds().calls)
	}
}

func TestRDSGetRouting(t *testing.T) {
	h, _ := newRDSHarness(t, app.Flags{}, nil)
	h.addDB("ap-east-1", "db-prod-01", dbAvailable, func(db *rdstypes.DBInstance) {
		db.TagList = []rdstypes.Tag{{Key: awssdk.String("Name"), Value: awssdk.String("db-prod-01")}}
		db.DBParameterGroups = []rdstypes.DBParameterGroupStatus{{DBParameterGroupName: awssdk.String("default.mysql8.0")}}
		db.BackupRetentionPeriod = awssdk.Int32(7)
	})

	// Unknown to the inventory: one sync, then a live read.
	if err := h.run("rds", "instance", "get", "db-prod-01"); err != nil {
		t.Fatalf("get: %v\n%s", err, h.stderr.String())
	}
	var d dbDetail
	h.jsonOut(&d)
	if d.ID != "db-prod-01" || d.Profile != "lab" || d.Region != "ap-east-1" || d.ParameterGroup != "default.mysql8.0" || d.BackupRetention != 7 ||
		d.Tags["Name"] != "db-prod-01" || !strings.Contains(h.stderr.String(), "syncing the RDS instances") {
		t.Errorf("get = %+v\n%s", d, h.stderr.String())
	}
	// By endpoint, in any case and with the trailing dot.
	if err := h.run("rds", "instance", "get", "DB-PROD-01.abc123.ap-east-1.rds.amazonaws.com."); err != nil {
		t.Fatalf("get by endpoint: %v", err)
	}
	h.jsonOut(&d)
	if d.ID != "db-prod-01" {
		t.Errorf("by endpoint = %+v", d)
	}
	if err := h.run("rds", "instance", "get", "nope.abc123.ap-east-1.rds.amazonaws.com"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("unknown endpoint = %v", err)
	}
	// Not anywhere: not found.
	if err := h.run("rds", "instance", "get", "db-missing"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing = %v", err)
	}
	// --offline shows the inventory's copy without asking AWS.
	h.rt.Flags.Offline = true
	before := len(h.rds().calls)
	if err := h.run("rds", "instance", "get", "db-prod-01"); err != nil {
		t.Fatalf("offline get: %v", err)
	}
	h.jsonOut(&d)
	if d.ID != "db-prod-01" || len(h.rds().calls) != before {
		t.Errorf("offline get = %+v, calls %v", d, h.rds().calls[before:])
	}
	h.rt.Flags.Offline = false

	// The instance went away: the row is dropped, the account synced again,
	// and the answer is not found.
	h.rds().dbs[0].gone = true
	if err := h.run("rds", "instance", "get", "db-prod-01"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("gone = %v", err)
	}
	if rows := h.dbRows("lab"); len(rows) != 0 {
		t.Errorf("rows left = %+v", rows)
	}
}

func TestRDSGetMovedInstanceIsFoundAfterResync(t *testing.T) {
	h, _ := newRDSHarness(t, app.Flags{}, nil)
	h.ec2.find.regions = []string{"ap-east-1", "eu-west-1"}
	old := h.addDB("ap-east-1", "db-x", dbAvailable)
	if err := h.run("rds", "instance", "list"); err != nil {
		t.Fatal(err)
	}
	// Deleted in one region and created in another since the last sync.
	old.gone = true
	h.addDB("eu-west-1", "db-x", dbAvailable)
	if err := h.run("rds", "instance", "get", "db-x"); err != nil {
		t.Fatalf("moved: %v\n%s", err, h.stderr.String())
	}
	var d dbDetail
	h.jsonOut(&d)
	if d.Region != "eu-west-1" {
		t.Errorf("moved = %+v", d)
	}
}

func TestRDSGetAmbiguousAcrossProfiles(t *testing.T) {
	h, _ := newRDSHarness(t, app.Flags{}, nil)
	h.addProfile(t)
	h.ec2.find.regions = []string{"ap-east-1"}
	h.addDB("ap-east-1", "shared", dbAvailable)
	var amb *app.AmbiguousError
	if err := h.run("rds", "instance", "get", "shared"); !errors.As(err, &amb) || len(amb.Candidates) != 2 {
		t.Fatalf("ambiguous = %v", err)
	}
	// --profile chooses.
	h.rt.Flags.Profile = "prod"
	if err := h.run("rds", "instance", "get", "shared"); err != nil {
		t.Fatalf("with --profile: %v", err)
	}
	var d dbDetail
	h.jsonOut(&d)
	if d.Profile != "prod" {
		t.Errorf("profile = %+v", d)
	}
	// --region asks the profile's account there directly.
	if err := h.run("rds", "instance", "get", "shared", "--region", "ap-east-1"); err != nil {
		t.Fatalf("with --region: %v", err)
	}
}

// ---------------------------------------------------------------- create

func createDefaults() map[string]any {
	return map[string]any{
		"tags": map[string]any{"team": "ops"},
		"rds": map[string]any{"default_class": "db.t3.micro", "subnet_group": "grp", "security_group_ids": []any{"sg-0123"},
			"default_tags": map[string]any{"backup": "daily"}},
	}
}

func setupVersions(h *awsHarness) {
	h.rds().versions = versions("5.7.44-rds.20260902", "8.0.9", "8.0.36", "8.0.46", "8.0.46-rds.20260908", "8.4.13", "9.7.4")
}

func TestRDSCreate(t *testing.T) {
	h, clk := newRDSHarness(t, app.Flags{}, createDefaults())
	setupVersions(h)
	h.rds().createHidden = 1 // not visible at once
	t.Setenv("RDS_PW", "s3cret-pass")

	err := h.run("rds", "instance", "create", "db-test-01", "--size", "50", "--az", "ap-east-1a", "--password-env", "RDS_PW", "--tag", "backup=weekly", "--tag", "env=test")
	if err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	var res createResult
	h.jsonOut(&res)
	if res.ID != "db-test-01" || res.Endpoint != "db-test-01.abc123.ap-east-1.rds.amazonaws.com" || res.Port != 3306 || res.EngineVersion != "8.0.46" || res.Status != dbAvailable {
		t.Errorf("result = %+v", res)
	}
	r := h.rds()
	if w := r.writes(); len(w) != 1 || len(r.creates) != 1 {
		t.Fatalf("writes = %v", w)
	}
	in := r.creates[0]
	tags := map[string]string{}
	for _, tg := range in.Tags {
		tags[awssdk.ToString(tg.Key)] = awssdk.ToString(tg.Value)
	}
	if awssdk.ToString(in.DBInstanceIdentifier) != "db-test-01" || awssdk.ToString(in.DBInstanceClass) != "db.t3.micro" || awssdk.ToString(in.Engine) != "mysql" ||
		awssdk.ToString(in.EngineVersion) != "8.0.46" || awssdk.ToString(in.MasterUsername) != "admin" || awssdk.ToString(in.MasterUserPassword) != "s3cret-pass" ||
		awssdk.ToInt32(in.AllocatedStorage) != 50 || awssdk.ToInt32(in.MaxAllocatedStorage) != 1000 || awssdk.ToString(in.StorageType) != "gp3" ||
		awssdk.ToString(in.DBSubnetGroupName) != "grp" || len(in.VpcSecurityGroupIds) != 1 || in.VpcSecurityGroupIds[0] != "sg-0123" || in.DBParameterGroupName != nil ||
		awssdk.ToString(in.AvailabilityZone) != "ap-east-1a" || awssdk.ToBool(in.PubliclyAccessible) || awssdk.ToInt32(in.BackupRetentionPeriod) != 7 ||
		awssdk.ToString(in.PreferredBackupWindow) != "03:00-04:00" || awssdk.ToString(in.PreferredMaintenanceWindow) != "sun:04:00-sun:05:00" {
		t.Errorf("input = %+v", in)
	}
	if len(tags) != 4 || tags["Name"] != "db-test-01" || tags["team"] != "ops" || tags["backup"] != "weekly" || tags["env"] != "test" {
		t.Errorf("tags = %v", tags)
	}
	// 30 second polls.
	if len(clk.slept) == 0 || clk.slept[0] != dbCreatePoll {
		t.Errorf("slept = %v", clk.slept)
	}
	if !strings.Contains(h.stderr.String(), "using MySQL version 8.0.46") {
		t.Errorf("stderr = %s", h.stderr.String())
	}
	// The password is nowhere but in the request.
	rows := h.dbRows("lab")
	for _, s := range []string{h.stdout.String(), h.stderr.String()} {
		if strings.Contains(s, "s3cret-pass") {
			t.Error("password printed")
		}
	}
	if len(rows) != 1 || strings.Contains(string(rows[0].Data), "s3cret-pass") {
		t.Errorf("inventory = %+v", rows)
	}
	var d dbInstance
	if err := rows[0].Decode(&d); err != nil || d.Status != dbAvailable || d.Endpoint == "" {
		t.Errorf("stored = %+v %v", d, err)
	}

	// A second create of the same identifier: exit code 1, nothing sent.
	err = h.run("rds", "instance", "create", "db-test-01", "--size", "50", "--az", "ap-east-1a", "--password-env", "RDS_PW")
	if err == nil || !strings.Contains(err.Error(), "already exists") || isUsage(err) || errors.Is(err, platform.ErrNotFound) || len(r.creates) != 1 {
		t.Errorf("exists = %v", err)
	}

	// The table form prints the endpoint as shell variables.
	h.rt.Flags.Output = "table"
	_ = h.rt.Init()
	if err := h.run("rds", "instance", "create", "db-test-02", "--size", "20", "--az", "ap-east-1a", "--password-env", "RDS_PW", "--engine-version", "8.0.36"); err != nil {
		t.Fatal(err)
	}
	if out := h.stdout.String(); out != "RDS_ENDPOINT=db-test-02.abc123.ap-east-1.rds.amazonaws.com\nRDS_PORT=3306\n" {
		t.Errorf("table = %q", out)
	}
	// A given version is sent as it is, without asking for the versions.
	if r.count("DescribeDBEngineVersions(8.0)") != 2 || awssdk.ToString(r.creates[1].EngineVersion) != "8.0.36" {
		t.Errorf("explicit version: %v", r.calls)
	}
}

func TestRDSCreateFlags(t *testing.T) {
	h, _ := newRDSHarness(t, app.Flags{}, nil)
	setupVersions(h)
	t.Setenv("RDS_PW", "s3cret-pass")
	base := []string{"rds", "instance", "create", "db-x", "--size", "20", "--az", "ap-east-1a"}
	usage := [][]string{
		{}, // no password
		{"--password-env", "RDS_PW", "--password-stdin"},
		{"--password-env", "UNSET_RDS_PW_VAR"},
		{"--password-env", "RDS_PW", "--max-size", "10"},
		{"--password-env", "RDS_PW", "--max-size", "20"},
		{"--password-env", "RDS_PW", "--major", "8"},
		{"--password-env", "RDS_PW", "--major", "8.0.4"},
		{"--password-env", "RDS_PW", "--storage-type", "sc1"},
		{"--password-env", "RDS_PW", "--storage-type", "io1"}, // 20 GB < 100
		{"--password-env", "RDS_PW", "--major", "8.4", "--engine-version", "8.0.36"},
	}
	for _, extra := range usage {
		if err := h.run(append(append([]string{}, base...), extra...)...); !isUsage(err) {
			t.Errorf("%v = %v, want a usage error", extra, err)
		}
	}
	if err := h.run("rds", "instance", "create", "db_x", "--size", "20", "--az", "ap-east-1a", "--password-env", "RDS_PW"); !isUsage(err) {
		t.Errorf("bad identifier = %v", err)
	}
	if err := h.run("rds", "instance", "create", "db-x", "--az", "ap-east-1a", "--password-env", "RDS_PW"); !isUsage(err) {
		t.Errorf("no size = %v", err)
	}
	if err := h.run("rds", "instance", "create", "db-x", "--size", "20", "--password-env", "RDS_PW"); !isUsage(err) {
		t.Errorf("no az = %v", err)
	}
	if err := h.run(append(append([]string{}, base...), "--password-env", "RDS_PW", "--engine", "postgres")...); !errors.Is(err, platform.ErrNotSupported) {
		t.Errorf("postgres = %v", err)
	}
	t.Setenv("SHORT_PW", "short")
	if err := h.run(append(append([]string{}, base...), "--password-env", "SHORT_PW")...); !isUsage(err) {
		t.Errorf("short password = %v", err)
	}
	if len(h.rds().calls) != 0 {
		t.Errorf("usage errors called AWS: %v", h.rds().calls)
	}
	// The password from stdin (one line of a pipe); --max-size 0 turns
	// autoscaling off; --major picks the family.
	h.rt.Stdin = strings.NewReader("piped-secret\n")
	if err := h.run(append(append([]string{}, base...), "--password-stdin", "--max-size", "0", "--major", "8.4", "--wait=false")...); err != nil {
		t.Fatalf("stdin: %v", err)
	}
	in := h.rds().creates[0]
	if awssdk.ToString(in.MasterUserPassword) != "piped-secret" || in.MaxAllocatedStorage != nil || awssdk.ToString(in.EngineVersion) != "8.4.13" ||
		awssdk.ToString(in.DBInstanceClass) != rdsDefaultClass || in.DBSubnetGroupName != nil || in.VpcSecurityGroupIds != nil {
		t.Errorf("input = %+v", in)
	}
	var res createResult
	h.jsonOut(&res)
	if res.Status != dbCreating || res.Endpoint != "" || strings.Contains(h.stdout.String(), "endpoint") {
		t.Errorf("no wait = %+v %s", res, h.stdout.String())
	}
	if !strings.Contains(h.stderr.String(), "default VPC") {
		t.Errorf("no default VPC note: %s", h.stderr.String())
	}
	h.rt.Stdin = strings.NewReader("")
	if err := h.run(append(append([]string{}, base...), "--password-stdin")...); !isUsage(err) {
		t.Errorf("empty stdin = %v", err)
	}
}

func TestRDSCreateDryRun(t *testing.T) {
	h, _ := newRDSHarness(t, app.Flags{DryRun: true}, nil)
	setupVersions(h)
	t.Setenv("RDS_PW", "s3cret-pass")
	if err := h.run("rds", "instance", "create", "db-x", "--size", "50", "--az", "ap-east-1a", "--password-env", "RDS_PW"); err != nil {
		t.Fatal(err)
	}
	rep := h.report()
	if !rep.DryRun || len(rep.Changes) != 2 || rep.Changes[0].Action != platform.WouldCreate ||
		rep.Changes[0].Detail != "mysql 8.0.46 db.m5.large 50GB gp3 az=ap-east-1a" || rep.Changes[0].Attrs["endpoint"] != platform.Pending ||
		rep.Changes[1].Resource != "db-instance/db-x/wait" || rep.Changes[1].Action != platform.Skipped {
		t.Errorf("report = %+v", rep)
	}
	if w := h.rds().writes(); len(w) != 0 {
		t.Errorf("dry run wrote %v", w)
	}
	// An existing identifier is the same error as for real.
	h.addDB("ap-east-1", "db-y", dbAvailable)
	if err := h.run("rds", "instance", "create", "db-y", "--size", "50", "--az", "ap-east-1a", "--password-env", "RDS_PW"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("dry run exists = %v", err)
	}
}

func TestRDSCreateWaits(t *testing.T) {
	h, _ := newRDSHarness(t, app.Flags{}, nil)
	setupVersions(h)
	t.Setenv("RDS_PW", "s3cret-pass")
	create := func(id string, extra ...string) error {
		return h.run(append([]string{"rds", "instance", "create", id, "--size", "20", "--az", "ap-east-1a", "--password-env", "RDS_PW"}, extra...)...)
	}
	// A failed instance ends the wait at once and is kept.
	h.rds().createSteps = []string{dbCreating, "failed"}
	if err := create("db-f"); err == nil || !strings.Contains(err.Error(), "entered status failed") || !strings.Contains(err.Error(), "kept") {
		t.Errorf("failed = %v", err)
	}
	// A timeout reports the last status and keeps the instance.
	h.rds().createSteps = []string{dbCreating, dbCreating, dbCreating, dbCreating, dbCreating, dbCreating}
	err := create("db-t", "--timeout", "1m")
	var te *platform.WaitTimeoutError
	if !errors.As(err, &te) || te.LastStatus != dbCreating {
		t.Errorf("timeout = %v", err)
	}
	if n := h.rds().count("DeleteDBInstance"); n != 0 {
		t.Error("deleted the half-made instance")
	}
}

func TestRDSCreateErrors(t *testing.T) {
	h, _ := newRDSHarness(t, app.Flags{}, nil)
	setupVersions(h)
	t.Setenv("RDS_PW", "s3cret-pass")
	r := h.rds()
	vpcErr := &rdstypes.InvalidVPCNetworkStateFault{Message: awssdk.String("no subnets with available IP addresses in ap-east-1c; choose from ap-east-1a, ap-east-1b")}
	create := func(az string, extra ...string) error {
		return h.run(append([]string{"rds", "instance", "create", "db-e", "--size", "20", "--az", az, "--password-env", "RDS_PW", "--class", "db.t3.micro"}, extra...)...)
	}
	cases := []struct {
		name, az, want string
		setup          func()
	}{
		{"group missing", "ap-east-1c", "check that the subnet group grp is set up", func() { r.subnetZones = nil }},
		{"zone not in group", "ap-east-1c", "not in the subnet group grp; use one of: ap-east-1a, ap-east-1b", func() {
			r.subnetZones = map[string][]string{"grp": {"ap-east-1b", "ap-east-1a", "ap-east-1a"}}
		}},
		{"class not offered", "ap-east-1a", "is not offered in ap-east-1a", func() {
			r.orderable = []rdstypes.OrderableDBInstanceOption{{DBInstanceClass: awssdk.String("db.t3.micro"), StorageType: awssdk.String("gp2"),
				AvailabilityZones: []rdstypes.AvailabilityZone{{Name: awssdk.String("ap-east-1a")}}}}
		}},
		{"capacity", "ap-east-1a", "short of capacity", func() {
			r.orderable = append(r.orderable, rdstypes.OrderableDBInstanceOption{DBInstanceClass: awssdk.String("db.t3.micro"), StorageType: awssdk.String("gp3"),
				AvailabilityZones: []rdstypes.AvailabilityZone{{Name: awssdk.String("ap-east-1a")}}})
		}},
	}
	for _, c := range cases {
		c.setup()
		r.errOnce = map[string][]error{"CreateDBInstance": {vpcErr}}
		err := create(c.az, "--subnet-group", "grp")
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "InvalidVPCNetworkStateFault") || !strings.Contains(err.Error(), "choose from") {
			t.Errorf("%s = %v", c.name, err)
		}
	}
	// A diagnosis that fails itself keeps the AWS error.
	r.errs = map[string]error{"DescribeOrderableDBInstanceOptions": &fakeAPIError{"Throttling", "slow down"}}
	r.errOnce = map[string][]error{"CreateDBInstance": {vpcErr}}
	if err := create("ap-east-1a", "--subnet-group", "grp"); err == nil || !strings.Contains(err.Error(), "InvalidVPCNetworkStateFault") {
		t.Errorf("failed diagnosis = %v", err)
	}
	r.errs = nil
	for code, want := range map[error]string{
		&rdstypes.InsufficientDBInstanceCapacityFault{Message: awssdk.String("none left")}: "has no capacity",
		&fakeAPIError{"InvalidParameterValue", "Invalid DB Instance class"}:                "check the parameter values",
		&fakeAPIError{"InvalidParameterCombination", "no"}:                                 "can be combined",
	} {
		r.errOnce = map[string][]error{"CreateDBInstance": {code}}
		err := create("ap-east-1a")
		if err == nil || !strings.Contains(err.Error(), want) || isUsage(err) || errors.Is(err, platform.ErrNotFound) {
			t.Errorf("%v = %v", code, err)
		}
	}
	r.errOnce = map[string][]error{"CreateDBInstance": {&fakeAPIError{"AccessDenied", "no"}}}
	if err := create("ap-east-1a"); !errors.Is(err, platform.ErrUnauthorized) || !strings.Contains(err.Error(), "rds:CreateDBInstance") {
		t.Errorf("denied = %v", err)
	}
}

// ------------------------------------------------------------ start, stop

func TestRDSStartStop(t *testing.T) {
	h, clk := newRDSHarness(t, app.Flags{}, nil)
	h.addDB("ap-east-1", "db-a", dbAvailable)
	r := h.rds()

	if err := h.run("rds", "instance", "stop", "db-a", "--wait"); err != nil {
		t.Fatalf("stop: %v", err)
	}
	rep := h.report()
	if c := rep.Changes[0]; c.Resource != "db-instance/db-a" || c.Action != platform.Updated || c.Detail != "stopped (was available)" {
		t.Errorf("stop = %+v", rep)
	}
	if r.count("StopDBInstance") != 1 || len(clk.slept) == 0 || clk.slept[0] != dbPowerPoll {
		t.Errorf("calls %v slept %v", r.calls, clk.slept)
	}
	// Already stopped: unchanged, nothing sent.
	if err := h.run("rds", "instance", "stop", "db-a"); err != nil {
		t.Fatal(err)
	}
	if c := h.report().Changes[0]; c.Action != platform.Unchanged || r.count("StopDBInstance") != 1 {
		t.Errorf("stopped = %+v", c)
	}
	// Start without --wait: the status AWS answers.
	if err := h.run("rds", "instance", "start", "db-a"); err != nil {
		t.Fatal(err)
	}
	if c := h.report().Changes[0]; c.Action != platform.Updated || c.Detail != "starting (was stopped)" {
		t.Errorf("start = %+v", c)
	}
	// Starting: unchanged; --wait waits for available.
	if err := h.run("rds", "instance", "start", "db-a", "--wait"); err != nil {
		t.Fatal(err)
	}
	if c := h.report().Changes[0]; c.Action != platform.Unchanged || c.Detail != "already starting; now available" || r.count("StartDBInstance") != 1 {
		t.Errorf("starting = %+v", c)
	}
	// Available: unchanged.
	if err := h.run("rds", "instance", "start", "db-a"); err != nil {
		t.Fatal(err)
	}
	if c := h.report().Changes[0]; c.Action != platform.Unchanged || c.Detail != "already running" {
		t.Errorf("available = %+v", c)
	}
	// Stopping is unchanged for stop.
	h.addDB("ap-east-1", "db-s", dbStopping)
	if err := h.run("rds", "instance", "stop", "db-s"); err != nil {
		t.Fatal(err)
	}
	if c := h.report().Changes[0]; c.Action != platform.Unchanged || c.Detail != "already stopping" {
		t.Errorf("stopping = %+v", c)
	}
	// Another status is exit code 1.
	h.addDB("ap-east-1", "db-m", dbModifying)
	for _, verb := range []string{"start", "stop"} {
		if err := h.run("rds", "instance", verb, "db-m"); err == nil || !strings.Contains(err.Error(), "is modifying") || isUsage(err) {
			t.Errorf("%s modifying = %v", verb, err)
		}
	}
	// A status that changed meanwhile: the AWS error, with its code.
	h.addDB("ap-east-1", "db-r", dbAvailable)
	r.errOnce = map[string][]error{"StopDBInstance": {invalidState("Instance db-r is not in available state.")}}
	if err := h.run("rds", "instance", "stop", "db-r"); err == nil || !strings.Contains(err.Error(), "not in available state") || !strings.Contains(err.Error(), "retry") {
		t.Errorf("invalid state = %v", err)
	}
	// Aurora members: exit code 7.
	h.addDB("ap-east-1", "db-aurora", dbAvailable, func(db *rdstypes.DBInstance) { db.DBClusterIdentifier = awssdk.String("cl-1") })
	if err := h.run("rds", "instance", "stop", "db-aurora"); !errors.Is(err, platform.ErrNotSupported) {
		t.Errorf("aurora = %v", err)
	}
	if err := h.run("rds", "instance", "stop", "db-missing"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing = %v", err)
	}
	// The inventory follows.
	var d dbInstance
	for _, row := range h.dbRows("lab") {
		if row.Name == "db-a" {
			_ = row.Decode(&d)
		}
	}
	if d.Status != dbAvailable {
		t.Errorf("stored status = %q", d.Status)
	}
}

func TestRDSStartStopDryRun(t *testing.T) {
	h, _ := newRDSHarness(t, app.Flags{DryRun: true}, nil)
	h.addDB("ap-east-1", "db-a", dbStopped)
	if err := h.run("rds", "instance", "start", "db-a", "--wait"); err != nil {
		t.Fatal(err)
	}
	rep := h.report()
	if !rep.DryRun || rep.Changes[0].Action != platform.WouldUpdate || rep.Changes[0].Detail != "stopped -> starting" {
		t.Errorf("dry run = %+v", rep)
	}
	if err := h.run("rds", "instance", "stop", "db-a"); err != nil {
		t.Fatal(err)
	}
	if c := h.report().Changes[0]; c.Action != platform.Unchanged {
		t.Errorf("dry run stopped = %+v", c)
	}
	if w := h.rds().writes(); len(w) != 0 {
		t.Errorf("dry run wrote %v", w)
	}
}

// ---------------------------------------------------------------- resize

func TestRDSResize(t *testing.T) {
	h, _ := newRDSHarness(t, app.Flags{}, nil)
	h.addDB("ap-east-1", "db-a", dbAvailable)
	r := h.rds()
	r.modifyLag = 2 // reads still show the old class as available

	if err := h.run("rds", "instance", "resize", "db-a", "--class", "db.t3.micro"); err != nil {
		t.Fatal(err)
	}
	if c := h.report().Changes[0]; c.Action != platform.Unchanged || len(r.writes()) != 0 {
		t.Errorf("same class = %+v %v", c, r.writes())
	}
	if err := h.run("rds", "instance", "resize", "db-a", "--class", "db.t3.small"); err != nil {
		t.Fatalf("resize: %v\n%s", err, h.stderr.String())
	}
	if c := h.report().Changes[0]; c.Action != platform.Updated || c.Detail != "db.t3.micro -> db.t3.small" {
		t.Errorf("resize = %+v", c)
	}
	if len(r.modifies) != 1 || !awssdk.ToBool(r.modifies[0].ApplyImmediately) || awssdk.ToString(r.modifies[0].DBInstanceClass) != "db.t3.small" {
		t.Errorf("modify = %+v", r.modifies)
	}
	// The wait went past the stale reads to the end of the change.
	db := r.dbs[0].db
	if awssdk.ToString(db.DBInstanceStatus) != dbAvailable || awssdk.ToString(db.DBInstanceClass) != "db.t3.small" || len(r.dbs[0].steps) != 0 {
		t.Errorf("ended early: %+v, %d steps left", db, len(r.dbs[0].steps))
	}
	if !strings.Contains(h.stderr.String(), "downtime") || !strings.Contains(h.stderr.String(), "done in") {
		t.Errorf("stderr = %s", h.stderr.String())
	}
	// --no-wait returns after the request.
	if err := h.run("rds", "instance", "resize", "db-a", "--class", "db.m5.large", "--no-wait"); err != nil {
		t.Fatal(err)
	}
	if c := h.report().Changes[0]; c.Detail != "db.t3.small -> db.m5.large (modifying)" {
		t.Errorf("no wait = %+v", c)
	}
	// Stopped: exit code 1, nothing sent.
	h.addDB("ap-east-1", "db-s", dbStopped)
	n := len(r.modifies)
	if err := h.run("rds", "instance", "resize", "db-s", "--class", "db.t3.small"); err == nil || !strings.Contains(err.Error(), "start it first") || len(r.modifies) != n {
		t.Errorf("stopped = %v", err)
	}
	if err := h.run("rds", "instance", "resize", "db-s"); !isUsage(err) {
		t.Errorf("no class = %v", err)
	}
}

func TestRDSResizeWaitsForAvailableFirst(t *testing.T) {
	h, _ := newRDSHarness(t, app.Flags{}, nil)
	d := h.addDB("ap-east-1", "db-b", "backing-up")
	// The resolve read, then two waits, then available.
	d.steps = []func(*rdstypes.DBInstance){status("backing-up"), status("backing-up"), status("backing-up"), status(dbAvailable)}
	if err := h.run("rds", "instance", "resize", "db-b", "--class", "db.t3.small"); err != nil {
		t.Fatalf("resize: %v\n%s", err, h.stderr.String())
	}
	if c := h.report().Changes[0]; c.Action != platform.Updated {
		t.Errorf("resize = %+v", c)
	}
	// A timeout while waiting reports the last status.
	h.addDB("ap-east-1", "db-c", dbModifying)
	var te *platform.WaitTimeoutError
	if err := h.run("rds", "instance", "resize", "db-c", "--class", "db.t3.small", "--timeout", "1m"); !errors.As(err, &te) || te.LastStatus != dbModifying {
		t.Errorf("timeout = %v", err)
	}
	// An instance that disappears while waited for is not found.
	g := h.addDB("ap-east-1", "db-g", dbModifying)
	g.goneAfter = 2
	if err := h.run("rds", "instance", "resize", "db-g", "--class", "db.t3.small"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("gone = %v", err)
	}
}

func TestRDSResizeDryRun(t *testing.T) {
	h, _ := newRDSHarness(t, app.Flags{DryRun: true}, nil)
	h.addDB("ap-east-1", "db-a", dbAvailable)
	if err := h.run("rds", "instance", "resize", "db-a", "--class", "db.m5.xlarge"); err != nil {
		t.Fatal(err)
	}
	if c := h.report().Changes[0]; c.Action != platform.WouldUpdate || c.Detail != "db.t3.micro -> db.m5.xlarge (apply immediately)" || len(h.rds().writes()) != 0 {
		t.Errorf("dry run = %+v", c)
	}
}

// ---------------------------------------------------------------- delete

func TestRDSDelete(t *testing.T) {
	h, _ := newRDSHarness(t, app.Flags{Yes: true}, nil)
	h.addDB("ap-east-1", "db-a", dbAvailable)
	r := h.rds()
	if err := h.run("rds", "instance", "delete", "db-a"); err != nil {
		t.Fatalf("delete: %v\n%s", err, h.stderr.String())
	}
	rep := h.report()
	if a := actions(rep); a["db-instance/db-a deleted"] != 1 || a["db-instance/db-a/final-snapshot created"] != 1 {
		t.Errorf("report = %+v", rep)
	}
	in := r.deletes[0]
	if awssdk.ToBool(in.SkipFinalSnapshot) || awssdk.ToString(in.FinalDBSnapshotIdentifier) != "db-a-final-snapshot" || in.DeleteAutomatedBackups != nil {
		t.Errorf("input = %+v", in)
	}
	if len(h.dbRows("lab")) != 0 {
		t.Error("inventory row kept")
	}
	// The same name again: the snapshot exists, exit code 1 before anything.
	h.addDB("ap-east-1", "db-a", dbAvailable, func(db *rdstypes.DBInstance) { db.DeletionProtection = awssdk.Bool(true) })
	n := len(r.writes())
	if err := h.run("rds", "instance", "delete", "db-a"); err == nil || !strings.Contains(err.Error(), "exists already") || len(r.writes()) != n {
		t.Errorf("snapshot exists = %v, writes %v", err, r.writes()[n:])
	}
	// Protected: protection off first, then the delete.
	if err := h.run("rds", "instance", "delete", "db-a", "--final-snapshot", "db-a-final-2"); err != nil {
		t.Fatal(err)
	}
	if w := r.writes()[n:]; len(w) != 2 || !strings.HasSuffix(w[0], "ModifyDBInstance") || !strings.HasSuffix(w[1], "DeleteDBInstance") {
		t.Errorf("order = %v", w)
	}
	if m := r.modifies[len(r.modifies)-1]; m.DeletionProtection == nil || awssdk.ToBool(m.DeletionProtection) || !awssdk.ToBool(m.ApplyImmediately) {
		t.Errorf("modify = %+v", m)
	}
	if a := actions(h.report()); a["db-instance/db-a updated"] != 1 || a["db-instance/db-a deleted"] != 1 {
		t.Errorf("protected report = %v", a)
	}
	// --keep-protection: exit code 1, nothing sent.
	h.addDB("ap-east-1", "db-p", dbAvailable, func(db *rdstypes.DBInstance) { db.DeletionProtection = awssdk.Bool(true) })
	n = len(r.writes())
	if err := h.run("rds", "instance", "delete", "db-p", "--keep-protection"); err == nil || !strings.Contains(err.Error(), "deletion protection") || len(r.writes()) != n {
		t.Errorf("keep protection = %v", err)
	}
	// --skip-final-snapshot sends no snapshot name; --wait waits until gone.
	r.deleteReads = 2
	if err := h.run("rds", "instance", "delete", "db-p", "--skip-final-snapshot", "--wait"); err != nil {
		t.Fatal(err)
	}
	in = r.deletes[len(r.deletes)-1]
	if !awssdk.ToBool(in.SkipFinalSnapshot) || in.FinalDBSnapshotIdentifier != nil {
		t.Errorf("skip input = %+v", in)
	}
	rep = h.report()
	if a := actions(rep); a["db-instance/db-p deleted"] != 1 || a["db-instance/db-p/final-snapshot created"] != 0 {
		t.Errorf("skip report = %+v", rep)
	}
	if !strings.Contains(h.stderr.String(), "no final snapshot") {
		t.Errorf("no warning: %s", h.stderr.String())
	}
	// Being deleted: unchanged.
	h.addDB("ap-east-1", "db-d", dbDeleting)
	n = len(r.writes())
	if err := h.run("rds", "instance", "delete", "db-d"); err != nil {
		t.Fatal(err)
	}
	if c := h.report().Changes[0]; c.Action != platform.Unchanged || len(r.writes()) != n {
		t.Errorf("deleting = %+v", c)
	}
	if err := h.run("rds", "instance", "delete", "db-d", "--skip-final-snapshot", "--final-snapshot", "x"); !isUsage(err) {
		t.Errorf("both = %v", err)
	}
}

func TestRDSDeleteConfirmation(t *testing.T) {
	h, _ := newRDSHarness(t, app.Flags{}, nil)
	h.addDB("ap-east-1", "db-a", dbAvailable, func(db *rdstypes.DBInstance) { db.DeletionProtection = awssdk.Bool(true) })
	r := h.rds()
	// Non-interactive without --yes: usage error, nothing sent.
	if err := h.run("rds", "instance", "delete", "db-a"); !isUsage(err) || len(r.writes()) != 0 {
		t.Errorf("no --yes = %v %v", err, r.writes())
	}
	// --dry-run asks nothing and writes nothing.
	h.rt.Flags.DryRun = true
	if err := h.run("rds", "instance", "delete", "db-a"); err != nil {
		t.Fatal(err)
	}
	if a := actions(h.report()); a["db-instance/db-a would_update"] != 1 || a["db-instance/db-a would_delete"] != 1 || len(r.writes()) != 0 {
		t.Errorf("dry run = %v", a)
	}
	h.rt.Flags.DryRun = false
	// Interactive: no (the default) is no failure and changes nothing.
	h.rt.Flags.NonInteractive = false
	h.rt.Picker = &scriptedPicker{t: t}
	h.rt.Stdin = strings.NewReader("\n")
	if err := h.run("rds", "instance", "delete", "db-a"); err != nil && !errors.Is(err, platform.ErrNothingToDo) {
		t.Errorf("declined = %v", err)
	}
	if len(r.writes()) != 0 {
		t.Errorf("declined but wrote %v", r.writes())
	}
	h.rt.Stdin = strings.NewReader("y\n")
	if err := h.run("rds", "instance", "delete", "db-a"); err != nil {
		t.Fatal(err)
	}
	if len(r.deletes) != 1 {
		t.Errorf("accepted: %v", r.writes())
	}
}

func TestRDSDeleteFailsAfterProtectionOff(t *testing.T) {
	h, _ := newRDSHarness(t, app.Flags{Yes: true}, nil)
	h.addDB("ap-east-1", "db-a", dbAvailable, func(db *rdstypes.DBInstance) { db.DeletionProtection = awssdk.Bool(true) })
	h.rds().errOnce = map[string][]error{"DeleteDBInstance": {&rdstypes.SnapshotQuotaExceededFault{Message: awssdk.String("quota")}}}
	err := h.run("rds", "instance", "delete", "db-a")
	if err == nil || !strings.Contains(err.Error(), "delete old snapshots") || !strings.Contains(err.Error(), "switch it on again") {
		t.Errorf("err = %v", err)
	}
}
