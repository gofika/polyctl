package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

func versions(vs ...string) []rdstypes.DBEngineVersion {
	var out []rdstypes.DBEngineVersion
	for _, v := range vs {
		st := "available"
		if strings.HasSuffix(v, "!") {
			v, st = strings.TrimSuffix(v, "!"), "deprecated"
		}
		out = append(out, rdstypes.DBEngineVersion{EngineVersion: awssdk.String(v), Status: awssdk.String(st)})
	}
	return out
}

func TestLatestEngineVersion(t *testing.T) {
	cases := []struct {
		name, major, want string
		list              []rdstypes.DBEngineVersion
	}{
		// Numbers, not strings: 8.0.36 is newer than 8.0.9.
		{"numeric", "8.0", "8.0.36", versions("8.0.9", "8.0.36", "8.0.11")},
		{"two-digit patch", "8.4", "8.4.13", versions("8.4.5", "8.4.9", "8.4.13", "8.4.11")},
		// A plain version wins over builds of the same version.
		{"plain over build", "8.0", "8.0.46", versions("8.0.46-rds.20260624", "8.0.46", "8.0.46-rds.20260908")},
		// Only builds: the latest date.
		{"builds only", "5.7", "5.7.44-rds.20260902", versions("5.7.44-rds.20250103", "5.7.44-rds.20260902", "5.7.44-rds.20251212")},
		// A newer core wins over a build of an older one.
		{"newer core", "8.0", "8.0.46-rds.20260101", versions("8.0.45", "8.0.46-rds.20260101")},
		// Deprecated versions are skipped.
		{"deprecated", "8.0", "8.0.36", versions("8.0.36", "8.0.40!")},
		// Other majors never match; 9.7.4 does not leak into 8.0.
		{"major only", "8.0", "8.0.36", versions("8.0.36", "8.4.13", "9.7.4", "8.01.1")},
		{"none", "8.4", "", versions("8.0.36")},
	}
	for _, c := range cases {
		got, ok := latestEngineVersion(c.list, c.major)
		if got != c.want || ok != (c.want != "") {
			t.Errorf("%s: latest = %q, %v; want %q", c.name, got, ok, c.want)
		}
	}
	// A missing status counts as available.
	if got, _ := latestEngineVersion([]rdstypes.DBEngineVersion{{EngineVersion: awssdk.String("8.0.40")}}, "8.0"); got != "8.0.40" {
		t.Errorf("no status = %q", got)
	}
}

func TestCompareEngineVersionsMissingParts(t *testing.T) {
	a, _ := parseEngineVersion("8.0")
	b, _ := parseEngineVersion("8.0.0")
	if compareEngineVersions(a, b) != 0 {
		t.Error("8.0 != 8.0.0")
	}
	if _, ok := parseEngineVersion("8.x.1"); ok {
		t.Error("8.x.1 parsed")
	}
}

func TestResolveLatestVersionFallsBack(t *testing.T) {
	h, _ := newRDSHarness(t, app.Flags{}, nil)
	c, err := openProfile(context.Background(), h.rt, "lab")
	if err != nil {
		t.Fatal(err)
	}
	r := h.rds()
	r.versions = versions("5.7.44-rds.20260902", "8.0.9", "8.0.36", "8.0.46-rds.20260908", "8.4.9", "8.4.13", "9.7.4")
	r.pageSize = 2
	// The major version answers its family (paged).
	if v, err := c.resolveLatestVersion(context.Background(), "ap-east-1", "mysql", "8.0"); err != nil || v != "8.0.46-rds.20260908" {
		t.Errorf("8.0 = %q, %v", v, err)
	}
	if n := r.count("DescribeDBEngineVersions"); n != 0 {
		t.Errorf("full listing used: %v", r.calls)
	}
	// A filter that answers nothing falls back to the full list, filtered
	// by prefix.
	r.calls, r.noFamily = nil, true
	if v, err := c.resolveLatestVersion(context.Background(), "ap-east-1", "mysql", "8.4"); err != nil || v != "8.4.13" {
		t.Errorf("8.4 fallback = %q, %v (%v)", v, err, r.calls)
	}
	if r.count("DescribeDBEngineVersions") < 1 {
		t.Errorf("no fallback: %v", r.calls)
	}
	// Nothing at all is an error.
	if _, err := c.resolveLatestVersion(context.Background(), "ap-east-1", "mysql", "10.1"); err == nil || !strings.Contains(err.Error(), "no available MySQL 10.1 version") {
		t.Errorf("none = %v", err)
	}
}

func TestRDSErrMapping(t *testing.T) {
	if err := rdsErr("DescribeDBInstances", "eu-west-1", notFoundDB("x")); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("not found = %v", err)
	}
	// The code string is the API's own: a "...Fault" spelling is no match.
	if isDBNotFound(&fakeAPIError{"DBInstanceNotFoundFault", "x"}) {
		t.Error("DBInstanceNotFoundFault string matched")
	}
	if !isDBNotFound(&fakeAPIError{"DBInstanceNotFound", "x"}) || !isDBNotFound(fmt.Errorf("wrapped: %w", notFoundDB("x"))) {
		t.Error("DBInstanceNotFound not matched")
	}
	err := rdsErr("StopDBInstance", "eu-west-1", &fakeAPIError{"AccessDenied", "no"})
	if !errors.Is(err, platform.ErrUnauthorized) || !strings.Contains(err.Error(), "rds:StopDBInstance") {
		t.Errorf("denied = %v", err)
	}
	// Parameter errors and others keep the general code.
	for _, code := range []string{"InvalidParameterValue", "InvalidParameterCombination", "DBSubnetGroupNotFoundFault"} {
		err := rdsErr("CreateDBInstance", "eu-west-1", &fakeAPIError{code, "x"})
		if errors.Is(err, platform.ErrNotFound) || errors.Is(err, platform.ErrInvalidInput) || errors.Is(err, platform.ErrUnauthorized) || !strings.Contains(err.Error(), code) {
			t.Errorf("%s = %v", code, err)
		}
	}
	if !isInvalidDBState(invalidState("x")) || !isInvalidDBState(&fakeAPIError{"InvalidDBInstanceState", "x"}) {
		t.Error("InvalidDBInstanceState not matched")
	}
}

func TestDBFromToleratesMissingFields(t *testing.T) {
	d := dbFrom("eu-west-1", rdstypes.DBInstance{DBInstanceIdentifier: awssdk.String("new"), DBInstanceStatus: awssdk.String(dbCreating)})
	if d.Endpoint != "" || d.Port != 0 || !d.CreatedAt.IsZero() || d.Region != "eu-west-1" {
		t.Errorf("creating = %+v", d)
	}
	r := d.resource()
	if r.ID != "eu-west-1/new" || r.Name != "new" || len(r.IPs) != 0 {
		t.Errorf("resource = %+v", r)
	}
	created := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	d = dbFrom("eu-west-1", rdstypes.DBInstance{DBInstanceIdentifier: awssdk.String("db"),
		Endpoint:            &rdstypes.Endpoint{Address: awssdk.String("db.x.eu-west-1.rds.amazonaws.com")},
		DBSubnetGroup:       &rdstypes.DBSubnetGroup{DBSubnetGroupName: awssdk.String("sg"), VpcId: awssdk.String("vpc-1")},
		VpcSecurityGroups:   []rdstypes.VpcSecurityGroupMembership{{VpcSecurityGroupId: awssdk.String("sg-1")}},
		DBParameterGroups:   []rdstypes.DBParameterGroupStatus{{DBParameterGroupName: awssdk.String("default.mysql8.0")}},
		TagList:             []rdstypes.Tag{{Key: awssdk.String("Name"), Value: awssdk.String("db")}},
		InstanceCreateTime:  &created,
		DBClusterIdentifier: awssdk.String("cl"),
		// A pending values struct without a class is no pending class.
		PendingModifiedValues: &rdstypes.PendingModifiedValues{},
	})
	if d.SubnetGroup != "sg" || d.VpcID != "vpc-1" || d.SecurityGroups[0] != "sg-1" || d.ParameterGroup != "default.mysql8.0" ||
		d.Tags["Name"] != "db" || !d.CreatedAt.Equal(created) || d.ClusterID != "cl" || d.PendingClass != "" || d.Port != 0 {
		t.Errorf("full = %+v", d)
	}
}

func TestClassApplied(t *testing.T) {
	done := classApplied("db.t3.small")
	db := func(class, st, pending string) rdstypes.DBInstance {
		d := rdstypes.DBInstance{DBInstanceClass: awssdk.String(class), DBInstanceStatus: awssdk.String(st)}
		if pending != "" {
			d.PendingModifiedValues = &rdstypes.PendingModifiedValues{DBInstanceClass: awssdk.String(pending)}
		}
		return d
	}
	// Right after the modify: available, old class, new class pending.
	if done(db("db.t3.micro", dbAvailable, "db.t3.small")) {
		t.Error("old available counted")
	}
	// The class is new but the instance is still modifying.
	if done(db("db.t3.small", dbModifying, "")) {
		t.Error("modifying counted")
	}
	if !done(db("db.t3.small", dbAvailable, "")) {
		t.Error("final state not counted")
	}
}

func TestCreateInputLeavesOutEmptyValues(t *testing.T) {
	in := dbCreateSpec{ID: "db", Class: "db.t3.micro", Engine: "mysql", EngineVersion: "8.0.46", MasterUser: "admin", Password: "secret123",
		Size: 20, StorageType: "gp2", AZ: "eu-west-1a", BackupRetention: 7, Tags: map[string]string{"b": "2", "a": "1"}}.createInput()
	if in.MaxAllocatedStorage != nil || in.DBSubnetGroupName != nil || in.DBParameterGroupName != nil || in.VpcSecurityGroupIds != nil ||
		in.PreferredBackupWindow != nil || awssdk.ToBool(in.PubliclyAccessible) {
		t.Errorf("input = %+v", in)
	}
	if len(in.Tags) != 2 || awssdk.ToString(in.Tags[0].Key) != "a" {
		t.Errorf("tags = %+v", in.Tags)
	}
}
