package aws

import (
	"errors"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

func orderable(class, storage string, zones ...string) rdstypes.OrderableDBInstanceOption {
	o := rdstypes.OrderableDBInstanceOption{DBInstanceClass: awssdk.String(class), StorageType: awssdk.String(storage), Engine: awssdk.String("mysql")}
	for _, z := range zones {
		o.AvailabilityZones = append(o.AvailabilityZones, rdstypes.AvailabilityZone{Name: awssdk.String(z)})
	}
	return o
}

// rdsPickHarness is an RDS harness in the interactive flow.
func rdsPickHarness(t *testing.T, flags app.Flags, defaults map[string]any) *awsHarness {
	t.Helper()
	flags.NonInteractive, flags.NonInteractiveSet = false, true
	h, _ := newRDSHarness(t, flags, defaults)
	h.rt.Picker = prompttest.New(t)
	return h
}

// start without the instance offers the stopped ones; resize without
// --class offers the x86 classes offered in the instance's zone, Graviton
// classes and its own class left out.
func TestRDSPicks(t *testing.T) {
	h := rdsPickHarness(t, app.Flags{DryRun: true}, nil)
	h.addDB("ap-east-1", "db-a", dbAvailable)
	h.addDB("ap-east-1", "db-b", dbStopped)
	h.ec2.mu.Lock()
	h.ec2.rds.orderable = []rdstypes.OrderableDBInstanceOption{
		orderable("db.t3.micro", "gp3", "ap-east-1a"), orderable("db.m5.large", "gp3", "ap-east-1a"),
		orderable("db.t4g.medium", "gp3", "ap-east-1a"), orderable("db.m6gd.large", "gp3", "ap-east-1a"),
		orderable("db.r5.large", "gp3", "ap-east-1b"), orderable("db.m6i.large", "gp2", "ap-east-1a"),
		orderable("db.t2.medium", "gp3", "ap-east-1a"), orderable("db.m4.large", "gp3", "ap-east-1a"),
	}
	h.ec2.mu.Unlock()

	p := prompttest.New(t, prompttest.Label("db-b  "))
	h.rt.Picker = p
	if err := h.run("rds", "instance", "start"); err != nil {
		t.Fatalf("start: %v", err)
	}
	if v := prompttest.Values(p.Asked[0].Options); v != "db-b.abc123.ap-east-1.rds.amazonaws.com" {
		t.Errorf("start offered %q", v)
	}
	if l := prompttest.Labels(p.Asked[0].Options); !strings.Contains(l, "db-b  mysql 8.0.36  db.t3.micro  stopped  ap-east-1a  aws/lab/ap-east-1") {
		t.Errorf("labels: %s", l)
	}

	p = prompttest.New(t, prompttest.Label("db-a  "), "db.m5.large")
	h.rt.Picker = p
	if err := h.run("rds", "instance", "resize"); err != nil {
		t.Fatalf("resize: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if v := prompttest.Values(p.Asked[1].Options); v != "db.m5.large" {
		t.Errorf("classes offered %q, want x86 classes of the zone and storage only", v)
	}

	h.rt.Picker = prompttest.New(t, prompttest.Abort{})
	if err := h.run("rds", "instance", "delete"); !errors.Is(err, prompt.ErrAborted) {
		t.Errorf("delete abort = %v", err)
	}
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("rds", "instance", "resize", "db-a"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("non-interactive = %v", err)
	}
}

func TestCurrentGenClass(t *testing.T) {
	for class, want := range map[string]bool{"db.t3.micro": true, "db.m5.large": true, "db.r6i.large": true, "db.x2iedn.xlarge": true,
		"db.t2.micro": false, "db.m4.large": false, "db.r4.large": false, "db.m3.medium": false} {
		if got := currentGenClass(class); got != want {
			t.Errorf("currentGenClass(%s) = %v", class, got)
		}
	}
}

func TestX86Class(t *testing.T) {
	for class, want := range map[string]bool{"db.t3.micro": true, "db.m5.large": true, "db.m6i.large": true, "db.r6id.large": true,
		"db.t4g.micro": false, "db.m6g.large": false, "db.m6gd.large": false, "db.r7g.large": false, "db.x2g.large": false} {
		if got := x86Class(class); got != want {
			t.Errorf("x86Class(%s) = %v", class, got)
		}
	}
}

// create without <id>, --size, --az and a password asks for each; ensure
// without arguments asks for the state and the instances.
func TestRDSCreateEnsureAsks(t *testing.T) {
	h := rdsPickHarness(t, app.Flags{DryRun: true}, map[string]any{"rds": map[string]any{"default_class": "db.t3.micro"}})
	h.addDB("ap-east-1", "db-a", dbAvailable)
	h.ec2.mu.Lock()
	h.ec2.rds.orderable = []rdstypes.OrderableDBInstanceOption{orderable("db.t3.micro", "gp3", "ap-east-1b")}
	h.ec2.mu.Unlock()
	h.rds().versions = versions("8.0.46")
	h.rt.Stdin = strings.NewReader("short\nlong-password\nlong-password\n")
	p := prompttest.New(t, "db-a", "db-new", "10", "30", "ap-east-1b")
	h.rt.Picker = p
	if err := h.run("rds", "instance", "create"); err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if v := prompttest.Values(p.Find("Availability zone (that of the instances that use the database)").Options); v != "ap-east-1b" {
		t.Errorf("zones offered %q", v)
	}
	if rep := h.report(); !strings.Contains(rep.Changes[0].Detail, "30GB") || !strings.Contains(rep.Changes[0].Detail, "az=ap-east-1b") {
		t.Errorf("report = %+v", rep)
	}

	h.rt.Flags.DryRun = true
	p = prompttest.New(t, "stopped", []string{"db-a"})
	h.rt.Picker = p
	if err := h.run("rds", "instance", "ensure"); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	p.Done()

	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("rds", "instance", "create", "x", "--size", "20", "--password-env", "NOPE_UNSET"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("non-interactive = %v", err)
	}
}

// The row chosen in the list is the target: an identifier held in two
// regions is asked about once, not again when the instance is looked up.
func TestRDSPickOfAnIdentifierInTwoRegions(t *testing.T) {
	h := rdsPickHarness(t, app.Flags{DryRun: true}, nil)
	h.ec2.find.regions = []string{"ap-east-1", "us-west-2"}
	h.addDB("ap-east-1", "db-a", dbStopped)
	h.addDB("us-west-2", "db-a", dbStopped)
	p := prompttest.New(t, prompttest.Label("us-west-2"))
	h.rt.Picker = p
	if err := h.run("rds", "instance", "start"); err != nil {
		t.Fatalf("start: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if len(p.Asked) != 1 || len(p.Asked[0].Options) != 2 {
		t.Errorf("prompts: %v", p.Titles())
	}
	if rep := h.report(); len(rep.Changes) != 1 || rep.Target.Region != "us-west-2" {
		t.Errorf("report = %+v", rep)
	}
}
