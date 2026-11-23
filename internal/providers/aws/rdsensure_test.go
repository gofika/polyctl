package aws

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

func byResource(rep platform.Report) map[string]platform.Change {
	out := map[string]platform.Change{}
	for _, c := range rep.Changes {
		out[c.Resource] = c
	}
	return out
}

func TestRDSEnsureStopped(t *testing.T) {
	h, _ := newRDSHarness(t, app.Flags{}, nil)
	h.addDB("ap-east-1", "db-a", dbAvailable)
	h.addDB("ap-east-1", "db-b", dbStopped)
	r := h.rds()

	if err := h.run("rds", "instance", "ensure", "db-a", "db-b", "--state", "stopped"); err != nil {
		t.Fatalf("ensure: %v\n%s", err, h.stderr.String())
	}
	rep := h.report()
	ch := byResource(rep)
	if c := ch["db-instance/db-a"]; c.Action != platform.Updated || c.Detail != "stopped (was available)" {
		t.Errorf("db-a = %+v", c)
	}
	if c := ch["db-instance/db-b"]; c.Action != platform.Unchanged {
		t.Errorf("db-b = %+v", c)
	}
	if rep.Target.Profile != "lab" || rep.Target.Region != "ap-east-1" {
		t.Errorf("target = %+v", rep.Target)
	}
	if n := r.count("StopDBInstance"); n != 1 {
		t.Errorf("stops = %d", n)
	}
	// A second run writes nothing.
	n := len(r.writes())
	if err := h.run("rds", "instance", "ensure", "db-a", "db-b", "--state", "stopped"); err != nil {
		t.Fatal(err)
	}
	for _, c := range h.report().Changes {
		if c.Action != platform.Unchanged {
			t.Errorf("second run: %+v", c)
		}
	}
	if len(r.writes()) != n {
		t.Errorf("second run wrote %v", r.writes()[n:])
	}
}

// An instance AWS started again after 7 days is starting for a few
// minutes: ensure waits until it is available and stops it on the same
// run.
func TestRDSEnsureStoppedWaitsForStarting(t *testing.T) {
	h, clk := newRDSHarness(t, app.Flags{}, nil)
	d := h.addDB("ap-east-1", "db-a", dbStarting)
	// The resolve read, then the wait: starting, configuring, available.
	d.steps = []func(*rdstypes.DBInstance){status(dbStarting), status(dbStarting), status("configuring-enhanced-monitoring"), status(dbAvailable)}
	if err := h.run("rds", "instance", "ensure", "db-a", "--state", "stopped"); err != nil {
		t.Fatalf("ensure: %v\n%s", err, h.stderr.String())
	}
	if c := h.report().Changes[0]; c.Action != platform.Updated || c.Detail != "stopped (was starting)" {
		t.Errorf("change = %+v", c)
	}
	if h.rds().count("StopDBInstance") != 1 || len(clk.slept) == 0 || clk.slept[0] != dbSettlePoll {
		t.Errorf("calls %v slept %v", h.rds().calls, clk.slept)
	}
}

// An instance that someone else stops while ensure waits for it to
// become available is already as asked: nothing is sent.
func TestRDSEnsureStoppedMeanwhile(t *testing.T) {
	h, _ := newRDSHarness(t, app.Flags{}, nil)
	d := h.addDB("ap-east-1", "db-a", dbModifying)
	d.steps = []func(*rdstypes.DBInstance){status(dbModifying), status(dbModifying), status(dbStopping), status(dbStopped)}
	if err := h.run("rds", "instance", "ensure", "db-a", "--state", "stopped"); err != nil {
		t.Fatalf("ensure: %v\n%s", err, h.stderr.String())
	}
	if c := h.report().Changes[0]; c.Action != platform.Unchanged || c.Detail != "stopped (was modifying)" {
		t.Errorf("change = %+v", c)
	}
	if n := h.rds().count("StopDBInstance"); n != 0 {
		t.Errorf("stops = %d", n)
	}
}

func TestRDSEnsureDryRun(t *testing.T) {
	h, _ := newRDSHarness(t, app.Flags{DryRun: true}, nil)
	h.addDB("ap-east-1", "db-a", dbAvailable)
	h.addDB("ap-east-1", "db-b", dbStarting)
	h.addDB("ap-east-1", "db-c", dbStopping)
	h.addDB("ap-east-1", "db-d", dbStopped)
	if err := h.run("rds", "instance", "ensure", "db-a", "db-b", "db-c", "db-d", "--state", "stopped"); err != nil {
		t.Fatal(err)
	}
	rep := h.report()
	ch := byResource(rep)
	if !rep.DryRun || ch["db-instance/db-a"].Action != platform.WouldUpdate || ch["db-instance/db-b"].Action != platform.WouldUpdate ||
		ch["db-instance/db-b"].Detail != "wait for available, then stop (now starting)" ||
		ch["db-instance/db-c"].Action != platform.Unchanged || ch["db-instance/db-d"].Action != platform.Unchanged {
		t.Errorf("dry run = %+v", rep.Changes)
	}
	if w := h.rds().writes(); len(w) != 0 {
		t.Errorf("dry run wrote %v", w)
	}
}

func TestRDSEnsureFailures(t *testing.T) {
	h, _ := newRDSHarness(t, app.Flags{}, nil)
	h.addDB("ap-east-1", "db-a", dbAvailable)
	h.addDB("ap-east-1", "db-new", dbCreating)
	hook := filepath.Join(t.TempDir(), "hook.json")
	cfg, err := h.rt.Config()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Hooks.OnFailure = "cat > " + hook

	// A missing and a creating instance fail; the others go on.
	err = h.run("rds", "instance", "ensure", "db-missing", "db-new", "db-a", "--state", "stopped")
	if err == nil || errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "the following 2 instance(s) failed: db-missing, db-new") {
		t.Fatalf("err = %v", err)
	}
	ch := byResource(h.report())
	if ch["db-instance/db-missing"].Action != platform.Failed || ch["db-instance/db-new"].Action != platform.Skipped ||
		ch["db-instance/db-new"].Detail != dbCreating || ch["db-instance/db-a"].Action != platform.Updated {
		t.Errorf("changes = %+v", h.report().Changes)
	}
	if b, err := os.ReadFile(hook); err != nil || !strings.Contains(string(b), "aws.rds.instance.ensure.failed") {
		t.Errorf("hook = %s %v", b, err)
	}
	// Only missing instances: exit code 4.
	if err := h.run("rds", "instance", "ensure", "db-missing", "db-gone", "--state", "stopped"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("all missing = %v", err)
	}
	// --continue-on-error=false stops at the first failure.
	h.addDB("ap-east-1", "db-b", dbAvailable)
	n := h.rds().count("StopDBInstance")
	if err := h.run("rds", "instance", "ensure", "db-new", "db-b", "--state", "stopped", "--continue-on-error=false"); err == nil {
		t.Error("no error")
	}
	if h.rds().count("StopDBInstance") != n {
		t.Error("went on after the failure")
	}
	// A stop AWS refuses is a failure with the AWS error.
	h.rds().errOnce = map[string][]error{"StopDBInstance": {&fakeAPIError{"InvalidDBInstanceState", "Instance db-b cannot be stopped: it has read replicas"}}}
	if err := h.run("rds", "instance", "ensure", "db-b", "--state", "stopped"); err == nil || !strings.Contains(err.Error(), "read replicas") {
		t.Errorf("refused = %v", err)
	}
	for _, args := range [][]string{{"db-b"}, {"db-b", "--state", "paused"}} {
		if err := h.run(append([]string{"rds", "instance", "ensure"}, args...)...); !isUsage(err) {
			t.Errorf("%v = %v", args, err)
		}
	}
}

func TestRDSEnsureRunning(t *testing.T) {
	h, _ := newRDSHarness(t, app.Flags{}, nil)
	h.addDB("ap-east-1", "db-a", dbStopped)
	h.addDB("ap-east-1", "db-b", dbAvailable)
	c := h.addDB("ap-east-1", "db-c", dbStopping)
	c.steps = []func(*rdstypes.DBInstance){status(dbStopping), status(dbStopped)}
	d := h.addDB("ap-east-1", "db-d", "backing-up")
	d.steps = []func(*rdstypes.DBInstance){status("backing-up"), status("backing-up"), status(dbAvailable)}
	if err := h.run("rds", "instance", "ensure", "db-a", "db-b", "db-c", "db-d", "--state", "available"); err != nil {
		t.Fatalf("ensure: %v\n%s", err, h.stderr.String())
	}
	ch := byResource(h.report())
	if ch["db-instance/db-a"].Action != platform.Updated || ch["db-instance/db-a"].Detail != "available (was stopped)" ||
		ch["db-instance/db-b"].Action != platform.Unchanged ||
		ch["db-instance/db-c"].Action != platform.Updated || ch["db-instance/db-c"].Detail != "available (was stopping)" ||
		ch["db-instance/db-d"].Action != platform.Unchanged || ch["db-instance/db-d"].Detail != "available (was backing-up)" {
		t.Errorf("changes = %+v", h.report().Changes)
	}
	if n := h.rds().count("StartDBInstance"); n != 2 {
		t.Errorf("starts = %d", n)
	}
}

func TestRDSEnsureNoWait(t *testing.T) {
	h, _ := newRDSHarness(t, app.Flags{}, nil)
	h.addDB("ap-east-1", "db-a", dbAvailable)
	if err := h.run("rds", "instance", "ensure", "db-a", "--state", "stopped", "--no-wait"); err != nil {
		t.Fatal(err)
	}
	if c := h.report().Changes[0]; c.Action != platform.Updated || c.Detail != "stopping (was available)" {
		t.Errorf("no wait = %+v", c)
	}
	if awssdk.ToString(h.rds().dbs[0].db.DBInstanceStatus) != dbStopping {
		t.Error("waited")
	}
}
