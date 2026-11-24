package aws

import (
	"errors"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

func TestInstanceListFilters(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{})
	h.addInstance("ap-east-1", running("i-0aaaaaaaaaaaaaaa1", "web-01"))
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa2", name: "web-02", typ: "c6a.xlarge", state: stateStopped})
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa3", name: "db", typ: "c6a.large", state: stateRunning})
	h.ec2.inst.pageSize = 1

	if err := h.run("ec2", "instance", "list", "--state", "running", "--type", "c6a.large,c6a.xlarge", "--name", "web-0"); err != nil {
		t.Fatal(err)
	}
	var res instanceResult
	h.jsonOut(&res)
	if len(res.Instances) != 1 || res.Instances[0].Name != "web-01" || res.Region != "ap-east-1" {
		t.Fatalf("filtered list = %+v", res)
	}
	flt := h.ec2.inst.filters[0]
	got := map[string]string{}
	for _, f := range flt {
		got[awssdk.ToString(f.Name)] = strings.Join(f.Values, ",")
	}
	if got["instance-state-name"] != "running" || got["instance-type"] != "c6a.large,c6a.xlarge" || got["tag:Name"] != "*web-0*" {
		t.Errorf("filters = %v", got)
	}

	// Two pages, every state: no filter drops anything.
	h.ec2.reset()
	if err := h.run("ec2", "instance", "list", "--name", "web"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&res)
	if len(res.Instances) != 2 || h.ec2.count("DescribeInstances") != 2 {
		t.Errorf("--name web = %+v in %d page(s)", res.Instances, h.ec2.count("DescribeInstances"))
	}

	// Nothing matches: an empty list, a note, exit code 0.
	if err := h.run("ec2", "instance", "list", "--state", "terminated"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&res)
	if len(res.Instances) != 0 || !strings.Contains(h.stdout.String(), `"instances": []`) || !strings.Contains(h.stderr.String(), "no matching instances") {
		t.Errorf("empty list: %s / %s", h.stdout.String(), h.stderr.String())
	}

	if err := h.run("ec2", "instance", "list", "--state", "sleeping"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("--state sleeping = %v", err)
	}
}

func TestInstanceStartStopWait(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{})
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa1", name: "web", typ: "t3.nano", state: stateStopped})
	// By name, like get.
	if err := h.run("ec2", "instance", "start", "web", "--wait"); err != nil {
		t.Fatal(err)
	}
	if st, _ := h.instState("ap-east-1", "i-0aaaaaaaaaaaaaaa1"); st != stateRunning || !strings.Contains(h.stderr.String(), "is running: public ip 203.0.113.") {
		t.Errorf("start --wait: %s / %s", st, h.stderr.String())
	}
	if rep := h.report(); len(rep.Changes) != 1 || rep.Changes[0].Action != platform.Updated || !strings.HasPrefix(rep.Changes[0].Detail, "start; running") {
		t.Errorf("start report = %+v", rep)
	}
	// Running already: unchanged, nothing written.
	h.ec2.reset()
	if err := h.run("ec2", "instance", "start", "web"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); len(rep.Changes) != 1 || rep.Changes[0].Action != platform.Unchanged || len(h.writes()) != 0 {
		t.Errorf("start of a running instance = %+v, writes %v", rep, h.writes())
	}
	// The non-interactive flow needs --yes to stop.
	if err := h.run("ec2", "instance", "stop", "web"); !errors.Is(err, app.ErrUsage) || len(h.writes()) != 0 {
		t.Errorf("stop without --yes = %v, writes %v", err, h.writes())
	}
	h.rt.Flags.Yes = true
	if err := h.run("ec2", "instance", "stop", "i-0aaaaaaaaaaaaaaa1", "--wait", "--timeout", "1m"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); len(rep.Changes) != 1 || rep.Changes[0].Detail != "stop; stopped" {
		t.Errorf("stop --wait = %+v", rep)
	}
	if st, _ := h.instState("ap-east-1", "i-0aaaaaaaaaaaaaaa1"); st != stateStopped {
		t.Errorf("state after stop = %s", st)
	}
}

func TestInstanceStopPending(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{Yes: true})
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa3", name: "booting", typ: "t3.nano", state: statePending, next: []string{statePending, statePending, stateRunning}})
	if err := h.run("ec2", "instance", "stop", "booting", "--wait", "--timeout", "1m"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if st, _ := h.instState("ap-east-1", "i-0aaaaaaaaaaaaaaa3"); st != stateStopped {
		t.Errorf("state after stop of a pending instance = %s", st)
	}
	if rep := h.report(); len(rep.Changes) != 1 || rep.Changes[0].Detail != "stop; stopped" {
		t.Errorf("report = %+v", rep)
	}
}

func TestInstanceStopError(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{Yes: true})
	h.addInstance("ap-east-1", running("i-0aaaaaaaaaaaaaaa1", "web"))
	h.ec2.inst.errs["StopInstances"] = &fakeAPIError{"UnauthorizedOperation", "not authorized"}
	err := h.run("ec2", "instance", "stop", "web", "--wait", "--timeout", "1m")
	if !errors.Is(err, platform.ErrUnauthorized) {
		t.Fatalf("refused stop = %v", err)
	}
	if strings.Contains(h.stderr.String(), "requested") || strings.Contains(h.stdout.String(), "updated") {
		t.Errorf("a refused stop was reported: %s / %s", h.stderr.String(), h.stdout.String())
	}
	if st, _ := h.instState("ap-east-1", "i-0aaaaaaaaaaaaaaa1"); st != stateRunning {
		t.Errorf("state = %s", st)
	}
}
