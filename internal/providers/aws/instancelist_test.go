package aws

import (
	"errors"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"

	"github.com/gofika/polyctl/internal/app"
)

func TestInstanceListFilters(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{})
	h.addInstance("ap-east-1", running("i-0aaaaaaaaaaaaaaa1", "site-xz7"))
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa2", name: "site-xz8", typ: "c6a.xlarge", state: stateStopped})
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa3", name: "db", typ: "c6a.large", state: stateRunning})
	h.ec2.inst.pageSize = 1

	if err := h.run("ec2", "instance", "list", "--state", "running", "--type", "c6a.large,c6a.xlarge", "--name", "xz"); err != nil {
		t.Fatal(err)
	}
	var res instanceResult
	h.jsonOut(&res)
	if len(res.Instances) != 1 || res.Instances[0].Name != "site-xz7" || res.Region != "ap-east-1" {
		t.Fatalf("filtered list = %+v", res)
	}
	flt := h.ec2.inst.filters[0]
	got := map[string]string{}
	for _, f := range flt {
		got[awssdk.ToString(f.Name)] = strings.Join(f.Values, ",")
	}
	if got["instance-state-name"] != "running" || got["instance-type"] != "c6a.large,c6a.xlarge" || got["tag:Name"] != "*xz*" {
		t.Errorf("filters = %v", got)
	}

	// Two pages, every state: no filter drops anything.
	h.ec2.reset()
	if err := h.run("ec2", "instance", "list", "--name", "site"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&res)
	if len(res.Instances) != 2 || h.ec2.count("DescribeInstances") != 2 {
		t.Errorf("--name site = %+v in %d page(s)", res.Instances, h.ec2.count("DescribeInstances"))
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
	if err := h.run("ec2", "instance", "start", "i-0aaaaaaaaaaaaaaa1", "--wait"); err != nil {
		t.Fatal(err)
	}
	if st, _ := h.instState("ap-east-1", "i-0aaaaaaaaaaaaaaa1"); st != stateRunning || !strings.Contains(h.stderr.String(), "is running: public ip 203.0.113.") {
		t.Errorf("start --wait: %s / %s", st, h.stderr.String())
	}
	if err := h.run("ec2", "instance", "stop", "i-0aaaaaaaaaaaaaaa1", "--wait", "--timeout", "1m"); err != nil {
		t.Fatal(err)
	}
	var res stateChangeResult
	h.jsonOut(&res)
	if len(res.Changes) != 1 || res.Changes[0].CurrentState != stateStopped {
		t.Errorf("stop --wait = %+v", res)
	}
}
