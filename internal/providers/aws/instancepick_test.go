package aws

import (
	"errors"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// interactiveHarness is an instance harness whose runtime runs the
// interactive flow with the scripted picker p.
func interactiveHarness(t *testing.T, flags app.Flags) *awsHarness {
	t.Helper()
	flags.NonInteractive, flags.NonInteractiveSet = false, true
	h := newInstanceHarness(t, flags)
	h.rt.Picker = prompttest.New(t)
	return h
}

// On a terminal, start without <name|id> offers the stopped instances of
// the inventory (synced first); stop offers the running ones, and none is
// nothing to do.
func TestInstanceStartStopPick(t *testing.T) {
	h := interactiveHarness(t, app.Flags{})
	h.addInstance("ap-east-1", running("i-0aaaaaaaaaaaaaaa1", "web-01"))
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa2", name: "web-02", typ: "t3.nano", state: stateStopped, priv: "10.0.1.5"})
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa3", name: "gone", typ: "t3.nano", state: stateTerminated})

	p := prompttest.New(t, "i-0aaaaaaaaaaaaaaa2")
	h.rt.Picker = p
	if err := h.run("ec2", "instance", "start", "--no-wait"); err != nil {
		t.Fatalf("start: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	a := p.Find("Instance")
	if v := prompttest.Values(a.Options); v != "i-0aaaaaaaaaaaaaaa2" {
		t.Errorf("start offered %q, want the stopped instance only", v)
	}
	if l := prompttest.Labels(a.Options); !strings.Contains(l, "web-02  i-0aaaaaaaaaaaaaaa2  stopped  t3.nano  ap-east-1a  10.0.1.5  aws/lab") {
		t.Errorf("label: %s", l)
	}
	if st, _ := h.instState("ap-east-1", "i-0aaaaaaaaaaaaaaa2"); st == stateStopped {
		t.Errorf("instance not started")
	}

	// Leaving the pick stops nothing.
	h.rt.Picker = prompttest.New(t, prompttest.Abort{})
	if err := h.run("ec2", "instance", "stop"); !errors.Is(err, prompt.ErrAborted) {
		t.Errorf("abort = %v", err)
	}
	for _, w := range h.writes() {
		if w == "StopInstances" {
			t.Errorf("an aborted stop stopped something: %v", h.writes())
		}
	}
}

// Without anything to choose from, start is nothing to do; the
// non-interactive flow still needs the argument.
func TestInstanceStartPickEmpty(t *testing.T) {
	h := interactiveHarness(t, app.Flags{})
	h.addInstance("ap-east-1", running("i-0aaaaaaaaaaaaaaa1", "web-01"))
	err := h.run("ec2", "instance", "start")
	if !errors.Is(err, platform.ErrNothingToDo) || !strings.Contains(err.Error(), "stopped AWS instance") {
		t.Errorf("start = %v, want nothing to do", err)
	}

	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("ec2", "instance", "start"); err == nil || !strings.Contains(err.Error(), "arg") {
		t.Errorf("non-interactive = %v, want the argument required", err)
	}
}

// get and delete offer every instance that still exists; a name held by
// several live instances is a pick in the interactive flow and exit code 5
// otherwise.
func TestInstanceGetPickAndAmbiguous(t *testing.T) {
	h := interactiveHarness(t, app.Flags{})
	h.addInstance("ap-east-1", running("i-0aaaaaaaaaaaaaaa1", "web"))
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa2", name: "web", typ: "t3.nano", state: stateStopped, priv: "10.0.1.5"})
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa3", name: "gone", typ: "t3.nano", state: stateTerminated})

	p := prompttest.New(t, "i-0aaaaaaaaaaaaaaa1")
	h.rt.Picker = p
	if err := h.run("ec2", "instance", "get"); err != nil {
		t.Fatalf("get: %v", err)
	}
	if v := prompttest.Values(p.Find("Instance").Options); v != "i-0aaaaaaaaaaaaaaa1 i-0aaaaaaaaaaaaaaa2" {
		t.Errorf("get offered %q, want no terminated instance", v)
	}

	p = prompttest.New(t, prompttest.Label("i-0aaaaaaaaaaaaaaa2"))
	h.rt.Picker = p
	if err := h.run("ec2", "instance", "get", "web"); err != nil {
		t.Fatalf("ambiguous get: %v", err)
	}
	p.Done()
	if !strings.Contains(h.stdout.String(), "i-0aaaaaaaaaaaaaaa2") {
		t.Errorf("stdout = %s", h.stdout.String())
	}
	if l := prompttest.Labels(p.Asked[0].Options); !strings.Contains(l, "web  i-0aaaaaaaaaaaaaaa2  stopped  t3.nano  ap-east-1a  10.0.1.5  aws/lab/ap-east-1") {
		t.Errorf("labels: %s", l)
	}

	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	var amb *app.AmbiguousError
	if err := h.run("ec2", "instance", "get", "web"); !errors.As(err, &amb) {
		t.Errorf("non-interactive ambiguous = %v, want exit code 5", err)
	}
}

// resize without --type offers the T3 sizes offered in the instance's zone
// (its own type left out, 2H4G preselected), resolved as --type <size>.
func TestInstanceResizeTypePick(t *testing.T) {
	h := interactiveHarness(t, app.Flags{DryRun: true})
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa1", name: "web", typ: "t3.small", state: stateStopped})

	p := prompttest.New(t, "i-0aaaaaaaaaaaaaaa1", "2H8G")
	h.rt.Picker = p
	if err := h.run("ec2", "instance", "resize"); err != nil {
		t.Fatalf("resize: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	a := p.Asked[1]
	if a.Default != "2H4G" || prompttest.HasValue(a.Options, "2H2G") {
		t.Errorf("size pick = %+v (want 2H4G preselected, no current t3.small)", a)
	}
	if l := prompttest.Labels(a.Options); !strings.Contains(l, "2H4G  t3.medium  2 vCPU  4 GiB") || !strings.Contains(l, "Other size or exact instance type...") {
		t.Errorf("labels: %s", l)
	}
	if rep := h.report(); !strings.Contains(rep.Changes[0].Detail, "t3.large") {
		t.Errorf("report = %+v", rep)
	}

	// "Other ..." takes a typed size or type, checked as typed.
	p = prompttest.New(t, prompttest.Label("Other size"), "not a type", "c6a.large")
	h.rt.Picker = p
	if err := h.run("ec2", "instance", "resize", "web"); err != nil {
		t.Fatalf("resize other: %v", err)
	}
	p.Done()
	if rep := h.report(); !strings.Contains(rep.Changes[0].Detail, "c6a.large") {
		t.Errorf("report = %+v", rep)
	}

	// The non-interactive flow still needs --type, before any call.
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("ec2", "instance", "resize", "web"); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--type") {
		t.Errorf("non-interactive = %v", err)
	}
}
