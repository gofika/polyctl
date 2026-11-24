package gcp

import (
	"errors"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// interactiveGCP is a harness whose runtime runs the interactive flow with
// the scripted picker p.
func interactiveGCP(t *testing.T, defaults map[string]any, answers ...any) (*gcpHarness, *prompttest.Picker) {
	t.Helper()
	h := newGCPHarness(t, app.Flags{NonInteractiveSet: true}, defaults)
	p := prompttest.New(t, answers...)
	h.rt.Picker = p
	return h, p
}

// answer replaces the scripted answers of the harness's picker.
func (h *gcpHarness) answer(answers ...any) *prompttest.Picker {
	p := prompttest.New(h.t, answers...)
	h.rt.Picker = p
	return p
}

// nonInteractive switches the harness to the non-interactive flow.
func (h *gcpHarness) nonInteractive() {
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
}

// On a terminal, start without <name|id> offers the stopped instances of
// the inventory; stop offers the running ones; leaving the pick changes
// nothing; none is nothing to do; the non-interactive flow still needs the
// argument.
func TestInstanceStartStopPick(t *testing.T) {
	h, _ := interactiveGCP(t, nil)
	h.gce.addInstance("proj", "us-central1-a", "web-1", "10.128.0.5", "203.0.113.10")
	old := h.gce.addInstance("proj", "us-central1-b", "old-1", "10.128.0.6", "")
	old.Status = statusTerminated

	p := h.answer(prompttest.Label("old-1"))
	if err := h.run("compute", "instance", "start"); err != nil {
		t.Fatalf("start: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	a := p.Find("Instance")
	if l := prompttest.Labels(a.Options); strings.Contains(l, "web-1") || !strings.Contains(l, "old-1") ||
		!strings.Contains(l, "TERMINATED  e2-small  us-central1-b  10.128.0.6  gcp/lab") {
		t.Errorf("start offered:\n%s", l)
	}
	if in := h.gce.instance("us-central1-b", "old-1"); in.Status != statusRunning {
		t.Errorf("old-1 is %s, want started", in.Status)
	}

	// Leaving the pick of stop stops nothing.
	h.answer(prompttest.Abort{})
	if err := h.run("compute", "instance", "stop"); !errors.Is(err, prompt.ErrAborted) || len(h.gce.writes()) != 0 {
		t.Errorf("abort = %v, writes %v", err, h.gce.writes())
	}

	// Every instance runs now: start has nothing to do.
	h.answer()
	if err := h.run("compute", "instance", "start"); exitClass(err) != "nothing" || !strings.Contains(err.Error(), "stopped GCP instance") {
		t.Errorf("start with nothing stopped = %v", err)
	}

	h.nonInteractive()
	if err := h.run("compute", "instance", "start"); err == nil || !strings.Contains(err.Error(), "arg") {
		t.Errorf("non-interactive = %v, want the argument required", err)
	}
}

// get offers every instance; a name held in two zones is a pick on a
// terminal and exit code 5 otherwise.
func TestInstanceGetPickAndAmbiguous(t *testing.T) {
	h, _ := interactiveGCP(t, nil)
	h.gce.addInstance("proj", "us-central1-a", "web-1", "10.128.0.5", "203.0.113.10")
	h.gce.addInstance("proj", "us-central1-b", "web-1", "10.128.0.7", "")

	p := h.answer(prompttest.Label("us-central1-b"))
	if err := h.run("compute", "instance", "get", "--field", "internal-ip"); err != nil || h.stdout.String() != "10.128.0.7\n" {
		t.Fatalf("get pick = %q, %v", h.stdout.String(), err)
	}
	if n := len(p.Find("Instance").Options); n != 2 {
		t.Errorf("get offered %d instances, want 2", n)
	}

	p = h.answer(prompttest.Label("10.128.0.7"))
	if err := h.run("compute", "instance", "get", "web-1", "--field", "zone"); err != nil || h.stdout.String() != "us-central1-b\n" {
		t.Fatalf("ambiguous get = %q, %v", h.stdout.String(), err)
	}
	p.Done()
	if !strings.HasPrefix(p.Asked[0].Title, "Ambiguous") {
		t.Errorf("prompts: %v", p.Titles())
	}

	h.nonInteractive()
	if err := h.run("compute", "instance", "get", "web-1"); exitClass(err) != "ambiguous" {
		t.Errorf("non-interactive ambiguous = %v", err)
	}
}

// resize without --machine-type offers the x86 machine types of the
// instance's zone that are not deprecated, E2 presets first, the current
// type left out; the non-interactive flow needs --machine-type.
func TestInstanceResizePicksMachineType(t *testing.T) {
	h, _ := interactiveGCP(t, nil)
	in := h.gce.addInstance("proj", "us-central1-a", "web-1", "10.128.0.5", "")
	in.Status = statusTerminated
	for _, mt := range []string{"t2a-standard-1", "c4a-standard-2", "n2-standard-2", "n2-standard-4", "n1-standard-1", "a2-highgpu-1g"} {
		h.gce.machineTypes["us-central1-a/"+mt] = true
	}
	h.gce.machineArch["c4a-standard-2"] = "ARM64"
	h.gce.machineDeprecated["n2-standard-4"] = "DEPRECATED"

	p := h.answer("e2-standard-2")
	if err := h.run("compute", "instance", "resize", "web-1", "--yes"); err != nil {
		t.Fatalf("resize: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	opts := p.Asked[0].Options
	v := prompttest.Values(opts)
	for _, bad := range []string{"t2a-standard-1", "c4a-standard-2", "n2-standard-4", "n1-standard-1", "a2-highgpu-1g", " e2-small "} {
		if strings.Contains(" "+v+" ", " "+strings.TrimSpace(bad)+" ") {
			t.Errorf("offered %s: %s", bad, v)
		}
	}
	if !strings.HasPrefix(v, "e2-micro e2-medium e2-standard-2") || !strings.Contains(v, "n2-standard-2") {
		t.Errorf("offered %s", v)
	}
	if !strings.Contains(opts[0].Label, "e2-micro  2 vCPU  1 GB  shared core") {
		t.Errorf("label %q", opts[0].Label)
	}
	if got := lastSegment(h.gce.instance("us-central1-a", "web-1").MachineType); got != "e2-standard-2" {
		t.Errorf("machine type = %s", got)
	}

	// A size typed after "Size ...".
	p = h.answer(prompttest.Label("Size"), "0H1G", "4H16G")
	if err := h.run("compute", "instance", "resize", "web-1", "--yes"); err != nil {
		t.Fatalf("resize by size: %v", err)
	}
	p.Done()
	if got := lastSegment(h.gce.instance("us-central1-a", "web-1").MachineType); got != "e2-standard-4" {
		t.Errorf("machine type = %s", got)
	}

	h.nonInteractive()
	if err := h.run("compute", "instance", "resize", "web-1", "--yes"); exitClass(err) != "usage" || !strings.Contains(err.Error(), "--machine-type") {
		t.Errorf("non-interactive = %v", err)
	}
}

// update without --ip-forward asks for it, the current value marked.
func TestInstanceUpdateAsksIPForward(t *testing.T) {
	h, _ := interactiveGCP(t, nil)
	h.gce.addInstance("proj", "us-central1-a", "web-1", "10.128.0.5", "")
	p := h.answer(prompttest.Label("web-1"), "on")
	if err := h.run("compute", "instance", "update"); err != nil {
		t.Fatalf("update: %v", err)
	}
	p.Done()
	if l := prompttest.Labels(p.Asked[1].Options); !strings.Contains(l, "Off  (current)") {
		t.Errorf("labels %s", l)
	}
	if !h.gce.instance("us-central1-a", "web-1").CanIpForward {
		t.Errorf("ip forwarding not switched on")
	}
	h.nonInteractive()
	if err := h.run("compute", "instance", "update", "web-1"); exitClass(err) != "usage" {
		t.Errorf("non-interactive = %v", err)
	}
}
