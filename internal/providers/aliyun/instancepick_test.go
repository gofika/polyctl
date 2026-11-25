package aliyun

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
	"github.com/gofika/polyctl/internal/secrets"
)

// On a terminal, start without <name|id> offers the Stopped instances of
// the inventory (synced first); stop offers the running ones, and none is
// nothing to do.
func TestInstanceStartStopPick(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, f, _ := computeHarness(t, app.Flags{})
	f.addVM("i-1", "site-a", instRunning, "ecs.u1-c1m1.large", "vpc-1", "vsw-b")
	f.addVM("i-2", "site-b", instStopped, "ecs.u1-c1m1.large", "vpc-1", "vsw-b")

	p := prompttest.New(t, "i-2")
	h.rt.Picker = p
	if err := h.run("ecs", "instance", "start"); err != nil {
		t.Fatalf("start: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if v := prompttest.Values(p.Find("Instance").Options); v != "i-2" {
		t.Errorf("start offered %q, want the Stopped instance only", v)
	}
	if l := prompttest.Labels(p.Find("Instance").Options); !strings.Contains(l, "site-b  i-2  Stopped  ecs.u1-c1m1.large  cn-shanghai-b  172.16.0.10  -  aliyun/ali") {
		t.Errorf("label: %s", l)
	}
	if len(h.api.callsFor("StartInstance")) != 1 {
		t.Errorf("StartInstance calls = %d", len(h.api.callsFor("StartInstance")))
	}

	// Leaving the pick starts nothing.
	h.rt.Picker = prompttest.New(t, prompttest.Abort{})
	if err := h.run("ecs", "instance", "stop"); !errors.Is(err, prompt.ErrAborted) || len(h.api.callsFor("StopInstance")) != 0 {
		t.Errorf("abort = %v", err)
	}
}

// Without anything to choose from, start is nothing to do (exit code 0).
func TestInstanceStartPickEmpty(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, f, _ := computeHarness(t, app.Flags{})
	f.addVM("i-1", "site-a", instRunning, "ecs.u1-c1m1.large", "vpc-1", "vsw-b")
	h.rt.Picker = prompttest.New(t)
	err := h.run("ecs", "instance", "start")
	if !errors.Is(err, platform.ErrNothingToDo) || !strings.Contains(err.Error(), "Stopped aliyun instance") {
		t.Errorf("start = %v, want nothing to do", err)
	}

	// The non-interactive flow is unchanged: the argument is required.
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("ecs", "instance", "start"); err == nil || !strings.Contains(err.Error(), "arg") {
		t.Errorf("non-interactive = %v", err)
	}
}

// resize without <name|id> and --type asks for the instance, then the size
// among the x86 sizes the instance can change to (its own size, arm64 and
// sold-out types left out), resolved to the cheapest type of the size.
func TestInstanceResizePick(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, f, cat := sizeHarness(t, app.Flags{})
	in := f.addVM("i-1", "site-a", instStopped, "ecs.u1-c1m1.large", "vpc-1", "vsw-b")
	in["Cpu"], in["Memory"], in["ImageId"] = 2, 2048, "m-1"
	cat.add("ecs.g8y.xlarge", 4, 16, "ARM", map[string]float64{"cn-shanghai-b": 0.01})
	p := prompttest.New(t, "i-1", "2H4G")
	h.rt.Picker = p
	if err := h.run("ecs", "instance", "resize"); err != nil {
		t.Fatalf("resize: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	a := p.Find("Instance size (the cheapest x86 type of the size is used)")
	if v := prompttest.Values(a.Options); v != "2H3.5G 2H4G" {
		t.Errorf("sizes offered %q (want no 2H2G current size, no ARM 4H16G)", v)
	}
	if f.vm("i-1")["InstanceType"] != "ecs.e-c1m2.large" {
		t.Errorf("type = %v", f.vm("i-1")["InstanceType"])
	}
}

// password without <name|id> offers the instances whose credentials are
// stored, and a name stored for several instances is a pick; none stored
// is nothing to do.
func TestInstancePasswordPick(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, _ := winHarness(t, app.Flags{})
	h.rt.Picker = prompttest.New(t)
	if err := h.run("ecs", "instance", "password"); !errors.Is(err, platform.ErrNothingToDo) {
		t.Errorf("nothing stored = %v", err)
	}
	st, err := h.rt.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"i-1", "i-2"} {
		c := secrets.Credentials{Ref: secrets.Ref{Platform: platform.Aliyun, Profile: "ali", Location: "cn-shanghai", InstanceID: id}, Name: "win", User: "Administrator", Password: "pw-" + id}
		if err := st.Put(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
	p := prompttest.New(t, "i-2")
	h.rt.Picker = p
	if err := h.run("ecs", "instance", "password"); err != nil {
		t.Fatal(err)
	}
	p.Done()
	if !strings.Contains(h.stdout.String(), "pw-i-2") {
		t.Errorf("stdout = %s", h.stdout.String())
	}
	if l := prompttest.Labels(p.Find("Instance").Options); !strings.Contains(l, "win  i-1  cn-shanghai  user Administrator") {
		t.Errorf("labels: %s", l)
	}

	p = prompttest.New(t, "i-1")
	h.rt.Picker = p
	if err := h.run("ecs", "instance", "password", "win"); err != nil {
		t.Fatal(err)
	}
	p.Done()
	if !strings.Contains(h.stdout.String(), "pw-i-1") {
		t.Errorf("stdout = %s", h.stdout.String())
	}

	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	var amb *app.AmbiguousError
	if err := h.run("ecs", "instance", "password", "win"); !errors.As(err, &amb) {
		t.Errorf("non-interactive = %v", err)
	}
}
