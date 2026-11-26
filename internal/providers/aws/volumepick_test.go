package aws

import (
	"errors"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// volumePickHarness is the volume harness in the interactive flow, with an
// available volume vol-0333 (orphan, ap-east-1a) besides the attached
// ones.
func volumePickHarness(t *testing.T, flags app.Flags) *awsHarness {
	t.Helper()
	flags.NonInteractive, flags.NonInteractiveSet = false, true
	h := newVolumeHarness(t, flags)
	h.addVolume("ap-east-1", &fakeVol{id: "vol-0333", name: "orphan", size: 8, typ: "gp2"})
	h.rt.Picker = prompttest.New(t)
	return h
}

// delete without the volume offers the available volumes only; detach the
// attached ones; get every one.
func TestVolumeTargetPicks(t *testing.T) {
	h := volumePickHarness(t, app.Flags{})

	p := prompttest.New(t, prompttest.Abort{})
	h.rt.Picker = p
	if err := h.run("ec2", "volume", "delete"); !errors.Is(err, prompt.ErrAborted) {
		t.Errorf("delete abort = %v", err)
	}
	if v := prompttest.Values(p.Asked[0].Options); v != "vol-0333" {
		t.Errorf("delete offered %q, want the available volume only", v)
	}
	if l := prompttest.Labels(p.Asked[0].Options); !strings.Contains(l, "orphan  vol-0333  8 GB  gp2  available  ap-east-1a  -  aws/lab") {
		t.Errorf("labels: %s", l)
	}

	p = prompttest.New(t, prompttest.Abort{})
	h.rt.Picker = p
	_ = h.run("ec2", "volume", "detach")
	if v := prompttest.Values(p.Asked[0].Options); v != "vol-0111 vol-0222" {
		t.Errorf("detach offered %q", v)
	}
	if l := prompttest.Labels(p.Asked[0].Options); !strings.Contains(l, "i-0aaaaaaaaaaaaaaa1 as /dev/sdb") {
		t.Errorf("labels: %s", l)
	}

	p = prompttest.New(t, "vol-0222")
	h.rt.Picker = p
	if err := h.run("ec2", "volume", "get"); err != nil || !strings.Contains(h.stdout.String(), "site-xz7-data") {
		t.Errorf("get = %v, %s", err, h.stdout.String())
	}

	// The non-interactive flow needs the argument.
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("ec2", "volume", "get"); err == nil || !strings.Contains(err.Error(), "arg") {
		t.Errorf("non-interactive = %v", err)
	}
}

// attach without the volume and --instance asks for an available volume,
// then a running or stopped instance of its zone.
func TestVolumeAttachPicks(t *testing.T) {
	h := volumePickHarness(t, app.Flags{})
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa2", name: "other-zone", typ: "t3.nano", state: stateRunning, az: "ap-east-1b"})

	p := prompttest.New(t, "vol-0333", "i-0aaaaaaaaaaaaaaa1")
	h.rt.Picker = p
	if err := h.run("ec2", "volume", "attach", "--device", "/dev/sdc", "--no-wait"); err != nil {
		t.Fatalf("attach: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if v := prompttest.Values(p.Asked[1].Options); v != "i-0aaaaaaaaaaaaaaa1" {
		t.Errorf("instances offered %q, want those of the volume's zone", v)
	}
	if a := h.ebs().attaches; len(a) != 1 || awssdk.ToString(a[0].VolumeId) != "vol-0333" || awssdk.ToString(a[0].InstanceId) != "i-0aaaaaaaaaaaaaaa1" {
		t.Errorf("attaches = %+v", a)
	}

	// No instance in the zone: a usage error naming --instance.
	h.addVolume("ap-east-1", &fakeVol{id: "vol-0555", size: 8, az: "ap-east-1c"})
	h.rt.Picker = prompttest.New(t)
	if err := h.run("ec2", "volume", "attach", "vol-0555"); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--instance") {
		t.Errorf("no instance = %v", err)
	}
}

// create without --size / --from-snapshot and --az asks for the zone and
// the source; resize without a change asks for the new size.
func TestVolumeCreateResizeAsks(t *testing.T) {
	h := volumePickHarness(t, app.Flags{DryRun: true})
	h.addSnap("ap-east-1", &fakeSnap{id: "snap-0aaa", volID: "vol-0222", size: 400, start: time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC)})
	h.addSnap("ap-east-1", &fakeSnap{id: "snap-0bbb", volID: "vol-0222", size: 400, state: "pending"})

	p := prompttest.New(t, "ap-east-1b", "snap-0aaa")
	h.rt.Picker = p
	if err := h.run("ec2", "volume", "create", "restored"); err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if v := prompttest.Values(p.Asked[0].Options); !strings.HasPrefix(v, "ap-east-1a ap-east-1b") {
		t.Errorf("zones offered %q", v)
	}
	if v := prompttest.Values(p.Asked[1].Options); strings.Contains(v, "snap-0bbb") || !strings.Contains(v, "snap-0aaa") {
		t.Errorf("snapshots offered %q, want completed ones only", v)
	}
	if rep := h.report(); !strings.Contains(rep.Changes[0].Detail, "snap-0aaa") || !strings.Contains(rep.Changes[0].Detail, "ap-east-1b") {
		t.Errorf("report = %+v", rep)
	}

	p = prompttest.New(t, prompttest.Label("The zone of an instance"), "i-0aaaaaaaaaaaaaaa1", prompttest.Label("Empty volume"), "0", "50")
	h.rt.Picker = p
	if err := h.run("ec2", "volume", "create"); err != nil {
		t.Fatalf("create empty: %v", err)
	}
	p.Done()
	if rep := h.report(); !strings.Contains(rep.Changes[0].Detail, "50") {
		t.Errorf("report = %+v", rep)
	}

	p = prompttest.New(t, "300", "500")
	h.rt.Picker = p
	if err := h.run("ec2", "volume", "resize", "vol-0222"); err != nil {
		t.Fatalf("resize: %v", err)
	}
	p.Done()
	if rep := h.report(); !strings.Contains(rep.Changes[0].Detail, "500") {
		t.Errorf("report = %+v", rep)
	}

	// The non-interactive flow is unchanged.
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("ec2", "volume", "create", "x", "--az", "ap-east-1a"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("non-interactive create = %v", err)
	}
	if err := h.run("ec2", "volume", "resize", "vol-0222"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("non-interactive resize = %v", err)
	}
}

// A volume name held by several volumes is a pick.
func TestVolumeAmbiguousPick(t *testing.T) {
	h := volumePickHarness(t, app.Flags{})
	h.addVolume("ap-east-1", &fakeVol{id: "vol-0666", name: "orphan", size: 16, typ: "gp3"})
	p := prompttest.New(t, prompttest.Label("vol-0666"))
	h.rt.Picker = p
	if err := h.run("ec2", "volume", "get", "orphan"); err != nil || !strings.Contains(h.stdout.String(), "vol-0666") {
		t.Errorf("get = %v, %s", err, h.stdout.String())
	}
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	var amb *app.AmbiguousError
	if err := h.run("ec2", "volume", "get", "orphan"); !errors.As(err, &amb) {
		t.Errorf("non-interactive = %v", err)
	}
}

// resize --instance with a --device no volume of the instance is attached
// as: the volumes are a list to choose from on a terminal.
func TestVolumeResizeByInstanceListsTheVolumes(t *testing.T) {
	h := volumePickHarness(t, app.Flags{DryRun: true})
	p := prompttest.New(t, prompttest.Label("vol-0222"))
	h.rt.Picker = p
	if err := h.run("ec2", "volume", "resize", "--instance", "site-xz7", "--device", "/dev/sdc", "--size", "500"); err != nil {
		t.Fatalf("resize: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	a := p.Asked[0]
	if !strings.HasPrefix(a.Title, "Ambiguous volume of instance") || len(a.Options) < 2 || !strings.Contains(prompttest.Labels(a.Options), "/dev/sdb") {
		t.Errorf("asked %q with %s", a.Title, prompttest.Labels(a.Options))
	}
	if rep := h.report(); rep.Changes[0].ID != "vol-0222" {
		t.Errorf("report = %+v", rep)
	}
}
