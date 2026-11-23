package aws

import (
	"errors"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

func TestVolumeAttach(t *testing.T) {
	h := newVolumeHarness(t, app.Flags{})
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa2", name: "site-tmp", typ: "t3.nano", state: stateRunning})
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa3", name: "far", typ: "t3.nano", state: stateRunning, az: "ap-east-1b"})
	// A volume still being created is waited for, then attached; the wait
	// goes on until the attachment is attached, not only in-use.
	h.addVolume("ap-east-1", &fakeVol{id: "vol-0333", name: "restore", size: 2, snapshot: "snap-0aaa", state: volCreating, next: []string{volCreating, volAvailable}})
	if err := h.run("ec2", "volume", "attach", "restore", "--instance", "site-tmp"); err != nil {
		t.Fatalf("attach: %v\n%s", err, h.stderr.String())
	}
	rep := h.report()
	if c := rep.Changes[0]; c.Action != platform.Updated || c.Detail != "attach vol-0333 -> i-0aaaaaaaaaaaaaaa2 as /dev/sdb; attached" {
		t.Errorf("report = %+v", rep)
	}
	if v := h.vol("ap-east-1", "vol-0333"); v.attachState != "attached" || v.instance != "i-0aaaaaaaaaaaaaaa2" {
		t.Errorf("volume = %+v", v)
	}
	if s := h.stderr.String(); !strings.Contains(s, "NVMe") || !strings.Contains(s, "first access") {
		t.Errorf("notes:\n%s", s)
	}
	// Again: unchanged, no write.
	h.ec2.reset()
	if err := h.run("ec2", "volume", "attach", "vol-0333", "--instance", "site-tmp", "--device", "/dev/sdb"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); rep.Changes[0].Action != platform.Unchanged || len(h.ebsWrites()) != 0 {
		t.Errorf("second = %+v, writes %v", rep, h.ebsWrites())
	}
	// Attached elsewhere: exit code 1.
	if err := h.run("ec2", "volume", "attach", "vol-0222", "--instance", "site-tmp"); err == nil || isUsage(err) || !strings.Contains(err.Error(), "detach it first") {
		t.Errorf("elsewhere = %v", err)
	}
	// Another zone: exit code 1 before any write.
	h.addVolume("ap-east-1", &fakeVol{id: "vol-0444", size: 2})
	if err := h.run("ec2", "volume", "attach", "vol-0444", "--instance", "far"); err == nil || isUsage(err) || !strings.Contains(err.Error(), "availability zone") || len(h.ebsWrites()) != 0 {
		t.Errorf("zone = %v, writes %v", err, h.ebsWrites())
	}
	// A device in use: exit code 2.
	if err := h.run("ec2", "volume", "attach", "vol-0444", "--instance", "site-xz7"); !errors.Is(err, platform.ErrInvalidInput) || len(h.ebsWrites()) != 0 {
		t.Errorf("device in use = %v", err)
	}
	// --dry-run writes nothing.
	h.rt.Flags.DryRun = true
	if err := h.run("ec2", "volume", "attach", "vol-0444", "--instance", "site-xz7", "--device", "/dev/sdc"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); rep.Changes[0].Action != platform.WouldUpdate || rep.Changes[0].Detail != "attach vol-0444 -> i-0aaaaaaaaaaaaaaa1 as /dev/sdc" || len(h.ebsWrites()) != 0 {
		t.Errorf("dry run = %+v", rep)
	}
	// A volume an earlier step of the dry run would create: (pending).
	if err := h.run("ec2", "volume", "attach", "not-yet", "--instance", "site-xz7"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); rep.Changes[0].ID != platform.Pending || rep.Changes[0].Action != platform.WouldUpdate {
		t.Errorf("pending = %+v", rep)
	}
	h.rt.Flags.DryRun = false
	// --no-wait sends the request only.
	h.ec2.reset()
	if err := h.run("ec2", "volume", "attach", "vol-0444", "--instance", "site-xz7", "--device", "/dev/sdc", "--no-wait"); err != nil {
		t.Fatal(err)
	}
	if in := h.ebs().attaches[len(h.ebs().attaches)-1]; awssdk.ToString(in.Device) != "/dev/sdc" || awssdk.ToString(in.InstanceId) != "i-0aaaaaaaaaaaaaaa1" {
		t.Errorf("AttachVolume = %+v", in)
	}
	if err := h.run("ec2", "volume", "attach", "vol-0444"); !isUsage(err) {
		t.Errorf("no --instance = %v", err)
	}
}

func TestVolumeDetach(t *testing.T) {
	h := newVolumeHarness(t, app.Flags{})
	// Non-interactive without --yes: exit code 2, nothing written; the
	// warning about unmounting is shown.
	if err := h.run("ec2", "volume", "detach", "site-xz7-data"); !isUsage(err) || len(h.ebsWrites()) != 0 {
		t.Errorf("no --yes = %v", err)
	}
	if !strings.Contains(h.stderr.String(), "Unmount") {
		t.Errorf("warning:\n%s", h.stderr.String())
	}
	// --force without --yes: exit code 2.
	if err := h.run("ec2", "volume", "detach", "vol-0222", "--force"); !isUsage(err) {
		t.Errorf("--force = %v", err)
	}
	// The root volume: exit code 1.
	h.rt.Flags.Yes = true
	if err := h.run("ec2", "volume", "detach", "vol-0111"); err == nil || isUsage(err) || !strings.Contains(err.Error(), "root volume") || len(h.ebsWrites()) != 0 {
		t.Errorf("root = %v", err)
	}
	// --dry-run --yes neither asks nor writes.
	h.rt.Flags.DryRun = true
	if err := h.run("ec2", "volume", "detach", "vol-0222"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); rep.Changes[0].Action != platform.WouldUpdate || !strings.HasPrefix(rep.Changes[0].Detail, "detach") || len(h.ebsWrites()) != 0 {
		t.Errorf("dry run = %+v", rep)
	}
	h.rt.Flags.DryRun = false
	// --yes detaches and waits until available.
	if err := h.run("ec2", "volume", "detach", "vol-0222"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); rep.Changes[0].Detail != "detach from i-0aaaaaaaaaaaaaaa1 (/dev/sdb); available" {
		t.Errorf("detach = %+v", rep)
	}
	if v := h.vol("ap-east-1", "vol-0222"); v.state != volAvailable || v.instance != "" {
		t.Errorf("volume = %+v", v)
	}
	// Again: unchanged.
	h.ec2.reset()
	if err := h.run("ec2", "volume", "detach", "vol-0222"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); rep.Changes[0].Action != platform.Unchanged || len(h.ebsWrites()) != 0 {
		t.Errorf("second = %+v, writes %v", rep, h.ebsWrites())
	}
	// Being detached already: unchanged, nothing asked or sent, waited for.
	h.rt.Flags.Yes = false
	h.addVolume("ap-east-1", &fakeVol{id: "vol-0666", size: 2, instance: "i-0aaaaaaaaaaaaaaa1", device: "/dev/sdg", attachState: "detaching",
		next: []string{volInUse, volAvailable}})
	h.ec2.reset()
	if err := h.run("ec2", "volume", "detach", "vol-0666"); err != nil {
		t.Fatalf("detaching: %v", err)
	}
	if rep := h.report(); rep.Changes[0].Action != platform.Unchanged || !strings.HasSuffix(rep.Changes[0].Detail, "available") || len(h.ebsWrites()) != 0 {
		t.Errorf("detaching = %+v, writes %v", rep, h.ebsWrites())
	}
	// A stuck detach is forced with --force --yes.
	h.rt.Flags.Yes = true
	h.addVolume("ap-east-1", &fakeVol{id: "vol-0667", size: 2, instance: "i-0aaaaaaaaaaaaaaa1", device: "/dev/sdh", attachState: "detaching"})
	if err := h.run("ec2", "volume", "detach", "vol-0667", "--force", "--no-wait"); err != nil {
		t.Fatalf("forced: %v", err)
	}
	if d := h.ebs().detaches; len(d) == 0 || awssdk.ToString(d[len(d)-1].VolumeId) != "vol-0667" || !awssdk.ToBool(d[len(d)-1].Force) {
		t.Errorf("DetachVolume = %+v", d)
	}
	// VolumeInUse inside the instance is explained.
	h.addVolume("ap-east-1", &fakeVol{id: "vol-0555", size: 2, instance: "i-0aaaaaaaaaaaaaaa1", device: "/dev/sdf"})
	h.ebsSetErr("DetachVolume", &fakeAPIError{"VolumeInUse", "busy"})
	if err := h.run("ec2", "volume", "detach", "vol-0555"); err == nil || !strings.Contains(err.Error(), "unmount") {
		t.Errorf("in use = %v", err)
	}
}

func TestVolumeDetachInteractiveDeclined(t *testing.T) {
	h := newVolumeHarness(t, app.Flags{NonInteractiveSet: true})
	h.rt.Picker = &scriptedPicker{t: t}
	h.rt.Flags.NonInteractive = false
	err := h.run("ec2", "volume", "detach", "vol-0222")
	if err != nil && !errors.Is(err, platform.ErrNothingToDo) {
		t.Errorf("declined = %v", err)
	}
	if w := h.ebsWrites(); len(w) != 0 {
		t.Errorf("declined but wrote: %v", w)
	}
}

func TestVolumeDelete(t *testing.T) {
	h := newVolumeHarness(t, app.Flags{})
	h.addVolume("ap-east-1", &fakeVol{id: "vol-0333", name: "orphan", size: 8})
	// Attached: exit code 1.
	h.rt.Flags.Yes = true
	if err := h.run("ec2", "volume", "delete", "vol-0222"); err == nil || isUsage(err) || !strings.Contains(err.Error(), "detach it first") || len(h.ebsWrites()) != 0 {
		t.Errorf("in use = %v", err)
	}
	// Non-interactive without --yes: exit code 2; the volume has no
	// snapshot, which is warned about.
	h.rt.Flags.Yes = false
	if err := h.run("ec2", "volume", "delete", "orphan"); !isUsage(err) || len(h.ebsWrites()) != 0 {
		t.Errorf("no --yes = %v", err)
	}
	if !strings.Contains(h.stderr.String(), "no snapshot") {
		t.Errorf("warning:\n%s", h.stderr.String())
	}
	// With a snapshot, it is named; --dry-run writes nothing.
	h.addSnap("ap-east-1", &fakeSnap{id: "snap-0bbb", volID: "vol-0333", size: 8})
	h.rt.Flags.DryRun, h.rt.Flags.Yes = true, true
	if err := h.run("ec2", "volume", "delete", "orphan"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); rep.Changes[0].Action != platform.WouldDelete || len(h.ebsWrites()) != 0 || !strings.Contains(h.stderr.String(), "snap-0bbb") {
		t.Errorf("dry run = %+v\n%s", rep, h.stderr.String())
	}
	h.rt.Flags.DryRun = false
	if err := h.run("ec2", "volume", "delete", "orphan"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); rep.Changes[0].Action != platform.Deleted || rep.Changes[0].ID != "vol-0333" {
		t.Errorf("delete = %+v", rep)
	}
	// Being deleted: unchanged without a write. Then gone: unchanged too.
	h.ec2.reset()
	if err := h.run("ec2", "volume", "delete", "vol-0333", "--region", "ap-east-1"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); rep.Changes[0].Action != platform.Unchanged || len(h.ebsWrites()) != 0 {
		t.Errorf("deleting = %+v, writes %v", rep, h.ebsWrites())
	}
	if h.vol("ap-east-1", "vol-0333") != nil {
		t.Fatal("the fake volume should be gone after one more read")
	}
	// The inventory still knows the id (stored above): gone is unchanged.
	if err := h.run("ec2", "volume", "delete", "vol-0333"); err != nil {
		t.Fatalf("gone: %v", err)
	}
	if rep := h.report(); rep.Changes[0].Action != platform.Unchanged || len(h.ebsWrites()) != 0 {
		t.Errorf("gone = %+v", rep)
	}
	// Unknown everywhere: exit code 4.
	if err := h.run("ec2", "volume", "delete", "vol-0999"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("unknown = %v", err)
	}
	// DeleteVolume answering NotFound (deleted meanwhile): unchanged.
	h.addVolume("ap-east-1", &fakeVol{id: "vol-0666", size: 1})
	h.ebsSetErr("DeleteVolume", &fakeAPIError{"InvalidVolume.NotFound", "gone"})
	if err := h.run("ec2", "volume", "delete", "vol-0666", "--region", "ap-east-1"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); rep.Changes[0].Action != platform.Unchanged {
		t.Errorf("deleted meanwhile = %+v", rep)
	}
}
