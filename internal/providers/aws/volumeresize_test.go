package aws

import (
	"errors"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

func TestVolumeResize(t *testing.T) {
	h := newVolumeHarness(t, app.Flags{})
	h.ebs().modNext = []string{modModifying, modOptimizing, modCompleted}

	// A fresh modification: one ModifyVolume with the fields given, a wait
	// that ends at optimizing, and the file system hint.
	if err := h.run("ec2", "volume", "resize", "vol-0222", "--size", "500", "--iops", "0"); err != nil {
		t.Fatalf("resize: %v\n%s", err, h.stderr.String())
	}
	rep := h.report()
	if c := rep.Changes[0]; c.Resource != "volume/vol-0222" || c.Action != platform.Updated || c.Detail != "size 400 -> 500, iops 3000 -> 0 (optimizing)" {
		t.Errorf("report = %+v", rep)
	}
	if n := len(h.ebs().modifies); n != 1 {
		t.Fatalf("ModifyVolume calls = %d", n)
	}
	in := h.ebs().modifies[0]
	if awssdk.ToInt32(in.Size) != 500 || in.Iops == nil || *in.Iops != 0 || in.Throughput != nil || in.VolumeType != "" {
		t.Errorf("ModifyVolume = %+v (iops 0 must be sent)", in)
	}
	if s := h.stderr.String(); !strings.Contains(s, "resize2fs /dev/nvme1n1") || !strings.Contains(s, "xfs_growfs /") {
		t.Errorf("hint:\n%s", s)
	}

	// The same command again while the modification is optimizing: the
	// size is reached, so unchanged without any write.
	h.ec2.reset()
	if err := h.run("ec2", "volume", "resize", "vol-0222", "--size", "500"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); rep.Changes[0].Action != platform.Unchanged || len(h.ebsWrites()) != 0 {
		t.Errorf("second run = %+v, writes %v", rep, h.ebsWrites())
	}

	// Another change while optimizing: exit code 1, nothing sent (also in
	// a dry run).
	h.setMod("vol-0222", &fakeMod{state: modOptimizing, progress: 40})
	for _, dry := range []bool{false, true} {
		h.rt.Flags.DryRun = dry
		err := h.run("ec2", "volume", "resize", "vol-0222", "--size", "600")
		if err == nil || isUsage(err) || !strings.Contains(err.Error(), "optimizing 40%") || len(h.ebsWrites()) != 0 {
			t.Errorf("optimizing (dry %v) = %v, writes %v", dry, err, h.ebsWrites())
		}
	}
	h.rt.Flags.DryRun = false

	// A shrink: exit code 2.
	h.setMod("vol-0222", &fakeMod{state: modCompleted})
	if err := h.run("ec2", "volume", "resize", "vol-0222", "--size", "100"); !isUsage(err) || len(h.ebsWrites()) != 0 {
		t.Errorf("shrink = %v", err)
	}
	// io2 without --iops on a gp3 volume: exit code 2.
	if err := h.run("ec2", "volume", "resize", "vol-0222", "--type", "io2"); !isUsage(err) {
		t.Errorf("io2 = %v", err)
	}
	// Nothing to change asked: exit code 2.
	if err := h.run("ec2", "volume", "resize", "vol-0222"); !isUsage(err) {
		t.Errorf("no field = %v", err)
	}

	// --dry-run reports the change and writes nothing.
	h.rt.Flags.DryRun = true
	if err := h.run("ec2", "volume", "resize", "site-xz7-data", "--size", "600", "--iops", "4000"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); !rep.DryRun || rep.Changes[0].Action != platform.WouldUpdate || rep.Changes[0].Detail != "size 500 -> 600, iops 0 -> 4000" || len(h.ebsWrites()) != 0 {
		t.Errorf("dry run = %+v, writes %v", rep, h.ebsWrites())
	}
	h.rt.Flags.DryRun = false

	// --no-wait returns after the request.
	h.ec2.reset()
	if err := h.run("ec2", "volume", "resize", "vol-0222", "--size", "600", "--no-wait"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); rep.Changes[0].Detail != "size 500 -> 600 (modifying)" || h.ec2.count("DescribeVolumesModifications") != 1 {
		t.Errorf("no wait = %+v, %v", rep, h.ec2.calls())
	}
}

func TestVolumeResizeWaitComplete(t *testing.T) {
	h := newVolumeHarness(t, app.Flags{})
	h.ebs().modNext = []string{modOptimizing, modOptimizing, modCompleted}
	h.ebs().modHidden = 1 // the first poll does not see the modification yet
	if err := h.run("ec2", "volume", "resize", "vol-0222", "--type", "gp2", "--wait-complete"); err != nil {
		t.Fatalf("resize: %v", err)
	}
	if rep := h.report(); rep.Changes[0].Detail != "type gp3 -> gp2 (completed)" || strings.Contains(h.stderr.String(), "resize2fs") {
		t.Errorf("report = %+v\n%s", rep, h.stderr.String())
	}
	if err := h.run("ec2", "volume", "resize", "vol-0222", "--type", "gp3", "--wait-complete", "--no-wait"); !isUsage(err) {
		t.Errorf("--wait-complete --no-wait = %v", err)
	}
	// A failed modification fails the command.
	h.setMod("vol-0222", &fakeMod{state: modCompleted})
	h.ebs().modNext, h.ebs().modHidden = []string{modFailed}, 0
	if err := h.run("ec2", "volume", "resize", "vol-0222", "--size", "450"); err == nil || isUsage(err) || !strings.Contains(err.Error(), "failed") {
		t.Errorf("failed = %v", err)
	}
}

func TestVolumeResizeRateLimit(t *testing.T) {
	h := newVolumeHarness(t, app.Flags{})
	h.ebsSetErr("ModifyVolume", &fakeAPIError{"VolumeModificationRateExceeded",
		"You've reached the maximum modification rate per volume limit. Wait until 2026-01-03T03:04:05.000Z before you can issue the next modification request for this volume."})
	err := h.run("ec2", "volume", "resize", "vol-0222", "--size", "500")
	if err == nil || isUsage(err) || !strings.Contains(err.Error(), "after 2026-01-03T03:04:05Z") {
		t.Errorf("rate limit = %v", err)
	}
	h.ebsSetErr("ModifyVolume", &fakeAPIError{"IncorrectModificationState", "cannot be modified in modification state MODIFYING"})
	if err := h.run("ec2", "volume", "resize", "vol-0222", "--size", "500"); err == nil || isUsage(err) || !strings.Contains(err.Error(), "being modified") {
		t.Errorf("incorrect state = %v", err)
	}
	h.ebsSetErr("ModifyVolume", &fakeAPIError{"InvalidParameterCombination", "The throughput parameter is not supported for gp2 volumes"})
	if err := h.run("ec2", "volume", "resize", "vol-0222", "--size", "500"); !errors.Is(err, platform.ErrInvalidInput) || !strings.Contains(err.Error(), "not supported for gp2") {
		t.Errorf("parameter combination = %v", err)
	}
}

func TestVolumeResizeByInstance(t *testing.T) {
	h := newVolumeHarness(t, app.Flags{})
	// --device names the data disk.
	if err := h.run("ec2", "volume", "resize", "--instance", "site-xz7", "--device", "/dev/sdb", "--size", "500"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); rep.Changes[0].ID != "vol-0222" {
		t.Errorf("by device = %+v", rep)
	}
	// The default device is the instance's root device (/dev/xvda here,
	// read from the instance, not /dev/sda1).
	if err := h.run("ec2", "volume", "resize", "--instance", "site-xz7", "--size", "40"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); rep.Changes[0].ID != "vol-0111" {
		t.Errorf("root = %+v", rep)
	}
	// A device that no volume has, with several volumes: exit code 2 and
	// the candidates, nothing written.
	h.ec2.reset()
	err := h.run("ec2", "volume", "resize", "--instance", "site-xz7", "--device", "/dev/sdc", "--size", "500")
	if !isUsage(err) || !strings.Contains(err.Error(), "vol-0111") || !strings.Contains(err.Error(), "vol-0222") || len(h.ebsWrites()) != 0 {
		t.Errorf("unknown device = %v", err)
	}
	// Usage errors of the locating flags.
	for _, args := range [][]string{
		{"vol-0222", "--instance", "site-xz7", "--size", "500"},
		{"--size", "500"},
		{"vol-0222", "--device", "/dev/sdb", "--size", "500"},
	} {
		if err := h.run(append([]string{"ec2", "volume", "resize"}, args...)...); !isUsage(err) {
			t.Errorf("resize %v = %v", args, err)
		}
	}
}
