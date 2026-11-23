package aws

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

func TestRateLimitUntil(t *testing.T) {
	msg := "You've reached the maximum modification rate per volume limit. Wait until 2026-01-02T03:04:05.000Z before you can issue the next modification request for this volume."
	got, ok := rateLimitUntil(msg)
	if !ok || !got.Equal(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Errorf("rateLimitUntil = %v, %v", got, ok)
	}
	if _, ok := rateLimitUntil("slow down"); ok {
		t.Error("a message without a time must not parse")
	}
	err := modifyErr("vol-0222", "ap-east-1", &fakeAPIError{"VolumeModificationRateExceeded", msg})
	if !strings.Contains(err.Error(), "after 2026-01-02T03:04:05Z") || errors.Is(err, platform.ErrInvalidInput) {
		t.Errorf("modifyErr = %v", err)
	}
}

func TestVolumeSpecCreateInput(t *testing.T) {
	in := volumeSpec{AZ: "ap-east-1a", Type: "gp3", Size: 10, Iops: 3000, Throughput: 125, Tags: map[string]string{"Name": "data"}}.createInput()
	if awssdk.ToInt32(in.Iops) != 3000 || awssdk.ToInt32(in.Throughput) != 125 || awssdk.ToInt32(in.Size) != 10 || in.Encrypted != nil || in.SnapshotId != nil {
		t.Errorf("gp3 input = %+v", in)
	}
	if len(in.TagSpecifications) != 1 || in.TagSpecifications[0].ResourceType != "volume" {
		t.Errorf("tags = %+v", in.TagSpecifications)
	}
	in = volumeSpec{AZ: "ap-east-1a", Type: "gp2", Snapshot: "snap-0aaa"}.createInput()
	if in.Iops != nil || in.Throughput != nil || in.Size != nil || awssdk.ToString(in.SnapshotId) != "snap-0aaa" || in.TagSpecifications != nil {
		t.Errorf("gp2 input = %+v", in)
	}
}

func TestLatestModificationNotFoundIsNone(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{})
	h.addVolume("ap-east-1", &fakeVol{id: "vol-0222", size: 10})
	c, err := openProfile(context.Background(), h.rt, "lab")
	if err != nil {
		t.Fatal(err)
	}
	m, err := c.latestModification(context.Background(), "ap-east-1", "vol-0222")
	if err != nil || m != nil {
		t.Fatalf("never modified = %v, %v", m, err)
	}
	h.setMod("vol-0222", &fakeMod{state: modOptimizing, progress: 40, origSize: 10, targetSize: 20})
	m, err = c.latestModification(context.Background(), "ap-east-1", "vol-0222")
	if err != nil || m == nil || string(m.ModificationState) != modOptimizing {
		t.Fatalf("modification = %v, %v", m, err)
	}
}

func TestWaitModification(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{})
	h.addVolume("ap-east-1", &fakeVol{id: "vol-0222", size: 10})
	c, err := openProfile(context.Background(), h.rt, "lab")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// Not visible at first, then modifying, then optimizing: done.
	h.setMod("vol-0222", &fakeMod{state: modModifying, hidden: 1, next: []string{modModifying, modOptimizing, modCompleted}})
	m, err := c.waitModification(ctx, "ap-east-1", "vol-0222", false, time.Minute)
	if err != nil || string(m.ModificationState) != modOptimizing {
		t.Fatalf("wait to optimizing = %v, %v", modProgress(m), err)
	}
	// --wait-complete goes on to completed.
	m, err = c.waitModification(ctx, "ap-east-1", "vol-0222", true, time.Minute)
	if err != nil || string(m.ModificationState) != modCompleted {
		t.Fatalf("wait to completed = %v, %v", modProgress(m), err)
	}
	// failed fails at once.
	h.setMod("vol-0222", &fakeMod{state: modFailed})
	if _, err := c.waitModification(ctx, "ap-east-1", "vol-0222", false, time.Minute); err == nil || !strings.Contains(err.Error(), "failed") {
		t.Fatalf("failed modification = %v", err)
	}
	// A timeout names the last status.
	h.setMod("vol-0222", &fakeMod{state: modModifying, progress: 7})
	var te *platform.WaitTimeoutError
	if _, err := c.waitModification(ctx, "ap-east-1", "vol-0222", false, 20*time.Second); !errors.As(err, &te) || !strings.Contains(te.LastStatus, "modifying 7%") {
		t.Fatalf("timeout = %v", err)
	}
	// One transient failure is retried, three in a row are not.
	h.setMod("vol-0222", &fakeMod{state: modCompleted})
	h.ebsSetErr("DescribeVolumesModifications", &fakeAPIError{"RequestLimitExceeded", "slow down"})
	if _, err := c.waitModification(ctx, "ap-east-1", "vol-0222", false, time.Minute); err == nil || !strings.Contains(err.Error(), "RequestLimitExceeded") {
		t.Fatalf("persistent failure = %v", err)
	}
	if n := h.ec2.count("DescribeVolumesModifications"); n < waitErrorBudget {
		t.Errorf("polls before giving up = %d", n)
	}
}

func TestTolerant(t *testing.T) {
	var tol tolerant
	e := errors.New("x")
	if tol.check(e) != nil || tol.check(e) != nil || tol.check(e) == nil {
		t.Error("the third failure in a row must end the wait")
	}
	tol = tolerant{}
	if tol.check(e) != nil || tol.check(nil) != nil || tol.check(e) != nil {
		t.Error("a success resets the count")
	}
	if tol.check(platform.ErrUnauthorized) == nil {
		t.Error("credential errors are never retried")
	}
}

func TestSyncVolumesEveryRegion(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{})
	h.ec2.find.regions = []string{"ap-east-1", "us-west-2"}
	h.addVolume("ap-east-1", &fakeVol{id: "vol-0a", name: "a", size: 10})
	h.addVolume("us-west-2", &fakeVol{id: "vol-0b", size: 20})
	c, err := openProfile(context.Background(), h.rt, "lab")
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Sync(context.Background(), platform.ResVolume)
	if err != nil || len(res) != 2 {
		t.Fatalf("sync = %v, %v", res, err)
	}
	for _, r := range res {
		v := r.Data.(volumeInfo)
		if r.Type != platform.ResVolume || r.ParentID != v.Region || (v.ID == "vol-0a") != (v.Region == "ap-east-1") {
			t.Errorf("resource = %+v", r)
		}
	}
}
