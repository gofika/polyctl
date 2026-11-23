package aws

import (
	"errors"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

func snapIDs(rows []snapshotInfo) string {
	var out []string
	for _, r := range rows {
		out = append(out, r.ID)
	}
	return strings.Join(out, ",")
}

func TestSnapshotList(t *testing.T) {
	h := newVolumeHarness(t, app.Flags{})
	h.ebs().snapPage = 1 // every snapshot on a page of its own
	day := func(d int) time.Time { return time.Date(2026, 1, d, 0, 0, 0, 0, time.UTC) }
	h.addSnap("ap-east-1", &fakeSnap{id: "snap-01", volID: "vol-0222", size: 400, start: day(1), desc: "old"})
	h.addSnap("ap-east-1", &fakeSnap{id: "snap-03", volID: "vol-0222", size: 400, start: day(3), state: snapPending, progress: "40%"})
	h.addSnap("ap-east-1", &fakeSnap{id: "snap-02", volID: "vol-0222", size: 400, start: day(2),
		tags: []ec2types.Tag{{Key: awssdk.String("Name"), Value: awssdk.String("site-xz7-data-20260102T0000Z")}}})
	h.addSnap("ap-east-1", &fakeSnap{id: "snap-09", volID: "vol-0111", size: 30, start: day(9)})

	if err := h.run("ec2", "snapshot", "list"); err != nil {
		t.Fatalf("list: %v", err)
	}
	var rows []snapshotInfo
	h.jsonOut(&rows)
	if got := snapIDs(rows); got != "snap-09,snap-03,snap-02,snap-01" {
		t.Errorf("newest first = %s", got)
	}
	if n := h.ec2.count("DescribeSnapshots"); n < 4 {
		t.Errorf("pages read = %d", n)
	}
	for _, owners := range h.ebs().snapOwners {
		if len(owners) != 1 || owners[0] != "self" {
			t.Errorf("OwnerIds = %v", owners)
		}
	}
	for args, want := range map[string]string{
		"--volume vol-0222":                            "snap-03,snap-02,snap-01",
		"--volume site-xz7-data --latest":              "snap-02",
		"--state pending":                              "snap-03",
		"--name site-xz7-*":                            "snap-02",
		"--volume vol-0111 --state error":              "",
		"--volume vol-0222 --state completed --latest": "snap-02",
	} {
		if err := h.run(append([]string{"ec2", "snapshot", "list"}, strings.Fields(args)...)...); err != nil {
			t.Fatalf("list %s: %v", args, err)
		}
		var rows []snapshotInfo
		h.jsonOut(&rows)
		if got := snapIDs(rows); got != want {
			t.Errorf("list %s = %q, want %q", args, got, want)
		}
	}
	if err := h.run("ec2", "snapshot", "list", "--volume", "vol-0222", "--latest"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&rows)
	if r := rows[0]; r.VolumeID != "vol-0222" || r.Size != 400 || r.State != snapCompleted || r.Progress != "100%" || r.Profile != "lab" ||
		r.Region != "ap-east-1" || r.StartTime != "2026-01-02T00:00:00Z" || r.Name != "site-xz7-data-20260102T0000Z" {
		t.Errorf("row = %+v", r)
	}
	if err := h.run("ec2", "snapshot", "list", "--state", "done"); !isUsage(err) {
		t.Errorf("bad state = %v", err)
	}
	// The id of a volume AWS no longer has still lists its snapshots (they
	// outlive it): no match is an empty list and exit code 0.
	h.addSnap("ap-east-1", &fakeSnap{id: "snap-0dead", volID: "vol-0999", size: 8, start: day(4)})
	if err := h.run("ec2", "snapshot", "list", "--volume", "vol-0999"); err != nil {
		t.Fatalf("deleted volume: %v", err)
	}
	h.jsonOut(&rows)
	if got := snapIDs(rows); got != "snap-0dead" {
		t.Errorf("deleted volume = %q", got)
	}
	// One the inventory knew: listed where the inventory saw it.
	h.addVolume("ap-east-1", &fakeVol{id: "vol-0777", size: 8, next: []string{"gone"}})
	h.addSnap("ap-east-1", &fakeSnap{id: "snap-0777", volID: "vol-0777", size: 8, start: day(5)})
	if err := h.run("ec2", "volume", "get", "vol-0777", "--region", "ap-east-1"); err != nil {
		t.Fatal(err)
	}
	if err := h.run("ec2", "snapshot", "list", "--volume", "vol-0777"); err != nil {
		t.Fatalf("gone volume: %v", err)
	}
	h.jsonOut(&rows)
	if got := snapIDs(rows); got != "snap-0777" || rows[0].Region != "ap-east-1" {
		t.Errorf("gone volume = %+v", rows)
	}
	if err := h.run("ec2", "snapshot", "list", "--volume", "vol-0998"); err != nil {
		t.Fatalf("unknown volume: %v", err)
	}
	h.jsonOut(&rows)
	if len(rows) != 0 {
		t.Errorf("unknown volume = %+v", rows)
	}
	// A name that matches no volume is still not found.
	if err := h.run("ec2", "snapshot", "list", "--volume", "no-such-volume"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("unknown name = %v", err)
	}
}

func TestSnapshotCreate(t *testing.T) {
	h := newVolumeHarness(t, app.Flags{})
	h.ebs().snapNext = []string{snapPending, snapCompleted}
	if err := h.run("ec2", "snapshot", "create", "vol-0222", "--description", "before resize", "--tag", "team=ops", "--wait"); err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	rep := h.report()
	// The fake clock starts at 2026-01-01T00:00Z.
	if c := rep.Changes[0]; c.Resource != "snapshot/site-xz7-data-20260101T0000Z" || c.Action != platform.Created || c.ID != "snap-0new1" ||
		c.Detail != "snapshot of vol-0222; completed" {
		t.Errorf("report = %+v", rep)
	}
	in := h.ebs().snapCreates[0]
	if awssdk.ToString(in.Description) != "before resize" || tagValue(in.TagSpecifications[0].Tags, "team") != "ops" || in.TagSpecifications[0].ResourceType != "snapshot" {
		t.Errorf("CreateSnapshot = %+v", in)
	}
	if !strings.Contains(h.stderr.String(), "crash-consistent") {
		t.Errorf("note:\n%s", h.stderr.String())
	}
	// --tag Name=... replaces the default name; without --wait the state
	// is pending.
	if err := h.run("ec2", "snapshot", "create", "vol-0111", "--tag", "Name=root-before"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); rep.Changes[0].Resource != "snapshot/root-before" || rep.Changes[0].Detail != "snapshot of vol-0111; pending" {
		t.Errorf("named = %+v", rep)
	}
	// One in progress already: exit code 1.
	err := h.run("ec2", "snapshot", "create", "vol-0111")
	if err == nil || isUsage(err) || !strings.Contains(err.Error(), "in progress") {
		t.Errorf("rate = %v", err)
	}
	// --dry-run writes nothing.
	h.ec2.reset()
	h.rt.Flags.DryRun = true
	if err := h.run("ec2", "snapshot", "create", "site-xz7-data"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); rep.Changes[0].Action != platform.WouldCreate || rep.Changes[0].Detail != "snapshot of vol-0222" || len(h.ebsWrites()) != 0 {
		t.Errorf("dry run = %+v, writes %v", rep, h.ebsWrites())
	}
}

func TestSnapshotCreateWaitError(t *testing.T) {
	h := newVolumeHarness(t, app.Flags{})
	h.ebs().snapNext = []string{snapPending, snapError}
	if err := h.run("ec2", "snapshot", "create", "vol-0222", "--wait"); err == nil || isUsage(err) || !strings.Contains(err.Error(), "error") {
		t.Errorf("error state = %v", err)
	}
}
