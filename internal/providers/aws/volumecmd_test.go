package aws

import (
	"context"
	"errors"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

// newVolumeHarness is an AWS harness with a running instance site-xz7
// (i-0aaaaaaaaaaaaaaa1, no instance volumes of the fake) and two volumes:
// the root volume and the data volume vol-0222 (site-xz7-data, 400GB gp3,
// /dev/sdb).
func newVolumeHarness(t *testing.T, flags app.Flags) *awsHarness {
	t.Helper()
	h := newInstanceHarness(t, flags)
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa1", name: "site-xz7", typ: "t3.nano", state: stateRunning})
	h.addVolume("ap-east-1", &fakeVol{id: "vol-0111", size: 30, iops: 3000, throughput: 125, instance: "i-0aaaaaaaaaaaaaaa1", device: "/dev/xvda", dot: true})
	h.addVolume("ap-east-1", &fakeVol{id: "vol-0222", name: "site-xz7-data", size: 400, iops: 3000, throughput: 125, snapshot: "snap-0aaa",
		instance: "i-0aaaaaaaaaaaaaaa1", device: "/dev/sdb"})
	return h
}

func (h *awsHarness) volumeRows(profile string) []inventory.Resource {
	h.t.Helper()
	db, err := h.rt.DB()
	if err != nil {
		h.t.Fatal(err)
	}
	rows, err := db.List(context.Background(), inventory.Query{Platform: platform.AWS, Profile: profile, Type: platform.ResVolume})
	if err != nil {
		h.t.Fatal(err)
	}
	return rows
}

func rowIDs(rows []volumeRow) string {
	var out []string
	for _, r := range rows {
		out = append(out, r.ID)
	}
	return strings.Join(out, ",")
}

func TestVolumeList(t *testing.T) {
	h := newVolumeHarness(t, app.Flags{})
	h.addVolume("ap-east-1", &fakeVol{id: "vol-0333", name: "orphan", size: 8, typ: "gp2", az: "ap-east-1b"})
	h.addVolume("us-west-2", &fakeVol{id: "vol-0444", size: 8})

	if err := h.run("ec2", "volume", "list"); err != nil {
		t.Fatalf("list: %v\n%s", err, h.stderr.String())
	}
	var rows []volumeRow
	h.jsonOut(&rows)
	if got := rowIDs(rows); got != "vol-0111,vol-0222,vol-0333" {
		t.Errorf("list = %s", got)
	}
	if r := rows[1]; r.Name != "site-xz7-data" || r.Size != 400 || r.Type != "gp3" || r.Iops != 3000 || r.Throughput != 125 || r.State != volInUse ||
		r.InstanceID != "i-0aaaaaaaaaaaaaaa1" || r.InstanceName != "site-xz7" || r.Device != "/dev/sdb" || r.Profile != "lab" || r.AZ != "ap-east-1a" {
		t.Errorf("row = %+v", r)
	}
	if n := len(h.volumeRows("lab")); n != 3 {
		t.Errorf("inventory rows = %d", n)
	}
	for args, want := range map[string]string{
		"--state available":      "vol-0333",
		"--instance site-xz7":    "vol-0111,vol-0222",
		"--az ap-east-1b":        "vol-0333",
		"--name site-*":          "vol-0222",
		"--region us-west-2":     "vol-0444",
		"--name nothing --az x1": "",
	} {
		if err := h.run(append([]string{"ec2", "volume", "list"}, strings.Fields(args)...)...); err != nil {
			t.Fatalf("list %s: %v", args, err)
		}
		var rows []volumeRow
		h.jsonOut(&rows)
		if got := rowIDs(rows); got != want {
			t.Errorf("list %s = %q, want %q", args, got, want)
		}
	}
	if err := h.run("ec2", "volume", "list", "--state", "nope"); !isUsage(err) {
		t.Errorf("bad state = %v", err)
	}
	if err := h.run("ec2", "volume", "list", "--state", "error"); err != nil || strings.TrimSpace(h.stdout.String()) != "[]" ||
		!strings.Contains(h.stderr.String(), "no matching volumes") {
		t.Errorf("empty = %v %q %q", err, h.stdout.String(), h.stderr.String())
	}
	// The table shows the instance name.
	h.rt.Flags.Output = "table"
	if err := h.rt.Init(); err != nil {
		t.Fatal(err)
	}
	if err := h.run("ec2", "volume", "list", "--name", "site-*"); err != nil {
		t.Fatal(err)
	}
	if out := h.stdout.String(); !strings.Contains(out, "THROUGHPUT") || !strings.Contains(out, "site-xz7 ") || !strings.Contains(out, "/dev/sdb") {
		t.Errorf("table:\n%s", out)
	}
	h.rt.Flags.Output = "json"
	if err := h.rt.Init(); err != nil {
		t.Fatal(err)
	}
	// --offline reads the inventory.
	h.rt.Flags.Offline = true
	h.ec2.reset()
	if err := h.run("ec2", "volume", "list", "--state", "in-use"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&rows)
	if got := rowIDs(rows); got != "vol-0111,vol-0222" || len(h.ec2.calls()) != 0 {
		t.Errorf("offline = %s, calls %v", got, h.ec2.calls())
	}
}

func TestVolumeGet(t *testing.T) {
	h := newVolumeHarness(t, app.Flags{})
	// Never modified: no modification field. Unknown to the inventory: one
	// sync finds the id.
	if err := h.run("ec2", "volume", "get", "vol-0222"); err != nil {
		t.Fatalf("get: %v\n%s", err, h.stderr.String())
	}
	if !strings.Contains(h.stdout.String(), `"volume_id": "vol-0222"`) || strings.Contains(h.stdout.String(), "modification") {
		t.Errorf("get:\n%s", h.stdout.String())
	}
	var d volumeDetail
	h.jsonOut(&d)
	if d.Name != "site-xz7-data" || d.Profile != "lab" || d.Region != "ap-east-1" || d.AvailabilityZone != "ap-east-1a" || d.Size != 400 ||
		d.SnapshotID != "snap-0aaa" || len(d.Attachments) != 1 || d.Attachments[0].InstanceName != "site-xz7" || d.Attachments[0].State != "attached" {
		t.Errorf("detail = %+v", d)
	}
	h.setMod("vol-0222", &fakeMod{state: modOptimizing, progress: 40, origSize: 300, targetSize: 400, origType: "gp3", targetType: "gp3"})
	if err := h.run("ec2", "volume", "get", "site-xz7-data"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&d)
	if m := d.Modification; m == nil || m.State != modOptimizing || m.Progress != 40 || m.OriginalSize != 300 || m.TargetSize != 400 || m.StartTime == "" {
		t.Errorf("modification = %+v", d.Modification)
	}
	// Unknown id and unknown name: exit code 4.
	if err := h.run("ec2", "volume", "get", "vol-0999"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("unknown id = %v", err)
	}
	if err := h.run("ec2", "volume", "get", "nothing"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("unknown name = %v", err)
	}
	// Two volumes of one name: exit code 5.
	h.addVolume("ap-east-1", &fakeVol{id: "vol-0555", name: "site-xz7-data", size: 1})
	if err := h.run("ec2", "volume", "get", "site-xz7-data"); !isAmbiguous(err) {
		t.Errorf("ambiguous = %v", err)
	}
	// --region asks that region directly.
	h.addVolume("us-west-2", &fakeVol{id: "vol-0444", size: 8})
	if err := h.run("ec2", "volume", "get", "vol-0444", "--region", "us-west-2"); err != nil {
		t.Fatal(err)
	}
	// --offline reads the inventory.
	h.rt.Flags.Offline = true
	h.ec2.reset()
	if err := h.run("ec2", "volume", "get", "vol-0222"); err != nil || len(h.ec2.calls()) != 0 {
		t.Errorf("offline = %v, calls %v", err, h.ec2.calls())
	}
}

func TestVolumeIDSearchesOtherAccounts(t *testing.T) {
	h := newVolumeHarness(t, app.Flags{})
	h.addProfile(t)
	h.ec2.find.regions = []string{"ap-east-1", "us-west-2"}
	h.addVolume("us-west-2", &fakeVol{id: "vol-0444", size: 8})
	// lab and prod are one fake account: the id is in both inventories.
	if err := h.run("ec2", "volume", "get", "vol-0444"); !isAmbiguous(err) {
		t.Fatalf("two profiles = %v", err)
	}
	h.rt.Flags.Profile = "prod"
	if err := h.run("ec2", "volume", "get", "vol-0444"); err != nil {
		t.Fatalf("--profile prod: %v", err)
	}
	var d volumeDetail
	h.jsonOut(&d)
	if d.Profile != "prod" || d.Region != "us-west-2" {
		t.Errorf("detail = %+v", d)
	}
}

func TestVolumeCreate(t *testing.T) {
	h := newVolumeHarness(t, app.Flags{})
	h.addSnap("ap-east-1", &fakeSnap{id: "snap-0aaa", volID: "vol-0222", size: 2})

	// From a snapshot, in the zone of --instance, waiting: the size is the
	// snapshot's, gp3 with 3000/125.
	if err := h.run("ec2", "volume", "create", "restore", "--from-snapshot", "snap-0aaa", "--instance", "site-xz7", "--wait"); err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	rep := h.report()
	if c := rep.Changes[0]; c.Resource != "volume/restore" || c.Action != platform.Created || c.ID != "vol-0new1" || !strings.Contains(c.Detail, "available") {
		t.Errorf("report = %+v", rep)
	}
	in := h.ebs().creates[0]
	if awssdk.ToString(in.AvailabilityZone) != "ap-east-1a" || awssdk.ToInt32(in.Size) != 2 || awssdk.ToString(in.SnapshotId) != "snap-0aaa" ||
		awssdk.ToInt32(in.Iops) != 3000 || awssdk.ToInt32(in.Throughput) != 125 || in.VolumeType != "gp3" || in.Encrypted != nil || in.ClientToken == nil {
		t.Errorf("CreateVolume = %+v", in)
	}
	if tagValue(in.TagSpecifications[0].Tags, "Name") != "restore" {
		t.Errorf("tags = %+v", in.TagSpecifications)
	}
	if v := h.vol("ap-east-1", "vol-0new1"); v == nil || v.state != volAvailable {
		t.Errorf("volume = %+v", v)
	}
	// A smaller --size than the snapshot: usage, nothing written.
	h.ec2.reset()
	if err := h.run("ec2", "volume", "create", "x", "--from-snapshot", "snap-0aaa", "--size", "1", "--az", "ap-east-1a"); !isUsage(err) || len(h.ebsWrites()) != 0 {
		t.Errorf("smaller = %v, writes %v", err, h.ebsWrites())
	}
	// The name is taken: exit code 1.
	if err := h.run("ec2", "volume", "create", "restore", "--size", "5", "--az", "ap-east-1a"); err == nil || isUsage(err) || len(h.ebsWrites()) != 0 {
		t.Errorf("taken = %v", err)
	}
	// gp2 sends neither IOPS nor throughput; no name, no wait.
	if err := h.run("ec2", "volume", "create", "--size", "5", "--az", "ap-east-1b", "--type", "gp2"); err != nil {
		t.Fatal(err)
	}
	in = h.ebs().creates[1]
	if in.Iops != nil || in.Throughput != nil || awssdk.ToInt32(in.Size) != 5 || len(in.TagSpecifications) != 0 {
		t.Errorf("gp2 = %+v", in)
	}
	if rep := h.report(); rep.Changes[0].Resource != "volume/(pending)" || rep.Changes[0].ID != "vol-0new2" {
		t.Errorf("unnamed = %+v", rep)
	}
	// Usage errors.
	for _, args := range [][]string{
		{"--az", "ap-east-1a"}, // neither size nor snapshot
		{"--size", "5"},        // no zone
		{"--size", "5", "--az", "ap-east-1a", "--instance", "site-xz7"},
		{"--size", "5", "--az", "ap-east-1a", "--type", "io2"}, // io2 without --iops
		{"--size", "5", "--az", "ap-east-1a", "--type", "gp2", "--iops", "100"},
		{"--size", "5", "--az", "ap-east-1a", "--type", "nvme"},
		{"--size", "5", "--az", "nowhere"},
	} {
		if err := h.run(append([]string{"ec2", "volume", "create"}, args...)...); !isUsage(err) {
			t.Errorf("create %v = %v", args, err)
		}
	}
	// io2 with --iops sends IOPS only.
	if err := h.run("ec2", "volume", "create", "--size", "5", "--az", "ap-east-1a", "--type", "io2", "--iops", "4000"); err != nil {
		t.Fatal(err)
	}
	if in := h.ebs().creates[2]; awssdk.ToInt32(in.Iops) != 4000 || in.Throughput != nil {
		t.Errorf("io2 = %+v", in)
	}
	// A missing snapshot: exit code 4.
	if err := h.run("ec2", "volume", "create", "--from-snapshot", "snap-0999", "--az", "ap-east-1a"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing snapshot = %v", err)
	}
	// --dry-run writes nothing.
	h.ec2.reset()
	h.rt.Flags.DryRun = true
	if err := h.run("ec2", "volume", "create", "dry", "--from-snapshot", "snap-0aaa", "--az", "ap-east-1a"); err != nil {
		t.Fatal(err)
	}
	rep = h.report()
	if c := rep.Changes[0]; !rep.DryRun || c.Action != platform.WouldCreate || c.ID != platform.Pending ||
		c.Detail != "size=2 type=gp3 iops=3000 throughput=125 az=ap-east-1a from snapshot snap-0aaa" || len(h.ebsWrites()) != 0 {
		t.Errorf("dry run = %+v, writes %v", rep, h.ebsWrites())
	}
}

func TestVolumeCreateWaitError(t *testing.T) {
	h := newVolumeHarness(t, app.Flags{})
	h.ebs().createNext = []string{volCreating, volError}
	err := h.run("ec2", "volume", "create", "bad", "--size", "5", "--az", "ap-east-1a", "--wait")
	if err == nil || isUsage(err) || !strings.Contains(err.Error(), "did not become available") {
		t.Errorf("error state = %v", err)
	}
}

func isAmbiguous(err error) bool {
	var amb *app.AmbiguousError
	return errors.As(err, &amb)
}
