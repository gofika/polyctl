package aws

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

func TestInstanceGet(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{})
	h.addInstance("ap-east-1", running("i-0aaaaaaaaaaaaaaa1", "web-01"))
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa2", name: "stopped-one", typ: "t3.nano", state: stateStopped, priv: "10.0.1.5"})
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa3", name: "gone", typ: "t3.nano", state: stateTerminated})

	if err := h.run("ec2", "instance", "get", "web-01"); err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	h.jsonOut(&d)
	for k, want := range map[string]any{"instance_id": "i-0aaaaaaaaaaaaaaa1", "instance_name": "web-01", "profile": "lab", "region": "ap-east-1",
		"availability_zone": "ap-east-1a", "instance_type": "c6a.large", "state": "running", "platform": "linux", "architecture": "x86_64",
		"private_ip": "10.0.1.23", "public_ip": "198.51.100.7", "vpc_id": "vpc-0abc", "subnet_id": "subnet-0def", "launch_time": "2026-01-02T03:04:05Z", "root_device": "/dev/xvda"} {
		if d[k] != want {
			t.Errorf("%s = %v, want %v", k, d[k], want)
		}
	}
	vols, _ := d["volumes"].([]any)
	if len(vols) != 2 {
		t.Fatalf("volumes = %v", d["volumes"])
	}
	data := vols[1].(map[string]any)
	if data["volume_id"] != "vol-0222" || data["delete_on_termination"] != false || data["size"] != float64(400) || vols[0].(map[string]any)["delete_on_termination"] != true {
		t.Errorf("volumes = %v", vols)
	}

	// --field prints the raw value.
	if err := h.run("ec2", "instance", "get", "web-01", "--field", "public_ip"); err != nil || h.stdout.String() != "198.51.100.7\n" {
		t.Errorf("--field public_ip = %q, %v", h.stdout.String(), err)
	}
	// A stopped instance is shown, with a note; its empty public ip is exit code 1.
	if err := h.run("ec2", "instance", "get", "stopped-one"); err != nil || !strings.Contains(h.stderr.String(), "is stopped") {
		t.Errorf("stopped get = %v, %s", err, h.stderr.String())
	}
	err := h.run("ec2", "instance", "get", "stopped-one", "--field", "public_ip")
	if err == nil || errors.Is(err, app.ErrUsage) || errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "new public IP") {
		t.Errorf("empty --field = %v", err)
	}
	if err := h.run("ec2", "instance", "get", "web-01", "--field", "bogus"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("--field bogus = %v", err)
	}

	// Terminated: not found, unless asked for.
	if err := h.run("ec2", "instance", "get", "gone"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("terminated get = %v", err)
	}
	if err := h.run("ec2", "instance", "get", "gone", "--include-terminated"); err != nil {
		t.Errorf("--include-terminated = %v", err)
	}

	// Two live instances of one name are ambiguous.
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa4", name: "web-01", typ: "t3.nano", state: stateStopped})
	var amb *app.AmbiguousError
	if err := h.run("ec2", "instance", "get", "web-01"); !errors.As(err, &amb) || !strings.Contains(amb.Hint, "instance id") {
		t.Errorf("duplicate name = %v", err)
	}
	// The id still works.
	if err := h.run("ec2", "instance", "get", "i-0aaaaaaaaaaaaaaa4"); err != nil {
		t.Errorf("get by id = %v", err)
	}

	// A failing volume listing does not fail the command.
	h.ec2.inst.volErr = &fakeAPIError{"UnauthorizedOperation", "denied"}
	if err := h.run("ec2", "instance", "get", "stopped-one"); err != nil || !strings.Contains(h.stderr.String(), "cannot list the volumes") {
		t.Errorf("volume failure = %v, %s", err, h.stderr.String())
	}
	h.jsonOut(&d)
	if v, ok := d["volumes"].([]any); !ok || len(v) != 0 {
		t.Errorf("volumes after a failure = %v", d["volumes"])
	}
}

func TestInstanceGetTable(t *testing.T) {
	g := detailGrid(instanceDetail{InstanceID: "i-1", InstanceName: "web", Region: "ap-east-1", AvailabilityZone: "ap-east-1a", RootDevice: "/dev/xvda",
		Volumes: []instanceVolume{{VolumeID: "vol-1", Device: "/dev/xvda", Size: 30, DeleteOnTermination: true}, {VolumeID: "vol-2", Device: "/dev/sdb", Size: 400}}})
	var b strings.Builder
	for _, r := range g.Rows {
		b.WriteString(strings.Join(r, " ") + "\n")
	}
	s := b.String()
	for _, want := range []string{"ap-east-1 (ap-east-1a)", "PUBLIC IP none", "(root, delete-on-termination)", "(keep on termination)"} {
		if !strings.Contains(s, want) {
			t.Errorf("table lacks %q:\n%s", want, s)
		}
	}
}

func TestInstanceRoutingSkipsTerminated(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{})
	h.addProfile(t)
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa1", name: "web", typ: "t3.nano", state: stateTerminated})
	h.addInstance("us-west-2", running("i-0bbbbbbbbbbbbbbb1", "web"))
	// The inventory of lab knows the terminated one only.
	h.rt.Flags.Profile = "lab"
	if err := h.run("ec2", "instance", "list"); err != nil {
		t.Fatal(err)
	}
	h.rt.Flags.Profile = ""
	if err := h.run("ec2", "instance", "get", "web"); err != nil {
		t.Fatal(err)
	}
	var d instanceDetail
	h.jsonOut(&d)
	if d.InstanceID != "i-0bbbbbbbbbbbbbbb1" || d.Profile != "prod" || d.Region != "us-west-2" {
		t.Errorf("routed to %+v", d)
	}
	// Live in both accounts: ambiguous, naming --profile.
	h.addInstance("ap-east-1", running("i-0aaaaaaaaaaaaaaa2", "web"))
	var amb *app.AmbiguousError
	h.rt.Flags.Refresh = true
	if err := h.run("ec2", "instance", "get", "web"); !errors.As(err, &amb) || !strings.Contains(amb.Hint, "--profile") {
		t.Errorf("two accounts = %v", err)
	}
	if err := h.run("ec2", "instance", "get", "nothing"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing = %v", err)
	}
}

func TestInstanceCreate(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{})
	old := newClientToken
	newClientToken = func() string { return "token-1" }
	t.Cleanup(func() { newClientToken = old })

	if err := h.run("ec2", "instance", "create", "site-new", "--type", "c6a.xlarge", "--disk", "400", "--tag", "team=ops", "--wait"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	rep := h.report()
	if len(rep.Changes) != 1 || rep.Changes[0].Action != platform.Created || rep.Changes[0].Attrs["public_ip"] == "" || !strings.Contains(rep.Changes[0].Detail, "running") {
		t.Fatalf("report = %+v", rep)
	}
	in := h.ec2.inst.runs[0]
	if in.SubnetId != nil || len(in.SecurityGroupIds) != 0 || len(in.NetworkInterfaces) != 1 {
		t.Errorf("network must go into NetworkInterfaces only: %+v", in)
	}
	nic := in.NetworkInterfaces[0]
	if awssdk.ToString(nic.SubnetId) != "subnet-0def" || strings.Join(nic.Groups, ",") != "sg-0aaa" || !awssdk.ToBool(nic.AssociatePublicIpAddress) || awssdk.ToInt32(nic.DeviceIndex) != 0 {
		t.Errorf("nic = %+v", nic)
	}
	if awssdk.ToString(in.ImageId) != "ami-0x86" || in.InstanceType != "c6a.xlarge" || awssdk.ToString(in.ClientToken) != "token-1" || in.KeyName != nil {
		t.Errorf("run input = %+v", in)
	}
	if len(in.BlockDeviceMappings) != 1 {
		t.Fatalf("bdm = %+v", in.BlockDeviceMappings)
	}
	bdm := in.BlockDeviceMappings[0]
	if awssdk.ToString(bdm.DeviceName) != "/dev/sdb" || awssdk.ToInt32(bdm.Ebs.VolumeSize) != 400 || bdm.Ebs.VolumeType != "gp3" || awssdk.ToInt32(bdm.Ebs.Iops) != 3000 ||
		awssdk.ToInt32(bdm.Ebs.Throughput) != 125 || awssdk.ToBool(bdm.Ebs.DeleteOnTermination) || bdm.Ebs.Encrypted != nil {
		t.Errorf("data disk = %+v", bdm.Ebs)
	}
	if len(in.TagSpecifications) != 2 || in.TagSpecifications[0].ResourceType != ec2types.ResourceTypeInstance || in.TagSpecifications[1].ResourceType != ec2types.ResourceTypeVolume {
		t.Fatalf("tag specs = %+v", in.TagSpecifications)
	}
	tags := map[string]string{}
	for _, tg := range in.TagSpecifications[0].Tags {
		tags[awssdk.ToString(tg.Key)] = awssdk.ToString(tg.Value)
	}
	if tags["Name"] != "site-new" || tags["team"] != "ops" {
		t.Errorf("tags = %v", tags)
	}
	if !strings.Contains(h.stderr.String(), "no key pair") {
		t.Errorf("stderr lacks the key pair note: %s", h.stderr.String())
	}

	// The same name again: exit code 1, no write.
	h.ec2.reset()
	err := h.run("ec2", "instance", "create", "site-new", "--type", "c6a.xlarge")
	if err == nil || errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "already exists") || len(h.writes()) != 0 {
		t.Errorf("duplicate = %v, writes %v", err, h.writes())
	}
}

func TestInstanceCreateDryRunAndArch(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{DryRun: true})
	if err := h.run("ec2", "instance", "create", "site-arm", "--type", "t4g.small", "--disk", "20", "--disk-type", "gp2", "--wait"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	rep := h.report()
	if !rep.DryRun || len(rep.Changes) != 1 || rep.Changes[0].Action != platform.WouldCreate || rep.Changes[0].ID != platform.Pending {
		t.Fatalf("report = %+v", rep)
	}
	detail := rep.Changes[0].Detail
	for _, want := range []string{"type=t4g.small", "ami=ami-0arm", "subnet=subnet-0def", "sgs=sg-0aaa", "disk=20GB(/dev/sdb, gp2, keep)"} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail %q lacks %q", detail, want)
		}
	}
	if w := h.writes(); len(w) != 0 {
		t.Errorf("dry run wrote: %v", w)
	}
}

func TestInstanceCreateAMIFallback(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{DryRun: true})
	h.ec2.inst.init()
	h.ec2.inst.ssmErr = &fakeAPIError{"AccessDeniedException", "not allowed"}
	h.ec2.inst.images["ap-east-1"] = []ec2types.Image{
		{ImageId: awssdk.String("ami-old"), Name: awssdk.String("al2023-ami-2023.8-kernel-6.1-x86_64"), Architecture: "x86_64", CreationDate: awssdk.String("2026-09-01T00:00:00.000Z")},
		{ImageId: awssdk.String("ami-new"), Name: awssdk.String("al2023-ami-2023.9-kernel-6.1-x86_64"), Architecture: "x86_64", CreationDate: awssdk.String("2026-10-01T00:00:00.000Z")},
		{ImageId: awssdk.String("ami-arm"), Name: awssdk.String("al2023-ami-2023.9-kernel-6.1-arm64"), Architecture: "arm64", CreationDate: awssdk.String("2026-11-01T00:00:00.000Z")},
	}
	if err := h.run("ec2", "instance", "create", "x", "--type", "t3.nano"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); !strings.Contains(rep.Changes[0].Detail, "ami=ami-new") || !strings.Contains(h.stderr.String(), "kernel-6.1") {
		t.Errorf("fallback = %+v / %s", rep, h.stderr.String())
	}
	h.ec2.inst.images["ap-east-1"] = nil
	if err := h.run("ec2", "instance", "create", "x", "--type", "t3.nano"); err == nil || !strings.Contains(err.Error(), "--ami") {
		t.Errorf("no image = %v", err)
	}
}

func TestInstanceCreateUsage(t *testing.T) {
	useFakeClock(t)
	h := newAWSHarness(t, app.Flags{}, nil)
	for _, args := range [][]string{
		{"create", "x"},                      // no type
		{"create", "x", "--type", "t3.nano"}, // no subnet
		{"create", "x", "--type", "t3.nano", "--subnet", "s", "--disk", "10", "--disk-type", "io2"},
		{"create", "x", "--type", "t3.nano", "--subnet", "s", "--disk", "10", "--disk-type", "gp2", "--disk-iops", "100"},
		{"create", "x", "--type", "t3.nano", "--subnet", "s", "--disk-type", "gp2"},
		{"create", "x", "--type", "t3.nano", "--subnet", "s", "--os", "ubuntu"},
		{"create", "x", "--type", "t3.nano", "--subnet", "s", "--ami", "ami-1", "--os", "al2023"},
		{"create", "x", "--type", "t3.nano", "--subnet", "s", "--tag", "Name=y"},
		{"create", "x", "--type", "t3.nano", "--subnet", "s", "--arch", "arm64"},
		{"create", "x", "--type", "t9.bogus", "--subnet", "s"},
	} {
		if err := h.run(append([]string{"ec2", "instance"}, args...)...); !errors.Is(err, app.ErrUsage) && !errors.Is(err, platform.ErrInvalidInput) {
			t.Errorf("%v = %v, want a usage error", args, err)
		}
	}
	if w := h.writes(); len(w) != 0 {
		t.Errorf("usage errors wrote: %v", w)
	}
}

func TestInstanceCreateWithKeyPair(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{})
	k := genED25519(t)
	h.add("ap-east-1", newFakeKeyPair("ops", k))
	file := writeKeyFile(t, h.dir, "ed.pub", k)
	if err := h.run("ec2", "instance", "create", "web", "--type", "t3.nano", "--ssh-key-file", file); err != nil {
		t.Fatal(err)
	}
	if got := awssdk.ToString(h.ec2.inst.runs[0].KeyName); got != "ops" {
		t.Errorf("key name = %q", got)
	}
	rep := h.report()
	if len(rep.Changes) != 2 || rep.Changes[0].Resource != "key-pair/ops" || rep.Changes[0].Action != platform.Unchanged {
		t.Errorf("report = %+v", rep)
	}
}

func TestInstanceDelete(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{})
	h.addInstance("ap-east-1", running("i-0aaaaaaaaaaaaaaa1", "site-old"))

	// Non-interactive without --yes: usage error after showing the instance.
	if err := h.run("ec2", "instance", "delete", "site-old"); !errors.Is(err, app.ErrUsage) {
		t.Fatalf("no --yes = %v", err)
	}
	stderr := h.stderr.String()
	for _, want := range []string{"c6a.large", "10.0.1.23", "198.51.100.7", "vol-0111", "permanently deleted", "vol-0222 will be kept", "cannot be undone"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("confirmation info lacks %q:\n%s", want, stderr)
		}
	}
	if w := h.writes(); len(w) != 0 {
		t.Fatalf("wrote without confirmation: %v", w)
	}

	// --dry-run --yes neither asks nor deletes.
	h.rt.Flags.DryRun, h.rt.Flags.Yes = true, true
	if err := h.run("ec2", "instance", "delete", "site-old"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); rep.Changes[0].Action != platform.WouldUpdate || rep.Changes[0].Detail != "terminate" || len(h.writes()) != 0 {
		t.Errorf("dry run = %+v, writes %v", rep, h.writes())
	}
	h.rt.Flags.DryRun = false

	// Termination protection: exit code 1, explained.
	h.ec2.inst.byRegion["ap-east-1"][0].protected = true
	err := h.run("ec2", "instance", "delete", "site-old")
	if err == nil || errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "termination protection") {
		t.Errorf("protected = %v", err)
	}
	h.ec2.inst.byRegion["ap-east-1"][0].protected = false

	// --yes --wait terminates and waits.
	if err := h.run("ec2", "instance", "terminate", "site-old", "--wait"); err != nil {
		t.Fatal(err)
	}
	if st, _ := h.instState("ap-east-1", "i-0aaaaaaaaaaaaaaa1"); st != stateTerminated {
		t.Errorf("state = %s", st)
	}
	if rep := h.report(); rep.Changes[0].Action != platform.Updated || !strings.Contains(h.stderr.String(), "left behind: data volume(s) vol-0222") {
		t.Errorf("report %+v / %s", rep, h.stderr.String())
	}

	// Already terminated: unchanged, exit code 0.
	h.ec2.reset()
	if err := h.run("ec2", "instance", "delete", "i-0aaaaaaaaaaaaaaa1"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); rep.Changes[0].Action != platform.Unchanged || len(h.writes()) != 0 {
		t.Errorf("terminated = %+v, writes %v", rep, h.writes())
	}
}

func TestInstanceDeleteInteractiveDeclined(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{NonInteractiveSet: true})
	h.rt.Picker = &scriptedPicker{t: t}
	h.rt.Flags.NonInteractive = false
	h.addInstance("ap-east-1", running("i-0aaaaaaaaaaaaaaa1", "site-old"))
	// The line prompt reads stdin, which is empty: that is a no.
	err := h.run("ec2", "instance", "delete", "site-old")
	if err != nil && !errors.Is(err, platform.ErrNothingToDo) {
		t.Errorf("declined = %v", err)
	}
	if w := h.writes(); len(w) != 0 {
		t.Errorf("declined but wrote: %v", w)
	}
}

func TestInstanceReboot(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{})
	h.addInstance("ap-east-1", running("i-0aaaaaaaaaaaaaaa1", "web"))
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa2", name: "off", typ: "t3.nano", state: stateStopped})
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa3", name: "booting", typ: "t3.nano", state: statePending})

	if err := h.run("ec2", "instance", "reboot", "web", "--wait"); err != nil {
		t.Fatal(err)
	}
	if w := h.writes(); strings.Join(w, ",") != "RebootInstances" || !strings.Contains(h.stderr.String(), "does not apply") {
		t.Errorf("running: writes %v, %s", w, h.stderr.String())
	}
	h.ec2.reset()
	if err := h.run("ec2", "instance", "reboot", "off", "--wait"); err != nil {
		t.Fatal(err)
	}
	if w := h.writes(); strings.Join(w, ",") != "StartInstances" {
		t.Errorf("stopped: writes %v", w)
	}
	if rep := h.report(); !strings.Contains(rep.Changes[0].Detail, "start (instance is stopped); running, public ip 203.0.113.") {
		t.Errorf("stopped report = %+v", rep)
	}
	h.ec2.reset()
	err := h.run("ec2", "instance", "reboot", "booting")
	if err == nil || errors.Is(err, app.ErrUsage) || len(h.writes()) != 0 {
		t.Errorf("pending = %v, writes %v", err, h.writes())
	}
	h.rt.Flags.DryRun = true
	if err := h.run("ec2", "instance", "reboot", "web"); err != nil || len(h.writes()) != 0 {
		t.Errorf("dry run = %v, writes %v", err, h.writes())
	}
}

func TestInstanceResizeRunning(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{Yes: true})
	h.addInstance("ap-east-1", running("i-0aaaaaaaaaaaaaaa1", "web"))
	if err := h.run("ec2", "instance", "resize", "web", "--type", "c6a.xlarge"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if w := strings.Join(h.writes(), ","); w != "StopInstances,ModifyInstanceAttribute,StartInstances" {
		t.Errorf("writes = %s", w)
	}
	st, typ := h.instState("ap-east-1", "i-0aaaaaaaaaaaaaaa1")
	if st != stateRunning || typ != "c6a.xlarge" {
		t.Errorf("end state %s %s", st, typ)
	}
	rep := h.report()
	if len(rep.Changes) != 3 || rep.Changes[1].Detail != "modify-type c6a.large -> c6a.xlarge" || !strings.Contains(rep.Changes[2].Detail, "public ip 198.51.100.7 -> 203.0.113.") {
		t.Errorf("report = %+v", rep)
	}
	if !strings.Contains(h.stderr.String(), "public ip of web changed") {
		t.Errorf("stderr lacks the IP change: %s", h.stderr.String())
	}

	// Same type again: unchanged, no write.
	h.ec2.reset()
	if err := h.run("ec2", "instance", "resize", "web", "--type", "c6a.xlarge"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); rep.Changes[0].Action != platform.Unchanged || len(h.writes()) != 0 {
		t.Errorf("same type = %+v, writes %v", rep, h.writes())
	}
}

func TestInstanceResizeChecks(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{Yes: true})
	h.addInstance("ap-east-1", running("i-0aaaaaaaaaaaaaaa1", "web"))
	// Architecture mismatch and a zone that lacks the type: exit 1, no write.
	for _, typ := range []string{"t4g.nano", "t3.micro"} {
		err := h.run("ec2", "instance", "resize", "web", "--type", typ)
		if err == nil || errors.Is(err, app.ErrUsage) || errors.Is(err, platform.ErrInvalidInput) {
			t.Errorf("%s = %v", typ, err)
		}
	}
	if err := h.run("ec2", "instance", "resize", "web", "--type", "t3.micro"); err == nil || !strings.Contains(err.Error(), "ap-east-1b") {
		t.Errorf("offering error should list the zones: %v", err)
	}
	if err := h.run("ec2", "instance", "resize", "web", "--type", "t9.bogus"); !errors.Is(err, platform.ErrInvalidInput) {
		t.Errorf("unknown type = %v", err)
	}
	if err := h.run("ec2", "instance", "resize", "web"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("no --type = %v", err)
	}
	if w := h.writes(); len(w) != 0 {
		t.Errorf("checks wrote: %v", w)
	}

	// Non-interactive without --yes: usage error, nothing written.
	h.rt.Flags.Yes = false
	if err := h.run("ec2", "instance", "resize", "web", "--type", "c6a.xlarge"); !errors.Is(err, app.ErrUsage) || len(h.writes()) != 0 {
		t.Errorf("no --yes = %v, writes %v", err, h.writes())
	}

	// Dry run: three steps, nothing written, nothing asked.
	h.rt.Flags.DryRun = true
	if err := h.run("ec2", "instance", "resize", "web", "--type", "c6a.xlarge"); err != nil {
		t.Fatal(err)
	}
	rep := h.report()
	var details []string
	for _, c := range rep.Changes {
		if c.Action != platform.WouldUpdate {
			t.Errorf("dry run action %s", c.Action)
		}
		details = append(details, c.Detail)
	}
	if strings.Join(details, "|") != "stop|modify-type c6a.large -> c6a.xlarge|start" || len(h.writes()) != 0 {
		t.Errorf("dry run = %v, writes %v", details, h.writes())
	}
}

func TestInstanceResizeStopped(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{})
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa1", name: "off", typ: "c6a.large", state: stateStopped})
	// A stopped instance needs no confirmation and stays stopped.
	if err := h.run("ec2", "instance", "resize", "off", "--type", "c6a.xlarge", "--wait-port", "22"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.stderr.String(), "--wait-port 22 skipped") {
		t.Errorf("stderr lacks the skipped port wait: %s", h.stderr.String())
	}
	if w := strings.Join(h.writes(), ","); w != "ModifyInstanceAttribute" || !strings.Contains(h.stderr.String(), "stays stopped") {
		t.Errorf("writes = %s / %s", w, h.stderr.String())
	}
	// Same type with --start starts it.
	h.ec2.reset()
	if err := h.run("ec2", "instance", "resize", "off", "--type", "c6a.xlarge", "--start"); err != nil {
		t.Fatal(err)
	}
	if w := strings.Join(h.writes(), ","); w != "StartInstances" {
		t.Errorf("--start writes = %s", w)
	}
}

func TestInstanceResizeFailures(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{Yes: true})
	h.addInstance("ap-east-1", running("i-0aaaaaaaaaaaaaaa1", "web"))
	h.ec2.inst.init()
	h.ec2.inst.errs["ModifyInstanceAttribute"] = &fakeAPIError{"InternalError", "boom"}
	err := h.run("ec2", "instance", "resize", "web", "--type", "c6a.xlarge")
	if err == nil || !strings.Contains(err.Error(), "its type is still c6a.large") {
		t.Fatalf("modify failure = %v", err)
	}
	if st, typ := h.instState("ap-east-1", "i-0aaaaaaaaaaaaaaa1"); st != stateStopped || typ != "c6a.large" {
		t.Errorf("after failure: %s %s", st, typ)
	}
	if w := strings.Join(h.writes(), ","); w != "StopInstances,ModifyInstanceAttribute" {
		t.Errorf("writes = %s", w)
	}
	rep := h.report()
	if rep.Changes[len(rep.Changes)-1].Action != platform.Failed {
		t.Errorf("report = %+v", rep)
	}

	// Running the command again continues from the stopped state.
	h.ec2.inst.errs["ModifyInstanceAttribute"] = nil
	h.ec2.reset()
	if err := h.run("ec2", "instance", "resize", "web", "--type", "c6a.xlarge", "--start"); err != nil {
		t.Fatal(err)
	}
	if w := strings.Join(h.writes(), ","); w != "ModifyInstanceAttribute,StartInstances" {
		t.Errorf("rerun writes = %s", w)
	}

	// No capacity at start: exit code 1, explained.
	h.ec2.inst.errs["StartInstances"] = &fakeAPIError{"InsufficientInstanceCapacity", "no capacity"}
	err = h.run("ec2", "instance", "resize", "web", "--type", "c6a.large")
	if err == nil || errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "no capacity for this instance type") {
		t.Errorf("capacity = %v", err)
	}
}

func TestResizeWaitPort(t *testing.T) {
	h := newInstanceHarness(t, app.Flags{Yes: true})
	h.addInstance("ap-east-1", running("i-0aaaaaaaaaaaaaaa1", "web"))
	var dialed []string
	old := dialTCP
	dialTCP = func(_ context.Context, addr string, _ time.Duration) error {
		dialed = append(dialed, addr)
		if len(dialed) < 3 {
			return errors.New("refused")
		}
		return nil
	}
	t.Cleanup(func() { dialTCP = old })
	if err := h.run("ec2", "instance", "resize", "web", "--type", "c6a.xlarge", "--wait-port", "22"); err != nil {
		t.Fatal(err)
	}
	sort.Strings(dialed)
	if len(dialed) != 3 || !strings.HasPrefix(dialed[0], "203.0.113.") || !strings.HasSuffix(dialed[0], ":22") {
		t.Errorf("dialed %v", dialed)
	}
	if err := h.run("ec2", "instance", "resize", "web", "--type", "c6a.large", "--wait-port", "70000"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("bad port = %v", err)
	}
}
