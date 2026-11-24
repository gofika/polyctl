package aliyun

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// The image of create follows the architecture of the type: an arm64 type
// gets the arm64 image, a type the region does not list the x86_64 one.
func TestInstanceCreateImageFollowsTypeArch(t *testing.T) {
	h, f, _ := computeHarness(t, app.Flags{})
	siteNet(f)
	f.addKeyPair("ops", "aa", "2026-11-17T16:10Z")
	f.typeArch = map[string]string{"ecs.g8y.large": "ARM", "ecs.u1-c1m1.large": "X86"}
	for _, tc := range []struct{ name, typ, image string }{
		{"arm", "ecs.g8y.large", "aliyun_4_arm64_20G_alibase_20261103.vhd"},
		{"x86", "ecs.u1-c1m1.large", alinux4},
		{"unlisted", "ecs.nosuch.large", alinux4},
	} {
		if err := h.run("ecs", "instance", "create", tc.name, "--type", tc.typ, "--security-group", "sg-common", "--key-pair", "ops", "--no-wait"); err != nil {
			t.Fatalf("%s: %v\n%s", tc.name, err, h.stderr.String())
		}
		runs := h.api.callsFor("RunInstances")
		if run := runs[len(runs)-1]; run.Get("ImageId") != tc.image || run.Get("InstanceType") != tc.typ {
			t.Errorf("%s: RunInstances = %v", tc.name, run)
		}
	}
	images := h.api.callsFor("DescribeImages")
	if images[0].Get("Architecture") != "arm64" || images[1].Get("Architecture") != "x86_64" {
		t.Errorf("image queries = %v", images)
	}
	if !strings.Contains(h.stderr.String(), "does not list instance type ecs.nosuch.large") {
		t.Errorf("stderr = %s", h.stderr.String())
	}
}

// --os windows: the newest Windows Server Datacenter (Chinese) image, a
// 40 GiB system disk by default, no key pair, a Windows host name.
func TestInstanceCreateWindows(t *testing.T) {
	h, f, _ := computeHarness(t, app.Flags{})
	siteNet(f)
	f.typeArch = map[string]string{"ecs.u1-c1m2.large": "X86", "ecs.g8y.large": "ARM"}
	if err := h.run("ecs", "instance", "create", "web.site-number-one", "--os", "windows", "--type", "ecs.u1-c1m2.large", "--security-group", "sg-common", "--no-wait"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if !slices.Equal(f.writes, []string{"RunInstances"}) {
		t.Fatalf("writes = %v", f.writes)
	}
	run := h.api.callsFor("RunInstances")[0]
	for k, v := range map[string]string{"ImageId": "win2025_datacenter_zh.vhd", "SystemDisk.Size": "40", "KeyPairName": "", "HostName": "web-site-number"} {
		if run.Get(k) != v {
			t.Errorf("RunInstances %s = %q, want %q", k, run.Get(k), v)
		}
	}
	if len(h.api.callsFor("DescribeKeyPairs")) != 0 {
		t.Error("windows looked up key pairs")
	}
	if !strings.Contains(h.stderr.String(), "no key pair and no password") {
		t.Errorf("stderr = %s", h.stderr.String())
	}
	// A larger --disk is kept.
	if err := h.run("ecs", "instance", "create", "win-b", "--os", "windows", "--type", "ecs.u1-c1m2.large", "--security-group", "sg-common", "--disk", "60", "--no-wait"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if run := h.api.callsFor("RunInstances")[1]; run.Get("SystemDisk.Size") != "60" {
		t.Errorf("--disk 60: %v", run)
	}

	// Refused before any write: a key pair, a disk below 40 GiB, an arm64
	// type, a host name of digits only.
	writes := len(f.writes)
	for _, args := range [][]string{
		{"ecs", "instance", "create", "win-c", "--os", "windows", "--type", "ecs.u1-c1m2.large", "--security-group", "sg-common", "--key-pair", "ops"},
		{"ecs", "instance", "create", "win-c", "--os", "windows", "--type", "ecs.u1-c1m2.large", "--security-group", "sg-common", "--disk", "30"},
		{"ecs", "instance", "create", "win-c", "--os", "windows", "--type", "ecs.g8y.large", "--security-group", "sg-common"},
		{"ecs", "instance", "create", "12345", "--os", "windows", "--type", "ecs.u1-c1m2.large", "--security-group", "sg-common"},
		{"ecs", "instance", "create", "win-c", "--os", "ubuntu", "--type", "ecs.u1-c1m2.large", "--security-group", "sg-common", "--key-pair", "ops"},
	} {
		if err := h.run(args...); !errors.Is(err, app.ErrUsage) {
			t.Errorf("%v = %v, want a usage error", args[3:], err)
		}
	}
	if len(f.writes) != writes {
		t.Errorf("usage errors wrote %v", f.writes[writes:])
	}
}

// No matching image is exit code 4, before anything is written, in a dry
// run too; a dry run picks the same image and writes nothing.
func TestInstanceEnsureImageNotFoundAndDryRun(t *testing.T) {
	h, f, _ := computeHarness(t, app.Flags{DryRun: true})
	f.images = realImages()
	key := testKey(t, "ed25519")
	if err := h.run("ecs", "instance", "ensure", "site-a", "--ssh-key", key, "--key-pair", "ops"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if len(f.writes) != 0 {
		t.Fatalf("dry run wrote %v", f.writes)
	}
	var out instanceEnsureReport
	h.jsonOut(&out)
	if c := changeOf(t, out.Report, "instance/site-a"); c.Action != platform.WouldCreate || !strings.Contains(c.Detail, "image "+alinux4) {
		t.Errorf("change = %+v", c)
	}

	h, f, _ = computeHarness(t, app.Flags{})
	f.images = []map[string]any{img("ubuntu.vhd", "acs:ubuntu_24_04_x64", "Ubuntu", "x86_64", "2026-01-01T00:00:00Z")}
	err := h.run("ecs", "instance", "ensure", "site-a", "--ssh-key", key, "--key-pair", "ops")
	if !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "--image <id>") {
		t.Errorf("no image = %v", err)
	}
	if len(f.writes) != 0 {
		t.Errorf("wrote %v", f.writes)
	}

	// ensure --os windows: no key pair step, the Windows image and disk.
	h, f, _ = computeHarness(t, app.Flags{})
	f.images = realImages()
	if err := h.run("ecs", "instance", "ensure", "win-a", "--os", "windows"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if f.writes[0] != "CreateVpc" {
		t.Errorf("writes = %v", f.writes)
	}
	run := h.api.callsFor("RunInstances")[0]
	if run.Get("ImageId") != "win2025_datacenter_zh.vhd" || run.Get("SystemDisk.Size") != "40" || run.Get("KeyPairName") != "" {
		t.Errorf("RunInstances = %v", run)
	}
}
