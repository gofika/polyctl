package aliyun

import (
	"errors"
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

}
