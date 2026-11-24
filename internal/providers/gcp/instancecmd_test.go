package gcp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// exitClass names the exit code an error maps to.
func exitClass(err error) string {
	var amb *app.AmbiguousError
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, platform.ErrNothingToDo):
		return "nothing"
	case errors.Is(err, app.ErrUsage), errors.Is(err, platform.ErrInvalidInput):
		return "usage"
	case errors.Is(err, platform.ErrUnauthorized), errors.Is(err, platform.ErrForbidden):
		return "auth"
	case errors.Is(err, platform.ErrNotFound):
		return "notfound"
	case errors.As(err, &amb), errors.Is(err, platform.ErrAmbiguous):
		return "ambiguous"
	case errors.Is(err, app.ErrOffline):
		return "offline"
	case errors.Is(err, platform.ErrNotSupported):
		return "unsupported"
	}
	return "general"
}

func defaultsUS() map[string]any {
	return map[string]any{"zone": "us-central1-a", "machine_type": "e2-small"}
}

func TestInstanceGet(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.gce.addInstance("proj", "us-central1-a", "web-1", "10.128.0.5", "203.0.113.10")
	stopped := h.gce.addInstance("proj", "us-central1-b", "old-1", "10.128.0.6", "")
	stopped.Status = statusTerminated

	if err := h.run("compute", "instance", "get", "web-1"); err != nil {
		t.Fatal(err)
	}
	var d instanceDetail
	h.jsonOut(&d)
	if d.Name != "web-1" || d.Zone != "us-central1-a" || d.Status != "RUNNING" || d.MachineType != "e2-small" || d.InternalIP != "10.128.0.5" ||
		d.ExternalIP != "203.0.113.10" || d.Network != "default" || d.Subnetwork != "default" || d.Profile != "lab" || d.Project != "proj" ||
		len(d.Tags) != 1 || len(d.Disks) != 1 || d.Disks[0].Type != "pd-balanced" || !d.Disks[0].Boot || d.Disks[0].SizeGB != 10 {
		t.Errorf("detail = %+v", d)
	}
	// --field prints the raw value.
	if err := h.run("compute", "instance", "get", "web-1", "--field", "external-ip"); err != nil || h.stdout.String() != "203.0.113.10\n" {
		t.Errorf("--field external-ip = %q, %v", h.stdout.String(), err)
	}
	if err := h.run("compute", "instance", "get", "web-1", "--field", "machine-type"); err != nil || h.stdout.String() != "e2-small\n" {
		t.Errorf("--field machine-type = %q, %v", h.stdout.String(), err)
	}
	// No external IP: exit code 1, the reason on stderr, nothing on stdout.
	err := h.run("compute", "instance", "get", "old-1", "--field", "external-ip")
	if exitClass(err) != "general" || h.stdout.Len() != 0 || !strings.Contains(err.Error(), "released") {
		t.Errorf("no external ip = %v, stdout %q", err, h.stdout.String())
	}
	// Without --field the stopped instance is shown with a warning.
	if err := h.run("compute", "instance", "get", "old-1"); err != nil || !strings.Contains(h.stderr.String(), "no external IP") {
		t.Errorf("get stopped = %v, %s", err, h.stderr.String())
	}
	if err := h.run("compute", "instance", "get", "web-1", "--field", "bogus"); exitClass(err) != "usage" {
		t.Errorf("--field bogus = %v", err)
	}
	if err := h.run("compute", "instance", "get", "nothing"); exitClass(err) != "notfound" {
		t.Errorf("missing = %v", err)
	}
	// Two zones hold web-1: ambiguous, unless --zone picks one.
	h.gce.addInstance("proj", "us-central1-b", "web-1", "10.128.0.7", "")
	h.rt.Flags.Refresh = true
	var amb *app.AmbiguousError
	if err := h.run("compute", "instance", "get", "web-1"); !errors.As(err, &amb) || !strings.Contains(amb.Hint, "--zone") {
		t.Errorf("two zones = %v", err)
	}
	h.rt.Flags.Refresh = false
	if err := h.run("compute", "instance", "get", "web-1", "--zone", "us-central1-b", "--field", "internal-ip"); err != nil || h.stdout.String() != "10.128.0.7\n" {
		t.Errorf("--zone = %q, %v", h.stdout.String(), err)
	}
	// Offline: live state is needed.
	h.rt.Flags.Offline = true
	if err := h.run("compute", "instance", "get", "web-1"); exitClass(err) != "offline" {
		t.Errorf("offline = %v", err)
	}
}

func TestInstanceGetFindsUncachedInstanceByZone(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.gce.addInstance("proj", "us-central1-a", "web-1", "10.128.0.5", "203.0.113.10")
	// The inventory is synced (and fresh) before the instance appears.
	if err := h.run("compute", "instance", "list"); err != nil {
		t.Fatal(err)
	}
	h.gce.addInstance("proj", "europe-west1-b", "new-1", "10.132.0.2", "")
	// A miss syncs the accounts once, although their sets are fresh.
	if err := h.run("compute", "instance", "get", "new-1", "--field", "zone"); err != nil || h.stdout.String() != "europe-west1-b\n" ||
		!strings.Contains(h.stderr.String(), "syncing") {
		t.Errorf("uncached = %q, %v, %s", h.stdout.String(), err, h.stderr.String())
	}
	// When the sync fails, --zone still finds an instance by asking live.
	h.gce.addInstance("proj", "europe-west1-b", "new-2", "10.132.0.3", "")
	h.gce.fail["GET /projects/proj/aggregated/instances"] = fakeErr{500, "backendError", "unavailable"}
	if err := h.run("compute", "instance", "get", "new-2"); exitClass(err) != "general" || !strings.Contains(err.Error(), "cannot tell where") {
		t.Errorf("sync failure without --zone = %v", err)
	}
	if err := h.run("compute", "instance", "get", "new-2", "--zone", "europe-west1-b", "--field", "internal-ip"); err != nil || h.stdout.String() != "10.132.0.3\n" {
		t.Errorf("sync failure with --zone = %q, %v", h.stdout.String(), err)
	}
	delete(h.gce.fail, "GET /projects/proj/aggregated/instances")
	// --zone pins the instance: the web-1 of another zone is not used.
	if err := h.run("compute", "instance", "get", "web-1", "--zone", "us-central1-b", "--field", "zone"); exitClass(err) != "notfound" ||
		!strings.Contains(err.Error(), "one is in zone us-central1-a") || h.stdout.String() != "" {
		t.Errorf("wrong --zone = %q, %v", h.stdout.String(), err)
	}
}

// TestInstanceZonePinsDelete: the inventory knows web-1 in one zone only;
// --zone of another zone acts on the web-1 there (found live), or on
// nothing, never on the cached one.
func TestInstanceZonePinsDelete(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.gce.addInstance("proj", "us-central1-a", "web-1", "10.128.0.5", "")
	if err := h.run("compute", "instance", "list"); err != nil {
		t.Fatal(err)
	}
	if err := h.run("compute", "instance", "delete", "web-1", "--zone", "europe-west1-b", "--yes"); exitClass(err) != "notfound" || len(h.gce.writes()) != 0 {
		t.Errorf("no web-1 in the zone = %v, writes %v", err, h.gce.writes())
	}
	// A web-1 created there since the last sync is found live.
	h.gce.addInstance("proj", "europe-west1-b", "web-1", "10.132.0.5", "")
	if err := h.run("compute", "instance", "delete", "web-1", "--zone", "europe-west1-b", "--yes"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if h.gce.instance("europe-west1-b", "web-1") != nil || h.gce.instance("us-central1-a", "web-1") == nil {
		t.Errorf("writes = %v", h.gce.writes())
	}
}

func TestInstanceCreate(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, map[string]any{"zone": "us-central1-a", "tags": []any{"lb-health-check"}})
	key := testPublicKey(t, "alice@example.com")
	keyFile := filepath.Join(t.TempDir(), "id.pub")
	if err := os.WriteFile(keyFile, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := h.run("compute", "instance", "create", "web-1", "--machine-type", "e2-standard-4", "--disk", "100", "--os", "ubuntu",
		"--ssh-key-file", keyFile, "--tag", "http-server", "--tag", "lb-health-check")
	if err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if got, want := h.gce.writes(), []string{"POST addresses", "POST addresses", "POST instances"}; !slices.Equal(got, want) {
		t.Errorf("writes = %v, want %v", got, want)
	}
	rep := h.report()
	got := rows(rep)
	for i, prefix := range []string{
		"image/ubuntu unchanged ubuntu-2604-resolute-amd64-v20261107 (min disk 10GB)",
		"address/web-1-external-ip created 198.51.100.",
		"address/web-1-internal-ip created 10.128.1.",
		"instance/web-1 created e2-standard-4, boot 10GB pd-balanced, data 100GB, tags http-server,lb-health-check, ssh keys alice, ip-forward false",
		"instance/web-1/status created RUNNING, external ip 198.51.100.",
	} {
		if i >= len(got) || !strings.HasPrefix(got[i], prefix) {
			t.Errorf("row %d = %q, want prefix %q (all: %v)", i, at(got, i), prefix, got)
		}
	}
	in := h.gce.instance("us-central1-a", "web-1")
	if in == nil {
		t.Fatal("instance not created")
	}
	ext, internal := h.gce.address("us-central1", "web-1-external-ip"), h.gce.address("us-central1", "web-1-internal-ip")
	nic := in.NetworkInterfaces[0]
	if nic.AccessConfigs[0].NatIP != ext.Address || nic.NetworkIP != internal.Address || ext.Status != addrInUse || internal.Status != addrInUse ||
		!strings.HasSuffix(internal.Subnetwork, "/regions/us-central1/subnetworks/default") || nic.StackType != "IPV4_ONLY" {
		t.Errorf("nic = %+v / ext %+v / int %+v", nic, ext, internal)
	}
	if in.Tags == nil || !slices.Equal(in.Tags.Items, []string{"http-server", "lb-health-check"}) {
		t.Errorf("tags = %+v", in.Tags)
	}
	if len(in.Disks) != 2 || in.Disks[0].DiskSizeGb != 10 || !in.Disks[0].Boot || in.Disks[1].Index != 1 || lastSegment(in.Disks[1].Source) != "web-1-data" ||
		in.Disks[1].DiskSizeGb != 100 || !in.Disks[1].AutoDelete {
		t.Errorf("disks = %+v %+v", in.Disks[0], in.Disks[1])
	}
	if len(in.ServiceAccounts) != 1 || in.ServiceAccounts[0].Email != "default" || len(in.ServiceAccounts[0].Scopes) != 6 {
		t.Errorf("service accounts = %+v", in.ServiceAccounts)
	}
	if in.Scheduling == nil || in.Scheduling.ProvisioningModel != "STANDARD" || in.ShieldedInstanceConfig == nil || !in.ShieldedInstanceConfig.EnableVtpm || in.CanIpForward {
		t.Errorf("scheduling / shielded / ip forward = %+v %+v %v", in.Scheduling, in.ShieldedInstanceConfig, in.CanIpForward)
	}
	if v, ok := metadataValue(in.Metadata, "ssh-keys"); !ok || !strings.HasPrefix(v, "alice:ssh-ed25519 ") {
		t.Errorf("ssh-keys = %q", v)
	}
	if !strings.Contains(h.stderr.String(), "is RUNNING") {
		t.Errorf("stderr = %s", h.stderr.String())
	}

	// Again: the instance exists (exit code 1), nothing is written.
	err = h.run("compute", "instance", "create", "web-1", "--machine-type", "e2-small")
	if exitClass(err) != "general" || !strings.Contains(err.Error(), "already exists") || len(h.gce.writes()) != 0 {
		t.Errorf("create existing = %v, writes %v", err, h.gce.writes())
	}
}

func at(s []string, i int) string {
	if i < len(s) {
		return s[i]
	}
	return ""
}

func TestInstanceCreateReusesAddresses(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, defaultsUS())
	h.gce.addAddress("us-central1", &compute.Address{Name: "web-1-external-ip", Address: "198.51.100.77", AddressType: "EXTERNAL"})
	// Internal address missing: only it is created.
	if err := h.run("compute", "instance", "create", "web-1"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if got, want := h.gce.writes(), []string{"POST addresses", "POST instances"}; !slices.Equal(got, want) {
		t.Errorf("writes = %v, want %v", got, want)
	}
	if r := rows(h.report()); !slices.Contains(r, "address/web-1-external-ip unchanged 198.51.100.77") {
		t.Errorf("rows = %v", r)
	}
	if in := h.gce.instance("us-central1-a", "web-1"); in.NetworkInterfaces[0].AccessConfigs[0].NatIP != "198.51.100.77" {
		t.Errorf("nat ip = %s", in.NetworkInterfaces[0].AccessConfigs[0].NatIP)
	}
	// Both addresses exist for web-2: no address writes at all.
	h.gce.addAddress("us-central1", &compute.Address{Name: "web-2-external-ip", Address: "198.51.100.78", AddressType: "EXTERNAL"})
	h.gce.addAddress("us-central1", &compute.Address{Name: "web-2-internal-ip", Address: "10.128.0.78", AddressType: "INTERNAL", Subnetwork: "default"})
	if err := h.run("compute", "instance", "create", "web-2"); err != nil {
		t.Fatal(err)
	}
	if got := h.gce.writes(); !slices.Equal(got, []string{"POST instances"}) {
		t.Errorf("writes = %v", got)
	}
	// An internal address reserved in another subnet is re-reserved.
	h.gce.mu.Lock()
	h.gce.subnets["proj/us-central1"] = append(h.gce.subnets["proj/us-central1"], &compute.Subnetwork{Name: "other", Network: apiBase + "projects/proj/global/networks/other-net"})
	h.gce.mu.Unlock()
	h.gce.addAddress("us-central1", &compute.Address{Name: "web-3-internal-ip", Address: "10.200.0.3", AddressType: "INTERNAL", Subnetwork: "other"})
	if err := h.run("compute", "instance", "create", "web-3", "--static-ip"); err != nil {
		t.Fatal(err)
	}
	if got, want := h.gce.writes(), []string{"POST addresses", "DELETE addresses/web-3-internal-ip", "POST addresses", "POST instances"}; !slices.Equal(got, want) {
		t.Errorf("re-reserve writes = %v, want %v", got, want)
	}
	if a := h.gce.address("us-central1", "web-3-internal-ip"); !strings.HasSuffix(a.Subnetwork, "/subnetworks/default") {
		t.Errorf("re-reserved in %s", a.Subnetwork)
	}
	// An address another instance uses stops create before any write.
	h.gce.addAddress("us-central1", &compute.Address{Name: "web-4-internal-ip", Address: "10.128.0.78", AddressType: "INTERNAL", Subnetwork: "default"})
	err := h.run("compute", "instance", "create", "web-4")
	if exitClass(err) != "general" || !strings.Contains(err.Error(), "already used by web-2") || len(h.gce.writes()) != 0 {
		t.Errorf("in use = %v, writes %v", err, h.gce.writes())
	}
}

func TestInstanceCreateDryRun(t *testing.T) {
	h := newGCPHarness(t, app.Flags{DryRun: true}, defaultsUS())
	if err := h.run("compute", "instance", "create", "web-1", "--disk", "100", "--tag", "lb-health-check"); err != nil {
		t.Fatal(err)
	}
	if w := h.gce.writes(); len(w) != 0 {
		t.Errorf("dry run wrote %v", w)
	}
	rep := h.report()
	if !rep.DryRun {
		t.Error("dry_run false")
	}
	want := []string{
		"image/debian unchanged debian-13-trixie-v20261116 (min disk 10GB)",
		"address/web-1-external-ip would_create EXTERNAL PREMIUM",
		"address/web-1-internal-ip would_create INTERNAL subnet default",
		"instance/web-1 would_create e2-small, boot 10GB pd-balanced, data 100GB, tags lb-health-check, ip-forward false",
		"instance/web-1/status would_create RUNNING",
	}
	if got := rows(rep); !slices.Equal(got, want) {
		t.Errorf("rows = %v\nwant %v", got, want)
	}
	if rep.Changes[1].ID != platform.Pending {
		t.Errorf("pending id = %q", rep.Changes[1].ID)
	}

	// --no-wait plans no wait for RUNNING, as a real run reports none.
	h = newGCPHarness(t, app.Flags{DryRun: true}, defaultsUS())
	if err := h.run("compute", "instance", "create", "web-1", "--no-wait"); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows(h.report()) {
		if strings.HasPrefix(r, "instance/web-1/status") {
			t.Errorf("--no-wait dry run plans %q", r)
		}
	}
}

func TestInstanceCreateValidation(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	for _, tc := range []struct {
		args []string
		want string
		msg  string
	}{
		{[]string{"1site", "--machine-type", "e2-small", "--zone", "us-central1-a"}, "usage", "lower-case letter"},
		{[]string{"Web_1", "--machine-type", "e2-small", "--zone", "us-central1-a"}, "usage", "lower-case letter"},
		{[]string{"web-1", "--zone", "us-central1-a"}, "usage", "--machine-type"},
		{[]string{"web-1", "--machine-type", "e2-small"}, "usage", "--zone"},
		{[]string{"web-1", "--machine-type", "e2-small", "--zone", "us-central1-a", "--os", "beos"}, "usage", "supported"},
		{[]string{"web-1", "--machine-type", "e2-small", "--zone", "us-central1-a", "--disk-type", "ssd"}, "usage", "--disk-type"},
		{[]string{"web-1", "--machine-type", "e2-small", "--zone", "us-central1-a", "--boot-disk-size", "5"}, "usage", "smaller than"},
		{[]string{"web-1", "--machine-type", "e2-small", "--zone", "us-central1-a", "--tag", "Bad_Tag"}, "usage", "network tag"},
		{[]string{"web-1", "--machine-type", "e2-small", "--zone", "us-central1-a", "--ssh-key", testPublicKey(t, "laptop")}, "usage", "user:"},
		{[]string{"web-1", "--machine-type", "e2-small", "--zone", "us-central1-a", "--image", "debian-12"}, "usage", "--image"},
		{[]string{"web-1", "--machine-type", "e2-small", "--zone", "us-central1-a", "--wait", "--no-wait"}, "usage", "contradict"},
		{[]string{"web-1", "--machine-type", "n9-huge", "--zone", "us-central1-a"}, "usage", "does not exist in zone"},
		{[]string{"web-1", "--machine-type", "e2-small", "--zone", "us-central1-a", "--os", "debian", "--os-version", "99"}, "notfound", "no current x86_64 image"},
		{[]string{"web-1", "--machine-type", "e2-small", "--zone", "us-central1-a", "--image", "projects/debian-cloud/global/images/nope"}, "notfound", "nope"},
		{[]string{"web-1", "--machine-type", "e2-small", "--zone", "us-central1-a", "--subnet", "missing"}, "notfound", "subnetwork missing"},
		{[]string{"web-1", "--machine-type", "e2-small", "--zone", "us-central1-a", "--network", "nonet"}, "notfound", "network nonet"},
	} {
		err := h.run(append([]string{"compute", "instance", "create"}, tc.args...)...)
		if exitClass(err) != tc.want || err == nil || !strings.Contains(err.Error(), tc.msg) {
			t.Errorf("create %v = %v (%s), want %s with %q", tc.args, err, exitClass(err), tc.want, tc.msg)
		}
		if w := h.gce.writes(); len(w) != 0 {
			t.Errorf("create %v wrote %v", tc.args, w)
		}
	}
	// A Windows image needs a bigger boot disk; the minimum is the default.
	if err := h.run("compute", "instance", "create", "win-1", "--machine-type", "e2-standard-4", "--zone", "us-central1-a", "--os", "windows", "--static-ip=false", "--no-wait"); err != nil {
		t.Fatal(err)
	}
	if in := h.gce.instance("us-central1-a", "win-1"); in.Disks[0].DiskSizeGb != 50 {
		t.Errorf("windows boot = %d", in.Disks[0].DiskSizeGb)
	}
	if got := rows(h.report()); !strings.HasSuffix(at(got, 1), "(provisioning)") || len(got) != 2 {
		t.Errorf("--no-wait rows = %v", got)
	}
}

// TestInstanceCreateImageArch checks that the image follows the
// architecture of the machine type, and that --os, --os-version and
// --image still override the default.
func TestInstanceCreateImageArch(t *testing.T) {
	h := newGCPHarness(t, app.Flags{DryRun: true}, defaultsUS())
	h.gce.mu.Lock()
	h.gce.machineTypes["us-central1-a/t2a-standard-1"] = true
	h.gce.machineArch["t2a-standard-1"] = "ARM64"
	// The API reports no architecture: the family tells.
	h.gce.machineTypes["us-central1-a/c4a-standard-1"] = true
	// The API wins over the family.
	h.gce.machineTypes["us-central1-a/c4a-weird-1"] = true
	h.gce.machineArch["c4a-weird-1"] = "X86_64"
	h.gce.mu.Unlock()
	for _, tc := range []struct {
		args []string
		want string // image row, or exit class:message
	}{
		{nil, "image/debian unchanged debian-13-trixie-v20261116 (min disk 10GB)"},
		{[]string{"--machine-type", "2H4G"}, "image/debian unchanged debian-13-trixie-v20261116 (min disk 10GB)"},
		{[]string{"--machine-type", "t2a-standard-1"}, "image/debian unchanged debian-13-trixie-arm64-v20261116 (min disk 10GB)"},
		{[]string{"--machine-type", "c4a-standard-1"}, "image/debian unchanged debian-13-trixie-arm64-v20261116 (min disk 10GB)"},
		{[]string{"--machine-type", "c4a-weird-1"}, "image/debian unchanged debian-13-trixie-v20261116 (min disk 10GB)"},
		{[]string{"--os-version", "12"}, "image/debian unchanged debian-12-bookworm-v20261117 (min disk 10GB)"},
		{[]string{"--os", "ubuntu"}, "image/ubuntu unchanged ubuntu-2604-resolute-amd64-v20261107 (min disk 10GB)"},
		{[]string{"--image", "projects/debian-cloud/global/images/debian-12-bookworm-v20261117"}, "image/custom unchanged debian-12-bookworm-v20261117 (min disk 10GB)"},
		{[]string{"--machine-type", "t2a-standard-1", "--image", "projects/debian-cloud/global/images/debian-13-trixie-arm64-v20261116"},
			"image/custom unchanged debian-13-trixie-arm64-v20261116 (min disk 10GB)"},
		{[]string{"--machine-type", "t2a-standard-1", "--os-version", "12"}, "notfound:no current arm64 image of debian 12 in project debian-cloud for machine type t2a-standard-1 (zone us-central1-a, region us-central1); check --os / --os-version, or pass --image"},
		{[]string{"--machine-type", "t2a-standard-1", "--os", "windows"}, "notfound:no current arm64 image of windows"},
		{[]string{"--machine-type", "t2a-standard-1", "--image", "projects/debian-cloud/global/images/debian-12-bookworm-v20261117"}, "usage:is an x86_64 image, but machine type t2a-standard-1 is arm64"},
		{[]string{"--image", "projects/debian-cloud/global/images/debian-13-trixie-arm64-v20261116"}, "usage:is an arm64 image, but machine type e2-small is x86_64"},
	} {
		err := h.run(append([]string{"compute", "instance", "create", "web-1"}, tc.args...)...)
		if class, msg, isErr := strings.Cut(tc.want, ":"); isErr && !strings.HasPrefix(tc.want, "image/") {
			if exitClass(err) != class || err == nil || !strings.Contains(err.Error(), msg) {
				t.Errorf("create %v = %v (%s), want %s with %q", tc.args, err, exitClass(err), class, msg)
			}
			continue
		}
		if err != nil {
			t.Errorf("create %v: %v", tc.args, err)
			continue
		}
		if got := rows(h.report()); at(got, 0) != tc.want {
			t.Errorf("create %v image = %q, want %q", tc.args, at(got, 0), tc.want)
		}
		if w := h.gce.writes(); len(w) != 0 {
			t.Errorf("create %v dry run wrote %v", tc.args, w)
		}
	}
}

func TestInstanceCreateSubnetDiscovery(t *testing.T) {
	h := newGCPHarness(t, app.Flags{DryRun: true}, defaultsUS())
	h.gce.mu.Lock()
	h.gce.networks["proj/net-a"] = &compute.Network{Name: "net-a"}
	h.gce.networks["proj/net-c"] = &compute.Network{Name: "net-c"}
	h.gce.subnets["proj/us-central1"] = append(h.gce.subnets["proj/us-central1"],
		&compute.Subnetwork{Name: "a-1", Network: apiBase + "projects/proj/global/networks/net-a"},
		&compute.Subnetwork{Name: "a2-1", Network: apiBase + "projects/proj/global/networks/net-a-2"},
		&compute.Subnetwork{Name: "a2-2", Network: apiBase + "projects/proj/global/networks/net-a-2"},
	)
	h.gce.mu.Unlock()
	// Exactly one subnetwork of net-a (net-a-2 does not count).
	if err := h.run("compute", "instance", "create", "web-1", "--network", "net-a"); err != nil {
		t.Fatal(err)
	}
	if r := rows(h.report()); !slices.Contains(r, "address/web-1-internal-ip would_create INTERNAL subnet a-1") {
		t.Errorf("rows = %v", r)
	}
	// Two subnetworks: usage error.
	if err := h.run("compute", "instance", "create", "web-1", "--network", "net-a-2"); exitClass(err) != "usage" || !strings.Contains(err.Error(), "--subnet") {
		t.Errorf("two subnets = %v", err)
	}
	// A custom-mode network without a subnetwork in the region: exit code 1.
	if err := h.run("compute", "instance", "create", "web-1", "--network", "net-c"); exitClass(err) != "general" || !strings.Contains(err.Error(), "custom-mode") {
		t.Errorf("custom without subnet = %v", err)
	}
	// A subnet of another network is a usage error.
	if err := h.run("compute", "instance", "create", "web-1", "--subnet", "a-1"); exitClass(err) != "usage" {
		t.Errorf("subnet of another network = %v", err)
	}
}

func TestInstanceCreateSSHKeysInProjectMetadata(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, defaultsUS())
	a, b := testPublicKey(t, "alice@example.com"), testPublicKey(t, "bob@example.com")
	h.gce.mu.Lock()
	h.gce.projectMeta["proj"] = &compute.Metadata{Items: []*compute.MetadataItems{{Key: "ssh-keys", Value: strPtr("alice:" + a)}, {Key: "enable-oslogin", Value: strPtr("TRUE")}}}
	h.gce.mu.Unlock()
	if err := h.run("compute", "instance", "create", "web-1", "--ssh-key", a, "--ssh-key", "ops:"+b, "--static-ip=false"); err != nil {
		t.Fatal(err)
	}
	if r := rows(h.report()); !strings.HasPrefix(at(r, 1), "ssh-key/alice unchanged present in project metadata") {
		t.Errorf("rows = %v", r)
	}
	in := h.gce.instance("us-central1-a", "web-1")
	v, _ := metadataValue(in.Metadata, "ssh-keys")
	if strings.Contains(v, "alice:") || !strings.HasPrefix(v, "ops:ssh-ed25519 ") || len(in.Metadata.Items) != 1 {
		t.Errorf("ssh-keys = %q", v)
	}
	if !strings.Contains(h.stderr.String(), "OS Login") {
		t.Errorf("no OS Login warning: %s", h.stderr.String())
	}
	// --ssh-key-instance-only writes them all, as one item with two lines.
	if err := h.run("compute", "instance", "create", "web-2", "--ssh-key", a, "--ssh-key", "ops:"+b, "--static-ip=false", "--ssh-key-instance-only"); err != nil {
		t.Fatal(err)
	}
	v, _ = metadataValue(h.gce.instance("us-central1-a", "web-2").Metadata, "ssh-keys")
	if strings.Count(v, "\n") != 1 || !strings.HasPrefix(v, "alice:") {
		t.Errorf("instance-only ssh-keys = %q", v)
	}
	// A project that blocks its own keys: every key goes into the instance.
	h.gce.mu.Lock()
	h.gce.projectMeta["proj"].Items = append(h.gce.projectMeta["proj"].Items, &compute.MetadataItems{Key: "block-project-ssh-keys", Value: strPtr("true")})
	h.gce.mu.Unlock()
	if err := h.run("compute", "instance", "create", "web-3", "--ssh-key", a, "--static-ip=false"); err != nil {
		t.Fatal(err)
	}
	v, _ = metadataValue(h.gce.instance("us-central1-a", "web-3").Metadata, "ssh-keys")
	if !strings.HasPrefix(v, "alice:") || !strings.Contains(h.stderr.String(), "block-project-ssh-keys") {
		t.Errorf("blocked project ssh-keys = %q\n%s", v, h.stderr.String())
	}
}

func TestInstanceCreateFailures(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, defaultsUS())
	// The instance operation fails: exit code 1 with the code, the
	// addresses are kept.
	h.gce.opFail["insert"] = compute.OperationErrorErrors{Code: "ZONE_RESOURCE_POOL_EXHAUSTED", Message: "no capacity"}
	err := h.run("compute", "instance", "create", "web-1")
	if exitClass(err) != "general" || !strings.Contains(err.Error(), "ZONE_RESOURCE_POOL_EXHAUSTED") || !strings.Contains(err.Error(), "another zone") {
		t.Errorf("capacity = %v", err)
	}
	if h.gce.address("us-central1", "web-1-external-ip") == nil || !strings.Contains(h.stderr.String(), "kept") {
		t.Errorf("addresses not kept / no note: %s", h.stderr.String())
	}
	delete(h.gce.opFail, "insert")
	// The retry reuses them.
	if err := h.run("compute", "instance", "create", "web-1"); err != nil {
		t.Fatal(err)
	}
	if got := h.gce.writes(); !slices.Equal(got, []string{"POST instances"}) {
		t.Errorf("retry writes = %v", got)
	}
	// A quota error at submission is exit code 1, not 3.
	h.gce.fail["POST /projects/proj/zones/us-central1-a/instances"] = fakeErr{403, "quotaExceeded", "Quota 'CPUS' exceeded."}
	if err := h.run("compute", "instance", "create", "web-2", "--static-ip=false"); exitClass(err) != "general" {
		t.Errorf("quota = %v (%s)", err, exitClass(err))
	}
	// A permission error is exit code 3.
	h.gce.fail["POST /projects/proj/zones/us-central1-a/instances"] = fakeErr{403, "forbidden", "Required 'compute.instances.create' permission"}
	if err := h.run("compute", "instance", "create", "web-2", "--static-ip=false"); exitClass(err) != "auth" {
		t.Errorf("forbidden = %v (%s)", err, exitClass(err))
	}
	delete(h.gce.fail, "POST /projects/proj/zones/us-central1-a/instances")
	// An instance that never runs is a timeout (exit code 1).
	h.gce.stuck["insert"] = statusStaging
	if err := h.run("compute", "instance", "create", "web-3", "--static-ip=false", "--timeout", "1m"); exitClass(err) != "general" || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("never running = %v", err)
	}
}

func TestInstanceDelete(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	in := h.gce.addInstance("proj", "us-central1-a", "web-1", "10.128.0.5", "198.51.100.5")
	h.gce.addAddress("us-central1", &compute.Address{Name: "web-1-external-ip", Address: "198.51.100.5", AddressType: "EXTERNAL"})
	h.gce.addAddress("us-central1", &compute.Address{Name: "web-1-internal-ip", Address: "10.128.0.99", AddressType: "INTERNAL", Subnetwork: "default"})
	other := h.gce.addInstance("proj", "us-central1-a", "web-2", "10.128.0.99", "")

	// Non-interactive without --yes: usage error, nothing written.
	if err := h.run("compute", "instance", "delete", "web-1"); exitClass(err) != "usage" || len(h.gce.writes()) != 0 {
		t.Errorf("no --yes = %v, writes %v", err, h.gce.writes())
	}
	if !strings.Contains(h.stderr.String(), "kept") || !strings.Contains(h.stderr.String(), "web-1-external-ip") {
		t.Errorf("kept addresses not listed: %s", h.stderr.String())
	}
	// Deletion protection: exit code 1.
	in.DeletionProtection = true
	if err := h.run("compute", "instance", "delete", "web-1", "--yes"); exitClass(err) != "general" || !strings.Contains(err.Error(), "deletion protection") {
		t.Errorf("protected = %v", err)
	}
	in.DeletionProtection = false
	// Dry run: no writes, no confirmation.
	h.rt.Flags.DryRun = true
	if err := h.run("compute", "instance", "delete", "web-1", "--release-ips"); err != nil || len(h.gce.writes()) != 0 {
		t.Errorf("dry run = %v, writes %v", err, h.gce.writes())
	}
	if r := rows(h.report()); !slices.Equal(r, []string{"instance/web-1 would_delete zone us-central1-a", "address/web-1-external-ip would_delete 198.51.100.5",
		"address/web-1-internal-ip skipped in use by web-2; kept"}) {
		t.Errorf("dry run rows = %v", r)
	}
	h.rt.Flags.DryRun = false
	// --release-ips deletes the RESERVED address only.
	if err := h.run("compute", "instance", "delete", "web-1", "--release-ips", "--yes"); err != nil {
		t.Fatal(err)
	}
	if got, want := h.gce.writes(), []string{"DELETE instances/web-1", "DELETE addresses/web-1-external-ip"}; !slices.Equal(got, want) {
		t.Errorf("writes = %v, want %v", got, want)
	}
	if h.gce.instance("us-central1-a", "web-1") != nil || h.gce.address("us-central1", "web-1-external-ip") != nil || h.gce.address("us-central1", "web-1-internal-ip") == nil {
		t.Error("wrong state after delete")
	}
	// The inventory forgot it.
	if err := h.run("compute", "instance", "get", "web-1"); exitClass(err) != "notfound" {
		t.Errorf("get after delete = %v", err)
	}
	_ = other
}

func TestInstanceDeleteInteractive(t *testing.T) {
	h := newGCPHarness(t, app.Flags{NonInteractiveSet: true}, nil)
	h.rt.Flags.NonInteractive = false
	h.rt.Picker = &scriptedPicker{t: t}
	h.gce.addInstance("proj", "us-central1-a", "web-1", "10.128.0.5", "198.51.100.5")
	h.rt.Stdin = strings.NewReader("n\n")
	if err := h.run("compute", "instance", "delete", "web-1"); exitClass(err) != "nothing" || len(h.gce.writes()) != 0 {
		t.Errorf("declined = %v, writes %v", err, h.gce.writes())
	}
	h.rt.Stdin = strings.NewReader("y\n")
	if err := h.run("compute", "instance", "delete", "web-1"); err != nil || !slices.Equal(h.gce.writes(), []string{"DELETE instances/web-1"}) {
		t.Errorf("confirmed = %v, writes %v", err, h.gce.writes())
	}
}

func TestInstanceResize(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.gce.addInstance("proj", "us-central1-a", "web-1", "10.128.0.5", "34.1.0.5")
	h.gce.addAddress("us-central1", &compute.Address{Name: "web-1-external-ip", Address: "34.1.0.5", AddressType: "EXTERNAL"})

	// Running, non-interactive without --yes: usage error before anything.
	if err := h.run("compute", "instance", "resize", "web-1", "--machine-type", "e2-standard-4"); exitClass(err) != "usage" || len(h.gce.writes()) != 0 {
		t.Errorf("no --yes = %v, writes %v", err, h.gce.writes())
	}
	// Dry run: the steps, no writes.
	h.rt.Flags.DryRun = true
	if err := h.run("compute", "instance", "resize", "web-1", "--machine-type", "e2-standard-4"); err != nil || len(h.gce.writes()) != 0 {
		t.Fatalf("dry run = %v, writes %v", err, h.gce.writes())
	}
	if r := rows(h.report()); !slices.Equal(r, []string{
		"address/web-1-external-ip unchanged 34.1.0.5 already static",
		"address/web-1-internal-ip would_create promote 10.128.0.5 to a static internal address",
		"instance/web-1/stop would_update stop",
		"instance/web-1/machine-type would_update e2-small -> e2-standard-4",
		"instance/web-1/start would_update start",
	}) {
		t.Errorf("dry run rows = %v", r)
	}
	h.rt.Flags.DryRun = false
	// The real run: promote the internal IP, stop, change, start.
	if err := h.run("compute", "instance", "resize", "web-1", "--machine-type", "e2-standard-4", "--yes"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if got, want := h.gce.writes(), []string{"POST addresses", "POST instances/web-1/stop", "POST instances/web-1/setMachineType", "POST instances/web-1/start"}; !slices.Equal(got, want) {
		t.Errorf("writes = %v, want %v", got, want)
	}
	in := h.gce.instance("us-central1-a", "web-1")
	if lastSegment(in.MachineType) != "e2-standard-4" || in.Status != statusRunning || in.NetworkInterfaces[0].AccessConfigs[0].NatIP != "34.1.0.5" {
		t.Errorf("after resize: %s %s %s", in.MachineType, in.Status, in.NetworkInterfaces[0].AccessConfigs[0].NatIP)
	}
	if a := h.gce.address("us-central1", "web-1-internal-ip"); a == nil || a.Address != "10.128.0.5" || !strings.HasSuffix(a.Subnetwork, "/subnetworks/default") {
		t.Errorf("promoted internal = %+v", a)
	}
	if strings.Contains(h.stderr.String(), "IP changed") || !strings.Contains(h.stderr.String(), "resized e2-small -> e2-standard-4") {
		t.Errorf("stderr = %s", h.stderr.String())
	}
	// The same type: unchanged, nothing written.
	if err := h.run("compute", "instance", "resize", "web-1", "--machine-type", "e2-standard-4"); err != nil || len(h.gce.writes()) != 0 {
		t.Errorf("same type = %v, writes %v", err, h.gce.writes())
	}
	if r := rows(h.report()); !slices.Equal(r, []string{"instance/web-1/machine-type unchanged e2-standard-4"}) {
		t.Errorf("same type rows = %v", r)
	}
	// A type the zone lacks: exit code 2, nothing written.
	if err := h.run("compute", "instance", "resize", "web-1", "--machine-type", "n9-huge", "--yes"); exitClass(err) != "usage" || len(h.gce.writes()) != 0 {
		t.Errorf("missing type = %v, writes %v", err, h.gce.writes())
	}
	if err := h.run("compute", "instance", "resize", "web-1"); exitClass(err) != "usage" {
		t.Errorf("no --machine-type = %v", err)
	}
}

func TestInstanceResizeStoppedAndEphemeral(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	// A stopped instance: no confirmation, no promotion, no start.
	off := h.gce.addInstance("proj", "us-central1-a", "off-1", "10.128.0.8", "")
	off.Status = statusTerminated
	if err := h.run("compute", "instance", "resize", "off-1", "--machine-type", "e2-medium"); err != nil {
		t.Fatal(err)
	}
	if got := h.gce.writes(); !slices.Equal(got, []string{"POST instances/off-1/setMachineType"}) {
		t.Errorf("stopped writes = %v", got)
	}
	if !strings.Contains(h.stderr.String(), "stays stopped") || h.gce.instance("us-central1-a", "off-1").Status != statusTerminated {
		t.Errorf("stderr = %s", h.stderr.String())
	}
	// --start starts it after the change.
	h.gce.mu.Lock()
	h.gce.calls = nil
	h.gce.mu.Unlock()
	if err := h.run("compute", "instance", "resize", "off-1", "--machine-type", "e2-standard-4", "--start"); err != nil {
		t.Fatal(err)
	}
	if got := h.gce.writes(); !slices.Equal(got, []string{"POST instances/off-1/setMachineType", "POST instances/off-1/start"}) || h.gce.instance("us-central1-a", "off-1").Status != statusRunning {
		t.Errorf("--start writes = %v", got)
	}
	// Ephemeral external IP: promoted to {name}-external-ip, kept after
	// the restart.
	h.gce.addInstance("proj", "us-central1-a", "eph-1", "10.128.0.9", "34.1.0.9")
	if err := h.run("compute", "instance", "resize", "eph-1", "--machine-type", "e2-medium", "--yes"); err != nil {
		t.Fatal(err)
	}
	if a := h.gce.address("us-central1", "eph-1-external-ip"); a == nil || a.Address != "34.1.0.9" || a.Status != addrInUse {
		t.Errorf("promoted external = %+v", a)
	}
	if ip := h.gce.instance("us-central1-a", "eph-1").NetworkInterfaces[0].AccessConfigs[0].NatIP; ip != "34.1.0.9" {
		t.Errorf("external ip after resize = %s", ip)
	}
	// The external promotion fails: the instance is not stopped.
	h.gce.addInstance("proj", "us-central1-a", "eph-2", "10.128.0.10", "34.1.0.10")
	h.gce.opFail["insertAddress"] = compute.OperationErrorErrors{Code: "QUOTA_EXCEEDED", Message: "STATIC_ADDRESSES"}
	err := h.run("compute", "instance", "resize", "eph-2", "--machine-type", "e2-medium", "--yes")
	if exitClass(err) != "general" || !strings.Contains(err.Error(), "not stopped") || h.gce.instance("us-central1-a", "eph-2").Status != statusRunning {
		t.Errorf("failed promotion = %v", err)
	}
	delete(h.gce.opFail, "insertAddress")
	// A stop that never completes is a timeout (exit code 1).
	h.gce.addInstance("proj", "us-central1-a", "slow-1", "10.128.0.11", "")
	h.gce.stuck["stop"] = statusStopping
	if err := h.run("compute", "instance", "resize", "slow-1", "--machine-type", "e2-medium", "--yes", "--timeout", "1m"); exitClass(err) != "general" || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("stop timeout = %v", err)
	}
}

func TestInstanceResizeWaitSSH(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.gce.addInstance("proj", "us-central1-a", "web-1", "10.128.0.5", "")
	var dialed []string
	dialTCP = func(ctx context.Context, addr string, _ time.Duration) error {
		dialed = append(dialed, addr)
		if len(dialed) < 3 {
			return errors.New("refused")
		}
		return nil
	}
	if err := h.run("compute", "instance", "resize", "web-1", "--machine-type", "e2-medium", "--yes", "--wait-ssh"); err != nil {
		t.Fatal(err)
	}
	if len(dialed) != 3 || dialed[0] != "10.128.0.5:22" || !strings.Contains(h.stderr.String(), "accepts connections") {
		t.Errorf("dialed %v, stderr %s", dialed, h.stderr.String())
	}
	// --wait-port names the port.
	dialed = nil
	if err := h.run("compute", "instance", "resize", "web-1", "--machine-type", "e2-standard-4", "--yes", "--wait-port", "2222"); err != nil {
		t.Fatal(err)
	}
	if len(dialed) != 3 || dialed[0] != "10.128.0.5:2222" {
		t.Errorf("--wait-port 2222 dialed %v", dialed)
	}
	// Never reachable: exit code 1 after 5 minutes.
	dialTCP = func(context.Context, string, time.Duration) error { return errors.New("refused") }
	if err := h.run("compute", "instance", "resize", "web-1", "--machine-type", "e2-small", "--yes", "--wait-ssh"); exitClass(err) != "general" || !strings.Contains(err.Error(), "port 22") {
		t.Errorf("unreachable = %v", err)
	}
}

func TestInstanceReboot(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.gce.addInstance("proj", "us-central1-a", "web-1", "10.128.0.5", "203.0.113.10")
	off := h.gce.addInstance("proj", "us-central1-a", "off-1", "10.128.0.6", "")
	off.Status = statusTerminated

	if err := h.run("compute", "instance", "reboot", "off-1", "--yes"); exitClass(err) != "general" || !strings.Contains(err.Error(), "RUNNING") || len(h.gce.writes()) != 0 {
		t.Errorf("stopped = %v, writes %v", err, h.gce.writes())
	}
	if err := h.run("compute", "instance", "reboot", "web-1"); exitClass(err) != "usage" || len(h.gce.writes()) != 0 {
		t.Errorf("no --yes = %v", err)
	}
	if !strings.Contains(h.stderr.String(), "hard reset") {
		t.Errorf("no hard reset warning: %s", h.stderr.String())
	}
	// By external IP, with --wait.
	if err := h.run("compute", "instance", "reboot", "203.0.113.10", "--yes", "--wait"); err != nil {
		t.Fatal(err)
	}
	if got := h.gce.writes(); !slices.Equal(got, []string{"POST instances/web-1/reset"}) {
		t.Errorf("writes = %v", got)
	}
	if r := rows(h.report()); !slices.Equal(r, []string{"instance/web-1 updated reset (hard reboot); done"}) {
		t.Errorf("rows = %v", r)
	}
	// The operation fails: exit code 1 with its code.
	h.gce.opFail["reset"] = compute.OperationErrorErrors{Code: "INTERNAL_ERROR", Message: "boom"}
	if err := h.run("compute", "instance", "reboot", "web-1", "--yes", "--wait"); exitClass(err) != "general" || !strings.Contains(err.Error(), "INTERNAL_ERROR") {
		t.Errorf("op error = %v", err)
	}
	delete(h.gce.opFail, "reset")
	// Dry run: no write, no confirmation.
	h.rt.Flags.DryRun = true
	if err := h.run("compute", "instance", "reboot", "web-1"); err != nil || len(h.gce.writes()) != 0 {
		t.Errorf("dry run = %v, writes %v", err, h.gce.writes())
	}
	h.rt.Flags.DryRun = false
	// An internal IP that two projects share: ambiguous.
	h.addProfile()
	h.gce.addInstance("other", "us-central1-a", "peer-1", "10.128.0.5", "")
	h.rt.Flags.Refresh = true
	var amb *app.AmbiguousError
	if err := h.run("compute", "instance", "reboot", "10.128.0.5", "--yes"); !errors.As(err, &amb) || len(amb.Candidates) != 2 {
		t.Errorf("shared ip = %v", err)
	}
}

func TestInstanceRebootInteractive(t *testing.T) {
	h := newGCPHarness(t, app.Flags{NonInteractiveSet: true}, nil)
	h.addProfile()
	h.rt.Flags.NonInteractive = false
	picker := &scriptedPicker{t: t, answers: []string{"1"}}
	h.rt.Picker = picker
	h.gce.addInstance("proj", "us-central1-a", "web-1", "10.128.0.5", "")
	h.gce.addInstance("other", "us-central1-a", "peer-1", "10.128.0.5", "")
	h.rt.Stdin = strings.NewReader("y\n")
	if err := h.run("compute", "instance", "reboot", "10.128.0.5"); err != nil {
		t.Fatal(err)
	}
	// Candidates are sorted by profile: lab, then prod; "1" is prod's peer-1.
	if got := h.gce.writes(); !slices.Equal(got, []string{"POST instances/peer-1/reset"}) {
		t.Errorf("writes = %v", got)
	}
	if len(picker.titles) != 1 || !strings.Contains(picker.titles[0], "10.128.0.5") {
		t.Errorf("questions = %v", picker.titles)
	}
	if !strings.Contains(h.stderr.String(), "Hard-reset") {
		t.Errorf("confirmation = %s", h.stderr.String())
	}
}

func TestInstanceUpdateIPForward(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.gce.addInstance("proj", "us-central1-a", "web-1", "10.128.0.5", "")
	if err := h.run("compute", "instance", "update", "web-1"); exitClass(err) != "usage" {
		t.Errorf("no flag = %v", err)
	}
	if err := h.run("compute", "instance", "update", "web-1", "--ip-forward=false"); err != nil || len(h.gce.writes()) != 0 {
		t.Errorf("unchanged = %v, writes %v", err, h.gce.writes())
	}
	if r := rows(h.report()); !slices.Equal(r, []string{"instance/web-1/ip-forward unchanged false"}) {
		t.Errorf("unchanged rows = %v", r)
	}
	h.rt.Flags.DryRun = true
	if err := h.run("compute", "instance", "update", "web-1", "--ip-forward"); err != nil || len(h.gce.writes()) != 0 {
		t.Errorf("dry run = %v, writes %v", err, h.gce.writes())
	}
	h.rt.Flags.DryRun = false
	if err := h.run("compute", "instance", "update", "web-1", "--ip-forward"); err != nil {
		t.Fatal(err)
	}
	in := h.gce.instance("us-central1-a", "web-1")
	if !in.CanIpForward || in.Status != statusRunning || len(h.gce.updates) != 1 || h.gce.updates[0] != "alt=json&mostDisruptiveAllowedAction=REFRESH&prettyPrint=false" {
		t.Errorf("after update: %v %s %v", in.CanIpForward, in.Status, h.gce.updates)
	}
	if r := rows(h.report()); !slices.Equal(r, []string{"instance/web-1/ip-forward updated false -> true"}) {
		t.Errorf("rows = %v", r)
	}
	// A stopped instance, with a stale fingerprint once: re-read and retry.
	in.Status = statusTerminated
	h.gce.staleFingerprints = 1
	if err := h.run("compute", "instance", "update", "web-1", "--ip-forward=false"); err != nil {
		t.Fatal(err)
	}
	if in := h.gce.instance("us-central1-a", "web-1"); in.CanIpForward || in.Status != statusTerminated || len(h.gce.updates) != 3 {
		t.Errorf("stale retry: %v %s %v", in.CanIpForward, in.Status, h.gce.updates)
	}
	// Stale twice: the error is returned.
	h.gce.staleFingerprints = 2
	if err := h.run("compute", "instance", "update", "web-1", "--ip-forward"); exitClass(err) != "general" || !strings.Contains(err.Error(), "Fingerprint") {
		t.Errorf("stale twice = %v", err)
	}
}

func TestInstanceRoutingAcrossProfiles(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.addProfile()
	h.gce.addInstance("other", "europe-west1-b", "db-1", "10.132.0.2", "")
	if err := h.run("compute", "instance", "get", "db-1"); err != nil {
		t.Fatal(err)
	}
	var d instanceDetail
	h.jsonOut(&d)
	if d.Profile != "prod" || d.Project != "other" || d.Zone != "europe-west1-b" {
		t.Errorf("routed to %+v", d)
	}
	h.gce.addInstance("proj", "us-central1-a", "db-1", "10.128.0.2", "")
	h.rt.Flags.Refresh = true
	var amb *app.AmbiguousError
	if err := h.run("compute", "instance", "get", "db-1"); !errors.As(err, &amb) || !strings.Contains(amb.Hint, "--profile") {
		t.Errorf("two profiles = %v", err)
	}
	h.rt.Flags.Profile = "lab"
	if err := h.run("compute", "instance", "get", "db-1", "--field", "zone"); err != nil || h.stdout.String() != "us-central1-a\n" {
		t.Errorf("--profile = %q, %v", h.stdout.String(), err)
	}
	// A stale inventory row: not found, and the row is dropped.
	h.rt.Flags.Refresh = false
	h.gce.mu.Lock()
	delete(h.gce.instances, "proj/us-central1-a/db-1")
	h.gce.mu.Unlock()
	if err := h.run("compute", "instance", "get", "db-1"); exitClass(err) != "notfound" || !strings.Contains(err.Error(), "stale") {
		t.Errorf("stale = %v", err)
	}
	_ = fmt.Sprint()
}

func TestInstanceStartStop(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.gce.addInstance("proj", "us-central1-a", "web-1", "10.128.0.5", "203.0.113.10")

	// Running already: unchanged, nothing written.
	if err := h.run("compute", "instance", "start", "web-1"); err != nil {
		t.Fatal(err)
	}
	if r := rows(h.report()); !slices.Equal(r, []string{"instance/web-1 unchanged RUNNING"}) || len(h.gce.writes()) != 0 {
		t.Errorf("start of a running instance: rows %v, writes %v", r, h.gce.writes())
	}
	// stop asks: the non-interactive flow needs --yes.
	if err := h.run("compute", "instance", "stop", "web-1"); exitClass(err) != "usage" || len(h.gce.writes()) != 0 {
		t.Errorf("stop without --yes = %v, writes %v", err, h.gce.writes())
	}
	if err := h.run("compute", "instance", "stop", "web-1", "--yes", "--wait"); err != nil {
		t.Fatal(err)
	}
	if r := rows(h.report()); !slices.Equal(r, []string{"instance/web-1 updated stop; TERMINATED"}) {
		t.Errorf("stop rows = %v", r)
	}
	if err := h.run("compute", "instance", "start", "web-1", "--wait"); err != nil {
		t.Fatal(err)
	}
	if r := rows(h.report()); !slices.Equal(r, []string{"instance/web-1 updated start; RUNNING"}) {
		t.Errorf("start rows = %v", r)
	}
	// An instance nobody has: not found (exit code 4), not a general error.
	if err := h.run("compute", "instance", "start", "nope"); exitClass(err) != "notfound" {
		t.Errorf("missing instance = %v (%s)", err, exitClass(err))
	}
}

// A Linux instance logs in with an SSH key only: without a key of its own
// the project has to hold one or enable OS Login, otherwise create is a
// usage error before anything is written. Nothing ever sets a password.
func TestInstanceCreateLinuxNeedsAKey(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, map[string]any{"zone": "us-central1-a"})
	h.gce.projectMeta["proj"] = nil
	err := h.run("compute", "instance", "create", "web-1", "--machine-type", "e2-small")
	if exitClass(err) != "usage" || !strings.Contains(err.Error(), "--ssh-key") || !strings.Contains(err.Error(), "never a password") {
		t.Fatalf("no key anywhere = %v", err)
	}
	if w := h.gce.writes(); len(w) != 0 {
		t.Errorf("writes = %v", w)
	}
	// The project's keys are enough; the instance then gets no metadata.
	key := testPublicKey(t, "")
	h.gce.projectMeta["proj"] = &compute.Metadata{Items: []*compute.MetadataItems{{Key: "ssh-keys", Value: strPtr("ops:" + key)}}}
	if err := h.run("compute", "instance", "create", "web-1", "--machine-type", "e2-small", "--static-ip=false"); err != nil {
		t.Fatalf("project keys: %v\n%s", err, h.stderr.String())
	}
	if in := h.gce.instance("us-central1-a", "web-1"); in == nil || in.Metadata != nil {
		t.Errorf("instance metadata = %+v", in)
	}
	if !strings.Contains(h.stderr.String(), "SSH keys of the project metadata") {
		t.Errorf("stderr = %s", h.stderr.String())
	}
	// An image of one's own built from Windows Server (the WINDOWS guest
	// OS feature) is a Windows instance: it needs no SSH key.
	h.gce.projectMeta["proj"] = nil
	h.gce.images["proj"] = []*compute.Image{{Name: "my-win", Architecture: "X86_64", DiskSizeGb: 50,
		GuestOsFeatures: []*compute.GuestOsFeature{{Type: "WINDOWS"}}}}
	if err := h.run("compute", "instance", "create", "win-1", "--machine-type", "e2-small", "--static-ip=false", "--image", "projects/proj/global/images/my-win"); err != nil {
		t.Fatalf("custom Windows image: %v\n%s", err, h.stderr.String())
	}
	// With its own key, the only metadata item is ssh-keys: no password,
	// no windows-keys, no startup script.
	if err := h.run("compute", "instance", "create", "web-2", "--machine-type", "e2-small", "--static-ip=false", "--ssh-key", "alice:"+key); err != nil {
		t.Fatal(err)
	}
	in := h.gce.instance("us-central1-a", "web-2")
	if in == nil || in.Metadata == nil || len(in.Metadata.Items) != 1 || in.Metadata.Items[0].Key != "ssh-keys" {
		t.Fatalf("metadata = %+v", in)
	}
}

func TestCheckProjectLogin(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	key := testPublicKey(t, "")
	md := func(items ...*compute.MetadataItems) func() (*compute.Metadata, error) {
		return func() (*compute.Metadata, error) { return &compute.Metadata{Items: items}, nil }
	}
	keys := &compute.MetadataItems{Key: "ssh-keys", Value: strPtr("ops:" + key)}
	for name, tc := range map[string]struct {
		read func() (*compute.Metadata, error)
		ok   bool
	}{
		"project keys": {md(keys), true},
		"os login":     {md(&compute.MetadataItems{Key: "enable-oslogin", Value: strPtr("TRUE")}), true},
		"blocked keys": {md(keys, &compute.MetadataItems{Key: "block-project-ssh-keys", Value: strPtr("TRUE")}), false},
		"nothing":      {md(), false},
		"unparseable":  {md(&compute.MetadataItems{Key: "ssh-keys", Value: strPtr("garbage")}), false},
		"no metadata":  {func() (*compute.Metadata, error) { return nil, nil }, false},
		"forbidden":    {func() (*compute.Metadata, error) { return nil, fmt.Errorf("%w: read", platform.ErrForbidden) }, false},
	} {
		err := checkProjectLogin(h.rt, tc.read)
		if tc.ok != (err == nil) || err != nil && exitClass(err) != "usage" {
			t.Errorf("%s = %v", name, err)
		}
	}
	// A failure that is not about the key keeps its class: an expired
	// login is still an auth error, a network failure a general one.
	if err := checkProjectLogin(h.rt, func() (*compute.Metadata, error) { return nil, fmt.Errorf("%w: token", platform.ErrUnauthorized) }); exitClass(err) != "auth" {
		t.Errorf("unauthorized = %v (%s)", err, exitClass(err))
	}
	if err := checkProjectLogin(h.rt, func() (*compute.Metadata, error) { return nil, errors.New("connection reset") }); err == nil || exitClass(err) == "usage" {
		t.Errorf("network failure = %v", err)
	}
	for _, tc := range []struct {
		os, image string
		want      bool
	}{
		{"windows", "", true},
		{"debian", "", false},
		{"windows", "projects/debian-cloud/global/images/family/debian-12", false},
		{"", "projects/windows-cloud/global/images/family/windows-2022", true},
		{"", "https://compute.googleapis.com/compute/v1/projects/windows-cloud/global/images/x", true},
	} {
		o := &createOptions{osName: tc.os, image: tc.image}
		if got := o.windows(); got != tc.want {
			t.Errorf("windows(%q, %q) = %v", tc.os, tc.image, got)
		}
	}
}

// TestInstanceZoneNamesEveryOtherZone: a name held only in other zones is
// not found, and the error names each of those zones.
func TestInstanceZoneNamesEveryOtherZone(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.gce.addInstance("proj", "us-central1-a", "web-1", "10.128.0.5", "")
	h.gce.addInstance("proj", "us-central1-c", "web-1", "10.128.0.6", "")
	if err := h.run("compute", "instance", "list"); err != nil {
		t.Fatal(err)
	}
	err := h.run("compute", "instance", "get", "web-1", "--zone", "us-central1-b")
	if exitClass(err) != "notfound" || !strings.Contains(err.Error(), "in zones us-central1-a, us-central1-c") {
		t.Errorf("err = %v", err)
	}
}
