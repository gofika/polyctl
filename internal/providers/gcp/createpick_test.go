package gcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// localKey makes a temporary home directory holding ~/.ssh/<name>.pub
// and returns the path of that file.
func localKey(t *testing.T, name, comment string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name+".pub")
	if err := os.WriteFile(path, []byte(testPublicKey(t, comment)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// On a terminal, create without <name>, --zone and --machine-type (and no
// defaults) picks the zone (UP and not deprecated only), the machine type
// of the zone (x86, E2 first) and asks the name, checked as typed against
// the rules and the instances of the zone. A project that offers no SSH
// login gets a local public key instead of a usage error.
func TestInstanceCreateInteractive(t *testing.T) {
	key := localKey(t, "id_ed25519", "")
	h, _ := interactiveGCP(t, nil)
	h.rt.Flags.DryRun = true
	h.gce.addInstance("proj", "us-central1-a", "web-1", "10.128.0.5", "")
	h.gce.projectMeta["proj"] = &compute.Metadata{}
	h.gce.machineTypes["us-central1-a/c4a-standard-2"] = true
	h.gce.machineArch["c4a-standard-2"] = "ARM64"

	p := h.answer("us-central1-a", "e2-small", "Bad_Name", "web-1", "web-9", key, "ops")
	if err := h.run("compute", "instance", "create"); err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if v := prompttest.Values(p.Find("Zone").Options); v != "europe-west1-b us-central1-a us-central1-b" {
		t.Errorf("zones offered: %s", v)
	}
	if v := prompttest.Values(p.Asked[1].Options); strings.Contains(v, "c4a") || !strings.HasPrefix(v, "e2-micro e2-small e2-medium") {
		t.Errorf("machine types offered: %s", v)
	}
	if p.Asked[1].Default != defaultPickMachineType {
		t.Errorf("machine type default %q", p.Asked[1].Default)
	}
	if l := prompttest.Labels(p.Asked[5].Options); !strings.Contains(l, "~/.ssh/id_ed25519.pub  ed25519 SHA256:") || !strings.Contains(l, "Another file...") {
		t.Errorf("keys offered:\n%s", l)
	}
	out := strings.Join(rows(h.report()), "\n")
	if !strings.Contains(out, "instance/web-9 would_create e2-small") || !strings.Contains(out, "ssh keys ops") {
		t.Errorf("report:\n%s", out)
	}

	// The non-interactive flow still needs the zone and keeps refusing a
	// Linux instance without an SSH login.
	h.nonInteractive()
	if err := h.run("compute", "instance", "create", "web-9", "--machine-type", "e2-small"); exitClass(err) != "usage" || !strings.Contains(err.Error(), "zone") {
		t.Errorf("non-interactive without a zone = %v", err)
	}
	if err := h.run("compute", "instance", "create", "web-9", "--machine-type", "e2-small", "--zone", "us-central1-a"); exitClass(err) != "usage" || !strings.Contains(err.Error(), "no SSH key given") {
		t.Errorf("non-interactive without a key = %v", err)
	}
	// A malformed size is a usage error, with no request made.
	h.gce.mu.Lock()
	h.gce.calls = nil
	h.gce.mu.Unlock()
	if err := h.run("compute", "instance", "create", "web-9", "--machine-type", "0H1G", "--zone", "us-central1-a"); exitClass(err) != "usage" || !strings.Contains(err.Error(), "vCPUs") {
		t.Errorf("non-interactive malformed size = %v", err)
	}
	h.gce.mu.Lock()
	calls := h.gce.calls
	h.gce.mu.Unlock()
	if len(calls) != 0 {
		t.Errorf("malformed size made requests: %v", calls)
	}
}

// Several ordinary subnetworks of the network in the zone's region are a
// pick (proxy-only ones left out); the non-interactive flow names --subnet.
func TestInstanceCreatePicksSubnet(t *testing.T) {
	h, _ := interactiveGCP(t, defaultsUS())
	h.rt.Flags.DryRun = true
	net := apiBase + "projects/proj/global/networks/default"
	h.gce.subnets["proj/us-central1"] = append(h.gce.subnets["proj/us-central1"],
		&compute.Subnetwork{Name: "apps", Network: net, IpCidrRange: "10.10.0.0/24", Purpose: "PRIVATE"},
		&compute.Subnetwork{Name: "proxy", Network: net, IpCidrRange: "10.129.0.0/23", Purpose: "REGIONAL_MANAGED_PROXY"})
	p := h.answer("apps")
	if err := h.run("compute", "instance", "create", "web-9"); err != nil {
		t.Fatalf("create: %v", err)
	}
	p.Done()
	if v := prompttest.Values(p.Asked[0].Options); v != "apps default" {
		t.Errorf("subnets offered: %s", v)
	}
	h.nonInteractive()
	if err := h.run("compute", "instance", "create", "web-9"); exitClass(err) != "usage" || !strings.Contains(err.Error(), "--subnet") {
		t.Errorf("non-interactive = %v", err)
	}
}

// A proxy-only subnetwork next to the only ordinary one is not counted:
// the ordinary one is used without --subnet, in either flow.
func TestInstanceCreateSkipsProxyOnlySubnet(t *testing.T) {
	h, _ := interactiveGCP(t, defaultsUS())
	h.rt.Flags.DryRun = true
	net := apiBase + "projects/proj/global/networks/default"
	h.gce.subnets["proj/us-central1"] = append(h.gce.subnets["proj/us-central1"],
		&compute.Subnetwork{Name: "proxy", Network: net, IpCidrRange: "10.129.0.0/23", Purpose: "REGIONAL_MANAGED_PROXY"})
	h.nonInteractive()
	if err := h.run("compute", "instance", "create", "web-9", "--ssh-key", "ops:"+testPublicKey(t, "")); err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	if out := strings.Join(rows(h.report()), "\n"); strings.Contains(out, "proxy") {
		t.Errorf("report names the proxy-only subnetwork:\n%s", out)
	}
}

// A project without a network named default: the network is picked.
func TestInstanceCreatePicksNetwork(t *testing.T) {
	h, _ := interactiveGCP(t, defaultsUS())
	h.rt.Flags.DryRun = true
	delete(h.gce.networks, "proj/default")
	h.gce.networks["proj/prod"] = &compute.Network{Name: "prod", AutoCreateSubnetworks: true}
	h.gce.subnets["proj/us-central1"] = []*compute.Subnetwork{{Name: "prod", Network: apiBase + "projects/proj/global/networks/prod", IpCidrRange: "10.128.0.0/20"}}
	p := h.answer("prod")
	if err := h.run("compute", "instance", "create", "web-9"); err != nil {
		t.Fatalf("create: %v", err)
	}
	p.Done()
	if l := prompttest.Labels(p.Asked[0].Options); l != "prod  auto  0 subnets" {
		t.Errorf("networks offered: %s", l)
	}
}
