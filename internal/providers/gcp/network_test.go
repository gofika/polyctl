package gcp

import (
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/platform"
)

// addVPCs adds the networks net-a (custom, with a secondary range and
// proxy-only subnetworks of the three purposes) and net-a-2 to the fake.
func (f *fakeCompute) addVPCs() {
	f.mu.Lock()
	defer f.mu.Unlock()
	netURL := func(n string) string { return apiBase + "projects/proj/global/networks/" + n }
	subURL := func(r, n string) string { return apiBase + "projects/proj/regions/" + r + "/subnetworks/" + n }
	f.networks["proj/net-a"] = &compute.Network{Name: "net-a", Mtu: 1500, RoutingConfig: &compute.NetworkRoutingConfig{RoutingMode: "GLOBAL"},
		Subnetworks: []string{subURL("us-central1", "a-main"), subURL("us-central1", "a-proxy"), subURL("europe-west1", "a-eu")}}
	f.networks["proj/net-a-2"] = &compute.Network{Name: "net-a-2", RoutingConfig: &compute.NetworkRoutingConfig{RoutingMode: "REGIONAL"},
		Subnetworks: []string{subURL("us-central1", "a2-main")}}
	f.networks["proj/old"] = &compute.Network{Name: "old", IPv4Range: "10.240.0.0/16"}
	f.subnets["proj/us-central1"] = append(f.subnets["proj/us-central1"],
		&compute.Subnetwork{Name: "a-main", Network: netURL("net-a"), Region: apiBase + "projects/proj/regions/us-central1", IpCidrRange: "10.0.0.0/24", Purpose: "PRIVATE",
			SecondaryIpRanges: []*compute.SubnetworkSecondaryRange{{RangeName: "pods", IpCidrRange: "10.4.0.0/14"}}},
		&compute.Subnetwork{Name: "a-proxy", Network: netURL("net-a"), Region: apiBase + "projects/proj/regions/us-central1", IpCidrRange: "10.129.0.0/23", Purpose: "REGIONAL_MANAGED_PROXY", Role: "ACTIVE"},
		&compute.Subnetwork{Name: "a-gproxy", Network: netURL("net-a"), Region: apiBase + "projects/proj/regions/us-central1", IpCidrRange: "10.130.0.0/23", Purpose: "GLOBAL_MANAGED_PROXY", Role: "ACTIVE"},
		&compute.Subnetwork{Name: "a-oldproxy", Network: netURL("net-a"), Region: apiBase + "projects/proj/regions/us-central1", IpCidrRange: "10.131.0.0/23", Purpose: "INTERNAL_HTTPS_LOAD_BALANCER", Role: "ACTIVE"},
		&compute.Subnetwork{Name: "a2-main", Network: netURL("net-a-2"), Region: apiBase + "projects/proj/regions/us-central1", IpCidrRange: "10.50.0.0/24", Purpose: "PRIVATE"},
	)
	f.subnets["proj/europe-west1"] = append(f.subnets["proj/europe-west1"],
		&compute.Subnetwork{Name: "a-eu", Network: netURL("net-a"), Region: apiBase + "projects/proj/regions/europe-west1", IpCidrRange: "10.1.0.0/24", Purpose: "PRIVATE"})
}

func TestNetworkList(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.gce.addVPCs()
	if err := h.run("compute", "network", "list"); err != nil {
		t.Fatal(err)
	}
	var rows []networkView
	h.jsonOut(&rows)
	got := map[string]networkView{}
	for _, r := range rows {
		got[r.Name] = r
	}
	if len(rows) != 4 || got["default"].Mode != "auto" || got["net-a"].Mode != "custom" || got["old"].Mode != "legacy" ||
		got["net-a"].RoutingMode != "GLOBAL" || got["net-a"].MTU != 1500 || len(got["net-a"].Subnetworks) != 3 ||
		got["net-a"].Subnetworks[0] != "europe-west1/a-eu" {
		t.Errorf("rows = %+v", rows)
	}
	// The table shows the default MTU of a network that never set one.
	ht := newGCPHarness(t, app.Flags{Output: "table"}, nil)
	ht.gce.addVPCs()
	if err := ht.run("compute", "network", "list"); err != nil {
		t.Fatal(err)
	}
	out := ht.stdout.String()
	if !strings.Contains(out, "1460(default)") || !strings.Contains(out, "SUBNETS") {
		t.Errorf("table:\n%s", out)
	}
	// Read-only: --dry-run is ignored.
	h.rt.Flags.DryRun = true
	if err := h.run("compute", "network", "list"); err != nil || !strings.Contains(h.stdout.String(), "net-a") {
		t.Errorf("dry run = %v", err)
	}
	h.rt.Flags.Offline = true
	if err := h.run("compute", "network", "list"); exitClass(err) != "offline" {
		t.Errorf("offline = %v", err)
	}
}

func TestNetworkGet(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.gce.addVPCs()
	if err := h.run("compute", "network", "get", "net-a"); err != nil {
		t.Fatal(err)
	}
	var v networkView
	h.jsonOut(&v)
	// Exact network match: the subnetworks of net-a-2 are not listed.
	var names []string
	for _, s := range v.Subnets {
		names = append(names, s.Region+"/"+s.Name)
	}
	if v.Name != "net-a" || strings.Join(names, ",") != "europe-west1/a-eu,us-central1/a-gproxy,us-central1/a-main,us-central1/a-oldproxy,us-central1/a-proxy" {
		t.Errorf("network = %+v (%v)", v, names)
	}
	if err := h.run("compute", "network", "get", "nope"); exitClass(err) != "notfound" || !strings.Contains(err.Error(), "gcp/lab") {
		t.Errorf("missing = %v", err)
	}
}

func TestSubnetList(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.gce.addVPCs()
	list := func(args ...string) []subnetView {
		t.Helper()
		if err := h.run(append([]string{"compute", "subnet", "list"}, args...)...); err != nil {
			t.Fatal(err)
		}
		var rows []subnetView
		h.jsonOut(&rows)
		return rows
	}
	names := func(rows []subnetView) string {
		var out []string
		for _, r := range rows {
			out = append(out, r.Name)
		}
		return strings.Join(out, ",")
	}
	if got := names(list()); got != "a-eu,a-gproxy,a-main,a-oldproxy,a-proxy,a2-main,default" {
		t.Errorf("all = %s", got)
	}
	if got := names(list("--network", "net-a")); got != "a-eu,a-gproxy,a-main,a-oldproxy,a-proxy" {
		t.Errorf("net-a = %s", got)
	}
	if got := names(list("--network", "net-a", "--region", "us-central1")); got != "a-gproxy,a-main,a-oldproxy,a-proxy" {
		t.Errorf("net-a us-central1 = %s", got)
	}
	// The three proxy-only purposes are recognised.
	if got := names(list("--network", "net-a", "--region", "us-central1", "--proxy-only")); got != "a-gproxy,a-oldproxy,a-proxy" {
		t.Errorf("proxy-only = %s", got)
	}
	rows := list("--region", "us-central1", "--network", "net-a")
	for _, r := range rows {
		if r.Name == "a-main" && (len(r.SecondaryRanges) != 1 || r.SecondaryRanges[0].Range != "10.4.0.0/14" || r.Region != "us-central1" || r.Network != "net-a") {
			t.Errorf("a-main = %+v", r)
		}
	}
	// Nothing matches: exit code 0, [] and a note.
	if got := list("--network", "nope"); len(got) != 0 || strings.TrimSpace(h.stdout.String()) != "[]" || !strings.Contains(h.stderr.String(), "no matching") {
		t.Errorf("empty = %q, %s", h.stdout.String(), h.stderr.String())
	}
	ht := newGCPHarness(t, app.Flags{Output: "table"}, nil)
	ht.gce.addVPCs()
	if err := ht.run("compute", "subnet", "list", "--network", "net-a", "--region", "us-central1"); err != nil {
		t.Fatal(err)
	}
	if out := ht.stdout.String(); !strings.Contains(out, "SECONDARY-RANGES") || !strings.Contains(out, "pods=10.4.0.0/14") || !strings.Contains(out, "REGIONAL_MANAGED_PROXY") {
		t.Errorf("table:\n%s", out)
	}
}

func TestGCPProfileWithoutGCPAccountIsUnsupported(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.rt.Flags.Profile = "nope"
	if err := h.run("compute", "network", "list"); exitClass(err) != "notfound" {
		t.Errorf("unknown profile = %v", err)
	}
	cfg, err := config.Load(filepath.Join(h.dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Profiles["dns"] = &config.Profile{Platforms: map[platform.ID]*config.Account{platform.Cloudflare: {Metadata: map[string]string{}}}}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.rt.ReloadConfig(); err != nil {
		t.Fatal(err)
	}
	h.rt.Flags.Profile = "dns"
	if err := h.run("compute", "network", "list"); exitClass(err) != "unsupported" {
		t.Errorf("profile without gcp = %v", err)
	}
}
