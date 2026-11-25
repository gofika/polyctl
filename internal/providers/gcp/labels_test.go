package gcp

import (
	"testing"

	compute "google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/platform"
)

// The labels of the selection lists are rows of cells: a fact keeps its
// position in every row, "-" stands for a fact a row does not have when a
// later cell follows, and trailing empty cells are dropped.
func TestOptionLabelsKeepTheirCells(t *testing.T) {
	for name, c := range map[string]struct{ got, want string }{
		"instance without an external address": {
			instanceOptionLabel(Instance{Name: "web-1", ID: "1234", Status: "RUNNING", MachineType: "e2-medium", Zone: "us-central1-a", InternalIP: "10.128.0.5", Project: "p1"}, "lab"),
			"web-1  1234  RUNNING  e2-medium  us-central1-a  10.128.0.5  -  project p1  gcp/lab"},
		"instance with both addresses": {
			instanceOptionLabel(Instance{Name: "web-1", ID: "1234", Status: "RUNNING", MachineType: "e2-medium", Zone: "us-central1-a", InternalIP: "10.128.0.5", ExternalIP: "203.0.113.10", Project: "p1"}, "lab"),
			"web-1  1234  RUNNING  e2-medium  us-central1-a  10.128.0.5  203.0.113.10  project p1  gcp/lab"},
		"machine type with a shared core": {
			machineTypeLabel(&compute.MachineType{Name: "e2-micro", GuestCpus: 2, MemoryMb: 1024, IsSharedCpu: true}),
			"e2-micro  2 vCPU  1 GB  shared core"},
		"machine type with cores of its own": {
			machineTypeLabel(&compute.MachineType{Name: "e2-standard-2", GuestCpus: 2, MemoryMb: 8192}),
			"e2-standard-2  2 vCPU  8 GB"},
		"managed zone without a visibility": {
			zoneLabel(platform.Zone{ID: "p1/example-zone", Name: "example.com", Nameservers: []string{"a", "b"}}),
			"example-zone  example.com  -  2 nameservers  project p1"},
		"record set of several values without a TTL": {
			recordSetLabel(recordSet{Name: "www.example.com", Type: "A", Records: []platform.Record{{Value: "192.0.2.1"}, {Value: "192.0.2.2"}}}),
			"www.example.com  A  192.0.2.1  -  +1 more"},
		"record set of one value": {
			recordSetLabel(recordSet{Name: "www.example.com", Type: "A", Records: []platform.Record{{Value: "192.0.2.1", TTL: 300}}}),
			"www.example.com  A  192.0.2.1  ttl 300"},
		"project without a display name": {projectLabel("p1", ""), "p1"},
		"project named like its id":      {projectLabel("p2", "p2"), "p2"},
		"project with a display name":    {projectLabel("p3", "Project three"), "p3  Project three"},
		"common protocol of a rule":      {commonAllows[0].Label, "tcp:22  SSH"},
		"firewall rule without ranges that is disabled": {
			firewallOptionLabel(&compute.Firewall{Name: "allow-ssh", Network: "global/networks/default", Direction: "INGRESS", Priority: 1000,
				Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"22"}}}, Disabled: true}, ""),
			"allow-ssh  default  INGRESS  prio 1000  tcp:22  -  every instance  disabled"},
		"firewall rule in a list of several projects": {
			firewallOptionLabel(&compute.Firewall{Name: "allow-ssh", Network: "global/networks/default", Direction: "INGRESS", Priority: 1000,
				Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"22"}}}, SourceRanges: []string{"10.0.0.0/8"}, TargetTags: []string{"ssh"}, Disabled: true}, "p1"),
			"allow-ssh  default  INGRESS  prio 1000  tcp:22  10.0.0.0/8  tags ssh  project p1  disabled"},
		"certificate without domains or an expiry that is in use": {
			certOptionLabel(&compute.SslCertificate{Name: "web-cert", Type: "MANAGED"}, []string{"web-https-proxy"}),
			"web-cert  global  MANAGED  -  -  used by web-https-proxy"},
	} {
		if c.got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", name, c.got, c.want)
		}
	}
}
