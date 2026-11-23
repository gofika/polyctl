package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/platform"
)

func refValues(rs []platform.IPRef) []string {
	var out []string
	for _, r := range rs {
		out = append(out, string(r.Kind)+":"+r.Value)
	}
	return out
}

func TestNetIfacesAllAddresses(t *testing.T) {
	in := &compute.Instance{Id: 7, Name: "multi", Zone: apiBase + "projects/proj/zones/us-central1-a", Status: "RUNNING",
		NetworkInterfaces: []*compute.NetworkInterface{
			{Name: "nic0", Network: apiBase + "projects/proj/global/networks/default", Subnetwork: apiBase + "projects/proj/regions/us-central1/subnetworks/default",
				NetworkIP: "10.128.0.5", AccessConfigs: []*compute.AccessConfig{{NatIP: "203.0.113.10"}, {NatIP: "203.0.113.11"}},
				AliasIpRanges: []*compute.AliasIpRange{{IpCidrRange: "10.2.3.4"}, {IpCidrRange: "10.1.2.0/24"}, {IpCidrRange: "/24"}}},
			{Name: "nic1", Network: apiBase + "projects/proj/global/networks/backend", Subnetwork: apiBase + "projects/proj/regions/us-central1/subnetworks/be",
				NetworkIP: "192.168.0.5", Ipv6Address: "fd20::5", StackType: "IPV4_IPV6",
				Ipv6AccessConfigs: []*compute.AccessConfig{{ExternalIpv6: "2600:1900:4000:1::", ExternalIpv6PrefixLength: 96}}},
		}}
	res := instanceResource(instanceFromAPI(in))
	got := strings.Join(refValues(res.IPs), " ")
	want := "internal:10.128.0.5 internal:10.2.3.4 internal:10.1.2.0/24 external:203.0.113.10 external:203.0.113.11 internal:192.168.0.5 internal:fd20::5 external:2600:1900:4000:1::/96"
	if got != want {
		t.Errorf("ips =\n%s\nwant\n%s", got, want)
	}
	i := res.Data.(Instance)
	if i.Interfaces[0].AliasMasks[0] != "/24" || i.Interfaces[1].SubnetRegion != "us-central1" {
		t.Errorf("interfaces = %+v", i.Interfaces)
	}

	// The second interface holds the address: its network is reported.
	b, _ := json.Marshal(i)
	m := &platform.FindMatch{Type: platform.ResInstance, Name: "multi", Data: b, Matched: "2600:1900:4000:1::/96"}
	if err := (&provider{}).DescribeMatch(nil, m); err != nil {
		t.Fatal(err)
	}
	if m.Network != "backend" || m.Subnet != "be" || m.Zone != "us-central1-a" || m.Region != "us-central1" || len(m.InternalIPs) != 5 || len(m.ExternalIPs) != 3 {
		t.Errorf("match = %+v", m)
	}
	m.Matched = "10.1.2.0/24"
	_ = (&provider{}).DescribeMatch(nil, m)
	if m.Network != "default" {
		t.Errorf("alias match network = %q", m.Network)
	}
}

func TestStaticAddressKinds(t *testing.T) {
	free := staticAddressFrom(&compute.Address{Id: 1, Name: "spare", Address: "203.0.113.20", Status: "RESERVED", Region: apiBase + "projects/proj/regions/us-central1"})
	used := staticAddressFrom(&compute.Address{Id: 2, Name: "web-ip", Address: "203.0.113.10", Status: "IN_USE",
		Users: []string{apiBase + "projects/proj/zones/us-central1-a/instances/web-1"}})
	internal := staticAddressFrom(&compute.Address{Id: 3, Name: "psa", Address: "10.50.0.0", PrefixLength: 16, AddressType: "INTERNAL", Purpose: "VPC_PEERING", Status: "RESERVED"})
	for _, tc := range []struct {
		a    StaticAddress
		want string
	}{
		{free, "external:203.0.113.20"},
		{used, "reserved:203.0.113.10"},
		{internal, "internal:10.50.0.0/16"},
	} {
		if got := strings.Join(refValues(tc.a.resource().IPs), " "); got != tc.want {
			t.Errorf("%s = %q, want %q", tc.a.Name, got, tc.want)
		}
	}
	b, _ := json.Marshal(used)
	m := &platform.FindMatch{Type: platform.ResEIP, Name: "web-ip", Data: b}
	p := &provider{}
	_ = p.DescribeMatch(nil, m)
	if m.Region != "global" || m.ExternalIPs[0] != "203.0.113.10" || !strings.Contains(m.Note, "web-1") {
		t.Errorf("address match = %+v", m)
	}
	if u := p.ConsoleURL(map[string]string{"project": "proj"}, m); u != consoleBase+"/compute/instancesDetail/zones/us-central1-a/instances/web-1?project=proj" {
		t.Errorf("address url = %q", u)
	}
	b, _ = json.Marshal(free)
	if u := p.ConsoleURL(map[string]string{"project": "proj"}, &platform.FindMatch{Type: platform.ResEIP, Data: b}); u != "" {
		t.Errorf("unused address url = %q", u)
	}
}

func TestConsoleURLs(t *testing.T) {
	p := &provider{}
	meta := map[string]string{"project": "proj"}
	regional, _ := json.Marshal(ForwardingRule{Name: "fr-web-1", Region: "asia-east1"})
	global, _ := json.Marshal(ForwardingRule{Name: "fr-global"})
	for _, tc := range []struct {
		m    platform.FindMatch
		want string
	}{
		{platform.FindMatch{Type: platform.ResInstance, Name: "web-1", Zone: "asia-east1-a"}, consoleBase + "/compute/instancesDetail/zones/asia-east1-a/instances/web-1?project=proj"},
		{platform.FindMatch{Type: platform.ResLoadBalancer, Data: regional}, consoleBase + "/net-services/loadbalancing/advanced/forwardingRules/details/regions/asia-east1/forwardingRules/fr-web-1?project=proj"},
		{platform.FindMatch{Type: platform.ResLoadBalancer, Data: global}, consoleBase + "/net-services/loadbalancing/advanced/globalForwardingRules/details/fr-global?project=proj"},
	} {
		if got := p.ConsoleURL(meta, &tc.m); got != tc.want {
			t.Errorf("%s = %q, want %q", tc.m.Type, got, tc.want)
		}
	}
	if got := p.ConsoleURL(nil, &platform.FindMatch{Type: platform.ResInstance, Name: "a", Zone: "z"}); got != "" {
		t.Errorf("no project = %q", got)
	}
}

func TestFindSyncAndSearch(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.gce.addInstance("proj", "us-central1-a", "web-1", "10.128.0.5", "203.0.113.10")
	h.gce.addInstance("proj", "us-central1-b", "web-2", "10.128.0.6", "")
	h.gce.addAddress("us-central1", &compute.Address{Name: "web-ip", Address: "203.0.113.10", AddressType: "EXTERNAL"})
	h.gce.addAddress("us-central1", &compute.Address{Name: "spare", Address: "203.0.113.20", AddressType: "EXTERNAL"})
	h.gce.forwardingRules = map[string][]*compute.ForwardingRule{"proj": {
		{Id: 11, Name: "fr-web", Region: apiBase + "projects/proj/regions/us-central1", IPAddress: "203.0.113.30", LoadBalancingScheme: "EXTERNAL",
			SelfLink: apiBase + "projects/proj/regions/us-central1/forwardingRules/fr-web"},
		{Id: 12, Name: "fr-global", IPAddress: "198.51.100.7", LoadBalancingScheme: "EXTERNAL_MANAGED", Target: apiBase + "projects/proj/global/targetHttpsProxies/p",
			SelfLink: apiBase + "projects/proj/global/forwardingRules/fr-global"},
		{Id: 12, Name: "fr-global", IPAddress: "198.51.100.7", LoadBalancingScheme: "EXTERNAL_MANAGED",
			SelfLink: apiBase + "projects/proj/global/forwardingRules/fr-global"},
		{Id: 13, Name: "fr-ilb", Region: apiBase + "projects/proj/regions/us-central1", IPAddress: "10.128.0.50", LoadBalancingScheme: "INTERNAL",
			SelfLink: apiBase + "projects/proj/regions/us-central1/forwardingRules/fr-ilb"},
	}}
	h.gce.subnets["proj/us-central1"][0].GatewayAddress = "10.128.0.1"
	ctx := context.Background()
	reports, err := h.rt.SyncAccount(ctx, config.AccountRef{Profile: "lab", Platform: platform.GCP}, app.FindTypes)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[platform.ResourceType]int{}
	for _, r := range reports {
		if r.Err != nil {
			t.Fatalf("sync %s: %v", r.Type, r.Err)
		}
		counts[r.Type] = r.Count
	}
	if counts[platform.ResInstance] != 2 || counts[platform.ResLoadBalancer] != 3 || counts[platform.ResEIP] != 2 {
		t.Errorf("counts = %v", counts)
	}

	find := func(s string, detail bool) *app.FindResult {
		t.Helper()
		q, err := platform.ParseFindQuery(s)
		if err != nil {
			t.Fatal(err)
		}
		res, err := h.rt.Find(ctx, app.FindRequest{Query: q, Detail: detail})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	// The static address of the instance annotates it.
	res := find("203.0.113.10", false)
	if len(res.Matches) != 1 || res.Matches[0].Name != "web-1" || len(res.Matches[0].Addresses) != 1 || res.Matches[0].Addresses[0] != "web-ip" ||
		res.Matches[0].MatchedField != "external_ip" || res.Matches[0].Network != "default" {
		t.Fatalf("instance = %+v", res.Matches)
	}
	if res := find("203.0.113.20", false); len(res.Matches) != 1 || res.Matches[0].Type != platform.ResEIP || res.Matches[0].State != "RESERVED" {
		t.Errorf("spare = %+v", res.Matches)
	}
	if res := find("198.51.100.7", false); len(res.Matches) != 1 || res.Matches[0].Region != "global" || !strings.Contains(res.Matches[0].URL, "globalForwardingRules") {
		t.Errorf("global rule = %+v", res.Matches)
	}
	if res := find("10.128.0.50", false); len(res.Matches) != 1 || res.Matches[0].MatchedField != "internal_ip" {
		t.Errorf("internal rule = %+v", res.Matches)
	}

	// --detail reads the subnetwork of the interface.
	res = find("10.128.0.6", true)
	if len(res.Matches) != 1 || res.Matches[0].Detail == nil || len(res.Errors) != 0 {
		t.Fatalf("detail = %+v %+v", res.Matches, res.Errors)
	}
	if d := res.Matches[0].Detail; d.SubnetCIDR != "10.128.0.0/20" || d.SubnetGateway != "10.128.0.1" || d.Subnet != "default" || d.SubnetRegion != "us-central1" || d.VPC != "default" {
		t.Errorf("detail = %+v", d)
	}
	// A failing lookup keeps the match.
	h.gce.fail["GET /projects/proj/regions/us-central1/subnetworks/default"] = fakeErr{code: 403, reason: "forbidden", message: "denied"}
	res = find("10.128.0.6", true)
	if len(res.Matches) != 1 || res.Matches[0].Detail != nil || len(res.Errors) != 1 || !errors.Is(res.Errors[0].Err, platform.ErrUnauthorized) {
		t.Errorf("failed detail = %+v %+v", res.Matches, res.Errors)
	}
}
