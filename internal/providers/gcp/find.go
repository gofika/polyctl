package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/platform"
)

var (
	_ platform.IPSource       = (*provider)(nil)
	_ platform.MatchDescriber = (*provider)(nil)
	_ platform.ConsoleLinker  = (*provider)(nil)
	_ platform.DetailProvider = (*client)(nil)
)

// NetIface is one network interface of an instance with all its addresses.
type NetIface struct {
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Network and Subnetwork are short names; SubnetRegion is the region
	// of the subnetwork, from its URL.
	Network      string `json:"network,omitempty" yaml:"network,omitempty"`
	Subnetwork   string `json:"subnetwork,omitempty" yaml:"subnetwork,omitempty"`
	SubnetRegion string `json:"subnet_region,omitempty" yaml:"subnet_region,omitempty"`
	// InternalIPs are the primary internal address and the internal IPv6
	// address.
	InternalIPs []string `json:"internal_ips,omitempty" yaml:"internal_ips,omitempty"`
	// AliasRanges are the alias IP ranges as CIDR. A range given only as a
	// mask ("/24") has no address to match and is kept in AliasMasks.
	AliasRanges []string `json:"alias_ranges,omitempty" yaml:"alias_ranges,omitempty"`
	AliasMasks  []string `json:"alias_masks,omitempty" yaml:"alias_masks,omitempty"`
	// ExternalIPs are the NAT addresses of the access configs and the
	// external IPv6 prefixes ("2600:1900:...:0/96").
	ExternalIPs []string `json:"external_ips,omitempty" yaml:"external_ips,omitempty"`
	StackType   string   `json:"stack_type,omitempty" yaml:"stack_type,omitempty"`
}

// netIfaceFrom flattens an interface of the API.
func netIfaceFrom(ni *compute.NetworkInterface) NetIface {
	out := NetIface{Name: ni.Name, Network: lastSegment(ni.Network), Subnetwork: lastSegment(ni.Subnetwork),
		SubnetRegion: subnetRegion(ni.Subnetwork), StackType: ni.StackType}
	for _, ip := range []string{ni.NetworkIP, ni.Ipv6Address} {
		if ip != "" {
			out.InternalIPs = append(out.InternalIPs, ip)
		}
	}
	for _, r := range ni.AliasIpRanges {
		switch v := strings.TrimSpace(r.IpCidrRange); {
		case v == "":
		case strings.HasPrefix(v, "/"):
			out.AliasMasks = append(out.AliasMasks, v)
		default:
			out.AliasRanges = append(out.AliasRanges, v)
		}
	}
	for _, ac := range ni.AccessConfigs {
		if ac.NatIP != "" {
			out.ExternalIPs = append(out.ExternalIPs, ac.NatIP)
		}
		if ac.ExternalIpv6 != "" {
			out.ExternalIPs = append(out.ExternalIPs, ipv6Prefix(ac.ExternalIpv6, ac.ExternalIpv6PrefixLength))
		}
	}
	for _, ac := range ni.Ipv6AccessConfigs {
		if ac.ExternalIpv6 != "" {
			out.ExternalIPs = append(out.ExternalIPs, ipv6Prefix(ac.ExternalIpv6, ac.ExternalIpv6PrefixLength))
		}
	}
	return out
}

// ipv6Prefix renders an external IPv6 address with its prefix length (the
// address of an IPv6 access config stands for a prefix), or the address
// when the length is unknown.
func ipv6Prefix(addr string, bits int64) string {
	if bits <= 0 || strings.Contains(addr, "/") {
		return addr
	}
	return addr + "/" + strconv.FormatInt(bits, 10)
}

// subnetRegion returns the region of a subnetwork URL: the third segment
// from the end (".../regions/<region>/subnetworks/<name>").
func subnetRegion(u string) string {
	parts := strings.Split(strings.TrimSuffix(u, "/"), "/")
	if len(parts) >= 3 && parts[len(parts)-2] == "subnetworks" {
		return parts[len(parts)-3]
	}
	return ""
}

// set fills an IPSet with the addresses of an interface.
func (n NetIface) set(s *platform.IPSet) {
	s.Add(platform.IPInternal, n.InternalIPs...)
	s.Add(platform.IPInternal, n.AliasRanges...)
	s.Add(platform.IPExternal, n.ExternalIPs...)
}

// ipSet returns every address of an instance; instances stored by an
// older version without interfaces have their two flat addresses.
func (i Instance) ipSet() *platform.IPSet {
	s := &platform.IPSet{}
	for _, n := range i.Interfaces {
		n.set(s)
	}
	if len(i.Interfaces) == 0 {
		s.Add(platform.IPInternal, i.InternalIP)
		s.Add(platform.IPExternal, i.ExternalIP)
	}
	return s
}

// unreachableErr turns the scopes an aggregated list of the client's
// project could not reach into region failures of a sync (nil when there
// are none): the stored rows of "<project>/<zone or region>" are kept. An
// unreachable global scope fails the whole list of the project instead:
// no row of the project is replaced.
func (c *client) unreachableErr(scopes []string) error {
	if len(scopes) == 0 {
		return nil
	}
	sort.Strings(scopes)
	for _, s := range scopes {
		if scopeKey(s) == "global" {
			return fmt.Errorf("the global scope could not be reached (unreachable scopes: %s)", strings.Join(scopes, ", "))
		}
	}
	e := &platform.RegionSyncError{}
	for _, s := range scopes {
		e.Failures = append(e.Failures, platform.RegionError{Region: parentOf(c.project, lastSegment(s)), Err: fmt.Errorf("unreachable")})
	}
	return e
}

// lbLabel is the label of the forwarding rules load-balancer ensure
// creates, carrying the load balancer name.
const lbLabel = "polyctl-lb"

// ForwardingRule is the inventory form of a forwarding rule: the address
// of a load balancer. Region is empty for a global rule.
type ForwardingRule struct {
	ID   string `json:"id" yaml:"id"`
	Name string `json:"name" yaml:"name"`
	// Project is the project of the rule (empty in rows stored before an
	// account could hold several: the default project).
	Project             string `json:"project,omitempty" yaml:"project,omitempty"`
	Region              string `json:"region,omitempty" yaml:"region,omitempty"`
	IPAddress           string `json:"ip_address" yaml:"ip_address"`
	IPProtocol          string `json:"ip_protocol,omitempty" yaml:"ip_protocol,omitempty"`
	PortRange           string `json:"port_range,omitempty" yaml:"port_range,omitempty"`
	LoadBalancingScheme string `json:"load_balancing_scheme,omitempty" yaml:"load_balancing_scheme,omitempty"`
	NetworkTier         string `json:"network_tier,omitempty" yaml:"network_tier,omitempty"`
	Target              string `json:"target,omitempty" yaml:"target,omitempty"`
	BackendService      string `json:"backend_service,omitempty" yaml:"backend_service,omitempty"`
	Network             string `json:"network,omitempty" yaml:"network,omitempty"`
	Subnetwork          string `json:"subnetwork,omitempty" yaml:"subnetwork,omitempty"`
	SelfLink            string `json:"self_link,omitempty" yaml:"self_link,omitempty"`
	// LoadBalancer is the name of the load balancer the rule belongs to:
	// its polyctl-lb label, else the URL map of its target proxy, else the
	// rule's own name (set by the sync; empty in rows of older versions).
	LoadBalancer string            `json:"load_balancer,omitempty" yaml:"load_balancer,omitempty"`
	Labels       map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
}

// fallbackID is the inventory id of a resource: its numeric id, else its
// self link, else "<project>/<region or global>/<name>".
func fallbackID(project, id, selfLink, region, name string) string {
	switch {
	case id != "" && id != "0":
		return id
	case selfLink != "":
		return selfLink
	case region == "":
		region = "global"
	}
	return project + "/" + region + "/" + name
}

// internalScheme reports a load balancing scheme of internal addresses.
func internalScheme(s string) bool { return strings.HasPrefix(strings.ToUpper(s), "INTERNAL") }

func forwardingRuleFrom(fr *compute.ForwardingRule) ForwardingRule {
	return ForwardingRule{ID: strconv.FormatUint(fr.Id, 10), Name: fr.Name, Region: lastSegment(fr.Region), IPAddress: fr.IPAddress,
		IPProtocol: fr.IPProtocol, PortRange: fr.PortRange, LoadBalancingScheme: fr.LoadBalancingScheme, NetworkTier: fr.NetworkTier,
		Target: lastSegment(fr.Target), BackendService: lastSegment(fr.BackendService), Network: lastSegment(fr.Network),
		Subnetwork: lastSegment(fr.Subnetwork), SelfLink: fr.SelfLink, Labels: fr.Labels, LoadBalancer: fr.Labels[lbLabel]}
}

// ruleOf flattens a forwarding rule of the client's project.
func (c *client) ruleOf(fr *compute.ForwardingRule) ForwardingRule {
	v := forwardingRuleFrom(fr)
	v.Project = c.project
	return v
}

// inventoryID is the id of the rule's inventory row.
func (f ForwardingRule) inventoryID() string {
	return fallbackID(f.Project, f.ID, f.SelfLink, f.Region, f.Name)
}

func (f ForwardingRule) kind() platform.IPKind {
	if internalScheme(f.LoadBalancingScheme) {
		return platform.IPInternal
	}
	return platform.IPExternal
}

func (f ForwardingRule) resource() platform.Resource {
	var s platform.IPSet
	s.Add(f.kind(), f.IPAddress)
	return platform.Resource{Type: platform.ResLoadBalancer, ID: f.inventoryID(), Name: f.Name, ParentID: parentOf(f.Project, f.Region), Data: f, IPs: s.Refs()}
}

// proxyURLMaps maps the target HTTP and HTTPS proxies of every scope
// (resourceKey of their self link) to the name of their URL map. It is
// best effort: a list that fails leaves its proxies out.
func (c *client) proxyURLMaps(ctx context.Context) map[string]string {
	out := map[string]string{}
	_, _ = aggregatedPages(ctx, c.compute.TargetHttpProxies.AggregatedList(c.project), func(l *compute.TargetHttpProxyAggregatedList) (string, []string) {
		for _, scoped := range l.Items {
			for _, p := range scoped.TargetHttpProxies {
				out[resourceKey(p.SelfLink)] = lastSegment(p.UrlMap)
			}
		}
		return l.NextPageToken, nil
	})
	_, _ = aggregatedPages(ctx, c.compute.TargetHttpsProxies.AggregatedList(c.project), func(l *compute.TargetHttpsProxyAggregatedList) (string, []string) {
		for _, scoped := range l.Items {
			for _, p := range scoped.TargetHttpsProxies {
				out[resourceKey(p.SelfLink)] = lastSegment(p.UrlMap)
			}
		}
		return l.NextPageToken, nil
	})
	return out
}

// lbNameOf is the load balancer a forwarding rule belongs to: its
// polyctl-lb label, else the URL map of its target proxy (load balancers
// built before polyctl, whatever their naming), else its own name.
func lbNameOf(fr *compute.ForwardingRule, urlMaps map[string]string) string {
	if v := fr.Labels[lbLabel]; v != "" {
		return v
	}
	if m := urlMaps[resourceKey(fr.Target)]; m != "" && fr.Target != "" {
		return m
	}
	return fr.Name
}

// syncForwardingRules lists every forwarding rule of the project. The
// aggregated list already holds the global rules, so it is the only call
// for the rules; rules are still deduplicated by self link. Each row
// carries the name of its load balancer (lbNameOf).
func (c *client) syncForwardingRules(ctx context.Context) ([]platform.Resource, error) {
	var out []platform.Resource
	seen := map[string]bool{}
	var urlMaps map[string]string
	unreachable, err := aggregatedPages(ctx, c.compute.ForwardingRules.AggregatedList(c.project), func(resp *compute.ForwardingRuleAggregatedList) (string, []string) {
		u := resp.Unreachables
		for scope, scoped := range resp.Items {
			if scoped.Warning != nil {
				u = append(u, warnedUnreachable(scope, scoped.Warning.Code)...)
			}
			for _, fr := range scoped.ForwardingRules {
				key := fr.SelfLink
				if key == "" {
					key = fr.Region + "/" + fr.Name
				}
				if seen[key] {
					continue
				}
				seen[key] = true
				v := c.ruleOf(fr)
				if v.LoadBalancer == "" {
					if urlMaps == nil && fr.Target != "" {
						urlMaps = c.proxyURLMaps(ctx)
					}
					v.LoadBalancer = lbNameOf(fr, urlMaps)
				}
				out = append(out, v.resource())
			}
		}
		return resp.NextPageToken, u
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return out, c.unreachableErr(unreachable)
}

// StaticAddress is the inventory form of a reserved address. Region is
// empty for a global address; Users are the URLs of the resources using it.
type StaticAddress struct {
	ID   string `json:"id" yaml:"id"`
	Name string `json:"name" yaml:"name"`
	// Project is the project of the address (empty in rows stored before
	// an account could hold several: the default project).
	Project      string   `json:"project,omitempty" yaml:"project,omitempty"`
	Region       string   `json:"region,omitempty" yaml:"region,omitempty"`
	Address      string   `json:"address" yaml:"address"`
	PrefixLength int64    `json:"prefix_length,omitempty" yaml:"prefix_length,omitempty"`
	AddressType  string   `json:"address_type,omitempty" yaml:"address_type,omitempty"`
	Purpose      string   `json:"purpose,omitempty" yaml:"purpose,omitempty"`
	Status       string   `json:"status,omitempty" yaml:"status,omitempty"`
	NetworkTier  string   `json:"network_tier,omitempty" yaml:"network_tier,omitempty"`
	Network      string   `json:"network,omitempty" yaml:"network,omitempty"`
	Subnetwork   string   `json:"subnetwork,omitempty" yaml:"subnetwork,omitempty"`
	Users        []string `json:"users,omitempty" yaml:"users,omitempty"`
	SelfLink     string   `json:"self_link,omitempty" yaml:"self_link,omitempty"`
}

func staticAddressFrom(a *compute.Address) StaticAddress {
	return StaticAddress{ID: strconv.FormatUint(a.Id, 10), Name: a.Name, Region: lastSegment(a.Region), Address: a.Address,
		PrefixLength: a.PrefixLength, AddressType: a.AddressType, Purpose: a.Purpose, Status: a.Status, NetworkTier: a.NetworkTier,
		Network: lastSegment(a.Network), Subnetwork: lastSegment(a.Subnetwork), Users: a.Users, SelfLink: a.SelfLink}
}

// independent reports whether the address is a match of its own: reserved
// and used by nothing. An address in use is also found through the
// resource that uses it (an instance's NAT address, a forwarding rule), and
// only annotates that match.
func (a StaticAddress) independent() bool { return a.Status == "RESERVED" || len(a.Users) == 0 }

func (a StaticAddress) kind() platform.IPKind {
	if strings.EqualFold(a.AddressType, "INTERNAL") {
		return platform.IPInternal
	}
	return platform.IPExternal
}

func (a StaticAddress) resource() platform.Resource {
	value := a.Address
	if a.PrefixLength > 0 && !strings.Contains(value, "/") {
		value += "/" + strconv.FormatInt(a.PrefixLength, 10)
	}
	var refs []platform.IPRef
	if r, ok := platform.IPAddr(a.kind(), value); ok {
		if !a.independent() {
			r.Kind = platform.IPReserved
		}
		refs = append(refs, r)
	}
	id := fallbackID(a.Project, a.ID, a.SelfLink, a.Region, a.Name)
	return platform.Resource{Type: platform.ResEIP, ID: id, Name: a.Name, ParentID: parentOf(a.Project, a.Region), Data: a, IPs: refs}
}

// syncAddresses lists every reserved address of the project; the
// aggregated list holds the global ones too.
func (c *client) syncAddresses(ctx context.Context) ([]platform.Resource, error) {
	var out []platform.Resource
	seen := map[string]bool{}
	unreachable, err := aggregatedPages(ctx, c.compute.Addresses.AggregatedList(c.project), func(resp *compute.AddressAggregatedList) (string, []string) {
		u := resp.Unreachables
		for scope, scoped := range resp.Items {
			if scoped.Warning != nil {
				u = append(u, warnedUnreachable(scope, scoped.Warning.Code)...)
			}
			for _, a := range scoped.Addresses {
				key := a.SelfLink
				if key == "" {
					key = a.Region + "/" + a.Name
				}
				if seen[key] {
					continue
				}
				seen[key] = true
				v := staticAddressFrom(a)
				v.Project = c.project
				out = append(out, v.resource())
			}
		}
		return resp.NextPageToken, u
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return out, c.unreachableErr(unreachable)
}

// FindTypes are the inventory types whose rows carry addresses.
func (*provider) FindTypes() []platform.ResourceType {
	return []platform.ResourceType{platform.ResInstance, platform.ResLoadBalancer, platform.ResEIP}
}

// matchedIface returns the interface of an instance holding the matched
// address, else the first one.
func matchedIface(i Instance, m *platform.FindMatch) *NetIface {
	for k := range i.Interfaces {
		n := &i.Interfaces[k]
		for _, group := range [][]string{n.InternalIPs, n.AliasRanges, n.ExternalIPs} {
			for _, v := range group {
				if m.Holds(v) {
					return n
				}
			}
		}
	}
	if len(i.Interfaces) > 0 {
		return &i.Interfaces[0]
	}
	return nil
}

// DescribeMatch fills a find match from the stored data. Its project is
// the one the row carries, or the default project of the account for a
// row stored before rows carried it.
func (*provider) DescribeMatch(meta map[string]string, m *platform.FindMatch) error {
	project := func(p string) string {
		if p == "" {
			return meta[metaProject]
		}
		return p
	}
	switch m.Type {
	case platform.ResInstance:
		var i Instance
		if err := json.Unmarshal(m.Data, &i); err != nil {
			return err
		}
		m.Project = project(i.Project)
		s := i.ipSet()
		m.Zone, m.Region, m.State = i.Zone, regionOf(i.Zone), i.Status
		m.InternalIPs, m.ExternalIPs = s.Values(platform.IPInternal), s.Values(platform.IPExternal)
		if n := matchedIface(i, m); n != nil {
			m.Network, m.Subnet = n.Network, n.Subnetwork
		}
	case platform.ResLoadBalancer:
		var f ForwardingRule
		if err := json.Unmarshal(m.Data, &f); err != nil {
			return err
		}
		m.Project = project(f.Project)
		m.Region = f.Region
		if m.Region == "" {
			m.Region = "global"
		}
		if f.kind() == platform.IPInternal {
			m.InternalIPs = []string{f.IPAddress}
		} else {
			m.ExternalIPs = []string{f.IPAddress}
		}
		m.Network, m.Subnet = f.Network, f.Subnetwork
		var parts []string
		for _, p := range []string{f.LoadBalancingScheme, f.IPProtocol, f.PortRange} {
			if p != "" {
				parts = append(parts, p)
			}
		}
		if t := f.Target; t != "" {
			parts = append(parts, "target "+t)
		} else if b := f.BackendService; b != "" {
			parts = append(parts, "backend service "+b)
		}
		m.Note = "forwarding rule " + strings.Join(parts, " ")
	case platform.ResEIP:
		var a StaticAddress
		if err := json.Unmarshal(m.Data, &a); err != nil {
			return err
		}
		m.Project = project(a.Project)
		m.Region, m.State = a.Region, a.Status
		if m.Region == "" {
			m.Region = "global"
		}
		if a.kind() == platform.IPInternal {
			m.InternalIPs = []string{a.Address}
		} else {
			m.ExternalIPs = []string{a.Address}
		}
		m.Network, m.Subnet = a.Network, a.Subnetwork
		if len(a.Users) > 0 {
			names := make([]string, 0, len(a.Users))
			for _, u := range a.Users {
				names = append(names, lastSegment(u))
			}
			m.Holders = names
			m.Note = "static address used by " + strings.Join(names, ", ")
		} else {
			m.Note = "static address, not in use"
		}
	default:
		return fmt.Errorf("%s: %w", m.Type, platform.ErrNotSupported)
	}
	return nil
}

const consoleBase = "https://console.cloud.google.com"

// ConsoleURL returns the Cloud Console page of a match. A static address
// links to the resource using it; one used by nothing has no page.
func (*provider) ConsoleURL(meta map[string]string, m *platform.FindMatch) string {
	// The project of the match, set by DescribeMatch from its row; the
	// default project of the account otherwise.
	project := m.Project
	if project == "" {
		project = meta[metaProject]
	}
	if project == "" {
		return ""
	}
	switch m.Type {
	case platform.ResInstance:
		if m.Zone == "" || m.Name == "" {
			return ""
		}
		return instanceURL(project, m.Zone, m.Name)
	case platform.ResLoadBalancer:
		var f ForwardingRule
		if json.Unmarshal(m.Data, &f) != nil {
			return ""
		}
		return forwardingRuleURL(project, f.Region, f.Name)
	case platform.ResEIP:
		var a StaticAddress
		if json.Unmarshal(m.Data, &a) != nil {
			return ""
		}
		for _, u := range a.Users {
			if link := userURL(project, u); link != "" {
				return link
			}
		}
	}
	return ""
}

func instanceURL(project, zone, name string) string {
	return fmt.Sprintf("%s/compute/instancesDetail/zones/%s/instances/%s?project=%s", consoleBase, url.PathEscape(zone), url.PathEscape(name), url.QueryEscape(project))
}

func forwardingRuleURL(project, region, name string) string {
	if region == "" {
		return fmt.Sprintf("%s/net-services/loadbalancing/advanced/globalForwardingRules/details/%s?project=%s", consoleBase, url.PathEscape(name), url.QueryEscape(project))
	}
	return fmt.Sprintf("%s/net-services/loadbalancing/advanced/forwardingRules/details/regions/%s/forwardingRules/%s?project=%s",
		consoleBase, url.PathEscape(region), url.PathEscape(name), url.QueryEscape(project))
}

// userURL links the user of a static address: an instance or a forwarding
// rule, from its resource URL.
func userURL(project, u string) string {
	parts := strings.Split(strings.TrimSuffix(u, "/"), "/")
	n := len(parts)
	if n < 4 {
		return ""
	}
	switch parts[n-2] {
	case "instances":
		if parts[n-4] == "zones" {
			return instanceURL(project, parts[n-3], parts[n-1])
		}
	case "forwardingRules":
		if parts[n-4] == "regions" {
			return forwardingRuleURL(project, parts[n-3], parts[n-1])
		}
		if parts[n-3] == "global" {
			return forwardingRuleURL(project, "", parts[n-1])
		}
	}
	return ""
}

// NetworkDetail reads the subnetwork of the interface of a matched instance
// that holds the address: its primary range, IPv6 range and gateway. The
// region and name come from the stored subnetwork URL; the instance is not
// read again.
func (c *client) NetworkDetail(ctx context.Context, m *platform.FindMatch) (*platform.NetworkDetail, error) {
	if m.Type != platform.ResInstance {
		return nil, platform.ErrNotSupported
	}
	var i Instance
	if err := json.Unmarshal(m.Data, &i); err != nil {
		return nil, err
	}
	n := matchedIface(i, m)
	if n == nil || n.Subnetwork == "" || n.SubnetRegion == "" {
		return nil, fmt.Errorf("%w: the instance has no subnetwork in the inventory (run polyctl find --refresh)", platform.ErrNotSupported)
	}
	// The subnetwork is read in the project of the instance.
	c = c.inProject(c.projectOr(i.Project))
	sn, err := c.compute.Subnetworks.Get(c.project, n.SubnetRegion, n.Subnetwork).Context(ctx).Do()
	if err != nil {
		return nil, computeErr(err)
	}
	d := &platform.NetworkDetail{VPC: lastSegment(sn.Network), Subnet: sn.Name, SubnetRegion: n.SubnetRegion,
		SubnetCIDR: sn.IpCidrRange, SubnetGateway: sn.GatewayAddress}
	for _, v := range []string{sn.Ipv6CidrRange, sn.ExternalIpv6Prefix, sn.InternalIpv6Prefix} {
		if v != "" {
			d.SubnetIPv6CIDR = append(d.SubnetIPv6CIDR, v)
		}
	}
	if d.VPC == "" {
		d.VPC = n.Network
	}
	return d, nil
}
