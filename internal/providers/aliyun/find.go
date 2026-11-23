package aliyun

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/alb"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"

	"github.com/gofika/polyctl/internal/platform"
)

var (
	_ platform.IPSource       = (*provider)(nil)
	_ platform.MatchDescriber = (*provider)(nil)
	_ platform.ConsoleLinker  = (*provider)(nil)
	_ platform.DetailProvider = (*client)(nil)
)

// regionConcurrency bounds the regions synced at the same time.
const regionConcurrency = 8

// albPageSize is the largest page ListLoadBalancers accepts (more is
// IllegalParam.MaxResults).
const albPageSize = 100

// albEndpoint is the ALB API endpoint of a region; ListLoadBalancers takes
// no RegionId, so the endpoint decides the region.
func albEndpoint(region string) string { return "alb." + region + ".aliyuncs.com" }

// netIface is one network interface with all its addresses.
type netIface struct {
	ID        string   `json:"id,omitempty" yaml:"id,omitempty"`
	Type      string   `json:"type,omitempty" yaml:"type,omitempty"`
	VSwitchID string   `json:"vswitch_id,omitempty" yaml:"vswitch_id,omitempty"`
	Private   []string `json:"private_ips,omitempty" yaml:"private_ips,omitempty"`
	Public    []string `json:"public_ips,omitempty" yaml:"public_ips,omitempty"`
	IPv6      []string `json:"ipv6,omitempty" yaml:"ipv6,omitempty"`
	Prefixes  []string `json:"prefixes,omitempty" yaml:"prefixes,omitempty"`
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func appendNew(list []string, values ...string) []string {
	for _, v := range values {
		if v != "" && !containsString(list, v) {
			list = append(list, v)
		}
	}
	return list
}

// netIfaceFromInstance flattens an interface of DescribeInstances, which
// lists only the primary address of each interface.
func netIfaceFromInstance(n ecs.NetworkInterface, vswitch string) netIface {
	out := netIface{ID: n.NetworkInterfaceId, Type: n.Type, VSwitchID: n.VSwitchId}
	if out.VSwitchID == "" && n.Type == "Primary" {
		out.VSwitchID = vswitch
	}
	out.Private = appendNew(out.Private, n.PrimaryIpAddress)
	for _, p := range n.PrivateIpSets.PrivateIpSet {
		out.Private = appendNew(out.Private, p.PrivateIpAddress)
		out.Public = appendNew(out.Public, p.AssociatedPublicIp.PublicIpAddress)
	}
	for _, v := range n.Ipv6Sets.Ipv6Set {
		out.IPv6 = appendNew(out.IPv6, v.Ipv6Address)
	}
	for _, p := range n.Ipv4PrefixSets.Ipv4PrefixSet {
		out.Prefixes = appendNew(out.Prefixes, p.Ipv4Prefix)
	}
	for _, p := range n.Ipv6PrefixSets.Ipv6PrefixSet {
		out.Prefixes = appendNew(out.Prefixes, p.Ipv6Prefix)
	}
	return out
}

// netIfaceFromENI flattens an interface of DescribeNetworkInterfaces, which
// lists every private address (the primary one not necessarily first).
func netIfaceFromENI(n ecs.NetworkInterfaceSet) netIface {
	out := netIface{ID: n.NetworkInterfaceId, Type: n.Type, VSwitchID: n.VSwitchId}
	out.Private = appendNew(out.Private, n.PrivateIpAddress)
	out.Public = appendNew(out.Public, n.AssociatedPublicIp.PublicIpAddress)
	for _, p := range n.PrivateIpSets.PrivateIpSet {
		out.Private = appendNew(out.Private, p.PrivateIpAddress)
		out.Public = appendNew(out.Public, p.AssociatedPublicIp.PublicIpAddress)
	}
	for _, v := range n.Ipv6Sets.Ipv6Set {
		out.IPv6 = appendNew(out.IPv6, v.Ipv6Address)
	}
	for _, p := range n.Ipv4PrefixSets.Ipv4PrefixSet {
		out.Prefixes = appendNew(out.Prefixes, p.Ipv4Prefix)
	}
	for _, p := range n.Ipv6PrefixSets.Ipv6PrefixSet {
		out.Prefixes = appendNew(out.Prefixes, p.Ipv6Prefix)
	}
	return out
}

// merge adds the addresses of other (the same interface, read by
// DescribeNetworkInterfaces) to n.
func (n *netIface) merge(other netIface) {
	n.Private = appendNew(n.Private, other.Private...)
	n.Public = appendNew(n.Public, other.Public...)
	n.IPv6 = appendNew(n.IPv6, other.IPv6...)
	n.Prefixes = appendNew(n.Prefixes, other.Prefixes...)
	if n.VSwitchID == "" {
		n.VSwitchID = other.VSwitchID
	}
	if n.Type == "" {
		n.Type = other.Type
	}
}

// ipSet returns every address of an instance.
func (in Instance) ipSet() *platform.IPSet {
	s := &platform.IPSet{}
	s.Add(platform.IPInternal, in.PrivateIP)
	s.Add(platform.IPInternal, in.InnerIPs...)
	for _, n := range in.Interfaces {
		s.Add(platform.IPInternal, n.Private...)
		s.Add(platform.IPInternal, n.IPv6...)
		s.Add(platform.IPInternal, n.Prefixes...)
	}
	s.Add(platform.IPExternal, in.PublicIP)
	s.Add(platform.IPExternal, in.PublicIPs...)
	s.Add(platform.IPExternal, in.EIP, in.NatIP)
	for _, n := range in.Interfaces {
		s.Add(platform.IPExternal, n.Public...)
	}
	return s
}

// enabledRegions lists the regions of the account (ecs DescribeRegions).
func (c *client) enabledRegions(ctx context.Context) ([]string, error) {
	cl, err := c.ecsClient(ctx, c.region)
	if err != nil {
		return nil, err
	}
	req := ecs.CreateDescribeRegionsRequest()
	c.route(req, endpointECS)
	req.RegionId = c.region
	resp, err := cl.DescribeRegions(req)
	if err != nil {
		return nil, wrapErr("ecs DescribeRegions", err)
	}
	var regions []string
	for _, r := range resp.Regions.Region {
		if r.RegionId != "" {
			regions = append(regions, r.RegionId)
		}
	}
	if len(regions) == 0 {
		regions = []string{c.region}
	}
	sort.Strings(regions)
	return regions, nil
}

// inEveryRegion runs fn in every region of the account; a region that fails
// (some region endpoints fail to resolve now and then) is a region failure
// of the sync, not of the account.
func (c *client) inEveryRegion(ctx context.Context, fn func(ctx context.Context, region string) ([]platform.Resource, error)) ([]platform.Resource, error) {
	regions, err := c.enabledRegions(ctx)
	if err != nil {
		return nil, err
	}
	return platform.SyncRegions(ctx, regions, regionConcurrency, fn)
}

// networkInterfaces lists the network interfaces of a region, page by page
// (NextToken empty or missing ends the list).
func (c *client) networkInterfaces(ctx context.Context, region string) ([]ecs.NetworkInterfaceSet, error) {
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return nil, err
	}
	var out []ecs.NetworkInterfaceSet
	token := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := ecs.CreateDescribeNetworkInterfacesRequest()
		c.route(req, endpointECS)
		req.RegionId = region
		req.MaxResults = requests.NewInteger(pageSize)
		req.NextToken = token
		resp, err := cl.DescribeNetworkInterfaces(req)
		if err != nil {
			return nil, wrapErr("ecs DescribeNetworkInterfaces "+region, err)
		}
		out = append(out, resp.NetworkInterfaceSets.NetworkInterfaceSet...)
		if resp.NextToken == "" || resp.NextToken == token || len(resp.NetworkInterfaceSets.NetworkInterfaceSet) == 0 {
			break
		}
		token = resp.NextToken
	}
	return out, nil
}

// instanceResources lists the instances of a region with every address of
// every interface: DescribeInstances lists the primary address of each
// interface only, so the interfaces of the region are read too. When they
// cannot be read, the instances are kept with what DescribeInstances gave
// and the region is reported.
func (c *client) instanceResources(ctx context.Context, region string) ([]platform.Resource, error) {
	res, err := c.ListInstances(ctx, region)
	if err != nil || len(res) == 0 {
		return res, err
	}
	enis, err := c.networkInterfaces(ctx, region)
	if err != nil {
		return res, &platform.RegionSyncError{Failures: []platform.RegionError{{Region: region + " (network interfaces)", Err: err}}}
	}
	byInstance := map[string][]netIface{}
	for _, e := range enis {
		if e.InstanceId != "" {
			byInstance[e.InstanceId] = append(byInstance[e.InstanceId], netIfaceFromENI(e))
		}
	}
	for k, r := range res {
		in, ok := r.Data.(Instance)
		if !ok || len(byInstance[in.ID]) == 0 {
			continue
		}
		for _, n := range byInstance[in.ID] {
			found := false
			for i := range in.Interfaces {
				if in.Interfaces[i].ID == n.ID && n.ID != "" {
					in.Interfaces[i].merge(n)
					found = true
				}
			}
			if !found {
				in.Interfaces = append(in.Interfaces, n)
			}
		}
		res[k] = instanceResource(in)
	}
	return res, nil
}

// albLoadBalancer is the inventory form of an ALB instance.
type albLoadBalancer struct {
	ID            string   `json:"id" yaml:"id"`
	Name          string   `json:"name" yaml:"name"`
	DNSName       string   `json:"dns_name,omitempty" yaml:"dns_name,omitempty"`
	AddressType   string   `json:"address_type,omitempty" yaml:"address_type,omitempty"`
	IPVersion     string   `json:"address_ip_version,omitempty" yaml:"address_ip_version,omitempty"`
	Status        string   `json:"status,omitempty" yaml:"status,omitempty"`
	VpcID         string   `json:"vpc_id,omitempty" yaml:"vpc_id,omitempty"`
	Region        string   `json:"region" yaml:"region"`
	Zones         []string `json:"zones,omitempty" yaml:"zones,omitempty"`
	Public        []string `json:"public_ips,omitempty" yaml:"public_ips,omitempty"`
	Private       []string `json:"private_ips,omitempty" yaml:"private_ips,omitempty"`
	AllocationIDs []string `json:"allocation_ids,omitempty" yaml:"allocation_ids,omitempty"`
	Interfaces    []string `json:"interfaces,omitempty" yaml:"interfaces,omitempty"`
}

func (l albLoadBalancer) resource() platform.Resource {
	var s platform.IPSet
	s.Add(platform.IPInternal, l.Private...)
	s.Add(platform.IPExternal, l.Public...)
	s.AddDNS(l.DNSName)
	name := l.Name
	if name == "" {
		name = l.ID
	}
	return platform.Resource{Type: platform.ResLoadBalancer, ID: l.ID, Name: name, ParentID: l.Region, Data: l, IPs: s.Refs()}
}

// albFromAttribute reads the addresses of an ALB. The zones come in no
// particular order, and any field may be missing (a load balancer that is
// internal only or IPv6 only).
func albFromAttribute(a *alb.GetLoadBalancerAttributeResponse, region string) albLoadBalancer {
	l := albLoadBalancer{ID: a.LoadBalancerId, Name: a.LoadBalancerName, DNSName: a.DNSName, AddressType: a.AddressType,
		IPVersion: a.AddressIpVersion, Status: a.LoadBalancerStatus, VpcID: a.VpcId, Region: region}
	for _, z := range a.ZoneMappings {
		l.Zones = appendNew(l.Zones, z.ZoneId)
		l.AllocationIDs = appendNew(l.AllocationIDs, z.AllocationId)
		for _, ad := range z.LoadBalancerAddresses {
			if strings.EqualFold(a.AddressType, "Intranet") {
				l.Private = appendNew(l.Private, ad.Address)
			} else {
				l.Public = appendNew(l.Public, ad.Address)
			}
			l.Private = appendNew(l.Private, ad.IntranetAddress)
			l.Private = appendNew(l.Private, ad.Ipv4LocalAddresses...)
			l.Private = appendNew(l.Private, ad.Ipv6LocalAddresses...)
			l.Public = appendNew(l.Public, ad.Ipv6Address)
			l.AllocationIDs = appendNew(l.AllocationIDs, ad.AllocationId)
		}
	}
	return l
}

// albInterfaceNames are the names ALB may give its network interfaces:
// observed as "alb-<id> CREATED_BY_ALB"; whether <id> there carries the
// "alb-" prefix of the load balancer id is not verified, so both forms are
// accepted.
func albInterfaceNames(id string) []string {
	return []string{id + " CREATED_BY_ALB", "alb-" + id + " CREATED_BY_ALB"}
}

// albResources lists the ALB instances of a region with their addresses:
// ListLoadBalancers has none, so each is read with GetLoadBalancerAttribute
// (a bounded number at a time), and the addresses of the network interfaces
// ALB created for it ("<id> CREATED_BY_ALB") are added.
func (c *client) albResources(ctx context.Context, region string) ([]platform.Resource, error) {
	cl, err := alb.NewClientWithOptions(region, sdkConfig(), c.credential())
	if err != nil {
		return nil, err
	}
	cl.SetTransport(ctxTransport{ctx: ctx, base: c.transport})
	var ids []string
	token := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := alb.CreateListLoadBalancersRequest()
		c.route(req, albEndpoint(region))
		req.MaxResults = requests.NewInteger(albPageSize)
		req.NextToken = token
		resp, err := cl.ListLoadBalancers(req)
		if err != nil {
			return nil, wrapErr("alb ListLoadBalancers "+region, err)
		}
		for _, lb := range resp.LoadBalancers {
			ids = append(ids, lb.LoadBalancerId)
		}
		if resp.NextToken == "" || resp.NextToken == token || len(resp.LoadBalancers) == 0 {
			break
		}
		token = resp.NextToken
	}
	if len(ids) == 0 {
		return nil, nil
	}
	got, err := platform.SyncRegions(ctx, ids, regionConcurrency, func(ctx context.Context, id string) ([]platform.Resource, error) {
		req := alb.CreateGetLoadBalancerAttributeRequest()
		c.route(req, albEndpoint(region))
		req.LoadBalancerId = id
		resp, err := cl.GetLoadBalancerAttribute(req)
		if err != nil {
			return nil, wrapErr("alb GetLoadBalancerAttribute "+id, err)
		}
		return []platform.Resource{{Data: albFromAttribute(resp, region)}}, nil
	})
	if err != nil && platform.AsRegionSyncError(err) == nil {
		return nil, err
	}
	partial := err
	byName := map[string]int{}
	lbs := make([]albLoadBalancer, 0, len(got))
	for i, r := range got {
		l := r.Data.(albLoadBalancer)
		for _, n := range albInterfaceNames(l.ID) {
			byName[n] = i
		}
		lbs = append(lbs, l)
	}
	if enis, err := c.networkInterfaces(ctx, region); err == nil {
		for _, e := range enis {
			i, ok := byName[e.NetworkInterfaceName]
			if !ok {
				continue
			}
			n := netIfaceFromENI(e)
			lbs[i].Interfaces = appendNew(lbs[i].Interfaces, n.ID)
			lbs[i].Private = appendNew(lbs[i].Private, n.Private...)
			lbs[i].Private = appendNew(lbs[i].Private, n.IPv6...)
			lbs[i].Public = appendNew(lbs[i].Public, n.Public...)
		}
	} else if partial == nil {
		partial = &platform.RegionSyncError{Failures: []platform.RegionError{{Region: region + " (network interfaces)", Err: err}}}
	}
	out := make([]platform.Resource, 0, len(lbs))
	for _, l := range lbs {
		out = append(out, l.resource())
	}
	if partial != nil {
		// The load balancers that could not be read are a failure of the
		// region; the others are stored.
		return out, &platform.RegionSyncError{Failures: []platform.RegionError{{Region: region, Err: partial}}}
	}
	return out, nil
}

// FindTypes are the inventory types whose rows carry addresses.
func (*provider) FindTypes() []platform.ResourceType {
	return []platform.ResourceType{platform.ResInstance, platform.ResLoadBalancer, platform.ResEIP}
}

// matchedIface returns the interface of an instance holding the matched
// address, else the primary one.
func (in Instance) matchedIface(m *platform.FindMatch) *netIface {
	var primary *netIface
	for k := range in.Interfaces {
		n := &in.Interfaces[k]
		if primary == nil && (n.Type == "Primary" || k == 0) {
			primary = n
		}
		for _, group := range [][]string{n.Private, n.Public, n.IPv6, n.Prefixes} {
			for _, v := range group {
				if m.Holds(v) {
					return n
				}
			}
		}
	}
	return primary
}

// DescribeMatch fills a find match from the stored data.
func (*provider) DescribeMatch(_ map[string]string, m *platform.FindMatch) error {
	switch m.Type {
	case platform.ResInstance:
		var in Instance
		if err := json.Unmarshal(m.Data, &in); err != nil {
			return err
		}
		s := in.ipSet()
		m.Region, m.Zone, m.State = in.Region, in.Zone, in.Status
		m.InternalIPs, m.ExternalIPs = s.Values(platform.IPInternal), s.Values(platform.IPExternal)
		m.Network, m.Subnet = in.VpcID, in.VSwitchID
		if n := in.matchedIface(m); n != nil && n.VSwitchID != "" {
			m.Subnet = n.VSwitchID
		}
	case platform.ResLoadBalancer:
		var l albLoadBalancer
		if err := json.Unmarshal(m.Data, &l); err != nil {
			return err
		}
		m.Region, m.State, m.Network = l.Region, l.Status, l.VpcID
		m.InternalIPs, m.ExternalIPs = l.Private, l.Public
		if l.DNSName != "" {
			m.DNSNames = []string{l.DNSName}
		}
		m.Note = strings.TrimSpace("ALB " + l.AddressType)
	case platform.ResEIP:
		var e eipAddress
		if err := json.Unmarshal(m.Data, &e); err != nil {
			return err
		}
		m.Region, m.State = e.Region, e.Status
		m.ExternalIPs = appendNew(nil, e.IP)
		if e.bound() {
			m.Note = "EIP bound to " + e.boundTo()
		} else {
			m.Note = "EIP, not bound"
		}
	default:
		return fmt.Errorf("%s: %w", m.Type, platform.ErrNotSupported)
	}
	return nil
}

// ConsoleURL returns the console page of an ECS instance, on the domain of
// the account's site (recorded at login; without it there is no link). ALB
// and EIP pages have no reliable link.
func (*provider) ConsoleURL(meta map[string]string, m *platform.FindMatch) string {
	if m.Type != platform.ResInstance || m.ID == "" || m.Region == "" {
		return ""
	}
	var host string
	switch strings.ToLower(strings.TrimSpace(meta[metaSite])) {
	case siteCN:
		host = "ecs.console.aliyun.com"
	case siteIntl:
		host = "ecs.console.alibabacloud.com"
	default:
		return ""
	}
	return fmt.Sprintf("https://%s/server/%s/detail?regionId=%s", host, url.PathEscape(m.ID), url.QueryEscape(m.Region))
}

// NetworkDetail reads the vSwitch of the interface of a matched instance
// that holds the address (vpc DescribeVSwitches).
func (c *client) NetworkDetail(ctx context.Context, m *platform.FindMatch) (*platform.NetworkDetail, error) {
	if m.Type != platform.ResInstance {
		return nil, platform.ErrNotSupported
	}
	var in Instance
	if err := json.Unmarshal(m.Data, &in); err != nil {
		return nil, err
	}
	vsw := in.VSwitchID
	if n := in.matchedIface(m); n != nil && n.VSwitchID != "" {
		vsw = n.VSwitchID
	}
	if vsw == "" || in.Region == "" {
		return nil, fmt.Errorf("%w: the instance has no vSwitch in the inventory (classic network, or run polyctl find --refresh)", platform.ErrNotSupported)
	}
	list, err := c.listVSwitches(ctx, in.Region, "", "", vsw)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("%w: vSwitch %s in %s", platform.ErrNotFound, vsw, in.Region)
	}
	v := list[0]
	d := &platform.NetworkDetail{VPC: v.VPC, Subnet: v.ID, SubnetRegion: in.Region, SubnetCIDR: v.CIDR}
	if v.IPv6CIDR != "" {
		d.SubnetIPv6CIDR = []string{v.IPv6CIDR}
	}
	return d, nil
}
