package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/rds"

	"github.com/gofika/polyctl/internal/platform"
)

var (
	_ platform.IPSource       = (*provider)(nil)
	_ platform.MatchDescriber = (*provider)(nil)
	_ platform.ConsoleLinker  = (*provider)(nil)
	_ platform.DetailProvider = (*client)(nil)
)

type elbAPI interface {
	DescribeLoadBalancers(ctx context.Context, in *elb.DescribeLoadBalancersInput, optFns ...func(*elb.Options)) (*elb.DescribeLoadBalancersOutput, error)
}

type rdsAPI interface {
	DescribeDBInstances(ctx context.Context, in *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
}

// newELB and newRDS create the regional clients; tests replace them.
var (
	newELB = func(cfg awssdk.Config) elbAPI { return elb.NewFromConfig(cfg) }
	newRDS = func(cfg awssdk.Config) rdsAPI { return rds.NewFromConfig(cfg) }
)

// regionConcurrency bounds the regions synced at the same time.
const regionConcurrency = 8

// netIface is one network interface with all its addresses.
type netIface struct {
	ID       string   `json:"id,omitempty" yaml:"id,omitempty"`
	SubnetID string   `json:"subnet_id,omitempty" yaml:"subnet_id,omitempty"`
	VpcID    string   `json:"vpc_id,omitempty" yaml:"vpc_id,omitempty"`
	Private  []string `json:"private_ips,omitempty" yaml:"private_ips,omitempty"`
	Public   []string `json:"public_ips,omitempty" yaml:"public_ips,omitempty"`
	IPv6     []string `json:"ipv6,omitempty" yaml:"ipv6,omitempty"`
	// Prefixes are the delegated IPv4 and IPv6 prefixes.
	Prefixes []string `json:"prefixes,omitempty" yaml:"prefixes,omitempty"`
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

// netIfaceFromInstance flattens an interface of DescribeInstances: every
// private address with its public association, IPv6 addresses and
// prefixes.
func netIfaceFromInstance(ni ec2types.InstanceNetworkInterface) netIface {
	out := netIface{ID: awssdk.ToString(ni.NetworkInterfaceId), SubnetID: awssdk.ToString(ni.SubnetId), VpcID: awssdk.ToString(ni.VpcId)}
	out.Private = appendNew(out.Private, awssdk.ToString(ni.PrivateIpAddress))
	if ni.Association != nil {
		out.Public = appendNew(out.Public, awssdk.ToString(ni.Association.PublicIp))
	}
	for _, p := range ni.PrivateIpAddresses {
		out.Private = appendNew(out.Private, awssdk.ToString(p.PrivateIpAddress))
		if p.Association != nil {
			out.Public = appendNew(out.Public, awssdk.ToString(p.Association.PublicIp))
		}
	}
	for _, a := range ni.Ipv6Addresses {
		out.IPv6 = appendNew(out.IPv6, awssdk.ToString(a.Ipv6Address))
	}
	for _, p := range ni.Ipv4Prefixes {
		out.Prefixes = appendNew(out.Prefixes, awssdk.ToString(p.Ipv4Prefix))
	}
	for _, p := range ni.Ipv6Prefixes {
		out.Prefixes = appendNew(out.Prefixes, awssdk.ToString(p.Ipv6Prefix))
	}
	return out
}

// netIfaceFromENI flattens a network interface of DescribeNetworkInterfaces.
func netIfaceFromENI(ni ec2types.NetworkInterface) netIface {
	out := netIface{ID: awssdk.ToString(ni.NetworkInterfaceId), SubnetID: awssdk.ToString(ni.SubnetId), VpcID: awssdk.ToString(ni.VpcId)}
	out.Private = appendNew(out.Private, awssdk.ToString(ni.PrivateIpAddress))
	if ni.Association != nil {
		out.Public = appendNew(out.Public, awssdk.ToString(ni.Association.PublicIp))
	}
	for _, p := range ni.PrivateIpAddresses {
		out.Private = appendNew(out.Private, awssdk.ToString(p.PrivateIpAddress))
		if p.Association != nil {
			out.Public = appendNew(out.Public, awssdk.ToString(p.Association.PublicIp))
		}
	}
	for _, a := range ni.Ipv6Addresses {
		out.IPv6 = appendNew(out.IPv6, awssdk.ToString(a.Ipv6Address))
	}
	for _, p := range ni.Ipv4Prefixes {
		out.Prefixes = appendNew(out.Prefixes, awssdk.ToString(p.Ipv4Prefix))
	}
	for _, p := range ni.Ipv6Prefixes {
		out.Prefixes = appendNew(out.Prefixes, awssdk.ToString(p.Ipv6Prefix))
	}
	return out
}

func (n netIface) set(s *platform.IPSet) {
	s.Add(platform.IPInternal, n.Private...)
	s.Add(platform.IPInternal, n.IPv6...)
	s.Add(platform.IPInternal, n.Prefixes...)
	s.Add(platform.IPExternal, n.Public...)
}

// ipSet returns every address and DNS name of an instance. A terminated
// instance holds none.
func (i instanceInfo) ipSet() *platform.IPSet {
	s := &platform.IPSet{}
	if i.State == stateTerminated {
		return s
	}
	s.Add(platform.IPInternal, i.PrivateIP)
	s.Add(platform.IPExternal, i.PublicIP)
	for _, n := range i.Interfaces {
		n.set(s)
	}
	s.AddDNS(i.PublicDNS, i.PrivateDNS)
	return s
}

// enabledRegions lists the regions enabled for the account
// (DescribeRegions without AllRegions).
func (c *client) enabledRegions(ctx context.Context) ([]string, error) {
	out, err := c.ec2For(c.region).DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, ec2Err("DescribeRegions", c.region, err)
	}
	var regions []string
	for _, r := range out.Regions {
		if n := awssdk.ToString(r.RegionName); n != "" {
			regions = append(regions, n)
		}
	}
	if len(regions) == 0 {
		regions = []string{c.region}
	}
	sort.Strings(regions)
	return regions, nil
}

// inEveryRegion runs fn in every enabled region; a region that fails is a
// region failure of the sync, not of the account.
func (c *client) inEveryRegion(ctx context.Context, fn func(ctx context.Context, region string) ([]platform.Resource, error)) ([]platform.Resource, error) {
	regions, err := c.enabledRegions(ctx)
	if err != nil {
		return nil, err
	}
	return platform.SyncRegions(ctx, regions, regionConcurrency, fn)
}

// networkInterfaces lists the network interfaces of a region matching the
// filters, page by page until NextToken is empty (a page can be much
// shorter than MaxResults).
func (c *client) networkInterfaces(ctx context.Context, region string, filters []ec2types.Filter) ([]ec2types.NetworkInterface, error) {
	var out []ec2types.NetworkInterface
	pg := ec2.NewDescribeNetworkInterfacesPaginator(c.ec2For(region), &ec2.DescribeNetworkInterfacesInput{Filters: filters, MaxResults: awssdk.Int32(1000)})
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, ec2Err("DescribeNetworkInterfaces", region, err)
		}
		out = append(out, page.NetworkInterfaces...)
	}
	return out, nil
}

// elbDescription is the description of the network interfaces of a load
// balancer: "ELB " and the part of its ARN after "loadbalancer/" (observed
// on Network Load Balancers: "ELB net/<name>/<id>").
func elbDescription(arn string) string {
	if _, suffix, ok := strings.Cut(arn, ":loadbalancer/"); ok {
		return "ELB " + suffix
	}
	return ""
}

// loadBalancer is the inventory form of an ELBv2 load balancer.
type loadBalancer struct {
	ARN     string   `json:"arn" yaml:"arn"`
	Name    string   `json:"name" yaml:"name"`
	Type    string   `json:"type,omitempty" yaml:"type,omitempty"`
	Scheme  string   `json:"scheme,omitempty" yaml:"scheme,omitempty"`
	State   string   `json:"state,omitempty" yaml:"state,omitempty"`
	DNSName string   `json:"dns_name,omitempty" yaml:"dns_name,omitempty"`
	VpcID   string   `json:"vpc_id,omitempty" yaml:"vpc_id,omitempty"`
	Region  string   `json:"region" yaml:"region"`
	Zones   []string `json:"zones,omitempty" yaml:"zones,omitempty"`
	// Private and Public are the addresses of the load balancer: those set
	// on its zones and those of its network interfaces.
	Private    []string `json:"private_ips,omitempty" yaml:"private_ips,omitempty"`
	Public     []string `json:"public_ips,omitempty" yaml:"public_ips,omitempty"`
	Interfaces []string `json:"interfaces,omitempty" yaml:"interfaces,omitempty"`
}

func (l loadBalancer) resource() platform.Resource {
	var s platform.IPSet
	s.Add(platform.IPInternal, l.Private...)
	s.Add(platform.IPExternal, l.Public...)
	s.AddDNS(l.DNSName)
	return platform.Resource{Type: platform.ResLoadBalancer, ID: l.ARN, Name: l.Name, ParentID: l.Region, Data: l, IPs: s.Refs()}
}

// loadBalancerResources lists the ELBv2 load balancers of a region with
// their addresses. The zones of a Network Load Balancer without elastic or
// fixed private addresses list none, so the addresses of the network
// interfaces whose description names the load balancer are added.
func (c *client) loadBalancerResources(ctx context.Context, region string) ([]platform.Resource, error) {
	var lbs []loadBalancer
	pg := elb.NewDescribeLoadBalancersPaginator(c.elbFor(region), &elb.DescribeLoadBalancersInput{PageSize: awssdk.Int32(400)})
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("elasticloadbalancing:DescribeLoadBalancers in %s: %w", region, mapErr(err))
		}
		for _, lb := range page.LoadBalancers {
			l := loadBalancer{ARN: awssdk.ToString(lb.LoadBalancerArn), Name: awssdk.ToString(lb.LoadBalancerName), Type: string(lb.Type),
				Scheme: string(lb.Scheme), DNSName: awssdk.ToString(lb.DNSName), VpcID: awssdk.ToString(lb.VpcId), Region: region}
			if lb.State != nil {
				l.State = string(lb.State.Code)
			}
			for _, z := range lb.AvailabilityZones {
				l.Zones = appendNew(l.Zones, awssdk.ToString(z.ZoneName))
				for _, a := range z.LoadBalancerAddresses {
					l.Public = appendNew(l.Public, awssdk.ToString(a.IpAddress))
					l.Private = appendNew(l.Private, awssdk.ToString(a.PrivateIPv4Address))
					if v := awssdk.ToString(a.IPv6Address); v != "" {
						l.Private = appendNew(l.Private, v)
					}
				}
			}
			lbs = append(lbs, l)
		}
	}
	if len(lbs) == 0 {
		return nil, nil
	}
	enis, err := c.networkInterfaces(ctx, region, []ec2types.Filter{{Name: awssdk.String("description"), Values: []string{"ELB *"}}})
	if err != nil {
		return nil, err
	}
	byDesc := map[string]int{}
	for i, l := range lbs {
		if d := elbDescription(l.ARN); d != "" {
			byDesc[d] = i
		}
	}
	for _, e := range enis {
		i, ok := byDesc[awssdk.ToString(e.Description)]
		if !ok {
			continue
		}
		n := netIfaceFromENI(e)
		lbs[i].Interfaces = appendNew(lbs[i].Interfaces, n.ID)
		lbs[i].Private = appendNew(lbs[i].Private, n.Private...)
		lbs[i].Private = appendNew(lbs[i].Private, n.IPv6...)
		lbs[i].Public = appendNew(lbs[i].Public, n.Public...)
	}
	out := make([]platform.Resource, 0, len(lbs))
	for _, l := range lbs {
		out = append(out, l.resource())
	}
	return out, nil
}

// address is the inventory form of an elastic IP address, or of a network
// interface no instance holds (Kind "network_interface": the interface of
// a NAT gateway, a database, an endpoint, ...), whose addresses are found
// nowhere else.
type address struct {
	Kind               string   `json:"kind" yaml:"kind"`
	ID                 string   `json:"id" yaml:"id"`
	PublicIP           string   `json:"public_ip,omitempty" yaml:"public_ip,omitempty"`
	PrivateIPs         []string `json:"private_ips,omitempty" yaml:"private_ips,omitempty"`
	PublicIPs          []string `json:"public_ips,omitempty" yaml:"public_ips,omitempty"`
	AssociationID      string   `json:"association_id,omitempty" yaml:"association_id,omitempty"`
	InstanceID         string   `json:"instance_id,omitempty" yaml:"instance_id,omitempty"`
	NetworkInterfaceID string   `json:"network_interface_id,omitempty" yaml:"network_interface_id,omitempty"`
	Domain             string   `json:"domain,omitempty" yaml:"domain,omitempty"`
	Name               string   `json:"name,omitempty" yaml:"name,omitempty"`
	Description        string   `json:"description,omitempty" yaml:"description,omitempty"`
	InterfaceType      string   `json:"interface_type,omitempty" yaml:"interface_type,omitempty"`
	Status             string   `json:"status,omitempty" yaml:"status,omitempty"`
	VpcID              string   `json:"vpc_id,omitempty" yaml:"vpc_id,omitempty"`
	SubnetID           string   `json:"subnet_id,omitempty" yaml:"subnet_id,omitempty"`
	Zone               string   `json:"zone,omitempty" yaml:"zone,omitempty"`
	Region             string   `json:"region" yaml:"region"`
}

const (
	addressKindEIP       = "elastic_ip"
	addressKindInterface = "network_interface"
)

func (a address) resource() platform.Resource {
	var s platform.IPSet
	s.Add(platform.IPExternal, a.PublicIP)
	s.Add(platform.IPExternal, a.PublicIPs...)
	s.Add(platform.IPInternal, a.PrivateIPs...)
	name := a.Name
	if name == "" {
		name = a.PublicIP
	}
	if name == "" {
		name = a.ID
	}
	return platform.Resource{Type: platform.ResEIP, ID: a.ID, Name: name, ParentID: a.Region, Data: a, IPs: s.Refs()}
}

// addressResources lists the elastic IP addresses of a region and the
// network interfaces that no instance and no load balancer holds.
// DescribeAddresses is not paginated.
func (c *client) addressResources(ctx context.Context, region string) ([]platform.Resource, error) {
	out, err := c.ec2For(region).DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return nil, ec2Err("DescribeAddresses", region, err)
	}
	var res []platform.Resource
	eipIfaces := map[string]bool{}
	for _, a := range out.Addresses {
		ad := address{Kind: addressKindEIP, ID: awssdk.ToString(a.AllocationId), PublicIP: awssdk.ToString(a.PublicIp),
			AssociationID: awssdk.ToString(a.AssociationId), InstanceID: awssdk.ToString(a.InstanceId),
			NetworkInterfaceID: awssdk.ToString(a.NetworkInterfaceId), Domain: string(a.Domain), Region: region}
		ad.PrivateIPs = appendNew(nil, awssdk.ToString(a.PrivateIpAddress))
		for _, t := range a.Tags {
			if awssdk.ToString(t.Key) == "Name" {
				ad.Name = awssdk.ToString(t.Value)
			}
		}
		if ad.ID == "" {
			ad.ID = ad.PublicIP
		}
		if ad.NetworkInterfaceID != "" {
			eipIfaces[ad.NetworkInterfaceID] = true
		}
		res = append(res, ad.resource())
	}
	enis, err := c.networkInterfaces(ctx, region, nil)
	if err != nil {
		return nil, err
	}
	for _, e := range enis {
		if e.Attachment != nil && awssdk.ToString(e.Attachment.InstanceId) != "" {
			continue // found through its instance
		}
		desc := awssdk.ToString(e.Description)
		if strings.HasPrefix(desc, "ELB ") || e.InterfaceType == ec2types.NetworkInterfaceTypeNetworkLoadBalancer {
			continue // found through its load balancer
		}
		n := netIfaceFromENI(e)
		ad := address{Kind: addressKindInterface, ID: n.ID, PrivateIPs: append(append([]string(nil), n.Private...), n.IPv6...),
			Description: desc, InterfaceType: string(e.InterfaceType), Status: string(e.Status), VpcID: n.VpcID, SubnetID: n.SubnetID,
			Zone: awssdk.ToString(e.AvailabilityZone), Region: region}
		if !eipIfaces[n.ID] {
			// An elastic IP of the interface is already a row of its own.
			ad.PublicIPs = n.Public
		}
		ad.PrivateIPs = append(ad.PrivateIPs, n.Prefixes...)
		ad.Name = desc
		res = append(res, ad.resource())
	}
	return res, nil
}

// dbInstance is the inventory form of an RDS instance.
type dbInstance struct {
	ID       string `json:"id" yaml:"id"`
	Status   string `json:"status,omitempty" yaml:"status,omitempty"`
	Engine   string `json:"engine,omitempty" yaml:"engine,omitempty"`
	Class    string `json:"class,omitempty" yaml:"class,omitempty"`
	Endpoint string `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`
	Port     int32  `json:"port,omitempty" yaml:"port,omitempty"`
	Zone     string `json:"zone,omitempty" yaml:"zone,omitempty"`
	VpcID    string `json:"vpc_id,omitempty" yaml:"vpc_id,omitempty"`
	Region   string `json:"region" yaml:"region"`
}

func (d dbInstance) resource() platform.Resource {
	var s platform.IPSet
	s.AddDNS(d.Endpoint)
	return platform.Resource{Type: platform.ResDBInstance, ID: d.ID, Name: d.ID, ParentID: d.Region, Data: d, IPs: s.Refs()}
}

// dbInstanceResources lists the RDS instances of a region. RDS gives no
// addresses: an instance is found by its endpoint, and one without an
// endpoint yet (being created) is stored without one.
func (c *client) dbInstanceResources(ctx context.Context, region string) ([]platform.Resource, error) {
	var res []platform.Resource
	pg := rds.NewDescribeDBInstancesPaginator(c.rdsFor(region), &rds.DescribeDBInstancesInput{MaxRecords: awssdk.Int32(100)})
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("rds:DescribeDBInstances in %s: %w", region, mapErr(err))
		}
		for _, db := range page.DBInstances {
			d := dbInstance{ID: awssdk.ToString(db.DBInstanceIdentifier), Status: awssdk.ToString(db.DBInstanceStatus),
				Engine: awssdk.ToString(db.Engine), Class: awssdk.ToString(db.DBInstanceClass), Zone: awssdk.ToString(db.AvailabilityZone), Region: region}
			if db.Endpoint != nil {
				d.Endpoint, d.Port = awssdk.ToString(db.Endpoint.Address), awssdk.ToInt32(db.Endpoint.Port)
			}
			if db.DBSubnetGroup != nil {
				d.VpcID = awssdk.ToString(db.DBSubnetGroup.VpcId)
			}
			res = append(res, d.resource())
		}
	}
	return res, nil
}

// FindTypes are the inventory types whose rows carry addresses.
func (*provider) FindTypes() []platform.ResourceType {
	return []platform.ResourceType{platform.ResInstance, platform.ResLoadBalancer, platform.ResEIP, platform.ResDBInstance}
}

// matchedIface returns the interface of an instance holding the matched
// address, else the first one.
func (i instanceInfo) matchedIface(m *platform.FindMatch) *netIface {
	for k := range i.Interfaces {
		n := &i.Interfaces[k]
		for _, group := range [][]string{n.Private, n.Public, n.IPv6, n.Prefixes} {
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

// DescribeMatch fills a find match from the stored data.
func (*provider) DescribeMatch(_ map[string]string, m *platform.FindMatch) error {
	switch m.Type {
	case platform.ResInstance:
		var i instanceInfo
		if err := json.Unmarshal(m.Data, &i); err != nil {
			return err
		}
		s := i.ipSet()
		m.Region, m.Zone, m.State = i.Region, i.AZ, i.State
		m.InternalIPs, m.ExternalIPs, m.DNSNames = s.Values(platform.IPInternal), s.Values(platform.IPExternal), s.Values(platform.IPDNS)
		m.Network, m.Subnet = i.VpcID, i.SubnetID
		if n := i.matchedIface(m); n != nil {
			if n.VpcID != "" {
				m.Network = n.VpcID
			}
			if n.SubnetID != "" {
				m.Subnet = n.SubnetID
			}
		}
	case platform.ResLoadBalancer:
		var l loadBalancer
		if err := json.Unmarshal(m.Data, &l); err != nil {
			return err
		}
		m.Region, m.State, m.Network = l.Region, l.State, l.VpcID
		m.InternalIPs, m.ExternalIPs = l.Private, l.Public
		if l.DNSName != "" {
			m.DNSNames = []string{l.DNSName}
		}
		m.Note = strings.TrimSpace(l.Type + " load balancer " + l.Scheme)
	case platform.ResEIP:
		var a address
		if err := json.Unmarshal(m.Data, &a); err != nil {
			return err
		}
		m.Region, m.Zone, m.Network, m.Subnet, m.State = a.Region, a.Zone, a.VpcID, a.SubnetID, a.Status
		m.InternalIPs = a.PrivateIPs
		m.ExternalIPs = appendNew(appendNew(nil, a.PublicIP), a.PublicIPs...)
		switch {
		case a.Kind == addressKindInterface:
			m.Note = "network interface " + a.ID
			if a.Description != "" {
				m.Note += ": " + a.Description
			}
		case a.InstanceID != "":
			m.Note = "elastic IP associated with instance " + a.InstanceID
		case a.NetworkInterfaceID != "":
			m.Note = "elastic IP associated with network interface " + a.NetworkInterfaceID
		default:
			m.Note = "elastic IP, not associated"
		}
	case platform.ResDBInstance:
		var d dbInstance
		if err := json.Unmarshal(m.Data, &d); err != nil {
			return err
		}
		m.Region, m.Zone, m.State, m.Network = d.Region, d.Zone, d.Status, d.VpcID
		if d.Endpoint != "" {
			m.DNSNames = []string{d.Endpoint}
		}
		m.Note = strings.TrimSpace("RDS " + d.Engine)
	default:
		return fmt.Errorf("%s: %w", m.Type, platform.ErrNotSupported)
	}
	return nil
}

// commercialRegion reports a region of the commercial partition, the only
// one the console links cover (China and GovCloud have other domains).
func commercialRegion(r string) bool {
	return r != "" && !strings.HasPrefix(r, "cn-") && !strings.HasPrefix(r, "us-gov-") && !strings.HasPrefix(r, "us-iso")
}

// ConsoleURL returns the console page of an instance or an RDS instance, on
// the region's console domain. The region is the one the resource was
// synced from, never derived from its availability zone. Load balancers and
// addresses have no link.
func (*provider) ConsoleURL(_ map[string]string, m *platform.FindMatch) string {
	if !commercialRegion(m.Region) || m.ID == "" {
		return ""
	}
	r := url.QueryEscape(m.Region)
	switch m.Type {
	case platform.ResInstance:
		return fmt.Sprintf("https://%s.console.aws.amazon.com/ec2/home?region=%s#InstanceDetails:instanceId=%s", r, r, url.QueryEscape(m.ID))
	case platform.ResDBInstance:
		return fmt.Sprintf("https://%s.console.aws.amazon.com/rds/home?region=%s#database:id=%s", r, r, url.QueryEscape(m.ID))
	}
	return ""
}

// NetworkDetail reads the subnet of the interface of a matched instance
// that holds the address (DescribeSubnets): its IPv4 and IPv6 blocks and
// VPC. AWS reports no gateway address.
func (c *client) NetworkDetail(ctx context.Context, m *platform.FindMatch) (*platform.NetworkDetail, error) {
	if m.Type != platform.ResInstance {
		return nil, platform.ErrNotSupported
	}
	var i instanceInfo
	if err := json.Unmarshal(m.Data, &i); err != nil {
		return nil, err
	}
	subnet := i.SubnetID
	if n := i.matchedIface(m); n != nil && n.SubnetID != "" {
		subnet = n.SubnetID
	}
	if subnet == "" || i.Region == "" {
		return nil, fmt.Errorf("%w: the instance has no subnet in the inventory (run polyctl find --refresh)", platform.ErrNotSupported)
	}
	out, err := c.ec2For(i.Region).DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{SubnetIds: []string{subnet}})
	if err != nil {
		return nil, ec2Err("DescribeSubnets", i.Region, err)
	}
	if len(out.Subnets) == 0 {
		return nil, fmt.Errorf("%w: subnet %s in %s", platform.ErrNotFound, subnet, i.Region)
	}
	sn := out.Subnets[0]
	d := &platform.NetworkDetail{VPC: awssdk.ToString(sn.VpcId), Subnet: awssdk.ToString(sn.SubnetId), SubnetRegion: i.Region, SubnetCIDR: awssdk.ToString(sn.CidrBlock)}
	for _, a := range sn.Ipv6CidrBlockAssociationSet {
		if v := awssdk.ToString(a.Ipv6CidrBlock); v != "" {
			d.SubnetIPv6CIDR = append(d.SubnetIPv6CIDR, v)
		}
	}
	return d, nil
}
