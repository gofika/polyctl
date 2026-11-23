package aliyun

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/alb"

	"github.com/gofika/polyctl/internal/platform"
)

// The values ALB load balancers, server groups and ACLs are created with.
const (
	albAddressType       = "Internet"
	albAddressIPVersion  = "Ipv4"
	albAllocatedMode     = "Fixed"
	albPayType           = "PostPay"
	albEdition           = "Standard"
	albServerGroupType   = "Instance"
	albServerTypeECS     = "Ecs"
	albForwardGroup      = "ForwardGroup"
	albStatusActive      = "Active"
	albStatusInactive    = "Inactive"
	albListenerRunning   = "Running"
	albAvailable         = "Available"
	albACLEntryBatch     = 20
	albACLEntriesPerPage = 100
)

// Error codes of the ALB API (verified on real accounts).
const (
	errALBLoadBalancerNotFound = "ResourceNotFound.LoadBalancer"
	errALBListenerNotFound     = "ResourceNotFound.Listener"
	errALBServerGroupNotFound  = "ResourceNotFound.ServerGroup"
	errALBACLNotFound          = "ResourceNotFound.Acl"
	errALBACLEntryNotFound     = "ResourceNotFound.AclEntry"
	errALBACLEntryExists       = "ResourceAlreadyExist.AclEntry"
	errALBDeletionProtection   = "OperationDenied.DeletionProtectionEnabled"
	errALBServerGroupInUse     = "ResourceInUse.ServerGroup"
	errALBDuplicateServer      = "DuplicatedParam.BackendServer"
	errALBVpcMismatch          = "Mismatch.VpcId"
	errALBMultiISP             = "OperationDenied.MultiIspType"
)

// albAddress is one address of a load balancer: the EIP of one zone.
type albAddress struct {
	Zone         string `json:"zone" yaml:"zone"`
	VSwitchID    string `json:"vswitch_id" yaml:"vswitch_id"`
	AllocationID string `json:"allocation_id" yaml:"allocation_id"`
	IP           string `json:"ip" yaml:"ip"`
}

// albLB is a load balancer as GetLoadBalancerAttribute reads it.
type albLB struct {
	ID                 string       `json:"id" yaml:"id"`
	Name               string       `json:"name" yaml:"name"`
	Status             string       `json:"status" yaml:"status"`
	Region             string       `json:"region" yaml:"region"`
	VpcID              string       `json:"vpc_id" yaml:"vpc_id"`
	DNSName            string       `json:"dns_name" yaml:"dns_name"`
	AddressType        string       `json:"address_type" yaml:"address_type"`
	Edition            string       `json:"edition" yaml:"edition"`
	ResourceGroupID    string       `json:"resource_group_id" yaml:"resource_group_id"`
	DeletionProtection bool         `json:"deletion_protection" yaml:"deletion_protection"`
	Addresses          []albAddress `json:"addresses" yaml:"addresses"`
}

// ips returns the public addresses of the load balancer, in zone order.
func (l albLB) ips() []string {
	var out []string
	for _, a := range l.Addresses {
		out = appendNew(out, a.IP)
	}
	return out
}

// allocationIDs returns the EIPs of the load balancer, in zone order.
func (l albLB) allocationIDs() []string {
	var out []string
	for _, a := range l.Addresses {
		out = appendNew(out, a.AllocationID)
	}
	return out
}

// albLBFromAttribute reads a load balancer. The zones come back in no
// particular order (verified: asked b, c; answered c, b), so they are
// sorted by zone id; an IPv4 load balancer has no IPv6 address.
func albLBFromAttribute(a *alb.GetLoadBalancerAttributeResponse, region string) albLB {
	l := albLB{ID: a.LoadBalancerId, Name: a.LoadBalancerName, Status: a.LoadBalancerStatus, Region: region, VpcID: a.VpcId,
		DNSName: a.DNSName, AddressType: a.AddressType, Edition: a.LoadBalancerEdition, ResourceGroupID: a.ResourceGroupId,
		DeletionProtection: a.DeletionProtectionConfig.Enabled, Addresses: []albAddress{}}
	zones := append([]alb.ZoneMapping(nil), a.ZoneMappings...)
	sort.SliceStable(zones, func(i, j int) bool { return zones[i].ZoneId < zones[j].ZoneId })
	for _, z := range zones {
		if len(z.LoadBalancerAddresses) == 0 {
			l.Addresses = append(l.Addresses, albAddress{Zone: z.ZoneId, VSwitchID: z.VSwitchId, AllocationID: z.AllocationId})
			continue
		}
		for _, ad := range z.LoadBalancerAddresses {
			id := ad.AllocationId
			if id == "" {
				id = z.AllocationId
			}
			ip := ad.Address
			if ip == "" {
				ip = ad.Ipv6Address
			}
			l.Addresses = append(l.Addresses, albAddress{Zone: z.ZoneId, VSwitchID: z.VSwitchId, AllocationID: id, IP: ip})
		}
	}
	return l
}

// listLBs lists the load balancers of the region that filter narrows
// (nil: all of them), every page.
func (a *albClient) listLBs(ctx context.Context, filter func(*alb.ListLoadBalancersRequest)) ([]albRef, error) {
	var out []albRef
	token := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := alb.CreateListLoadBalancersRequest()
		a.route(req)
		req.MaxResults = requests.NewInteger(albPageSize)
		req.NextToken = token
		if filter != nil {
			filter(req)
		}
		resp, err := a.cl.ListLoadBalancers(req)
		if err != nil {
			if isNoSuchHost(err) {
				return nil, fmt.Errorf("alb ListLoadBalancers %s: %w: %v", a.region, errNoALBEndpoint, err)
			}
			return nil, wrapErr("alb ListLoadBalancers "+a.region, err)
		}
		for _, lb := range resp.LoadBalancers {
			out = append(out, albRef{ID: lb.LoadBalancerId, Name: lb.LoadBalancerName, Status: lb.LoadBalancerStatus, VpcID: lb.VpcId,
				DNSName: lb.DNSName})
		}
		if resp.NextToken == "" || resp.NextToken == token || len(resp.LoadBalancers) == 0 {
			break
		}
		token = resp.NextToken
	}
	return out, nil
}

// findLoadBalancersByName returns the load balancers of that exact name
// (names are not unique).
func (a *albClient) findLoadBalancersByName(ctx context.Context, name string) ([]albRef, error) {
	list, err := a.listLBs(ctx, func(req *alb.ListLoadBalancersRequest) { req.LoadBalancerNames = &[]string{name} })
	if err != nil {
		return nil, err
	}
	var out []albRef
	for _, l := range list {
		if l.Name == name {
			out = append(out, l)
		}
	}
	return out, nil
}

// getLoadBalancer reads a load balancer; nil when it does not exist.
func (a *albClient) getLoadBalancer(ctx context.Context, id string) (*albLB, error) {
	req := alb.CreateGetLoadBalancerAttributeRequest()
	a.route(req)
	req.LoadBalancerId = id
	resp, err := a.cl.GetLoadBalancerAttribute(req)
	if err != nil {
		if platform.HasErrorCode(err, errALBLoadBalancerNotFound) {
			return nil, nil
		}
		return nil, wrapErr("alb GetLoadBalancerAttribute "+id, err)
	}
	if resp.LoadBalancerId == "" {
		return nil, nil
	}
	l := albLBFromAttribute(resp, a.region)
	return &l, nil
}

// albZoneMapping places a load balancer in one zone: a vSwitch and an EIP.
type albZoneMapping struct {
	Zone         string
	VSwitchID    string
	AllocationID string
}

// albLBSpec is a load balancer to create.
type albLBSpec struct {
	Name          string
	VpcID         string
	ResourceGroup string
	Zones         []albZoneMapping
	// Token is the ClientToken: the same for retries of one request, a new
	// one whenever any parameter changes (a token used once, even by a
	// request that failed, refuses other parameters).
	Token string
}

// createLoadBalancer creates an Internet-facing IPv4 Standard load balancer
// paid as you go, on the EIPs given (Fixed), and returns its id.
func (a *albClient) createLoadBalancer(ctx context.Context, s albLBSpec) (string, error) {
	req := alb.CreateCreateLoadBalancerRequest()
	a.route(req)
	req.LoadBalancerName = s.Name
	req.VpcId = s.VpcID
	req.AddressType = albAddressType
	req.AddressIpVersion = albAddressIPVersion
	req.AddressAllocatedMode = albAllocatedMode
	req.ResourceGroupId = s.ResourceGroup
	req.LoadBalancerEdition = albEdition
	req.LoadBalancerBillingConfig = alb.CreateLoadBalancerLoadBalancerBillingConfig{PayType: albPayType}
	zones := make([]alb.CreateLoadBalancerZoneMappings, 0, len(s.Zones))
	for _, z := range s.Zones {
		zones = append(zones, alb.CreateLoadBalancerZoneMappings{ZoneId: z.Zone, VSwitchId: z.VSwitchID, AllocationId: z.AllocationID})
	}
	req.ZoneMappings = &zones
	req.ClientToken = s.Token
	resp, err := a.cl.CreateLoadBalancer(req)
	if err != nil {
		return "", albCreateLBError(wrapErr("alb CreateLoadBalancer "+s.Name, err))
	}
	if resp.LoadBalancerId == "" {
		return "", fmt.Errorf("alb CreateLoadBalancer %s: the answer holds no LoadBalancerId", s.Name)
	}
	return resp.LoadBalancerId, nil
}

// albCreateLBError adds what to do to the known CreateLoadBalancer errors.
func albCreateLBError(err error) error {
	switch {
	case platform.HasErrorCode(err, errALBMultiISP):
		return fmt.Errorf("%w (the EIPs of a load balancer must share one ISP: set defaults.aliyun.eip.isp)", err)
	case platform.HasErrorCode(err, "ResourceAlreadyAssociated.Eip"):
		return fmt.Errorf("%w (an EIP is bound to something else already)", err)
	case platform.HasErrorCode(err, "BASIC_INFO_UNCOMPLETED", "OperationFailed.BasicInfoUncompleted"):
		return fmt.Errorf("%w (complete the account's basic information in the Alibaba Cloud console first)", err)
	}
	return err
}

// deleteLoadBalancer deletes a load balancer (its listeners go with it).
func (a *albClient) deleteLoadBalancer(ctx context.Context, id string) error {
	req := alb.CreateDeleteLoadBalancerRequest()
	a.route(req)
	req.LoadBalancerId = id
	req.ClientToken = clientToken()
	if _, err := a.cl.DeleteLoadBalancer(req); err != nil {
		err = wrapErr("alb DeleteLoadBalancer "+id, err)
		if platform.HasErrorCode(err, errALBDeletionProtection) {
			return fmt.Errorf("%w (deletion protection is on: switch it off in the console first; polyctl never does)", err)
		}
		return err
	}
	return nil
}

// renameLoadBalancer sets the name of a load balancer. The change is
// asynchronous: the load balancer is Configuring for a while after it.
func (a *albClient) renameLoadBalancer(ctx context.Context, id, name string) error {
	req := alb.CreateUpdateLoadBalancerAttributeRequest()
	a.route(req)
	req.LoadBalancerId = id
	req.LoadBalancerName = name
	req.ClientToken = clientToken()
	if _, err := a.cl.UpdateLoadBalancerAttribute(req); err != nil {
		return albLBWriteError(wrapErr("alb UpdateLoadBalancerAttribute "+id, err))
	}
	return nil
}

// setDeletionProtection switches the deletion protection of a load
// balancer on or off.
func (a *albClient) setDeletionProtection(ctx context.Context, id string, on bool) error {
	if on {
		req := alb.CreateEnableDeletionProtectionRequest()
		a.route(req)
		req.ResourceId = id
		req.ClientToken = clientToken()
		if _, err := a.cl.EnableDeletionProtection(req); err != nil {
			return albLBWriteError(wrapErr("alb EnableDeletionProtection "+id, err))
		}
		return nil
	}
	req := alb.CreateDisableDeletionProtectionRequest()
	a.route(req)
	req.ResourceId = id
	req.ClientToken = clientToken()
	if _, err := a.cl.DisableDeletionProtection(req); err != nil {
		return albLBWriteError(wrapErr("alb DisableDeletionProtection "+id, err))
	}
	return nil
}

// albLBWriteError adds what to do to the known load balancer write errors.
func albLBWriteError(err error) error {
	if platform.HasErrorCode(err, "IncorrectStatus.LoadBalancer") {
		return fmt.Errorf("%w (the load balancer is still changing; try again in a few seconds)", err)
	}
	return err
}

// describeZones returns the zones of the region that offer ALB, sorted.
func (a *albClient) describeZones(ctx context.Context) ([]string, error) {
	req := alb.CreateDescribeZonesRequest()
	a.route(req)
	resp, err := a.cl.DescribeZones(req)
	if err != nil {
		return nil, wrapErr("alb DescribeZones "+a.region, err)
	}
	var out []string
	for _, z := range resp.Zones {
		out = appendNew(out, z.ZoneId)
	}
	sort.Strings(out)
	return out, nil
}

// ------------------------------------------------------- server groups

// albServerGroup is a server group (a backend pool of ECS instances).
type albServerGroup struct {
	ID              string `json:"id" yaml:"id"`
	Name            string `json:"name" yaml:"name"`
	Protocol        string `json:"protocol" yaml:"protocol"`
	Type            string `json:"type" yaml:"type"`
	Status          string `json:"status" yaml:"status"`
	VpcID           string `json:"vpc_id" yaml:"vpc_id"`
	ResourceGroupID string `json:"resource_group_id" yaml:"resource_group_id"`
	ServerCount     int    `json:"server_count" yaml:"server_count"`
	HealthCheck     bool   `json:"health_check" yaml:"health_check"`
	// HealthCheckProtocol and HealthCheckPath are those of the health
	// check (empty when it is off).
	HealthCheckProtocol string `json:"health_check_protocol,omitempty" yaml:"health_check_protocol,omitempty"`
	HealthCheckPath     string `json:"health_check_path,omitempty" yaml:"health_check_path,omitempty"`
	// Scheduler is the balancing algorithm: Wrr, Wlc or Sch.
	Scheduler     string   `json:"scheduler" yaml:"scheduler"`
	StickySession bool     `json:"sticky_session" yaml:"sticky_session"`
	LoadBalancers []string `json:"load_balancers" yaml:"load_balancers"`
	Listeners     []string `json:"listeners" yaml:"listeners"`
	Region        string   `json:"region" yaml:"region"`
}

func albServerGroupFrom(g alb.ServerGroup, region string) albServerGroup {
	out := albServerGroup{ID: g.ServerGroupId, Name: g.ServerGroupName, Protocol: g.Protocol, Type: g.ServerGroupType, Status: g.ServerGroupStatus,
		VpcID: g.VpcId, ResourceGroupID: g.ResourceGroupId, ServerCount: g.ServerCount, HealthCheck: g.HealthCheckConfig.HealthCheckEnabled,
		Scheduler: g.Scheduler, StickySession: g.StickySessionConfig.StickySessionEnabled,
		LoadBalancers: append([]string{}, g.RelatedLoadBalancerIds...), Listeners: append([]string{}, g.RelatedListenerIds...), Region: region}
	if out.HealthCheck {
		out.HealthCheckProtocol, out.HealthCheckPath = g.HealthCheckConfig.HealthCheckProtocol, g.HealthCheckConfig.HealthCheckPath
	}
	return out
}

// listServerGroups lists the server groups of the region, those of the
// names or ids given when there are any, every page. Names are not
// unique: a name may answer several groups.
func (a *albClient) listServerGroups(ctx context.Context, names, ids []string) ([]albServerGroup, error) {
	var out []albServerGroup
	token := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := alb.CreateListServerGroupsRequest()
		a.route(req)
		req.MaxResults = requests.NewInteger(albPageSize)
		req.NextToken = token
		if len(names) > 0 {
			req.ServerGroupNames = &names
		}
		if len(ids) > 0 {
			req.ServerGroupIds = &ids
		}
		resp, err := a.cl.ListServerGroups(req)
		if err != nil {
			return nil, wrapErr("alb ListServerGroups "+a.region, err)
		}
		for _, g := range resp.ServerGroups {
			if (len(names) > 0 && !containsString(names, g.ServerGroupName)) || (len(ids) > 0 && !containsString(ids, g.ServerGroupId)) {
				continue
			}
			out = append(out, albServerGroupFrom(g, a.region))
		}
		if resp.NextToken == "" || resp.NextToken == token || len(resp.ServerGroups) == 0 {
			break
		}
		token = resp.NextToken
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// createServerGroup creates an Instance server group with its health check
// and session persistence off (both configurations are required: without
// them the API answers MissingHealthCheckConfig / MissingParam.StickySession)
// and returns its id.
func (a *albClient) createServerGroup(ctx context.Context, name, protocol, vpcID, resourceGroup string) (string, error) {
	req := alb.CreateCreateServerGroupRequest()
	a.route(req)
	req.ServerGroupName = name
	req.ServerGroupType = albServerGroupType
	req.Protocol = protocol
	req.VpcId = vpcID
	req.ResourceGroupId = resourceGroup
	req.HealthCheckConfig = alb.CreateServerGroupHealthCheckConfig{HealthCheckEnabled: "false"}
	req.StickySessionConfig = alb.CreateServerGroupStickySessionConfig{StickySessionEnabled: "false"}
	req.ClientToken = clientToken()
	resp, err := a.cl.CreateServerGroup(req)
	if err != nil {
		return "", wrapErr("alb CreateServerGroup "+name, err)
	}
	if resp.ServerGroupId == "" {
		return "", fmt.Errorf("alb CreateServerGroup %s: the answer holds no ServerGroupId", name)
	}
	return resp.ServerGroupId, nil
}

// deleteServerGroup deletes a server group; one a listener still forwards
// to is refused (ResourceInUse.ServerGroup).
func (a *albClient) deleteServerGroup(ctx context.Context, id string) error {
	req := alb.CreateDeleteServerGroupRequest()
	a.route(req)
	req.ServerGroupId = id
	req.ClientToken = clientToken()
	if _, err := a.cl.DeleteServerGroup(req); err != nil {
		err = wrapErr("alb DeleteServerGroup "+id, err)
		if platform.HasErrorCode(err, errALBServerGroupInUse) {
			return fmt.Errorf("%w (a listener still forwards to it; the listeners of a deleted load balancer linger for about a minute)", err)
		}
		return err
	}
	return nil
}

// albServerGroupUpdate is a change to a server group: the fields set
// (not "", not nil) are written, the others are left as they are.
type albServerGroupUpdate struct {
	Name      string
	Scheduler string
	// HealthCheck switches the health check on or off; HealthCheckPath
	// (with the health check on) sets its path.
	HealthCheck     *bool
	HealthCheckPath string
	// StickySession switches session persistence on (the load balancer
	// inserts the cookie) or off.
	StickySession *bool
}

// albStickyInsert is the session persistence of `--sticky-session`: the
// load balancer inserts the cookie (Server would need a cookie name).
const albStickyInsert = "Insert"

// updateServerGroup writes u to a server group. The change is
// asynchronous: the group is Configuring for a while after it.
func (a *albClient) updateServerGroup(ctx context.Context, id string, u albServerGroupUpdate) error {
	req := alb.CreateUpdateServerGroupAttributeRequest()
	a.route(req)
	req.ServerGroupId = id
	req.ServerGroupName = u.Name
	req.Scheduler = u.Scheduler
	if u.HealthCheck != nil {
		req.HealthCheckConfig = alb.UpdateServerGroupAttributeHealthCheckConfig{HealthCheckEnabled: strconv.FormatBool(*u.HealthCheck)}
		if *u.HealthCheck {
			req.HealthCheckConfig.HealthCheckPath = u.HealthCheckPath
		}
	}
	if u.StickySession != nil {
		req.StickySessionConfig = alb.UpdateServerGroupAttributeStickySessionConfig{StickySessionEnabled: strconv.FormatBool(*u.StickySession)}
		if *u.StickySession {
			req.StickySessionConfig.StickySessionType = albStickyInsert
		}
	}
	req.ClientToken = clientToken()
	if _, err := a.cl.UpdateServerGroupAttribute(req); err != nil {
		err = wrapErr("alb UpdateServerGroupAttribute "+id, err)
		if platform.HasErrorCode(err, "IncorrectStatus.ServerGroup") {
			return fmt.Errorf("%w (the server group is still changing; try again in a few seconds)", err)
		}
		return err
	}
	return nil
}

// albBackend is a server of a server group.
type albBackend struct {
	ServerID string `json:"server_id" yaml:"server_id"`
	Type     string `json:"type" yaml:"type"`
	Port     int    `json:"port" yaml:"port"`
	IP       string `json:"ip,omitempty" yaml:"ip,omitempty"`
	Weight   int    `json:"weight" yaml:"weight"`
	Status   string `json:"status" yaml:"status"`
}

// listServerGroupServers lists the servers of a server group, every page
// (an empty group answers no server field at all).
func (a *albClient) listServerGroupServers(ctx context.Context, groupID string) ([]albBackend, error) {
	out := []albBackend{}
	token := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := alb.CreateListServerGroupServersRequest()
		a.route(req)
		req.ServerGroupId = groupID
		req.MaxResults = requests.NewInteger(albPageSize)
		req.NextToken = token
		resp, err := a.cl.ListServerGroupServers(req)
		if err != nil {
			return nil, wrapErr("alb ListServerGroupServers "+groupID, err)
		}
		for _, s := range resp.Servers {
			out = append(out, albBackend{ServerID: s.ServerId, Type: s.ServerType, Port: s.Port, IP: s.ServerIp, Weight: s.Weight, Status: s.Status})
		}
		if resp.NextToken == "" || resp.NextToken == token || len(resp.Servers) == 0 {
			break
		}
		token = resp.NextToken
	}
	return out, nil
}

// addServer adds an ECS instance on port to a server group.
func (a *albClient) addServer(ctx context.Context, groupID, instanceID string, port int) error {
	req := alb.CreateAddServersToServerGroupRequest()
	a.route(req)
	req.ServerGroupId = groupID
	req.Servers = &[]alb.AddServersToServerGroupServers{{ServerId: instanceID, ServerType: albServerTypeECS, Port: strconv.Itoa(port)}}
	req.ClientToken = clientToken()
	if _, err := a.cl.AddServersToServerGroup(req); err != nil {
		err = wrapErr("alb AddServersToServerGroup "+groupID, err)
		if platform.HasErrorCode(err, errALBVpcMismatch) {
			return fmt.Errorf("%w (the instance and the server group are in different VPCs)", err)
		}
		return err
	}
	return nil
}

// ----------------------------------------------------------- listeners

// listListenersOf lists the listeners of a load balancer, of one protocol
// when protocol is not "".
func (a *albClient) listListenersOf(ctx context.Context, lbID, protocol string) ([]albListener, error) {
	var out []albListener
	token := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := alb.CreateListListenersRequest()
		a.route(req)
		req.LoadBalancerIds = &[]string{lbID}
		req.ListenerProtocol = protocol
		req.MaxResults = requests.NewInteger(albListenerPageSize)
		req.NextToken = token
		resp, err := a.cl.ListListeners(req)
		if err != nil {
			return nil, wrapErr("alb ListListeners "+lbID, err)
		}
		for _, l := range resp.Listeners {
			if l.LoadBalancerId != "" && l.LoadBalancerId != lbID {
				continue
			}
			if protocol != "" && !strings.EqualFold(l.ListenerProtocol, protocol) {
				continue
			}
			out = append(out, albListener{ID: l.ListenerId, LoadBalancerID: lbID, Protocol: l.ListenerProtocol, Port: l.ListenerPort,
				Status: l.ListenerStatus, ServerGroups: forwardGroups(l.DefaultActions), DefaultAction: firstAction(l.DefaultActions),
				Region: a.region})
		}
		if resp.NextToken == "" || resp.NextToken == token || len(resp.Listeners) == 0 {
			break
		}
		token = resp.NextToken
	}
	return out, nil
}

func forwardGroups(actions []alb.DefaultAction) []string {
	out := []string{}
	for _, a := range actions {
		for _, t := range a.ForwardGroupConfig.ServerGroupTuples {
			out = appendNew(out, t.ServerGroupId)
		}
	}
	return out
}

func firstAction(actions []alb.DefaultAction) string {
	if len(actions) == 0 {
		return ""
	}
	return actions[0].Type
}

// getListener reads a listener with its certificates; nil when it does
// not exist.
func (a *albClient) getListener(ctx context.Context, id string) (*albListener, error) {
	req := alb.CreateGetListenerAttributeRequest()
	a.route(req)
	req.ListenerId = id
	resp, err := a.cl.GetListenerAttribute(req)
	if err != nil {
		if platform.HasErrorCode(err, errALBListenerNotFound) {
			return nil, nil
		}
		return nil, wrapErr("alb GetListenerAttribute "+id, err)
	}
	if resp.ListenerId == "" {
		return nil, nil
	}
	l := albListener{ID: resp.ListenerId, LoadBalancerID: resp.LoadBalancerId, Protocol: resp.ListenerProtocol, Port: resp.ListenerPort,
		Status: resp.ListenerStatus, ServerGroups: forwardGroups(resp.DefaultActions), DefaultAction: firstAction(resp.DefaultActions),
		Certificates: []string{}, Region: a.region}
	for _, c := range resp.Certificates {
		l.Certificates = appendNew(l.Certificates, strings.TrimSpace(c.CertificateId))
	}
	return &l, nil
}

// createListener creates a listener forwarding to a server group, with
// the certificate certID (a listener certificate id; HTTPS only), and
// returns its id.
func (a *albClient) createListener(ctx context.Context, lbID, protocol string, port int, groupID, certID string) (string, error) {
	req := alb.CreateCreateListenerRequest()
	a.route(req)
	req.LoadBalancerId = lbID
	req.ListenerProtocol = protocol
	req.ListenerPort = requests.NewInteger(port)
	req.DefaultActions = &[]alb.CreateListenerDefaultActions{{Type: albForwardGroup,
		ForwardGroupConfig: alb.CreateListenerDefaultActionsForwardGroupConfig{
			ServerGroupTuples: &[]alb.CreateListenerDefaultActionsForwardGroupConfigServerGroupTuplesItem{{ServerGroupId: groupID}}}}}
	if certID != "" {
		req.Certificates = &[]alb.CreateListenerCertificates{{CertificateId: certID}}
	}
	req.ClientToken = clientToken()
	resp, err := a.cl.CreateListener(req)
	if err != nil {
		return "", albListenerError(wrapErr(fmt.Sprintf("alb CreateListener %s:%d on %s", protocol, port, lbID), err), certID)
	}
	if resp.ListenerId == "" {
		return "", fmt.Errorf("alb CreateListener %s:%d on %s: the answer holds no ListenerId", protocol, port, lbID)
	}
	return resp.ListenerId, nil
}

// updateListener replaces the default certificate (certID not "") and/or
// the server group the listener forwards to (groupID not "").
func (a *albClient) updateListener(ctx context.Context, id, certID, groupID string) error {
	req := alb.CreateUpdateListenerAttributeRequest()
	a.route(req)
	req.ListenerId = id
	if certID != "" {
		req.Certificates = &[]alb.UpdateListenerAttributeCertificates{{CertificateId: certID}}
	}
	if groupID != "" {
		req.DefaultActions = &[]alb.UpdateListenerAttributeDefaultActions{{Type: albForwardGroup,
			ForwardGroupConfig: alb.UpdateListenerAttributeDefaultActionsForwardGroupConfig{
				ServerGroupTuples: &[]alb.UpdateListenerAttributeDefaultActionsForwardGroupConfigServerGroupTuplesItem{{ServerGroupId: groupID}}}}}
	}
	req.ClientToken = clientToken()
	if _, err := a.cl.UpdateListenerAttribute(req); err != nil {
		return albListenerError(wrapErr("alb UpdateListenerAttribute "+id, err), certID)
	}
	return nil
}

// albListenerError adds what to do to the known listener write errors.
func albListenerError(err error, certID string) error {
	switch {
	case platform.HasErrorCode(err, "IncorrectStatus.Listener"):
		return fmt.Errorf("%w (the listener is still changing; try again in a few seconds)", err)
	case platform.HasErrorCode(err, "ResourceNotFound.Certificate"):
		return fmt.Errorf("%w (certificate %s: it has to be in the CAS store of the region, written <id>-<cas region> outside the central store)", err, certID)
	case platform.HasErrorCode(err, "ResourceAlreadyExist.Listener"):
		return fmt.Errorf("%w (the load balancer has a listener on that port already)", err)
	}
	return err
}

// deleteListener deletes a listener.
func (a *albClient) deleteListener(ctx context.Context, id string) error {
	req := alb.CreateDeleteListenerRequest()
	a.route(req)
	req.ListenerId = id
	req.ClientToken = clientToken()
	if _, err := a.cl.DeleteListener(req); err != nil {
		return wrapErr("alb DeleteListener "+id, err)
	}
	return nil
}

// ---------------------------------------------------------------- ACLs

// albACL is an access control list (an IP allow / deny list a listener
// may use).
type albACL struct {
	ID              string `json:"id" yaml:"id"`
	Name            string `json:"name" yaml:"name"`
	Status          string `json:"status" yaml:"status"`
	ResourceGroupID string `json:"resource_group_id" yaml:"resource_group_id"`
	IPVersion       string `json:"address_ip_version,omitempty" yaml:"address_ip_version,omitempty"`
	Region          string `json:"region" yaml:"region"`
}

// albACLEntry is one entry of an ACL: an IPv4 CIDR block.
type albACLEntry struct {
	Entry       string `json:"entry" yaml:"entry"`
	Description string `json:"description" yaml:"description"`
	Status      string `json:"status" yaml:"status"`
}

// listACLs lists the ACLs of the region, those of the names or ids given
// when there are any (names are exact and not unique), every page.
func (a *albClient) listACLs(ctx context.Context, names, ids []string) ([]albACL, error) {
	var out []albACL
	token := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := alb.CreateListAclsRequest()
		a.route(req)
		req.MaxResults = requests.NewInteger(albPageSize)
		req.NextToken = token
		if len(names) > 0 {
			req.AclNames = &names
		}
		if len(ids) > 0 {
			req.AclIds = &ids
		}
		resp, err := a.cl.ListAcls(req)
		if err != nil {
			return nil, wrapErr("alb ListAcls "+a.region, err)
		}
		for _, x := range resp.Acls {
			if (len(names) > 0 && !containsString(names, x.AclName)) || (len(ids) > 0 && !containsString(ids, x.AclId)) {
				continue
			}
			out = append(out, albACL{ID: x.AclId, Name: x.AclName, Status: x.AclStatus, ResourceGroupID: x.ResourceGroupId,
				IPVersion: x.AddressIPVersion, Region: a.region})
		}
		if resp.NextToken == "" || resp.NextToken == token || len(resp.Acls) == 0 {
			break
		}
		token = resp.NextToken
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// listACLEntries lists every entry of an ACL (the API returns the newest
// first).
func (a *albClient) listACLEntries(ctx context.Context, id string) ([]albACLEntry, error) {
	out := []albACLEntry{}
	token := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := alb.CreateListAclEntriesRequest()
		a.route(req)
		req.AclId = id
		req.MaxResults = requests.NewInteger(albACLEntriesPerPage)
		req.NextToken = token
		resp, err := a.cl.ListAclEntries(req)
		if err != nil {
			return nil, wrapErr("alb ListAclEntries "+id, err)
		}
		for _, e := range resp.AclEntries {
			out = append(out, albACLEntry{Entry: e.Entry, Description: e.Description, Status: e.Status})
		}
		if resp.NextToken == "" || resp.NextToken == token || len(resp.AclEntries) == 0 {
			break
		}
		token = resp.NextToken
	}
	return out, nil
}

// createACL creates an ACL and returns its id.
func (a *albClient) createACL(ctx context.Context, name, resourceGroup string) (string, error) {
	req := alb.CreateCreateAclRequest()
	a.route(req)
	req.AclName = name
	req.ResourceGroupId = resourceGroup
	req.ClientToken = clientToken()
	resp, err := a.cl.CreateAcl(req)
	if err != nil {
		return "", wrapErr("alb CreateAcl "+name, err)
	}
	if resp.AclId == "" {
		return "", fmt.Errorf("alb CreateAcl %s: the answer holds no AclId", name)
	}
	return resp.AclId, nil
}

// deleteACL deletes an ACL, its entries with it.
func (a *albClient) deleteACL(ctx context.Context, id string) error {
	req := alb.CreateDeleteAclRequest()
	a.route(req)
	req.AclId = id
	req.ClientToken = clientToken()
	if _, err := a.cl.DeleteAcl(req); err != nil {
		return wrapErr("alb DeleteAcl "+id, err)
	}
	return nil
}

// addACLEntries adds up to albACLEntryBatch entries in one call (the API
// refuses more, InvalidAclEntries). A batch is atomic: one entry that
// exists already fails the whole batch. An empty description is left out.
func (a *albClient) addACLEntries(ctx context.Context, id string, entries []albACLEntry) error {
	req := alb.CreateAddEntriesToAclRequest()
	a.route(req)
	req.AclId = id
	list := make([]alb.AddEntriesToAclAclEntries, 0, len(entries))
	for _, e := range entries {
		list = append(list, alb.AddEntriesToAclAclEntries{Entry: e.Entry, Description: e.Description})
	}
	req.AclEntries = &list
	req.ClientToken = clientToken()
	if _, err := a.cl.AddEntriesToAcl(req); err != nil {
		return albACLError(wrapErr("alb AddEntriesToAcl "+id, err))
	}
	return nil
}

// removeACLEntries removes entries, written as the ACL stores them.
func (a *albClient) removeACLEntries(ctx context.Context, id string, entries []string) error {
	req := alb.CreateRemoveEntriesFromAclRequest()
	a.route(req)
	req.AclId = id
	req.Entries = &entries
	req.ClientToken = clientToken()
	if _, err := a.cl.RemoveEntriesFromAcl(req); err != nil {
		return albACLError(wrapErr("alb RemoveEntriesFromAcl "+id, err))
	}
	return nil
}

// albACLError adds what to do to the known ACL write errors. A quota
// message quotes the account's real limit ("usage 504/500"): it is shown
// as it is, never with a limit written here.
func albACLError(err error) error {
	switch {
	case strings.HasPrefix(platform.ErrorCode(err), "ResourceQuotaExceeded."):
		return fmt.Errorf("%w (the ACL is full: the batch was refused as a whole; remove entries first)", err)
	case platform.HasErrorCode(err, "IncorrectStatus.Acl"):
		return fmt.Errorf("%w (the ACL is still changing; try again in a few seconds)", err)
	}
	return err
}
