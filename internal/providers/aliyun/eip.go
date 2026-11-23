package aliyun

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/resourcemanager"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"

	"github.com/gofika/polyctl/internal/platform"
)

// eipPageSize is the largest page DescribeEipAddresses accepts (101 or more
// is InvalidParameter).
const eipPageSize = 100

// endpointResourceManager is the ResourceManager API endpoint; resource
// groups belong to the account, not to a region.
const endpointResourceManager = "resourcemanager.aliyuncs.com"

// The settings of an EIP that polyctl allocates: pay by traffic, pay as
// you go, public network, paid automatically.
const (
	eipInternetChargeType = "PayByTraffic"
	eipInstanceChargeType = "PostPaid"
	eipNetmode            = "public"
	eipDefaultBandwidth   = "200"
	eipDefaultISP         = "BGP_PRO"
	defaultResourceGroup  = "default"
)

// EIP status values.
const (
	eipAvailable = "Available"
	eipInUse     = "InUse"
)

// Error codes of the EIP API.
const (
	errAllocationNotFound = "InvalidAllocationId.NotFound"
	errResourceGroupID    = "InvalidResourceGroupId"
	errInvalidComponent   = "COMMODITY.INVALID_COMPONENT"
)

// eipAddress is the inventory and output form of an elastic IP address.
type eipAddress struct {
	AllocationID       string `json:"allocation_id" yaml:"allocation_id"`
	IP                 string `json:"ip" yaml:"ip"`
	Status             string `json:"status" yaml:"status"`
	InstanceID         string `json:"instance_id" yaml:"instance_id"`
	InstanceType       string `json:"instance_type" yaml:"instance_type"`
	Name               string `json:"name" yaml:"name"`
	Description        string `json:"description" yaml:"description"`
	Bandwidth          string `json:"bandwidth" yaml:"bandwidth"`
	ISP                string `json:"isp" yaml:"isp"`
	ChargeType         string `json:"charge_type" yaml:"charge_type"`
	InternetChargeType string `json:"internet_charge_type" yaml:"internet_charge_type"`
	ServiceManaged     bool   `json:"service_managed" yaml:"service_managed"`
	ResourceGroupID    string `json:"resource_group_id" yaml:"resource_group_id"`
	Region             string `json:"region" yaml:"region"`
}

func eipFromSDK(e vpc.EipAddress, region string) eipAddress {
	desc := e.Description
	if desc == "" {
		// DescribeEipAddresses also returns the field misspelled
		// (Descritpion), with the same value; it is only a fallback.
		desc = e.Descritpion
	}
	r := e.RegionId
	if r == "" {
		r = region
	}
	return eipAddress{AllocationID: e.AllocationId, IP: e.IpAddress, Status: e.Status, InstanceID: e.InstanceId, InstanceType: e.InstanceType,
		Name: e.Name, Description: desc, Bandwidth: e.Bandwidth, ISP: e.ISP, ChargeType: e.ChargeType,
		InternetChargeType: e.InternetChargeType, ServiceManaged: e.ServiceManaged != 0, ResourceGroupID: e.ResourceGroupId, Region: r}
}

// resource is the inventory row of an EIP: named by its address, in its
// region.
//
// For find, an EIP bound to something is indexed as reserved: the instance
// or load balancer holding it is the match, and the EIP annotates it.
func (e eipAddress) resource() platform.Resource {
	var refs []platform.IPRef
	if r, ok := platform.IPAddr(platform.IPExternal, e.IP); ok {
		if e.bound() {
			r.Kind = platform.IPReserved
		}
		refs = append(refs, r)
	}
	return platform.Resource{Type: platform.ResEIP, ID: e.AllocationID, Name: e.IP, ParentID: e.Region, Data: e, IPs: refs}
}

// bound reports whether the EIP is bound to anything.
func (e eipAddress) bound() bool { return e.InstanceID != "" }

// idle reports whether the EIP may be reused: bound to nothing, Available,
// not managed by a cloud product (a load balancer keeps ServiceManaged at 1
// for up to a minute after it let the address go) and of the ISP asked for
// (a load balancer refuses EIPs of mixed ISPs).
func (e eipAddress) idle(isp string) bool {
	return e.InstanceID == "" && e.Status == eipAvailable && !e.ServiceManaged && (isp == "" || strings.EqualFold(e.ISP, isp))
}

// boundTo describes what the EIP is bound to ("-" for nothing).
func (e eipAddress) boundTo() string {
	if e.InstanceID == "" {
		return "-"
	}
	if e.InstanceType == "" {
		return e.InstanceID
	}
	return e.InstanceID + " (" + e.InstanceType + ")"
}

// pickIdleEIP returns the first idle EIP (in the order given) whose
// allocation id is not in exclude, or nil.
func pickIdleEIP(eips []eipAddress, isp string, exclude map[string]bool) *eipAddress {
	for i := range eips {
		if exclude[eips[i].AllocationID] {
			continue
		}
		if eips[i].idle(isp) {
			return &eips[i]
		}
	}
	return nil
}

// eipFilter narrows DescribeEipAddresses.
type eipFilter struct {
	AllocationID string
	IP           string
}

// listEIPs returns the EIPs of a region (every page), optionally only the
// one of an allocation id or address. They are sorted by allocation id, so
// that picking an idle one is deterministic.
func (c *client) listEIPs(ctx context.Context, region string, f eipFilter) ([]eipAddress, error) {
	region = c.regionOr(region)
	cl, err := c.vpcClient(ctx, region)
	if err != nil {
		return nil, err
	}
	var out []eipAddress
	seen := 0
	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := vpc.CreateDescribeEipAddressesRequest()
		c.route(req, vpcEndpoint(region))
		req.RegionId = region
		req.PageNumber = requests.NewInteger(page)
		req.PageSize = requests.NewInteger(eipPageSize)
		req.AllocationId = f.AllocationID
		req.EipAddress = f.IP
		resp, err := cl.DescribeEipAddresses(req)
		if err != nil {
			if f.AllocationID != "" && platform.HasErrorCode(err, errAllocationNotFound) {
				return nil, nil
			}
			return nil, wrapErr("vpc DescribeEipAddresses "+region, err)
		}
		for _, e := range resp.EipAddresses.EipAddress {
			seen++
			if (f.AllocationID != "" && e.AllocationId != f.AllocationID) || (f.IP != "" && e.IpAddress != f.IP) {
				continue
			}
			out = append(out, eipFromSDK(e, region))
		}
		// TotalCount decides: a total that is a multiple of the page size
		// asks for no extra empty page.
		if len(resp.EipAddresses.EipAddress) == 0 || seen >= resp.TotalCount {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AllocationID < out[j].AllocationID })
	return out, nil
}

// getEIP returns the EIP of an allocation id or address, nil when there is
// none (an unknown allocation id is an empty answer, not an error).
func (c *client) getEIP(ctx context.Context, region, ref string) (*eipAddress, error) {
	f := eipFilter{AllocationID: ref}
	if _, err := netip.ParseAddr(ref); err == nil {
		f = eipFilter{IP: ref}
	}
	found, err := c.listEIPs(ctx, region, f)
	if err != nil || len(found) == 0 {
		return nil, err
	}
	return &found[0], nil
}

// eipResources lists the EIPs of a region for the inventory.
func (c *client) eipResources(ctx context.Context, region string) ([]platform.Resource, error) {
	eips, err := c.listEIPs(ctx, region, eipFilter{})
	if err != nil {
		return nil, err
	}
	out := make([]platform.Resource, 0, len(eips))
	for _, e := range eips {
		out = append(out, e.resource())
	}
	return out, nil
}

// eipSpec is what an EIP is allocated with.
type eipSpec struct {
	Bandwidth     string
	ISP           string
	ResourceGroup string
}

// summary describes the spec in reports ("BGP_PRO 200Mbps PayByTraffic").
func (s eipSpec) summary() string {
	return fmt.Sprintf("%s %sMbps %s", s.ISP, s.Bandwidth, eipInternetChargeType)
}

// allocateEIP allocates an EIP and returns its allocation id and address.
func (c *client) allocateEIP(ctx context.Context, region string, s eipSpec) (id, ip string, err error) {
	region = c.regionOr(region)
	cl, err := c.vpcClient(ctx, region)
	if err != nil {
		return "", "", err
	}
	req := vpc.CreateAllocateEipAddressRequest()
	c.route(req, vpcEndpoint(region))
	req.RegionId = region
	req.Bandwidth = s.Bandwidth
	req.ISP = s.ISP
	req.InternetChargeType = eipInternetChargeType
	req.InstanceChargeType = eipInstanceChargeType
	req.Netmode = eipNetmode
	req.ResourceGroupId = s.ResourceGroup
	req.AutoPay = requests.NewBoolean(true)
	req.ClientToken = clientToken()
	resp, err := cl.AllocateEipAddress(req)
	if err != nil {
		return "", "", eipAllocateError(wrapErr("vpc AllocateEipAddress "+region, err), region, s)
	}
	if resp.AllocationId == "" {
		return "", "", fmt.Errorf("vpc AllocateEipAddress %s: the answer holds no AllocationId", region)
	}
	return resp.AllocationId, resp.EipAddress, nil
}

// eipAllocateError adds what to do to the AllocateEipAddress errors that
// are known. Which code a region that does not offer the ISP answers with
// is not verified: an invalid component, or a code that names the ISP, is
// reported as unsupported.
func eipAllocateError(err error, region string, s eipSpec) error {
	code := platform.ErrorCode(err)
	switch {
	case code == errResourceGroupID:
		return fmt.Errorf("%w: resource group %s (pass an existing one with --resource-group): %w", platform.ErrNotFound, s.ResourceGroup, err)
	case code == errInvalidComponent, strings.Contains(strings.ToUpper(code), "ISP"):
		return fmt.Errorf("%w: ISP %s is not offered in region %s, or is not a valid ISP (pass another with --isp): %w",
			platform.ErrNotSupported, s.ISP, region, err)
	}
	return err
}

// associateEIP binds an EIP to an ECS instance.
func (c *client) associateEIP(ctx context.Context, region, allocationID, instanceID string) error {
	region = c.regionOr(region)
	cl, err := c.vpcClient(ctx, region)
	if err != nil {
		return err
	}
	req := vpc.CreateAssociateEipAddressRequest()
	c.route(req, vpcEndpoint(region))
	req.RegionId = region
	req.AllocationId = allocationID
	req.InstanceId = instanceID
	req.InstanceType = "EcsInstance"
	req.ClientToken = clientToken()
	if _, err := cl.AssociateEipAddress(req); err != nil {
		return wrapErr("vpc AssociateEipAddress "+allocationID, err)
	}
	return nil
}

func (c *client) resourceManagerClient(ctx context.Context) (*resourcemanager.Client, error) {
	cl, err := resourcemanager.NewClientWithOptions(c.region, sdkConfig(), c.credential())
	if err != nil {
		return nil, err
	}
	cl.SetTransport(ctxTransport{ctx: ctx, base: c.transport})
	return cl, nil
}

// resourceGroupID returns the id of the resource group of that exact name;
// a name no group holds is not found.
func (c *client) resourceGroupID(ctx context.Context, name string) (string, error) {
	cl, err := c.resourceManagerClient(ctx)
	if err != nil {
		return "", err
	}
	req := resourcemanager.CreateListResourceGroupsRequest()
	c.route(req, endpointResourceManager)
	req.Name = name
	req.PageSize = requests.NewInteger(100)
	resp, err := cl.ListResourceGroups(req)
	if err != nil {
		return "", wrapErr("resourcemanager ListResourceGroups "+name, err)
	}
	for _, g := range resp.ResourceGroups.ResourceGroup {
		if g.Name == name && g.Id != "" {
			return g.Id, nil
		}
	}
	return "", fmt.Errorf("%w: resource group %q (pass an existing one with --resource-group, by name or rg- id)", platform.ErrNotFound, name)
}
