package aliyun

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"

	"github.com/gofika/polyctl/internal/platform"
)

// vpcPageSize is the largest page DescribeVpcs and DescribeVSwitches accept
// (51 or more is InvalidParameter).
const vpcPageSize = 50

// Status values of VPCs and vSwitches.
const (
	statusAvailable = "Available"
	statusPending   = "Pending"
)

// Error codes of the VPC API (verified on real accounts).
const (
	errVpcStatus      = "IncorrectVpcStatus"
	errCidrOverlapped = "InvalidCidrBlock.Overlapped"
	errCidrAlignment  = "IllegalParam.CidrBlock"
	errInvalidParam   = "InvalidParameter"
	errZoneNotOffered = "ResourceNotAvailable"
	errVSwitchID      = "IncorrectVSwitchId"
)

// vpcInfo is the output form of a VPC.
type vpcInfo struct {
	ID        string `json:"id" yaml:"id"`
	Name      string `json:"name" yaml:"name"`
	CIDR      string `json:"cidr" yaml:"cidr"`
	Region    string `json:"region" yaml:"region"`
	IsDefault bool   `json:"is_default" yaml:"is_default"`
	Status    string `json:"status,omitempty" yaml:"status,omitempty"`
}

// vSwitch is the output form of a vSwitch.
type vSwitch struct {
	ID           string `json:"id" yaml:"id"`
	Name         string `json:"name" yaml:"name"`
	VPC          string `json:"vpc_id" yaml:"vpc_id"`
	Zone         string `json:"zone" yaml:"zone"`
	CIDR         string `json:"cidr" yaml:"cidr"`
	Status       string `json:"status" yaml:"status"`
	AvailableIPs int64  `json:"available_ips" yaml:"available_ips"`
	Region       string `json:"region" yaml:"region"`
	IPv6CIDR     string `json:"ipv6_cidr,omitempty" yaml:"ipv6_cidr,omitempty"`
}

// vpcEndpoint is the VPC API endpoint of a region. The endpoint's region
// decides whose VPCs are returned, whatever RegionId says, so it always
// matches the region asked for.
func vpcEndpoint(region string) string { return "vpc." + region + ".aliyuncs.com" }

func (c *client) vpcClient(ctx context.Context, region string) (*vpc.Client, error) {
	cl, err := vpc.NewClientWithOptions(region, sdkConfig(ctx), c.credential())
	if err != nil {
		return nil, err
	}
	cl.SetTransport(ctxTransport{ctx: ctx, base: c.transport})
	return cl, nil
}

// clientToken returns a fresh idempotency token: the SDK retries a request
// that timed out, and the token makes the platform answer the retry with
// the resource the first attempt created instead of creating a second one.
func clientToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// looksLikeVPCID reports whether ref names a VPC by id.
func looksLikeVPCID(ref string) bool { return strings.HasPrefix(ref, "vpc-") && len(ref) > 4 }

// looksLikeVSwitchID reports whether ref names a vSwitch by id.
func looksLikeVSwitchID(ref string) bool { return strings.HasPrefix(ref, "vsw-") && len(ref) > 4 }

func vpcFromSDK(v vpc.Vpc, region string) vpcInfo {
	return vpcInfo{ID: v.VpcId, Name: v.VpcName, CIDR: v.CidrBlock, Region: region, IsDefault: v.IsDefault, Status: v.Status}
}

// describeVPCs pages through DescribeVpcs with the filters set by filter
// and returns the VPCs keep accepts.
func (c *client) describeVPCs(ctx context.Context, region string, filter func(*vpc.DescribeVpcsRequest), keep func(vpc.Vpc) bool) ([]vpcInfo, error) {
	region = c.regionOr(region)
	cl, err := c.vpcClient(ctx, region)
	if err != nil {
		return nil, err
	}
	var out []vpcInfo
	seen := 0
	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := vpc.CreateDescribeVpcsRequest()
		c.route(req, vpcEndpoint(region))
		req.RegionId = region
		req.PageNumber = requests.NewInteger(page)
		req.PageSize = requests.NewInteger(vpcPageSize)
		filter(req)
		resp, err := cl.DescribeVpcs(req)
		if err != nil {
			if req.VpcId != "" && platform.HasErrorCode(err, "InvalidVpcId.NotFound") {
				return nil, nil
			}
			return nil, wrapErr("vpc DescribeVpcs "+region, err)
		}
		for _, v := range resp.Vpcs.Vpc {
			seen++
			if keep(v) {
				out = append(out, vpcFromSDK(v, region))
			}
		}
		if len(resp.Vpcs.Vpc) == 0 || seen >= resp.TotalCount {
			break
		}
	}
	return out, nil
}

// findVPCs returns the VPCs of a region that ref names: the VPC of that id,
// or the VPCs of that exact name (names are not unique). None is not an
// error.
func (c *client) findVPCs(ctx context.Context, region, ref string) ([]vpcInfo, error) {
	byID := looksLikeVPCID(ref)
	out, err := c.describeVPCs(ctx, region, func(req *vpc.DescribeVpcsRequest) {
		if byID {
			req.VpcId = ref
		} else {
			req.VpcName = ref
		}
	}, func(v vpc.Vpc) bool {
		// VpcName is an exact match (verified); the name is compared here
		// all the same.
		return (byID && v.VpcId == ref) || (!byID && v.VpcName == ref)
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// listVPCs returns the VPCs of a region, sorted by name then id. The
// default VPC is left out unless all is set.
func (c *client) listVPCs(ctx context.Context, region string, all bool) ([]vpcInfo, error) {
	out, err := c.describeVPCs(ctx, region, func(req *vpc.DescribeVpcsRequest) {
		if !all {
			req.IsDefault = requests.NewBoolean(false)
		}
	}, func(v vpc.Vpc) bool { return all || !v.IsDefault })
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// vpcStatus returns the status of the VPC of that id, looked up by id
// (names are not unique).
func (c *client) vpcStatus(ctx context.Context, region, id string) (string, error) {
	found, err := c.findVPCs(ctx, region, id)
	if err != nil {
		return "", err
	}
	if len(found) == 0 {
		return "", fmt.Errorf("%w: VPC %s in %s", platform.ErrNotFound, id, c.regionOr(region))
	}
	return found[0].Status, nil
}

// createVPC creates a VPC and returns its id.
func (c *client) createVPC(ctx context.Context, region, name, cidr string) (string, error) {
	region = c.regionOr(region)
	cl, err := c.vpcClient(ctx, region)
	if err != nil {
		return "", err
	}
	req := vpc.CreateCreateVpcRequest()
	c.route(req, vpcEndpoint(region))
	req.RegionId = region
	req.VpcName = name
	req.CidrBlock = cidr
	req.ClientToken = clientToken()
	resp, err := cl.CreateVpc(req)
	if err != nil {
		return "", wrapErr("vpc CreateVpc "+name, err)
	}
	if resp.VpcId == "" {
		return "", fmt.Errorf("vpc CreateVpc %s: the answer holds no VpcId", name)
	}
	return resp.VpcId, nil
}

func vSwitchFromSDK(v vpc.VSwitch, region string) vSwitch {
	return vSwitch{ID: v.VSwitchId, Name: v.VSwitchName, VPC: v.VpcId, Zone: v.ZoneId, CIDR: v.CidrBlock, Status: v.Status,
		AvailableIPs: v.AvailableIpAddressCount, Region: region, IPv6CIDR: v.Ipv6CidrBlock}
}

// listVSwitches returns the vSwitches of a region, of one VPC when vpcID is
// not "", of one exact name when name is not "", the vSwitch of that id
// when id is not "". Names are unique neither in a region nor in a VPC.
func (c *client) listVSwitches(ctx context.Context, region, vpcID, name, id string) ([]vSwitch, error) {
	region = c.regionOr(region)
	cl, err := c.vpcClient(ctx, region)
	if err != nil {
		return nil, err
	}
	var out []vSwitch
	seen := 0
	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := vpc.CreateDescribeVSwitchesRequest()
		c.route(req, vpcEndpoint(region))
		req.RegionId = region
		req.PageNumber = requests.NewInteger(page)
		req.PageSize = requests.NewInteger(vpcPageSize)
		req.VpcId = vpcID
		req.VSwitchName = name
		req.VSwitchId = id
		resp, err := cl.DescribeVSwitches(req)
		if err != nil {
			if id != "" && platform.HasErrorCode(err, errVSwitchID, "InvalidVSwitchId.NotFound") {
				return nil, nil
			}
			return nil, wrapErr("vpc DescribeVSwitches "+region, err)
		}
		for _, v := range resp.VSwitches.VSwitch {
			seen++
			// The filters are compared here too: a vSwitch of another VPC
			// must never pass for one of this VPC.
			if (vpcID != "" && v.VpcId != vpcID) || (name != "" && v.VSwitchName != name) || (id != "" && v.VSwitchId != id) {
				continue
			}
			out = append(out, vSwitchFromSDK(v, region))
		}
		if len(resp.VSwitches.VSwitch) == 0 || seen >= resp.TotalCount {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].Zone != out[j].Zone {
			return out[i].Zone < out[j].Zone
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// vSwitchStatus returns the status of a vSwitch (DescribeVSwitchAttributes).
func (c *client) vSwitchStatus(ctx context.Context, region, id string) (string, error) {
	region = c.regionOr(region)
	cl, err := c.vpcClient(ctx, region)
	if err != nil {
		return "", err
	}
	req := vpc.CreateDescribeVSwitchAttributesRequest()
	c.route(req, vpcEndpoint(region))
	req.RegionId = region
	req.VSwitchId = id
	resp, err := cl.DescribeVSwitchAttributes(req)
	if err != nil {
		return "", wrapErr("vpc DescribeVSwitchAttributes "+id, err)
	}
	return resp.Status, nil
}

// createVSwitch creates a vSwitch and returns its id. CreateVSwitch takes
// RegionId too; the region endpoint is what decides.
func (c *client) createVSwitch(ctx context.Context, region, vpcID, zone, name, cidr string) (string, error) {
	region = c.regionOr(region)
	cl, err := c.vpcClient(ctx, region)
	if err != nil {
		return "", err
	}
	req := vpc.CreateCreateVSwitchRequest()
	c.route(req, vpcEndpoint(region))
	req.RegionId = region
	req.VpcId = vpcID
	req.ZoneId = zone
	req.VSwitchName = name
	req.CidrBlock = cidr
	req.ClientToken = clientToken()
	resp, err := cl.CreateVSwitch(req)
	if err != nil {
		return "", vSwitchCreateError(wrapErr("vpc CreateVSwitch "+name, err), region, zone, cidr)
	}
	if resp.VSwitchId == "" {
		return "", fmt.Errorf("vpc CreateVSwitch %s: the answer holds no VSwitchId", name)
	}
	return resp.VSwitchId, nil
}

// vSwitchCreateError adds what to do to the CreateVSwitch errors that are
// known (matched by code, never by message).
func vSwitchCreateError(err error, region, zone, cidr string) error {
	switch {
	case platform.HasErrorCode(err, errCidrOverlapped):
		return fmt.Errorf("%w (%s overlaps a vSwitch of the VPC; pass another --cidr)", err, cidr)
	case platform.HasErrorCode(err, errCidrAlignment):
		return fmt.Errorf("%w (%s is not aligned to its mask)", err, cidr)
	case platform.HasErrorCode(err, errInvalidParam) && strings.Contains(strings.ToLower(err.Error()), "cidr"):
		return fmt.Errorf("%w (%s is not inside the CIDR block of the VPC)", err, cidr)
	case platform.HasErrorCode(err, errZoneNotOffered):
		return fmt.Errorf("%w: zone %s is not available in region %s; pass the zones of the region with --zones (or --zone): %w",
			platform.ErrNotSupported, zone, region, err)
	case platform.HasErrorCode(err, errVpcStatus):
		return fmt.Errorf("%w (the VPC is not Available yet; run the command again in a few seconds)", err)
	}
	return err
}

// errNoCIDRSpace is returned by allocateCIDR when the base block has no
// room left for the blocks asked for.
var errNoCIDRSpace = errors.New("no free CIDR block left")

// allocateCIDR returns n blocks of size /mask inside base that overlap
// none of existing nor each other: the base block is scanned from its
// start, block by block, and the first free ones are taken. The result is
// deterministic, so a dry run shows the blocks a real run creates.
func allocateCIDR(existing []string, base string, mask int, n int) ([]string, error) {
	bp, err := netip.ParsePrefix(base)
	if err != nil || !bp.Addr().Is4() {
		return nil, fmt.Errorf("%w: %q is not an IPv4 CIDR block", platform.ErrInvalidInput, base)
	}
	bp = bp.Masked()
	if mask < bp.Bits() || mask > 32 {
		return nil, fmt.Errorf("%w: a /%d block does not fit in %s", platform.ErrInvalidInput, mask, bp)
	}
	var used []netip.Prefix
	for _, e := range existing {
		p, err := netip.ParsePrefix(strings.TrimSpace(e))
		if err != nil || !p.Addr().Is4() {
			continue
		}
		used = append(used, p.Masked())
	}
	size := uint64(1) << (32 - mask)
	start := uint64(ipv4Uint(bp.Addr()))
	end := start + (uint64(1) << (32 - bp.Bits()))
	var out []string
	for a := start; a+size <= end && len(out) < n; a += size {
		cand := netip.PrefixFrom(uint32IPv4(uint32(a)), mask)
		free := true
		for _, u := range used {
			if u.Overlaps(cand) {
				free = false
				break
			}
		}
		if free {
			out = append(out, cand.String())
			used = append(used, cand)
		}
	}
	if len(out) < n {
		return out, fmt.Errorf("%w: %s holds %d free /%d block(s), %d needed", errNoCIDRSpace, bp, len(out), mask, n)
	}
	return out, nil
}

func ipv4Uint(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uint32IPv4(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// vpcLabel describes a VPC for messages ("vpc-1 (cn-hongkong-vpc)").
func (v vpcInfo) label() string {
	if v.Name == "" {
		return v.ID
	}
	return fmt.Sprintf("%s (%s)", v.ID, v.Name)
}
