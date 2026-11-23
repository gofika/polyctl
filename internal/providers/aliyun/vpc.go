package aliyun

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"

	"github.com/gofika/polyctl/internal/platform"
)

// vpcPageSize is the largest page DescribeVpcs accepts.
const vpcPageSize = 50

// vpcInfo is a VPC as the security group commands need it.
type vpcInfo struct {
	ID        string `json:"id" yaml:"id"`
	Name      string `json:"name" yaml:"name"`
	CIDR      string `json:"cidr" yaml:"cidr"`
	Region    string `json:"region" yaml:"region"`
	IsDefault bool   `json:"is_default" yaml:"is_default"`
}

// vpcEndpoint is the VPC API endpoint of a region. The endpoint's region
// decides whose VPCs are returned, whatever RegionId says, so it always
// matches the region asked for.
func vpcEndpoint(region string) string { return "vpc." + region + ".aliyuncs.com" }

func (c *client) vpcClient(ctx context.Context, region string) (*vpc.Client, error) {
	cl, err := vpc.NewClientWithOptions(region, sdkConfig(), c.credential())
	if err != nil {
		return nil, err
	}
	cl.SetTransport(ctxTransport{ctx: ctx, base: c.transport})
	return cl, nil
}

// looksLikeVPCID reports whether ref names a VPC by id.
func looksLikeVPCID(ref string) bool { return strings.HasPrefix(ref, "vpc-") && len(ref) > 4 }

// findVPCs returns the VPCs of a region that ref names: the VPC of that id,
// or the VPCs of that exact name (names are not unique). None is not an
// error.
func (c *client) findVPCs(ctx context.Context, region, ref string) ([]vpcInfo, error) {
	region = c.regionOr(region)
	cl, err := c.vpcClient(ctx, region)
	if err != nil {
		return nil, err
	}
	byID := looksLikeVPCID(ref)
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
		if byID {
			req.VpcId = ref
		} else {
			req.VpcName = ref
		}
		resp, err := cl.DescribeVpcs(req)
		if err != nil {
			if byID && platform.HasErrorCode(err, "InvalidVpcId.NotFound") {
				return nil, nil
			}
			return nil, wrapErr("vpc DescribeVpcs "+region, err)
		}
		for _, v := range resp.Vpcs.Vpc {
			seen++
			// Whether VpcName is an exact match is not documented: the
			// name is compared here.
			if (byID && v.VpcId == ref) || (!byID && v.VpcName == ref) {
				out = append(out, vpcInfo{ID: v.VpcId, Name: v.VpcName, CIDR: v.CidrBlock, Region: region, IsDefault: v.IsDefault})
			}
		}
		if len(resp.Vpcs.Vpc) == 0 || seen >= resp.TotalCount {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// vpcLabel describes a VPC for messages ("vpc-1 (cn-hongkong-vpc)").
func (v vpcInfo) label() string {
	if v.Name == "" {
		return v.ID
	}
	return fmt.Sprintf("%s (%s)", v.ID, v.Name)
}
