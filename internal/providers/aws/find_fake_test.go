package aws

import (
	"context"
	"slices"
	"sort"
	"strconv"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

// fakeFind is the part of the fake account find reads: the enabled
// regions, addresses, network interfaces, subnets, load balancers and
// databases, per region.
type fakeFind struct {
	// regions are the enabled regions; nil means only the region asked.
	regions   []string
	addresses map[string][]ec2types.Address
	enis      map[string][]ec2types.NetworkInterface
	subnets   map[string]ec2types.Subnet
	// vpcs are the VPCs per region.
	vpcs map[string][]ec2types.Vpc
	lbs  map[string][]elbtypes.LoadBalancer
	dbs  map[string][]rdstypes.DBInstance
	// regionErr fails every call in a region.
	regionErr map[string]error
	// eniPage is the page length of DescribeNetworkInterfaces (0: all).
	eniPage  int
	eniCalls int
}

func (f *fakeEC2) findCall(call string) error {
	f.mu.Lock()
	f.record(call)
	f.mu.Unlock()
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	return f.shared.find.regionErr[f.region]
}

func (f *fakeEC2) DescribeRegions(_ context.Context, in *ec2.DescribeRegionsInput, _ ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	if err := f.findCall("DescribeRegions"); err != nil {
		return nil, err
	}
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	regions := f.shared.find.regions
	if regions == nil {
		regions = []string{f.region}
	}
	out := &ec2.DescribeRegionsOutput{}
	for _, r := range regions {
		out.Regions = append(out.Regions, ec2types.Region{RegionName: awssdk.String(r)})
	}
	return out, nil
}

func (f *fakeEC2) DescribeAddresses(_ context.Context, in *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	if err := f.findCall("DescribeAddresses"); err != nil {
		return nil, err
	}
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	return &ec2.DescribeAddressesOutput{Addresses: f.shared.find.addresses[f.region]}, nil
}

func (f *fakeEC2) DescribeNetworkInterfaces(_ context.Context, in *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	if err := f.findCall("DescribeNetworkInterfaces"); err != nil {
		return nil, err
	}
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	ff := &f.shared.find
	ff.eniCalls++
	var match []ec2types.NetworkInterface
	for _, e := range ff.enis[f.region] {
		ok := true
		for _, flt := range in.Filters {
			if awssdk.ToString(flt.Name) == "description" {
				hit := false
				for _, v := range flt.Values {
					prefix := strings.TrimSuffix(v, "*")
					hit = hit || strings.HasPrefix(awssdk.ToString(e.Description), prefix)
				}
				ok = ok && hit
			}
		}
		if ok {
			match = append(match, e)
		}
	}
	start := 0
	if in.NextToken != nil {
		start, _ = strconv.Atoi(*in.NextToken)
	}
	end := len(match)
	out := &ec2.DescribeNetworkInterfacesOutput{}
	if ff.eniPage > 0 && start+ff.eniPage < end {
		end = start + ff.eniPage
		out.NextToken = awssdk.String(strconv.Itoa(end))
	}
	out.NetworkInterfaces = match[start:end]
	return out, nil
}

func (f *fakeEC2) DescribeSubnets(_ context.Context, in *ec2.DescribeSubnetsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	if err := f.findCall("DescribeSubnets"); err != nil {
		return nil, err
	}
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	out := &ec2.DescribeSubnetsOutput{}
	if len(in.SubnetIds) == 0 {
		// A filtered listing of the region (state, vpc-id,
		// availability-zone), sorted by id; a subnet without a state is
		// available.
		var keys []string
		for k := range f.shared.find.subnets {
			if strings.HasPrefix(k, f.region+"/") {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			sn := f.shared.find.subnets[k]
			ok := true
			for _, flt := range in.Filters {
				var v string
				switch awssdk.ToString(flt.Name) {
				case "state":
					v = string(sn.State)
					if v == "" {
						v = "available"
					}
				case "vpc-id":
					v = awssdk.ToString(sn.VpcId)
				case "availability-zone":
					v = awssdk.ToString(sn.AvailabilityZone)
				default:
					return nil, &fakeAPIError{"InvalidParameterValue", "unknown filter " + awssdk.ToString(flt.Name)}
				}
				ok = ok && slices.Contains(flt.Values, v)
			}
			if ok {
				out.Subnets = append(out.Subnets, sn)
			}
		}
		return out, nil
	}
	for _, id := range in.SubnetIds {
		if sn, ok := f.shared.find.subnets[f.region+"/"+id]; ok {
			out.Subnets = append(out.Subnets, sn)
		}
	}
	if len(out.Subnets) == 0 {
		return nil, &fakeAPIError{"InvalidSubnetID.NotFound", "The subnet ID does not exist"}
	}
	return out, nil
}

// fakeELB serves the load balancers of a region.
type fakeELB struct {
	shared *fakeEC2s
	region string
}

// DescribeVpcs lists the VPCs of the region, filtered on state (a VPC
// without a state is available).
func (f *fakeEC2) DescribeVpcs(_ context.Context, in *ec2.DescribeVpcsInput, _ ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
	if err := f.findCall("DescribeVpcs"); err != nil {
		return nil, err
	}
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	out := &ec2.DescribeVpcsOutput{}
	for _, v := range f.shared.find.vpcs[f.region] {
		ok := len(in.VpcIds) == 0 || slices.Contains(in.VpcIds, awssdk.ToString(v.VpcId))
		for _, flt := range in.Filters {
			switch awssdk.ToString(flt.Name) {
			case "state":
				st := string(v.State)
				if st == "" {
					st = "available"
				}
				ok = ok && slices.Contains(flt.Values, st)
			default:
				return nil, &fakeAPIError{"InvalidParameterValue", "unknown filter " + awssdk.ToString(flt.Name)}
			}
		}
		if ok {
			out.Vpcs = append(out.Vpcs, v)
		}
	}
	return out, nil
}
