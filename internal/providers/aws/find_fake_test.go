package aws

import (
	"context"
	"strconv"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
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
	lbs       map[string][]elbtypes.LoadBalancer
	dbs       map[string][]rdstypes.DBInstance
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

// fakeELB and fakeRDS serve the load balancers and databases of a region.
type fakeELB struct {
	shared *fakeEC2s
	region string
}

type fakeRDS struct {
	shared *fakeEC2s
	region string
}

func (f *fakeRDS) DescribeDBInstances(_ context.Context, in *rds.DescribeDBInstancesInput, _ ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	if err := f.shared.find.regionErr[f.region]; err != nil {
		return nil, err
	}
	return &rds.DescribeDBInstancesOutput{DBInstances: f.shared.find.dbs[f.region]}, nil
}
