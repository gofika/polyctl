package aws

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/gofika/polyctl/internal/platform"
)

// typePreset is a preset instance type and its shape.
type typePreset struct {
	Name   string
	Cores  int
	MemMiB int
}

// t3Presets are the burstable x86_64 T3 types a size picks first when one
// has exactly that shape.
var t3Presets = []typePreset{
	{"t3.nano", 2, 512},
	{"t3.micro", 2, 1024},
	{"t3.small", 2, 2048},
	{"t3.medium", 2, 4096},
	{"t3.large", 2, 8192},
	{"t3.xlarge", 4, 16384},
	{"t3.2xlarge", 8, 32768},
}

// familyPreference is the order in which a size picks among the matching
// types when no T3 preset fits: these families first, then every other
// family; types of one rank go alphabetically.
var familyPreference = []string{"t3", "t3a", "m7i", "m6i", "c7i", "c6i", "r7i", "r6i", "m5", "c5", "r5"}

// offeringBatch is the number of instance types one
// DescribeInstanceTypeOfferings call filters on.
const offeringBatch = 50

// presetFor returns the T3 preset of exactly that shape, or "".
func presetFor(cores, memMiB int) string {
	for _, p := range t3Presets {
		if p.Cores == cores && p.MemMiB == memMiB {
			return p.Name
		}
	}
	return ""
}

// presetSizes lists the sizes of the T3 presets ("2H0.5G, 2H1G, ...").
func presetSizes() string {
	var out []string
	for _, p := range t3Presets {
		out = append(out, fmt.Sprintf("%dH%gG", p.Cores, float64(p.MemMiB)/1024))
	}
	return strings.Join(out, ", ")
}

// familyRank is the place of a type's family in familyPreference
// (len(familyPreference) for every other family).
func familyRank(typ string) int {
	fam, _, _ := strings.Cut(typ, ".")
	if i := slices.Index(familyPreference, fam); i >= 0 {
		return i
	}
	return len(familyPreference)
}

// sortByPreference orders types by family preference, then by name.
func sortByPreference(types []string) {
	sort.SliceStable(types, func(i, j int) bool {
		ri, rj := familyRank(types[i]), familyRank(types[j])
		if ri != rj {
			return ri < rj
		}
		return types[i] < types[j]
	})
}

// typeChoice is the instance type a size was resolved to.
type typeChoice struct {
	Size platform.TypeShorthand
	Type string
	// Location is the availability zone (or the region) that offers it.
	Location string
	Preset   bool
}

func (t typeChoice) kind() string {
	if t.Preset {
		return "T3 preset"
	}
	return "family preference"
}

// note is the line printed on stderr: "2H4G -> t3.medium (ap-east-1a, T3
// preset)".
func (t typeChoice) note() string {
	return fmt.Sprintf("%s -> %s (%s, %s)", t.Size, t.Type, t.Location, t.kind())
}

// label is what the change report adds to the type: "(2H4G)".
func (t typeChoice) label() string { return "(" + t.Size.String() + ")" }

// attrs are the json / yaml attrs of a change that uses the type.
func (t typeChoice) attrs() map[string]string {
	return map[string]string{"instance_type": t.Type, "size": t.Size.String()}
}

// typeShape returns the default vCPUs and the memory in MiB of an instance
// type. An unknown type is a usage error.
func (c *client) typeShape(ctx context.Context, region, typ string) (int, int, error) {
	region = c.regionOr(region)
	out, err := c.ec2For(region).DescribeInstanceTypes(ctx, &ec2.DescribeInstanceTypesInput{InstanceTypes: []ec2types.InstanceType{ec2types.InstanceType(typ)}})
	if err != nil {
		if platform.HasErrorCode(err, "InvalidInstanceType") {
			return 0, 0, fmt.Errorf("%w: unknown instance type %q in %s", platform.ErrInvalidInput, typ, region)
		}
		return 0, 0, ec2Err("DescribeInstanceTypes", region, err)
	}
	for _, it := range out.InstanceTypes {
		if string(it.InstanceType) == typ {
			cores, mem := shapeOf(it)
			return cores, mem, nil
		}
	}
	return 0, 0, fmt.Errorf("%w: unknown instance type %q in %s", platform.ErrInvalidInput, typ, region)
}

// shapeOf returns the default vCPUs and the memory in MiB of a type.
func shapeOf(it ec2types.InstanceTypeInfo) (int, int) {
	cores, mem := 0, 0
	if it.VCpuInfo != nil {
		cores = int(awssdk.ToInt32(it.VCpuInfo.DefaultVCpus))
	}
	if it.MemoryInfo != nil {
		mem = int(awssdk.ToInt64(it.MemoryInfo.SizeInMiB))
	}
	return cores, mem
}

// typesOfSize lists the current-generation x86_64 instance types of
// exactly the size's default vCPUs and memory (every page).
func (c *client) typesOfSize(ctx context.Context, region string, s platform.TypeShorthand) ([]string, error) {
	region = c.regionOr(region)
	mem := s.MemoryMiB()
	pg := ec2.NewDescribeInstanceTypesPaginator(c.ec2For(region), &ec2.DescribeInstanceTypesInput{Filters: []ec2types.Filter{
		{Name: awssdk.String("vcpu-info.default-vcpus"), Values: []string{fmt.Sprint(s.Cores)}},
		{Name: awssdk.String("memory-info.size-in-mib"), Values: []string{fmt.Sprint(mem)}},
		{Name: awssdk.String("processor-info.supported-architecture"), Values: []string{"x86_64"}},
		{Name: awssdk.String("current-generation"), Values: []string{"true"}},
	}})
	var out []string
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, ec2Err("DescribeInstanceTypes", region, err)
		}
		for _, it := range page.InstanceTypes {
			cores, m := shapeOf(it)
			if !s.Matches(cores, m) || !awssdk.ToBool(it.CurrentGeneration) || it.ProcessorInfo == nil ||
				!slices.Contains(it.ProcessorInfo.SupportedArchitectures, ec2types.ArchitectureTypeX8664) {
				continue
			}
			if t := string(it.InstanceType); !slices.Contains(out, t) {
				out = append(out, t)
			}
		}
	}
	return out, nil
}

// offeredIn returns those of types that are offered in the availability
// zone az, or anywhere in the region when az is "", asking for
// offeringBatch types per call.
func (c *client) offeredIn(ctx context.Context, region, az string, types []string) (map[string]bool, error) {
	region = c.regionOr(region)
	lt, loc := ec2types.LocationTypeAvailabilityZone, az
	if az == "" {
		lt, loc = ec2types.LocationTypeRegion, region
	}
	out := map[string]bool{}
	for start := 0; start < len(types); start += offeringBatch {
		batch := types[start:min(start+offeringBatch, len(types))]
		pg := ec2.NewDescribeInstanceTypeOfferingsPaginator(c.ec2For(region), &ec2.DescribeInstanceTypeOfferingsInput{
			LocationType: lt,
			Filters: []ec2types.Filter{
				{Name: awssdk.String("location"), Values: []string{loc}},
				{Name: awssdk.String("instance-type"), Values: batch},
			},
		})
		for pg.HasMorePages() {
			page, err := pg.NextPage(ctx)
			if err != nil {
				return nil, ec2Err("DescribeInstanceTypeOfferings", region, err)
			}
			for _, o := range page.InstanceTypeOfferings {
				if awssdk.ToString(o.Location) == loc && slices.Contains(batch, string(o.InstanceType)) {
					out[string(o.InstanceType)] = true
				}
			}
		}
	}
	return out, nil
}

// subnetAZ returns the availability zone of a subnet.
func (c *client) subnetAZ(ctx context.Context, region, subnet string) (string, error) {
	region = c.regionOr(region)
	out, err := c.ec2For(region).DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{SubnetIds: []string{subnet}})
	if err != nil {
		return "", ec2Err("DescribeSubnets", region, err)
	}
	for _, sn := range out.Subnets {
		if awssdk.ToString(sn.SubnetId) == subnet {
			return awssdk.ToString(sn.AvailabilityZone), nil
		}
	}
	return "", fmt.Errorf("%w: subnet %s in %s", platform.ErrNotFound, subnet, region)
}

// resolveTypeSize resolves a <cores>H<memory>G size to an instance type
// offered in the availability zone az (the region when az is ""). It is
// read-only and runs on every call, in a dry run too: the T3 preset of
// exactly that shape when it is offered there, else the current-generation
// x86_64 type of exactly that shape offered there that comes first by
// familyPreference. No such type is ErrNotFound (exit code 4).
func (c *client) resolveTypeSize(ctx context.Context, region, az string, s platform.TypeShorthand) (typeChoice, error) {
	region = c.regionOr(region)
	where := az
	if where == "" {
		where = region
	}
	if p := presetFor(s.Cores, s.MemoryMiB()); p != "" {
		offered, err := c.offeredIn(ctx, region, az, []string{p})
		if err != nil {
			return typeChoice{}, err
		}
		if offered[p] {
			return typeChoice{Size: s, Type: p, Location: where, Preset: true}, nil
		}
	}
	types, err := c.typesOfSize(ctx, region, s)
	if err != nil {
		return typeChoice{}, err
	}
	if len(types) == 0 {
		return typeChoice{}, fmt.Errorf("%w: no current-generation x86_64 instance type has %d vCPUs and %s GiB (%s) in %s: "+
			"pass an exact instance type with --type, or another size (the T3 presets are %s)",
			platform.ErrNotFound, s.Cores, s.Memory(), s, region, presetSizes())
	}
	offered, err := c.offeredIn(ctx, region, az, types)
	if err != nil {
		return typeChoice{}, err
	}
	var avail []string
	for _, t := range types {
		if offered[t] {
			avail = append(avail, t)
		}
	}
	if len(avail) == 0 {
		sortByPreference(types)
		shown := types
		if len(shown) > 5 {
			shown = append(slices.Clone(shown[:5]), "...")
		}
		return typeChoice{}, fmt.Errorf("%w: no instance type of %s (%s) is offered in %s: "+
			"pass an exact instance type with --type, or another size",
			platform.ErrNotFound, s, strings.Join(shown, ", "), where)
	}
	sortByPreference(avail)
	return typeChoice{Size: s, Type: avail[0], Location: where}, nil
}
