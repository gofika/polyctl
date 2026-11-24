package aws

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// The interactive picks of the aws commands: what a resource is (name, id)
// and the facts that tell candidates apart (zone, state, type, CIDR,
// account). Every list holds only usable candidates; see README
// "Interactive and non-interactive use".

// joinLabel joins the non-empty parts of a label with two spaces.
func joinLabel(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "  ")
}

// nameOr returns name, else id.
func nameOr(name, id string) string {
	if name != "" {
		return name
	}
	return id
}

// instanceOptionLabel: "web-01  i-0abc  running  t3.medium  ap-east-1a
// 10.0.1.23  198.51.100.7  aws/lab".
func instanceOptionLabel(in instanceInfo, profile string) string {
	return joinLabel(nameOr(in.Name, in.ID), in.ID, in.State, in.Type, in.AZ, in.PrivateIP, in.PublicIP, "aws/"+profile)
}

// instanceInfoOf decodes an inventory row of an instance; the region falls
// back to the row's parent.
func instanceInfoOf(r inventory.Resource) instanceInfo {
	var in instanceInfo
	_ = r.Decode(&in)
	if in.ID == "" {
		in.ID = r.ID
	}
	if in.Name == "" && r.Name != r.ID {
		in.Name = r.Name
	}
	if in.Region == "" {
		in.Region = r.ParentID
	}
	return in
}

// statesIn keeps the instances in one of the states.
func statesIn(states ...string) func(instanceInfo) bool {
	return func(in instanceInfo) bool { return slices.Contains(states, in.State) }
}

// notTerminated keeps every instance that still exists.
func notTerminated(in instanceInfo) bool {
	return in.State != stateTerminated && in.State != stateShuttingDown
}

// pickInstanceRef asks for an instance of the selected AWS accounts in the
// interactive flow, from the inventory (synced first when stale, never
// with --offline): those in region when it is given, those keep accepts.
// The value is the instance id, which resolveInstance finds again. what
// names the candidates of an empty list ("stopped AWS instance"); arg is
// the input for messages ("<name|id>", "--instance"). required turns an
// empty list into a usage error naming arg (an input a command cannot do
// without) instead of "nothing to do".
func pickInstanceRef(ctx context.Context, rt *app.Runtime, arg, region, what string, required bool, keep func(instanceInfo) bool) (string, error) {
	return rt.PickResource(ctx, app.ResourcePick{Platform: platform.AWS, Kind: platform.ResInstance,
		Title: "Instance", Arg: arg, What: what, Required: required,
		Filter: func(r inventory.Resource) bool {
			in := instanceInfoOf(r)
			if region != "" && in.Region != region {
				return false
			}
			return keep == nil || keep(in)
		},
		Label: func(r inventory.Resource) string { return instanceOptionLabel(instanceInfoOf(r), r.Profile) }})
}

// instanceArg fills in a missing <name|id> of an instance command in the
// interactive flow with pickInstanceRef; with the argument given, args is
// returned as it is.
func instanceArg(ctx context.Context, rt *app.Runtime, args []string, region, what string, keep func(instanceInfo) bool) ([]string, error) {
	if len(args) > 0 {
		return args, nil
	}
	id, err := pickInstanceRef(ctx, rt, "<name|id>", region, what, false, keep)
	if err != nil {
		return nil, err
	}
	return []string{id}, nil
}

// disambiguate turns an ambiguous lookup into a pick in the interactive
// flow: amb gets one option per candidate (value: its index, label: label
// of it) and the index chosen is returned. The non-interactive flow gets
// amb back (exit code 5).
func disambiguate[T any](rt *app.Runtime, amb *app.AmbiguousError, found []T, label func(T) string) (T, error) {
	var zero T
	for i, f := range found {
		amb.Options = append(amb.Options, prompt.Option{Label: label(f), Value: strconv.Itoa(i)})
	}
	v, err := rt.Disambiguate(amb)
	if err != nil {
		return zero, err
	}
	i, err := strconv.Atoi(v)
	if err != nil || i < 0 || i >= len(found) {
		return zero, fmt.Errorf("unexpected choice %q", v)
	}
	return found[i], nil
}

// locatedLabel shows a live instance found by a lookup: "web-01  i-0abc
// running  t3.medium  ap-east-1a  aws/lab/ap-east-1".
func locatedLabel(l *locatedInstance) string {
	az := ""
	if l.inst.Placement != nil {
		az = awssdk.ToString(l.inst.Placement.AvailabilityZone)
	}
	return joinLabel(l.name(), l.id(), instanceState(l.inst), string(l.inst.InstanceType), az,
		awssdk.ToString(l.inst.PrivateIpAddress), awssdk.ToString(l.inst.PublicIpAddress), "aws/"+l.profile+"/"+l.region)
}

// defaultPickSize is the size preselected by the type pick.
const defaultPickSize = "2H4G"

// otherValue is the value of the "Other ..." option of a pick.
const otherValue = "\x00other"

// pickInstanceType asks for the --type of create and resize in the
// interactive flow: the sizes of the T3 presets (x86_64, current
// generation) offered in the availability zone az (the region when az is
// ""), each with its type and shape, current (the type of the instance a
// resize changes) left out, 2H4G preselected; then "Other size or
// type...", a size <cores>H<memory>G or an exact type, checked as typed.
// The value is a size or a type, resolved as --type is. x86 false (an
// arm64 instance) asks for an exact type only: no arm64 type is ever
// proposed. The non-interactive flow returns the usage error "--type is
// required".
func pickInstanceType(ctx context.Context, rt *app.Runtime, c *client, region, az, current string, x86 bool) (string, error) {
	if !rt.Interactive() {
		return "", app.UsageErrf("--type is required")
	}
	var opts []prompt.Option
	if x86 {
		names := make([]string, 0, len(t3Presets))
		for _, p := range t3Presets {
			names = append(names, p.Name)
		}
		offered, err := c.offeredIn(ctx, region, az, names)
		if err != nil {
			return "", err
		}
		for _, p := range t3Presets {
			if !offered[p.Name] || p.Name == current {
				continue
			}
			gib := strconv.FormatFloat(float64(p.MemMiB)/1024, 'f', -1, 64)
			size := fmt.Sprintf("%dH%sG", p.Cores, gib)
			opts = append(opts, prompt.Option{Label: joinLabel(size, p.Name, fmt.Sprintf("%d vCPU", p.Cores), gib+" GiB"), Value: size})
		}
	}
	title := "Instance size"
	if az != "" {
		title += " (offered in " + az + ")"
	}
	v := otherValue
	if len(opts) > 0 {
		opts = append(opts, prompt.Option{Label: "Other size or exact instance type...", Value: otherValue})
		var err error
		if v, err = rt.Pick().Select(title, opts, defaultPickSize); err != nil {
			return "", err
		}
	}
	if v != otherValue {
		return v, nil
	}
	q := "Size <cores>H<memory>G (such as 4H8G) or exact instance type (such as c6a.xlarge)"
	if !x86 {
		q = "Exact instance type of the instance's architecture (such as t4g.medium)"
	}
	return rt.AskInput("--type", q, "", checkTypeInput(x86))
}

// checkTypeInput validates a typed --type: a size (x86 only) or a name
// shaped like an instance type (<family>.<size>); whether the type exists
// is checked when it is resolved.
func checkTypeInput(x86 bool) func(string) error {
	return func(s string) error {
		s = strings.TrimSpace(s)
		if s == "" {
			return fmt.Errorf("a size or an instance type is required")
		}
		_, isSize, err := platform.ParseTypeShorthand(s)
		if err != nil {
			return err
		}
		if isSize {
			if !x86 {
				return fmt.Errorf("a size resolves to an x86_64 type: enter an exact type")
			}
			return nil
		}
		fam, size, ok := strings.Cut(s, ".")
		if !ok || fam == "" || size == "" || strings.ContainsAny(s, " /:") {
			return fmt.Errorf("%q is neither a size such as 4H8G nor an instance type such as c6a.xlarge", s)
		}
		return nil
	}
}

// availableSubnets lists the available subnets of region (every page),
// those of vpc and az when given, sorted by availability zone, then id.
func (c *client) availableSubnets(ctx context.Context, region, vpc, az string) ([]ec2types.Subnet, error) {
	region = c.regionOr(region)
	filters := []ec2types.Filter{{Name: awssdk.String("state"), Values: []string{string(ec2types.SubnetStateAvailable)}}}
	if vpc != "" {
		filters = append(filters, ec2types.Filter{Name: awssdk.String("vpc-id"), Values: []string{vpc}})
	}
	if az != "" {
		filters = append(filters, ec2types.Filter{Name: awssdk.String("availability-zone"), Values: []string{az}})
	}
	pg := ec2.NewDescribeSubnetsPaginator(c.ec2For(region), &ec2.DescribeSubnetsInput{Filters: filters})
	var out []ec2types.Subnet
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, ec2Err("DescribeSubnets", region, err)
		}
		for _, sn := range page.Subnets {
			if sn.State == "" || sn.State == ec2types.SubnetStateAvailable {
				out = append(out, sn)
			}
		}
	}
	slices.SortFunc(out, func(a, b ec2types.Subnet) int {
		if c := strings.Compare(awssdk.ToString(a.AvailabilityZone), awssdk.ToString(b.AvailabilityZone)); c != 0 {
			return c
		}
		return strings.Compare(awssdk.ToString(a.SubnetId), awssdk.ToString(b.SubnetId))
	})
	return out, nil
}

// tagName returns the Name tag of tags.
func tagName(tags []ec2types.Tag) string {
	for _, t := range tags {
		if awssdk.ToString(t.Key) == "Name" {
			return awssdk.ToString(t.Value)
		}
	}
	return ""
}

// subnetLabel: "public-a  subnet-0def  ap-east-1a  10.0.1.0/24  vpc-0abc
// 250 free IPs  [default for zone]".
func subnetLabel(sn ec2types.Subnet) string {
	free := ""
	if sn.AvailableIpAddressCount != nil {
		free = fmt.Sprintf("%d free IPs", awssdk.ToInt32(sn.AvailableIpAddressCount))
	}
	def := ""
	if awssdk.ToBool(sn.DefaultForAz) {
		def = "[default for zone]"
	}
	id := awssdk.ToString(sn.SubnetId)
	return joinLabel(nameOr(tagName(sn.Tags), id), id, awssdk.ToString(sn.AvailabilityZone), awssdk.ToString(sn.CidrBlock), awssdk.ToString(sn.VpcId), free, def)
}

// pickSubnet asks for the subnet of a create (--subnet) in the interactive
// flow: the available subnets of region (of vpc when given), the first
// default subnet of a zone preselected. polyctl creates no subnets: none
// is a usage error naming --subnet. It returns the subnet chosen.
func pickSubnet(ctx context.Context, rt *app.Runtime, c *client, region, vpc string) (ec2types.Subnet, error) {
	if !rt.Interactive() {
		return ec2types.Subnet{}, app.UsageErrf("--subnet is required")
	}
	subnets, err := c.availableSubnets(ctx, region, vpc, "")
	if err != nil {
		return ec2types.Subnet{}, err
	}
	var opts []prompt.Option
	def := ""
	for _, sn := range subnets {
		id := awssdk.ToString(sn.SubnetId)
		if def == "" && awssdk.ToBool(sn.DefaultForAz) {
			def = id
		}
		opts = append(opts, prompt.Option{Label: subnetLabel(sn), Value: id})
	}
	what := "available subnet in " + c.regionOr(region)
	if vpc != "" {
		what = "available subnet of " + vpc
	}
	v, err := rt.Choose(app.Choice{Title: "Subnet", Options: opts, Default: def, Arg: "--subnet", Required: true, What: what})
	if err != nil {
		return ec2types.Subnet{}, err
	}
	for _, sn := range subnets {
		if awssdk.ToString(sn.SubnetId) == v {
			return sn, nil
		}
	}
	return ec2types.Subnet{}, fmt.Errorf("unexpected subnet %q", v)
}

// inline turns a usage error into the message of an inline validation
// (no "usage:" prefix): the question stays open for a correction.
func inline(err error) error {
	if err == nil {
		return nil
	}
	msg := strings.TrimPrefix(err.Error(), app.ErrUsage.Error()+": ")
	return errors.New(strings.TrimPrefix(msg, platform.ErrInvalidInput.Error()+": "))
}

// availableVPCs lists the available VPCs of region (every page), the
// default VPC first, then by id.
func (c *client) availableVPCs(ctx context.Context, region string) ([]ec2types.Vpc, error) {
	region = c.regionOr(region)
	pg := ec2.NewDescribeVpcsPaginator(c.ec2For(region), &ec2.DescribeVpcsInput{Filters: []ec2types.Filter{
		{Name: awssdk.String("state"), Values: []string{string(ec2types.VpcStateAvailable)}}}})
	var out []ec2types.Vpc
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, ec2Err("DescribeVpcs", region, err)
		}
		for _, v := range page.Vpcs {
			if v.State == "" || v.State == ec2types.VpcStateAvailable {
				out = append(out, v)
			}
		}
	}
	slices.SortFunc(out, func(a, b ec2types.Vpc) int {
		if da, db := awssdk.ToBool(a.IsDefault), awssdk.ToBool(b.IsDefault); da != db {
			if da {
				return -1
			}
			return 1
		}
		return strings.Compare(awssdk.ToString(a.VpcId), awssdk.ToString(b.VpcId))
	})
	return out, nil
}

// vpcLabel: "main  vpc-0abc  10.0.0.0/16  [default]".
func vpcLabel(v ec2types.Vpc) string {
	def := ""
	if awssdk.ToBool(v.IsDefault) {
		def = "[default]"
	}
	id := awssdk.ToString(v.VpcId)
	return joinLabel(nameOr(tagName(v.Tags), id), id, awssdk.ToString(v.CidrBlock), def)
}

// pickVPC asks for the VPC of a create (--vpc) in the interactive flow: the
// available VPCs of region, the default VPC preselected. polyctl creates no
// VPCs: none is a usage error naming --vpc. The non-interactive flow gets
// missing (nil: "--vpc is required").
func pickVPC(ctx context.Context, rt *app.Runtime, c *client, region string, missing func() error) (string, error) {
	if !rt.Interactive() {
		if missing != nil {
			return "", missing()
		}
		return "", app.UsageErrf("--vpc is required")
	}
	vpcs, err := c.availableVPCs(ctx, region)
	if err != nil {
		return "", err
	}
	var opts []prompt.Option
	def := ""
	for _, v := range vpcs {
		id := awssdk.ToString(v.VpcId)
		if def == "" && awssdk.ToBool(v.IsDefault) {
			def = id
		}
		opts = append(opts, prompt.Option{Label: vpcLabel(v), Value: id})
	}
	return rt.Choose(app.Choice{Title: "VPC", Options: opts, Default: def, Arg: "--vpc", Required: true, What: "available VPC in " + c.regionOr(region)})
}
