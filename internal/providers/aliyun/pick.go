package aliyun

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// The labels of the interactive picks of the aliyun commands: what a
// resource is (name, id) and the facts that tell candidates apart (zone,
// CIDR, status, VPC). Empty facts are left out.

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

// vpcLabel: "cn-shanghai-vpc  vpc-1  172.16.0.0/12  Available  [default]".
func vpcLabel(v vpcInfo) string {
	def := ""
	if v.IsDefault {
		def = "[default]"
	}
	return joinLabel(nameOr(v.Name, v.ID), v.ID, v.CIDR, v.Status, def)
}

// sgLabel: "sg-common  sg-1  vpc-1  description".
func sgLabel(g securityGroup) string {
	return joinLabel(nameOr(g.Name, g.ID), g.ID, g.VPC, g.Description)
}

// vswLabel: "cn-shanghai-switch-b  vsw-1  cn-shanghai-b  172.16.0.0/22
// vpc-name  N free IPs"; vpcNames, when given, names the VPC.
func vswLabel(v vSwitch, vpcNames map[string]string) string {
	vpc := v.VPC
	if n := vpcNames[v.VPC]; n != "" && n != v.VPC {
		vpc = n + " (" + v.VPC + ")"
	}
	free := ""
	if v.AvailableIPs > 0 {
		free = itoa64(v.AvailableIPs) + " free IPs"
	}
	return joinLabel(nameOr(v.Name, v.ID), v.ID, v.Zone, v.CIDR, vpc, free)
}

// instanceOptionLabel: "site-a  i-1  cn-shanghai-b  Running  ecs.u1  203.0.113.9".
func instanceOptionLabel(in Instance) string {
	ip := in.PublicIP
	if ip == "" {
		ip = in.EIP
	}
	return joinLabel(nameOr(in.Name, in.ID), in.ID, in.Zone, in.Status, in.Type, ip)
}

// lbOptionLabel: "web  alb-1  Active  dns-name".
func lbOptionLabel(l albRef) string {
	return joinLabel(nameOr(l.Name, l.ID), l.ID, l.Status, l.VpcID, l.DNSName)
}

// serverGroupLabel: "web  sgp-1  HTTP  vpc-1  2 servers".
func serverGroupLabel(g albServerGroup) string {
	return joinLabel(nameOr(g.Name, g.ID), g.ID, g.Protocol, g.VpcID, itoa64(int64(g.ServerCount))+" servers")
}

// aclLabel: "office  acl-1  Available".
func aclLabel(x albACL) string {
	return joinLabel(nameOr(x.Name, x.ID), x.ID, x.Status)
}

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }

// narrowVPCs turns several VPCs of the name into the one the user picks in
// the interactive flow; otherwise several are ambiguous (exit code 5) with
// hint. None or one is returned as it is.
func narrowVPCs(s *ecsScope, name string, vpcs []vpcInfo, hint string) ([]vpcInfo, error) {
	if len(vpcs) < 2 {
		return vpcs, nil
	}
	var ids []string
	for _, v := range vpcs {
		ids = append(ids, v.ID)
	}
	amb := &app.AmbiguousError{What: fmt.Sprintf("VPC %q in %s", name, s.where()), Candidates: ids, Hint: hint}
	v, err := pickAmong(s, amb, vpcs, func(v vpcInfo) string { return v.ID }, vpcLabel)
	if err != nil {
		return nil, err
	}
	return []vpcInfo{*v}, nil
}

// instanceArg fills in a missing <name|id> of an instance command in the
// interactive flow: the aliyun instances of the selected accounts as the
// inventory knows them (synced first when stale, never with --offline), in
// region when it is given, those keep accepts (nil: all). what names them
// for an empty list ("stopped instance"), which is nothing to do. With the
// argument given, args is returned as it is.
func instanceArg(ctx context.Context, rt *app.Runtime, args []string, region, what string, keep func(Instance) bool) ([]string, error) {
	if len(args) > 0 {
		return args, nil
	}
	id, err := rt.PickResource(ctx, app.ResourcePick{Platform: platform.Aliyun, Kind: platform.ResInstance,
		Title: "Instance", Arg: "<name|id>", What: what,
		Filter: func(r inventory.Resource) bool {
			in := instanceOf(r)
			if region != "" && in.Region != region {
				return false
			}
			return keep == nil || keep(in)
		},
		Label: func(r inventory.Resource) string {
			in := instanceOf(r)
			return joinLabel(instanceOptionLabel(in), "aliyun/"+r.Profile)
		}})
	if err != nil {
		return nil, err
	}
	return []string{id}, nil
}

// instanceOf decodes an inventory row of an instance; the region falls
// back to the row's parent.
func instanceOf(r inventory.Resource) Instance {
	var in Instance
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

// statusIn keeps the instances in one of the statuses.
func statusIn(statuses ...string) func(Instance) bool {
	return func(in Instance) bool { return slices.Contains(statuses, in.Status) }
}

// defaultPickSize is the size preselected by the size pick of create.
const defaultPickSize = "2H4G"

// pickSize asks for an instance size (the --type of create and resize) in
// the interactive flow: the sizes of the x86 types in stock in zones
// (resize: those instance resizeID can change to, without its current
// size), GPU types left out, each with how many types and which zones
// offer it. The size is then resolved like --type <cores>H<memory>G: the
// cheapest type of that size. def is preselected when offered. No size is
// a usage error naming --type.
func pickSize(ctx context.Context, rt *app.Runtime, s *ecsScope, zones []string, resizeID string, current *platform.TypeShorthand, def string) (string, error) {
	if !rt.Interactive() {
		return "", app.UsageErrf("--type is required")
	}
	var found []typeZone
	var err error
	if resizeID != "" {
		found, err = s.c.modifiableTypes(ctx, s.region, resizeID, 0, 0)
	} else {
		q := stockQuery{}
		if len(zones) == 1 {
			q.Zone = zones[0]
		}
		found, err = s.c.stockedTypes(ctx, s.region, q)
	}
	if err != nil {
		return "", err
	}
	var types []string
	for _, tz := range found {
		if (len(zones) == 0 || slices.Contains(zones, tz.Zone)) && !slices.Contains(types, tz.Type) {
			types = append(types, tz.Type)
		}
	}
	slices.Sort(types)
	info, err := s.c.x86TypeInfo(ctx, s.region, types)
	if err != nil {
		return "", err
	}
	type sizeOpt struct {
		cores        int
		mem          float64
		types, zones []string
	}
	bySize := map[string]*sizeOpt{}
	for _, tz := range found {
		ti, ok := info[tz.Type]
		if !ok || ti.GPUs > 0 || ti.Cores < 1 || ti.Memory <= 0 || (len(zones) > 0 && !slices.Contains(zones, tz.Zone)) {
			continue
		}
		key := fmt.Sprintf("%dH%sG", ti.Cores, strconv.FormatFloat(ti.Memory, 'f', -1, 64))
		if current != nil && current.Matches(ti.Cores, int(ti.Memory*1024+0.5)) {
			continue
		}
		o := bySize[key]
		if o == nil {
			o = &sizeOpt{cores: ti.Cores, mem: ti.Memory}
			bySize[key] = o
		}
		if !slices.Contains(o.types, tz.Type) {
			o.types = append(o.types, tz.Type)
		}
		if !slices.Contains(o.zones, tz.Zone) {
			o.zones = append(o.zones, tz.Zone)
		}
	}
	keys := make([]string, 0, len(bySize))
	for k := range bySize {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b string) int {
		x, y := bySize[a], bySize[b]
		if x.cores != y.cores {
			return x.cores - y.cores
		}
		switch {
		case x.mem < y.mem:
			return -1
		case x.mem > y.mem:
			return 1
		}
		return 0
	})
	var opts []prompt.Option
	for _, k := range keys {
		o := bySize[k]
		slices.Sort(o.zones)
		n := fmt.Sprintf("%d x86 types", len(o.types))
		if len(o.types) == 1 {
			n = "1 x86 type"
		}
		opts = append(opts, prompt.Option{Label: joinLabel(k, fmt.Sprintf("%d vCPU / %s GiB", o.cores, strconv.FormatFloat(o.mem, 'f', -1, 64)),
			n+" in stock", strings.Join(o.zones, ", ")), Value: k})
	}
	if _, ok := bySize[def]; !ok {
		def = ""
	}
	where := s.where()
	if len(zones) > 0 {
		where = strings.Join(zones, ", ")
	}
	return rt.Choose(app.Choice{Title: "Instance size (the cheapest x86 type of the size is used)", Options: opts, Default: def,
		Arg: "--type", Required: true, Empty: app.UsageErrf("--type is required, and no x86 instance type is in stock in %s", where)})
}
