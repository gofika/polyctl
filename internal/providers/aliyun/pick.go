package aliyun

import (
	"context"
	"errors"
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

// instanceOptionLabel: "site-a  i-1  Running  ecs.u1  cn-shanghai-b
// 172.16.0.5  203.0.113.9", in the order of the aws and gcp labels.
func instanceOptionLabel(in Instance) string {
	ip := in.PublicIP
	if ip == "" {
		ip = in.EIP
	}
	return joinLabel(nameOr(in.Name, in.ID), in.ID, in.Status, in.Type, in.Zone, in.PrivateIP, ip)
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

// inline turns a usage error into the message an Input shows under the
// value being typed.
func inline(err error) error {
	if err == nil {
		return nil
	}
	msg := strings.TrimPrefix(err.Error(), app.ErrUsage.Error()+": ")
	return errors.New(strings.TrimPrefix(msg, platform.ErrInvalidInput.Error()+": "))
}

// askInstanceName asks for the name of a new instance, checked as it is
// typed (the rules of checkInstanceName and of the host name made of it).
func askInstanceName(rt *app.Runtime) (string, error) {
	return rt.AskInput("<name>", "Name of the new instance", "", func(v string) error {
		if err := checkInstanceName(v); err != nil {
			return inline(err)
		}
		_, _, err := normalizeHostName(v)
		return inline(err)
	})
}

// newSGValue is the value of the "Create a new security group..." option.
const newSGValue = "\x00new-sg"

// pickInstanceSG asks for the security group of a new instance in the
// interactive flow: the groups of vpc (the one named by
// naming.aliyun_ecs_security_group preselected), or "Create a new security
// group..." with the name asked (the naming template's name proposed,
// checked as it is typed, unused in the VPC). It returns the group chosen,
// or the name of the group to create.
func pickInstanceSG(ctx context.Context, rt *app.Runtime, s *ecsScope, vpc string) (*securityGroup, string, error) {
	if !rt.Interactive() {
		return nil, "", app.UsageErrf("--security-group is required")
	}
	groups, err := s.c.listSecurityGroups(ctx, s.region, vpc, "", "")
	if err != nil {
		return nil, "", err
	}
	def, err := rt.ResourceName("aliyun_ecs_security_group", "", map[string]string{"region": s.region})
	if err != nil {
		return nil, "", err
	}
	var opts []prompt.Option
	pre := ""
	for _, g := range groups {
		if g.VPC != vpc {
			continue
		}
		opts = append(opts, prompt.Option{Label: sgLabel(g), Value: g.ID})
		if g.Name == def && pre == "" {
			pre = g.ID
		}
	}
	newName := ""
	v, err := rt.Choose(app.Choice{Title: "Security group (VPC " + vpc + ")", Options: opts, Default: pre, Arg: "--security-group", Required: true,
		CreateLabel: "Create a new security group...", Create: func() (string, error) {
			taken := map[string]bool{}
			for _, g := range groups {
				taken[g.Name] = true
			}
			proposal := def
			if taken[proposal] {
				proposal = ""
			}
			n, err := rt.AskInput("--security-group", "Name of the new security group (rules: defaults.aliyun.ecs_security_group_rules, else ICMP, 80 and 443)", proposal, func(v string) error {
				if err := checkInstanceSGName(v); err != nil {
					return inline(err)
				}
				if taken[strings.TrimSpace(v)] {
					return fmt.Errorf("VPC %s already has a security group %q", vpc, strings.TrimSpace(v))
				}
				return nil
			})
			newName = n
			return newSGValue, err
		}})
	if err != nil {
		return nil, "", err
	}
	if v == newSGValue {
		return nil, newName, nil
	}
	for i := range groups {
		if groups[i].ID == v {
			return &groups[i], "", nil
		}
	}
	return nil, "", fmt.Errorf("security group %s is no longer listed", v)
}

// pickVSwitchOf asks for an Available vSwitch of the region (of vpc and
// zone when they are given), labelled with its zone, CIDR block, VPC and
// free addresses. empty is returned when there is none.
func pickVSwitchOf(ctx context.Context, rt *app.Runtime, s *ecsScope, vpc, zone, arg string, empty error) (*vSwitch, error) {
	if !rt.Interactive() {
		return nil, app.UsageErrf("%s is required", arg)
	}
	list, err := s.c.listVSwitches(ctx, s.region, vpc, "", "")
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	if vpcs, err := s.c.listVPCs(ctx, s.region, true); err == nil {
		for _, v := range vpcs {
			names[v.ID] = v.Name
		}
	}
	var opts []prompt.Option
	for _, v := range list {
		if v.Status != statusAvailable || (zone != "" && v.Zone != zone) {
			continue
		}
		opts = append(opts, prompt.Option{Label: vswLabel(v, names), Value: v.ID})
	}
	id, err := rt.Choose(app.Choice{Title: "vSwitch", Options: opts, Arg: arg, Required: true, Empty: empty})
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].ID == id {
			return &list[i], nil
		}
	}
	return nil, fmt.Errorf("vSwitch %s is no longer listed", id)
}

// pickEnsureName asks for the <name> of instance ensure in the interactive
// flow: the instances of the region (read live), or "Create a new instance..."
// for a name checked as it is typed.
func pickEnsureName(ctx context.Context, rt *app.Runtime, s *ecsScope) (string, error) {
	rows, err := s.c.instanceResources(ctx, s.region)
	if err != nil {
		return "", err
	}
	var opts []prompt.Option
	seen := map[string]bool{}
	for _, r := range rows {
		in, ok := r.Data.(Instance)
		if !ok {
			in = Instance{ID: r.ID, Name: r.Name}
		}
		if in.Name == "" || seen[in.Name] {
			continue
		}
		seen[in.Name] = true
		opts = append(opts, prompt.Option{Label: instanceOptionLabel(in), Value: in.Name})
	}
	return rt.Choose(app.Choice{Title: "Instance to ensure (" + s.where() + ")", Options: opts, Arg: "<name>", Required: true,
		CreateLabel: "Create a new instance...", Create: func() (string, error) { return askInstanceName(rt) }})
}
