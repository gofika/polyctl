package aliyun

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// The interactive picks of the security group and VPC commands.

// sgArg fills in a missing <name|id> / <sg> of a security group command in
// the interactive flow: the groups of the region (of --vpc when given),
// labelled with their VPC and description; the value is the group id. No
// group is nothing to do. With the argument given, args is returned as it
// is.
func sgArg(ctx context.Context, rt *app.Runtime, s *ecsScope, args []string, vpcFlag string) ([]string, error) {
	if len(args) > 0 {
		return args, nil
	}
	vpc := ""
	if vpcFlag != "" {
		v, err := resolveVPC(ctx, s, vpcFlag)
		if err != nil {
			return nil, err
		}
		vpc = v.ID
	}
	groups, err := s.c.listSecurityGroups(ctx, s.region, vpc, "", "")
	if err != nil {
		return nil, err
	}
	var opts []prompt.Option
	for _, g := range groups {
		opts = append(opts, prompt.Option{Label: sgLabel(g), Value: g.ID})
	}
	id, err := rt.Choose(app.Choice{Title: "Security group (" + s.where() + ")", Options: opts, Arg: "<sg>", What: "security group in " + s.where()})
	if err != nil {
		return nil, err
	}
	return []string{id}, nil
}

// newGroupValue is the value of "Create a new security group...".
const newGroupValue = "\x00new-group"

// sgEnsureArg fills in a missing <name> of security-group ensure: the
// groups of the region (chosen by id), or "Create a new security group..." for a
// name (naming.aliyun_ecs_security_group proposed, checked as it is
// typed).
func sgEnsureArg(ctx context.Context, rt *app.Runtime, s *ecsScope) (string, error) {
	groups, err := s.c.listSecurityGroups(ctx, s.region, "", "", "")
	if err != nil {
		return "", err
	}
	var opts []prompt.Option
	for _, g := range groups {
		opts = append(opts, prompt.Option{Label: sgLabel(g), Value: g.ID})
	}
	def, err := rt.ResourceName("aliyun_ecs_security_group", "", map[string]string{"region": s.region})
	if err != nil {
		return "", err
	}
	if checkSGName(def) != nil {
		def = ""
	}
	return rt.Choose(app.Choice{Title: "Security group to ensure (" + s.where() + ")", Options: opts, Arg: "<name>", Required: true,
		CreateLabel: "Create a new security group...", Create: func() (string, error) {
			return rt.AskInput("<name>", "Name of the security group", def, func(v string) error { return inline(checkSGName(strings.TrimSpace(v))) })
		}})
}

// pickVPC asks for an Available VPC of the region (the default VPC marked,
// the one named prefer preselected) for the input arg (a flag such as
// --vpc). empty is returned when there is none (nil: a usage error naming
// arg).
func pickVPC(ctx context.Context, rt *app.Runtime, s *ecsScope, arg, prefer string, empty error) (vpcInfo, error) {
	if !rt.Interactive() {
		return vpcInfo{}, app.UsageErrf("%s is required", arg)
	}
	vpcs, err := s.c.listVPCs(ctx, s.region, true)
	if err != nil {
		return vpcInfo{}, err
	}
	var opts []prompt.Option
	def := ""
	for _, v := range vpcs {
		if v.Status != "" && v.Status != statusAvailable {
			continue
		}
		opts = append(opts, prompt.Option{Label: vpcLabel(v), Value: v.ID})
		if prefer != "" && v.Name == prefer && def == "" {
			def = v.ID
		}
	}
	id, err := rt.Choose(app.Choice{Title: "VPC (" + s.where() + ")", Options: opts, Default: def, Arg: arg, Required: true, What: "Available VPC in " + s.region, Empty: empty})
	if err != nil {
		return vpcInfo{}, err
	}
	for _, v := range vpcs {
		if v.ID == id {
			return v, nil
		}
	}
	return vpcInfo{}, fmt.Errorf("VPC %s is no longer listed", id)
}

// The common ingress rules rule add offers, from anywhere.
var presetRules = []string{"tcp:ssh:0.0.0.0/0", "tcp:http:0.0.0.0/0", "tcp:https:0.0.0.0/0", "icmp:all:0.0.0.0/0"}

// otherRulesValue is the value of "Other rules (typed)...".
const otherRulesValue = "\x00other-rules"

// askRules asks for the --rule of rule add in the interactive flow: the
// common rules the group does not hold yet (multiple choice) and "Other
// rules (typed)...", which asks for one rule after another, each checked
// as it is typed, until an empty line.
func askRules(rt *app.Runtime, have []sgRule) ([]string, error) {
	var opts []prompt.Option
	for _, spec := range presetRules {
		r, err := platform.ParseIngressRule(spec)
		if err != nil {
			continue
		}
		if len(matchingRules(have, r)) > 0 {
			continue
		}
		opts = append(opts, prompt.Option{Label: spec, Value: spec})
	}
	opts = append(opts, prompt.Option{Label: "Other rules (typed)...", Value: otherRulesValue})
	picked, err := rt.ChooseMany(app.Choice{Title: "Rules to add (from anywhere unless typed)", Options: opts, Arg: "--rule"})
	if err != nil {
		return nil, err
	}
	var out []string
	other := false
	for _, v := range picked {
		if v == otherRulesValue {
			other = true
			continue
		}
		out = append(out, v)
	}
	for other {
		v, err := rt.AskInput("--rule", "Rule "+platform.RuleFormat+" (empty line ends)", "", func(s string) error {
			if strings.TrimSpace(s) == "" {
				return nil
			}
			_, err := platform.ParseIngressRule(strings.TrimSpace(s))
			return inline(err)
		})
		if err != nil {
			return nil, err
		}
		if v == "" {
			break
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil, app.NothingToDof("no rule was given")
	}
	return out, nil
}

// pickRuleIDs asks for the rules rule remove removes (multiple choice),
// labelled "tcp 22/22 0.0.0.0/0  prio 1  sgr-...  description". No rule is
// nothing to do.
func pickRuleIDs(rt *app.Runtime, sg *securityGroup, have []sgRule) ([]string, error) {
	var opts []prompt.Option
	for _, r := range have {
		if r.ID == "" {
			continue
		}
		opts = append(opts, prompt.Option{Label: joinLabel(r.String(), fmt.Sprintf("prio %d", r.Priority), r.ID, r.Description), Value: r.ID})
	}
	return rt.ChooseMany(app.Choice{Title: "Rules to remove from " + orID(sg.Name, sg.ID), Options: opts, Arg: "--rule or --rule-id",
		Empty: app.NothingToDof("security group %s has no ingress rules", sg.ID)})
}

// vpcArg fills in a missing <name|id> of vpc get in the interactive flow:
// every VPC of the region; none is nothing to do.
func vpcArg(ctx context.Context, rt *app.Runtime, s *ecsScope, args []string) ([]string, error) {
	if len(args) > 0 {
		return args, nil
	}
	vpcs, err := s.c.listVPCs(ctx, s.region, true)
	if err != nil {
		return nil, err
	}
	var opts []prompt.Option
	for _, v := range vpcs {
		opts = append(opts, prompt.Option{Label: vpcLabel(v), Value: v.ID})
	}
	id, err := rt.Choose(app.Choice{Title: "VPC (" + s.where() + ")", Options: opts, Arg: "<name|id>", What: "VPC in " + s.where()})
	if err != nil {
		return nil, err
	}
	return []string{id}, nil
}

// vswArg fills in a missing <name|id> of vswitch get in the interactive
// flow: every vSwitch of the region (of --vpc when given); none is nothing
// to do.
func vswArg(ctx context.Context, rt *app.Runtime, s *ecsScope, args []string, vpcRef string) ([]string, error) {
	if len(args) > 0 {
		return args, nil
	}
	vpc := ""
	if vpcRef != "" {
		v, err := resolveVPC(ctx, s, vpcRef)
		if err != nil {
			return nil, err
		}
		vpc = v.ID
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
		opts = append(opts, prompt.Option{Label: joinLabel(vswLabel(v, names), v.Status), Value: v.ID})
	}
	id, err := rt.Choose(app.Choice{Title: "vSwitch (" + s.where() + ")", Options: opts, Arg: "<name|id>", What: "vSwitch in " + s.where()})
	if err != nil {
		return nil, err
	}
	return []string{id}, nil
}

// askNetName asks for the name of a new VPC or vSwitch, proposal (when
// valid and free) as the default, checked as it is typed against the
// rules and taken.
func askNetName(rt *app.Runtime, kind, idPrefix, title, proposal string, taken func(string) string) (string, error) {
	if checkNetName(kind, idPrefix, proposal) != nil || taken(proposal) != "" {
		proposal = ""
	}
	return rt.AskInput("<name>", title, proposal, func(v string) error {
		v = strings.TrimSpace(v)
		if err := checkNetName(kind, idPrefix, v); err != nil {
			return inline(err)
		}
		if id := taken(v); id != "" {
			return fmt.Errorf("%s %q already exists (%s)", kind, v, id)
		}
		return nil
	})
}

// pickZone asks for a zone of the region for a vSwitch of vpc: the zones
// where instance types are in stock, those already holding a vSwitch of the
// VPC marked; the first default zone (b, c) without one is preselected.
func pickZone(ctx context.Context, rt *app.Runtime, s *ecsScope, existing []vSwitch) (zoneTarget, error) {
	found, err := s.c.stockedTypes(ctx, s.region, stockQuery{})
	if err != nil {
		return zoneTarget{}, err
	}
	var zones []string
	for _, tz := range found {
		if !slices.Contains(zones, tz.Zone) {
			zones = append(zones, tz.Zone)
		}
	}
	slices.Sort(zones)
	used := map[string][]string{}
	for _, v := range existing {
		used[v.Zone] = append(used[v.Zone], nameOr(v.Name, v.ID))
	}
	var opts []prompt.Option
	for _, z := range zones {
		label := z
		if u := used[z]; len(u) > 0 {
			label += "  (vSwitch " + strings.Join(u, ", ") + ")"
		}
		opts = append(opts, prompt.Option{Label: label, Value: z})
	}
	def := ""
	for _, suffix := range defaultZones {
		z := s.region + "-" + suffix
		if slices.Contains(zones, z) && len(used[z]) == 0 {
			def = z
			break
		}
	}
	z, err := rt.Choose(app.Choice{Title: "Zone (" + s.region + ")", Options: opts, Default: def, Arg: "--zone", Required: true,
		Empty: app.UsageErrf("--zone is required, and no zone of %s offers instances", s.region)})
	if err != nil {
		return zoneTarget{}, err
	}
	return parseZone(s.region, z, "zone")
}
