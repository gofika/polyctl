package aliyun

import (
	"context"
	"fmt"
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

// newGroupValue is the value of "New security group...".
const newGroupValue = "\x00new-group"

// sgEnsureArg fills in a missing <name> of security-group ensure: the
// groups of the region (chosen by id), or "New security group..." for a
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
		CreateLabel: "New security group...", Create: func() (string, error) {
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
