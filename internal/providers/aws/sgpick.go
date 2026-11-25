package aws

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// sgOptionLabel: "web  sg-0abc  vpc-0abc  3 rules  description".
func sgOptionLabel(g platform.SecurityGroup) string {
	return prompt.Cells(nameOr(g.Name, g.ID), g.ID, g.VPC, fmt.Sprintf("%d rules", len(g.Ingress)), g.Description)
}

// sgOptions lists the groups of the scope (of vpc when given) that keep
// accepts (nil: all) as options, valued by id.
func sgOptions(ctx context.Context, s *sgScope, vpc string, keep func(platform.SecurityGroup) bool) ([]prompt.Option, error) {
	sgs, err := s.c.ListSecurityGroups(ctx, s.region, platform.SecurityGroupFilter{VPC: vpc})
	if err != nil {
		return nil, err
	}
	var opts []prompt.Option
	for _, g := range sgs {
		if keep == nil || keep(g) {
			opts = append(opts, prompt.Option{Label: sgOptionLabel(g), Value: g.ID})
		}
	}
	return opts, nil
}

// sgTarget opens the account of a command acting on an existing group and
// resolves the group: args[0], or in the interactive flow a pick among the
// groups of the region (of --vpc or defaults.aws.vpc_id when set) that keep
// accepts; none is nothing to do.
func sgTarget(ctx context.Context, rt *app.Runtime, args []string, region, vpcFlag string, keep func(platform.SecurityGroup) bool) (*sgScope, *platform.SecurityGroup, error) {
	ref := app.Arg(args, 0)
	s, err := openSGScope(ctx, rt, ref, region)
	if err != nil {
		return nil, nil, err
	}
	if ref == "" {
		vpc, err := lookupVPC(rt, s.profile, vpcFlag)
		if err != nil {
			return nil, nil, err
		}
		opts, err := sgOptions(ctx, s, vpc, keep)
		if err != nil {
			return nil, nil, err
		}
		what := "security group in " + s.where()
		if vpc != "" {
			what += " (" + vpc + ")"
		}
		if ref, err = rt.Choose(app.Choice{Title: "Security group", Options: opts, Arg: "<sg-id|name>", What: what}); err != nil {
			return nil, nil, err
		}
	}
	sg, err := resolveSG(ctx, rt, s, ref, vpcFlag)
	if err != nil {
		return nil, nil, err
	}
	return s, sg, nil
}

// presetRules are the common rules rule add offers.
var presetRules = []string{"tcp:ssh:0.0.0.0/0", "tcp:http:0.0.0.0/0", "tcp:https:0.0.0.0/0", "icmp:all:0.0.0.0/0"}

// otherRulesValue is the value of "Other rules (typed)...".
const otherRulesValue = "\x00other-rules"

// askRules asks for the --rule of rule add in the interactive flow: the
// common rules the group does not hold yet (multiple choice) and "Other
// rules (typed)...", which asks for one rule after another, each checked
// as it is typed, until an empty line.
func askRules(rt *app.Runtime, c *client, sg platform.SecurityGroup) ([]string, error) {
	var opts []prompt.Option
	for _, spec := range presetRules {
		r, err := platform.ParseIngressRule(spec)
		if err != nil {
			continue
		}
		if missing, _, err := c.MissingIngressRules(sg, []platform.IngressRule{r}); err != nil || len(missing) == 0 {
			continue
		}
		opts = append(opts, prompt.Option{Label: spec, Value: spec})
	}
	opts = append(opts, prompt.Option{Label: "Other rules (typed)...", Value: otherRulesValue})
	picked, err := rt.ChooseMany(app.Choice{Title: "Rules to add to " + nameOr(sg.Name, sg.ID), Options: opts, Arg: "--rule"})
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

// pickRules asks for the rules rule remove removes (multiple choice), from
// the ingress rules of the group, labelled "tcp  22  0.0.0.0/0
// description". No rule is nothing to do.
func pickRules(rt *app.Runtime, sg platform.SecurityGroup) ([]platform.IngressRule, error) {
	var rules []platform.IngressRule
	var opts []prompt.Option
	for _, r := range sg.Ingress {
		if r.SourceType == platform.SourcePrefixList {
			// A prefix list source cannot be named by --rule either.
			continue
		}
		ir := platform.IngressRule{Protocol: r.Protocol, FromPort: r.FromPort, ToPort: r.ToPort, Source: r.Source, SourceKind: r.SourceType, Description: r.Description}
		opts = append(opts, prompt.Option{Label: prompt.Cells(ir.Protocol, ir.Ports(), ir.Source, r.Description), Value: strconv.Itoa(len(rules))})
		rules = append(rules, ir)
	}
	picked, err := rt.ChooseMany(app.Choice{Title: "Rules to remove from " + nameOr(sg.Name, sg.ID), Options: opts, Arg: "--rule",
		Empty: app.NothingToDof("security group %s has no ingress rules", sg.ID)})
	if err != nil {
		return nil, err
	}
	var out []platform.IngressRule
	for _, v := range picked {
		if i, err := strconv.Atoi(v); err == nil && i >= 0 && i < len(rules) {
			out = append(out, rules[i])
		}
	}
	return out, nil
}

// askSGName asks for the name of a new group in vpc, checked as it is
// typed (the rules of checkSGName and checkAWSText, and not taken in the
// VPC).
func askSGName(ctx context.Context, rt *app.Runtime, s *sgScope, vpc string) (string, error) {
	return rt.AskInput("<name>", "Name of the new security group in "+vpc, "", func(v string) error {
		v = strings.TrimSpace(v)
		if err := checkSGName(v); err != nil {
			return inline(err)
		}
		found, err := s.c.FindSecurityGroups(ctx, s.region, v, vpc)
		if err != nil {
			return err
		}
		if len(found) > 0 {
			return fmt.Errorf("security group %q already exists in %s (%s)", v, vpc, found[0].ID)
		}
		return nil
	})
}

// newSGValue is the value of "Create a new security group..." of ensure.
const newSGValue = "\x00new-sg"

// sgEnsureName asks for the <name> of ensure in the interactive flow: one
// of the groups of vpc, or "Create a new security group..." (its name checked as it
// is typed).
func sgEnsureName(ctx context.Context, rt *app.Runtime, s *sgScope, vpc string) (string, error) {
	sgs, err := s.c.ListSecurityGroups(ctx, s.region, platform.SecurityGroupFilter{VPC: vpc})
	if err != nil {
		return "", err
	}
	var opts []prompt.Option
	for _, g := range sgs {
		opts = append(opts, prompt.Option{Label: sgOptionLabel(g), Value: g.Name})
	}
	return rt.Choose(app.Choice{Title: "Security group", Options: opts, Arg: "<name>", Required: true,
		CreateLabel: "Create a new security group...", Create: func() (string, error) { return askSGName(ctx, rt, s, vpc) }})
}
