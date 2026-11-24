package aws

import (
	"context"
	"fmt"
	"slices"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// securityGroupCmd is `aws ec2 security-group`: list, get, create, delete,
// ensure and the ingress rules (rule add, rule remove).
func securityGroupCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "security-group",
		Short: "EC2 security groups and their ingress rules",
		Long: `EC2 security groups (regional, one VPC each) and their ingress rules.

A security group is named by its id (sg-...) or by its name. Names are
unique within a VPC only: a name is looked up in --vpc, else in
defaults.aws.vpc_id, else in every VPC of the region, where a name held by
several groups is ambiguous (exit code 5). An id is looked up in the account
whose inventory holds it when --profile and --region are not given.

Rules are written <protocol>:<port|from-to|alias|all>:<source>:
  protocol  tcp, udp, icmp or all
  port      80, 8000-8999, an alias (ssh, http, https, mysql, postgres, ...),
            all (every port: icmp:all, all:all, and tcp:all / udp:all for 1-65535)
  source    an IPv4 or IPv6 CIDR (a bare address gets /32 or /128) or a
            security group id of the same account
Examples: tcp:443:0.0.0.0/0, tcp:ssh:10.0.0.0/8, icmp:all:::/0,
all:all:sg-0123456789abcdef0. ICMP from an IPv6 source is ICMPv6.

Rules are compared by protocol, ports and source; their descriptions never
count. Egress rules are not managed: a new group keeps the AWS default that
allows all outbound traffic.`,
	}
	rule := &cobra.Command{
		Use:   "rule",
		Short: "Ingress rules of a security group",
	}
	rule.AddCommand(sgRuleAddCmd(rt), sgRuleRemoveCmd(rt))
	cmd.AddCommand(sgListCmd(rt), sgGetCmd(rt), sgCreateCmd(rt), sgDeleteCmd(rt), sgEnsureCmd(rt), rule)
	return cmd
}

// sgScope is the account and region a security group command works in.
type sgScope struct {
	c       *client
	profile string
	region  string
}

func (s *sgScope) target() platform.Target {
	return platform.Target{Platform: platform.AWS, Profile: s.profile, Region: s.region}
}

func (s *sgScope) where() string { return "aws/" + s.profile + "/" + s.region }

// openSGScope opens the account of a command. For an sg- id without
// --profile and --region, the inventory tells which account (and region)
// holds the group when exactly one does; otherwise the selected profile
// and its region (or --region) are used.
func openSGScope(ctx context.Context, rt *app.Runtime, ref, region string) (*sgScope, error) {
	if rt.Flags.Offline {
		return nil, app.ErrOffline
	}
	if looksLikeGroupID(ref) && region == "" && rt.Flags.Profile == "" {
		if s := sgScopeFromInventory(ctx, rt, ref); s != nil {
			return s, nil
		}
	}
	c, prof, err := openClient(ctx, rt)
	if err != nil {
		return nil, err
	}
	return &sgScope{c: c, profile: prof.Name, region: c.regionOr(region)}, nil
}

// sgScopeFromInventory returns the account whose cached security groups
// hold id, when exactly one does (no sync: the profile's account is the
// fallback).
func sgScopeFromInventory(ctx context.Context, rt *app.Runtime, id string) *sgScope {
	accounts, err := awsAccounts(rt)
	if err != nil || len(accounts) < 2 {
		return nil
	}
	db, err := rt.DB()
	if err != nil {
		return nil
	}
	type hit struct{ profile, region string }
	var hits []hit
	for _, a := range accounts {
		rows, err := db.List(ctx, inventory.Query{Platform: platform.AWS, Profile: a.Profile, Type: platform.ResSecurityGroup})
		if err != nil {
			return nil
		}
		for _, r := range rows {
			if r.ID == id {
				var sg platform.SecurityGroup
				_ = r.Decode(&sg)
				hits = append(hits, hit{a.Profile, sg.Region})
			}
		}
	}
	if len(hits) != 1 {
		return nil
	}
	c, err := openProfile(ctx, rt, hits[0].profile)
	if err != nil {
		return nil
	}
	return &sgScope{c: c, profile: hits[0].profile, region: c.regionOr(hits[0].region)}
}

// lookupVPC is the VPC a name is looked up in: --vpc, else
// defaults.aws.vpc_id, else "" (every VPC).
func lookupVPC(rt *app.Runtime, profile, vpc string) (string, error) {
	return rt.Setting(profile, platform.AWS, "vpc_id", vpc)
}

// findSG returns the group ref names in the scope, nil when there is none.
// A name held by groups of several VPCs is ambiguous.
func findSG(ctx context.Context, rt *app.Runtime, s *sgScope, ref, vpc string) (*platform.SecurityGroup, error) {
	if strings.TrimSpace(ref) == "" {
		return nil, app.UsageErrf("the security group name or id is empty")
	}
	if looksLikeGroupID(ref) {
		vpc = ""
	}
	found, err := s.c.FindSecurityGroups(ctx, s.region, ref, vpc)
	if err != nil {
		return nil, err
	}
	switch len(found) {
	case 0:
		return nil, nil
	case 1:
		return &found[0], nil
	}
	var names []string
	for _, sg := range found {
		names = append(names, sg.ID+" ("+sg.VPC+")")
	}
	amb := &app.AmbiguousError{What: fmt.Sprintf("security group %q in %s", ref, s.where()), Candidates: names,
		Hint: "the name is used in several VPCs; pass --vpc <vpc-id> or the security group id"}
	// The interactive flow asks which one.
	sg, err := disambiguate(rt, amb, found, sgOptionLabel)
	if err != nil {
		return nil, err
	}
	return &sg, nil
}

// sgNotFound is the error of a group that does not exist.
func sgNotFound(s *sgScope, ref, vpc string) error {
	what := "name"
	if looksLikeGroupID(ref) {
		what, vpc = "id", ""
	}
	in := s.where()
	if vpc != "" {
		in += " (" + vpc + ")"
	}
	return fmt.Errorf("%w: security group with %s %q in %s", platform.ErrNotFound, what, ref, in)
}

// resolveSG returns the group ref names; a missing one is ErrNotFound.
func resolveSG(ctx context.Context, rt *app.Runtime, s *sgScope, ref, vpcFlag string) (*platform.SecurityGroup, error) {
	vpc, err := lookupVPC(rt, s.profile, vpcFlag)
	if err != nil {
		return nil, err
	}
	sg, err := findSG(ctx, rt, s, ref, vpc)
	if err != nil {
		return nil, err
	}
	if sg == nil {
		return nil, sgNotFound(s, ref, vpc)
	}
	return sg, nil
}

// awsTextChars are the characters AWS accepts in security group names and
// descriptions and in rule descriptions (besides letters and digits).
const awsTextChars = ". _-:/()#,@[]+=&;{}!$*"

// checkAWSText refuses what AWS would refuse in a name or description:
// more than 255 characters or a character outside its set (no non-ASCII).
func checkAWSText(what, s string) error {
	if len(s) > 255 {
		return app.UsageErrf("%s %q is longer than 255 characters", what, s)
	}
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(awsTextChars, r) {
			continue
		}
		return app.UsageErrf("%s %q holds %q, which AWS does not accept (letters, digits, spaces and %s only)", what, s, r, strings.ReplaceAll(awsTextChars, " ", ""))
	}
	return nil
}

// checkSGName refuses a name AWS would refuse.
func checkSGName(name string) error {
	if strings.TrimSpace(name) == "" {
		return app.UsageErrf("the security group name is empty")
	}
	if looksLikeGroupID(name) {
		return app.UsageErrf("security group name %q: names may not start with sg- (that is how ids are written)", name)
	}
	return checkAWSText("security group name", name)
}

// sgTags are the tags of a new group: polyctl:managed=true, then
// defaults.aws.tags (which may override it), then Name.
func sgTags(rt *app.Runtime, profile, name string) (map[string]string, error) {
	tags, err := keyPairTags(rt, profile)
	if err != nil {
		return nil, err
	}
	out := map[string]string{"polyctl:managed": "true"}
	for k, v := range tags {
		out[k] = v
	}
	out["Name"] = name
	return out, nil
}

// storeSG records a group in the inventory, when it belongs to the region
// the inventory holds (the profile's region).
func storeSG(ctx context.Context, rt *app.Runtime, s *sgScope, sg platform.SecurityGroup) {
	if s.region != s.c.region || sg.ID == "" {
		return
	}
	db, err := rt.DB()
	if err != nil {
		return
	}
	cfg, _ := rt.Config()
	_ = db.Upsert(ctx, inventory.Set{Platform: platform.AWS, Profile: s.profile, Type: platform.ResSecurityGroup}, sgResource(sg), cfg.TTLFor(platform.ResSecurityGroup))
}

// refreshSG reads a group again and stores it.
func refreshSG(ctx context.Context, rt *app.Runtime, s *sgScope, id string) {
	found, err := s.c.FindSecurityGroups(ctx, s.region, id, "")
	if err != nil || len(found) != 1 {
		rt.Verbosef("re-read security group %s: %v", id, err)
		return
	}
	storeSG(ctx, rt, s, found[0])
}

// dropSG removes a group from the inventory.
func dropSG(ctx context.Context, rt *app.Runtime, profile, id string) {
	if db, err := rt.DB(); err == nil {
		_ = db.Delete(ctx, inventory.Set{Platform: platform.AWS, Profile: profile, Type: platform.ResSecurityGroup}, platform.ResSecurityGroup, id)
	}
}

// parseRules parses the --rule values, dropping repeated ones.
func parseRules(specs []string, required bool) ([]platform.IngressRule, error) {
	if len(specs) == 0 && required {
		return nil, app.UsageErrf("at least one --rule is required (format %s)", platform.RuleFormat)
	}
	rules, err := platform.ParseIngressRules(specs)
	if err != nil {
		return nil, err
	}
	for _, r := range rules {
		if _, err := toIpPermission(r, ""); err != nil {
			return nil, err
		}
	}
	return rules, nil
}

// ruleBatch runs one AddIngressRules or RemoveIngressRules for all the rule
// steps of a plan: the first step that runs sends the batch, every step
// reports its own rule.
type ruleBatch struct {
	run  func(ctx context.Context) ([]platform.RuleOutcome, error)
	done bool
	out  []platform.RuleOutcome
	err  error
}

func (b *ruleBatch) outcome(ctx context.Context, r platform.IngressRule) (platform.RuleOutcome, error) {
	if !b.done {
		b.done = true
		b.out, b.err = b.run(ctx)
	}
	for _, o := range b.out {
		if o.Rule.Key() == r.Key() {
			return o, nil
		}
	}
	if b.err != nil {
		return platform.RuleOutcome{}, b.err
	}
	return platform.RuleOutcome{}, fmt.Errorf("internal error: no outcome for rule %s", r)
}

// addRuleSteps adds the rule rows of create, ensure and rule add: present
// rules are unchanged; the missing ones are added in one batch to the
// group groupID returns (the id of a group created by an earlier step).
func addRuleSteps(plan *platform.Plan, rt *app.Runtime, s *sgScope, resource string, groupID func() string, missing, present []platform.IngressRule, desc string) {
	for _, r := range present {
		plan.Add(platform.Step{Resource: resource, Action: platform.Unchanged, Desc: r.String()})
	}
	batch := &ruleBatch{run: func(ctx context.Context) ([]platform.RuleOutcome, error) {
		id := groupID()
		out, err := s.c.AddIngressRules(ctx, s.region, id, missing, desc)
		refreshSG(ctx, rt, s, id)
		return out, err
	}}
	for _, r := range missing {
		plan.Add(platform.Step{Resource: resource, Action: platform.Created, Desc: r.String(), Apply: func(ctx context.Context) (platform.Change, error) {
			o, err := batch.outcome(ctx, r)
			if err != nil {
				return platform.Change{}, err
			}
			if !o.Done {
				return platform.Change{Action: platform.Unchanged, Detail: r.String() + " (already present)"}, nil
			}
			return platform.Change{ID: o.ID, Detail: r.String()}, nil
		}})
	}
}

// sgDetail is the output of `security-group get`.
type sgDetail struct {
	ID          string                       `json:"id" yaml:"id"`
	Name        string                       `json:"name" yaml:"name"`
	VPC         string                       `json:"vpc_id" yaml:"vpc_id"`
	Description string                       `json:"description" yaml:"description"`
	Profile     string                       `json:"profile" yaml:"profile"`
	Region      string                       `json:"region" yaml:"region"`
	Tags        map[string]string            `json:"tags" yaml:"tags"`
	Ingress     []platform.SecurityGroupRule `json:"ingress" yaml:"ingress"`
	Instances   []string                     `json:"instances" yaml:"instances"`
}

func sgDetailGrid(d sgDetail) output.Grid {
	g := output.Grid{Rows: [][]string{
		{"ID", d.ID, "NAME", d.Name},
		{"VPC", d.VPC, "PROFILE", d.Profile},
		{"REGION", d.Region},
		{"DESCRIPTION", d.Description},
		{"INSTANCES", orNone(strings.Join(d.Instances, ", "))},
		{"INGRESS"},
	}}
	if len(d.Ingress) == 0 {
		g.Rows = append(g.Rows, []string{"  (none)"})
		return g
	}
	g.Rows = append(g.Rows, []string{"  PROTO", "PORTS", "SOURCE", "DESCRIPTION"})
	for _, r := range d.Ingress {
		g.Rows = append(g.Rows, []string{"  " + r.Protocol, r.Ports(), r.Source, r.Description})
	}
	return g
}

func sgListGrid(sgs []platform.SecurityGroup) output.Grid {
	g := output.Grid{Headers: []string{"ID", "NAME", "VPC", "RULES", "DESCRIPTION"}, Empty: "no security groups"}
	for _, sg := range sgs {
		g.Rows = append(g.Rows, []string{sg.ID, sg.Name, sg.VPC, fmt.Sprint(len(sg.Ingress)), sg.Description})
	}
	return g
}

// ---------------------------------------------------------------- list

func sgListCmd(rt *app.Runtime) *cobra.Command {
	var vpc, name, instance, region string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List security groups (the profile's region is cached locally)",
		Long: `List the security groups of the profile's region; the list is cached in the
local inventory. --region, --vpc and --name ask AWS directly: --vpc keeps the
groups of one VPC, --name the groups of that name (* is a wildcard).
--instance lists the groups attached to an instance, found like
instance get finds it. RULES counts the ingress rules, one per source.`,
		Example: "  polyctl aws ec2 security-group list --vpc vpc-0abc -o json\n  polyctl aws ec2 security-group list --instance site-xz7",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			filter := platform.SecurityGroupFilter{VPC: vpc, Name: name}
			var sgs []platform.SecurityGroup
			var where string
			switch {
			case instance != "":
				l, err := resolveInstance(ctx, rt, instance, region, false)
				if err != nil {
					return err
				}
				where = "aws/" + l.profile + "/" + l.region + " (instance " + l.name() + ")"
				if filter.IDs = instanceGroupIDs(l.inst); len(filter.IDs) > 0 {
					if sgs, err = l.c.ListSecurityGroups(ctx, l.region, filter); err != nil {
						return err
					}
				}
			case region != "" || vpc != "" || name != "":
				if rt.Flags.Offline {
					return app.ErrOffline
				}
				c, prof, err := openClient(ctx, rt)
				if err != nil {
					return err
				}
				r := c.regionOr(region)
				where = "aws/" + prof.Name + "/" + r
				if sgs, err = c.ListSecurityGroups(ctx, r, filter); err != nil {
					return err
				}
			default:
				profName, err := rt.ProfileFor(platform.AWS)
				if err != nil {
					return err
				}
				where = "aws/" + profName
				set := inventory.Set{Platform: platform.AWS, Profile: profName, Type: platform.ResSecurityGroup}
				rows, cached, err := rt.EnsureSet(ctx, set, func(ctx context.Context) ([]platform.Resource, error) {
					c, _, err := openClient(ctx, rt)
					if err != nil {
						return nil, err
					}
					return c.securityGroupResources(ctx, c.region)
				})
				if err != nil {
					return err
				}
				for _, r := range rows {
					var sg platform.SecurityGroup
					if err := r.Decode(&sg); err != nil {
						return fmt.Errorf("decode cached security group %s: %w", r.ID, err)
					}
					sgs = append(sgs, sg)
				}
				slices.SortFunc(sgs, func(a, b platform.SecurityGroup) int {
					if c := strings.Compare(a.Name, b.Name); c != 0 {
						return c
					}
					return strings.Compare(a.ID, b.ID)
				})
				if cached {
					rt.Infof("%d security group(s) via %s (local inventory)", len(sgs), where)
				}
			}
			if sgs == nil {
				sgs = []platform.SecurityGroup{}
			}
			if len(sgs) == 0 {
				rt.Infof("no security groups via %s", where)
			}
			return rt.Render(sgs, func() output.Grid { return sgListGrid(sgs) })
		},
	}
	cmd.Flags().StringVar(&vpc, "vpc", "", "only the groups of this VPC")
	cmd.Flags().StringVar(&name, "name", "", "only the groups of this name (* is a wildcard)")
	cmd.Flags().StringVar(&instance, "instance", "", "only the groups attached to this instance (Name tag or id)")
	cmd.Flags().StringVar(&region, "region", "", "list another region (bypasses the local inventory)")
	return cmd
}

// ----------------------------------------------------------------- get

func sgGetCmd(rt *app.Runtime) *cobra.Command {
	var vpc, region string
	cmd := &cobra.Command{
		Use:   "get <sg-id|name>",
		Short: "Show a security group, its ingress rules and its instances",
		Example: `  polyctl aws ec2 security-group get web --vpc vpc-0abc
  polyctl aws ec2 security-group get sg-0123456789abcdef0 -o json`,
		Args: app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			s, sg, err := sgTarget(ctx, rt, args, region, vpc, nil)
			if err != nil {
				return err
			}
			storeSG(ctx, rt, s, *sg)
			insts, err := s.c.SecurityGroupInstances(ctx, s.region, sg.ID)
			if err != nil {
				return err
			}
			if insts == nil {
				insts = []string{}
			}
			d := sgDetail{ID: sg.ID, Name: sg.Name, VPC: sg.VPC, Description: sg.Description, Profile: s.profile, Region: s.region,
				Tags: sg.Tags, Ingress: sg.Ingress, Instances: insts}
			return rt.Render(d, func() output.Grid { return sgDetailGrid(d) })
		},
	}
	cmd.Flags().StringVar(&vpc, "vpc", "", "VPC to look the name up in (default: defaults.aws.vpc_id, else every VPC)")
	cmd.Flags().StringVar(&region, "region", "", "region of the group (default: the profile's region)")
	return cmd
}

// --------------------------------------------------------- create/ensure

// sgWriteFlags are the flags create and ensure share.
type sgWriteFlags struct {
	vpc, region, description, ruleDescription string
	rules                                     []string
}

func (f *sgWriteFlags) add(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.vpc, "vpc", "", "VPC of the group (default: defaults.aws.vpc_id)")
	cmd.Flags().StringArrayVar(&f.rules, "rule", nil, "ingress rule <protocol>:<port|from-to|alias|all>:<source> (repeatable)")
	cmd.Flags().StringVar(&f.description, "description", "", `description of a new group (default "auto created <name>"; AWS cannot change it later)`)
	cmd.Flags().StringVar(&f.ruleDescription, "rule-description", "", "description of every rule this command adds (never compared)")
	cmd.Flags().StringVar(&f.region, "region", "", "region of the group (default: the profile's region)")
}

// check validates the name, the rules and the descriptions.
func (f *sgWriteFlags) check(name string) ([]platform.IngressRule, string, error) {
	if err := checkSGName(name); err != nil {
		return nil, "", err
	}
	rules, err := parseRules(f.rules, false)
	if err != nil {
		return nil, "", err
	}
	desc := f.description
	if desc == "" {
		desc = "auto created " + name
	}
	if err := checkAWSText("--description", desc); err != nil {
		return nil, "", err
	}
	if err := checkAWSText("--rule-description", f.ruleDescription); err != nil {
		return nil, "", err
	}
	return rules, desc, nil
}

// sgCreateStep is the step that creates the group. With ensure, a group
// created meanwhile by someone else (InvalidGroup.Duplicate) is looked up
// and reported unchanged; create reports the duplicate as an error.
func sgCreateStep(rt *app.Runtime, s *sgScope, name, vpc, desc string, ensure bool, groupID *string) (platform.Step, error) {
	var tags map[string]string
	if !rt.DryRun() {
		var err error
		if tags, err = sgTags(rt, s.profile, name); err != nil {
			return platform.Step{}, err
		}
	}
	return platform.Step{Resource: "security-group/" + name, Action: platform.Created, Desc: fmt.Sprintf("%s, description %q", vpc, desc),
		Apply: func(ctx context.Context) (platform.Change, error) {
			id, err := s.c.CreateSecurityGroup(ctx, platform.SecurityGroupSpec{Region: s.region, Name: name, Description: desc, VPC: vpc, Tags: tags})
			if platform.HasErrorCode(err, errGroupDuplicate) {
				if !ensure {
					return platform.Change{}, fmt.Errorf("security group %q already exists in %s; use `polyctl aws ec2 security-group ensure` to reuse it: %w", name, vpc, err)
				}
				sg, ferr := findSG(ctx, rt, s, name, vpc)
				if ferr != nil || sg == nil {
					return platform.Change{}, err
				}
				*groupID = sg.ID
				storeSG(ctx, rt, s, *sg)
				return platform.Change{Action: platform.Unchanged, ID: sg.ID, Detail: "created meanwhile by someone else"}, nil
			}
			if err != nil {
				return platform.Change{}, err
			}
			*groupID = id
			refreshSG(ctx, rt, s, id)
			return platform.Change{ID: id}, nil
		}}, nil
}

func sgCreateCmd(rt *app.Runtime) *cobra.Command {
	var f sgWriteFlags
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a security group with ingress rules",
		Long: `Create the security group <name> in --vpc (default: defaults.aws.vpc_id; one
of the two is required) with the --rule ingress rules. A group of that name
in the VPC is an error (exit code 1): use ensure to reuse it. The group is
tagged Name=<name>, polyctl:managed=true and the tags of defaults.aws.tags.`,
		Example: `  polyctl aws ec2 security-group create web --vpc vpc-0abc --rule tcp:http:0.0.0.0/0 --rule tcp:https:0.0.0.0/0`,
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name := app.Arg(args, 0)
			// A missing name is asked once the VPC is known; the rest is
			// checked first.
			rules, desc, err := f.check(nameOr(name, "x"))
			if err != nil {
				return err
			}
			s, err := openSGScope(ctx, rt, name, f.region)
			if err != nil {
				return err
			}
			vpc, err := rt.Setting(s.profile, platform.AWS, "vpc_id", f.vpc)
			if err != nil {
				return err
			}
			if vpc == "" {
				if vpc, err = pickVPC(ctx, rt, s.c, s.region, func() error {
					_, err := rt.RequireSetting(s.profile, platform.AWS, "vpc_id", "vpc", "")
					return err
				}); err != nil {
					return err
				}
			}
			if name == "" {
				if name, err = askSGName(ctx, rt, s, vpc); err != nil {
					return err
				}
				if rules, desc, err = f.check(name); err != nil {
					return err
				}
			}
			if sg, err := findSG(ctx, rt, s, name, vpc); err != nil {
				return err
			} else if sg != nil {
				return fmt.Errorf("security group %q already exists in %s (%s, %s): use `polyctl aws ec2 security-group ensure %s` to reuse it", name, vpc, sg.ID, s.where(), name)
			}
			var groupID string
			var plan platform.Plan
			step, err := sgCreateStep(rt, s, name, vpc, desc, false, &groupID)
			if err != nil {
				return err
			}
			plan.Add(step)
			addRuleSteps(&plan, rt, s, "security-group/"+name+"/rule", func() string { return groupID }, rules, nil, f.ruleDescription)
			return rt.Ensure(ctx, "aws.ec2.security-group.create", s.target(), &plan)
		},
	}
	f.add(cmd)
	return cmd
}

func sgEnsureCmd(rt *app.Runtime) *cobra.Command {
	var f sgWriteFlags
	var instance string
	cmd := &cobra.Command{
		Use:   "ensure <name>",
		Short: "Make sure a security group exists, holds the rules and is attached to an instance",
		Long: `Make sure the security group <name> exists, holds the --rule ingress rules and,
with --instance, is attached to that instance. Running it again changes
nothing.

- The VPC is --vpc, else the instance's VPC, else defaults.aws.vpc_id; none
  is a usage error (exit code 2). With --instance the group must be in the
  instance's VPC: another --vpc is a usage error.
- A missing group is created (description "auto created <name>" unless
  --description; tags as for create). An existing one is used as it is: its
  description cannot be changed.
- Missing rules are added in one call; rules present are unchanged, whatever
  their description. Rules are never removed (use rule remove).
- --instance (Name tag or id, found like instance get finds it, in every
  selected account) attaches the group, keeping every group the instance
  already has. An instance that already has 5 groups (the default quota) is
  an error before anything is written, and so is an instance with several
  network interfaces, which is not supported.`,
		Example: `  polyctl aws ec2 security-group ensure web --instance site-xz7 \
    --rule tcp:http:0.0.0.0/0 --rule tcp:https:0.0.0.0/0 --rule tcp:ssh:10.0.0.0/8
  polyctl aws ec2 security-group ensure existing-sg --instance site-xz7 --dry-run`,
		Args: app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name := app.Arg(args, 0)
			// A missing name is asked once the VPC is known; the rest is
			// checked first.
			rules, desc, err := f.check(nameOr(name, "x"))
			if err != nil {
				return err
			}
			var s *sgScope
			var l *locatedInstance
			vpc := f.vpc
			if instance != "" {
				if l, err = resolveInstance(ctx, rt, instance, f.region, false); err != nil {
					return err
				}
				s = &sgScope{c: l.c, profile: l.profile, region: l.region}
				instVPC := awssdk.ToString(l.inst.VpcId)
				if instVPC == "" {
					return fmt.Errorf("instance %s is in no VPC; security groups cannot be attached to it", instanceLabel(l.inst))
				}
				if vpc != "" && vpc != instVPC {
					return app.UsageErrf("--vpc %s differs from the VPC of instance %s (%s): a security group can only be attached to instances of its own VPC", vpc, instanceLabel(l.inst), instVPC)
				}
				vpc = instVPC
			} else if s, err = openSGScope(ctx, rt, name, f.region); err != nil {
				return err
			}
			if vpc == "" {
				if vpc, err = rt.Setting(s.profile, platform.AWS, "vpc_id", ""); err != nil {
					return err
				}
				if vpc == "" {
					missing := func() error {
						return app.UsageErrf("no VPC for security group %q: pass --vpc <vpc-id> or --instance <name|id>, or set defaults.aws.vpc_id in config.yaml", name)
					}
					if vpc, err = pickVPC(ctx, rt, s.c, s.region, missing); err != nil {
						return err
					}
				}
			}
			if name == "" {
				if name, err = sgEnsureName(ctx, rt, s, vpc); err != nil {
					return err
				}
				if rules, desc, err = f.check(name); err != nil {
					return err
				}
			}
			sg, err := findSG(ctx, rt, s, name, vpc)
			if err != nil {
				return err
			}
			var current []string
			if l != nil {
				current = instanceGroupIDs(l.inst)
				attached := sg != nil && slices.Contains(current, sg.ID)
				if !attached {
					if len(l.inst.NetworkInterfaces) > 1 {
						return fmt.Errorf("%w: instance %s has %d network interfaces; attaching a security group to an instance with several network interfaces is not supported (attach it to the network interface in AWS)", platform.ErrNotSupported, instanceLabel(l.inst), len(l.inst.NetworkInterfaces))
					}
					if len(current) >= maxGroupsPerInterface {
						return fmt.Errorf("instance %s already has %d security groups (%s), the default quota per network interface; detach one first or raise the quota", instanceLabel(l.inst), len(current), strings.Join(current, ", "))
					}
				}
			}

			resource := "security-group/" + name
			var groupID string
			var plan platform.Plan
			missing := rules
			var present []platform.IngressRule
			if sg != nil {
				groupID = sg.ID
				if f.description != "" && f.description != sg.Description {
					rt.Infof("note: security group %s keeps its description %q (AWS cannot change it)", sg.ID, sg.Description)
				}
				plan.Add(platform.Step{Resource: resource, Action: platform.Unchanged, ID: sg.ID})
				if missing, present, err = s.c.MissingIngressRules(*sg, rules); err != nil {
					return err
				}
			} else {
				step, err := sgCreateStep(rt, s, name, vpc, desc, true, &groupID)
				if err != nil {
					return err
				}
				plan.Add(step)
			}
			addRuleSteps(&plan, rt, s, resource+"/rule", func() string { return groupID }, missing, present, f.ruleDescription)
			if l != nil {
				keep := "none"
				if len(current) > 0 {
					keep = strings.Join(current, ", ")
				}
				if sg != nil && slices.Contains(current, sg.ID) {
					plan.Add(platform.Step{Resource: l.resource(), Action: platform.Unchanged, ID: l.id(), Desc: "already attached " + sg.ID})
				} else {
					label := platform.Pending
					if sg != nil {
						label = sg.ID
					}
					plan.Add(platform.Step{Resource: l.resource(), Action: platform.Updated, ID: l.id(), Desc: fmt.Sprintf("attach %s (keep: %s)", label, keep),
						Apply: func(ctx context.Context) (platform.Change, error) {
							if slices.Contains(current, groupID) {
								// A group created meanwhile by someone else
								// may be attached already.
								return platform.Change{Action: platform.Unchanged, Detail: "already attached " + groupID}, nil
							}
							groups := append(slices.Clone(current), groupID)
							if err := s.c.SetInstanceSecurityGroups(ctx, s.region, l.id(), groups); err != nil {
								return platform.Change{}, err
							}
							l.reread(ctx, rt)
							return platform.Change{Detail: fmt.Sprintf("attached %s (kept %d existing)", groupID, len(current))}, nil
						}})
				}
			}
			return rt.Ensure(ctx, "aws.ec2.security-group.ensure", s.target(), &plan)
		},
	}
	f.add(cmd)
	cmd.Flags().StringVar(&instance, "instance", "", "attach the group to this instance (Name tag or id); its VPC is the group's")
	return cmd
}

// -------------------------------------------------------------- delete

func sgDeleteCmd(rt *app.Runtime) *cobra.Command {
	var vpc, region string
	cmd := &cobra.Command{
		Use:   "delete <sg-id|name>",
		Short: "Delete a security group (asks first)",
		Long: `Delete a security group. Its name, VPC and the instances it is attached to are
shown first, then a confirmation is asked (default no; --yes skips it, and
the non-interactive flow needs --yes). A group still attached to an
instance or network interface, or used as the source of another group's
rule, is not deleted (exit code 1): detach it or remove the reference
first. The default group of a VPC cannot be deleted. A group that is gone
by the time it is deleted is reported unchanged.`,
		Example: "  polyctl aws ec2 security-group delete web --vpc vpc-0abc --yes",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			// The default group of a VPC cannot be deleted: it is never
			// offered.
			s, sg, err := sgTarget(ctx, rt, args, region, vpc, func(g platform.SecurityGroup) bool { return g.Name != "default" })
			if err != nil {
				return err
			}
			if sg.Name == "default" {
				return fmt.Errorf("security group %s is the default group of %s, which AWS does not let anybody delete", sg.ID, sg.VPC)
			}
			insts, err := s.c.SecurityGroupInstances(ctx, s.region, sg.ID)
			if err != nil {
				return err
			}
			rt.Infof("security group %s in %s", sg.Name, s.where())
			rt.Infof("  id         %s", sg.ID)
			rt.Infof("  vpc        %s", sg.VPC)
			rt.Infof("  rules      %d ingress", len(sg.Ingress))
			rt.Infof("  instances  %s", orNone(strings.Join(insts, ", ")))
			if len(insts) > 0 {
				rt.Infof("warning: the group is attached to %d instance(s); AWS refuses to delete it until it is detached", len(insts))
			}
			change := platform.Change{Resource: "security-group/" + sg.Name, Action: platform.Deleted, ID: sg.ID}
			if done, err := rt.WouldWrite(s.target(), change); done || err != nil {
				return err
			}
			ok, err := rt.Confirm(ctx, fmt.Sprintf("Delete security group %s (%s)?", sg.Name, sg.ID), false)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("%w: cancelled; security group %s was not deleted", platform.ErrNothingToDo, sg.ID)
			}
			if err := s.c.DeleteSecurityGroup(ctx, s.region, sg.ID); err != nil {
				if !platform.HasErrorCode(err, errGroupNotFound) {
					return err
				}
				change.Action, change.Detail = platform.Unchanged, "already deleted"
			}
			dropSG(ctx, rt, s.profile, sg.ID)
			return rt.RenderReport(platform.Report{Target: s.target(), Changes: []platform.Change{change}})
		},
	}
	cmd.Flags().StringVar(&vpc, "vpc", "", "VPC to look the name up in (default: defaults.aws.vpc_id, else every VPC)")
	cmd.Flags().StringVar(&region, "region", "", "region of the group (default: the profile's region)")
	return cmd
}

// ---------------------------------------------------------------- rules

func sgRuleAddCmd(rt *app.Runtime) *cobra.Command {
	var vpc, region, ruleDesc string
	var specs []string
	cmd := &cobra.Command{
		Use:   "add <sg-id|name>",
		Short: "Add ingress rules to a security group (present ones are unchanged)",
		Long: `Add the --rule ingress rules to an existing security group (a missing group is
exit code 4). Rules already present, whatever their description, are
unchanged; the others are added in one call, each with --rule-description.`,
		Example: `  polyctl aws ec2 security-group rule add sg-0123456789abcdef0 --rule icmp:all:::/0 --rule-description "ping v6"`,
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			rules, err := parseRules(specs, !rt.Interactive())
			if err != nil {
				return err
			}
			if err := checkAWSText("--rule-description", ruleDesc); err != nil {
				return err
			}
			s, sg, err := sgTarget(ctx, rt, args, region, vpc, nil)
			if err != nil {
				return err
			}
			if len(rules) == 0 {
				picked, err := askRules(rt, s.c, *sg)
				if err != nil {
					return err
				}
				if rules, err = parseRules(picked, true); err != nil {
					return err
				}
			}
			missing, present, err := s.c.MissingIngressRules(*sg, rules)
			if err != nil {
				return err
			}
			var plan platform.Plan
			addRuleSteps(&plan, rt, s, "security-group/"+sg.Name+"/rule", func() string { return sg.ID }, missing, present, ruleDesc)
			return rt.Ensure(ctx, "aws.ec2.security-group.rule.add", s.target(), &plan)
		},
	}
	cmd.Flags().StringArrayVar(&specs, "rule", nil, "ingress rule <protocol>:<port|from-to|alias|all>:<source> (repeatable, required)")
	cmd.Flags().StringVar(&ruleDesc, "rule-description", "", "description of every rule added (never compared)")
	cmd.Flags().StringVar(&vpc, "vpc", "", "VPC to look the name up in (default: defaults.aws.vpc_id, else every VPC)")
	cmd.Flags().StringVar(&region, "region", "", "region of the group (default: the profile's region)")
	return cmd
}

func sgRuleRemoveCmd(rt *app.Runtime) *cobra.Command {
	var vpc, region string
	var specs []string
	cmd := &cobra.Command{
		Use:   "remove <sg-id|name>",
		Short: "Remove ingress rules from a security group (asks first)",
		Long: `Remove the --rule ingress rules from a security group, compared by protocol,
ports and source (descriptions do not matter). Rules that are not there are
reported unchanged. The rules to remove are shown and a confirmation is
asked (default no; --yes skips it, and the non-interactive flow needs
--yes); nothing to remove asks nothing.`,
		Example: "  polyctl aws ec2 security-group rule remove web --vpc vpc-0abc --rule tcp:22:10.0.0.0/8 --yes",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			rules, err := parseRules(specs, !rt.Interactive())
			if err != nil {
				return err
			}
			s, sg, err := sgTarget(ctx, rt, args, region, vpc, nil)
			if err != nil {
				return err
			}
			if len(rules) == 0 {
				if rules, err = pickRules(rt, *sg); err != nil {
					return err
				}
			}
			absent, present, err := s.c.MissingIngressRules(*sg, rules)
			if err != nil {
				return err
			}
			resource := "security-group/" + sg.Name + "/rule"
			var plan platform.Plan
			for _, r := range absent {
				plan.Add(platform.Step{Resource: resource, Action: platform.Unchanged, Desc: r.String() + " (not present)"})
			}
			batch := &ruleBatch{run: func(ctx context.Context) ([]platform.RuleOutcome, error) {
				out, err := s.c.RemoveIngressRules(ctx, s.region, sg.ID, present)
				refreshSG(ctx, rt, s, sg.ID)
				return out, err
			}}
			for _, r := range present {
				plan.Add(platform.Step{Resource: resource, Action: platform.Deleted, Desc: r.String(), Apply: func(ctx context.Context) (platform.Change, error) {
					o, err := batch.outcome(ctx, r)
					if err != nil {
						return platform.Change{}, err
					}
					if !o.Done {
						return platform.Change{Action: platform.Unchanged, Detail: r.String() + " (not present)"}, nil
					}
					return platform.Change{}, nil
				}})
			}
			if len(present) > 0 && !rt.DryRun() {
				rt.Infof("security group %s (%s) in %s: rules to remove", sg.Name, sg.ID, s.where())
				for _, r := range present {
					rt.Infof("  %s", r)
				}
				ok, err := rt.Confirm(ctx, fmt.Sprintf("Remove %d rule(s) from security group %s?", len(present), sg.ID), false)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("%w: cancelled; no rule of security group %s was removed", platform.ErrNothingToDo, sg.ID)
				}
			}
			return rt.Ensure(ctx, "aws.ec2.security-group.rule.remove", s.target(), &plan)
		},
	}
	cmd.Flags().StringArrayVar(&specs, "rule", nil, "ingress rule <protocol>:<port|from-to|alias|all>:<source> (repeatable, required)")
	cmd.Flags().StringVar(&vpc, "vpc", "", "VPC to look the name up in (default: defaults.aws.vpc_id, else every VPC)")
	cmd.Flags().StringVar(&region, "region", "", "region of the group (default: the profile's region)")
	return cmd
}
