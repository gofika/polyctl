package aliyun

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// newSecurityGroupCmd is `aliyun ecs security-group`: list, get, create,
// delete, ensure and the ingress rules (rule add, rule remove).
func newSecurityGroupCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "security-group",
		Short: "ECS security groups (VPC type) and their ingress rules",
		Long: `ECS security groups and their ingress rules. A security group belongs to one
region (--region, the profile's region by default) and one VPC; polyctl only
creates VPC security groups, and never without a VPC.

A security group is named by its id (sg-...) or by its name. Alibaba Cloud
does not keep names unique, not even within a VPC: a name held by several
groups is ambiguous (exit code 5); pass the id, or --vpc.

Rules are written <protocol>:<port|from-to|alias|all>:<source>:
  protocol  tcp, udp, icmp or all
  port      80, 8000-8999, an alias (ssh, http, https, mysql, postgres, ...),
            all (every port: icmp:all, all:all, and tcp:all / udp:all for 1-65535)
  source    an IPv4 or IPv6 CIDR (a bare address gets /32 or /128) or a
            security group id of the same account
Examples: tcp:443:0.0.0.0/0, tcp:ssh:10.0.0.0/8, icmp:all:0.0.0.0/0,
tcp:8000-8999:sg-0123456789abcdef. Rules are written with the policy accept
and --priority (1-100, default 1).

Rules are compared by protocol, ports, source and policy; their priority
and description never count. Only ingress rules are managed.`,
	}
	rule := &cobra.Command{Use: "rule", Short: "Ingress rules of a security group"}
	rule.AddCommand(sgRuleAddCmd(rt), sgRuleRemoveCmd(rt))
	cmd.AddCommand(sgListCmd(rt), sgGetCmd(rt), sgCreateCmd(rt), sgDeleteCmd(rt), sgEnsureCmd(rt), rule)
	return cmd
}

// ecsScope is the account and region an ECS command works in.
type ecsScope struct {
	c       *client
	profile string
	region  string
}

func (s *ecsScope) target() platform.Target {
	return platform.Target{Platform: platform.Aliyun, Profile: s.profile, Region: s.region}
}

func (s *ecsScope) where() string { return "aliyun/" + s.profile + "/" + s.region }

// openECSScope opens the selected profile in region (its own by default).
func openECSScope(ctx context.Context, rt *app.Runtime, region string) (*ecsScope, error) {
	c, p, err := openClient(rt, ctx)
	if err != nil {
		return nil, err
	}
	return &ecsScope{c: c, profile: p.Name, region: c.regionOr(region)}, nil
}

// resolveVPC returns the VPC ref names (an id or a name) in the scope's
// region: a missing one is not found (exit code 4), a name several VPCs
// hold is ambiguous (exit code 5).
func resolveVPC(ctx context.Context, s *ecsScope, ref string) (vpcInfo, error) {
	found, err := s.c.findVPCs(ctx, s.region, ref)
	if err != nil {
		return vpcInfo{}, err
	}
	switch len(found) {
	case 0:
		return vpcInfo{}, fmt.Errorf("%w: VPC %q in %s", platform.ErrNotFound, ref, s.where())
	case 1:
		return found[0], nil
	}
	var ids []string
	for _, v := range found {
		ids = append(ids, v.ID)
	}
	return vpcInfo{}, &app.AmbiguousError{What: fmt.Sprintf("VPC %q in %s", ref, s.where()), Candidates: ids, Hint: "pass the VPC id (vpc-...)"}
}

// lookupVPCFilter resolves the --vpc of a lookup ("" = every VPC).
func lookupVPCFilter(ctx context.Context, s *ecsScope, ref, flag string) (string, error) {
	if flag == "" || looksLikeGroupID(ref) {
		return "", nil
	}
	v, err := resolveVPC(ctx, s, flag)
	if err != nil {
		return "", err
	}
	return v.ID, nil
}

// findSG returns the group ref names in the scope, nil when there is none.
func findSG(ctx context.Context, s *ecsScope, ref, vpc string) (*securityGroup, error) {
	if strings.TrimSpace(ref) == "" {
		return nil, app.UsageErrf("the security group name or id is empty")
	}
	found, err := s.c.findSecurityGroups(ctx, s.region, ref, vpc)
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
	hint := "Alibaba Cloud lets several groups share a name; pass the security group id"
	if vpc == "" {
		hint += " or --vpc <vpc>"
	}
	return nil, &app.AmbiguousError{What: fmt.Sprintf("security group %q in %s", ref, s.where()), Candidates: names, Hint: hint}
}

// resolveSG returns the group ref names; a missing one is not found.
func resolveSG(ctx context.Context, s *ecsScope, ref, vpcFlag string) (*securityGroup, error) {
	vpc, err := lookupVPCFilter(ctx, s, ref, vpcFlag)
	if err != nil {
		return nil, err
	}
	sg, err := findSG(ctx, s, ref, vpc)
	if err != nil {
		return nil, err
	}
	if sg == nil {
		in := s.where()
		if vpc != "" {
			in += " (" + vpc + ")"
		}
		return nil, fmt.Errorf("%w: security group %q in %s", platform.ErrNotFound, ref, in)
	}
	return sg, nil
}

// checkSGName refuses a name that would be read as an id, or that is
// longer than Alibaba Cloud accepts.
func checkSGName(name string) error {
	switch {
	case strings.TrimSpace(name) == "":
		return app.UsageErrf("the security group name is empty")
	case strings.HasPrefix(name, "sg-"):
		return app.UsageErrf("security group name %q: names may not start with sg- (that is how ids are written)", name)
	case len([]rune(name)) > sgNameMaxLength:
		return app.UsageErrf("security group name %q is longer than %d characters", name, sgNameMaxLength)
	}
	return nil
}

// storeSG records a group in the inventory.
func storeSG(ctx context.Context, rt *app.Runtime, s *ecsScope, sg securityGroup) {
	if sg.ID == "" {
		return
	}
	db, err := rt.DB()
	if err != nil {
		return
	}
	cfg, _ := rt.Config()
	_ = db.Upsert(ctx, inventory.Set{Platform: platform.Aliyun, Profile: s.profile, Type: platform.ResSecurityGroup}, sg.resource(), cfg.TTLFor(platform.ResSecurityGroup))
}

// refreshSG reads a group again (its rule count changed) and stores it.
func refreshSG(ctx context.Context, rt *app.Runtime, s *ecsScope, id string) {
	found, err := s.c.findSecurityGroups(ctx, s.region, id, "")
	if err != nil || len(found) != 1 {
		rt.Verbosef("re-read security group %s: %v", id, err)
		return
	}
	storeSG(ctx, rt, s, found[0])
}

// dropSG removes a group from the inventory.
func dropSG(ctx context.Context, rt *app.Runtime, profile, id string) {
	if db, err := rt.DB(); err == nil {
		_ = db.Delete(ctx, inventory.Set{Platform: platform.Aliyun, Profile: profile, Type: platform.ResSecurityGroup}, platform.ResSecurityGroup, id)
	}
}

// parseRules parses the --rule values, dropping repeated ones.
func parseRules(specs []string, required bool) ([]platform.IngressRule, error) {
	if len(specs) == 0 && required {
		return nil, app.UsageErrf("at least one --rule is required (format %s)", platform.RuleFormat)
	}
	return platform.ParseIngressRules(specs)
}

// once runs a batch call for the first step that needs it; the other steps
// of the batch share its result.
type once struct {
	done bool
	err  error
}

func (o *once) do(ctx context.Context, fn func(ctx context.Context) error) error {
	if !o.done {
		o.done = true
		o.err = fn(ctx)
	}
	return o.err
}

// addRuleSteps adds the rule rows of ensure and rule add: present rules
// are unchanged; the missing ones are added in one AuthorizeSecurityGroup
// call (all or nothing) to the group groupID returns (the id of a group an
// earlier step created, which created reports).
func addRuleSteps(plan *platform.Plan, rt *app.Runtime, s *ecsScope, resource string, groupID func() string, created func() bool,
	missing, present []platform.IngressRule, priority int, desc string) {
	for _, r := range present {
		plan.Add(platform.Step{Resource: resource, Action: platform.Unchanged, Desc: aliRuleString(r)})
	}
	batch := &once{}
	for _, r := range missing {
		plan.Add(platform.Step{Resource: resource, Action: platform.Created, Desc: aliRuleString(r), Apply: func(ctx context.Context) (platform.Change, error) {
			err := batch.do(ctx, func(ctx context.Context) error {
				id := groupID()
				err := s.c.authorizeIngress(ctx, s.region, id, missing, priority, desc, created())
				refreshSG(ctx, rt, s, id)
				return err
			})
			if err != nil {
				return platform.Change{}, err
			}
			return platform.Change{Detail: aliRuleString(r)}, nil
		}})
	}
}

// sgDetail is the output of `security-group get`.
type sgDetail struct {
	Name        string   `json:"name" yaml:"name"`
	ID          string   `json:"id" yaml:"id"`
	VPC         string   `json:"vpc_id" yaml:"vpc_id"`
	Region      string   `json:"region" yaml:"region"`
	Type        string   `json:"type" yaml:"type"`
	Description string   `json:"description" yaml:"description"`
	Profile     string   `json:"profile" yaml:"profile"`
	Rules       []sgRule `json:"rules" yaml:"rules"`
}

func sgDetailGrid(d sgDetail) output.Grid {
	g := output.Grid{Rows: [][]string{
		{"NAME", d.Name, "ID", d.ID},
		{"VPC", d.VPC, "REGION", d.Region},
		{"TYPE", d.Type, "PROFILE", d.Profile},
		{"DESCRIPTION", d.Description},
		{"INGRESS"},
	}}
	if len(d.Rules) == 0 {
		g.Rows = append(g.Rows, []string{"  (none)"})
		return g
	}
	g.Rows = append(g.Rows, []string{"  PROTO", "PORT", "SOURCE", "POLICY", "PRIORITY", "ID", "DESCRIPTION"})
	for _, r := range d.Rules {
		g.Rows = append(g.Rows, []string{"  " + r.Protocol, r.Port, r.Source, r.Policy, strconv.Itoa(r.Priority), r.ID, r.Description})
	}
	return g
}

func sgListGrid(sgs []securityGroup) output.Grid {
	g := output.Grid{Headers: []string{"NAME", "ID", "VPC", "RULES", "DESCRIPTION"}, Empty: "no security groups"}
	for _, sg := range sgs {
		g.Rows = append(g.Rows, []string{sg.Name, sg.ID, sg.VPC, strconv.Itoa(sg.RuleCount), sg.Description})
	}
	return g
}

// ---------------------------------------------------------------- list

func sgListCmd(rt *app.Runtime) *cobra.Command {
	var vpc, region string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the security groups of a region (cached locally)",
		Long: `List the security groups of the profile's region, or of --region; the list is
cached in the local inventory per region. --vpc keeps the groups of one VPC
(by id). RULES counts the rules of both directions, as ECS reports it.`,
		Example: "  polyctl aliyun ecs security-group list --vpc vpc-0abc -o json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			prof, err := rt.ProfileFor(platform.Aliyun)
			if err != nil {
				return err
			}
			region, err := resolveRegion(rt, prof, region)
			if err != nil {
				return err
			}
			set := inventory.Set{Platform: platform.Aliyun, Profile: prof, Type: platform.ResSecurityGroup, Scope: region}
			rows, cached, err := rt.EnsureSet(ctx, set, func(ctx context.Context) ([]platform.Resource, error) {
				c, err := openNamed(rt, ctx, prof)
				if err != nil {
					return nil, err
				}
				return c.securityGroupResources(ctx, region)
			})
			if err != nil {
				return err
			}
			sgs := []securityGroup{}
			for _, r := range rows {
				var sg securityGroup
				if err := r.Decode(&sg); err != nil {
					return fmt.Errorf("decode cached security group %s: %w", r.ID, err)
				}
				if vpc != "" && sg.VPC != vpc {
					continue
				}
				sgs = append(sgs, sg)
			}
			slices.SortFunc(sgs, func(a, b securityGroup) int {
				if c := strings.Compare(a.Name, b.Name); c != 0 {
					return c
				}
				return strings.Compare(a.ID, b.ID)
			})
			where := "aliyun/" + prof + "/" + region
			if vpc != "" {
				where += " (" + vpc + ")"
			}
			if len(sgs) == 0 {
				rt.Infof("no security groups in %s%s", where, cacheNote(cached))
			} else {
				rt.Infof("%d security group(s) in %s%s", len(sgs), where, cacheNote(cached))
			}
			return rt.Render(sgs, func() output.Grid { return sgListGrid(sgs) })
		},
	}
	cmd.Flags().StringVar(&vpc, "vpc", "", "only the groups of this VPC (id)")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

// ----------------------------------------------------------------- get

func sgGetCmd(rt *app.Runtime) *cobra.Command {
	var vpc, region string
	cmd := &cobra.Command{
		Use:   "get <name|id>",
		Short: "Show a security group and its ingress rules",
		Example: `  polyctl aliyun ecs security-group get web
  polyctl aliyun ecs security-group get sg-0123456789abcdef -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			s, err := openECSScope(ctx, rt, region)
			if err != nil {
				return err
			}
			sg, err := resolveSG(ctx, s, args[0], vpc)
			if err != nil {
				return err
			}
			rules, err := s.c.securityGroupRules(ctx, s.region, sg.ID)
			if err != nil {
				return err
			}
			storeSG(ctx, rt, s, *sg)
			if rules == nil {
				rules = []sgRule{}
			}
			d := sgDetail{Name: sg.Name, ID: sg.ID, VPC: sg.VPC, Region: s.region, Type: sg.Type, Description: sg.Description, Profile: s.profile, Rules: rules}
			return rt.Render(d, func() output.Grid { return sgDetailGrid(d) })
		},
	}
	cmd.Flags().StringVar(&vpc, "vpc", "", "VPC (id or name) to look the name up in (default: every VPC)")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

// -------------------------------------------------------- create/ensure

// sgCreateStep is the step that creates the group; it stores the new id in
// groupID and sets created.
func sgCreateStep(rt *app.Runtime, s *ecsScope, name, vpc, desc string, groupID *string, created *bool) platform.Step {
	return platform.Step{Resource: "security-group/" + name, Action: platform.Created, Desc: vpc,
		Apply: func(ctx context.Context) (platform.Change, error) {
			id, err := s.c.createSecurityGroup(ctx, s.region, name, vpc, desc)
			if err != nil {
				return platform.Change{}, err
			}
			*groupID, *created = id, true
			refreshSG(ctx, rt, s, id)
			return platform.Change{ID: id, Detail: id + " " + vpc}, nil
		}}
}

func sgCreateCmd(rt *app.Runtime) *cobra.Command {
	var vpc, region, desc string
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a security group in a VPC",
		Long: `Create the security group <name> in --vpc (an id or a name; required: a
security group is never created without a VPC, since Alibaba Cloud would
then create a default VPC on its own). A group of that name in the VPC is an
error (exit code 1): use ensure to reuse it. Add rules with rule add or
ensure.`,
		Example: `  polyctl aliyun ecs security-group create web --vpc cn-hongkong-vpc --description "web servers"`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name := args[0]
			if err := checkSGName(name); err != nil {
				return err
			}
			if vpc == "" {
				return app.UsageErrf("--vpc is required: a security group belongs to a VPC (pass its id or name)")
			}
			s, err := openECSScope(ctx, rt, region)
			if err != nil {
				return err
			}
			v, err := resolveVPC(ctx, s, vpc)
			if err != nil {
				return err
			}
			if sg, err := findSG(ctx, s, name, v.ID); err != nil {
				return err
			} else if sg != nil {
				return fmt.Errorf("security group %q already exists in %s (%s, %s): use `polyctl aliyun ecs security-group ensure %s` to reuse it", name, v.ID, sg.ID, s.where(), name)
			}
			var groupID string
			var created bool
			var plan platform.Plan
			plan.Add(sgCreateStep(rt, s, name, v.ID, desc, &groupID, &created))
			return rt.Ensure(ctx, "aliyun.ecs.security-group.create", s.target(), &plan)
		},
	}
	cmd.Flags().StringVar(&vpc, "vpc", "", "VPC of the group, id or name (required)")
	cmd.Flags().StringVar(&desc, "description", "", "description of the group")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

func sgEnsureCmd(rt *app.Runtime) *cobra.Command {
	var vpcFlag, region, desc, instance string
	var specs []string
	var priority int
	cmd := &cobra.Command{
		Use:   "ensure <name>",
		Short: "Make sure a security group exists, holds the rules and is joined to an instance",
		Long: `Make sure the security group <name> exists, holds the --rule ingress rules and,
with --instance, that the instance is in it. Running it again changes
nothing.

- The VPC is the instance's with --instance (another --vpc is a usage
  error), else --vpc (id or name), else the VPC named by naming.aliyun_vpc
  ({region}-vpc), which must exist (otherwise exit code 2: pass --vpc).
- The group is looked up by name in that VPC: none is created (with
  --description), one is used as it is, several are ambiguous (exit code 5).
  A group given by id that is in another VPC is an error (exit code 1): a
  group cannot change VPCs.
- Rules present (compared by protocol, ports, source and policy) are
  unchanged; the missing ones are added in one call, with --priority. Rules
  are never removed (use rule remove). Without --rule only the group is
  ensured.
- --instance (name or id, found through the inventory in every selected
  account) joins the instance to the group, keeping its other groups.`,
		Example: `  polyctl aliyun ecs security-group ensure web --vpc cn-hongkong-vpc \
    --rule icmp:all:0.0.0.0/0 --rule tcp:http:0.0.0.0/0 --rule tcp:https:0.0.0.0/0 --dry-run
  polyctl aliyun ecs security-group ensure web --instance site-1 --rule tcp:ssh:203.0.113.7`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name := args[0]
			byID := looksLikeGroupID(name)
			if !byID {
				if err := checkSGName(name); err != nil {
					return err
				}
			}
			rules, err := parseRules(specs, false)
			if err != nil {
				return err
			}
			if err := checkPriority(priority); err != nil {
				return err
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			var s *ecsScope
			var inst *Instance
			var vpc string
			if instance != "" {
				res, err := rt.ResolveResource(ctx, platform.Aliyun, platform.ResInstance, instance)
				if err != nil {
					return err
				}
				var cachedInst Instance
				_ = res.Decode(&cachedInst)
				instRegion := cachedInst.Region
				if instRegion == "" {
					instRegion = res.ParentID
				}
				if region != "" && instRegion != "" && region != instRegion {
					return app.UsageErrf("--region %s differs from the region of instance %s (%s)", region, instance, instRegion)
				}
				c, err := openNamed(rt, ctx, res.Profile)
				if err != nil {
					return err
				}
				s = &ecsScope{c: c, profile: res.Profile, region: c.regionOr(instRegion)}
				if inst, err = c.describeInstance(ctx, s.region, res.ID); err != nil {
					return err
				}
				if inst.VpcID == "" {
					return fmt.Errorf("instance %s is in no VPC; polyctl only manages VPC security groups", instance)
				}
				if vpcFlag != "" {
					v, err := resolveVPC(ctx, s, vpcFlag)
					if err != nil {
						return err
					}
					if v.ID != inst.VpcID {
						return app.UsageErrf("--vpc %s differs from the VPC of instance %s (%s): a security group can only hold instances of its own VPC", vpcFlag, instance, inst.VpcID)
					}
				}
				vpc = inst.VpcID
			} else {
				if s, err = openECSScope(ctx, rt, region); err != nil {
					return err
				}
				ref := vpcFlag
				if ref == "" {
					if ref, err = rt.ResourceName("aliyun_vpc", "", map[string]string{"region": s.region}); err != nil {
						return err
					}
				}
				v, err := resolveVPC(ctx, s, ref)
				if vpcFlag == "" && errors.Is(err, platform.ErrNotFound) {
					return app.UsageErrf("no VPC for security group %q: the default VPC %q (naming.aliyun_vpc) does not exist in %s; pass --vpc <id|name> or --instance <name|id>", name, ref, s.region)
				}
				if err != nil {
					return err
				}
				vpc = v.ID
			}

			var sg *securityGroup
			if byID {
				if sg, err = findSG(ctx, s, name, ""); err != nil {
					return err
				}
				if sg == nil {
					return fmt.Errorf("%w: security group %q in %s", platform.ErrNotFound, name, s.where())
				}
				if sg.VPC != vpc {
					return fmt.Errorf("security group %s is in VPC %s, not in %s; a security group cannot move to another VPC: ensure a group by name to create one there", sg.ID, sg.VPC, vpc)
				}
			} else if sg, err = findSG(ctx, s, name, vpc); err != nil {
				return err
			}

			label := name
			if sg != nil && byID && sg.Name != "" {
				label = sg.Name
			}
			resource := "security-group/" + label
			var groupID string
			var created bool
			var plan platform.Plan
			missing := rules
			var present []platform.IngressRule
			if sg != nil {
				groupID = sg.ID
				if desc != "" && desc != sg.Description {
					rt.Infof("note: security group %s keeps its description %q", sg.ID, sg.Description)
				}
				plan.Add(platform.Step{Resource: resource, Action: platform.Unchanged, ID: sg.ID, Desc: sg.ID + " " + sg.VPC})
				if len(rules) > 0 {
					have, err := s.c.securityGroupRules(ctx, s.region, sg.ID)
					if err != nil {
						return err
					}
					missing, present = splitRules(have, rules)
				}
			} else {
				plan.Add(sgCreateStep(rt, s, name, vpc, desc, &groupID, &created))
			}
			addRuleSteps(&plan, rt, s, resource+"/rule", func() string { return groupID }, func() bool { return created }, missing, present, priority, "")
			if inst != nil {
				instRes := "instance/" + instanceLabel(inst)
				if sg != nil && slices.Contains(inst.SecurityGroupIDs, sg.ID) {
					plan.Add(platform.Step{Resource: instRes, Action: platform.Unchanged, ID: inst.ID, Desc: "already in " + sg.ID})
				} else {
					sgLabel := platform.Pending
					if sg != nil {
						sgLabel = sg.ID
					}
					plan.Add(platform.Step{Resource: instRes, Action: platform.Updated, ID: inst.ID, Desc: fmt.Sprintf("join %s to %s", sgLabel, inst.ID),
						Apply: func(ctx context.Context) (platform.Change, error) {
							if err := s.c.joinSecurityGroup(ctx, s.region, inst.ID, groupID); err != nil {
								if platform.HasErrorCode(err, errInstanceMismatch) {
									return platform.Change{}, fmt.Errorf("instance %s and security group %s are not in the same VPC: %w", inst.ID, groupID, err)
								}
								return platform.Change{}, err
							}
							refreshInstance(rt, ctx, s.c, s.profile, s.region, inst.ID)
							return platform.Change{Detail: fmt.Sprintf("joined %s to %s", groupID, inst.ID)}, nil
						}})
				}
			}
			return rt.Ensure(ctx, "aliyun.ecs.security-group.ensure", s.target(), &plan)
		},
	}
	cmd.Flags().StringVar(&vpcFlag, "vpc", "", "VPC of the group, id or name (default: the instance's, else naming.aliyun_vpc)")
	cmd.Flags().StringArrayVar(&specs, "rule", nil, "ingress rule <protocol>:<port|from-to|alias|all>:<source> (repeatable)")
	cmd.Flags().IntVar(&priority, "priority", sgPriorityDefault, "priority of the rules added (1-100, 1 is the highest)")
	cmd.Flags().StringVar(&desc, "description", "", "description of a new group")
	cmd.Flags().StringVar(&instance, "instance", "", "join this instance (name or id) to the group; its VPC is the group's")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region, or the instance's)")
	return cmd
}

// instanceLabel names an instance in reports: its name, else its id.
func instanceLabel(in *Instance) string {
	if in.Name != "" {
		return in.Name
	}
	return in.ID
}

// -------------------------------------------------------------- delete

func sgDeleteCmd(rt *app.Runtime) *cobra.Command {
	var vpc, region string
	cmd := &cobra.Command{
		Use:   "delete <name|id>",
		Short: "Delete a security group (asks first)",
		Long: `Delete a security group. Its name, id, VPC and rule count are shown first, then a
confirmation is asked (default no; --yes skips it, and the non-interactive
flow needs --yes, exit code 2). A group that instances are still in, or
that another group's rule references, is not deleted (exit code 1): remove
the instances or the reference first; polyctl never does it for you. A
group that is gone by the time it is deleted is reported unchanged.`,
		Example: "  polyctl aliyun ecs security-group delete web --vpc cn-hongkong-vpc --yes",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			action := "delete security group " + args[0]
			// The non-interactive flow without --yes is refused before the
			// account is opened. A dry run deletes nothing.
			if !rt.DryRun() {
				if err := rt.CanConfirm(action); err != nil {
					return err
				}
			}
			s, err := openECSScope(ctx, rt, region)
			if err != nil {
				return err
			}
			sg, err := resolveSG(ctx, s, args[0], vpc)
			if err != nil {
				return err
			}
			rt.Infof("security group %s in %s", orDash(sg.Name), s.where())
			rt.Infof("  id     %s", sg.ID)
			rt.Infof("  vpc    %s", sg.VPC)
			rt.Infof("  rules  %d", sg.RuleCount)
			change := platform.Change{Resource: "security-group/" + orID(sg.Name, sg.ID), Action: platform.Deleted, ID: sg.ID}
			if done, err := rt.WouldWrite(s.target(), change); done || err != nil {
				return err
			}
			ok, err := rt.Confirm(ctx, fmt.Sprintf("Delete security group %s (%s)?", orDash(sg.Name), sg.ID), false)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("%w: cancelled; security group %s was not deleted", platform.ErrNothingToDo, sg.ID)
			}
			if err := s.c.deleteSecurityGroup(ctx, s.region, sg.ID); err != nil {
				switch {
				case platform.HasErrorCode(err, errSGNotFound, errSGIDNotFound):
					change.Action, change.Detail = platform.Unchanged, "already deleted"
				case platform.HasErrorCode(err, errSGDependency):
					return fmt.Errorf("security group %s is still in use: %w (%s)", sg.ID, err, dependencyHint(err))
				default:
					return err
				}
			}
			dropSG(ctx, rt, s.profile, sg.ID)
			return rt.RenderReport(platform.Report{Target: s.target(), Changes: []platform.Change{change}})
		},
	}
	cmd.Flags().StringVar(&vpc, "vpc", "", "VPC (id or name) to look the name up in (default: every VPC)")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

// dependencyHint tells the two DependencyViolation answers of
// DeleteSecurityGroup apart by their message.
func dependencyHint(err error) string {
	if strings.Contains(strings.ToLower(err.Error()), "instance") {
		return "instances are still in the group: move them to another group first"
	}
	return "a rule of another security group references it: remove that rule first"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func orID(name, id string) string {
	if name == "" {
		return id
	}
	return name
}

// ---------------------------------------------------------------- rules

func sgRuleAddCmd(rt *app.Runtime) *cobra.Command {
	var vpc, region, desc string
	var specs []string
	var priority int
	cmd := &cobra.Command{
		Use:   "add <sg>",
		Short: "Add ingress rules to a security group (present ones are unchanged)",
		Long: `Add the --rule ingress rules to an existing security group (name or id; a
missing group is exit code 4). Rules already present (same protocol, ports,
source and policy, whatever their priority or description) are unchanged;
the others are added in one call with --priority and --description.`,
		Example: `  polyctl aliyun ecs security-group rule add web --rule tcp:8000-8999:10.0.0.0/8 --description "internal"`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			rules, err := parseRules(specs, true)
			if err != nil {
				return err
			}
			if err := checkPriority(priority); err != nil {
				return err
			}
			s, err := openECSScope(ctx, rt, region)
			if err != nil {
				return err
			}
			sg, err := resolveSG(ctx, s, args[0], vpc)
			if err != nil {
				return err
			}
			have, err := s.c.securityGroupRules(ctx, s.region, sg.ID)
			if err != nil {
				return err
			}
			missing, present := splitRules(have, rules)
			var plan platform.Plan
			addRuleSteps(&plan, rt, s, "security-group/"+orID(sg.Name, sg.ID)+"/rule", func() string { return sg.ID }, func() bool { return false }, missing, present, priority, desc)
			return rt.Ensure(ctx, "aliyun.ecs.security-group.rule.add", s.target(), &plan)
		},
	}
	cmd.Flags().StringArrayVar(&specs, "rule", nil, "ingress rule <protocol>:<port|from-to|alias|all>:<source> (repeatable, required)")
	cmd.Flags().StringVar(&desc, "description", "", "description of every rule added (never compared)")
	cmd.Flags().IntVar(&priority, "priority", sgPriorityDefault, "priority of the rules added (1-100, 1 is the highest)")
	cmd.Flags().StringVar(&vpc, "vpc", "", "VPC (id or name) to look the name up in (default: every VPC)")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

func sgRuleRemoveCmd(rt *app.Runtime) *cobra.Command {
	var vpc, region string
	var specs, ids []string
	cmd := &cobra.Command{
		Use:   "remove <sg>",
		Short: "Remove ingress rules from a security group (asks first)",
		Long: `Remove ingress rules from a security group, given as --rule (compared by
protocol, ports, source and policy; every stored rule equal to it is
removed) or as --rule-id (the sgr-... ids get shows), not both. A rule that
is not there is unchanged. The rules to remove are shown and a confirmation
is asked (default no; --yes skips it, and the non-interactive flow needs
--yes, exit code 2); nothing to remove asks nothing.`,
		Example: `  polyctl aliyun ecs security-group rule remove web --rule tcp:8000-8999:10.0.0.0/8 --yes
  polyctl aliyun ecs security-group rule remove sg-0123456789abcdef --rule-id sgr-0123456789abcdef --yes`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if len(specs) > 0 && len(ids) > 0 {
				return app.UsageErrf("--rule and --rule-id are mutually exclusive")
			}
			if len(specs) == 0 && len(ids) == 0 {
				return app.UsageErrf("pass the rules to remove with --rule <rule> (format %s) or --rule-id <sgr-id>", platform.RuleFormat)
			}
			rules, err := parseRules(specs, false)
			if err != nil {
				return err
			}
			for _, id := range ids {
				if strings.TrimSpace(id) == "" {
					return app.UsageErrf("--rule-id is empty")
				}
			}
			s, err := openECSScope(ctx, rt, region)
			if err != nil {
				return err
			}
			sg, err := resolveSG(ctx, s, args[0], vpc)
			if err != nil {
				return err
			}
			have, err := s.c.securityGroupRules(ctx, s.region, sg.ID)
			if err != nil {
				return err
			}
			resource := "security-group/" + orID(sg.Name, sg.ID) + "/rule"

			// Each row removes the stored rules of one --rule or one
			// --rule-id; the removals run in one call.
			type row struct {
				desc string
				ids  []string
			}
			var rows []row
			var absent []string
			if len(rules) > 0 {
				for _, r := range rules {
					m := matchingRules(have, r)
					if len(m) == 0 {
						absent = append(absent, aliRuleString(r))
						continue
					}
					var rids []string
					for _, h := range m {
						rids = append(rids, h.ID)
					}
					rows = append(rows, row{desc: aliRuleString(r) + " (" + strings.Join(rids, ", ") + ")", ids: rids})
				}
			} else {
				seen := map[string]bool{}
				for _, id := range ids {
					if seen[id] {
						continue
					}
					seen[id] = true
					i := slices.IndexFunc(have, func(h sgRule) bool { return h.ID == id })
					if i < 0 {
						absent = append(absent, id)
						continue
					}
					rows = append(rows, row{desc: have[i].String() + " (" + id + ")", ids: []string{id}})
				}
			}
			var plan platform.Plan
			for _, a := range absent {
				plan.Add(platform.Step{Resource: resource, Action: platform.Unchanged, Desc: a + " (not present)"})
			}
			var all []string
			for _, r := range rows {
				for _, id := range r.ids {
					if !slices.Contains(all, id) {
						all = append(all, id)
					}
				}
			}
			gone := map[string]bool{}
			batch := &once{}
			for _, r := range rows {
				plan.Add(platform.Step{Resource: resource, Action: platform.Deleted, Desc: r.desc, Apply: func(ctx context.Context) (platform.Change, error) {
					err := batch.do(ctx, func(ctx context.Context) error {
						defer refreshSG(ctx, rt, s, sg.ID)
						return revokeRules(ctx, s, sg.ID, all, gone)
					})
					if err != nil {
						return platform.Change{}, err
					}
					for _, id := range r.ids {
						if !gone[id] {
							return platform.Change{Detail: r.desc}, nil
						}
					}
					return platform.Change{Action: platform.Unchanged, Detail: r.desc + " (already removed)"}, nil
				}})
			}
			if len(rows) > 0 && !rt.DryRun() {
				rt.Infof("security group %s (%s) in %s: rules to remove", orDash(sg.Name), sg.ID, s.where())
				for _, r := range rows {
					rt.Infof("  %s", r.desc)
				}
				ok, err := rt.Confirm(ctx, fmt.Sprintf("Remove %d rule(s) from security group %s?", len(all), sg.ID), false)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("%w: cancelled; no rule of security group %s was removed", platform.ErrNothingToDo, sg.ID)
				}
			}
			return rt.Ensure(ctx, "aliyun.ecs.security-group.rule.remove", s.target(), &plan)
		},
	}
	cmd.Flags().StringArrayVar(&specs, "rule", nil, "ingress rule <protocol>:<port|from-to|alias|all>:<source> to remove (repeatable)")
	cmd.Flags().StringArrayVar(&ids, "rule-id", nil, "id of a rule to remove, sgr-... (repeatable)")
	cmd.Flags().StringVar(&vpc, "vpc", "", "VPC (id or name) to look the name up in (default: every VPC)")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

// revokeRules removes rules by id in one call. A rule removed meanwhile
// makes ECS refuse the batch (InvalidParam.SecurityGroupRuleId): the rules
// are then removed one by one, and those already gone are recorded in gone.
func revokeRules(ctx context.Context, s *ecsScope, sgID string, ids []string, gone map[string]bool) error {
	err := s.c.revokeIngress(ctx, s.region, sgID, ids)
	if err == nil || !platform.HasErrorCode(err, errRuleIDNotFound) {
		return err
	}
	for _, id := range ids {
		err := s.c.revokeIngress(ctx, s.region, sgID, []string{id})
		switch {
		case err == nil:
		case platform.HasErrorCode(err, errRuleIDNotFound):
			gone[id] = true
		default:
			return err
		}
	}
	return nil
}
