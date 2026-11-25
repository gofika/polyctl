package gcp

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

func newFirewallCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "firewall", Short: "VPC firewall rules"}
	cmd.AddCommand(firewallListCmd(rt), firewallGetCmd(rt), firewallCreateCmd(rt), firewallUpdateCmd(rt), firewallDeleteCmd(rt), firewallEnsureCmd(rt))
	return cmd
}

// defaultNetwork resolves --network for a write: the flag, else
// defaults.gcp.network, else "default".
func defaultNetwork(rt *app.Runtime, profile, flag string) (string, error) {
	n, err := rt.Setting(profile, platform.GCP, "network", flag)
	if err != nil {
		return "", err
	}
	if n == "" {
		n = "default"
	}
	return lastSegment(n), nil
}

// ruleNetwork is defaultNetwork for a command that has a client: with
// neither the flag nor defaults.gcp.network, a project without a network
// named default gets a pick in the interactive flow (builtinNetwork).
func ruleNetwork(ctx context.Context, rt *app.Runtime, c *client, profile, flag string) (string, error) {
	n, err := rt.Setting(profile, platform.GCP, "network", flag)
	if err != nil || n != "" {
		return lastSegment(n), err
	}
	return builtinNetwork(ctx, rt, c)
}

func firewallTarget(c *client, profile string) platform.Target {
	return platform.Target{Platform: platform.GCP, Profile: profile, Project: c.project}
}

func firewallListCmd(rt *app.Runtime) *cobra.Command {
	var network string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the firewall rules of the selected projects, or of one --network",
		Long: `List the VPC firewall rules of the selected projects, each project's sorted by priority (lower numbers
win; at the same priority a deny rule wins over an allow rule). Without
--network the rules of every network are listed; --network keeps the rules
of that network, matched by its exact name.`,
		Example: "  polyctl gcp compute firewall list --network default -o json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, profile, err := openGCP(cmd.Context(), rt)
			if err != nil {
				return err
			}
			network := lastSegment(network)
			// The rules of every selected project (of --project alone),
			// each project's own by priority.
			type projectRule struct {
				project string
				fw      *compute.Firewall
			}
			var list []projectRule
			err = c.forProjects(cmd.Context(), func(pc *client) error {
				all, err := pc.listFirewalls(cmd.Context())
				if err != nil {
					return err
				}
				for _, fw := range all {
					if network == "" || lastSegment(fw.Network) == network {
						list = append(list, projectRule{pc.project, fw})
					}
				}
				return nil
			})
			if err != nil {
				return err
			}
			sort.SliceStable(list, func(i, j int) bool {
				if list[i].project != list[j].project {
					return list[i].project < list[j].project
				}
				if list[i].fw.Priority != list[j].fw.Priority {
					return list[i].fw.Priority < list[j].fw.Priority
				}
				return list[i].fw.Name < list[j].fw.Name
			})
			rows := make([]firewallView, 0, len(list))
			for _, r := range list {
				v := firewallFromAPI(r.fw)
				v.Project = r.project
				rows = append(rows, v)
			}
			where := c.projectsLabel()
			switch {
			case len(rows) > 0:
				rt.Infof("%d firewall rule(s) in %s via gcp/%s", len(rows), where, profile)
			case network != "":
				rt.Infof("note: no firewall rules on network %s in %s (gcp/%s)", network, where, profile)
			default:
				rt.Infof("note: no firewall rules in %s (gcp/%s)", where, profile)
			}
			return rt.Render(rows, func() output.Grid {
				g := output.Grid{Headers: []string{"NAME", "PROJECT", "NETWORK", "DIR", "PRI", "ALLOW", "SOURCES", "TARGET-TAGS"}, Empty: "no firewall rules"}
				for _, r := range list {
					fw := r.fw
					name := fw.Name
					if fw.Disabled {
						name += " (disabled)"
					}
					g.Rows = append(g.Rows, []string{name, r.project, lastSegment(fw.Network), fw.Direction, strconv.FormatInt(fw.Priority, 10),
						ruleLabel(fw), strconv.Itoa(rangeCount(fw)), strings.Join(fw.TargetTags, ",")})
				}
				return g
			})
		},
	}
	cmd.Flags().StringVar(&network, "network", "", "only the rules of this VPC network (exact name; default: every network)")
	return cmd
}

func firewallGrid(v firewallView) output.Grid {
	label := func(rs []ruleView) string {
		var parts []string
		for _, r := range rs {
			p := r.Protocol
			if len(r.Ports) > 0 {
				p += ":" + strings.Join(r.Ports, ",")
			}
			parts = append(parts, p)
		}
		return strings.Join(parts, " ")
	}
	g := output.KV("name", v.Name, "project", v.Project, "network", v.Network, "direction", v.Direction, "priority", strconv.FormatInt(v.Priority, 10))
	if len(v.Denied) > 0 {
		g.Rows = append(g.Rows, []string{"denied", label(v.Denied)})
	} else {
		g.Rows = append(g.Rows, []string{"allowed", label(v.Allowed)})
	}
	if v.Direction == dirEgress {
		g.Rows = append(g.Rows, []string{"destination ranges", strings.Join(v.DestinationRanges, ", ")})
	} else {
		g.Rows = append(g.Rows, []string{"source ranges", strings.Join(v.SourceRanges, ", ")})
	}
	if len(v.SourceTags) > 0 {
		g.Rows = append(g.Rows, []string{"source tags", strings.Join(v.SourceTags, ", ")})
	}
	tags := strings.Join(v.TargetTags, ", ")
	if tags == "" {
		tags = "(every instance of the network)"
	}
	g.Rows = append(g.Rows, []string{"target tags", tags}, []string{"disabled", strconv.FormatBool(v.Disabled)},
		[]string{"description", v.Description}, []string{"created", v.CreationTimestamp})
	return g
}

func firewallGetCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get <name>",
		Short: "Show one firewall rule",
		Long:  "Show one VPC firewall rule. On a terminal, without <name> the rules of the\nselected projects are offered.",
		Args:  app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, profile, err := openGCP(cmd.Context(), rt)
			if err != nil {
				return err
			}
			c, name, err := firewallArg(cmd.Context(), rt, c, profile, args)
			if err != nil {
				return err
			}
			fw, err := c.getFirewall(cmd.Context(), name)
			if err != nil {
				return fmt.Errorf("%w (gcp/%s)", err, profile)
			}
			v := firewallFromAPI(fw)
			v.Project = c.project
			return rt.Render(v, func() output.Grid { return firewallGrid(v) })
		},
	}
}

// ruleFlags are the rule settings of create, update and ensure.
type ruleFlags struct {
	network      string
	allow        []string
	sourceRanges []string
	destRanges   []string
	targetTags   []string
	direction    string
	priority     int64
	description  string
}

func (f *ruleFlags) register(cmd *cobra.Command, withNetworkDefault bool) {
	fl := cmd.Flags()
	help := "VPC network of the rule"
	if withNetworkDefault {
		help += " (default: defaults.gcp.network, else default)"
	}
	fl.StringVar(&f.network, "network", "", help)
	fl.StringArrayVar(&f.allow, "allow", nil, "allowed protocol and ports: tcp|udp|icmp|all, optionally :<ports> for tcp and udp (tcp:80,443,8000-8100, tcp:ssh); repeatable")
	fl.StringArrayVar(&f.sourceRanges, "source-range", nil, "source CIDR of an ingress rule (repeatable)")
	fl.StringArrayVar(&f.destRanges, "destination-range", nil, "destination CIDR of an egress rule (repeatable)")
	fl.StringArrayVar(&f.targetTags, "target-tag", nil, "network tag of the instances the rule applies to (repeatable; none: every instance of the network)")
	fl.StringVar(&f.direction, "direction", "ingress", "ingress or egress")
	fl.Int64Var(&f.priority, "priority", defaultFirewallPriority, "priority 0-65535 (lower numbers win)")
	fl.StringVar(&f.description, "description", "", "description of the rule")
}

// ruleSpec is a validated rule of create and ensure.
type ruleSpec struct {
	direction  string
	allowed    []*compute.FirewallAllowed
	sources    []string
	dests      []string
	targetTags []string
}

// parseRule validates the rule flags. An ingress rule needs a source
// range: the API would silently open a rule without one to 0.0.0.0/0. An
// egress rule takes destination ranges (it needs one for the same reason)
// and no source range.
func (f *ruleFlags) parseRule() (*ruleSpec, error) {
	if len(f.allow) == 0 {
		return nil, app.UsageErrf("--allow is required (e.g. --allow tcp:22)")
	}
	dir, err := parseDirection(f.direction)
	if err != nil {
		return nil, err
	}
	if err := checkPriority(f.priority); err != nil {
		return nil, err
	}
	s := &ruleSpec{direction: dir}
	if s.allowed, err = parseAllow(f.allow); err != nil {
		return nil, err
	}
	if s.sources, err = parseCIDRs("source-range", f.sourceRanges); err != nil {
		return nil, err
	}
	if s.dests, err = parseCIDRs("destination-range", f.destRanges); err != nil {
		return nil, err
	}
	switch dir {
	case dirIngress:
		if len(s.dests) > 0 {
			return nil, app.UsageErrf("--destination-range applies to egress rules; an ingress rule takes --source-range")
		}
		if len(s.sources) == 0 {
			return nil, app.UsageErrf("an ingress rule needs --source-range: without one Compute Engine opens the rule to 0.0.0.0/0 (pass --source-range 0.0.0.0/0 to mean that)")
		}
	case dirEgress:
		if len(s.sources) > 0 {
			return nil, app.UsageErrf("--source-range applies to ingress rules; an egress rule takes --destination-range")
		}
		if len(s.dests) == 0 {
			return nil, app.UsageErrf("an egress rule needs --destination-range: without one Compute Engine applies the rule to 0.0.0.0/0 (pass --destination-range 0.0.0.0/0 to mean that)")
		}
	}
	for _, t := range f.targetTags {
		if strings.TrimSpace(t) == "" {
			return nil, app.UsageErrf("--target-tag must not be empty")
		}
	}
	s.targetTags = dedupe(f.targetTags)
	return s, nil
}

// ruleDesc summarises a rule for a change report.
func ruleDesc(network string, s *ruleSpec) string {
	parts := []string{strings.ToLower(s.direction), allowedLabel(s.allowed)}
	if s.direction == dirEgress {
		parts = append(parts, plural(len(s.dests), "destination range"))
	} else {
		parts = append(parts, plural(len(s.sources), "source range"))
	}
	if len(s.targetTags) > 0 {
		parts = append(parts, "tag "+strings.Join(s.targetTags, ","))
	} else {
		parts = append(parts, "every instance")
	}
	return strings.Join(parts, ", ") + ", network " + network
}

// firewallBody is the rule a create sends.
func (c *client) firewallBody(name, network string, s *ruleSpec, priority int64, description string) *compute.Firewall {
	return &compute.Firewall{Name: name, Network: c.networkPath(network), Direction: s.direction, Priority: priority,
		Description: description, Allowed: s.allowed, SourceRanges: s.sources, DestinationRanges: s.dests, TargetTags: s.targetTags,
		ForceSendFields: []string{"Priority"}}
}

func firewallCreateCmd(rt *app.Runtime) *cobra.Command {
	var rf ruleFlags
	var wf app.WaitFlags
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a firewall rule (an existing rule of that name is an error)",
		Long: `Create a VPC firewall rule in the default project of the account, or in the
project of --project. A rule of that name already in the project is exit
code 1: use ensure to converge an existing rule, update to change it.

--allow (required, repeatable) is <protocol> or <protocol>:<ports> with the
protocol tcp, udp, icmp or all; only tcp and udp take ports: numbers,
from-to ranges and the aliases ssh, http, https, mysql, ... separated by
commas (tcp:80,443,8000-8100). An ingress rule (the default) needs
--source-range: Compute Engine would open a rule without one to
0.0.0.0/0. --direction egress takes --destination-range instead. Without
--target-tag the rule applies to every instance of the network.

On a terminal, what is missing is asked: the network when the project has
none named default, the name (checked as it is typed against the rules of
the project), the allowed protocols (common ones, or typed) and the ranges
(the ranges of the network's subnetworks, the IAP range for SSH and RDP,
0.0.0.0/0 never preselected, or typed).

The command waits for the operation (--timeout, 10m); --no-wait returns once
the creation was accepted.`,
		Example: "  polyctl gcp compute firewall create allow-ssh-internal --network default --allow tcp:22 --source-range 10.0.0.0/8 --target-tag ssh-internal",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name := app.Arg(args, 0)
			wait, timeout, err := wf.Resolve(cmd)
			if err != nil {
				return err
			}
			if name != "" {
				if err := checkFirewallName(name); err != nil {
					return err
				}
			}
			if !rt.Interactive() {
				// Refused before anything is read.
				if _, err := rf.parseRule(); err != nil {
					return err
				}
			}
			c, profile, err := openGCP(ctx, rt)
			if err != nil {
				return err
			}
			network, err := ruleNetwork(ctx, rt, c, profile, rf.network)
			if err != nil {
				return err
			}
			if name == "" {
				if name, err = askFirewallName(ctx, rt, c); err != nil {
					return err
				}
			}
			if err := askRule(ctx, rt, c, &rf, network, nil); err != nil {
				return err
			}
			spec, err := rf.parseRule()
			if err != nil {
				return err
			}
			existing, err := c.findFirewall(ctx, name)
			if err != nil {
				return err
			}
			if existing != nil {
				return fmt.Errorf("firewall rule %s already exists in project %s (network %s, gcp/%s): use `polyctl gcp compute firewall ensure` to converge it, or `update` to change it", name, c.project, lastSegment(existing.Network), profile)
			}
			if _, err := c.network(ctx, network); err != nil {
				return fmt.Errorf("%w (gcp/%s)", err, profile)
			}
			change := platform.Change{Resource: "firewall/" + name, Action: platform.Created, Detail: ruleDesc(network, spec)}
			if done, err := rt.WouldWrite(firewallTarget(c, profile), change); done || err != nil {
				return err
			}
			wctx, cancel, conv := deadline(ctx, timeout, change.Resource, "created")
			defer cancel()
			if err := c.insertFirewall(wctx, c.firewallBody(name, network, spec, rf.priority, rf.description), wait); err != nil {
				return conv(err)
			}
			if !wait {
				change.Detail += " (requested)"
			}
			rt.Infof("created firewall rule %s on network %s in project %s via gcp/%s", name, network, c.project, profile)
			return rt.RenderReport(platform.Report{Target: firewallTarget(c, profile), Changes: []platform.Change{change}})
		},
	}
	rf.register(cmd, true)
	app.AddWaitFlags(cmd, &wf, true, app.DefaultWaitTimeout)
	return cmd
}

func firewallUpdateCmd(rt *app.Runtime) *cobra.Command {
	var rf ruleFlags
	var addSources []string
	var wf app.WaitFlags
	cmd := &cobra.Command{
		Use:   "update <name>",
		Short: "Change fields of a firewall rule",
		Long: `Change fields of a VPC firewall rule; the others are kept. --allow,
--source-range, --destination-range and --target-tag replace that field as
a whole; --add-source-range adds ranges to the existing ones (a union, never
a removal). --description and --priority set those fields. Values that are
already set are unchanged, and nothing is sent. Without any field to change
it is exit code 2; on a terminal, what to change is asked instead (the
allowed protocols, ranges to add, the target tags, the description or the
priority, each with its current value), then its new value.

The network and the direction of a rule are never changed (exit code 2):
delete the rule and create it again. --target-tag "" makes the rule apply to
every instance of the network; as only a full replacement of the rule can
clear a list, the rule is then read and sent back whole. On a terminal,
without <name> the rules of the selected projects are offered.

The command waits for the operation (--timeout, 10m); --no-wait returns once
the change was accepted.`,
		Example: `  polyctl gcp compute firewall update allow-lb-health-check-default --add-source-range 10.20.0.0/24
  polyctl gcp compute firewall update allow-ssh-internal --allow tcp:22,2222`,
		Args: app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			fl := cmd.Flags()
			wait, timeout, err := wf.Resolve(cmd)
			if err != nil {
				return err
			}
			for _, f := range []string{"network", "direction"} {
				if fl.Changed(f) {
					return app.UsageErrf("the %s of a firewall rule cannot be changed with polyctl: delete the rule and create it again", f)
				}
			}
			changed := false
			for _, f := range []string{"allow", "source-range", "add-source-range", "destination-range", "target-tag", "description", "priority"} {
				changed = changed || fl.Changed(f)
			}
			if !changed && !rt.Interactive() {
				return app.UsageErrf("nothing to update: pass --allow, --source-range, --add-source-range, --destination-range, --target-tag, --description or --priority")
			}
			// asked is the field the interactive flow asked for when no field
			// flag was given.
			asked := ""
			set := func(f string) bool { return fl.Changed(f) || f == asked }
			if fl.Changed("source-range") && fl.Changed("add-source-range") {
				return app.UsageErrf("--source-range replaces the source ranges and --add-source-range adds to them: pass one of them")
			}
			var allowed []*compute.FirewallAllowed
			if fl.Changed("allow") {
				if allowed, err = parseAllow(rf.allow); err != nil {
					return err
				}
			}
			sources, err := parseCIDRs("source-range", rf.sourceRanges)
			if err != nil {
				return err
			}
			adds, err := parseCIDRs("add-source-range", addSources)
			if err != nil {
				return err
			}
			dests, err := parseCIDRs("destination-range", rf.destRanges)
			if err != nil {
				return err
			}
			if fl.Changed("source-range") && len(sources) == 0 || fl.Changed("destination-range") && len(dests) == 0 {
				return app.UsageErrf("the ranges of a rule cannot be emptied: Compute Engine would then apply the rule to 0.0.0.0/0")
			}
			if fl.Changed("priority") {
				if err := checkPriority(rf.priority); err != nil {
					return err
				}
			}
			clearTags := false
			var tags []string
			if fl.Changed("target-tag") {
				for _, t := range rf.targetTags {
					if strings.TrimSpace(t) != "" {
						tags = append(tags, strings.TrimSpace(t))
					}
				}
				tags = dedupe(tags)
				clearTags = len(tags) == 0
				if clearTags && len(rf.targetTags) > 1 {
					return app.UsageErrf("--target-tag \"\" clears the target tags and takes no other value")
				}
			}
			c, profile, err := openGCP(ctx, rt)
			if err != nil {
				return err
			}
			c, name, err := firewallArg(ctx, rt, c, profile, args)
			if err != nil {
				return err
			}
			fw, err := c.getFirewall(ctx, name)
			if err != nil {
				return fmt.Errorf("%w (gcp/%s)", err, profile)
			}
			switch {
			case fw.Direction == dirEgress && (fl.Changed("source-range") || fl.Changed("add-source-range")):
				return app.UsageErrf("firewall rule %s is an egress rule: it takes --destination-range, not source ranges", name)
			case fw.Direction != dirEgress && fl.Changed("destination-range"):
				return app.UsageErrf("firewall rule %s is an ingress rule: it takes --source-range or --add-source-range, not --destination-range", name)
			case len(fw.Denied) > 0 && allowed != nil:
				return fmt.Errorf("firewall rule %s is a deny rule: polyctl manages the allowed protocols of allow rules only", name)
			}
			if !changed {
				if asked, err = askFirewallUpdate(ctx, rt, c, fw, &rf, &addSources); err != nil {
					return err
				}
				switch asked {
				case "allow":
					allowed, err = parseAllow(rf.allow)
				case "add-source-range":
					adds, err = parseCIDRs("add-source-range", addSources)
				case "destination-range":
					dests, err = parseCIDRs("destination-range", rf.destRanges)
				case "target-tag":
					tags = dedupe(rf.targetTags)
				}
				if err != nil {
					return err
				}
			}
			patch := &compute.Firewall{}
			var details []string
			if allowed != nil && allowedKey(allowed) != allowedKey(fw.Allowed) {
				patch.Allowed = allowed
				details = append(details, fmt.Sprintf("allow %s -> %s", allowedLabel(fw.Allowed), allowedLabel(allowed)))
			}
			if set("source-range") && !sameSet(sources, fw.SourceRanges) {
				patch.SourceRanges = sources
				details = append(details, fmt.Sprintf("source ranges %s -> %s", strings.Join(fw.SourceRanges, ","), strings.Join(sources, ",")))
			}
			if len(adds) > 0 {
				union, added := unionRanges(fw.SourceRanges, adds)
				if len(added) > 0 {
					patch.SourceRanges = union
					details = append(details, fmt.Sprintf("+%s (now %s)", strings.Join(added, ", +"), plural(len(union), "range")))
				}
			}
			if set("destination-range") && !sameSet(dests, fw.DestinationRanges) {
				patch.DestinationRanges = dests
				details = append(details, fmt.Sprintf("destination ranges %s -> %s", strings.Join(fw.DestinationRanges, ","), strings.Join(dests, ",")))
			}
			if set("target-tag") && !(clearTags && len(fw.TargetTags) == 0) && (clearTags || !sameSet(tags, fw.TargetTags)) {
				patch.TargetTags = tags
				to := strings.Join(tags, ",")
				if clearTags {
					to = "(every instance of the network)"
				}
				details = append(details, fmt.Sprintf("target tags %s -> %s", strings.Join(fw.TargetTags, ","), to))
			} else {
				clearTags = false
			}
			if set("description") && rf.description != fw.Description {
				patch.Description = rf.description
				patch.ForceSendFields = append(patch.ForceSendFields, "Description")
				details = append(details, "description")
			}
			if set("priority") && rf.priority != fw.Priority {
				patch.Priority = rf.priority
				patch.ForceSendFields = append(patch.ForceSendFields, "Priority")
				details = append(details, fmt.Sprintf("priority %d -> %d", fw.Priority, rf.priority))
			}
			target := firewallTarget(c, profile)
			res := "firewall/" + name
			if len(details) == 0 {
				rt.Infof("firewall rule %s already is as requested; nothing sent", name)
				return rt.RenderReport(platform.Report{Target: target, DryRun: rt.DryRun(), Changes: []platform.Change{
					{Resource: res, Action: platform.Unchanged, Detail: "already as requested"}}})
			}
			change := platform.Change{Resource: res, Action: platform.Updated, Detail: strings.Join(details, "; "),
				Attrs: map[string]string{}}
			if patch.SourceRanges != nil {
				change.Attrs["source_ranges"] = strings.Join(patch.SourceRanges, ",")
			}
			if len(change.Attrs) == 0 {
				change.Attrs = nil
			}
			if clearTags {
				rt.Infof("warning: without target tags rule %s applies to every instance of network %s", name, lastSegment(fw.Network))
			}
			if done, err := rt.WouldWrite(target, change); done || err != nil {
				return err
			}
			wctx, cancel, conv := deadline(ctx, timeout, res, "updated")
			defer cancel()
			if clearTags {
				err = c.replaceFirewall(wctx, name, mergedRule(fw, patch), wait)
			} else {
				err = c.patchFirewall(wctx, name, patch, wait)
			}
			if err != nil {
				return conv(err)
			}
			if !wait {
				change.Detail += " (requested)"
			}
			rt.Infof("updated firewall rule %s in project %s via gcp/%s", name, c.project, profile)
			return rt.RenderReport(platform.Report{Target: target, Changes: []platform.Change{change}})
		},
	}
	rf.register(cmd, false)
	cmd.Flags().Lookup("network").Usage = "not supported: the network of a rule cannot be changed (delete and create it again)"
	cmd.Flags().Lookup("direction").Usage = "not supported: the direction of a rule cannot be changed (delete and create it again)"
	cmd.Flags().StringArrayVar(&addSources, "add-source-range", nil, "add a source CIDR to the existing ones (repeatable; a union, nothing is removed)")
	app.AddWaitFlags(cmd, &wf, true, app.DefaultWaitTimeout)
	return cmd
}

// mergedRule is the whole rule a PUT sends: the rule as read with the
// fields of patch applied (TargetTags always taken from patch, so that it
// can be cleared). The network and direction are sent unchanged.
func mergedRule(fw, patch *compute.Firewall) *compute.Firewall {
	out := *fw
	out.TargetTags = patch.TargetTags
	if patch.Allowed != nil {
		out.Allowed = patch.Allowed
	}
	if patch.SourceRanges != nil {
		out.SourceRanges = patch.SourceRanges
	}
	if patch.DestinationRanges != nil {
		out.DestinationRanges = patch.DestinationRanges
	}
	for _, f := range patch.ForceSendFields {
		switch f {
		case "Description":
			out.Description = patch.Description
		case "Priority":
			out.Priority = patch.Priority
		}
	}
	out.ForceSendFields = []string{"Priority", "Disabled"}
	return &out
}

func firewallDeleteCmd(rt *app.Runtime) *cobra.Command {
	var wf app.WaitFlags
	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a firewall rule (asks first)",
		Long: `Delete a VPC firewall rule. The rule (network, direction, protocols, ranges,
target tags) is shown first, then a confirmation is asked (default no; --yes
skips it, and the non-interactive flow needs --yes). A missing rule is exit
code 4. The command waits for the operation (--timeout, 10m); --no-wait
returns once the deletion was accepted. On a terminal, without <name> the
rules of the selected projects are offered.`,
		Example: "  polyctl gcp compute firewall delete allow-ssh-internal --yes",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			wait, timeout, err := wf.Resolve(cmd)
			if err != nil {
				return err
			}
			c, profile, err := openGCP(ctx, rt)
			if err != nil {
				return err
			}
			c, name, err := firewallArg(ctx, rt, c, profile, args)
			if err != nil {
				return err
			}
			fw, err := c.getFirewall(ctx, name)
			if err != nil {
				return fmt.Errorf("%w (gcp/%s)", err, profile)
			}
			tags := strings.Join(fw.TargetTags, ",")
			if tags == "" {
				tags = "(every instance of the network)"
			}
			ranges := fw.SourceRanges
			if fw.Direction == dirEgress {
				ranges = fw.DestinationRanges
			}
			rt.Infof("firewall rule %s (gcp/%s, project %s)", name, profile, c.project)
			rt.Infof("  network       %s", lastSegment(fw.Network))
			rt.Infof("  direction     %s, priority %d", fw.Direction, fw.Priority)
			rt.Infof("  rule          %s", ruleLabel(fw))
			rt.Infof("  ranges        %s", strings.Join(ranges, ", "))
			rt.Infof("  target tags   %s", tags)
			change := platform.Change{Resource: "firewall/" + name, Action: platform.Deleted, Detail: "network " + lastSegment(fw.Network)}
			if done, err := rt.WouldWrite(firewallTarget(c, profile), change); done || err != nil {
				return err
			}
			ok, err := rt.Confirm(ctx, fmt.Sprintf("Delete firewall rule %s (network %s, project %s)?", name, lastSegment(fw.Network), c.project), false)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("%w: cancelled; firewall rule %s was not deleted", platform.ErrNothingToDo, name)
			}
			wctx, cancel, conv := deadline(ctx, timeout, change.Resource, "deleted")
			defer cancel()
			if err := c.deleteFirewall(wctx, name, wait); err != nil {
				return conv(err)
			}
			if !wait {
				change.Detail += " (requested)"
			}
			rt.Infof("deleted firewall rule %s in project %s via gcp/%s", name, c.project, profile)
			return rt.RenderReport(platform.Report{Target: firewallTarget(c, profile), Changes: []platform.Change{change}})
		},
	}
	app.AddWaitFlags(cmd, &wf, true, app.DefaultWaitTimeout)
	return cmd
}
