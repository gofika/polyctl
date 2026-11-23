package aws

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// resolveTG returns the target group ref names (a name or an ARN) in the
// scope; a missing one is ErrNotFound.
func resolveTG(ctx context.Context, s *lbScope, ref string) (*platform.LBTargetGroup, error) {
	if strings.TrimSpace(ref) == "" {
		return nil, app.UsageErrf("the target group name or ARN is empty")
	}
	tg, err := s.c.FindTargetGroup(ctx, s.region, ref)
	if err != nil {
		return nil, err
	}
	if tg == nil {
		return nil, fmt.Errorf("%w: target group %q in %s", platform.ErrNotFound, ref, s.where())
	}
	return tg, nil
}

// openTG opens the scope of a target group command and finds the group.
func openTG(ctx context.Context, rt *app.Runtime, ref, region string) (*lbScope, *platform.LBTargetGroup, error) {
	s, err := openELBScope(ctx, rt, region, ref)
	if err != nil {
		return nil, nil, err
	}
	tg, err := resolveTG(ctx, s, ref)
	return s, tg, err
}

// parseGroupTargets parses --target values for a group of targetType: an
// instance id for instance groups, an IP address for ip groups; a missing
// port is the group's port.
func parseGroupTargets(flag string, specs []string, targetType string, port int32) ([]platform.LBTargetSpec, error) {
	targets, err := platform.ParseTargets(specs)
	if err != nil {
		return nil, err
	}
	out := targets[:0]
	seen := map[platform.LBTargetSpec]bool{}
	for _, t := range targets {
		switch targetType {
		case "instance":
			if !looksLikeInstanceID(t.ID) {
				return nil, app.UsageErrf("--%s %s: the target group registers instances: expected an instance id (i-...)", flag, t)
			}
		case "ip":
			if !platform.IsIPTarget(t.ID) {
				return nil, app.UsageErrf("--%s %s: the target group registers IP addresses: expected an IP address", flag, t)
			}
		}
		if t.Port == 0 {
			t.Port = port
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out, nil
}

func tgListGrid(tgs []platform.LBTargetGroup) output.Grid {
	g := output.Grid{Headers: []string{"NAME", "PROTOCOL", "PORT", "TARGET TYPE", "VPC", "LOAD BALANCERS"}, Empty: "no target groups"}
	for _, tg := range tgs {
		var lbs []string
		for _, lb := range tg.LoadBalancers {
			lbs = append(lbs, arnName(lb))
		}
		g.Rows = append(g.Rows, []string{tg.Name, tg.Protocol, strconv.Itoa(int(tg.Port)), tg.TargetType, tg.VPC, joinOrNone(lbs)})
	}
	return g
}

func tgDetailGrid(d tgView) output.Grid {
	var lbs []string
	for _, lb := range d.LoadBalancers {
		lbs = append(lbs, arnName(lb))
	}
	hc := d.HealthCheck
	g := output.Grid{Rows: [][]string{
		{"NAME", d.Name, "PROTOCOL", fmt.Sprintf("%s/%d", d.Protocol, d.Port)},
		{"TARGET TYPE", d.TargetType, "VPC", d.VPC},
		{"PROFILE", d.Profile, "REGION", d.Region},
		{"ARN", d.ID},
		{"LOAD BALANCERS", joinOrNone(lbs)},
		{"HEALTH CHECK", fmt.Sprintf("%s port %s every %ds (timeout %ds, healthy %d, unhealthy %d)", hc.Protocol, hc.Port, hc.IntervalSeconds, hc.TimeoutSeconds, hc.HealthyThreshold, hc.UnhealthyThreshold)},
		{"TARGETS"},
	}}
	targetRows(&g, d.Targets)
	return g
}

// ---------------------------------------------------------------- list

func tgListCmd(rt *app.Runtime) *cobra.Command {
	var lbRef, vpc, region string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List target groups",
		Long: `List the target groups of the profile's region (--region for another one), or
with --lb those of one load balancer (found like load-balancer get). --vpc
keeps the groups of one VPC. The list is read from AWS every time.`,
		Example: "  polyctl aws elbv2 target-group list --lb site-xz7-lb\n  polyctl aws elbv2 target-group list --vpc vpc-0abc -o json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			var s *lbScope
			lbID := ""
			if lbRef != "" {
				var lb *platform.LoadBalancer
				var err error
				if s, lb, err = resolveLB(ctx, rt, lbRef, region); err != nil {
					return err
				}
				lbID = lb.ID
			} else {
				var err error
				if s, err = openELBScope(ctx, rt, region, ""); err != nil {
					return err
				}
			}
			tgs, err := s.c.ListTargetGroups(ctx, s.region, lbID)
			if err != nil {
				return err
			}
			kept := []platform.LBTargetGroup{}
			for _, tg := range tgs {
				if vpc == "" || tg.VPC == vpc {
					kept = append(kept, tg)
				}
			}
			slices.SortFunc(kept, func(a, b platform.LBTargetGroup) int { return strings.Compare(a.Name, b.Name) })
			if len(kept) == 0 {
				rt.Infof("no target groups in %s", s.where())
			}
			return rt.Render(kept, func() output.Grid { return tgListGrid(kept) })
		},
	}
	cmd.Flags().StringVar(&lbRef, "lb", "", "only the target groups of this load balancer (name, ARN or DNS name)")
	cmd.Flags().StringVar(&vpc, "vpc", "", "only the target groups of this VPC")
	cmd.Flags().StringVar(&region, "region", "", "region to list (default: the profile's region)")
	return cmd
}

// ----------------------------------------------------------------- get

func tgGetCmd(rt *app.Runtime) *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:     "get <name|arn>",
		Short:   "Show a target group, its health check and its targets with their health",
		Example: "  polyctl aws elbv2 target-group get site-xz7-80-target -o json",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			s, tg, err := openTG(ctx, rt, args[0], region)
			if err != nil {
				return err
			}
			targets, err := s.c.TargetHealth(ctx, s.region, tg.ID)
			if err != nil {
				return err
			}
			d := tgView{LBTargetGroup: *tg, Profile: s.profile, Targets: targets}
			return rt.Render(d, func() output.Grid { return tgDetailGrid(d) })
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region of the target group (default: the profile's region, or the ARN's)")
	return cmd
}

// -------------------------------------------------------------- create

// tgHealthFlags are the health check flags of create and update.
type tgHealthFlags struct {
	protocol string
	port     string
	interval int
}

func (f *tgHealthFlags) check(cmd *cobra.Command) error {
	if cmd.Flags().Changed("health-check-protocol") {
		p, err := oneOf("health-check-protocol", f.protocol, healthProtocols)
		if err != nil {
			return err
		}
		f.protocol = p
	}
	if cmd.Flags().Changed("health-check-port") && f.port != "traffic-port" {
		p, err := strconv.Atoi(f.port)
		if err != nil || checkPort("health-check-port", p) != nil {
			return app.UsageErrf("--health-check-port %q: expected traffic-port or a port between 1 and 65535", f.port)
		}
	}
	if cmd.Flags().Changed("health-check-interval") && (f.interval < 5 || f.interval > 300) {
		return app.UsageErrf("--health-check-interval %d: expected 5 to 300 seconds (and more than the health check timeout, 10 seconds by default for TCP)", f.interval)
	}
	return nil
}

func tgCreateCmd(rt *app.Runtime) *cobra.Command {
	var name, protocol, vpc, targetType, region string
	var port int
	var hf tgHealthFlags
	var targetSpecs []string
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a target group and register targets",
		Long: `Create the target group <name> for --protocol (TCP, TLS, UDP, TCP_UDP, HTTP,
HTTPS) on --port in --vpc (default defaults.aws.vpc_id; one of the two is
required). --target-type is instance (default; targets are instance ids) or
ip (targets are IP addresses). The health check keeps the AWS defaults
unless --health-check-protocol (TCP, HTTP, HTTPS), --health-check-port
(traffic-port or a port) or --health-check-interval (seconds) are given.
--target <id>[:<port>] (repeatable) registers targets; a missing port is
the group's port. A group of that name is an error (exit code 1). Protocol,
port, VPC and target type cannot be changed later. The group is tagged
polyctl:managed=true and with the tags of defaults.aws.tags.`,
		Example: `  polyctl aws elbv2 target-group create db-30001-target --protocol TCP --port 3306 --target-type ip \
    --health-check-interval 300 --target 10.0.1.25 --vpc vpc-0abc`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name = args[0]
			if err := checkELBName("target group", name, false); err != nil {
				return err
			}
			if protocol == "" {
				return app.UsageErrf("--protocol is required (%s)", strings.Join(elbProtocols, ", "))
			}
			var err error
			if protocol, err = oneOf("protocol", protocol, elbProtocols); err != nil {
				return err
			}
			if !cmd.Flags().Changed("port") {
				return app.UsageErrf("--port is required")
			}
			if err := checkPort("port", port); err != nil {
				return err
			}
			if targetType, err = oneOf("target-type", targetType, tgTargetTypes); err != nil {
				return err
			}
			if err := hf.check(cmd); err != nil {
				return err
			}
			targets, err := parseGroupTargets("target", targetSpecs, targetType, int32(port))
			if err != nil {
				return err
			}
			s, err := openELBScope(ctx, rt, region, "")
			if err != nil {
				return err
			}
			if vpc, err = rt.RequireSetting(s.profile, platform.AWS, "vpc_id", "vpc", vpc); err != nil {
				return err
			}
			if tg, err := s.c.FindTargetGroup(ctx, s.region, name); err != nil {
				return err
			} else if tg != nil {
				return fmt.Errorf("target group %q already exists in %s (%s): use `polyctl aws elbv2 target-group update %s` to change its targets", name, s.where(), tg.ID, name)
			}
			var tags map[string]string
			if !rt.DryRun() {
				if tags, err = elbTagsFor(rt, s.profile); err != nil {
					return err
				}
			}
			var tgID string
			var plan platform.Plan
			plan.Add(platform.Step{Resource: "target-group/" + name, Action: platform.Created,
				Desc: fmt.Sprintf("%s/%d %s %s", strings.ToLower(protocol), port, targetType, vpc),
				Apply: func(ctx context.Context) (platform.Change, error) {
					tg, err := s.c.CreateTargetGroup(ctx, platform.TargetGroupSpec{Region: s.region, Name: name, Protocol: protocol, Port: int32(port), VPC: vpc,
						TargetType: targetType, HealthCheckProtocol: hf.protocol, HealthCheckPort: hf.port, HealthCheckInterval: int32(hf.interval), Tags: tags})
					if err != nil {
						return platform.Change{}, err
					}
					tgID = tg.ID
					return platform.Change{ID: tg.ID}, nil
				}})
			addTargetSteps(&plan, s, "target-group/"+name+"/target", func() string { return tgID }, targets, platform.Created)
			return rt.Ensure(ctx, "aws.elbv2.target-group.create", s.target(), &plan)
		},
	}
	cmd.Flags().StringVar(&protocol, "protocol", "", "TCP, TLS, UDP, TCP_UDP, HTTP or HTTPS (required)")
	cmd.Flags().IntVar(&port, "port", 0, "port the targets receive traffic on (required)")
	cmd.Flags().StringVar(&vpc, "vpc", "", "VPC of the group (default: defaults.aws.vpc_id)")
	cmd.Flags().StringVar(&targetType, "target-type", "instance", "instance or ip")
	cmd.Flags().StringVar(&hf.protocol, "health-check-protocol", "", "TCP, HTTP or HTTPS (default: the AWS default)")
	cmd.Flags().StringVar(&hf.port, "health-check-port", "", "traffic-port or a port (default: traffic-port)")
	cmd.Flags().IntVar(&hf.interval, "health-check-interval", 0, "seconds between health checks, 5 to 300 (default: the AWS default, 30)")
	cmd.Flags().StringArrayVar(&targetSpecs, "target", nil, "target <id>[:<port>] to register (repeatable)")
	cmd.Flags().StringVar(&region, "region", "", "region of the group (default: the profile's region)")
	return cmd
}

// addTargetSteps adds one step per target: registered (action Created) or
// deregistered (action Deleted) in the group groupID returns.
func addTargetSteps(plan *platform.Plan, s *lbScope, resource string, groupID func() string, targets []platform.LBTargetSpec, action platform.Action) {
	for _, t := range targets {
		t := t
		plan.Add(platform.Step{Resource: resource, Action: action, Desc: t.String(), Apply: func(ctx context.Context) (platform.Change, error) {
			var err error
			if action == platform.Deleted {
				err = s.c.DeregisterTargets(ctx, s.region, groupID(), []platform.LBTargetSpec{t})
			} else {
				err = s.c.RegisterTargets(ctx, s.region, groupID(), []platform.LBTargetSpec{t})
			}
			return platform.Change{}, err
		}})
	}
}

// -------------------------------------------------------------- update

func tgUpdateCmd(rt *app.Runtime) *cobra.Command {
	var region string
	var add, remove, set []string
	var hf tgHealthFlags
	cmd := &cobra.Command{
		Use:   "update <name|arn>",
		Short: "Register or deregister targets, or change the health check of a target group",
		Long: `Change the targets or the health check of a target group. Targets are
<id>[:<port>] (an instance id, or an IP address for ip groups; a missing port
is the group's port).

- --add-target registers targets; registered ones are unchanged.
- --remove-target deregisters targets; ones that are not registered are
  unchanged. A deregistered target drains first (deregistration delay, 300
  seconds by default) and shows as draining until then.
- --set-target makes the targets of each port it names exactly the given
  ones: the others on those ports are deregistered, the missing ones
  registered; targets on other ports are left alone. It cannot be combined
  with --add-target or --remove-target.
- --health-check-protocol and --health-check-interval change the health
  check (when they differ). Protocol, port, VPC and target type cannot be
  changed.`,
		Example: "  polyctl aws elbv2 target-group update site-xz7-80-target --set-target i-0123456789abcdef0\n  polyctl aws elbv2 target-group update db-target --health-check-interval 300",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			fl := cmd.Flags()
			if len(add) == 0 && len(remove) == 0 && len(set) == 0 && !fl.Changed("health-check-protocol") && !fl.Changed("health-check-interval") {
				return app.UsageErrf("nothing to update: pass --add-target, --remove-target, --set-target, --health-check-protocol or --health-check-interval")
			}
			if len(set) > 0 && (len(add) > 0 || len(remove) > 0) {
				return app.UsageErrf("--set-target cannot be combined with --add-target or --remove-target")
			}
			if err := hf.check(cmd); err != nil {
				return err
			}
			for _, specs := range [][]string{add, remove, set} {
				if _, err := platform.ParseTargets(specs); err != nil {
					return err
				}
			}
			s, tg, err := openTG(ctx, rt, args[0], region)
			if err != nil {
				return err
			}
			addT, err := parseGroupTargets("add-target", add, tg.TargetType, tg.Port)
			if err != nil {
				return err
			}
			removeT, err := parseGroupTargets("remove-target", remove, tg.TargetType, tg.Port)
			if err != nil {
				return err
			}
			setT, err := parseGroupTargets("set-target", set, tg.TargetType, tg.Port)
			if err != nil {
				return err
			}
			current, err := s.c.TargetHealth(ctx, s.region, tg.ID)
			if err != nil {
				return err
			}
			registered := func(t platform.LBTargetSpec) bool { return isRegistered(current, t.ID, t.Port) }
			res := "target-group/" + tg.Name + "/target"
			var plan platform.Plan
			var toAdd, toRemove []platform.LBTargetSpec
			if len(setT) > 0 {
				ports := map[int32]bool{}
				for _, t := range setT {
					ports[t.Port] = true
				}
				for _, c := range current {
					t := platform.LBTargetSpec{ID: c.ID, Port: c.Port}
					if ports[c.Port] && c.State != "draining" && !slices.Contains(setT, t) {
						toRemove = append(toRemove, t)
					}
				}
				addT = setT
			} else {
				for _, t := range removeT {
					if registered(t) {
						toRemove = append(toRemove, t)
					} else {
						plan.Add(platform.Step{Resource: res, Action: platform.Unchanged, Desc: t.String() + " (not registered)"})
					}
				}
			}
			for _, t := range addT {
				if registered(t) {
					plan.Add(platform.Step{Resource: res, Action: platform.Unchanged, Desc: t.String()})
				} else {
					toAdd = append(toAdd, t)
				}
			}
			id := func() string { return tg.ID }
			addTargetSteps(&plan, s, res, id, toRemove, platform.Deleted)
			addTargetSteps(&plan, s, res, id, toAdd, platform.Created)
			hcRes := "target-group/" + tg.Name + "/health-check"
			if fl.Changed("health-check-protocol") {
				if hf.protocol == tg.HealthCheck.Protocol {
					plan.Add(platform.Step{Resource: hcRes, Desc: "protocol " + hf.protocol})
				} else {
					p := hf.protocol
					plan.Add(platform.Step{Resource: hcRes, Action: platform.Updated, ID: tg.ID, Desc: fmt.Sprintf("protocol %s -> %s", tg.HealthCheck.Protocol, p),
						Apply: func(ctx context.Context) (platform.Change, error) {
							return platform.Change{}, s.c.ModifyTargetGroupHealthCheck(ctx, s.region, tg.ID, platform.HealthCheckChange{Protocol: p})
						}})
				}
			}
			if fl.Changed("health-check-interval") {
				iv := int32(hf.interval)
				if iv == tg.HealthCheck.IntervalSeconds {
					plan.Add(platform.Step{Resource: hcRes, Desc: fmt.Sprintf("interval %ds", iv)})
				} else {
					plan.Add(platform.Step{Resource: hcRes, Action: platform.Updated, ID: tg.ID, Desc: fmt.Sprintf("interval %ds -> %ds", tg.HealthCheck.IntervalSeconds, iv),
						Apply: func(ctx context.Context) (platform.Change, error) {
							return platform.Change{}, s.c.ModifyTargetGroupHealthCheck(ctx, s.region, tg.ID, platform.HealthCheckChange{Interval: iv})
						}})
				}
			}
			return rt.Ensure(ctx, "aws.elbv2.target-group.update", s.target(), &plan)
		},
	}
	cmd.Flags().StringArrayVar(&add, "add-target", nil, "register target <id>[:<port>] (repeatable)")
	cmd.Flags().StringArrayVar(&remove, "remove-target", nil, "deregister target <id>[:<port>] (repeatable)")
	cmd.Flags().StringArrayVar(&set, "set-target", nil, "the targets of the ports named, exactly: <id>[:<port>] (repeatable)")
	cmd.Flags().StringVar(&hf.protocol, "health-check-protocol", "", "TCP, HTTP or HTTPS")
	cmd.Flags().IntVar(&hf.interval, "health-check-interval", 0, "seconds between health checks, 5 to 300")
	cmd.Flags().StringVar(&region, "region", "", "region of the target group (default: the profile's region, or the ARN's)")
	return cmd
}

// -------------------------------------------------------------- delete

func tgDeleteCmd(rt *app.Runtime) *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:   "delete <name|arn>",
		Short: "Delete a target group (asks first)",
		Long: `Delete a target group. Its protocol, port, load balancers and targets are
shown first, then a confirmation is asked (default no; --yes skips it, and
the non-interactive flow needs --yes). A group a listener or rule still
forwards to is exit code 1 (ResourceInUse): change or delete the listener
first.`,
		Example: "  polyctl aws elbv2 target-group delete site-xz7-443-target --yes",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			s, tg, err := openTG(ctx, rt, args[0], region)
			if err != nil {
				return err
			}
			targets, err := s.c.TargetHealth(ctx, s.region, tg.ID)
			if err != nil {
				return err
			}
			var lbs, ts []string
			for _, lb := range tg.LoadBalancers {
				lbs = append(lbs, arnName(lb))
			}
			for _, t := range targets {
				ts = append(ts, platform.LBTargetSpec{ID: t.ID, Port: t.Port}.String())
			}
			rt.Infof("target group %s in %s", tg.Name, s.where())
			rt.Infof("  protocol        %s/%d %s", tg.Protocol, tg.Port, tg.TargetType)
			rt.Infof("  load balancers  %s", joinOrNone(lbs))
			rt.Infof("  targets         %s", joinOrNone(ts))
			if len(lbs) > 0 {
				rt.Infof("warning: listeners of %s forward to the group; AWS refuses to delete it until they no longer do", strings.Join(lbs, ", "))
			}
			change := platform.Change{Resource: "target-group/" + tg.Name, Action: platform.Deleted, ID: tg.ID}
			if done, err := rt.WouldWrite(s.target(), change); done || err != nil {
				return err
			}
			ok, err := rt.Confirm(ctx, fmt.Sprintf("Delete target group %s?", tg.Name), false)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("%w: cancelled; target group %s was not deleted", platform.ErrNothingToDo, tg.Name)
			}
			if err := s.c.DeleteTargetGroup(ctx, s.region, tg.ID); err != nil {
				if platform.HasErrorCode(err, errResourceInUse) {
					return fmt.Errorf("target group %s is in use by a listener or rule: change or delete the listener first (polyctl aws elbv2 listener list <lb>): %w", tg.Name, err)
				}
				return err
			}
			return rt.RenderReport(platform.Report{Target: s.target(), Changes: []platform.Change{change}})
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region of the target group (default: the profile's region, or the ARN's)")
	return cmd
}
