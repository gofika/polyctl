package aws

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// defaultEnsureListeners are the listeners of load-balancer ensure without
// --listener: TCP pass-through of HTTP and HTTPS to the instance.
var defaultEnsureListeners = []string{"tcp:80", "tcp:443"}

// lbEnsureListener is a listener in the result of load-balancer ensure.
type lbEnsureListener struct {
	Port        int32  `json:"port" yaml:"port"`
	Protocol    string `json:"protocol" yaml:"protocol"`
	TargetGroup string `json:"target_group" yaml:"target_group"`
}

// lbEnsureResult is the load balancer load-balancer ensure stands for.
type lbEnsureResult struct {
	Name      string             `json:"name" yaml:"name"`
	ARN       string             `json:"arn" yaml:"arn"`
	Type      string             `json:"type" yaml:"type"`
	Scheme    string             `json:"scheme" yaml:"scheme"`
	State     string             `json:"state" yaml:"state"`
	VPC       string             `json:"vpc_id" yaml:"vpc_id"`
	DNSName   string             `json:"dns_name" yaml:"dns_name"`
	IPs       []string           `json:"ips" yaml:"ips"`
	Listeners []lbEnsureListener `json:"listeners" yaml:"listeners"`
}

// lbEnsureReport is the output of load-balancer ensure: the change report
// and the load balancer.
type lbEnsureReport struct {
	platform.Report `yaml:",inline"`
	LoadBalancer    lbEnsureResult `json:"load_balancer" yaml:"load_balancer"`
}

// ensurePort is what load-balancer ensure knows about one listener port.
type ensurePort struct {
	port   int32
	tgName string
	tg     *platform.LBTargetGroup
	// registered: the target is in the group on this port and not draining.
	registered bool
	listener   *platform.LBListener
	// tgID is the id of the group once known (Pending in a dry run).
	tgID string
}

// lbEnsure holds the state of one load-balancer ensure run.
type lbEnsure struct {
	rt         *app.Runtime
	s          *lbScope
	inst       *locatedInstance
	lbName     string
	targetType string
	targetID   string
	vpc        string
	subnets    []string
	sgs        []string
	wait       bool
	timeout    time.Duration
	ports      []*ensurePort
	lb         *platform.LoadBalancer
	tags       map[string]string
	plan       platform.Plan
}

func lbEnsureCmd(rt *app.Runtime) *cobra.Command {
	var instance, typ, targetType, region string
	var listenerSpecs, subnets, sgs []string
	var skipHTTPS, waitHealthy bool
	var wf app.WaitFlags
	cmd := &cobra.Command{
		Use:   "ensure <name>",
		Short: "Put a Network Load Balancer in front of an EC2 instance (TCP 80 and 443)",
		Long: `Make sure a Network Load Balancer forwards TCP traffic to an instance: one
target group per listener port with the instance registered, the load
balancer, and one TCP listener per port. What already matches is reported
unchanged and nothing is written for it; running it again changes nothing.
At the end the DNS name of the load balancer and the addresses it resolves
to are printed.

- <name> is the main name: the load balancer is naming.aws_elbv2_load_balancer
  ({name}-lb by default) and the target group of a port
  naming.aws_elbv2_target_group ({name}-{port}-target). Names are the key:
  changing a template makes ensure build a new set instead of finding the
  old one. Every name is checked before anything is written: at most 32
  letters, digits and hyphens (exit code 2), so with the default templates
  <name> has at most 21 characters.
- --instance (Name tag or id, found in every selected account like instance
  get) must be running (exit code 1 otherwise). The target groups are
  created in its VPC, the load balancer in its subnet unless --subnet, which
  must include a subnet of the instance's availability zone (AWS would
  accept the target and never route to it).
- --listener tcp:<port> (repeatable; default tcp:80 and tcp:443; --skip-https
  is tcp:80 alone). Only TCP listeners are supported (other protocols are
  exit code 7): TLS passes through to the instance. --type application is
  not supported either (exit code 7).
- A target group is TCP on the listener port with a TCP health check on the
  traffic port and the AWS default interval. One that exists with another
  protocol, port, VPC or target type is exit code 1 before anything is
  written: those cannot be changed. --target-type ip registers the
  instance's private address instead of its id.
- The load balancer is internet-facing, ipv4, with the --sg security groups
  (default defaults.aws.elb_security_group_ids). Without any it is created
  without security groups, and AWS never lets a Network Load Balancer
  created so have any: an existing one is then reported skipped when
  security groups are asked for. An existing load balancer of the name must
  be a network one in the instance's VPC and availability zone; its scheme
  and subnets are left as they are.
- A listener on the port that forwards elsewhere, or with another protocol,
  is modified in place (no downtime), never deleted and created again.
- The new load balancer is waited for until active (15 second polls,
  --timeout 10m; --no-wait returns at once), then its DNS name is resolved
  (retried for a minute). --wait-healthy also waits until the instance is
  healthy in every target group.
- The instance's security groups must let the clients in (for instance
  tcp:80:0.0.0.0/0 and tcp:443:0.0.0.0/0, see aws ec2 security-group
  ensure): the client address is preserved, so allowing the load balancer
  alone is not enough.
- -o json adds "load_balancer": {"name", "arn", "type", "scheme", "state",
  "vpc_id", "dns_name", "ips", "listeners": [{"port", "protocol",
  "target_group"}]}.`,
		Example: `  polyctl aws elbv2 load-balancer ensure site-xz7 --instance site-xz7 --dry-run
  polyctl aws elbv2 load-balancer ensure site-xz7 --instance site-xz7 --listener tcp:80 --listener tcp:443
  polyctl aws elbv2 load-balancer ensure site-xz7 --instance site-xz7 --skip-https`,
		Args: app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name := strings.TrimSpace(app.Arg(args, 0))
			if len(args) > 0 && name == "" {
				return app.UsageErrf("the name is empty")
			}
			var err error
			if typ, err = oneOf("type", typ, lbTypes); err != nil {
				return err
			}
			if typ != "network" {
				return fmt.Errorf("%w: load-balancer ensure builds Network Load Balancers only; --type %s is not supported (use create, then target-group and listener)", platform.ErrNotSupported, typ)
			}
			if skipHTTPS && cmd.Flags().Changed("listener") {
				return app.UsageErrf("--skip-https and --listener contradict each other: --skip-https means --listener tcp:80 alone")
			}
			specs := listenerSpecs
			switch {
			case skipHTTPS:
				specs = []string{"tcp:80"}
			case len(specs) == 0:
				specs = defaultEnsureListeners
			}
			ports, err := ensureListenerPorts(specs)
			if err != nil {
				return err
			}
			if targetType, err = oneOf("target-type", targetType, tgTargetTypes); err != nil {
				return err
			}
			if err := checkSubnetIDs(subnets); err != nil {
				return err
			}
			if err := checkSGIDs(sgs); err != nil {
				return err
			}
			wait, timeout, err := wf.Resolve(cmd)
			if err != nil {
				return err
			}
			if waitHealthy && !wait {
				return app.UsageErrf("--wait-healthy needs the wait: drop --no-wait")
			}
			if strings.TrimSpace(instance) == "" {
				if !rt.Interactive() {
					return app.UsageErrf("--instance is required: the instance the load balancer forwards to (Name tag or id)")
				}
				if instance, err = pickInstanceRef(ctx, rt, "--instance", "", region, "running AWS instance", true, statesIn(stateRunning)); err != nil {
					return err
				}
			}
			if name == "" {
				// The interactive flow: the main name, the instance's name
				// proposed, checked as typed against the naming templates.
				if name, err = askEnsureName(ctx, rt, instance, region, ports); err != nil {
					return err
				}
			}
			e := &lbEnsure{rt: rt, targetType: targetType, wait: wait, timeout: timeout}
			if err := e.observe(ctx, name, instance, region, ports, subnets, sgs); err != nil {
				return err
			}
			e.build()
			return e.run(ctx, waitHealthy)
		},
	}
	cmd.Flags().StringVar(&instance, "instance", "", "the instance to forward to (Name tag or id; required)")
	cmd.Flags().StringVar(&typ, "type", "network", "load balancer type; only network is supported")
	cmd.Flags().StringArrayVar(&listenerSpecs, "listener", nil, "listener tcp:<port>, one target group each (repeatable; default tcp:80 and tcp:443)")
	cmd.Flags().BoolVar(&skipHTTPS, "skip-https", false, "only the tcp:80 listener (same as --listener tcp:80)")
	cmd.Flags().StringVar(&targetType, "target-type", "instance", "instance (register the instance id) or ip (register its private address)")
	cmd.Flags().StringArrayVar(&subnets, "subnet", nil, "subnet of a new load balancer, one per availability zone (repeatable; default: the instance's subnet)")
	cmd.Flags().StringArrayVar(&sgs, "sg", nil, "security group of a new load balancer (repeatable; default: defaults.aws.elb_security_group_ids)")
	cmd.Flags().BoolVar(&waitHealthy, "wait-healthy", false, "also wait until the instance is healthy in every target group")
	cmd.Flags().StringVar(&region, "region", "", "region of the instance (default: found through the inventory)")
	app.AddWaitFlags(cmd, &wf, true, app.DefaultWaitTimeout)
	return cmd
}

// ensureListenerPorts parses the --listener values of ensure: TCP only,
// each port once.
func ensureListenerPorts(specs []string) ([]int32, error) {
	var ports []int32
	for _, spec := range specs {
		l, err := platform.ParseListener(spec)
		if err != nil {
			return nil, err
		}
		if l.Protocol != "tcp" {
			return nil, fmt.Errorf("%w: --listener %s: load-balancer ensure supports tcp listeners only (TLS passes through a tcp listener to the instance); use listener create for other protocols", platform.ErrNotSupported, spec)
		}
		if !slices.Contains(ports, int32(l.Port)) {
			ports = append(ports, int32(l.Port))
		}
	}
	return ports, nil
}

// tgDiffs lists how a target group differs from what ensure needs; these
// settings cannot change after creation.
func tgDiffs(tg platform.LBTargetGroup, port int32, vpc, targetType string) []string {
	var out []string
	if tg.Protocol != "TCP" {
		out = append(out, fmt.Sprintf("protocol %s (want TCP)", tg.Protocol))
	}
	if tg.Port != port {
		out = append(out, fmt.Sprintf("port %d (want %d)", tg.Port, port))
	}
	if tg.VPC != vpc {
		out = append(out, fmt.Sprintf("VPC %s (want %s, the instance's)", tg.VPC, vpc))
	}
	if tg.TargetType != targetType {
		out = append(out, fmt.Sprintf("target type %s (want %s)", tg.TargetType, targetType))
	}
	return out
}

func tgMismatch(name string, diffs []string) error {
	return fmt.Errorf("target group %s exists with other settings: %s; these cannot be changed after creation: delete it (polyctl aws elbv2 target-group delete %s) or use another name", name, strings.Join(diffs, ", "), name)
}

// observe reads everything ensure needs (the instance, its subnets, the
// target groups, their targets, the load balancer and its listeners) and
// checks every name and setting before anything is written.
func (e *lbEnsure) observe(ctx context.Context, name, instance, region string, ports []int32, subnetFlags, sgFlags []string) error {
	rt := e.rt
	l, err := resolveInstance(ctx, rt, instance, region, false)
	if err != nil {
		return err
	}
	if st := instanceState(l.inst); st != stateRunning {
		return fmt.Errorf("instance %s is not running (state %s): start it first (polyctl aws ec2 instance start %s)", instanceLabel(l.inst), st, l.id())
	}
	e.inst = l
	e.s = &lbScope{c: l.c, profile: l.profile, region: l.region}
	vars := map[string]string{"name": name, "region": e.s.region, "protocol": "tcp"}
	if e.lbName, err = rt.ResourceName("aws_elbv2_load_balancer", "", vars); err != nil {
		return app.UsageErrf("%v", err)
	}
	if err := checkELBName("load balancer", e.lbName, true); err != nil {
		return err
	}
	seen := map[string]int32{}
	for _, p := range ports {
		v := map[string]string{"name": name, "region": e.s.region, "protocol": "tcp", "port": strconv.Itoa(int(p))}
		tgName, err := rt.ResourceName("aws_elbv2_target_group", "", v)
		if err != nil {
			return app.UsageErrf("%v", err)
		}
		if err := checkELBName("target group", tgName, false); err != nil {
			return err
		}
		if other, ok := seen[tgName]; ok {
			return app.UsageErrf("ports %d and %d would share the target group %s: naming.aws_elbv2_target_group must use {port}", other, p, tgName)
		}
		seen[tgName] = p
		e.ports = append(e.ports, &ensurePort{port: p, tgName: tgName})
	}

	e.vpc = awssdk.ToString(l.inst.VpcId)
	instSubnet := awssdk.ToString(l.inst.SubnetId)
	instAZ := ""
	if l.inst.Placement != nil {
		instAZ = awssdk.ToString(l.inst.Placement.AvailabilityZone)
	}
	if e.vpc == "" || instSubnet == "" {
		return fmt.Errorf("instance %s is in no VPC subnet; a Network Load Balancer cannot forward to it", instanceLabel(l.inst))
	}
	if e.targetType == "ip" {
		if e.targetID = awssdk.ToString(l.inst.PrivateIpAddress); e.targetID == "" {
			return fmt.Errorf("instance %s has no private IPv4 address to register (--target-type ip)", instanceLabel(l.inst))
		}
	} else {
		e.targetID = l.id()
	}
	e.subnets = subnetFlags
	if len(e.subnets) == 0 {
		e.subnets = []string{instSubnet}
	} else if err := e.checkSubnets(ctx, instAZ); err != nil {
		return err
	}
	if e.sgs, err = rt.SettingList(e.s.profile, platform.AWS, "elb_security_group_ids", sgFlags); err != nil {
		return err
	}
	if err := checkSGIDs(e.sgs); err != nil {
		return app.UsageErrf("defaults.aws.elb_security_group_ids: %v", err)
	}
	if !rt.DryRun() {
		if e.tags, err = elbTagsFor(rt, e.s.profile); err != nil {
			return err
		}
	}

	for _, p := range e.ports {
		tg, err := e.s.c.FindTargetGroup(ctx, e.s.region, p.tgName)
		if err != nil {
			return err
		}
		if tg == nil {
			continue
		}
		if diffs := tgDiffs(*tg, p.port, e.vpc, e.targetType); len(diffs) > 0 {
			return tgMismatch(p.tgName, diffs)
		}
		p.tg, p.tgID = tg, tg.ID
		targets, err := e.s.c.TargetHealth(ctx, e.s.region, tg.ID)
		if err != nil {
			return err
		}
		p.registered = isRegistered(targets, e.targetID, p.port)
	}
	if e.lb, err = e.s.c.FindLoadBalancer(ctx, e.s.region, e.lbName); err != nil {
		return err
	}
	if e.lb != nil {
		if err := e.checkLB(*e.lb, instAZ); err != nil {
			return err
		}
		listeners, err := e.s.c.ListListeners(ctx, e.s.region, e.lb.ID)
		if err != nil {
			return err
		}
		for _, p := range e.ports {
			for i := range listeners {
				if listeners[i].Port == p.port {
					p.listener = &listeners[i]
				}
			}
		}
	} else if len(e.sgs) == 0 {
		rt.Infof("note: no security group for the new load balancer (--sg or defaults.aws.elb_security_group_ids): it is created without any, and AWS never lets a Network Load Balancer created so have any")
	}
	return nil
}

// isRegistered reports whether id is a target of the group on port that is
// not draining (a draining target is on its way out).
func isRegistered(targets []platform.LBTarget, id string, port int32) bool {
	for _, t := range targets {
		if t.ID == id && t.Port == port && t.State != "draining" {
			return true
		}
	}
	return false
}

// checkSubnets checks --subnet: every subnet in the instance's VPC, and one
// of them in the instance's availability zone.
func (e *lbEnsure) checkSubnets(ctx context.Context, instAZ string) error {
	out, err := e.s.c.ec2For(e.s.region).DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{SubnetIds: e.subnets})
	if err != nil {
		return ec2Err("DescribeSubnets", e.s.region, err)
	}
	var zones []string
	for _, sn := range out.Subnets {
		if v := awssdk.ToString(sn.VpcId); v != e.vpc {
			return fmt.Errorf("subnet %s is in %s, not in the VPC of instance %s (%s)", awssdk.ToString(sn.SubnetId), v, instanceLabel(e.inst.inst), e.vpc)
		}
		zones = append(zones, awssdk.ToString(sn.AvailabilityZone))
	}
	if len(out.Subnets) < len(e.subnets) {
		return fmt.Errorf("%w: some of the subnets %s in %s", platform.ErrNotFound, strings.Join(e.subnets, ", "), e.s.region)
	}
	if instAZ != "" && !slices.Contains(zones, instAZ) {
		return fmt.Errorf("no --subnet is in %s, the availability zone of instance %s: the load balancer would never route to it (AWS accepts the target and reports it unused); add a subnet of %s", instAZ, instanceLabel(e.inst.inst), instAZ)
	}
	return nil
}

// checkLB checks an existing load balancer of the name: a network one, in
// the instance's VPC, enabled in its availability zone.
func (e *lbEnsure) checkLB(lb platform.LoadBalancer, instAZ string) error {
	if lb.Type != "network" {
		return fmt.Errorf("load balancer %s exists and is of type %s, not network: the name is taken (use another name)", lb.Name, lb.Type)
	}
	if lb.VPC != e.vpc {
		return fmt.Errorf("load balancer %s is in %s, not in the VPC of instance %s (%s)", lb.Name, lb.VPC, instanceLabel(e.inst.inst), e.vpc)
	}
	if instAZ != "" && !slices.Contains(lb.ZoneNames(), instAZ) {
		return fmt.Errorf("load balancer %s is not enabled in %s, the availability zone of instance %s (it is in %s): it would never route to it; add a subnet of %s (polyctl aws elbv2 load-balancer update %s --subnet ...)",
			lb.Name, instAZ, instanceLabel(e.inst.inst), joinOrNone(lb.ZoneNames()), instAZ, lb.Name)
	}
	return nil
}

func (e *lbEnsure) lbID() string {
	if e.lb != nil {
		return e.lb.ID
	}
	return platform.Pending
}

func (e *lbEnsure) lbDesc() string { return "network internet-facing" }

// build turns what observe found into the plan: every target group (and
// its registration), then the load balancer, then every listener.
func (e *lbEnsure) build() {
	rt, s, tags := e.rt, e.s, e.tags
	for _, p := range e.ports {
		p := p
		res := "target-group/" + p.tgName
		if p.tg != nil {
			e.plan.Add(platform.Step{Resource: res, Action: platform.Unchanged, ID: p.tg.ID})
		} else {
			e.plan.Add(platform.Step{Resource: res, Action: platform.Created, Desc: fmt.Sprintf("tcp/%d %s %s", p.port, e.targetType, e.vpc),
				Apply: func(ctx context.Context) (platform.Change, error) {
					tg, err := s.c.CreateTargetGroup(ctx, platform.TargetGroupSpec{Region: s.region, Name: p.tgName, Protocol: "TCP", Port: p.port,
						VPC: e.vpc, TargetType: e.targetType, HealthCheckProtocol: "TCP", HealthCheckPort: "traffic-port", Tags: tags})
					if platform.HasErrorCode(err, errDuplicateTGName) {
						found, ferr := s.c.FindTargetGroup(ctx, s.region, p.tgName)
						if ferr != nil || found == nil {
							return platform.Change{}, err
						}
						if diffs := tgDiffs(*found, p.port, e.vpc, e.targetType); len(diffs) > 0 {
							return platform.Change{}, tgMismatch(p.tgName, diffs)
						}
						p.tgID = found.ID
						return platform.Change{Action: platform.Unchanged, ID: found.ID, Detail: "created meanwhile by someone else"}, nil
					}
					if err != nil {
						return platform.Change{}, err
					}
					p.tgID = tg.ID
					return platform.Change{ID: tg.ID}, nil
				}})
		}
		target := platform.LBTargetSpec{ID: e.targetID, Port: p.port}
		if p.registered {
			e.plan.Add(platform.Step{Resource: res + "/target", Action: platform.Unchanged, Desc: target.String()})
		} else {
			e.plan.Add(platform.Step{Resource: res + "/target", Action: platform.Created, Desc: target.String(),
				Apply: func(ctx context.Context) (platform.Change, error) {
					if err := s.c.RegisterTargets(ctx, s.region, p.tgID, []platform.LBTargetSpec{target}); err != nil {
						return platform.Change{}, err
					}
					return platform.Change{}, nil
				}})
		}
	}

	lbRes := "load-balancer/" + e.lbName
	if e.lb != nil {
		lb := e.lb
		e.plan.Add(platform.Step{Resource: lbRes, Check: func(ctx context.Context) (platform.Change, bool, error) {
			detail := fmt.Sprintf("%s %s, %s", lb.Type, lb.Scheme, lb.State)
			if lb.State == "active" || !e.wait || rt.DryRun() {
				return platform.Change{Action: platform.Unchanged, ID: lb.ID, Detail: detail}, true, nil
			}
			rt.Infof("waiting for load balancer %s to become active (up to %s)...", lb.Name, e.timeout)
			again, err := s.c.waitLoadBalancerActive(ctx, s.region, lb.ID, lb.Name, e.timeout)
			if err != nil {
				return platform.Change{ID: lb.ID}, false, err
			}
			*e.lb = again
			return platform.Change{Action: platform.Unchanged, ID: lb.ID, Detail: fmt.Sprintf("%s %s, active", lb.Type, lb.Scheme)}, true, nil
		}})
		switch {
		case len(e.sgs) == 0:
		case len(lb.SecurityGroups) == 0:
			e.plan.Add(platform.Step{Resource: lbRes + "/security-groups", Action: platform.Skipped,
				Desc: fmt.Sprintf("created without security groups: AWS cannot add %s (delete and create the load balancer again to have them)", strings.Join(e.sgs, ","))})
		case !sameSet(lb.SecurityGroups, e.sgs):
			e.plan.Add(platform.Step{Resource: lbRes + "/security-groups", Action: platform.Skipped,
				Desc: fmt.Sprintf("has %s, not %s: left as it is (use load-balancer update --sg)", strings.Join(lb.SecurityGroups, ","), strings.Join(e.sgs, ","))})
		}
	} else {
		e.plan.Add(platform.Step{Resource: lbRes, Action: platform.Created,
			Desc: fmt.Sprintf("%s, subnets %s, security groups %s", e.lbDesc(), strings.Join(e.subnets, ","), joinOrNone(e.sgs)),
			Apply: func(ctx context.Context) (platform.Change, error) {
				return e.createLB(ctx, tags)
			}})
	}

	for _, p := range e.ports {
		p := p
		res := fmt.Sprintf("listener/%s:%d", e.lbName, p.port)
		want := fmt.Sprintf("tcp:%d -> %s", p.port, p.tgName)
		switch {
		case p.listener == nil:
			e.plan.Add(platform.Step{Resource: res, Action: platform.Created, Desc: want,
				Apply: func(ctx context.Context) (platform.Change, error) { return e.createListener(ctx, p) }})
		case p.tg != nil && p.listener.Protocol == "TCP" && p.listener.ForwardsTo(p.tg.ID):
			e.plan.Add(platform.Step{Resource: res, Action: platform.Unchanged, ID: p.listener.ID, Desc: want})
		default:
			ls := p.listener
			e.plan.Add(platform.Step{Resource: res, Action: platform.Updated, ID: ls.ID, Desc: listenerSummary(*ls) + " -> " + want,
				Apply: func(ctx context.Context) (platform.Change, error) {
					if _, err := s.c.ModifyListener(ctx, s.region, ls.ID, "TCP", p.tgID); err != nil {
						return platform.Change{}, err
					}
					return platform.Change{}, nil
				}})
		}
	}
}

// listenerSummary describes a listener as "tcp:80 -> target-group".
func listenerSummary(l platform.LBListener) string {
	to := l.DefaultAction
	if len(l.TargetGroups) > 0 {
		var names []string
		for _, tg := range l.TargetGroups {
			names = append(names, arnName(tg))
		}
		to = strings.Join(names, ",")
	}
	return fmt.Sprintf("%s:%d -> %s", strings.ToLower(l.Protocol), l.Port, to)
}

// createLB creates the load balancer and waits until it is active (unless
// --no-wait). A load balancer of the name created meanwhile with other
// settings (DuplicateLoadBalancerName) is used when it fits.
func (e *lbEnsure) createLB(ctx context.Context, tags map[string]string) (platform.Change, error) {
	rt, s := e.rt, e.s
	lb, err := s.c.CreateLoadBalancer(ctx, platform.LoadBalancerSpec{Region: s.region, Name: e.lbName, Type: "network", Scheme: "internet-facing",
		Subnets: e.subnets, IPAddressType: "ipv4", SecurityGroups: e.sgs, Tags: tags})
	action := platform.Created
	if platform.HasErrorCode(err, errDuplicateLBName) {
		found, ferr := s.c.FindLoadBalancer(ctx, s.region, e.lbName)
		if ferr != nil || found == nil {
			return platform.Change{}, err
		}
		instAZ := ""
		if e.inst.inst.Placement != nil {
			instAZ = awssdk.ToString(e.inst.inst.Placement.AvailabilityZone)
		}
		if cerr := e.checkLB(*found, instAZ); cerr != nil {
			return platform.Change{}, cerr
		}
		lb, err, action = *found, nil, platform.Unchanged
	}
	if err != nil {
		return platform.Change{}, err
	}
	e.lb = &lb
	storeLB(ctx, rt, s.profile, lb, nil)
	detail := fmt.Sprintf("%s %s, %s", lb.Type, lb.Scheme, lb.State)
	if e.wait && lb.State != "active" {
		rt.Infof("waiting for load balancer %s to become active (up to %s; usually 2 to 3 minutes)...", e.lbName, e.timeout)
		again, werr := s.c.waitLoadBalancerActive(ctx, s.region, lb.ID, e.lbName, e.timeout)
		if werr != nil {
			return platform.Change{ID: lb.ID}, werr
		}
		*e.lb = again
		detail = fmt.Sprintf("%s %s, active", lb.Type, lb.Scheme)
	}
	if action == platform.Unchanged {
		detail += " (created meanwhile by someone else)"
	}
	return platform.Change{Action: action, ID: lb.ID, Detail: detail}, nil
}

// createListener creates the listener of a port. A listener created
// meanwhile on the port (DuplicateListener) is read back: unchanged when it
// forwards to the group, modified otherwise.
func (e *lbEnsure) createListener(ctx context.Context, p *ensurePort) (platform.Change, error) {
	s := e.s
	l, err := s.c.CreateListener(ctx, platform.ListenerCreateSpec{Region: s.region, LoadBalancer: e.lb.ID, Protocol: "TCP", Port: p.port, TargetGroup: p.tgID})
	if platform.HasErrorCode(err, errDuplicateListener) {
		listeners, lerr := s.c.ListListeners(ctx, s.region, e.lb.ID)
		if lerr != nil {
			return platform.Change{}, err
		}
		for _, have := range listeners {
			if have.Port != p.port {
				continue
			}
			if have.Protocol == "TCP" && have.ForwardsTo(p.tgID) {
				return platform.Change{Action: platform.Unchanged, ID: have.ID, Detail: fmt.Sprintf("tcp:%d -> %s (created meanwhile by someone else)", p.port, p.tgName)}, nil
			}
			if _, merr := s.c.ModifyListener(ctx, s.region, have.ID, "TCP", p.tgID); merr != nil {
				return platform.Change{}, merr
			}
			return platform.Change{Action: platform.Updated, ID: have.ID, Detail: listenerSummary(have) + fmt.Sprintf(" -> tcp:%d -> %s", p.port, p.tgName)}, nil
		}
		return platform.Change{}, err
	}
	if err != nil {
		return platform.Change{}, err
	}
	return platform.Change{ID: l.ID}, nil
}

// result builds the load balancer part of the output: its DNS name, read
// again, and its addresses once it is active.
func (e *lbEnsure) result(ctx context.Context, planErr error) lbEnsureResult {
	rt, s := e.rt, e.s
	r := lbEnsureResult{Name: e.lbName, ARN: e.lbID(), Type: "network", Scheme: "internet-facing", VPC: e.vpc, IPs: []string{}, Listeners: []lbEnsureListener{}}
	for _, p := range e.ports {
		r.Listeners = append(r.Listeners, lbEnsureListener{Port: p.port, Protocol: "TCP", TargetGroup: p.tgName})
	}
	if e.lb == nil {
		r.State = platform.Pending
		return r
	}
	lb := *e.lb
	if planErr == nil {
		if again, err := s.c.FindLoadBalancer(ctx, s.region, lb.ID); err == nil && again != nil {
			lb = *again
		} else if err != nil {
			rt.Infof("warning: cannot read load balancer %s again: %v", e.lbName, err)
		}
	}
	r.ARN, r.Type, r.Scheme, r.State, r.VPC, r.DNSName = lb.ID, lb.Type, lb.Scheme, lb.State, lb.VPC, lb.DNSName
	if planErr != nil {
		return r
	}
	switch {
	case r.DNSName == "":
		rt.Infof("warning: cannot get the DNS name of load balancer %s", e.lbName)
	case r.State != "active":
		rt.Infof("note: load balancer %s is %s; its DNS name resolves once it is active", e.lbName, r.State)
	default:
		ips, err := resolveLBIPs(ctx, r.DNSName)
		if err != nil || len(ips) == 0 {
			rt.Infof("warning: cannot resolve %s yet: %v", r.DNSName, err)
		} else {
			r.IPs = ips
		}
	}
	storeLB(ctx, rt, s.profile, lb, r.IPs)
	return r
}

// waitHealthy waits until the target is healthy in every target group.
func (e *lbEnsure) waitHealthy(ctx context.Context) error {
	s := e.s
	for _, p := range e.ports {
		target := platform.LBTargetSpec{ID: e.targetID, Port: p.port}
		e.rt.Infof("waiting for %s to be healthy in target group %s (up to %s)...", target, p.tgName, e.timeout)
		err := platform.WaitUntil(ctx, platform.WaitOptions{Resource: "target-group/" + p.tgName + "/target " + target.String(), Want: "healthy",
			Timeout: e.timeout, Interval: lbActivePoll, Clock: elbClock},
			func(ctx context.Context) (platform.WaitState, string, error) {
				targets, err := s.c.TargetHealth(ctx, s.region, p.tgID)
				if err != nil {
					return 0, "", err
				}
				for _, t := range targets {
					if t.ID == e.targetID && t.Port == p.port {
						status := t.State
						if t.Reason != "" {
							status += " (" + t.Reason + ")"
						}
						if t.State == "healthy" {
							return platform.WaitDone, status, nil
						}
						return platform.KeepWaiting, status, nil
					}
				}
				return platform.KeepWaiting, "not registered", nil
			})
		if err != nil {
			return err
		}
	}
	return nil
}

// run runs the plan, reads the DNS name and addresses, and prints the
// report with the load balancer.
func (e *lbEnsure) run(ctx context.Context, waitHealthy bool) error {
	rt := e.rt
	rep, err := rt.RunPlan(ctx, e.s.target(), &e.plan)
	if rep.Changes == nil {
		rep.Changes = []platform.Change{}
	}
	if err == nil && waitHealthy && !rep.DryRun {
		err = e.waitHealthy(ctx)
	}
	out := lbEnsureReport{Report: rep, LoadBalancer: e.result(ctx, err)}
	if err == nil {
		writes := false
		for _, c := range rep.Changes {
			writes = writes || c.Action.Writes()
		}
		if !writes {
			rt.Infof("all unchanged")
		}
		if !rep.DryRun {
			rt.Infof("note: the security groups of instance %s must allow the clients on the listener ports (the client address is preserved), e.g. polyctl aws ec2 security-group ensure <name> --instance %s --rule tcp:80:0.0.0.0/0 --rule tcp:443:0.0.0.0/0", e.inst.name(), e.inst.id())
		}
	}
	if rerr := rt.Render(out, func() output.Grid { return app.ChangeGrid(rep.Changes) }); rerr != nil && err == nil {
		err = rerr
	}
	if rt.Format() == output.Table && out.LoadBalancer.DNSName != "" {
		fmt.Fprintf(rt.Stdout, "\n# load balancer\n%s\n", out.LoadBalancer.DNSName)
		for _, ip := range out.LoadBalancer.IPs {
			fmt.Fprintln(rt.Stdout, ip)
		}
	}
	if err != nil && !rep.DryRun && !errors.Is(err, app.ErrUsage) {
		rt.NotifyFailure(ctx, app.Failure{Event: "aws.elbv2.load-balancer.ensure.failed", Platform: string(platform.AWS), Profile: e.s.profile,
			Error: err.Error(), Changes: rep.Changes})
	}
	return err
}
