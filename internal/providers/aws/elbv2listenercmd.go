package aws

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// certProtocols are the listener protocols that need a certificate.
var certProtocols = []string{"TLS", "HTTPS"}

func needsCert(protocol string) bool {
	for _, p := range certProtocols {
		if p == protocol {
			return true
		}
	}
	return false
}

// listenerRef is a parsed <listener-arn|lb:port>.
type listenerRef struct {
	arn  string
	lb   string
	port int32
}

// parseListenerRef parses a listener ARN, or <lb>:<port> where lb is a
// load balancer name, ARN or DNS name.
func parseListenerRef(ref string) (listenerRef, error) {
	ref = strings.TrimSpace(ref)
	if isELBARN(ref, "listener") {
		return listenerRef{arn: ref}, nil
	}
	i := strings.LastIndex(ref, ":")
	if i <= 0 || i == len(ref)-1 {
		return listenerRef{}, app.UsageErrf("listener %q: expected a listener ARN or <load-balancer>:<port> (site-lb:80)", ref)
	}
	p, err := strconv.Atoi(ref[i+1:])
	if err != nil || p < 1 || p > 65535 {
		return listenerRef{}, app.UsageErrf("listener %q: %q is not a port (expected <load-balancer>:<port>)", ref, ref[i+1:])
	}
	return listenerRef{lb: ref[:i], port: int32(p)}, nil
}

// resolveListener finds the listener ref names, with the scope it is in.
func resolveListener(ctx context.Context, rt *app.Runtime, ref, region string) (*lbScope, *platform.LBListener, error) {
	lr, err := parseListenerRef(ref)
	if err != nil {
		return nil, nil, err
	}
	if lr.arn != "" {
		s, err := openELBScope(ctx, rt, region, lr.arn)
		if err != nil {
			return nil, nil, err
		}
		l, err := s.c.FindListener(ctx, s.region, lr.arn)
		if err != nil {
			return nil, nil, err
		}
		if l == nil {
			return nil, nil, fmt.Errorf("%w: listener %s in %s", platform.ErrNotFound, lr.arn, s.where())
		}
		return s, l, nil
	}
	s, lb, err := resolveLB(ctx, rt, lr.lb, region)
	if err != nil {
		return nil, nil, err
	}
	listeners, err := s.c.ListListeners(ctx, s.region, lb.ID)
	if err != nil {
		return nil, nil, err
	}
	for i := range listeners {
		if listeners[i].Port == lr.port {
			return s, &listeners[i], nil
		}
	}
	return nil, nil, fmt.Errorf("%w: load balancer %s has no listener on port %d", platform.ErrNotFound, lb.Name, lr.port)
}

// listenerName names a listener in reports: listener/<lb>:<port>.
func listenerName(l platform.LBListener) string {
	return fmt.Sprintf("listener/%s:%d", arnName(l.LoadBalancer), l.Port)
}

func listenerListGrid(ls []lbListenerView) output.Grid {
	g := output.Grid{Headers: []string{"PORT", "PROTOCOL", "FORWARDS TO", "ARN"}, Empty: "no listeners"}
	for _, l := range ls {
		to := l.DefaultAction
		if len(l.TargetGroups) > 0 {
			to = strings.Join(l.TargetGroups, ", ")
		}
		g.Rows = append(g.Rows, []string{strconv.Itoa(int(l.Port)), l.Protocol, to, l.ARN})
	}
	return g
}

func listenerDetailGrid(l lbListenerView) output.Grid {
	to := l.DefaultAction
	if len(l.TargetGroups) > 0 {
		to = l.DefaultAction + " " + strings.Join(l.TargetGroups, ", ")
	}
	return output.Grid{Rows: [][]string{
		{"LOAD BALANCER", l.LoadBalancer},
		{"PORT", strconv.Itoa(int(l.Port)), "PROTOCOL", l.Protocol},
		{"DEFAULT ACTION", to},
		{"CERTIFICATES", joinOrNone(l.Certificates)},
		{"ARN", l.ARN},
	}}
}

func listenerListCmd(rt *app.Runtime) *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:     "list <lb>",
		Short:   "List the listeners of a load balancer",
		Long:    "List the listeners of a load balancer (name, ARN or DNS name), by port, with the target groups they forward to.",
		Example: "  polyctl aws elbv2 listener list site-xz7-lb",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			s, lb, err := resolveLB(ctx, rt, args[0], region)
			if err != nil {
				return err
			}
			listeners, err := s.c.ListListeners(ctx, s.region, lb.ID)
			if err != nil {
				return err
			}
			views := []lbListenerView{}
			for _, l := range listeners {
				views = append(views, listenerView(l))
			}
			if len(views) == 0 {
				rt.Infof("load balancer %s has no listeners", lb.Name)
			}
			return rt.Render(views, func() output.Grid { return listenerListGrid(views) })
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region of the load balancer (asks the profile's account there directly)")
	return cmd
}

func listenerGetCmd(rt *app.Runtime) *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:     "get <listener-arn|lb:port>",
		Short:   "Show a listener",
		Example: "  polyctl aws elbv2 listener get site-xz7-lb:443 -o json",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, l, err := resolveListener(cmd.Context(), rt, args[0], region)
			if err != nil {
				return err
			}
			v := listenerView(*l)
			return rt.Render(v, func() output.Grid { return listenerDetailGrid(v) })
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region of the load balancer (default: found through the inventory, or the ARN's)")
	return cmd
}

func listenerCreateCmd(rt *app.Runtime) *cobra.Command {
	var protocol, tgRef, cert, region string
	var port int
	cmd := &cobra.Command{
		Use:   "create <lb>",
		Short: "Create a listener that forwards to a target group",
		Long: `Create a listener on --port of a load balancer for --protocol (TCP, TLS, UDP,
TCP_UDP, HTTP, HTTPS) that forwards to --target-group (name or ARN, in the
load balancer's region). TLS and HTTPS need --cert (the ARN of an ACM
certificate, see aws acm); the other protocols take none. A listener on the
port already is an error (exit code 1): use listener update.`,
		Example: "  polyctl aws elbv2 listener create site-xz7-lb --protocol TCP --port 30001 --target-group db-30001-target",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
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
			if tgRef == "" {
				return app.UsageErrf("--target-group is required")
			}
			switch {
			case needsCert(protocol) && cert == "":
				return app.UsageErrf("a %s listener needs a certificate: pass --cert <acm-certificate-arn>", protocol)
			case !needsCert(protocol) && cert != "":
				return app.UsageErrf("--cert applies to TLS and HTTPS listeners only, not %s", protocol)
			case cert != "" && !strings.HasPrefix(cert, "arn:"):
				return app.UsageErrf("--cert %q: expected the ARN of an ACM certificate", cert)
			}
			s, lb, err := resolveLB(ctx, rt, args[0], region)
			if err != nil {
				return err
			}
			if a, ok := parseELBARN(tgRef); ok && a.Region != s.region {
				return app.UsageErrf("target group %s is in %s, the load balancer in %s", tgRef, a.Region, s.region)
			}
			tg, err := resolveTG(ctx, s, tgRef)
			if err != nil {
				return err
			}
			listeners, err := s.c.ListListeners(ctx, s.region, lb.ID)
			if err != nil {
				return err
			}
			for _, l := range listeners {
				if l.Port == int32(port) {
					return fmt.Errorf("load balancer %s already has a listener on port %d (%s): use `polyctl aws elbv2 listener update %s:%d`", lb.Name, port, listenerSummary(l), lb.Name, port)
				}
			}
			var plan platform.Plan
			plan.Add(platform.Step{Resource: fmt.Sprintf("listener/%s:%d", lb.Name, port), Action: platform.Created,
				Desc: fmt.Sprintf("%s:%d -> %s", strings.ToLower(protocol), port, tg.Name),
				Apply: func(ctx context.Context) (platform.Change, error) {
					l, err := s.c.CreateListener(ctx, platform.ListenerCreateSpec{Region: s.region, LoadBalancer: lb.ID, Protocol: protocol, Port: int32(port),
						TargetGroup: tg.ID, Certificate: cert})
					if err != nil {
						return platform.Change{}, err
					}
					return platform.Change{ID: l.ID}, nil
				}})
			return rt.Ensure(ctx, "aws.elbv2.listener.create", s.target(), &plan)
		},
	}
	cmd.Flags().StringVar(&protocol, "protocol", "", "TCP, TLS, UDP, TCP_UDP, HTTP or HTTPS (required)")
	cmd.Flags().IntVar(&port, "port", 0, "port the load balancer listens on (required)")
	cmd.Flags().StringVar(&tgRef, "target-group", "", "target group to forward to, name or ARN (required)")
	cmd.Flags().StringVar(&cert, "cert", "", "ACM certificate ARN (TLS and HTTPS listeners)")
	cmd.Flags().StringVar(&region, "region", "", "region of the load balancer (asks the profile's account there directly)")
	return cmd
}

func listenerUpdateCmd(rt *app.Runtime) *cobra.Command {
	var protocol, tgRef, region string
	cmd := &cobra.Command{
		Use:   "update <listener-arn|lb:port>",
		Short: "Change the target group or protocol of a listener (in place)",
		Long: `Change what a listener forwards to (--target-group, name or ARN) and its
protocol (--protocol), in place: the listener is never deleted and created
again. Values that are already set are reported unchanged. Switching to TLS
or HTTPS needs a certificate the listener does not have: delete it and
create it again with --cert.`,
		Example: "  polyctl aws elbv2 listener update site-xz7-lb:80 --target-group site-xz7-80-target",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if protocol == "" && tgRef == "" {
				return app.UsageErrf("nothing to update: pass --target-group or --protocol")
			}
			var err error
			if protocol != "" {
				if protocol, err = oneOf("protocol", protocol, elbProtocols); err != nil {
					return err
				}
			}
			if _, err := parseListenerRef(args[0]); err != nil {
				return err
			}
			s, l, err := resolveListener(ctx, rt, args[0], region)
			if err != nil {
				return err
			}
			if protocol != "" && needsCert(protocol) && len(l.Certificates) == 0 {
				return app.UsageErrf("a %s listener needs a certificate, and %s has none: delete it and create it again with --cert", protocol, listenerName(*l))
			}
			var tg *platform.LBTargetGroup
			if tgRef != "" {
				if tg, err = resolveTG(ctx, s, tgRef); err != nil {
					return err
				}
			}
			newProto, newTG := "", ""
			var from, to []string
			if protocol != "" && protocol != l.Protocol {
				newProto = protocol
				from, to = append(from, "protocol "+l.Protocol), append(to, "protocol "+protocol)
			}
			if tg != nil && !l.ForwardsTo(tg.ID) {
				newTG = tg.ID
				from, to = append(from, listenerSummary(*l)), append(to, "forward to "+tg.Name)
			}
			var plan platform.Plan
			if newProto == "" && newTG == "" {
				plan.Add(platform.Step{Resource: listenerName(*l), ID: l.ID, Desc: listenerSummary(*l)})
			} else {
				plan.Add(platform.Step{Resource: listenerName(*l), Action: platform.Updated, ID: l.ID, Desc: strings.Join(from, ", ") + " -> " + strings.Join(to, ", "),
					Apply: func(ctx context.Context) (platform.Change, error) {
						_, err := s.c.ModifyListener(ctx, s.region, l.ID, newProto, newTG)
						return platform.Change{}, err
					}})
			}
			return rt.Ensure(ctx, "aws.elbv2.listener.update", s.target(), &plan)
		},
	}
	cmd.Flags().StringVar(&tgRef, "target-group", "", "target group to forward to, name or ARN")
	cmd.Flags().StringVar(&protocol, "protocol", "", "TCP, TLS, UDP, TCP_UDP, HTTP or HTTPS")
	cmd.Flags().StringVar(&region, "region", "", "region of the load balancer (default: found through the inventory, or the ARN's)")
	return cmd
}

func listenerDeleteCmd(rt *app.Runtime) *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:   "delete <listener-arn|lb:port>",
		Short: "Delete a listener (asks first)",
		Long: `Delete a listener. It is shown first, then a confirmation is asked (default
no; --yes skips it, and the non-interactive flow needs --yes). The target
group it forwards to stays.`,
		Example: "  polyctl aws elbv2 listener delete site-xz7-lb:443 --yes",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			s, l, err := resolveListener(ctx, rt, args[0], region)
			if err != nil {
				return err
			}
			rt.Infof("listener %s in %s: %s", listenerName(*l), s.where(), listenerSummary(*l))
			change := platform.Change{Resource: listenerName(*l), Action: platform.Deleted, ID: l.ID, Detail: listenerSummary(*l)}
			if done, err := rt.WouldWrite(s.target(), change); done || err != nil {
				return err
			}
			ok, err := rt.Confirm(ctx, fmt.Sprintf("Delete %s?", listenerName(*l)), false)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("%w: cancelled; %s was not deleted", platform.ErrNothingToDo, listenerName(*l))
			}
			if err := s.c.DeleteListener(ctx, s.region, l.ID); err != nil {
				if !elbNotFound(err) {
					return err
				}
				change.Action, change.Detail = platform.Unchanged, "already deleted"
			}
			return rt.RenderReport(platform.Report{Target: s.target(), Changes: []platform.Change{change}})
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region of the load balancer (default: found through the inventory, or the ARN's)")
	return cmd
}
