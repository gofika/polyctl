package aliyun

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// The waits of the ALB commands.
const (
	albLBWaitInterval       = 5 * time.Second
	albListenerWaitTimeout  = 60 * time.Second
	albListenerWaitInterval = 5 * time.Second
	albGroupWaitTimeout     = 60 * time.Second
	albGroupWaitInterval    = 2 * time.Second
	albACLWaitTimeout       = 60 * time.Second
	albACLWaitInterval      = 500 * time.Millisecond
	albGoneWaitInterval     = 2 * time.Second
)

// newALBCmd is `aliyun alb`: Application Load Balancer.
func newALBCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "alb",
		Short: "Application Load Balancer: load balancers, listeners, server groups, ACLs",
		Long: `Application Load Balancer (ALB). Load balancers, listeners, server groups and
access control lists (ACLs) belong to one region (--region, the profile's
region by default). Alibaba Cloud keeps none of their names unique: a name
held by several is a pick on a terminal and ambiguous (exit code 5) in the
non-interactive flow; pass the id. On a terminal, a load balancer,
listener, server group, ACL, certificate, instance, port or ACL entry a
command needs and was not given is offered from the region's resources (or
asked, checked as it is typed) instead of failing.`,
	}
	lb := &cobra.Command{Use: "load-balancer", Short: "ALB load balancers"}
	lb.AddCommand(albLBListCmd(rt), albLBGetCmd(rt), albLBCreateCmd(rt), albLBUpdateCmd(rt), albLBDeleteCmd(rt), albLBEnsureCmd(rt))
	lsn := &cobra.Command{Use: "listener", Short: "Listeners of a load balancer"}
	cert := &cobra.Command{Use: "cert", Short: "The certificate of an HTTPS listener"}
	cert.AddCommand(albListenerCertSetCmd(rt))
	lsn.AddCommand(albListenerListCmd(rt), albListenerGetCmd(rt), albListenerCreateCmd(rt), albListenerUpdateCmd(rt), albListenerDeleteCmd(rt), cert)
	sg := &cobra.Command{Use: "server-group", Short: "Server groups (backend pools of ECS instances)"}
	srv := &cobra.Command{Use: "server", Short: "Servers of a server group"}
	srv.AddCommand(albServerAddCmd(rt))
	sg.AddCommand(albSGListCmd(rt), albSGGetCmd(rt), albSGCreateCmd(rt), albSGUpdateCmd(rt), albSGDeleteCmd(rt), srv)
	acl := &cobra.Command{Use: "acl", Short: "Access control lists (IPv4 allow / deny lists)"}
	entry := &cobra.Command{Use: "entry", Short: "Entries of an ACL"}
	entry.AddCommand(albACLEntryAddCmd(rt), albACLEntryRemoveCmd(rt))
	acl.AddCommand(albACLListCmd(rt), albACLGetCmd(rt), albACLCreateCmd(rt), albACLDeleteCmd(rt), entry)
	cmd.AddCommand(lb, lsn, sg, acl)
	return cmd
}

// albScope is an account, a region and its ALB client.
type albScope struct {
	*ecsScope
	a *albClient
}

// openALBScope opens the selected profile in region (its own by default).
// Every ALB command asks the API: --offline is exit code 6.
func openALBScope(ctx context.Context, rt *app.Runtime, region string) (*albScope, error) {
	if rt.Flags.Offline {
		return nil, app.ErrOffline
	}
	s, err := openECSScope(ctx, rt, region)
	if err != nil {
		return nil, err
	}
	return albScopeOf(ctx, s)
}

func albScopeOf(ctx context.Context, s *ecsScope) (*albScope, error) {
	a, err := s.c.albClient(ctx, s.region)
	if err != nil {
		return nil, err
	}
	return &albScope{ecsScope: s, a: a}, nil
}

// albCanConfirm refuses, before the account is opened, a destructive
// command that cannot be confirmed (non-interactive without --yes); a dry
// run deletes nothing and needs no confirmation.
func albCanConfirm(rt *app.Runtime, action string) error {
	if rt.DryRun() {
		return nil
	}
	return rt.CanConfirm(action)
}

// ---------------------------------------------------------------- waits

// waitLBActive waits until the load balancer is Active. Inactive (stopped)
// never becomes Active on its own: it is a failure at once.
func waitLBActive(ctx context.Context, a *albClient, id string, timeout time.Duration) (string, error) {
	last := ""
	err := platform.WaitUntil(ctx, platform.WaitOptions{Resource: "load-balancer/" + id, Want: albStatusActive, Timeout: timeout,
		Interval: albLBWaitInterval, Clock: netClock()}, func(ctx context.Context) (platform.WaitState, string, error) {
		lb, err := a.getLoadBalancer(ctx, id)
		if err != nil {
			return platform.KeepWaiting, "", err
		}
		if lb == nil {
			// A load balancer just created may not be readable yet.
			return platform.KeepWaiting, statusNotFound, nil
		}
		last = lb.Status
		switch lb.Status {
		case albStatusActive:
			return platform.WaitDone, lb.Status, nil
		case albStatusInactive:
			return platform.WaitFailed, lb.Status, nil
		}
		return platform.KeepWaiting, lb.Status, nil
	})
	if err != nil && last == albStatusInactive {
		err = fmt.Errorf("%w (an Inactive load balancer does not become Active on its own: enable it in the console)", err)
	}
	return last, err
}

// waitListenerRunning waits up to a minute for a listener to be Running:
// a listener that is Provisioning or Configuring refuses every write
// (IncorrectStatus.Listener).
func waitListenerRunning(ctx context.Context, a *albClient, id string) error {
	return platform.WaitUntil(ctx, platform.WaitOptions{Resource: "listener/" + id, Want: albListenerRunning, Timeout: albListenerWaitTimeout,
		Interval: albListenerWaitInterval, Clock: netClock()}, func(ctx context.Context) (platform.WaitState, string, error) {
		l, err := a.getListener(ctx, id)
		if err != nil {
			return platform.KeepWaiting, "", err
		}
		if l == nil {
			return platform.KeepWaiting, statusNotFound, nil
		}
		if l.Status == albListenerRunning {
			return platform.WaitDone, l.Status, nil
		}
		return platform.KeepWaiting, l.Status, nil
	})
}

// waitServerGroupAvailable waits up to a minute for a new server group.
func waitServerGroupAvailable(ctx context.Context, a *albClient, id string) error {
	return platform.WaitUntil(ctx, platform.WaitOptions{Resource: "server-group/" + id, Want: albAvailable, Timeout: albGroupWaitTimeout,
		Interval: albGroupWaitInterval, Clock: netClock()}, func(ctx context.Context) (platform.WaitState, string, error) {
		gs, err := a.listServerGroups(ctx, nil, []string{id})
		if err != nil {
			return platform.KeepWaiting, "", err
		}
		if len(gs) == 0 {
			return platform.KeepWaiting, statusNotFound, nil
		}
		if gs[0].Status == albAvailable {
			return platform.WaitDone, gs[0].Status, nil
		}
		return platform.KeepWaiting, gs[0].Status, nil
	})
}

// waitACLAvailable waits up to a minute for an ACL to be Available again:
// an ACL that is Configuring refuses writes (IncorrectStatus.Acl).
func waitACLAvailable(ctx context.Context, a *albClient, id string) error {
	return platform.WaitUntil(ctx, platform.WaitOptions{Resource: "acl/" + id, Want: albAvailable, Timeout: albACLWaitTimeout,
		Interval: albACLWaitInterval, Clock: netClock()}, func(ctx context.Context) (platform.WaitState, string, error) {
		acls, err := a.listACLs(ctx, nil, []string{id})
		if err != nil {
			return platform.KeepWaiting, "", err
		}
		if len(acls) == 0 {
			return platform.KeepWaiting, statusNotFound, nil
		}
		if acls[0].Status == albAvailable {
			return platform.WaitDone, acls[0].Status, nil
		}
		return platform.KeepWaiting, acls[0].Status, nil
	})
}

// settleACL waits, before the first write to an ACL, until it is Available
// when it was read in another status (a write of an earlier command still
// configuring it), then records it as Available: each write waits after
// itself.
func settleACL(ctx context.Context, a *albClient, x *albACL) error {
	if x.Status == albAvailable {
		return nil
	}
	if err := waitACLAvailable(ctx, a, x.ID); err != nil {
		return err
	}
	x.Status = albAvailable
	return nil
}

// setListenerCertificate makes certID (a listener certificate id) the
// default certificate of a listener, then waits until the listener is
// Running again, so that the next write to it (cert deploy updates several
// in a row) is not refused.
func setListenerCertificate(ctx context.Context, a *albClient, listenerID, certID string) error {
	if err := a.updateListener(ctx, listenerID, certID, ""); err != nil {
		return err
	}
	if err := waitListenerRunning(ctx, a, listenerID); err != nil {
		return fmt.Errorf("listener %s: certificate set to %s: %w", listenerID, certID, err)
	}
	return nil
}

// --------------------------------------------------------- certificates

var listenerCertRe = regexp.MustCompile(`^[0-9]+-[a-z0-9-]+$`)

// checkCertFlag validates --cert: a CAS certificate id (an integer), or a
// listener certificate id as a listener holds it ("1234567-ap-southeast-1").
func checkCertFlag(v string) error {
	v = strings.TrimSpace(v)
	if _, err := strconv.ParseInt(v, 10, 64); err == nil {
		return nil
	}
	if listenerCertRe.MatchString(v) {
		return nil
	}
	return app.UsageErrf("--cert %q is not a CAS certificate id (an integer such as 1234567)", v)
}

// listenerCert is the listener certificate id of --cert for listeners of
// region: the CAS id with the suffix of the region's CAS store
// ("<id>-ap-southeast-1" in cn-hongkong), or the value as it is when it
// carries a suffix already.
func listenerCert(c *client, region, v string) (string, error) {
	v = strings.TrimSpace(v)
	if strings.Contains(v, "-") {
		return v, nil
	}
	s, err := c.casFor(region)
	if err != nil {
		return "", err
	}
	return listenerCertID(s.Region, v), nil
}

// ---------------------------------------------------------- resolution

func looksLikeALBID(ref string) bool         { return strings.HasPrefix(ref, "alb-") && len(ref) > 4 }
func looksLikeServerGroupID(ref string) bool { return strings.HasPrefix(ref, "sgp-") && len(ref) > 4 }
func looksLikeACLID(ref string) bool         { return strings.HasPrefix(ref, "acl-") && len(ref) > 4 }

// resolveLB finds a load balancer of the scope's region by id or name.
func resolveLB(ctx context.Context, sc *albScope, ref string) (*albLB, error) {
	id := ref
	if !looksLikeALBID(ref) {
		found, err := sc.a.findLoadBalancersByName(ctx, ref)
		if err != nil {
			return nil, err
		}
		switch len(found) {
		case 0:
			return nil, fmt.Errorf("%w: load balancer %q in %s", platform.ErrNotFound, ref, sc.where())
		case 1:
			id = found[0].ID
		default:
			var ids []string
			for _, f := range found {
				ids = append(ids, f.ID)
			}
			amb := &app.AmbiguousError{What: fmt.Sprintf("load balancer %q in %s", ref, sc.where()), Candidates: ids,
				Hint: "Alibaba Cloud lets several load balancers share a name; pass the id"}
			pick, err := pickAmong(sc.ecsScope, amb, found, func(x albRef) string { return x.ID }, lbOptionLabel)
			if err != nil {
				return nil, err
			}
			id = pick.ID
		}
	}
	lb, err := sc.a.getLoadBalancer(ctx, id)
	if err != nil {
		return nil, err
	}
	if lb == nil {
		return nil, fmt.Errorf("%w: load balancer %q in %s", platform.ErrNotFound, ref, sc.where())
	}
	return lb, nil
}

// lbScope finds a load balancer named by the user and opens its account:
// with --region, the selected profile in that region; without, through the
// inventory of every selected account (synced once when it does not know
// the name).
func lbScope(ctx context.Context, rt *app.Runtime, ref, region string) (*albScope, *albLB, error) {
	if region != "" {
		sc, err := openALBScope(ctx, rt, region)
		if err != nil {
			return nil, nil, err
		}
		lb, err := resolveLB(ctx, sc, ref)
		return sc, lb, err
	}
	res, err := rt.ResolveResource(ctx, platform.Aliyun, platform.ResLoadBalancer, ref)
	if err != nil {
		if rt.Flags.Offline && errors.Is(err, platform.ErrNotFound) {
			return nil, nil, fmt.Errorf("%w: load balancer %q is not in the local inventory", app.ErrOffline, ref)
		}
		return nil, nil, err
	}
	if rt.Flags.Offline {
		return nil, nil, app.ErrOffline
	}
	var cached albLoadBalancer
	_ = res.Decode(&cached)
	lbRegion := cached.Region
	if lbRegion == "" {
		lbRegion = res.ParentID
	}
	c, err := openNamed(rt, ctx, res.Profile)
	if err != nil {
		return nil, nil, err
	}
	sc, err := albScopeOf(ctx, &ecsScope{c: c, profile: res.Profile, region: c.regionOr(lbRegion), rt: rt})
	if err != nil {
		return nil, nil, err
	}
	lb, err := sc.a.getLoadBalancer(ctx, res.ID)
	if err != nil {
		return nil, nil, err
	}
	if lb == nil {
		dropLB(ctx, rt, res.Profile, res.ID)
		return nil, nil, fmt.Errorf("%w: load balancer %q in %s (it was deleted since the inventory was synced)", platform.ErrNotFound, ref, sc.where())
	}
	return sc, lb, nil
}

// resolveServerGroup finds a server group of the scope's region by id or
// name.
func resolveServerGroup(ctx context.Context, sc *albScope, ref string) (*albServerGroup, error) {
	var found []albServerGroup
	var err error
	if looksLikeServerGroupID(ref) {
		found, err = sc.a.listServerGroups(ctx, nil, []string{ref})
	} else {
		found, err = sc.a.listServerGroups(ctx, []string{ref}, nil)
	}
	if err != nil {
		return nil, err
	}
	switch len(found) {
	case 0:
		return nil, fmt.Errorf("%w: server group %q in %s", platform.ErrNotFound, ref, sc.where())
	case 1:
		return &found[0], nil
	}
	var ids []string
	for _, g := range found {
		ids = append(ids, g.ID+" ("+g.Protocol+", "+g.VpcID+")")
	}
	amb := &app.AmbiguousError{What: fmt.Sprintf("server group %q in %s", ref, sc.where()), Candidates: ids,
		Hint: "Alibaba Cloud lets several server groups share a name; pass the id"}
	return pickAmong(sc.ecsScope, amb, found, func(g albServerGroup) string { return g.ID }, serverGroupLabel)
}

// resolveACL finds an ACL of the scope's region by id or name.
func resolveACL(ctx context.Context, sc *albScope, ref string) (*albACL, error) {
	var found []albACL
	var err error
	if looksLikeACLID(ref) {
		found, err = sc.a.listACLs(ctx, nil, []string{ref})
	} else {
		found, err = sc.a.listACLs(ctx, []string{ref}, nil)
	}
	if err != nil {
		return nil, err
	}
	switch len(found) {
	case 0:
		return nil, fmt.Errorf("%w: ACL %q in %s", platform.ErrNotFound, ref, sc.where())
	case 1:
		return &found[0], nil
	}
	var ids []string
	for _, x := range found {
		ids = append(ids, x.ID)
	}
	amb := &app.AmbiguousError{What: fmt.Sprintf("ACL %q in %s", ref, sc.where()), Candidates: ids,
		Hint: "Alibaba Cloud lets several ACLs share a name; pass the id"}
	return pickAmong(sc.ecsScope, amb, found, func(x albACL) string { return x.ID }, aclLabel)
}

// resolveInstanceIn finds an ECS instance of the scope's account and
// region by id or exact name. An instance of another account or region is
// not found: a server group holds instances of its own VPC only.
func resolveInstanceIn(ctx context.Context, s *ecsScope, ref string) (*Instance, error) {
	if looksLikeInstanceID(ref) {
		inst, err := s.c.describeInstance(ctx, s.region, ref)
		if err != nil {
			if errors.Is(err, platform.ErrNotFound) {
				return nil, fmt.Errorf("%w: instance %q in %s (the instance has to be in the account and region of the load balancer)", platform.ErrNotFound, ref, s.where())
			}
			return nil, err
		}
		return inst, nil
	}
	found, err := s.c.findInstances(ctx, s.region, ref)
	if err != nil {
		return nil, err
	}
	switch len(found) {
	case 0:
		return nil, fmt.Errorf("%w: instance %q in %s (the instance has to be in the account and region of the load balancer)", platform.ErrNotFound, ref, s.where())
	case 1:
		return &found[0], nil
	}
	var ids []string
	for _, in := range found {
		ids = append(ids, in.ID)
	}
	amb := &app.AmbiguousError{What: fmt.Sprintf("instance %q in %s", ref, s.where()), Candidates: ids,
		Hint: "several instances share the name; pass the instance id"}
	return pickAmong(s, amb, found, func(in Instance) string { return in.ID }, instanceOptionLabel)
}

// ------------------------------------------------------------ inventory

// storeLB records a load balancer in the inventory (find and the routing
// of get / delete read it).
func storeLB(ctx context.Context, rt *app.Runtime, profile string, l albLB) {
	if l.ID == "" {
		return
	}
	db, err := rt.DB()
	if err != nil {
		return
	}
	cfg, _ := rt.Config()
	row := albLoadBalancer{ID: l.ID, Name: l.Name, DNSName: l.DNSName, AddressType: l.AddressType, Status: l.Status, VpcID: l.VpcID,
		Region: l.Region, Public: l.ips(), AllocationIDs: l.allocationIDs()}
	for _, a := range l.Addresses {
		row.Zones = appendNew(row.Zones, a.Zone)
	}
	_ = db.Upsert(ctx, inventory.Set{Platform: platform.Aliyun, Profile: profile, Type: platform.ResLoadBalancer}, row.resource(), cfg.TTLFor(platform.ResLoadBalancer))
}

func dropLB(ctx context.Context, rt *app.Runtime, profile, id string) {
	if db, err := rt.DB(); err == nil {
		_ = db.Delete(ctx, inventory.Set{Platform: platform.Aliyun, Profile: profile, Type: platform.ResLoadBalancer}, platform.ResLoadBalancer, id)
	}
}

// -------------------------------------------------------- load balancer

func albLBGrid(rows []albLoadBalancer) output.Grid {
	g := output.Grid{Headers: []string{"ID", "NAME", "STATUS", "VPC", "REGION", "DNS_NAME"}, Empty: "no load balancers"}
	for _, l := range rows {
		g.Rows = append(g.Rows, []string{l.ID, orDash(l.Name), orDash(l.Status), orDash(l.VpcID), l.Region, orDash(l.DNSName)})
	}
	return g
}

func albLBListCmd(rt *app.Runtime) *cobra.Command {
	var region, name string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the ALB load balancers of the account (cached locally)",
		Long: `List the ALB load balancers of the profile, in every region of the account, or in
--region only; --name keeps those whose name contains the text. The list is
the local inventory (load_balancer), refreshed when it has expired or with
--refresh; --offline shows it as it is.`,
		Example: "  polyctl aliyun alb load-balancer list --region cn-hongkong -o json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			prof, err := rt.ProfileFor(platform.Aliyun)
			if err != nil {
				return err
			}
			set := inventory.Set{Platform: platform.Aliyun, Profile: prof, Type: platform.ResLoadBalancer}
			rows, cached, err := rt.EnsureSet(ctx, set, func(ctx context.Context) ([]platform.Resource, error) {
				c, err := openNamed(rt, ctx, prof)
				if err != nil {
					return nil, err
				}
				return c.inEveryRegion(ctx, c.albResources)
			})
			if err != nil {
				return err
			}
			out := []albLoadBalancer{}
			for _, r := range rows {
				var l albLoadBalancer
				if err := r.Decode(&l); err != nil {
					return fmt.Errorf("decode cached load balancer %s: %w", r.ID, err)
				}
				if l.Region == "" {
					l.Region = r.ParentID
				}
				if (region != "" && l.Region != region) || (name != "" && !strings.Contains(l.Name, name)) {
					continue
				}
				out = append(out, l)
			}
			where := "aliyun/" + prof
			if region != "" {
				where += "/" + region
			}
			if len(out) == 0 {
				rt.Infof("no load balancers in %s%s", where, cacheNote(cached))
			} else {
				rt.Infof("%d load balancer(s) in %s%s", len(out), where, cacheNote(cached))
			}
			return rt.Render(out, func() output.Grid { return albLBGrid(out) })
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "only the load balancers of this region (default: every region)")
	cmd.Flags().StringVar(&name, "name", "", "only the load balancers whose name contains this text")
	return cmd
}

// albListenerSummary is a listener in the output of load-balancer get.
type albListenerSummary struct {
	ID            string `json:"id" yaml:"id"`
	Protocol      string `json:"protocol" yaml:"protocol"`
	Port          int    `json:"port" yaml:"port"`
	Status        string `json:"status" yaml:"status"`
	CertificateID string `json:"certificate_id,omitempty" yaml:"certificate_id,omitempty"`
}

// albLBDetail is the output of load-balancer get.
type albLBDetail struct {
	albLB     `yaml:",inline"`
	Profile   string               `json:"profile" yaml:"profile"`
	Listeners []albListenerSummary `json:"listeners" yaml:"listeners"`
}

func albLBGetCmd(rt *app.Runtime) *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:   "get <name|id>",
		Short: "Show a load balancer, its addresses and listeners",
		Long: `Show a load balancer (name or alb- id): its status, VPC, DNS name, the EIP of
each zone and its listeners with the certificate of the HTTPS ones. Without
--region it is found through the inventory of every selected account (synced
once when it does not know the name); several of the name are a pick on a
terminal, exit code 5 otherwise.`,
		Example: "  polyctl aliyun alb load-balancer get lb-example-com -o json",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			args, err := lbArg(ctx, rt, args, region)
			if err != nil {
				return err
			}
			sc, lb, err := lbScope(ctx, rt, args[0], region)
			if err != nil {
				return err
			}
			storeLB(ctx, rt, sc.profile, *lb)
			ls, err := sc.a.listListeners(ctx, lb.ID)
			if err != nil {
				return err
			}
			d := albLBDetail{albLB: *lb, Profile: sc.profile, Listeners: []albListenerSummary{}}
			for _, l := range ls {
				sum := albListenerSummary{ID: l.ID, Protocol: l.Protocol, Port: l.Port, Status: l.Status}
				if carriesCertificates(l.Protocol) {
					// ListListeners does not carry certificates.
					full, err := sc.a.getListener(ctx, l.ID)
					if err != nil {
						return err
					}
					if full != nil && len(full.Certificates) > 0 {
						sum.CertificateID = full.Certificates[0]
					}
				}
				d.Listeners = append(d.Listeners, sum)
			}
			return rt.Render(d, func() output.Grid {
				g := output.Grid{Rows: [][]string{
					{"NAME", orDash(lb.Name), "ID", lb.ID},
					{"STATUS", orDash(lb.Status), "REGION", lb.Region},
					{"VPC", orDash(lb.VpcID), "EDITION", orDash(lb.Edition)},
					{"DNS_NAME", orDash(lb.DNSName)},
					{"ADDRESSES"},
				}}
				for _, a := range lb.Addresses {
					g.Rows = append(g.Rows, []string{"  " + a.Zone, orDash(a.IP), orDash(a.AllocationID), orDash(a.VSwitchID)})
				}
				g.Rows = append(g.Rows, []string{"LISTENERS"})
				if len(d.Listeners) == 0 {
					g.Rows = append(g.Rows, []string{"  (none)"})
				}
				for _, l := range d.Listeners {
					g.Rows = append(g.Rows, []string{"  " + l.ID, fmt.Sprintf("%s:%d", l.Protocol, l.Port), l.Status, orDash(l.CertificateID)})
				}
				return g
			})
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region id: ask this region of the selected profile instead of the inventory")
	return cmd
}

// parseZoneMapping reads --zone-mapping <zone-id>:<vswitch-id>:<eip-allocation-id>.
func parseZoneMapping(v string) (albZoneMapping, error) {
	parts := strings.Split(strings.TrimSpace(v), ":")
	if len(parts) != 3 || parts[0] == "" || !looksLikeVSwitchID(parts[1]) || !strings.HasPrefix(parts[2], "eip-") {
		return albZoneMapping{}, app.UsageErrf("--zone-mapping %q: expected <zone-id>:<vswitch-id>:<eip-allocation-id>, e.g. cn-hongkong-b:vsw-aaa:eip-bbb", v)
	}
	return albZoneMapping{Zone: parts[0], VSwitchID: parts[1], AllocationID: parts[2]}, nil
}

// checkLBName refuses a load balancer name ALB would refuse or polyctl
// would read as an id.
func checkLBName(name string) error {
	switch {
	case strings.TrimSpace(name) == "":
		return app.UsageErrf("the load balancer name is empty")
	case strings.Contains(name, "*"):
		return app.UsageErrf("load balancer name %q holds '*'", name)
	case looksLikeALBID(name):
		return app.UsageErrf("load balancer name %q starts with alb- (that is how ids are written)", name)
	case len([]rune(name)) > netNameMaxLength:
		return app.UsageErrf("load balancer name %q is longer than %d characters", name, netNameMaxLength)
	}
	return nil
}

// lbCreateStep creates the load balancer of spec (spec() is called when the
// step runs: the ids of earlier steps are known then) and, with wait, waits
// until it is Active. It stores the new id in *id.
func lbCreateStep(rt *app.Runtime, sc *albScope, name string, desc string, spec func() albLBSpec, wait bool, timeout time.Duration, id *string) platform.Step {
	return platform.Step{Resource: "load-balancer/" + name, Action: platform.Created, Desc: desc,
		Apply: func(ctx context.Context) (platform.Change, error) {
			start := netClock().Now()
			lid, err := sc.a.createLoadBalancer(ctx, spec())
			if err != nil {
				return platform.Change{}, err
			}
			*id = lid
			if !wait {
				if lb, _ := sc.a.getLoadBalancer(ctx, lid); lb != nil {
					storeLB(ctx, rt, sc.profile, *lb)
				}
				return platform.Change{ID: lid, Detail: lid + " (creation requested; not waited for)"}, nil
			}
			last, err := waitLBActive(ctx, sc.a, lid, timeout)
			if lb, _ := sc.a.getLoadBalancer(ctx, lid); lb != nil {
				storeLB(ctx, rt, sc.profile, *lb)
			}
			if err != nil {
				return platform.Change{ID: lid}, fmt.Errorf("load balancer %s (%s) was created: %w", name, lid, err)
			}
			return platform.Change{ID: lid, Detail: fmt.Sprintf("%s (%s after %s)", lid, last, netClock().Now().Sub(start).Round(time.Second))}, nil
		}}
}

func albLBCreateCmd(rt *app.Runtime) *cobra.Command {
	var region, vpcID, group string
	var mappings []string
	var w app.WaitFlags
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create an ALB load balancer on existing vSwitches and EIPs",
		Long: `Create the Internet-facing IPv4 load balancer <name> (Standard edition, pay as
you go) in --vpc (an id; required) with one --zone-mapping per zone, exactly
two: <zone-id>:<vswitch-id>:<eip-allocation-id>. Nothing it depends on is
created (use ensure for that). The EIPs have to share one ISP. A load
balancer of the name in the region is exit code 1. --resource-group (a name
or rg- id; default defaults.aliyun.resource_group, else "default"). --wait
waits until it is Active (about 45 seconds), bounded by --timeout.`,
		Example: "  polyctl aliyun alb load-balancer create lb-web --vpc vpc-aaa --zone-mapping cn-hongkong-b:vsw-b:eip-1 --zone-mapping cn-hongkong-c:vsw-c:eip-2 --wait",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name := args[0]
			if err := checkLBName(name); err != nil {
				return err
			}
			if !looksLikeVPCID(vpcID) {
				return app.UsageErrf("--vpc is required and takes a VPC id (vpc-...); create does not create what it depends on, ensure does")
			}
			if len(mappings) != 2 {
				return app.UsageErrf("--zone-mapping is required twice (one per zone), got %d", len(mappings))
			}
			var zones []albZoneMapping
			for _, m := range mappings {
				z, err := parseZoneMapping(m)
				if err != nil {
					return err
				}
				zones = append(zones, z)
			}
			if zones[0].Zone == zones[1].Zone {
				return app.UsageErrf("the two --zone-mapping name the same zone %s", zones[0].Zone)
			}
			wait, timeout, err := w.Resolve(cmd)
			if err != nil {
				return err
			}
			sc, err := openALBScope(ctx, rt, region)
			if err != nil {
				return err
			}
			found, err := sc.a.findLoadBalancersByName(ctx, name)
			if err != nil {
				return err
			}
			if len(found) > 0 {
				return fmt.Errorf("load balancer %q already exists in %s (%s)", name, sc.where(), found[0].ID)
			}
			rg, err := resolveResourceGroup(ctx, rt, sc.ecsScope, group)
			if err != nil {
				return err
			}
			spec := albLBSpec{Name: name, VpcID: vpcID, ResourceGroup: rg, Zones: zones, Token: clientToken()}
			var desc []string
			for _, z := range zones {
				desc = append(desc, z.Zone+"="+z.AllocationID)
			}
			var id string
			var plan platform.Plan
			plan.Add(lbCreateStep(rt, sc, name, vpcID+" "+strings.Join(desc, ","), func() albLBSpec { return spec }, wait, timeout, &id))
			return rt.Ensure(ctx, "aliyun.alb.load_balancer.create", sc.target(), &plan)
		},
	}
	cmd.Flags().StringVar(&vpcID, "vpc", "", "VPC id of the load balancer (required)")
	cmd.Flags().StringArrayVar(&mappings, "zone-mapping", nil, "<zone-id>:<vswitch-id>:<eip-allocation-id>, once per zone (exactly 2)")
	cmd.Flags().StringVar(&group, "resource-group", "", "resource group, a name or an rg- id (default defaults.aliyun.resource_group, else \"default\")")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	app.AddWaitFlags(cmd, &w, false, app.DefaultWaitTimeout)
	return cmd
}

func albLBUpdateCmd(rt *app.Runtime) *cobra.Command {
	var region, name string
	var deletionProtection bool
	var w app.WaitFlags
	cmd := &cobra.Command{
		Use:   "update <name|id>",
		Short: "Rename a load balancer or switch its deletion protection",
		Long: `Change what the flags name, each only when it differs (otherwise it is
reported unchanged): --name renames the load balancer (a name another load
balancer of the region holds is exit code 1), --deletion-protection[=false]
switches its deletion protection. The load balancer is found like get.
After a rename the command waits until the load balancer is Active again,
bounded by --timeout; --no-wait returns at once.`,
		Example: "  polyctl aliyun alb load-balancer update lb-web --deletion-protection\n  polyctl aliyun alb load-balancer update alb-0123456789 --name lb-web-2 --deletion-protection=false",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			fl := cmd.Flags()
			setName, setProtection := fl.Changed("name"), fl.Changed("deletion-protection")
			if !setName && !setProtection && !rt.Interactive() {
				return app.UsageErrf("nothing to update: pass --name or --deletion-protection")
			}
			if setName {
				if err := checkLBName(name); err != nil {
					return err
				}
			}
			wait, timeout, err := w.Resolve(cmd)
			if err != nil {
				return err
			}
			if args, err = lbArg(ctx, rt, args, region); err != nil {
				return err
			}
			sc, lb, err := lbScope(ctx, rt, args[0], region)
			if err != nil {
				return err
			}
			if !setName && !setProtection {
				// The interactive flow asks what to change.
				what, err := rt.Choose(app.Choice{Title: "Change what of " + orID(lb.Name, lb.ID) + "?", Arg: "--name or --deletion-protection",
					Options: []prompt.Option{{Label: "Name (now " + orDash(lb.Name) + ")", Value: "name"}, {Label: "Deletion protection (now " + strconv.FormatBool(lb.DeletionProtection) + ")", Value: "protection"}}})
				if err != nil {
					return err
				}
				if what == "name" {
					setName = true
					if name, err = rt.AskInput("--name", "New name of the load balancer", lb.Name, func(v string) error { return inline(checkLBName(strings.TrimSpace(v))) }); err != nil {
						return err
					}
				} else {
					setProtection = true
					cur := lb.DeletionProtection
					v, err := rt.PickOnOff("Deletion protection of "+orID(lb.Name, lb.ID), &cur)
					if err != nil {
						return err
					}
					deletionProtection = v == "on"
				}
			}
			res := "load-balancer/" + orID(lb.Name, lb.ID)
			var plan platform.Plan
			if setProtection {
				want := deletionProtection
				if lb.DeletionProtection == want {
					plan.Add(platform.Step{Resource: res + "/deletion-protection", ID: lb.ID, Desc: strconv.FormatBool(want)})
				} else {
					plan.Add(platform.Step{Resource: res + "/deletion-protection", Action: platform.Updated, ID: lb.ID,
						Desc: fmt.Sprintf("%t -> %t", lb.DeletionProtection, want),
						Apply: func(ctx context.Context) (platform.Change, error) {
							return platform.Change{}, sc.a.setDeletionProtection(ctx, lb.ID, want)
						}})
				}
			}
			if setName {
				if name == lb.Name {
					plan.Add(platform.Step{Resource: res + "/name", ID: lb.ID, Desc: name})
				} else {
					found, err := sc.a.findLoadBalancersByName(ctx, name)
					if err != nil {
						return err
					}
					if len(found) > 0 {
						return fmt.Errorf("load balancer %q already exists in %s (%s)", name, sc.where(), found[0].ID)
					}
					plan.Add(platform.Step{Resource: res + "/name", Action: platform.Updated, ID: lb.ID,
						Desc: orDash(lb.Name) + " -> " + name,
						Apply: func(ctx context.Context) (platform.Change, error) {
							if err := sc.a.renameLoadBalancer(ctx, lb.ID, name); err != nil {
								return platform.Change{}, err
							}
							// An Inactive (stopped) load balancer never becomes
							// Active on its own: nothing to wait for.
							if !wait || lb.Status == albStatusInactive {
								return platform.Change{}, nil
							}
							if _, err := waitLBActive(ctx, sc.a, lb.ID, timeout); err != nil {
								return platform.Change{}, fmt.Errorf("load balancer %s was renamed to %s: %w", lb.ID, name, err)
							}
							return platform.Change{}, nil
						}})
				}
			}
			err = rt.Ensure(ctx, "aliyun.alb.load_balancer.update", sc.target(), &plan)
			if err == nil && !rt.DryRun() {
				if again, gerr := sc.a.getLoadBalancer(ctx, lb.ID); gerr == nil && again != nil {
					storeLB(ctx, rt, sc.profile, *again)
				}
			}
			return err
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "new name of the load balancer")
	cmd.Flags().BoolVar(&deletionProtection, "deletion-protection", false, "turn deletion protection on (--deletion-protection=false turns it off)")
	cmd.Flags().StringVar(&region, "region", "", "region id: ask this region of the selected profile instead of the inventory")
	app.AddWaitFlags(cmd, &w, true, app.DefaultWaitTimeout)
	return cmd
}

func albLBDeleteCmd(rt *app.Runtime) *cobra.Command {
	var region string
	var force bool
	var w app.WaitFlags
	cmd := &cobra.Command{
		Use:   "delete <name|id>",
		Short: "Delete a load balancer (asks first)",
		Long: `Delete a load balancer (name or alb- id; found like get). It is shown first, then
a confirmation is asked (default no; --yes skips it, the non-interactive flow
needs --yes, exit code 2). ALB deletes the listeners with the load balancer,
so a load balancer that still has listeners needs --force (exit code 2
without it). Deletion protection is exit code 1: switch it off first with
update --deletion-protection=false (delete never does). Server groups are kept, and the EIPs are
unbound but not released (they stay billed; a note names them). --wait
waits until the load balancer is gone, bounded by --timeout.`,
		Example: "  polyctl aliyun alb load-balancer delete lb-example-com --force --yes",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			wait, timeout, err := w.Resolve(cmd)
			if err != nil {
				return err
			}
			if args, err = lbArg(ctx, rt, args, region); err != nil {
				return err
			}
			if err := albCanConfirm(rt, "delete load balancer "+args[0]); err != nil {
				return err
			}
			sc, lb, err := lbScope(ctx, rt, args[0], region)
			if err != nil {
				return err
			}
			ls, err := sc.a.listListeners(ctx, lb.ID)
			if err != nil {
				return err
			}
			rt.Infof("load balancer %s in %s", orDash(lb.Name), sc.where())
			rt.Infof("  id         %s", lb.ID)
			rt.Infof("  status     %s", lb.Status)
			rt.Infof("  addresses  %s", strings.Join(lb.ips(), ", "))
			for _, l := range ls {
				rt.Infof("  listener   %s %s:%d", l.ID, l.Protocol, l.Port)
			}
			if lb.DeletionProtection {
				return fmt.Errorf("load balancer %s has deletion protection on: switch it off first with `polyctl aliyun alb load-balancer update %s --deletion-protection=false` (delete never does)", lb.ID, lb.ID)
			}
			if len(ls) > 0 && !force {
				return app.UsageErrf("load balancer %s has %d listener(s), which are deleted with it: pass --force to delete them too", lb.ID, len(ls))
			}
			change := platform.Change{Resource: "load-balancer/" + orID(lb.Name, lb.ID), Action: platform.Deleted, ID: lb.ID}
			if len(ls) > 0 {
				change.Detail = fmt.Sprintf("with %d listener(s)", len(ls))
			}
			if done, err := rt.WouldWrite(sc.target(), change); done || err != nil {
				return err
			}
			ok, err := rt.Confirm(ctx, fmt.Sprintf("Delete load balancer %s (%s)?", orDash(lb.Name), lb.ID), false)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("%w: cancelled; load balancer %s was not deleted", platform.ErrNothingToDo, lb.ID)
			}
			if err := sc.a.deleteLoadBalancer(ctx, lb.ID); err != nil {
				if !platform.HasErrorCode(err, errALBLoadBalancerNotFound) {
					return err
				}
				change.Action, change.Detail = platform.Unchanged, "already deleted"
			}
			dropLB(ctx, rt, sc.profile, lb.ID)
			if wait && change.Action == platform.Deleted {
				err := platform.WaitUntil(ctx, platform.WaitOptions{Resource: "load-balancer/" + lb.ID, Want: "deleted", Timeout: timeout,
					Interval: albGoneWaitInterval, Clock: netClock()}, func(ctx context.Context) (platform.WaitState, string, error) {
					got, err := sc.a.getLoadBalancer(ctx, lb.ID)
					if err != nil {
						return platform.KeepWaiting, "", err
					}
					if got == nil {
						return platform.WaitDone, "deleted", nil
					}
					return platform.KeepWaiting, got.Status, nil
				})
				if err != nil {
					return err
				}
			}
			for _, a := range lb.Addresses {
				if a.AllocationID != "" {
					rt.Infof("note: EIP %s (%s) is unbound but not released: it stays billed; release it in the console when it is no longer needed", a.AllocationID, orDash(a.IP))
				}
			}
			return rt.RenderReport(platform.Report{Target: sc.target(), Changes: []platform.Change{change}})
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "delete a load balancer that still has listeners (they are deleted with it)")
	cmd.Flags().StringVar(&region, "region", "", "region id: ask this region of the selected profile instead of the inventory")
	app.AddWaitFlags(cmd, &w, false, app.DefaultWaitTimeout)
	return cmd
}

// ------------------------------------------------------------- listener

// parseListenerSpec reads <protocol>:<port>; the protocol is http or https.
func parseListenerSpec(flag, v string) (string, int, error) {
	proto, port, ok := strings.Cut(strings.TrimSpace(v), ":")
	p := strings.ToUpper(proto)
	if !ok || (p != "HTTP" && p != "HTTPS") {
		return "", 0, app.UsageErrf("--%s %q: expected <protocol>:<port> with protocol http or https, e.g. https:443", flag, v)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", 0, app.UsageErrf("--%s %q: the port must be 1-65535", flag, v)
	}
	return p, n, nil
}

func albListenerGrid(ls []albListener) output.Grid {
	g := output.Grid{Headers: []string{"ID", "PROTOCOL", "PORT", "STATUS", "SERVER_GROUPS"}, Empty: "no listeners"}
	for _, l := range ls {
		g.Rows = append(g.Rows, []string{l.ID, l.Protocol, strconv.Itoa(l.Port), orDash(l.Status), orDash(strings.Join(l.ServerGroups, ","))})
	}
	return g
}

func albListenerListCmd(rt *app.Runtime) *cobra.Command {
	var region, lbRef, protocol string
	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List the listeners of a load balancer",
		Example: "  polyctl aliyun alb listener list --lb lb-example-com --protocol HTTPS",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if lbRef == "" && !rt.Interactive() {
				return app.UsageErrf("--lb is required: name the load balancer (name or id)")
			}
			p := strings.ToUpper(strings.TrimSpace(protocol))
			if p != "" && p != "HTTP" && p != "HTTPS" && p != "QUIC" {
				return app.UsageErrf("--protocol must be HTTP, HTTPS or QUIC, got %q", protocol)
			}
			sc, err := openALBScope(ctx, rt, region)
			if err != nil {
				return err
			}
			if lbRef == "" {
				if lbRef, err = pickLB(ctx, rt, sc, "--lb"); err != nil {
					return err
				}
			}
			lb, err := resolveLB(ctx, sc, lbRef)
			if err != nil {
				return err
			}
			ls, err := sc.a.listListenersOf(ctx, lb.ID, p)
			if err != nil {
				return err
			}
			if ls == nil {
				ls = []albListener{}
			}
			if len(ls) == 0 {
				rt.Infof("no listeners on %s in %s", lb.ID, sc.where())
			}
			return rt.Render(ls, func() output.Grid { return albListenerGrid(ls) })
		},
	}
	cmd.Flags().StringVar(&lbRef, "lb", "", "load balancer, name or id (required)")
	cmd.Flags().StringVar(&protocol, "protocol", "", "only the listeners of this protocol: HTTP, HTTPS or QUIC")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

// getListenerOrNotFound reads a listener; a missing one is exit code 4.
func getListenerOrNotFound(ctx context.Context, sc *albScope, id string) (*albListener, error) {
	if !strings.HasPrefix(id, "lsn-") {
		return nil, app.UsageErrf("%q is not a listener id (lsn-...)", id)
	}
	l, err := sc.a.getListener(ctx, id)
	if err != nil {
		return nil, err
	}
	if l == nil {
		return nil, fmt.Errorf("%w: listener %s in %s (pass --region when it is in another region)", platform.ErrNotFound, id, sc.where())
	}
	return l, nil
}

func albListenerGetCmd(rt *app.Runtime) *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:     "get <listener-id>",
		Short:   "Show a listener: status, certificates, server groups",
		Example: "  polyctl aliyun alb listener get lsn-0123456789 --region cn-hongkong",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if len(args) > 0 && !strings.HasPrefix(args[0], "lsn-") {
				return app.UsageErrf("%q is not a listener id (lsn-...)", args[0])
			}
			sc, err := openALBScope(ctx, rt, region)
			if err != nil {
				return err
			}
			if args, err = listenerArg(ctx, rt, sc, args); err != nil {
				return err
			}
			l, err := getListenerOrNotFound(ctx, sc, args[0])
			if err != nil {
				return err
			}
			return rt.Render(l, func() output.Grid {
				return output.Grid{Rows: [][]string{
					{"ID", l.ID, "LOAD_BALANCER", l.LoadBalancerID},
					{"PROTOCOL", l.Protocol, "PORT", strconv.Itoa(l.Port)},
					{"STATUS", orDash(l.Status), "SERVER_GROUPS", orDash(strings.Join(l.ServerGroups, ","))},
					{"CERTIFICATES", orDash(strings.Join(l.Certificates, ","))},
				}}
			})
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

func albListenerCreateCmd(rt *app.Runtime) *cobra.Command {
	var region, lbRef, spec, groupRef, cert string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a listener forwarding to a server group",
		Long: `Create a listener on --lb (name or id) for --listener <protocol>:<port>
(http or https) that forwards to --server-group (name or id). An HTTPS
listener needs --cert, a CAS certificate id (written <id>-<cas region> for
the listener where the region's certificates live in another CAS store, as
in cn-hongkong); an HTTP one takes none. The command waits up to a minute
for the listener to be Running.`,
		Example: "  polyctl aliyun alb listener create --lb lb-example-com --listener https:443 --server-group site-a-http --cert 1234567",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if (lbRef == "" || spec == "" || groupRef == "") && !rt.Interactive() {
				return app.UsageErrf("--lb, --listener and --server-group are required")
			}
			var proto string
			var port int
			var err error
			if spec != "" {
				if proto, port, err = parseListenerSpec("listener", spec); err != nil {
					return err
				}
			}
			switch {
			case spec != "" && proto == "HTTPS" && cert == "" && !rt.Interactive():
				return app.UsageErrf("an HTTPS listener needs --cert <cas-cert-id>")
			case proto == "HTTP" && cert != "":
				return app.UsageErrf("an HTTP listener takes no --cert")
			}
			if cert != "" {
				if err := checkCertFlag(cert); err != nil {
					return err
				}
			}
			sc, err := openALBScope(ctx, rt, region)
			if err != nil {
				return err
			}
			if lbRef == "" {
				if lbRef, err = pickLB(ctx, rt, sc, "--lb"); err != nil {
					return app.RequiredPick(err, "--lb")
				}
			}
			lb, err := resolveLB(ctx, sc, lbRef)
			if err != nil {
				return err
			}
			if spec == "" {
				// The interactive flow: http:80 or https:443 when the load
				// balancer does not use the port yet, or another one.
				if proto, port, err = askListenerSpec(ctx, rt, sc, lb.ID); err != nil {
					return err
				}
				if proto == "HTTP" && cert != "" {
					return app.UsageErrf("an HTTP listener takes no --cert")
				}
			}
			if groupRef == "" {
				picked, err := serverGroupArg(ctx, rt, sc, nil, "--server-group")
				if err != nil {
					return app.RequiredPick(err, "--server-group")
				}
				groupRef = picked[0]
			}
			g, err := resolveServerGroup(ctx, sc, groupRef)
			if err != nil {
				return err
			}
			if proto == "HTTPS" && cert == "" {
				if cert, err = askCASCert(ctx, rt, sc.c, sc.region, "", "--cert"); err != nil {
					return err
				}
			}
			certID := ""
			if cert != "" {
				if certID, err = listenerCert(sc.c, sc.region, cert); err != nil {
					return err
				}
			}
			ls, err := sc.a.listListeners(ctx, lb.ID)
			if err != nil {
				return err
			}
			for _, l := range ls {
				if l.Port == port {
					return fmt.Errorf("load balancer %s has a listener on port %d already (%s %s)", lb.ID, port, l.ID, l.Protocol)
				}
			}
			res := fmt.Sprintf("load-balancer/%s/listener/%s:%d", orID(lb.Name, lb.ID), strings.ToLower(proto), port)
			desc := "-> " + orID(g.Name, g.ID)
			if certID != "" {
				desc += " cert=" + certID
			}
			var plan platform.Plan
			plan.Add(listenerCreateStep(sc, res, desc, func() string { return lb.ID }, proto, port, func() string { return g.ID }, certID))
			return rt.Ensure(ctx, "aliyun.alb.listener.create", sc.target(), &plan)
		},
	}
	cmd.Flags().StringVar(&lbRef, "lb", "", "load balancer, name or id (required)")
	cmd.Flags().StringVar(&spec, "listener", "", "<protocol>:<port>, protocol http or https (required)")
	cmd.Flags().StringVar(&groupRef, "server-group", "", "server group to forward to, name or id (required)")
	cmd.Flags().StringVar(&cert, "cert", "", "CAS certificate id (HTTPS only)")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

// listenerCreateStep creates a listener and waits until it is Running.
func listenerCreateStep(sc *albScope, res, desc string, lbID func() string, proto string, port int, groupID func() string, certID string) platform.Step {
	return platform.Step{Resource: res, Action: platform.Created, Desc: desc,
		Apply: func(ctx context.Context) (platform.Change, error) {
			id, err := sc.a.createListener(ctx, lbID(), proto, port, groupID(), certID)
			if err != nil {
				return platform.Change{}, err
			}
			detail := id + " " + desc
			if err := waitListenerRunning(ctx, sc.a, id); err != nil {
				return platform.Change{ID: id}, fmt.Errorf("listener %s was created: %w", id, err)
			}
			return platform.Change{ID: id, Detail: detail}, nil
		}}
}

func albListenerUpdateCmd(rt *app.Runtime) *cobra.Command {
	var region, groupRef, cert string
	cmd := &cobra.Command{
		Use:   "update <listener-id>",
		Short: "Change the server group or the certificate of a listener",
		Long: `Change what a listener forwards to (--server-group, name or id) and/or the
default certificate of an HTTPS listener (--cert, a CAS certificate id).
Nothing else is changed. Values the listener holds already are unchanged;
after a change the command waits up to a minute for the listener to be
Running again.`,
		Example: "  polyctl aliyun alb listener update lsn-0123456789 --server-group site-a-https",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if groupRef == "" && cert == "" && !rt.Interactive() {
				return app.UsageErrf("nothing to change: pass --server-group and/or --cert")
			}
			if cert != "" {
				if err := checkCertFlag(cert); err != nil {
					return err
				}
			}
			if len(args) > 0 && !strings.HasPrefix(args[0], "lsn-") {
				return app.UsageErrf("%q is not a listener id (lsn-...)", args[0])
			}
			sc, err := openALBScope(ctx, rt, region)
			if err != nil {
				return err
			}
			if args, err = listenerArg(ctx, rt, sc, args); err != nil {
				return err
			}
			l, err := getListenerOrNotFound(ctx, sc, args[0])
			if err != nil {
				return err
			}
			if groupRef == "" && cert == "" {
				// The interactive flow asks what to change, then offers the
				// server groups or the certificates.
				opts := []prompt.Option{{Label: "Server group (now " + orDash(strings.Join(l.ServerGroups, ",")) + ")", Value: "group"}}
				if carriesCertificates(l.Protocol) {
					opts = append(opts, prompt.Option{Label: "Certificate (now " + orDash(firstOr(l.Certificates, "")) + ")", Value: "cert"})
				}
				what, err := rt.Choose(app.Choice{Title: "Change what of listener " + l.ID + "?", Options: opts, Arg: "--server-group or --cert"})
				if err != nil {
					return err
				}
				if what == "cert" {
					if cert, err = askCASCert(ctx, rt, sc.c, sc.region, firstOr(l.Certificates, ""), "--cert"); err != nil {
						return err
					}
				} else {
					picked, err := serverGroupArg(ctx, rt, sc, nil, "--server-group")
					if err != nil {
						return err
					}
					groupRef = picked[0]
				}
			}
			var changes []string
			groupID, certID := "", ""
			if groupRef != "" {
				g, err := resolveServerGroup(ctx, sc, groupRef)
				if err != nil {
					return err
				}
				if !(len(l.ServerGroups) == 1 && l.ServerGroups[0] == g.ID) {
					groupID = g.ID
					changes = append(changes, fmt.Sprintf("server group %s -> %s", orDash(strings.Join(l.ServerGroups, ",")), g.ID))
				}
			}
			if cert != "" {
				if !carriesCertificates(l.Protocol) {
					return app.UsageErrf("listener %s is %s: only HTTPS listeners hold certificates", l.ID, l.Protocol)
				}
				want, err := listenerCert(sc.c, sc.region, cert)
				if err != nil {
					return err
				}
				if cur := firstOr(l.Certificates, ""); cur != want {
					certID = want
					changes = append(changes, fmt.Sprintf("cert %s -> %s", orDash(cur), want))
				}
			}
			res := "listener/" + l.ID
			var plan platform.Plan
			if len(changes) == 0 {
				plan.Add(platform.Step{Resource: res, Action: platform.Unchanged, ID: l.ID, Desc: "already as asked"})
			} else {
				plan.Add(platform.Step{Resource: res, Action: platform.Updated, ID: l.ID, Desc: strings.Join(changes, "; "),
					Apply: func(ctx context.Context) (platform.Change, error) {
						if err := sc.a.updateListener(ctx, l.ID, certID, groupID); err != nil {
							return platform.Change{}, err
						}
						if err := waitListenerRunning(ctx, sc.a, l.ID); err != nil {
							return platform.Change{}, fmt.Errorf("listener %s was updated: %w", l.ID, err)
						}
						return platform.Change{}, nil
					}})
			}
			return rt.Ensure(ctx, "aliyun.alb.listener.update", sc.target(), &plan)
		},
	}
	cmd.Flags().StringVar(&groupRef, "server-group", "", "server group to forward to, name or id")
	cmd.Flags().StringVar(&cert, "cert", "", "CAS certificate id (HTTPS listeners)")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

func firstOr(list []string, def string) string {
	if len(list) == 0 {
		return def
	}
	return list[0]
}

func albListenerCertSetCmd(rt *app.Runtime) *cobra.Command {
	var region, cert string
	cmd := &cobra.Command{
		Use:   "set <listener-id>",
		Short: "Make a CAS certificate the default certificate of an HTTPS listener",
		Long: `Make --cert (a CAS certificate id) the default certificate of the HTTPS listener,
then wait up to a minute for the listener to be Running again (a listener
that is still Configuring refuses the next write). The certificate is
written for the listener as the region needs it: <id>-ap-southeast-1 in
cn-hongkong (its certificates live in the Singapore CAS store), the bare id
elsewhere. A listener holding it already is unchanged.`,
		Example: "  polyctl aliyun alb listener cert set lsn-0123456789 --cert 1234567 --region cn-hongkong",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if cert == "" && !rt.Interactive() {
				return app.UsageErrf("--cert is required: the CAS certificate id")
			}
			if cert != "" {
				if err := checkCertFlag(cert); err != nil {
					return err
				}
			}
			if len(args) > 0 && !strings.HasPrefix(args[0], "lsn-") {
				return app.UsageErrf("%q is not a listener id (lsn-...)", args[0])
			}
			sc, err := openALBScope(ctx, rt, region)
			if err != nil {
				return err
			}
			if args, err = listenerArg(ctx, rt, sc, args, "HTTPS", "QUIC"); err != nil {
				return err
			}
			l, err := getListenerOrNotFound(ctx, sc, args[0])
			if err != nil {
				return err
			}
			if !carriesCertificates(l.Protocol) {
				return app.UsageErrf("listener %s is %s: only HTTPS listeners hold certificates", l.ID, l.Protocol)
			}
			if cert == "" {
				if cert, err = askCASCert(ctx, rt, sc.c, sc.region, firstOr(l.Certificates, ""), "--cert"); err != nil {
					return err
				}
			}
			want, err := listenerCert(sc.c, sc.region, cert)
			if err != nil {
				return err
			}
			var plan platform.Plan
			plan.Add(listenerCertStep(sc, "listener/"+l.ID, l, want))
			return rt.Ensure(ctx, "aliyun.alb.listener.cert.set", sc.target(), &plan)
		},
	}
	cmd.Flags().StringVar(&cert, "cert", "", "CAS certificate id (required)")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

// listenerCertStep makes want the default certificate of l: unchanged when
// it is already, else updated and waited for.
func listenerCertStep(sc *albScope, res string, l *albListener, want string) platform.Step {
	cur := firstOr(l.Certificates, "")
	if cur == want {
		return platform.Step{Resource: res, Action: platform.Unchanged, ID: l.ID, Desc: l.ID + " cert=" + want}
	}
	return platform.Step{Resource: res, Action: platform.Updated, ID: l.ID, Desc: fmt.Sprintf("%s cert %s -> %s", l.ID, orDash(cur), want),
		Apply: func(ctx context.Context) (platform.Change, error) {
			if err := setListenerCertificate(ctx, sc.a, l.ID, want); err != nil {
				return platform.Change{}, err
			}
			return platform.Change{}, nil
		}}
}

func albListenerDeleteCmd(rt *app.Runtime) *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:     "delete <listener-id>",
		Short:   "Delete a listener (asks first)",
		Long:    `Delete a listener. It is shown first, then a confirmation is asked (default no; --yes skips it, the non-interactive flow needs --yes, exit code 2).`,
		Example: "  polyctl aliyun alb listener delete lsn-0123456789 --yes",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if len(args) > 0 && !strings.HasPrefix(args[0], "lsn-") {
				return app.UsageErrf("%q is not a listener id (lsn-...)", args[0])
			}
			if err := albCanConfirm(rt, "delete listener "+app.Arg(args, 0)); err != nil {
				return err
			}
			sc, err := openALBScope(ctx, rt, region)
			if err != nil {
				return err
			}
			if args, err = listenerArg(ctx, rt, sc, args); err != nil {
				return err
			}
			l, err := getListenerOrNotFound(ctx, sc, args[0])
			if err != nil {
				return err
			}
			rt.Infof("listener %s %s:%d of %s in %s", l.ID, l.Protocol, l.Port, l.LoadBalancerID, sc.where())
			change := platform.Change{Resource: "listener/" + l.ID, Action: platform.Deleted, ID: l.ID, Detail: fmt.Sprintf("%s:%d of %s", l.Protocol, l.Port, l.LoadBalancerID)}
			if done, err := rt.WouldWrite(sc.target(), change); done || err != nil {
				return err
			}
			ok, err := rt.Confirm(ctx, fmt.Sprintf("Delete listener %s (%s:%d)?", l.ID, l.Protocol, l.Port), false)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("%w: cancelled; listener %s was not deleted", platform.ErrNothingToDo, l.ID)
			}
			if err := sc.a.deleteListener(ctx, l.ID); err != nil {
				if !platform.HasErrorCode(err, errALBListenerNotFound) {
					return err
				}
				change.Action, change.Detail = platform.Unchanged, "already deleted"
			}
			return rt.RenderReport(platform.Report{Target: sc.target(), Changes: []platform.Change{change}})
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

// --------------------------------------------------------- server group

func albSGGrid(gs []albServerGroup) output.Grid {
	g := output.Grid{Headers: []string{"NAME", "ID", "PROTOCOL", "VPC", "STATUS", "SERVERS"}, Empty: "no server groups"}
	for _, x := range gs {
		g.Rows = append(g.Rows, []string{orDash(x.Name), x.ID, x.Protocol, orDash(x.VpcID), orDash(x.Status), strconv.Itoa(x.ServerCount)})
	}
	return g
}

func albSGListCmd(rt *app.Runtime) *cobra.Command {
	var region, name string
	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List the server groups of a region",
		Example: "  polyctl aliyun alb server-group list --name site-a-http",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			sc, err := openALBScope(ctx, rt, region)
			if err != nil {
				return err
			}
			var names []string
			if name != "" {
				names = []string{name}
			}
			gs, err := sc.a.listServerGroups(ctx, names, nil)
			if err != nil {
				return err
			}
			if gs == nil {
				gs = []albServerGroup{}
			}
			if len(gs) == 0 {
				rt.Infof("no server groups in %s", sc.where())
			} else {
				rt.Infof("%d server group(s) in %s", len(gs), sc.where())
			}
			return rt.Render(gs, func() output.Grid { return albSGGrid(gs) })
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "only the server groups of this exact name")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

// albSGDetail is the output of server-group get.
type albSGDetail struct {
	albServerGroup `yaml:",inline"`
	Servers        []albBackend `json:"servers" yaml:"servers"`
}

func albSGGetCmd(rt *app.Runtime) *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:   "get <name|id>",
		Short: "Show a server group and its servers",
		Args:  app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			sc, err := openALBScope(ctx, rt, region)
			if err != nil {
				return err
			}
			if args, err = serverGroupArg(ctx, rt, sc, args, "<name|id>"); err != nil {
				return err
			}
			g, err := resolveServerGroup(ctx, sc, args[0])
			if err != nil {
				return err
			}
			srv, err := sc.a.listServerGroupServers(ctx, g.ID)
			if err != nil {
				return err
			}
			d := albSGDetail{albServerGroup: *g, Servers: srv}
			return rt.Render(d, func() output.Grid {
				out := output.Grid{Rows: [][]string{
					{"NAME", orDash(g.Name), "ID", g.ID},
					{"PROTOCOL", g.Protocol, "VPC", orDash(g.VpcID)},
					{"STATUS", orDash(g.Status), "HEALTH_CHECK", strconv.FormatBool(g.HealthCheck)},
					{"SCHEDULER", orDash(g.Scheduler), "STICKY_SESSION", strconv.FormatBool(g.StickySession)},
					{"SERVERS"},
				}}
				if len(srv) == 0 {
					out.Rows = append(out.Rows, []string{"  (none)"})
				}
				for _, s := range srv {
					out.Rows = append(out.Rows, []string{"  " + s.ServerID, strconv.Itoa(s.Port), orDash(s.IP), orDash(s.Status)})
				}
				return out
			})
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

// parseGroupProtocol reads --protocol of a server group.
func parseGroupProtocol(v string) (string, error) {
	p := strings.ToUpper(strings.TrimSpace(v))
	if p != "HTTP" && p != "HTTPS" {
		return "", app.UsageErrf("--protocol must be HTTP or HTTPS, got %q", v)
	}
	return p, nil
}

// serverGroupCreateStep creates a server group and waits until it is
// Available; it stores the new id in *id.
func serverGroupCreateStep(sc *albScope, name, protocol string, vpcID func() string, resourceGroup string, id *string) platform.Step {
	return platform.Step{Resource: "server-group/" + name, Action: platform.Created, Desc: protocol,
		Apply: func(ctx context.Context) (platform.Change, error) {
			gid, err := sc.a.createServerGroup(ctx, name, protocol, vpcID(), resourceGroup)
			if err != nil {
				return platform.Change{}, err
			}
			*id = gid
			if err := waitServerGroupAvailable(ctx, sc.a, gid); err != nil {
				return platform.Change{ID: gid}, fmt.Errorf("server group %s (%s) was created: %w", name, gid, err)
			}
			return platform.Change{ID: gid, Detail: gid + " " + protocol}, nil
		}}
}

func albSGCreateCmd(rt *app.Runtime) *cobra.Command {
	var region, vpcRef, protocol, group string
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a server group of ECS instances",
		Long: `Create the server group <name> (type Instance) in --vpc (id or name; required)
for --protocol HTTP or HTTPS (required), with the health check and session
persistence off. Alibaba Cloud allows several server groups of one name;
polyctl refuses to create a second one in the same VPC (exit code 1).`,
		Example: "  polyctl aliyun alb server-group create site-a-http --vpc cn-hongkong-vpc --protocol HTTP",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name := app.Arg(args, 0)
			checkName := func(n string) error {
				if strings.TrimSpace(n) == "" || looksLikeServerGroupID(n) {
					return app.UsageErrf("server group name %q is empty or starts with sgp- (that is how ids are written)", n)
				}
				return nil
			}
			if len(args) > 0 {
				if err := checkName(name); err != nil {
					return err
				}
			}
			if vpcRef == "" && !rt.Interactive() {
				return app.UsageErrf("--vpc is required: a server group belongs to one VPC")
			}
			var p string
			var err error
			if protocol != "" || !rt.Interactive() {
				if p, err = parseGroupProtocol(protocol); err != nil {
					return err
				}
			}
			sc, err := openALBScope(ctx, rt, region)
			if err != nil {
				return err
			}
			var v vpcInfo
			if vpcRef == "" {
				prefer, _ := rt.ResourceName("aliyun_vpc", "", map[string]string{"region": sc.region})
				v, err = pickVPC(ctx, rt, sc.ecsScope, "--vpc", prefer, nil)
			} else {
				v, err = resolveVPC(ctx, sc.ecsScope, vpcRef)
			}
			if err != nil {
				return err
			}
			if p == "" {
				if p, err = rt.Choose(app.Choice{Title: "Backend protocol", Arg: "--protocol", Default: "HTTP",
					Options: []prompt.Option{{Label: "HTTP", Value: "HTTP"}, {Label: "HTTPS", Value: "HTTPS"}}}); err != nil {
					return err
				}
			}
			if name == "" {
				groups, err := sc.a.listServerGroups(ctx, nil, nil)
				if err != nil {
					return err
				}
				if name, err = rt.AskInput("<name>", "Name of the new server group ("+v.ID+")", "", func(n string) error {
					n = strings.TrimSpace(n)
					if err := checkName(n); err != nil {
						return inline(err)
					}
					for _, g := range groups {
						if g.Name == n && g.VpcID == v.ID {
							return fmt.Errorf("server group %q already exists in %s (%s)", n, v.ID, g.ID)
						}
					}
					return nil
				}); err != nil {
					return err
				}
			}
			found, err := sc.a.listServerGroups(ctx, []string{name}, nil)
			if err != nil {
				return err
			}
			for _, g := range found {
				if g.VpcID == v.ID {
					return fmt.Errorf("server group %q already exists in %s (%s)", name, v.ID, g.ID)
				}
			}
			rg, err := resolveResourceGroup(ctx, rt, sc.ecsScope, group)
			if err != nil {
				return err
			}
			var id string
			var plan platform.Plan
			plan.Add(serverGroupCreateStep(sc, name, p, func() string { return v.ID }, rg, &id))
			return rt.Ensure(ctx, "aliyun.alb.server_group.create", sc.target(), &plan)
		},
	}
	cmd.Flags().StringVar(&vpcRef, "vpc", "", "VPC of the server group, id or name (required)")
	cmd.Flags().StringVar(&protocol, "protocol", "", "backend protocol: HTTP or HTTPS (required)")
	cmd.Flags().StringVar(&group, "resource-group", "", "resource group, a name or an rg- id (default defaults.aliyun.resource_group, else \"default\")")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

// albSchedulers are the balancing algorithms of a server group, as the API
// writes them.
var albSchedulers = []string{"Wrr", "Wlc", "Sch"}

// parseScheduler reads --scheduler (any case).
func parseScheduler(v string) (string, error) {
	for _, s := range albSchedulers {
		if strings.EqualFold(strings.TrimSpace(v), s) {
			return s, nil
		}
	}
	return "", app.UsageErrf("--scheduler must be one of %s, got %q", strings.Join(albSchedulers, ", "), v)
}

// checkHealthCheckPath validates --health-check-path: an absolute path of
// at most 80 characters without spaces (the API's limits).
func checkHealthCheckPath(v string) error {
	if !strings.HasPrefix(v, "/") || len(v) > 80 || strings.ContainsAny(v, " \t\r\n") {
		return app.UsageErrf("--health-check-path %q: expected a path starting with / (at most 80 characters, no spaces)", v)
	}
	return nil
}

func albSGUpdateCmd(rt *app.Runtime) *cobra.Command {
	var region, name, scheduler, path string
	var healthCheck, sticky bool
	cmd := &cobra.Command{
		Use:   "update <name|id>",
		Short: "Rename a server group or change its scheduler, health check or session persistence",
		Long: `Change what the flags name, each only when it differs (otherwise the group is
reported unchanged): --name renames the group (a name another group of its
VPC holds is exit code 1), --scheduler sets the balancing algorithm (Wrr,
Wlc or Sch), --health-check[=false] switches the health check on or off,
--health-check-path sets its path (the health check has to be on, or
switched on by --health-check; an HTTP or HTTPS check), and
--sticky-session[=false] switches session persistence on (the load balancer
inserts the cookie) or off. Nothing else is changed. After a change the
command waits up to a minute for the group to be Available again.`,
		Example: "  polyctl aliyun alb server-group update site-a-http --health-check --health-check-path /healthz\n  polyctl aliyun alb server-group update sgp-0123456789 --scheduler Wlc --sticky-session=false",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			fl := cmd.Flags()
			if !fl.Changed("name") && !fl.Changed("scheduler") && !fl.Changed("health-check") && !fl.Changed("health-check-path") && !fl.Changed("sticky-session") {
				return app.UsageErrf("nothing to update: pass --name, --scheduler, --health-check, --health-check-path or --sticky-session")
			}
			if fl.Changed("name") && (strings.TrimSpace(name) == "" || looksLikeServerGroupID(name)) {
				return app.UsageErrf("server group name %q is empty or starts with sgp- (that is how ids are written)", name)
			}
			if fl.Changed("scheduler") {
				var err error
				if scheduler, err = parseScheduler(scheduler); err != nil {
					return err
				}
			}
			if fl.Changed("health-check-path") {
				if err := checkHealthCheckPath(path); err != nil {
					return err
				}
				if fl.Changed("health-check") && !healthCheck {
					return app.UsageErrf("--health-check-path needs the health check on: it cannot be combined with --health-check=false")
				}
			}
			sc, err := openALBScope(ctx, rt, region)
			if err != nil {
				return err
			}
			g, err := resolveServerGroup(ctx, sc, args[0])
			if err != nil {
				return err
			}
			var u albServerGroupUpdate
			var changes []string
			if fl.Changed("name") && name != g.Name {
				found, err := sc.a.listServerGroups(ctx, []string{name}, nil)
				if err != nil {
					return err
				}
				for _, o := range found {
					if o.VpcID == g.VpcID {
						return fmt.Errorf("server group %q already exists in %s (%s)", name, g.VpcID, o.ID)
					}
				}
				u.Name = name
				changes = append(changes, fmt.Sprintf("name %s -> %s", orDash(g.Name), name))
			}
			if fl.Changed("scheduler") && scheduler != g.Scheduler {
				u.Scheduler = scheduler
				changes = append(changes, fmt.Sprintf("scheduler %s -> %s", orDash(g.Scheduler), scheduler))
			}
			hcOn := g.HealthCheck
			if fl.Changed("health-check") {
				hcOn = healthCheck
			}
			if fl.Changed("health-check-path") {
				if !hcOn {
					return app.UsageErrf("server group %s has the health check off: pass --health-check with --health-check-path", g.ID)
				}
				if g.HealthCheck && g.HealthCheckProtocol != "" && !strings.EqualFold(g.HealthCheckProtocol, "HTTP") && !strings.EqualFold(g.HealthCheckProtocol, "HTTPS") {
					return app.UsageErrf("server group %s has a %s health check, which has no path", g.ID, g.HealthCheckProtocol)
				}
			}
			if fl.Changed("health-check") && healthCheck != g.HealthCheck {
				changes = append(changes, fmt.Sprintf("health check %t -> %t", g.HealthCheck, healthCheck))
				u.HealthCheck = &hcOn
			}
			if fl.Changed("health-check-path") && (!g.HealthCheck || path != g.HealthCheckPath) {
				if g.HealthCheck {
					changes = append(changes, fmt.Sprintf("health check path %s -> %s", orDash(g.HealthCheckPath), path))
				} else {
					changes = append(changes, "health check path "+path)
				}
				u.HealthCheck, u.HealthCheckPath = &hcOn, path
			}
			if fl.Changed("sticky-session") && sticky != g.StickySession {
				v := sticky
				u.StickySession = &v
				changes = append(changes, fmt.Sprintf("sticky session %t -> %t", g.StickySession, sticky))
			}
			res := "server-group/" + orID(g.Name, g.ID)
			var plan platform.Plan
			if len(changes) == 0 {
				plan.Add(platform.Step{Resource: res, Action: platform.Unchanged, ID: g.ID, Desc: "already as asked"})
			} else {
				plan.Add(platform.Step{Resource: res, Action: platform.Updated, ID: g.ID, Desc: strings.Join(changes, "; "),
					Apply: func(ctx context.Context) (platform.Change, error) {
						if err := sc.a.updateServerGroup(ctx, g.ID, u); err != nil {
							return platform.Change{}, err
						}
						if err := waitServerGroupAvailable(ctx, sc.a, g.ID); err != nil {
							return platform.Change{}, fmt.Errorf("server group %s was updated: %w", g.ID, err)
						}
						return platform.Change{}, nil
					}})
			}
			return rt.Ensure(ctx, "aliyun.alb.server_group.update", sc.target(), &plan)
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "new name of the server group")
	cmd.Flags().StringVar(&scheduler, "scheduler", "", "balancing algorithm: Wrr, Wlc or Sch")
	cmd.Flags().BoolVar(&healthCheck, "health-check", false, "turn the health check on (--health-check=false turns it off)")
	cmd.Flags().StringVar(&path, "health-check-path", "", "path of the HTTP / HTTPS health check, e.g. /healthz (the health check has to be on)")
	cmd.Flags().BoolVar(&sticky, "sticky-session", false, "turn session persistence on, with a cookie the load balancer inserts (--sticky-session=false turns it off)")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

func albSGDeleteCmd(rt *app.Runtime) *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:   "delete <name|id>",
		Short: "Delete a server group (asks first)",
		Long: `Delete a server group. It is shown first, then a confirmation is asked (default
no; --yes skips it, the non-interactive flow needs --yes, exit code 2). A
group a listener still forwards to is refused by Alibaba Cloud (exit code 1).`,
		Example: "  polyctl aliyun alb server-group delete site-a-http --yes",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if err := albCanConfirm(rt, "delete server group "+app.Arg(args, 0)); err != nil {
				return err
			}
			sc, err := openALBScope(ctx, rt, region)
			if err != nil {
				return err
			}
			if args, err = serverGroupArg(ctx, rt, sc, args, "<name|id>"); err != nil {
				return err
			}
			g, err := resolveServerGroup(ctx, sc, args[0])
			if err != nil {
				return err
			}
			rt.Infof("server group %s (%s, %s, %d server(s)) in %s", orDash(g.Name), g.ID, g.Protocol, g.ServerCount, sc.where())
			change := platform.Change{Resource: "server-group/" + orID(g.Name, g.ID), Action: platform.Deleted, ID: g.ID}
			if done, err := rt.WouldWrite(sc.target(), change); done || err != nil {
				return err
			}
			ok, err := rt.Confirm(ctx, fmt.Sprintf("Delete server group %s (%s)?", orDash(g.Name), g.ID), false)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("%w: cancelled; server group %s was not deleted", platform.ErrNothingToDo, g.ID)
			}
			if err := sc.a.deleteServerGroup(ctx, g.ID); err != nil {
				if !platform.HasErrorCode(err, errALBServerGroupNotFound) {
					return err
				}
				change.Action, change.Detail = platform.Unchanged, "already deleted"
			}
			return rt.RenderReport(platform.Report{Target: sc.target(), Changes: []platform.Change{change}})
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

// serverAddStep adds the instance on port to the group of groupID() (the
// id of a group an earlier step creates).
func serverAddStep(sc *albScope, res, label string, groupID func() string, instanceID string, port int) platform.Step {
	return platform.Step{Resource: res, Action: platform.Created, Desc: fmt.Sprintf("%s:%d", label, port),
		Apply: func(ctx context.Context) (platform.Change, error) {
			if err := sc.a.addServer(ctx, groupID(), instanceID, port); err != nil {
				return platform.Change{}, err
			}
			return platform.Change{ID: instanceID, Detail: fmt.Sprintf("%s:%d (%s)", label, port, instanceID)}, nil
		}}
}

func albServerAddCmd(rt *app.Runtime) *cobra.Command {
	var region, instance string
	var port int
	cmd := &cobra.Command{
		Use:   "add <server-group>",
		Short: "Add an ECS instance to a server group",
		Long: `Add the ECS instance --instance (name or id, in the account and region of the
group; required) on --port (required) to the server group (name or id). An
instance already in the group on that port is unchanged. The instance has to
be in the group's VPC (exit code 1 otherwise).`,
		Example: "  polyctl aliyun alb server-group server add site-a-http --instance site-a --port 80",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if instance == "" && !rt.Interactive() {
				return app.UsageErrf("--instance is required: name the ECS instance")
			}
			if (port < 1 || port > 65535) && !(port == 0 && rt.Interactive()) {
				return app.UsageErrf("--port is required and must be 1-65535, got %d", port)
			}
			sc, err := openALBScope(ctx, rt, region)
			if err != nil {
				return err
			}
			if args, err = serverGroupArg(ctx, rt, sc, args, "<server-group>"); err != nil {
				return err
			}
			g, err := resolveServerGroup(ctx, sc, args[0])
			if err != nil {
				return err
			}
			if instance == "" {
				// The instances of the group's VPC in the region, not in
				// the group yet.
				if instance, err = pickGroupInstance(ctx, rt, sc, g); err != nil {
					return err
				}
			}
			if port == 0 {
				def := "80"
				if strings.EqualFold(g.Protocol, "HTTPS") {
					def = "443"
				}
				v, err := rt.AskInput("--port", "Port of the instance the group forwards to", def, func(s string) error {
					if n, err := strconv.Atoi(strings.TrimSpace(s)); err != nil || n < 1 || n > 65535 {
						return fmt.Errorf("a TCP port is 1-65535")
					}
					return nil
				})
				if err != nil {
					return err
				}
				port, _ = strconv.Atoi(v)
			}
			inst, err := resolveInstanceIn(ctx, sc.ecsScope, instance)
			if err != nil {
				return err
			}
			if inst.VpcID != "" && g.VpcID != "" && inst.VpcID != g.VpcID {
				return fmt.Errorf("instance %s is in %s, server group %s in %s: a server group holds instances of its own VPC only", inst.ID, inst.VpcID, g.ID, g.VpcID)
			}
			srv, err := sc.a.listServerGroupServers(ctx, g.ID)
			if err != nil {
				return err
			}
			res := "server-group/" + orID(g.Name, g.ID) + "/server"
			label := orID(inst.Name, inst.ID)
			var plan platform.Plan
			dup := false
			for _, s := range srv {
				if s.ServerID == inst.ID && s.Port == port {
					dup = true
				}
			}
			if dup {
				plan.Add(platform.Step{Resource: res, Action: platform.Unchanged, ID: inst.ID, Desc: fmt.Sprintf("%s:%d already in the group", label, port)})
			} else {
				plan.Add(serverAddStep(sc, res, label, func() string { return g.ID }, inst.ID, port))
			}
			return rt.Ensure(ctx, "aliyun.alb.server_group.server.add", sc.target(), &plan)
		},
	}
	cmd.Flags().StringVar(&instance, "instance", "", "ECS instance, name or id (required)")
	cmd.Flags().IntVar(&port, "port", 0, "backend port of the instance (required)")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

// ------------------------------------------------------------------ acl

func albACLGrid(list []albACL) output.Grid {
	g := output.Grid{Headers: []string{"NAME", "ID", "STATUS", "RESOURCE_GROUP"}, Empty: "no ACLs"}
	for _, x := range list {
		g.Rows = append(g.Rows, []string{orDash(x.Name), x.ID, orDash(x.Status), orDash(x.ResourceGroupID)})
	}
	return g
}

func albACLListCmd(rt *app.Runtime) *cobra.Command {
	var region, name string
	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List the ACLs of a region",
		Example: "  polyctl aliyun alb acl list --name office-allow",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			sc, err := openALBScope(ctx, rt, region)
			if err != nil {
				return err
			}
			var names []string
			if name != "" {
				names = []string{name}
			}
			list, err := sc.a.listACLs(ctx, names, nil)
			if err != nil {
				return err
			}
			if list == nil {
				list = []albACL{}
			}
			if len(list) == 0 {
				rt.Infof("no ACLs in %s", sc.where())
			} else {
				rt.Infof("%d ACL(s) in %s", len(list), sc.where())
			}
			return rt.Render(list, func() output.Grid { return albACLGrid(list) })
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "only the ACLs of this exact name")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

// albACLDetail is the output of acl get.
type albACLDetail struct {
	albACL     `yaml:",inline"`
	Entries    []albACLEntry `json:"entries" yaml:"entries"`
	EntryCount int           `json:"entry_count" yaml:"entry_count"`
}

func albACLGetCmd(rt *app.Runtime) *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:   "get <name|id>",
		Short: "Show an ACL and its entries",
		Args:  app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			sc, err := openALBScope(ctx, rt, region)
			if err != nil {
				return err
			}
			if args, err = aclArg(ctx, rt, sc, args, "<name|id>"); err != nil {
				return err
			}
			x, err := resolveACL(ctx, sc, args[0])
			if err != nil {
				return err
			}
			entries, err := sc.a.listACLEntries(ctx, x.ID)
			if err != nil {
				return err
			}
			d := albACLDetail{albACL: *x, Entries: entries, EntryCount: len(entries)}
			return rt.Render(d, func() output.Grid {
				g := output.Grid{Rows: [][]string{
					{"NAME", orDash(x.Name), "ID", x.ID},
					{"STATUS", orDash(x.Status), "ENTRIES", strconv.Itoa(len(entries))},
				}}
				for _, e := range entries {
					g.Rows = append(g.Rows, []string{"  " + e.Entry, orDash(e.Description), orDash(e.Status)})
				}
				return g
			})
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

func albACLCreateCmd(rt *app.Runtime) *cobra.Command {
	var region, group string
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create an ACL",
		Long: `Create the ACL <name> in --resource-group (a name or rg- id; default
defaults.aliyun.resource_group, else "default"). Alibaba Cloud allows several
ACLs of one name; polyctl refuses to create a second one (exit code 1). An
ACL takes effect once it is bound to a listener, which polyctl does not do.`,
		Example: "  polyctl aliyun alb acl create office-allow",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name := app.Arg(args, 0)
			checkName := func(n string) error {
				if strings.TrimSpace(n) == "" || looksLikeACLID(n) {
					return app.UsageErrf("ACL name %q is empty or starts with acl- (that is how ids are written)", n)
				}
				return nil
			}
			if len(args) > 0 {
				if err := checkName(name); err != nil {
					return err
				}
			}
			sc, err := openALBScope(ctx, rt, region)
			if err != nil {
				return err
			}
			if name == "" {
				acls, err := sc.a.listACLs(ctx, nil, nil)
				if err != nil {
					return err
				}
				if name, err = rt.AskInput("<name>", "Name of the new ACL", "", func(n string) error {
					n = strings.TrimSpace(n)
					if err := checkName(n); err != nil {
						return inline(err)
					}
					for _, x := range acls {
						if x.Name == n {
							return fmt.Errorf("ACL %q already exists (%s)", n, x.ID)
						}
					}
					return nil
				}); err != nil {
					return err
				}
			}
			found, err := sc.a.listACLs(ctx, []string{name}, nil)
			if err != nil {
				return err
			}
			if len(found) > 0 {
				return fmt.Errorf("ACL %q already exists in %s (%s)", name, sc.where(), found[0].ID)
			}
			rg, err := resolveResourceGroup(ctx, rt, sc.ecsScope, group)
			if err != nil {
				return err
			}
			var plan platform.Plan
			plan.Add(platform.Step{Resource: "acl/" + name, Action: platform.Created,
				Apply: func(ctx context.Context) (platform.Change, error) {
					id, err := sc.a.createACL(ctx, name, rg)
					if err != nil {
						return platform.Change{}, err
					}
					if err := waitACLAvailable(ctx, sc.a, id); err != nil {
						return platform.Change{ID: id}, fmt.Errorf("ACL %s (%s) was created: %w", name, id, err)
					}
					return platform.Change{ID: id, Detail: id}, nil
				}})
			return rt.Ensure(ctx, "aliyun.alb.acl.create", sc.target(), &plan)
		},
	}
	cmd.Flags().StringVar(&group, "resource-group", "", "resource group, a name or an rg- id (default defaults.aliyun.resource_group, else \"default\")")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

func albACLDeleteCmd(rt *app.Runtime) *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:     "delete <name|id>",
		Short:   "Delete an ACL and its entries (asks first)",
		Long:    `Delete an ACL with its entries. It is shown first, then a confirmation is asked (default no; --yes skips it, the non-interactive flow needs --yes, exit code 2).`,
		Example: "  polyctl aliyun alb acl delete office-allow --yes",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if err := albCanConfirm(rt, "delete ACL "+app.Arg(args, 0)); err != nil {
				return err
			}
			sc, err := openALBScope(ctx, rt, region)
			if err != nil {
				return err
			}
			if args, err = aclArg(ctx, rt, sc, args, "<name|id>"); err != nil {
				return err
			}
			x, err := resolveACL(ctx, sc, args[0])
			if err != nil {
				return err
			}
			entries, err := sc.a.listACLEntries(ctx, x.ID)
			if err != nil {
				return err
			}
			rt.Infof("ACL %s (%s, %d entries) in %s", orDash(x.Name), x.ID, len(entries), sc.where())
			change := platform.Change{Resource: "acl/" + orID(x.Name, x.ID), Action: platform.Deleted, ID: x.ID, Detail: fmt.Sprintf("with %d entries", len(entries))}
			if done, err := rt.WouldWrite(sc.target(), change); done || err != nil {
				return err
			}
			ok, err := rt.Confirm(ctx, fmt.Sprintf("Delete ACL %s (%s) and its %d entries?", orDash(x.Name), x.ID, len(entries)), false)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("%w: cancelled; ACL %s was not deleted", platform.ErrNothingToDo, x.ID)
			}
			if err := sc.a.deleteACL(ctx, x.ID); err != nil {
				if !platform.HasErrorCode(err, errALBACLNotFound) {
					return err
				}
				change.Action, change.Detail = platform.Unchanged, "already deleted"
			}
			return rt.RenderReport(platform.Report{Target: sc.target(), Changes: []platform.Change{change}})
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

// normalizeACLEntry writes an entry as ALB needs it: an IPv4 CIDR block.
// A bare IPv4 address becomes /32 (ALB refuses it without a mask); a block
// with host bits set is refused rather than changed, and so is IPv6 (ALB
// ACLs hold IPv4 entries only).
func normalizeACLEntry(v string) (string, error) {
	v = strings.TrimSpace(v)
	if a, err := netip.ParseAddr(v); err == nil {
		if !a.Is4() {
			return "", app.UsageErrf("%q: ALB ACLs hold IPv4 entries only", v)
		}
		return netip.PrefixFrom(a, 32).String(), nil
	}
	p, err := netip.ParsePrefix(v)
	if err != nil {
		return "", app.UsageErrf("%q is neither an IPv4 address nor an IPv4 CIDR block", v)
	}
	if !p.Addr().Is4() {
		return "", app.UsageErrf("%q: ALB ACLs hold IPv4 entries only", v)
	}
	if p.Masked() != p {
		return "", app.UsageErrf("%q has host bits set (did you mean %s?)", v, p.Masked())
	}
	return p.String(), nil
}

// normalizeACLEntries normalizes the entries given, dropping repeats.
func normalizeACLEntries(args []string) ([]string, error) {
	var out []string
	for _, a := range args {
		e, err := normalizeACLEntry(a)
		if err != nil {
			return nil, err
		}
		out = appendNew(out, e)
	}
	return out, nil
}

func chunk(list []string, n int) [][]string {
	var out [][]string
	for len(list) > n {
		out = append(out, list[:n])
		list = list[n:]
	}
	if len(list) > 0 {
		out = append(out, list)
	}
	return out
}

func albACLEntryAddCmd(rt *app.Runtime) *cobra.Command {
	var region, desc string
	cmd := &cobra.Command{
		Use:   "add <acl> <cidr>...",
		Short: "Add IPv4 entries to an ACL (present ones are unchanged)",
		Long: `Add entries (IPv4 addresses or CIDR blocks) to the ACL (name or id). A bare
address is written as /32; a block with host bits set and IPv6 are exit
code 2. Entries the ACL holds already are unchanged (ALB refuses a whole
batch that repeats one). The others are added 20 per call, waiting for the
ACL to be Available after each. A full ACL refuses the batch as a whole;
the message quotes the account's limit (500 entries by default).
--description is set on every entry added.`,
		Example: "  polyctl aliyun alb acl entry add office-allow 203.0.113.0/24 198.51.100.7 --description office",
		Args:    app.MinArgsOrInteractive(rt, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			sc, err := openALBScope(ctx, rt, region)
			if err != nil {
				return err
			}
			if args, err = aclArg(ctx, rt, sc, args, "<acl>"); err != nil {
				return err
			}
			if len(args) < 2 {
				typed, err := askCIDRs(rt)
				if err != nil {
					return err
				}
				args = append(args, typed...)
			}
			entries, err := normalizeACLEntries(args[1:])
			if err != nil {
				return err
			}
			x, err := resolveACL(ctx, sc, args[0])
			if err != nil {
				return err
			}
			have, err := sc.a.listACLEntries(ctx, x.ID)
			if err != nil {
				return err
			}
			present := map[string]bool{}
			for _, e := range have {
				present[e.Entry] = true
			}
			res := "acl/" + orID(x.Name, x.ID)
			var plan platform.Plan
			var missing []string
			for _, e := range entries {
				if present[e] {
					plan.Add(platform.Step{Resource: res + "/entry/" + e, Action: platform.Unchanged, Desc: e + " already in the ACL"})
				} else {
					missing = append(missing, e)
				}
			}
			for _, batch := range chunk(missing, albACLEntryBatch) {
				for i, e := range batch {
					step := platform.Step{Resource: res + "/entry/" + e, Action: platform.Created, Desc: e}
					if i == 0 {
						// The first step of a batch writes the whole batch.
						step.Apply = func(ctx context.Context) (platform.Change, error) {
							if err := settleACL(ctx, sc.a, x); err != nil {
								return platform.Change{}, err
							}
							list := make([]albACLEntry, 0, len(batch))
							for _, b := range batch {
								list = append(list, albACLEntry{Entry: b, Description: desc})
							}
							if err := sc.a.addACLEntries(ctx, x.ID, list); err != nil {
								return platform.Change{}, err
							}
							if err := waitACLAvailable(ctx, sc.a, x.ID); err != nil {
								return platform.Change{}, err
							}
							return platform.Change{}, nil
						}
					} else {
						step.Apply = func(ctx context.Context) (platform.Change, error) { return platform.Change{}, nil }
					}
					plan.Add(step)
				}
			}
			return rt.Ensure(ctx, "aliyun.alb.acl.entry.add", sc.target(), &plan)
		},
	}
	cmd.Flags().StringVar(&desc, "description", "", "description of the entries added")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

func albACLEntryRemoveCmd(rt *app.Runtime) *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:   "remove <acl> <cidr>...",
		Short: "Remove entries from an ACL (missing ones are unchanged)",
		Long: `Remove entries (IPv4 addresses or CIDR blocks, normalized like entry add: a bare
address is its /32) from the ACL (name or id). Entries the ACL does not hold
are unchanged. The others are removed 20 per call, waiting for the ACL to
be Available after each.`,
		Example: "  polyctl aliyun alb acl entry remove office-allow 198.51.100.7",
		Args:    app.MinArgsOrInteractive(rt, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			sc, err := openALBScope(ctx, rt, region)
			if err != nil {
				return err
			}
			if args, err = aclArg(ctx, rt, sc, args, "<acl>"); err != nil {
				return err
			}
			x, err := resolveACL(ctx, sc, args[0])
			if err != nil {
				return err
			}
			have, err := sc.a.listACLEntries(ctx, x.ID)
			if err != nil {
				return err
			}
			if len(args) < 2 {
				// The interactive flow offers the entries of the ACL.
				var opts []prompt.Option
				for _, e := range have {
					opts = append(opts, prompt.Option{Label: joinLabel(e.Entry, e.Description, e.Status), Value: e.Entry})
				}
				picked, err := rt.ChooseMany(app.Choice{Title: "Entries to remove from " + orID(x.Name, x.ID), Options: opts, Arg: "<cidr>...",
					Empty: app.NothingToDof("ACL %s has no entries", x.ID)})
				if err != nil {
					return err
				}
				args = append(args, picked...)
			}
			entries, err := normalizeACLEntries(args[1:])
			if err != nil {
				return err
			}
			present := map[string]bool{}
			for _, e := range have {
				present[e.Entry] = true
			}
			res := "acl/" + orID(x.Name, x.ID)
			var plan platform.Plan
			var gone []string
			for _, e := range entries {
				if present[e] {
					gone = append(gone, e)
				} else {
					plan.Add(platform.Step{Resource: res + "/entry/" + e, Action: platform.Unchanged, Desc: e + " not in the ACL"})
				}
			}
			for _, batch := range chunk(gone, albACLEntryBatch) {
				for i, e := range batch {
					step := platform.Step{Resource: res + "/entry/" + e, Action: platform.Deleted, Desc: e}
					if i == 0 {
						step.Apply = func(ctx context.Context) (platform.Change, error) {
							if err := settleACL(ctx, sc.a, x); err != nil {
								return platform.Change{}, err
							}
							if err := sc.a.removeACLEntries(ctx, x.ID, batch); err != nil {
								return platform.Change{}, err
							}
							if err := waitACLAvailable(ctx, sc.a, x.ID); err != nil {
								return platform.Change{}, err
							}
							return platform.Change{}, nil
						}
					} else {
						step.Apply = func(ctx context.Context) (platform.Change, error) { return platform.Change{}, nil }
					}
					plan.Add(step)
				}
			}
			return rt.Ensure(ctx, "aliyun.alb.acl.entry.remove", sc.target(), &plan)
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}
