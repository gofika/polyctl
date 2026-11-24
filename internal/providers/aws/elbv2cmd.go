package aws

import (
	"context"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// elbv2Cmd is `aws elbv2`: load balancers, target groups and listeners.
func elbv2Cmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "elbv2",
		Short: "Elastic Load Balancing v2: load balancers, target groups and listeners",
		Long: `Elastic Load Balancing v2 (Network and Application Load Balancers): load
balancers, their target groups and listeners, and load-balancer ensure, which
puts a Network Load Balancer in front of an EC2 instance in one command.

A load balancer is named by its name, its ARN or its DNS name. Names are
unique within an account and region only: without --region the inventory
tells which account (and region) holds it, synced once when it does not
know; several matches are ambiguous (exit code 5). Target groups and
listeners are looked up in the profile's region (--region, or the region of
an ARN).`,
	}
	lb := &cobra.Command{Use: "load-balancer", Short: "Load balancers (Network and Application)"}
	lb.AddCommand(lbListCmd(rt), lbGetCmd(rt), lbCreateCmd(rt), lbUpdateCmd(rt), lbDeleteCmd(rt), lbEnsureCmd(rt))
	tg := &cobra.Command{Use: "target-group", Short: "Target groups and their targets"}
	tg.AddCommand(tgListCmd(rt), tgGetCmd(rt), tgCreateCmd(rt), tgUpdateCmd(rt), tgDeleteCmd(rt))
	ls := &cobra.Command{Use: "listener", Short: "Listeners of a load balancer"}
	ls.AddCommand(listenerListCmd(rt), listenerGetCmd(rt), listenerCreateCmd(rt), listenerUpdateCmd(rt), listenerDeleteCmd(rt))
	cmd.AddCommand(lb, tg, ls)
	return cmd
}

// ------------------------------------------------------------ scopes

// lbScope is the account and region an elbv2 command works in.
type lbScope struct {
	c       *client
	profile string
	region  string
}

func (s *lbScope) target() platform.Target {
	return platform.Target{Platform: platform.AWS, Profile: s.profile, Region: s.region}
}

func (s *lbScope) where() string { return "aws/" + s.profile + "/" + s.region }

// openELBScope opens the account and region of a command: the region of an
// ARN ref (another --region is a usage error), else --region, else the
// profile's. The account of an ARN is the one whose inventory holds load
// balancers of that account id, unless --profile is given.
func openELBScope(ctx context.Context, rt *app.Runtime, region, ref string) (*lbScope, error) {
	if rt.Flags.Offline {
		return nil, app.ErrOffline
	}
	profile := ""
	if a, ok := parseELBARN(ref); ok {
		if region != "" && region != a.Region {
			return nil, app.UsageErrf("--region %s differs from the region of %s (%s)", region, ref, a.Region)
		}
		region = a.Region
		if rt.Flags.Profile == "" && a.Account != "" {
			profile = profileOfAccount(ctx, rt, a.Account)
		}
	}
	if profile == "" {
		var err error
		if profile, err = rt.ProfileFor(platform.AWS); err != nil {
			return nil, err
		}
	}
	c, err := openProfile(ctx, rt, profile)
	if err != nil {
		return nil, err
	}
	return &lbScope{c: c, profile: profile, region: c.regionOr(region)}, nil
}

// profileOfAccount returns the AWS profile whose cached load balancers
// belong to the account id, when exactly one does.
func profileOfAccount(ctx context.Context, rt *app.Runtime, account string) string {
	accounts, err := awsAccounts(rt)
	if err != nil || len(accounts) < 2 {
		return ""
	}
	db, err := rt.DB()
	if err != nil {
		return ""
	}
	var hits []string
	for _, a := range accounts {
		rows, err := db.List(ctx, inventory.Query{Platform: platform.AWS, Profile: a.Profile, Type: platform.ResLoadBalancer})
		if err != nil {
			return ""
		}
		for _, r := range rows {
			if arn, ok := parseELBARN(r.ID); ok && arn.Account == account {
				hits = append(hits, a.Profile)
				break
			}
		}
	}
	if len(hits) != 1 {
		return ""
	}
	return hits[0]
}

// lbCandidate is a load balancer found for a command.
type lbCandidate struct {
	s  *lbScope
	lb platform.LoadBalancer
}

// resolveLB finds the load balancer ref names: a name, an ARN or a DNS
// name. With --region, or for an ARN, the account is asked directly.
// Otherwise the inventory says which accounts hold it (the stale load
// balancer sets are synced once when none does); each hit is checked live.
// When nothing is found that way, every selected account is asked live in
// its region (the region of a DNS name when it holds one), and an account
// that cannot be asked is a warning. Several matches are ambiguous.
func resolveLB(ctx context.Context, rt *app.Runtime, ref, region string) (*lbScope, *platform.LoadBalancer, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, nil, app.UsageErrf("the load balancer name, ARN or DNS name is empty")
	}
	if rt.Flags.Offline {
		return nil, nil, app.ErrOffline
	}
	find := func(s *lbScope) (*platform.LoadBalancer, error) {
		if looksLikeDNSName(ref) {
			return s.c.FindLoadBalancerByDNS(ctx, s.region, ref)
		}
		return s.c.FindLoadBalancer(ctx, s.region, ref)
	}
	if region != "" || isELBARN(ref, "loadbalancer") {
		s, err := openELBScope(ctx, rt, region, ref)
		if err != nil {
			return nil, nil, err
		}
		lb, err := find(s)
		if err != nil {
			return nil, nil, err
		}
		if lb == nil {
			return nil, nil, fmt.Errorf("%w: load balancer %q in %s", platform.ErrNotFound, ref, s.where())
		}
		return s, lb, nil
	}
	accounts, err := awsAccounts(rt)
	if err != nil {
		return nil, nil, err
	}
	hits, err := lbInventoryHits(ctx, rt, accounts, ref)
	if err != nil {
		return nil, nil, err
	}
	var found []lbCandidate
	var failure error
	asked := map[string]bool{}
	ask := func(profile, region string) {
		c, err := openProfile(ctx, rt, profile)
		if err == nil {
			s := &lbScope{c: c, profile: profile, region: c.regionOr(region)}
			key := profile + "|" + s.region
			if asked[key] {
				return
			}
			asked[key] = true
			var lb *platform.LoadBalancer
			if lb, err = find(s); err == nil {
				if lb != nil {
					found = append(found, lbCandidate{s: s, lb: *lb})
				}
				return
			}
		}
		rt.Infof("warning: looking up load balancer %q in aws/%s: %v", ref, profile, err)
		if failure == nil {
			failure = fmt.Errorf("aws/%s: %w", profile, err)
		}
	}
	for _, h := range hits {
		ask(h.profile, h.region)
	}
	if len(found) == 0 {
		for _, a := range accounts {
			ask(a.Profile, dnsRegion(ref))
		}
	}
	switch len(found) {
	case 1:
		return found[0].s, &found[0].lb, nil
	case 0:
		if failure != nil {
			return nil, nil, fmt.Errorf("cannot tell where load balancer %q is: %w", ref, failure)
		}
		return nil, nil, fmt.Errorf("%w: load balancer %q in the selected AWS accounts (pass --region for a load balancer outside the profile's region)", platform.ErrNotFound, ref)
	}
	var names []string
	profiles := map[string]bool{}
	for _, f := range found {
		names = append(names, fmt.Sprintf("%s (%s)", f.s.where(), f.lb.ID))
		profiles[f.s.profile] = true
	}
	hint := "pass --profile <name> to choose"
	if len(profiles) == 1 {
		hint = "the account holds load balancers of this name in several regions; pass --region or the ARN"
	}
	amb := &app.AmbiguousError{What: fmt.Sprintf("load balancer %q", ref), Candidates: names, Hint: hint}
	// The interactive flow asks which one.
	f, err := disambiguate(rt, amb, found, func(f lbCandidate) string {
		return joinLabel(f.lb.Name, f.lb.Type, f.lb.Scheme, f.lb.State, f.lb.VPC, f.lb.DNSName, f.s.where())
	})
	if err != nil {
		return nil, nil, err
	}
	return f.s, &f.lb, nil
}

// lbInventoryHits returns the accounts and regions whose cached load
// balancers include ref by name, ARN or DNS name. When none does, the
// stale load balancer sets are synced once and the lookup is repeated.
func lbInventoryHits(ctx context.Context, rt *app.Runtime, accounts []config.AccountRef, ref string) ([]inventoryHit, error) {
	db, err := rt.DB()
	if err != nil {
		return nil, err
	}
	lookup := func() ([]inventoryHit, error) {
		var out []inventoryHit
		for _, a := range accounts {
			rows, err := db.List(ctx, inventory.Query{Platform: platform.AWS, Profile: a.Profile, Type: platform.ResLoadBalancer})
			if err != nil {
				return nil, err
			}
			for _, r := range rows {
				var l loadBalancer
				_ = r.Decode(&l)
				if r.ID == ref || r.Name == ref || l.DNSName != "" && normalizeDNS(l.DNSName) == normalizeDNS(ref) {
					out = append(out, inventoryHit{profile: a.Profile, region: l.Region})
				}
			}
		}
		return out, nil
	}
	hits, err := lookup()
	if err != nil || len(hits) > 0 {
		return hits, err
	}
	var stale []config.AccountRef
	for _, a := range accounts {
		st, err := db.GetState(ctx, inventory.Set{Platform: a.Platform, Profile: a.Profile, Type: platform.ResLoadBalancer})
		if err != nil {
			return nil, err
		}
		if rt.Flags.Refresh || !st.Fresh(time.Now()) {
			stale = append(stale, a)
		}
	}
	if len(stale) == 0 {
		return nil, nil
	}
	rt.Infof("looking up load balancer %q: syncing the load balancers of %d account(s)...", ref, len(stale))
	for _, a := range stale {
		reps, err := rt.SyncAccount(ctx, a, []platform.ResourceType{platform.ResLoadBalancer})
		if err == nil {
			for _, r := range reps {
				if r.Err != nil {
					err = r.Err
					break
				}
			}
		}
		if err != nil {
			// The live lookup that follows asks the account again.
			rt.Infof("warning: sync %s: %v", a.Label(), err)
		}
	}
	return lookup()
}

// storeLB writes a load balancer to the inventory. The addresses the
// inventory holds for it (found through its network interfaces by a sync)
// are kept unless ips replaces them.
func storeLB(ctx context.Context, rt *app.Runtime, profile string, lb platform.LoadBalancer, ips []string) {
	if lb.ID == "" || lb.ID == platform.Pending {
		return
	}
	db, err := rt.DB()
	if err != nil {
		return
	}
	set := inventory.Set{Platform: platform.AWS, Profile: profile, Type: platform.ResLoadBalancer}
	l := loadBalancer{ARN: lb.ID, Name: lb.Name, Type: lb.Type, Scheme: lb.Scheme, State: lb.State, DNSName: lb.DNSName, VpcID: lb.VPC,
		Region: lb.Region, Zones: lb.ZoneNames()}
	if rows, err := db.List(ctx, inventory.Query{Platform: platform.AWS, Profile: profile, Type: platform.ResLoadBalancer}); err == nil {
		for _, r := range rows {
			if r.ID == lb.ID {
				var old loadBalancer
				if r.Decode(&old) == nil {
					l.Private, l.Public, l.Interfaces = old.Private, old.Public, old.Interfaces
				}
			}
		}
	}
	for _, z := range lb.Zones {
		ips = append(ips, z.Addresses...)
	}
	if len(ips) > 0 {
		if lb.Scheme == "internal" {
			l.Private = appendNew(l.Private, ips...)
		} else {
			l.Public = appendNew(l.Public, ips...)
		}
	}
	cfg, _ := rt.Config()
	_ = db.Upsert(ctx, set, l.resource(), cfg.TTLFor(platform.ResLoadBalancer))
}

// dropLB removes a load balancer from the inventory.
func dropLB(ctx context.Context, rt *app.Runtime, profile, id string) {
	if db, err := rt.DB(); err == nil {
		_ = db.Delete(ctx, inventory.Set{Platform: platform.AWS, Profile: profile, Type: platform.ResLoadBalancer}, platform.ResLoadBalancer, id)
	}
}

// elbTagsFor are the tags of a new load balancer or target group:
// polyctl:managed=true, then defaults.aws.tags (which may override it).
func elbTagsFor(rt *app.Runtime, profile string) (map[string]string, error) {
	tags, err := keyPairTags(rt, profile)
	if err != nil {
		return nil, err
	}
	out := map[string]string{"polyctl:managed": "true"}
	for k, v := range tags {
		out[k] = v
	}
	return out, nil
}

// ---------------------------------------------------------- flag values

// LB types, schemes and IP address types the commands accept.
var (
	lbTypes          = []string{"network", "application"}
	lbSchemes        = []string{"internet-facing", "internal"}
	lbIPAddressTypes = []string{"ipv4", "dualstack"}
	elbProtocols     = []string{"TCP", "TLS", "UDP", "TCP_UDP", "HTTP", "HTTPS"}
	tgTargetTypes    = []string{"instance", "ip"}
	healthProtocols  = []string{"TCP", "HTTP", "HTTPS"}
)

// oneOf checks a flag value against the accepted ones (case-insensitive)
// and returns it in their spelling.
func oneOf(flag, v string, valid []string) (string, error) {
	for _, x := range valid {
		if strings.EqualFold(x, strings.TrimSpace(v)) {
			return x, nil
		}
	}
	return "", app.UsageErrf("--%s %q: expected one of %s", flag, v, strings.Join(valid, ", "))
}

// checkPort checks a --port value.
func checkPort(flag string, p int) error {
	if p < 1 || p > 65535 {
		return app.UsageErrf("--%s %d: expected a port between 1 and 65535", flag, p)
	}
	return nil
}

// checkSGIDs refuses empty security group ids.
func checkSGIDs(ids []string) error {
	for _, id := range ids {
		if !looksLikeGroupID(id) {
			return app.UsageErrf("--sg %q: expected a security group id (sg-...)", id)
		}
	}
	return nil
}

// checkSubnetIDs refuses values that are no subnet ids.
func checkSubnetIDs(ids []string) error {
	for _, id := range ids {
		if !strings.HasPrefix(id, "subnet-") || len(id) < 8 {
			return app.UsageErrf("--subnet %q: expected a subnet id (subnet-...)", id)
		}
	}
	return nil
}

// sameSet reports whether two lists hold the same values, in any order.
func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}

func joinOrNone(list []string) string { return orNone(strings.Join(list, ", ")) }

// ---------------------------------------------------------------- list

// lbRow is a load balancer of a list, live or from the inventory.
type lbRow struct {
	Name    string `json:"name" yaml:"name"`
	ARN     string `json:"arn" yaml:"arn"`
	Type    string `json:"type" yaml:"type"`
	Scheme  string `json:"scheme" yaml:"scheme"`
	State   string `json:"state" yaml:"state"`
	VPC     string `json:"vpc_id" yaml:"vpc_id"`
	DNSName string `json:"dns_name" yaml:"dns_name"`
	Region  string `json:"region" yaml:"region"`
}

func lbListGrid(rows []lbRow) output.Grid {
	g := output.Grid{Headers: []string{"NAME", "TYPE", "SCHEME", "STATE", "VPC", "DNS"}, Empty: "no load balancers"}
	for _, r := range rows {
		g.Rows = append(g.Rows, []string{r.Name, r.Type, r.Scheme, r.State, r.VPC, r.DNSName})
	}
	return g
}

func lbListCmd(rt *app.Runtime) *cobra.Command {
	var typ, name, region string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List load balancers (the inventory caches every region)",
		Long: `List the load balancers of the profile's region. The local inventory holds those
of every enabled region; --region asks AWS about another region directly.
--type keeps network or application load balancers, --name the names that
match a pattern (* and ? are wildcards; without them, the exact name).`,
		Example: "  polyctl aws elbv2 load-balancer list --type network\n  polyctl aws elbv2 load-balancer list --name 'site-*' --region ap-east-1 -o json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if typ != "" {
				var err error
				if typ, err = oneOf("type", typ, lbTypes); err != nil {
					return err
				}
			}
			if name != "" {
				if _, err := path.Match(name, ""); err != nil {
					return app.UsageErrf("--name %q: %v", name, err)
				}
			}
			var rows []lbRow
			var where string
			if region != "" {
				if rt.Flags.Offline {
					return app.ErrOffline
				}
				s, err := openELBScope(ctx, rt, region, "")
				if err != nil {
					return err
				}
				where = s.where()
				lbs, err := s.c.ListLoadBalancers(ctx, s.region)
				if err != nil {
					return err
				}
				for _, l := range lbs {
					rows = append(rows, lbRow{Name: l.Name, ARN: l.ID, Type: l.Type, Scheme: l.Scheme, State: l.State, VPC: l.VPC, DNSName: l.DNSName, Region: l.Region})
				}
			} else {
				profName, err := rt.ProfileFor(platform.AWS)
				if err != nil {
					return err
				}
				set := inventory.Set{Platform: platform.AWS, Profile: profName, Type: platform.ResLoadBalancer}
				listRegion := ""
				invRows, cached, err := rt.EnsureSet(ctx, set, func(ctx context.Context) ([]platform.Resource, error) {
					c, _, err := openClient(ctx, rt)
					if err != nil {
						return nil, err
					}
					listRegion = c.region
					return c.Sync(ctx, platform.ResLoadBalancer)
				})
				if err != nil {
					return err
				}
				if listRegion == "" {
					listRegion = profileRegion(rt, profName)
				}
				where = "aws/" + profName
				if listRegion != "" {
					where += "/" + listRegion
				}
				for _, r := range invRows {
					var l loadBalancer
					if err := r.Decode(&l); err != nil {
						return fmt.Errorf("decode cached load balancer %s: %w", r.ID, err)
					}
					if listRegion != "" && l.Region != "" && l.Region != listRegion {
						continue
					}
					rows = append(rows, lbRow{Name: l.Name, ARN: l.ARN, Type: l.Type, Scheme: l.Scheme, State: l.State, VPC: l.VpcID, DNSName: l.DNSName, Region: l.Region})
				}
				if cached {
					rt.Infof("load balancers via %s (local inventory)", where)
				}
			}
			kept := rows[:0]
			for _, r := range rows {
				if typ != "" && r.Type != typ {
					continue
				}
				if name != "" {
					if ok, _ := path.Match(name, r.Name); !ok {
						continue
					}
				}
				kept = append(kept, r)
			}
			rows = kept
			slices.SortFunc(rows, func(a, b lbRow) int { return strings.Compare(a.Name+"|"+a.ARN, b.Name+"|"+b.ARN) })
			if len(rows) == 0 {
				rows = []lbRow{}
				rt.Infof("no load balancers via %s", where)
			}
			return rt.Render(rows, func() output.Grid { return lbListGrid(rows) })
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "only load balancers of this type (network or application)")
	cmd.Flags().StringVar(&name, "name", "", "only load balancers whose name matches (* and ? are wildcards)")
	cmd.Flags().StringVar(&region, "region", "", "list another region (asks AWS, bypassing the local inventory)")
	return cmd
}

// ----------------------------------------------------------------- get

// lbListenerView is a listener in the output of load-balancer get and
// listener list / get.
type lbListenerView struct {
	ARN           string   `json:"arn" yaml:"arn"`
	Port          int32    `json:"port" yaml:"port"`
	Protocol      string   `json:"protocol" yaml:"protocol"`
	DefaultAction string   `json:"default_action" yaml:"default_action"`
	TargetGroups  []string `json:"target_groups" yaml:"target_groups"`
	Certificates  []string `json:"certificates" yaml:"certificates"`
	LoadBalancer  string   `json:"load_balancer" yaml:"load_balancer"`
}

func listenerView(l platform.LBListener) lbListenerView {
	v := lbListenerView{ARN: l.ID, Port: l.Port, Protocol: l.Protocol, DefaultAction: l.DefaultAction, TargetGroups: []string{},
		Certificates: l.Certificates, LoadBalancer: arnName(l.LoadBalancer)}
	for _, tg := range l.TargetGroups {
		v.TargetGroups = append(v.TargetGroups, arnName(tg))
	}
	if v.Certificates == nil {
		v.Certificates = []string{}
	}
	return v
}

// tgView is a target group with its targets.
type tgView struct {
	platform.LBTargetGroup `yaml:",inline"`
	Profile                string              `json:"profile" yaml:"profile"`
	Targets                []platform.LBTarget `json:"targets" yaml:"targets"`
}

// lbDetail is the output of load-balancer get.
type lbDetail struct {
	platform.LoadBalancer `yaml:",inline"`
	Profile               string           `json:"profile" yaml:"profile"`
	DeletionProtection    bool             `json:"deletion_protection" yaml:"deletion_protection"`
	CrossZone             bool             `json:"cross_zone" yaml:"cross_zone"`
	Listeners             []lbListenerView `json:"listeners" yaml:"listeners"`
	TargetGroups          []tgView         `json:"target_groups" yaml:"target_groups"`
}

func targetRows(g *output.Grid, targets []platform.LBTarget) {
	if len(targets) == 0 {
		g.Rows = append(g.Rows, []string{"    (no targets)"})
		return
	}
	for _, t := range targets {
		state := t.State
		if t.Reason != "" {
			state += " (" + t.Reason + ")"
		}
		g.Rows = append(g.Rows, []string{"    " + platform.LBTargetSpec{ID: t.ID, Port: t.Port}.String(), t.Zone, state})
	}
}

func lbDetailGrid(d lbDetail) output.Grid {
	sgs := joinOrNone(d.SecurityGroups)
	if len(d.SecurityGroups) == 0 && d.Type == "network" {
		sgs = "none (created without security groups: none can be added)"
	}
	var zones []string
	for _, z := range d.Zones {
		zones = append(zones, z.Zone+" "+z.Subnet)
	}
	g := output.Grid{Rows: [][]string{
		{"NAME", d.Name, "TYPE", d.Type},
		{"SCHEME", d.Scheme, "STATE", d.State},
		{"PROFILE", d.Profile, "REGION", d.Region},
		{"VPC", d.VPC, "IP TYPE", d.IPAddressType},
		{"DNS", d.DNSName},
		{"ARN", d.ID},
		{"ZONES", joinOrNone(zones)},
		{"SECURITY GROUPS", sgs},
		{"DELETION PROTECTION", strconv.FormatBool(d.DeletionProtection), "CROSS ZONE", strconv.FormatBool(d.CrossZone)},
		{"LISTENERS"},
	}}
	if len(d.Listeners) == 0 {
		g.Rows = append(g.Rows, []string{"  (none)"})
	}
	for _, l := range d.Listeners {
		to := l.DefaultAction
		if len(l.TargetGroups) > 0 {
			to = strings.Join(l.TargetGroups, ", ")
		}
		g.Rows = append(g.Rows, []string{fmt.Sprintf("  %s:%d", strings.ToLower(l.Protocol), l.Port), "-> " + to})
	}
	g.Rows = append(g.Rows, []string{"TARGET GROUPS"})
	if len(d.TargetGroups) == 0 {
		g.Rows = append(g.Rows, []string{"  (none)"})
	}
	for _, tg := range d.TargetGroups {
		g.Rows = append(g.Rows, []string{"  " + tg.Name, fmt.Sprintf("%s/%d", strings.ToLower(tg.Protocol), tg.Port), tg.TargetType})
		targetRows(&g, tg.Targets)
	}
	return g
}

// targetGroupsOf returns the target groups of a load balancer with their
// targets.
func targetGroupsOf(ctx context.Context, s *lbScope, lbID string) ([]tgView, error) {
	tgs, err := s.c.ListTargetGroups(ctx, s.region, lbID)
	if err != nil {
		return nil, err
	}
	out := []tgView{}
	for _, tg := range tgs {
		targets, err := s.c.TargetHealth(ctx, s.region, tg.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, tgView{LBTargetGroup: tg, Profile: s.profile, Targets: targets})
	}
	return out, nil
}

func lbGetCmd(rt *app.Runtime) *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:   "get <name|arn|dns-name>",
		Short: "Show a load balancer, its listeners, target groups and target health",
		Long: `Show a load balancer with its attributes, its listeners and the target groups
attached to it, with the health of every target (healthy, unhealthy,
initial, draining, unused, unavailable). The load balancer is named by its
name, ARN or DNS name.`,
		Example: "  polyctl aws elbv2 load-balancer get site-xz7-lb -o json\n  polyctl aws elbv2 load-balancer get site-xz7-lb-0123456789abcdef.elb.ap-east-1.amazonaws.com",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			args, err := lbArg(ctx, rt, args, "<name|arn|dns-name>", region, "AWS load balancer", false, nil)
			if err != nil {
				return err
			}
			s, lb, err := resolveLB(ctx, rt, args[0], region)
			if err != nil {
				return err
			}
			storeLB(ctx, rt, s.profile, *lb, nil)
			d := lbDetail{LoadBalancer: *lb, Profile: s.profile, Listeners: []lbListenerView{}}
			attrs, err := s.c.LoadBalancerAttributes(ctx, s.region, lb.ID)
			if err != nil {
				return err
			}
			d.DeletionProtection, d.CrossZone = attrs.DeletionProtection, attrs.CrossZone
			listeners, err := s.c.ListListeners(ctx, s.region, lb.ID)
			if err != nil {
				return err
			}
			for _, l := range listeners {
				d.Listeners = append(d.Listeners, listenerView(l))
			}
			if d.TargetGroups, err = targetGroupsOf(ctx, s, lb.ID); err != nil {
				return err
			}
			return rt.Render(d, func() output.Grid { return lbDetailGrid(d) })
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region of the load balancer (asks the profile's account there directly)")
	return cmd
}

// -------------------------------------------------------------- create

func lbCreateCmd(rt *app.Runtime) *cobra.Command {
	var typ, scheme, ipType, region string
	var subnets, sgs []string
	var wf app.WaitFlags
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a load balancer",
		Long: `Create the load balancer <name> of --type network or application in the
--subnet subnets (one per availability zone; required). --scheme is
internet-facing (default) or internal, --ip-address-type ipv4 (default) or
dualstack. --sg attaches security groups; without any the request carries
none, and a Network Load Balancer created without security groups can never
get any. A load balancer of that name in the region is an error (exit code
1): use ensure. The load balancer is tagged polyctl:managed=true and with the
tags of defaults.aws.tags. --wait waits until it is active.`,
		Example: "  polyctl aws elbv2 load-balancer create site-lb --type network --subnet subnet-0abc --sg sg-0123456789abcdef0 --wait",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name := app.Arg(args, 0)
			if name != "" {
				if err := checkELBName("load balancer", name, true); err != nil {
					return err
				}
			}
			if typ == "" && !rt.Interactive() {
				return app.UsageErrf("--type is required (network or application)")
			}
			var err error
			if typ != "" {
				if typ, err = oneOf("type", typ, lbTypes); err != nil {
					return err
				}
			}
			if scheme, err = oneOf("scheme", scheme, lbSchemes); err != nil {
				return err
			}
			if ipType, err = oneOf("ip-address-type", ipType, lbIPAddressTypes); err != nil {
				return err
			}
			if len(subnets) == 0 && !rt.Interactive() {
				return app.UsageErrf("--subnet is required (one subnet per availability zone)")
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
			s, err := openELBScope(ctx, rt, region, "")
			if err != nil {
				return err
			}
			if err := askLBCreate(ctx, rt, s, &name, &typ, &subnets, &sgs, cmd.Flags().Changed("sg")); err != nil {
				return err
			}
			if lb, err := s.c.FindLoadBalancer(ctx, s.region, name); err != nil {
				return err
			} else if lb != nil {
				return fmt.Errorf("load balancer %q already exists in %s (%s): use `polyctl aws elbv2 load-balancer ensure` to reuse it", name, s.where(), lb.ID)
			}
			var tags map[string]string
			if !rt.DryRun() {
				if tags, err = elbTagsFor(rt, s.profile); err != nil {
					return err
				}
			}
			desc := fmt.Sprintf("%s %s, subnets %s, security groups %s", typ, scheme, strings.Join(subnets, ","), joinOrNone(sgs))
			var plan platform.Plan
			plan.Add(platform.Step{Resource: "load-balancer/" + name, Action: platform.Created, Desc: desc,
				Apply: func(ctx context.Context) (platform.Change, error) {
					lb, err := s.c.CreateLoadBalancer(ctx, platform.LoadBalancerSpec{Region: s.region, Name: name, Type: typ, Scheme: scheme,
						Subnets: subnets, IPAddressType: ipType, SecurityGroups: sgs, Tags: tags})
					if err != nil {
						return platform.Change{}, err
					}
					storeLB(ctx, rt, s.profile, lb, nil)
					detail := fmt.Sprintf("%s %s, %s", typ, scheme, lb.DNSName)
					if wait {
						rt.Infof("waiting for load balancer %s to become active (up to %s)...", name, timeout)
						if lb, err = s.c.waitLoadBalancerActive(ctx, s.region, lb.ID, name, timeout); err != nil {
							return platform.Change{ID: lb.ID}, err
						}
						storeLB(ctx, rt, s.profile, lb, nil)
						detail += ", active"
					}
					return platform.Change{ID: lb.ID, Detail: detail}, nil
				}})
			return rt.Ensure(ctx, "aws.elbv2.load-balancer.create", s.target(), &plan)
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "network or application (required)")
	cmd.Flags().StringVar(&scheme, "scheme", "internet-facing", "internet-facing or internal")
	cmd.Flags().StringArrayVar(&subnets, "subnet", nil, "subnet id, one per availability zone (repeatable, required)")
	cmd.Flags().StringArrayVar(&sgs, "sg", nil, "security group id (repeatable)")
	cmd.Flags().StringVar(&ipType, "ip-address-type", "ipv4", "ipv4 or dualstack")
	cmd.Flags().StringVar(&region, "region", "", "region of the load balancer (default: the profile's region)")
	app.AddWaitFlags(cmd, &wf, false, app.DefaultWaitTimeout)
	return cmd
}

// -------------------------------------------------------------- update

func lbUpdateCmd(rt *app.Runtime) *cobra.Command {
	var sgs, subnets []string
	var ipType, region string
	var deletionProtection, crossZone bool
	cmd := &cobra.Command{
		Use:   "update <name|arn>",
		Short: "Change the security groups, subnets, IP address type or attributes of a load balancer",
		Long: `Change what the flags name, each only when it differs (otherwise it is
reported unchanged): --sg replaces the security groups (a Network Load
Balancer created without security groups can never get any: exit code 1;
the list cannot be emptied), --subnet replaces the subnets, --ip-address-type
sets ipv4 or dualstack (dualstack needs subnets with an IPv6 block),
--deletion-protection[=false] and --cross-zone[=false] set the attributes.`,
		Example: "  polyctl aws elbv2 load-balancer update site-xz7-lb --deletion-protection\n  polyctl aws elbv2 load-balancer update site-xz7-lb --cross-zone=false --sg sg-0123456789abcdef0",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			fl := cmd.Flags()
			changed := map[string]bool{}
			for _, f := range []string{"sg", "subnet", "ip-address-type", "deletion-protection", "cross-zone"} {
				changed[f] = fl.Changed(f)
			}
			nothing := !changed["sg"] && !changed["subnet"] && !changed["ip-address-type"] && !changed["deletion-protection"] && !changed["cross-zone"]
			if nothing && !rt.Interactive() {
				return app.UsageErrf("nothing to update: pass --sg, --subnet, --ip-address-type, --deletion-protection or --cross-zone")
			}
			args, err := lbArg(ctx, rt, args, "<name|arn>", region, "AWS load balancer", false, nil)
			if err != nil {
				return err
			}
			if fl.Changed("sg") {
				if err := checkSGIDs(sgs); err != nil {
					return err
				}
			}
			if fl.Changed("subnet") {
				if err := checkSubnetIDs(subnets); err != nil {
					return err
				}
			}
			if fl.Changed("ip-address-type") {
				var err error
				if ipType, err = oneOf("ip-address-type", ipType, lbIPAddressTypes); err != nil {
					return err
				}
			}
			s, lb, err := resolveLB(ctx, rt, args[0], region)
			if err != nil {
				return err
			}
			if nothing {
				// The interactive flow: what to change, then its value.
				u := lbUpdateAnswers{sgs: &sgs, subnets: &subnets, ipType: &ipType, deletionProtection: &deletionProtection, crossZone: &crossZone}
				key, err := askLBUpdate(ctx, rt, s, lb, u)
				if err != nil {
					return err
				}
				changed[key] = true
			}
			if changed["sg"] && len(lb.SecurityGroups) == 0 && lb.Type == "network" {
				return fmt.Errorf("load balancer %s is a Network Load Balancer created without security groups: AWS cannot add any to it (InvalidConfigurationRequest); delete it and create it again with --sg", lb.Name)
			}
			res := "load-balancer/" + lb.Name
			var plan platform.Plan
			if changed["sg"] {
				if sameSet(sgs, lb.SecurityGroups) {
					plan.Add(platform.Step{Resource: res + "/security-groups", Desc: strings.Join(lb.SecurityGroups, ",")})
				} else {
					plan.Add(platform.Step{Resource: res + "/security-groups", Action: platform.Updated, ID: lb.ID,
						Desc: joinOrNone(lb.SecurityGroups) + " -> " + strings.Join(sgs, ","),
						Apply: func(ctx context.Context) (platform.Change, error) {
							return platform.Change{}, s.c.SetLoadBalancerSecurityGroups(ctx, s.region, lb.ID, sgs)
						}})
				}
			}
			if changed["subnet"] {
				if sameSet(subnets, lb.Subnets()) {
					plan.Add(platform.Step{Resource: res + "/subnets", Desc: strings.Join(lb.Subnets(), ",")})
				} else {
					plan.Add(platform.Step{Resource: res + "/subnets", Action: platform.Updated, ID: lb.ID,
						Desc: joinOrNone(lb.Subnets()) + " -> " + strings.Join(subnets, ","),
						Apply: func(ctx context.Context) (platform.Change, error) {
							return platform.Change{}, s.c.SetLoadBalancerSubnets(ctx, s.region, lb.ID, subnets)
						}})
				}
			}
			if changed["ip-address-type"] {
				if ipType == lb.IPAddressType {
					plan.Add(platform.Step{Resource: res + "/ip-address-type", Desc: ipType})
				} else {
					plan.Add(platform.Step{Resource: res + "/ip-address-type", Action: platform.Updated, ID: lb.ID, Desc: lb.IPAddressType + " -> " + ipType,
						Apply: func(ctx context.Context) (platform.Change, error) {
							return platform.Change{}, s.c.SetLoadBalancerIPAddressType(ctx, s.region, lb.ID, ipType)
						}})
				}
			}
			if changed["deletion-protection"] || changed["cross-zone"] {
				attrs, err := s.c.LoadBalancerAttributes(ctx, s.region, lb.ID)
				if err != nil {
					return err
				}
				attr := func(key string, have, want bool, set func(*platform.LoadBalancerAttributeChange, *bool)) {
					if have == want {
						plan.Add(platform.Step{Resource: res + "/" + key, Desc: strconv.FormatBool(want)})
						return
					}
					plan.Add(platform.Step{Resource: res + "/" + key, Action: platform.Updated, ID: lb.ID, Desc: fmt.Sprintf("%t -> %t", have, want),
						Apply: func(ctx context.Context) (platform.Change, error) {
							var ch platform.LoadBalancerAttributeChange
							v := want
							set(&ch, &v)
							return platform.Change{}, s.c.ModifyLoadBalancerAttributes(ctx, s.region, lb.ID, ch)
						}})
				}
				if changed["deletion-protection"] {
					attr("deletion-protection", attrs.DeletionProtection, deletionProtection, func(c *platform.LoadBalancerAttributeChange, v *bool) { c.DeletionProtection = v })
				}
				if changed["cross-zone"] {
					attr("cross-zone", attrs.CrossZone, crossZone, func(c *platform.LoadBalancerAttributeChange, v *bool) { c.CrossZone = v })
				}
			}
			err = rt.Ensure(ctx, "aws.elbv2.load-balancer.update", s.target(), &plan)
			if err == nil && !rt.DryRun() {
				if again, ferr := s.c.FindLoadBalancer(ctx, s.region, lb.ID); ferr == nil && again != nil {
					storeLB(ctx, rt, s.profile, *again, nil)
				}
			}
			return err
		},
	}
	cmd.Flags().StringArrayVar(&sgs, "sg", nil, "security group id; the list replaces the current one (repeatable)")
	cmd.Flags().StringArrayVar(&subnets, "subnet", nil, "subnet id; the list replaces the current one (repeatable)")
	cmd.Flags().StringVar(&ipType, "ip-address-type", "", "ipv4 or dualstack")
	cmd.Flags().BoolVar(&deletionProtection, "deletion-protection", false, "turn deletion protection on (--deletion-protection=false turns it off)")
	cmd.Flags().BoolVar(&crossZone, "cross-zone", false, "turn cross-zone load balancing on (--cross-zone=false turns it off)")
	cmd.Flags().StringVar(&region, "region", "", "region of the load balancer (asks the profile's account there directly)")
	return cmd
}

// -------------------------------------------------------------- delete

func lbDeleteCmd(rt *app.Runtime) *cobra.Command {
	var region string
	var cascade bool
	var wf app.WaitFlags
	cmd := &cobra.Command{
		Use:   "delete <name|arn>",
		Short: "Delete a load balancer (asks first); --cascade also deletes its target groups",
		Long: `Delete a load balancer. Its name, type, listeners and target groups are shown
first, then a confirmation is asked (default no; --yes skips it, and the
non-interactive flow needs --yes). The listeners go with the load balancer;
the target groups stay unless --cascade, which deletes them afterwards
(retrying for up to a minute while AWS still reports them in use; one that
another load balancer still uses is skipped with a warning, at once when
AWS lists that load balancer on the group). Deletion
protection is exit code 1: turn it off first with
update --deletion-protection=false (polyctl never does it for you). --wait
waits until the load balancer is no longer listed.`,
		Example: "  polyctl aws elbv2 load-balancer delete site-xz7-lb --cascade --yes",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			wait, timeout, err := wf.Resolve(cmd)
			if err != nil {
				return err
			}
			if args, err = lbArg(ctx, rt, args, "<name|arn>", region, "AWS load balancer", false, nil); err != nil {
				return err
			}
			s, lb, err := resolveLB(ctx, rt, args[0], region)
			if err != nil {
				return err
			}
			listeners, err := s.c.ListListeners(ctx, s.region, lb.ID)
			if err != nil {
				return err
			}
			tgs, err := s.c.ListTargetGroups(ctx, s.region, lb.ID)
			if err != nil {
				return err
			}
			var tgNames []string
			for _, tg := range tgs {
				tgNames = append(tgNames, tg.Name)
			}
			rt.Infof("load balancer %s in %s", lb.Name, s.where())
			rt.Infof("  type           %s %s", lb.Type, lb.Scheme)
			rt.Infof("  dns            %s", lb.DNSName)
			rt.Infof("  listeners      %d (deleted with it)", len(listeners))
			if cascade {
				rt.Infof("  target groups  %s (deleted too: --cascade)", joinOrNone(tgNames))
			} else {
				rt.Infof("  target groups  %s (kept; --cascade deletes them)", joinOrNone(tgNames))
			}
			change := platform.Change{Resource: "load-balancer/" + lb.Name, Action: platform.Deleted, ID: lb.ID}
			changes := []platform.Change{change}
			if cascade {
				for _, tg := range tgs {
					changes = append(changes, cascadeTGChange(tg, lb.ID))
				}
			}
			if done, err := rt.WouldWrite(s.target(), changes...); done || err != nil {
				return err
			}
			what := fmt.Sprintf("Delete load balancer %s", lb.Name)
			if n := len(changes) - 1; cascade && n > 0 {
				for _, c := range changes[1:] {
					if c.Action == platform.Skipped {
						n--
					}
				}
				if n > 0 {
					what += fmt.Sprintf(" and its %d target group(s)", n)
				}
			}
			ok, err := rt.Confirm(ctx, what+"?", false)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("%w: cancelled; load balancer %s was not deleted", platform.ErrNothingToDo, lb.Name)
			}
			rep := platform.Report{Target: s.target()}
			if err := s.c.DeleteLoadBalancer(ctx, s.region, lb.ID); err != nil {
				if platform.HasErrorCode(err, errOperationNotAllowed) {
					err = fmt.Errorf("load balancer %s has deletion protection: turn it off with `polyctl aws elbv2 load-balancer update %s --deletion-protection=false` and delete it again: %w", lb.Name, lb.Name, err)
				}
				rep.Changes = append(rep.Changes, platform.Change{Resource: change.Resource, Action: platform.Failed, ID: lb.ID, Detail: err.Error()})
				_ = rt.RenderReport(rep)
				return err
			}
			dropLB(ctx, rt, s.profile, lb.ID)
			if wait {
				rt.Infof("waiting for load balancer %s to be deleted (up to %s)...", lb.Name, timeout)
				if err := s.c.waitLoadBalancerGone(ctx, s.region, lb.ID, lb.Name, timeout); err != nil {
					rep.Changes = append(rep.Changes, platform.Change{Resource: change.Resource, Action: platform.Failed, ID: lb.ID, Detail: err.Error()})
					_ = rt.RenderReport(rep)
					return err
				}
			}
			rep.Changes = append(rep.Changes, change)
			var failed error
			if cascade {
				for _, tg := range tgs {
					if ch := cascadeTGChange(tg, lb.ID); ch.Action == platform.Skipped {
						rt.Infof("warning: target group %s was kept: %s", tg.Name, ch.Detail)
						rep.Changes = append(rep.Changes, ch)
						continue
					}
					ch := deleteTGAfterLB(ctx, rt, s, tg)
					if ch.Action == platform.Failed && failed == nil {
						failed = fmt.Errorf("target group %s was not deleted: %s", tg.Name, ch.Detail)
					}
					rep.Changes = append(rep.Changes, ch)
				}
			}
			if err := rt.RenderReport(rep); err != nil {
				return err
			}
			return failed
		},
	}
	cmd.Flags().BoolVar(&cascade, "cascade", false, "also delete the target groups of the load balancer")
	cmd.Flags().StringVar(&region, "region", "", "region of the load balancer (asks the profile's account there directly)")
	app.AddWaitFlags(cmd, &wf, false, app.DefaultWaitTimeout)
	return cmd
}

// cascadeTGChange is what delete --cascade does to a target group of the
// load balancer lbID: deleted, or skipped at once when the listeners or
// rules of another load balancer forward to it too (AWS would refuse it as
// in use for as long as they do, so retrying is pointless).
func cascadeTGChange(tg platform.LBTargetGroup, lbID string) platform.Change {
	ch := platform.Change{Resource: "target-group/" + tg.Name, Action: platform.Deleted, ID: tg.ID}
	var others []string
	for _, arn := range tg.LoadBalancers {
		if arn != lbID {
			others = append(others, arnName(arn))
		}
	}
	if len(others) > 0 {
		ch.Action, ch.Detail = platform.Skipped, "still in use by load balancer "+strings.Join(others, ", ")
	}
	return ch
}

// deleteTGAfterLB deletes a target group of a load balancer that was just
// deleted, retrying while AWS still reports it in use (every 5 seconds, a
// minute at most). One still in use then (another load balancer forwards
// to it) is skipped with a warning.
func deleteTGAfterLB(ctx context.Context, rt *app.Runtime, s *lbScope, tg platform.LBTargetGroup) platform.Change {
	ch := platform.Change{Resource: "target-group/" + tg.Name, Action: platform.Deleted, ID: tg.ID}
	err := platform.Retry(ctx, platform.RetryPolicy{Codes: []string{errResourceInUse}, Initial: tgInUseRetry, Max: tgInUseRetry, Multiplier: 1,
		Timeout: tgInUseTimeout, Clock: elbClock}, func(ctx context.Context) error {
		return s.c.DeleteTargetGroup(ctx, s.region, tg.ID)
	})
	switch {
	case err == nil:
		return ch
	case platform.HasErrorCode(err, errResourceInUse):
		rt.Infof("warning: target group %s is still in use (by another load balancer's listener or rule) and was kept", tg.Name)
		ch.Action, ch.Detail = platform.Skipped, "still in use by another listener or rule"
		return ch
	}
	rt.Infof("warning: target group %s was not deleted: %v", tg.Name, err)
	ch.Action, ch.Detail = platform.Failed, err.Error()
	return ch
}
