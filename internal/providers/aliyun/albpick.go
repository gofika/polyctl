package aliyun

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// The interactive picks of the alb and cas commands.

// lbArg fills in a missing <name|id> of a load balancer command: the ALBs
// of the selected accounts as the inventory knows them (synced first when
// stale), in region when given; the value is the id. None is nothing to
// do.
func lbArg(ctx context.Context, rt *app.Runtime, args []string, region string) ([]string, error) {
	if len(args) > 0 {
		return args, nil
	}
	id, err := rt.PickResource(ctx, app.ResourcePick{Platform: platform.Aliyun, Kind: platform.ResLoadBalancer,
		Title: "Load balancer", Arg: "<name|id>", What: "aliyun load balancer",
		Filter: func(r inventory.Resource) bool {
			if region == "" {
				return true
			}
			var lb albLoadBalancer
			_ = r.Decode(&lb)
			return lb.Region == region || r.ParentID == region
		},
		Label: func(r inventory.Resource) string {
			var lb albLoadBalancer
			_ = r.Decode(&lb)
			reg := lb.Region
			if reg == "" {
				reg = r.ParentID
			}
			return joinLabel(nameOr(r.Name, r.ID), r.ID, reg, lb.Status, lb.DNSName, "aliyun/"+r.Profile)
		}})
	if err != nil {
		return nil, err
	}
	return []string{id}, nil
}

// pickLB asks for one of the ALBs of the scope's region for the input arg
// ("--lb"); it returns the id. None is nothing to do.
func pickLB(ctx context.Context, rt *app.Runtime, sc *albScope, arg string) (string, error) {
	if !rt.Interactive() {
		return "", app.UsageErrf("%s is required", arg)
	}
	lbs, err := sc.a.listLBs(ctx, nil)
	if err != nil {
		return "", err
	}
	var opts []prompt.Option
	for _, l := range lbs {
		opts = append(opts, prompt.Option{Label: lbOptionLabel(l), Value: l.ID})
	}
	return rt.Choose(app.Choice{Title: "Load balancer (" + sc.where() + ")", Options: opts, Arg: arg, What: "load balancer in " + sc.where()})
}

// listenerArg fills in a missing <listener-id>: the load balancer of the
// region, then its listeners (of protocols when given). None is nothing to
// do.
func listenerArg(ctx context.Context, rt *app.Runtime, sc *albScope, args []string, protocols ...string) ([]string, error) {
	if len(args) > 0 {
		return args, nil
	}
	lbID, err := pickLB(ctx, rt, sc, "<listener-id>")
	if err != nil {
		return nil, err
	}
	ls, err := sc.a.listListenersOf(ctx, lbID, "")
	if err != nil {
		return nil, err
	}
	var opts []prompt.Option
	for _, l := range ls {
		if len(protocols) > 0 && !slices.Contains(protocols, strings.ToUpper(l.Protocol)) {
			continue
		}
		opts = append(opts, prompt.Option{Label: joinLabel(fmt.Sprintf("%s:%d", l.Protocol, l.Port), l.ID, l.Status, strings.Join(l.ServerGroups, ",")), Value: l.ID})
	}
	what := "listener of " + lbID
	if len(protocols) > 0 {
		what = strings.Join(protocols, "/") + " " + what
	}
	id, err := rt.Choose(app.Choice{Title: "Listener of " + lbID, Options: opts, Arg: "<listener-id>", What: what})
	if err != nil {
		return nil, err
	}
	return []string{id}, nil
}

// serverGroupArg fills in a missing server group argument: the server
// groups of the scope's region. None is nothing to do.
func serverGroupArg(ctx context.Context, rt *app.Runtime, sc *albScope, args []string, arg string) ([]string, error) {
	if len(args) > 0 {
		return args, nil
	}
	groups, err := sc.a.listServerGroups(ctx, nil, nil)
	if err != nil {
		return nil, err
	}
	var opts []prompt.Option
	for _, g := range groups {
		opts = append(opts, prompt.Option{Label: serverGroupLabel(g), Value: g.ID})
	}
	id, err := rt.Choose(app.Choice{Title: "Server group (" + sc.where() + ")", Options: opts, Arg: arg, What: "server group in " + sc.where()})
	if err != nil {
		return nil, err
	}
	return []string{id}, nil
}

// aclArg fills in a missing ACL argument: the ACLs of the scope's region.
// None is nothing to do.
func aclArg(ctx context.Context, rt *app.Runtime, sc *albScope, args []string, arg string) ([]string, error) {
	if len(args) > 0 {
		return args, nil
	}
	acls, err := sc.a.listACLs(ctx, nil, nil)
	if err != nil {
		return nil, err
	}
	var opts []prompt.Option
	for _, x := range acls {
		opts = append(opts, prompt.Option{Label: aclLabel(x), Value: x.ID})
	}
	id, err := rt.Choose(app.Choice{Title: "ACL (" + sc.where() + ")", Options: opts, Arg: arg, What: "ACL in " + sc.where()})
	if err != nil {
		return nil, err
	}
	return []string{id}, nil
}

// casCertLabel: "site  example.com,www.example.com  expires 2027-01-01
// 1234567".
func casCertLabel(ct casCertificate, now time.Time) string {
	names := ct.CommonName
	if ct.Sans != "" {
		names = ct.Sans
	}
	exp := "expires " + ct.EndDate
	if ct.expired(now) {
		exp = "expired " + ct.EndDate
	}
	return joinLabel(ct.Name, names, exp, ct.ID)
}

// askCASCert asks for an unexpired uploaded certificate of the CAS store
// of region (the current one marked, the newest other one preselected) for
// the input arg ("--cert").
func askCASCert(ctx context.Context, rt *app.Runtime, c *client, region, current, arg string) (string, error) {
	if !rt.Interactive() {
		return "", app.UsageErrf("%s is required", arg)
	}
	store, err := c.casFor(region)
	if err != nil {
		return "", err
	}
	certs, _, err := c.listCASCertificatesIn(ctx, store)
	if err != nil {
		return "", err
	}
	// A listener names a certificate <id>-<region>.
	current, _, _ = strings.Cut(current, "-")
	now := time.Now()
	var valid []casCertificate
	for _, ct := range certs {
		if !ct.expired(now) {
			valid = append(valid, ct)
		}
	}
	slices.SortStableFunc(valid, func(a, b casCertificate) int { return b.notAfter().Compare(a.notAfter()) })
	var opts []prompt.Option
	def := ""
	for _, ct := range valid {
		label := casCertLabel(ct, now)
		if ct.ID == current {
			label += "  (current)"
		} else if def == "" {
			def = ct.ID
		}
		opts = append(opts, prompt.Option{Label: label, Value: ct.ID})
	}
	return rt.Choose(app.Choice{Title: "Certificate (CAS)", Options: opts, Default: def, Arg: arg, Required: true, What: "unexpired uploaded certificate"})
}

// allExpiredValue is the value of "All expired certificates".
const allExpiredValue = "\x00expired"

// pickCASDelete asks what cas certificate delete deletes: "All expired
// certificates (N)" (when there are any) or one uploaded certificate.
// No certificate is nothing to do.
func pickCASDelete(rt *app.Runtime, certs []casCertificate) (string, error) {
	now := time.Now()
	var opts []prompt.Option
	n := 0
	for _, ct := range certs {
		if ct.expired(now) {
			n++
		}
	}
	if n > 0 {
		opts = append(opts, prompt.Option{Label: "All expired certificates (" + strconv.Itoa(n) + ")", Value: allExpiredValue})
	}
	for _, ct := range certs {
		opts = append(opts, prompt.Option{Label: casCertLabel(ct, now), Value: ct.ID})
	}
	return rt.Choose(app.Choice{Title: "Certificate to delete", Options: opts, Arg: "<cert-id> or --expired", What: "uploaded certificate"})
}

// askCIDRs asks for ACL entries, one IPv4 address or CIDR block per line
// checked as it is typed, until an empty line.
func askCIDRs(rt *app.Runtime) ([]string, error) {
	var out []string
	for {
		v, err := rt.AskInput("<cidr>...", "IPv4 address or CIDR block (empty line ends)", "", func(s string) error {
			if strings.TrimSpace(s) == "" {
				if len(out) == 0 {
					return fmt.Errorf("at least one entry is required")
				}
				return nil
			}
			_, err := normalizeACLEntries([]string{strings.TrimSpace(s)})
			return inline(err)
		})
		if err != nil {
			return nil, err
		}
		if v == "" {
			return out, nil
		}
		out = append(out, v)
	}
}

// pickGroupInstance asks for an instance of the scope's account and region
// for server group g: those of its VPC, Running or Stopped, not in the
// group yet. None is a usage error naming --instance.
func pickGroupInstance(ctx context.Context, rt *app.Runtime, sc *albScope, g *albServerGroup) (string, error) {
	rows, err := sc.c.instanceResources(ctx, sc.region)
	if err != nil {
		return "", err
	}
	in, err := sc.a.listServerGroupServers(ctx, g.ID)
	if err != nil {
		return "", err
	}
	member := map[string]bool{}
	for _, b := range in {
		member[b.ServerID] = true
	}
	var opts []prompt.Option
	for _, r := range rows {
		inst, ok := r.Data.(Instance)
		if !ok || member[inst.ID] || (g.VpcID != "" && inst.VpcID != g.VpcID) || (inst.Status != instRunning && inst.Status != instStopped) {
			continue
		}
		opts = append(opts, prompt.Option{Label: instanceOptionLabel(inst), Value: inst.ID})
	}
	return rt.Choose(app.Choice{Title: "Instance to add to " + orID(g.Name, g.ID), Options: opts, Arg: "--instance", Required: true,
		Empty: app.UsageErrf("--instance is required, and no instance of %s in %s is outside the group", g.VpcID, sc.where())})
}

// otherPortValue is the value of "Other port...".
const otherPortValue = "\x00other-port"

// askListenerSpec asks for the --listener of listener create: http:80 and
// https:443 when the load balancer has no listener on the port, or "Other
// port..." for a <protocol>:<port> checked as it is typed.
func askListenerSpec(ctx context.Context, rt *app.Runtime, sc *albScope, lbID string) (string, int, error) {
	ls, err := sc.a.listListeners(ctx, lbID)
	if err != nil {
		return "", 0, err
	}
	used := map[int]bool{}
	for _, l := range ls {
		used[l.Port] = true
	}
	var opts []prompt.Option
	for _, o := range []struct {
		spec string
		port int
	}{{"https:443", 443}, {"http:80", 80}} {
		if !used[o.port] {
			opts = append(opts, prompt.Option{Label: o.spec, Value: o.spec})
		}
	}
	opts = append(opts, prompt.Option{Label: "Other port...", Value: otherPortValue})
	v, err := rt.Choose(app.Choice{Title: "Listener of " + lbID, Options: opts, Arg: "--listener"})
	if err != nil {
		return "", 0, err
	}
	if v == otherPortValue {
		if v, err = rt.AskInput("--listener", "Listener <protocol>:<port> (http or https)", "", func(s string) error {
			_, port, err := parseListenerSpec("listener", strings.TrimSpace(s))
			if err != nil {
				return inline(err)
			}
			if used[port] {
				return fmt.Errorf("%s has a listener on port %d already", lbID, port)
			}
			return nil
		}); err != nil {
			return "", 0, err
		}
	}
	return parseListenerSpec("listener", v)
}
