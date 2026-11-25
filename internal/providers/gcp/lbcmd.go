package gcp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

func newLoadBalancerCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "load-balancer", Short: "Load balancers: a forwarding rule and the chain behind it"}
	certCmd := &cobra.Command{Use: "cert", Short: "Certificates of the target HTTPS proxies of a load balancer"}
	certCmd.AddCommand(lbCertSetCmd(rt))
	cmd.AddCommand(lbEnsureCmd(rt), lbListCmd(rt), lbGetCmd(rt), lbDeleteCmd(rt), certCmd)
	return cmd
}

// checkPortFlag validates a port flag.
func checkPortFlag(flag string, v int64) error {
	if v < 1 || v > 65535 {
		return app.UsageErrf("--%s must be a port between 1 and 65535, got %d", flag, v)
	}
	return nil
}

// checkNameFlag validates a resource name given on the command line.
func checkNameFlag(flag, v string) error {
	if !certNameRe.MatchString(v) {
		return app.UsageErrf("--%s %q is not a valid Compute Engine name: a lower-case letter first, then lower-case letters, digits and hyphens, not ending with a hyphen, at most 63 characters", flag, v)
	}
	return nil
}

func lbEnsureCmd(rt *app.Runtime) *cobra.Command {
	var protocol, name, checkName, sslCert, address, zone, region, backendProtocol string
	var port, backendPort, checkPort int64
	var healthTimeout time.Duration
	var wf app.WaitFlags
	cmd := &cobra.Command{
		Use:   "ensure <instance>",
		Short: "Build or complete a regional external load balancer in front of an instance",
		Long: `Build, or complete, a regional external load balancer (EXTERNAL_MANAGED,
premium tier) in front of an existing instance. <instance> is the instance
(name or id; the inventory tells its project and zone, and --zone, --region
and --profile that disagree with it are noted and the instance's own values
used); the load balancer goes into the instance's region and network.

Components, each read first: created when missing, completed in place where
that is safe, otherwise compared (a difference polyctl cannot change in
place is exit code 1, and nothing is ever deleted or rolled back):
  - the health check firewall rule allow-lb-health-check-{network} and the
    network tag lb-health-check on the instance (as firewall ensure --preset
    lb-health-check does; a missing permission is skipped with a warning);
  - the regional TCP health check check-{port} (--health-check-name), shared
    by load balancers of the region;
  - the zonal instance group ig-{instance} with the named port of the backend
    (http:80 for HTTP(S) on port 80, else port-{port}:{port}; other named
    ports are kept) and the instance as member. An instance already in an
    instance group a backend service uses keeps that group: an instance may
    belong to one such group only;
  - the backend service bs-{instance} (tcp: bs-tcp-{instance}); a backend
    service without the instance group gets it added;
  - http and https: the URL map lb-{instance} and the target proxy
    proxy-{instance} (https: proxy-https-{instance} with --ssl-certificate,
    an existing regional certificate); tcp: the target TCP proxy
    proxy-tcp-{instance};
  - the forwarding rule fr-{instance} (https: fr-https-, tcp: fr-tcp-) on
    --port, on the static address --address (reserved when missing) or an
    ephemeral IP, labelled polyctl-lb={lb-name}.
--name names the load balancer (default lb-{instance}, tcp lb-tcp-{instance};
naming.gcp_*_prefix change the prefixes) and the other components follow it.
A proxy-only subnetwork (purpose REGIONAL_MANAGED_PROXY, role ACTIVE) of the
network in the region must exist: none is exit code 1 before anything is
written. Run ensure twice, with http and https, for both ports: they share
the URL map, backend service and instance group.

Every operation is waited for (--timeout bounds each one, 10m), since each
component needs the previous one. Then http and https wait up to
--health-timeout (3m) for a HEALTHY backend; running out of time is a
warning with a checklist, not an error. --no-wait skips that wait.
--dry-run runs every read and reports what would be created.

On a terminal, what is missing is asked: the instance, from the running
instances of the selected accounts; the protocol (http preselected); the
port of a tcp load balancer, checked as it is typed; for https the
certificate, from the unexpired certificates of the instance's region, or
"Create a new certificate..." (from polyctl's certificate store or files,
its name proposed from naming.gcp_ssl_certificate), created as the first
step of the plan.`,
		Example: `  polyctl gcp compute load-balancer ensure web-1 --protocol http --dry-run
  polyctl gcp compute load-balancer ensure web-1 --protocol https --ssl-certificate web-example-com-cert-20261117
  polyctl gcp compute load-balancer ensure db-1 --protocol tcp --port 3306 --address lb-tcp-db-1-ip -o json`,
		Args: app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			fl := cmd.Flags()
			wait, timeout, err := wf.Resolve(cmd)
			if err != nil {
				return err
			}
			protocol = strings.ToLower(strings.TrimSpace(protocol))
			if protocol == "" && rt.Interactive() {
				if protocol, err = rt.Choose(app.Choice{Title: "Front end protocol", Default: lbProtoHTTP, Arg: "--protocol", Options: []prompt.Option{
					{Label: "http  (port 80)", Value: lbProtoHTTP}, {Label: "https  (port 443, needs a certificate)", Value: lbProtoHTTPS},
					{Label: "tcp  (a port of your choice)", Value: lbProtoTCP}}}); err != nil {
					return err
				}
			}
			switch protocol {
			case lbProtoHTTP, lbProtoHTTPS, lbProtoTCP:
			case "":
				return app.UsageErrf("--protocol is required: http, https or tcp")
			default:
				return app.UsageErrf("--protocol must be http, https or tcp, got %q", protocol)
			}
			if !fl.Changed("port") {
				switch protocol {
				case lbProtoHTTP:
					port = 80
				case lbProtoHTTPS:
					port = 443
				default:
					v, err := rt.AskInput("--port", "Port of the forwarding rule (1-65535)", "", func(s string) error {
						n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
						if err != nil {
							return fmt.Errorf("%q is not a port number", s)
						}
						return checkPortFlag("port", n)
					})
					if err != nil {
						if !rt.Interactive() {
							return app.UsageErrf("--port is required with --protocol tcp (the port of the forwarding rule)")
						}
						return err
					}
					port, _ = strconv.ParseInt(v, 10, 64)
				}
			}
			if err := checkPortFlag("port", port); err != nil {
				return err
			}
			if !fl.Changed("backend-port") {
				backendPort = 80
				if protocol == lbProtoTCP {
					backendPort = port
				}
			}
			if err := checkPortFlag("backend-port", backendPort); err != nil {
				return err
			}
			if !fl.Changed("health-check-port") {
				checkPort = backendPort
			}
			if err := checkPortFlag("health-check-port", checkPort); err != nil {
				return err
			}
			switch {
			case protocol == lbProtoHTTPS && sslCert == "" && !rt.Interactive():
				return app.UsageErrf("--ssl-certificate is required with --protocol https: an existing regional certificate (gcp compute ssl-certificate create ...)")
			case protocol != lbProtoHTTPS && sslCert != "":
				return app.UsageErrf("--ssl-certificate applies to --protocol https only")
			case protocol != lbProtoHTTPS && fl.Changed("backend-protocol"):
				return app.UsageErrf("--backend-protocol applies to --protocol https only")
			}
			bp := "HTTP"
			switch strings.ToLower(backendProtocol) {
			case "", "http":
			case "https":
				bp = "HTTPS"
			default:
				return app.UsageErrf("--backend-protocol must be http or https, got %q", backendProtocol)
			}
			if protocol == lbProtoTCP {
				bp = "TCP"
			}
			for flag, v := range map[string]string{"name": name, "health-check-name": checkName, "ssl-certificate": sslCert, "address": address} {
				if v != "" {
					if err := checkNameFlag(flag, v); err != nil {
						return err
					}
				}
			}
			if healthTimeout <= 0 {
				return app.UsageErrf("--health-timeout must be a positive duration, got %s", healthTimeout)
			}
			if rt.Flags.Offline {
				return fmt.Errorf("%w: load-balancer ensure reads and writes the load balancer live", app.ErrOffline)
			}
			if args, err = instanceArg(ctx, rt, args, zone, "running GCP instance", statusIn(statusRunning)); err != nil {
				return err
			}
			l, err := resolveInstance(ctx, rt, args[0], zone, false)
			if err != nil {
				return err
			}
			if def, perr := gcpProfile(rt); perr == nil && def != l.profile {
				rt.Infof("note: instance %s is in gcp/%s, not gcp/%s; the load balancer is built in gcp/%s", l.name(), l.profile, def, l.profile)
			}
			if region != "" && region != l.region() {
				rt.Infof("note: instance %s is in region %s, not %s; using %s", l.name(), l.region(), region, l.region())
			}
			network := ""
			if len(l.inst.NetworkInterfaces) > 0 {
				network = lastSegment(l.inst.NetworkInterfaces[0].Network)
			}
			if network == "" {
				if network, err = defaultNetwork(rt, l.profile, ""); err != nil {
					return err
				}
				rt.Infof("warning: the network of instance %s is unknown; using network %s", l.name(), network)
			}
			e := &lbEnsure{rt: rt, c: l.c, scope: certScope{c: l.c, region: l.region(), timeout: timeout}, profile: l.profile, zone: l.zone,
				network: network, inst: l.inst, protocol: protocol, backendProtocol: bp, port: port, backendPort: backendPort,
				checkPort: checkPort, sslCert: sslCert, address: address, wait: wait, timeout: timeout, healthTimeout: healthTimeout}
			if protocol == lbProtoHTTPS && e.sslCert == "" {
				if err := pickLBCert(ctx, rt, e); err != nil {
					return err
				}
			}
			if err := e.deriveNames(name, checkName); err != nil {
				return err
			}
			plan, err := e.plan(ctx)
			if err != nil {
				return err
			}
			return runLBEnsure(ctx, rt, e, plan)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&protocol, "protocol", "", "front end protocol: http, https or tcp (required)")
	fl.Int64Var(&port, "port", 0, "port of the forwarding rule (default 80 for http, 443 for https; required for tcp)")
	fl.Int64Var(&backendPort, "backend-port", 0, "port the instance serves on, which names the named port (default 80 for http and https, --port for tcp)")
	fl.StringVar(&name, "name", "", "load balancer name (default lb-{instance}, tcp lb-tcp-{instance}); the other components follow it")
	fl.Int64Var(&checkPort, "health-check-port", 0, "port the TCP health check probes (default: the backend port)")
	fl.StringVar(&checkName, "health-check-name", "", "regional health check name (default check-{health-check-port})")
	fl.StringVar(&sslCert, "ssl-certificate", "", "existing regional SSL certificate of the HTTPS proxy (required for https)")
	fl.StringVar(&backendProtocol, "backend-protocol", "", "with --protocol https: http (default, TLS ends at the load balancer) or https")
	fl.StringVar(&address, "address", "", "regional static external address of the forwarding rule, reserved when missing (recommended name: {lb-name}-ip; default: an ephemeral IP)")
	fl.StringVar(&zone, "zone", "", "zone of the instance; only an instance in this zone is used (default: from the inventory)")
	fl.StringVar(&region, "region", "", "region of the instance (only checked: the instance's region is used)")
	fl.DurationVar(&healthTimeout, "health-timeout", defaultHealthTimeout, "how long http and https wait for a HEALTHY backend")
	app.AddWaitFlags(cmd, &wf, true, app.DefaultWaitTimeout)
	return cmd
}

// runLBEnsure runs the plan, prints the report with the load balancer and
// keeps the inventory up to date.
func runLBEnsure(ctx context.Context, rt *app.Runtime, e *lbEnsure, plan *platform.Plan) error {
	target := platform.Target{Platform: platform.GCP, Profile: e.profile, Project: e.c.project, Region: e.scope.region, Zone: e.zone}
	rep, err := rt.RunPlan(ctx, target, plan)
	if rep.Changes == nil {
		rep.Changes = []platform.Change{}
	}
	if !rep.DryRun {
		if fr, ferr := e.scope.findRule(ctx, e.names.rule); ferr == nil && fr != nil {
			if e.ip == "" {
				e.ip = fr.IPAddress
			}
			storeRule(ctx, rt, e.c, e.profile, fr, e.names.lb)
		}
	}
	res := lbEnsureResult{Target: lbEnsureTarget{Target: target, Project: e.c.project}, DryRun: rep.DryRun, LoadBalancer: e.summary(), Changes: rep.Changes}
	if rerr := rt.Render(res, func() output.Grid { return app.ChangeGrid(rep.Changes) }); rerr != nil && err == nil {
		err = rerr
	}
	if err != nil {
		if !rep.DryRun && !errors.Is(err, app.ErrUsage) {
			rt.Infof("the components above that were created stay; fix the cause and run the same ensure again: it reuses them and goes on from the failed step")
			rt.NotifyFailure(ctx, app.Failure{Event: "gcp.compute.load-balancer.ensure.failed", Platform: string(platform.GCP), Profile: e.profile,
				Error: err.Error(), Changes: rep.Changes})
		}
		return err
	}
	switch {
	case rep.DryRun:
	case e.ip == "":
		rt.Infof("warning: the IP of forwarding rule %s is not known yet", e.names.rule)
	default:
		rt.Infof("load balancer %s: %s", e.names.lb, accessURL(e.protocol, e.ip, e.port))
	}
	return nil
}

// ---------------------------------------------------------------- list

func lbListCmd(rt *app.Runtime) *cobra.Command {
	var sf scopeFlags
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the load balancers of the project, one row per forwarding rule",
		Long: `List the load balancers of the project, read live: one row per forwarding rule,
named after its load balancer (the polyctl-lb label of the rule, else the URL
map of its target proxy, else the rule's own name), with the protocol, IP,
port, backend services and the health of their instances (HEALTHY, 1/2
HEALTHY, UNHEALTHY, "no status yet" for a backend that just joined, "-" when
it cannot be read). Every scope by default; --region or --global narrows it.
No load balancer is exit code 0 with an empty list and a note.`,
		Example: "  polyctl gcp compute load-balancer list -o json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			region, all, err := sf.resolve(false)
			if err != nil {
				return err
			}
			c, profile, err := openGCP(ctx, rt)
			if err != nil {
				return err
			}
			rows := []lbRow{}
			// Every selected project (--project: that one alone).
			err = c.forProjects(ctx, func(c *client) error {
				x, err := c.loadLBIndex(ctx)
				if err != nil {
					return fmt.Errorf("%w (gcp/%s)", err, profile)
				}
				if len(x.unreachable) > 0 {
					rt.Infof("warning: project %s: unreachable scopes: %s", c.project, strings.Join(x.unreachable, ", "))
				}
				for _, e := range x.entries() {
					if !all && e.region != region {
						continue
					}
					rows = append(rows, x.row(e, profile, c.project, c.healthOf(ctx, x, e.backendKeys)))
				}
				return nil
			})
			if err != nil {
				return err
			}
			sort.SliceStable(rows, func(i, j int) bool {
				if rows[i].Project != rows[j].Project {
					return rows[i].Project < rows[j].Project
				}
				if rows[i].Name != rows[j].Name {
					return rows[i].Name < rows[j].Name
				}
				return rows[i].Port < rows[j].Port
			})
			if len(rows) == 0 {
				rt.Infof("note: no load balancers in %s (gcp/%s)", c.projectsLabel(), profile)
			} else {
				rt.Infof("%d forwarding rule(s) in %s via gcp/%s", len(rows), c.projectsLabel(), profile)
			}
			return rt.Render(rows, func() output.Grid {
				g := output.Grid{Headers: []string{"NAME", "PROJECT", "SCOPE", "REGION", "PROTOCOL", "IP", "PORT", "BACKEND", "HEALTH"}, Empty: "no load balancers"}
				for _, r := range rows {
					g.Rows = append(g.Rows, []string{r.Name, r.Project, r.Scope, dash(r.Region), r.Protocol, r.IPAddress, r.Port, dash(strings.Join(r.Backends, ",")), r.Health})
				}
				return g
			})
		},
	}
	sf.register(cmd, "load balancer (default: every scope)")
	return cmd
}

// ---------------------------------------------------------------- routing

// lbTarget is a load balancer found for get and delete.
type lbTarget struct {
	name    string
	profile string
	c       *client
	x       *lbIndex
	region  string // "" for global
	entries []lbEntry
}

func (t *lbTarget) scope() certScope { return certScope{c: t.c, region: t.region} }

// lbScopes returns the accounts and projects whose inventory has a
// forwarding rule of that name or of that load balancer, syncing the
// forwarding rules of the selected accounts once when none does. With
// --project only that project counts; an account in whose selection it is
// not is not in the inventory and is returned to be read live.
func lbScopes(ctx context.Context, rt *app.Runtime, ref string) ([]scope, error) {
	accounts, err := gcpAccounts(rt)
	if err != nil {
		return nil, err
	}
	db, err := rt.DB()
	if err != nil {
		return nil, err
	}
	var live []scope
	var cached []config.AccountRef
	for _, a := range accounts {
		if pinUnselected(rt, a.Profile) {
			live = append(live, scope{a.Profile, pinnedProject(rt)})
		} else {
			cached = append(cached, a)
		}
	}
	accounts = cached
	if len(accounts) == 0 {
		return live, nil
	}
	lookup := func() ([]scope, error) {
		out := live
		for _, a := range accounts {
			rows, err := db.List(ctx, inventory.Query{Platform: platform.GCP, Profile: a.Profile, Type: platform.ResLoadBalancer})
			if err != nil {
				return nil, err
			}
			def, _, _ := accountProjects(rt, a.Profile)
			for _, r := range rows {
				var fr ForwardingRule
				if r.Name != ref && (r.Decode(&fr) != nil || fr.LoadBalancer != ref) {
					continue
				}
				_ = r.Decode(&fr)
				sc := scope{a.Profile, fr.Project}
				if sc.project == "" {
					sc.project = def
				}
				if keepProject(rt, a.Profile, sc.project) && !slices.Contains(out, sc) {
					out = append(out, sc)
				}
			}
		}
		return out, nil
	}
	if !rt.Flags.Refresh {
		if found, err := lookup(); err != nil || len(found) > len(live) {
			return found, err
		}
	}
	rt.Infof("looking up load balancer %q: syncing the forwarding rules of %d account(s)...", ref, len(accounts))
	var syncErr error
	for _, a := range accounts {
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
			rt.Infof("warning: sync %s: %v", a.Label(), err)
			if syncErr == nil {
				syncErr = fmt.Errorf("sync %s: %w", a.Label(), err)
			}
		}
	}
	found, err := lookup()
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		var names []string
		for _, a := range accounts {
			names = append(names, "gcp/"+a.Profile)
		}
		if pin := pinnedProject(rt); pin != "" {
			names[len(names)-1] += " (project " + pin + ")"
		}
		if syncErr != nil {
			return nil, fmt.Errorf("cannot tell where load balancer %q is: %w", ref, syncErr)
		}
		return nil, fmt.Errorf("%w: load balancer %q: no forwarding rule of that name or load balancer in %s", platform.ErrNotFound, ref, strings.Join(names, ", "))
	}
	return found, nil
}

// resolveLBTarget finds the load balancer ref names: the inventory tells
// which accounts hold it, and their components are then read live. ref is
// a load balancer name, or the name of one of its forwarding rules. Load
// balancers of one name in several accounts, projects or scopes are a pick
// in the interactive flow and ambiguous (exit code 5) otherwise, unless
// --profile, --project, --region or --global choose.
func resolveLBTarget(ctx context.Context, rt *app.Runtime, ref, region string, all bool) (*lbTarget, error) {
	if rt.Flags.Offline {
		return nil, fmt.Errorf("%w: load balancers are read live", app.ErrOffline)
	}
	if rt.Flags.Profile != "" {
		if _, err := gcpProfile(rt); err != nil {
			return nil, err
		}
	}
	scopes, err := lbScopes(ctx, rt, ref)
	if err != nil {
		return nil, err
	}
	var hits []*lbTarget
	for _, sc := range scopes {
		p := sc.profile
		c, err := openScope(ctx, rt, sc)
		if err != nil {
			return nil, err
		}
		x, err := c.loadLBIndex(ctx)
		if err != nil {
			return nil, fmt.Errorf("%w (%s)", err, sc)
		}
		entries := x.entries()
		byScope := map[string][]lbEntry{}
		name := ref
		for _, e := range entries {
			if e.name == ref && (all || e.region == region) {
				byScope[e.region] = append(byScope[e.region], e)
			}
		}
		if len(byScope) == 0 {
			// A forwarding rule name stands for its load balancer.
			for _, e := range entries {
				if e.rule.Name == ref && (all || e.region == region) {
					name = e.name
					break
				}
			}
			if name != ref {
				rt.Infof("note: forwarding rule %s belongs to load balancer %s", ref, name)
				for _, e := range entries {
					if e.name == name && (all || e.region == region) {
						byScope[e.region] = append(byScope[e.region], e)
					}
				}
			}
		}
		for r, list := range byScope {
			hits = append(hits, &lbTarget{name: name, profile: p, c: c, x: x, region: r, entries: list})
		}
	}
	if all {
		// Without --region or --global a regional load balancer wins over a
		// global one of the same name.
		var regional []*lbTarget
		for _, h := range hits {
			if h.region != "" {
				regional = append(regional, h)
			}
		}
		if len(regional) > 0 && len(regional) < len(hits) {
			rt.Infof("note: load balancer %q also exists in the global scope; using the regional one (pass --global for the other)", ref)
			hits = regional
		}
	}
	switch len(hits) {
	case 0:
		where := ""
		if !all {
			where = " in the " + (certScope{region: region}).label() + " scope"
		}
		return nil, fmt.Errorf("%w: load balancer %q%s of %s (the local inventory may be stale: retry with --refresh)", platform.ErrNotFound, ref, where, scopeLabels(scopes))
	case 1:
		return hits[0], nil
	}
	sort.Slice(hits, func(i, j int) bool {
		return hits[i].profile+"/"+hits[i].c.project+"/"+hits[i].region < hits[j].profile+"/"+hits[j].c.project+"/"+hits[j].region
	})
	cands := make([]cand, 0, len(hits))
	for _, h := range hits {
		cands = append(cands, cand{profile: h.profile, project: h.c.project, where: (certScope{region: h.region}).label()})
	}
	return disambiguate(rt, ambiguous("load balancer", ref, cands, regionFlags, ""), hits, lbTargetLabel)
}

// ---------------------------------------------------------------- get

type lbRuleView struct {
	Name      string `json:"name" yaml:"name"`
	IPAddress string `json:"ip_address" yaml:"ip_address"`
	Port      string `json:"port" yaml:"port"`
	Protocol  string `json:"protocol" yaml:"protocol"`
	Scheme    string `json:"scheme" yaml:"scheme"`
	Target    string `json:"target,omitempty" yaml:"target,omitempty"`
	Network   string `json:"network,omitempty" yaml:"network,omitempty"`
}

type lbProxyView struct {
	Name            string   `json:"name" yaml:"name"`
	Kind            string   `json:"kind" yaml:"kind"`
	URLMap          string   `json:"url_map,omitempty" yaml:"url_map,omitempty"`
	BackendService  string   `json:"backend_service,omitempty" yaml:"backend_service,omitempty"`
	SSLCertificates []string `json:"ssl_certificates,omitempty" yaml:"ssl_certificates,omitempty"`
}

type lbURLMapView struct {
	Name           string   `json:"name" yaml:"name"`
	DefaultService string   `json:"default_service" yaml:"default_service"`
	Services       []string `json:"backend_services" yaml:"backend_services"`
}

type lbDetail struct {
	Name            string           `json:"name" yaml:"name"`
	Profile         string           `json:"profile" yaml:"profile"`
	Project         string           `json:"project" yaml:"project"`
	Scope           string           `json:"scope" yaml:"scope"`
	Region          string           `json:"region,omitempty" yaml:"region,omitempty"`
	ForwardingRules []lbRuleView     `json:"forwarding_rules" yaml:"forwarding_rules"`
	Proxies         []lbProxyView    `json:"proxies" yaml:"proxies"`
	URLMaps         []lbURLMapView   `json:"url_maps" yaml:"url_maps"`
	BackendServices []backendView    `json:"backend_services" yaml:"backend_services"`
	HealthChecks    []healthCheckRow `json:"health_checks" yaml:"health_checks"`
	InstanceGroups  []groupDetail    `json:"instance_groups" yaml:"instance_groups"`
}

// detail reads the whole chain of the load balancer: backend health and
// instance groups with their members are read now (best effort).
func (t *lbTarget) detail(ctx context.Context, rt *app.Runtime) lbDetail {
	d := lbDetail{Name: t.name, Profile: t.profile, Project: t.c.project, Scope: t.scope().kind(), Region: t.region,
		ForwardingRules: []lbRuleView{}, Proxies: []lbProxyView{}, URLMaps: []lbURLMapView{}, BackendServices: []backendView{},
		HealthChecks: []healthCheckRow{}, InstanceGroups: []groupDetail{}}
	seen := map[string]bool{}
	once := func(k string) bool {
		if seen[k] {
			return false
		}
		seen[k] = true
		return true
	}
	var backendKeys []string
	for _, e := range t.entries {
		fr := e.rule
		v := lbRuleView{Name: fr.Name, IPAddress: fr.IPAddress, Port: portLabel(fr.PortRange), Protocol: e.protocol(), Scheme: fr.LoadBalancingScheme,
			Network: lastSegment(fr.Network)}
		if e.proxyName != "" {
			v.Target = string(e.proxyKind) + "/" + e.proxyName
		}
		d.ForwardingRules = append(d.ForwardingRules, v)
		if e.proxyKey != "" && once(e.proxyKey) {
			pv := lbProxyView{Name: e.proxyName, Kind: string(e.proxyKind)}
			switch e.proxyKind {
			case kindHTTPProxy:
				if p := t.x.httpProxies[e.proxyKey]; p != nil {
					pv.URLMap = lastSegment(p.UrlMap)
				}
			case kindHTTPSProxy:
				if p := t.x.httpsProxy[e.proxyKey]; p != nil {
					pv.URLMap = lastSegment(p.UrlMap)
					for _, u := range p.SslCertificates {
						pv.SSLCertificates = append(pv.SSLCertificates, lastSegment(u))
					}
				}
			case kindTCPProxy:
				if p := t.x.tcpProxies[e.proxyKey]; p != nil {
					pv.BackendService = lastSegment(p.Service)
				}
			}
			d.Proxies = append(d.Proxies, pv)
		}
		if e.urlMap != nil && once(resourceKey(e.urlMap.SelfLink)) {
			mv := lbURLMapView{Name: e.urlMap.Name, DefaultService: lastSegment(e.urlMap.DefaultService), Services: []string{}}
			for _, k := range urlMapServices(e.urlMap) {
				mv.Services = append(mv.Services, lastSegment(k))
			}
			d.URLMaps = append(d.URLMaps, mv)
		}
		backendKeys = append(backendKeys, e.backendKeys...)
	}
	var checkKeys, groups []string
	for _, k := range dedupe(backendKeys) {
		bs := t.x.backends[k]
		if bs == nil {
			continue
		}
		v := backendViewOf(bs)
		v.withHealth(ctx, t.c, bs)
		d.BackendServices = append(d.BackendServices, v)
		for _, h := range bs.HealthChecks {
			checkKeys = append(checkKeys, resourceKey(h))
		}
		for _, b := range bs.Backends {
			if strings.Contains(b.Group, "/instanceGroups/") {
				groups = append(groups, resourceKey(b.Group))
			}
		}
	}
	for _, k := range dedupe(checkKeys) {
		if hc := t.x.checks[k]; hc != nil {
			d.HealthChecks = append(d.HealthChecks, healthCheckRowOf(hc))
		}
	}
	for _, k := range dedupe(groups) {
		zone, name := zoneOfGroup(k), lastSegment(k)
		g, err := t.c.findInstanceGroup(ctx, zone, name)
		if err != nil || g == nil {
			rt.Verbosef("instance group %s: %v", k, err)
			d.InstanceGroups = append(d.InstanceGroups, groupDetail{groupRow: groupRow{Name: name, Zone: zone, NamedPorts: []string{}}, Members: []groupMember{}})
			continue
		}
		d.InstanceGroups = append(d.InstanceGroups, groupDetailOf(ctx, t.c, g))
	}
	return d
}

// zoneOfGroup returns the zone of an instance group reference
// ("projects/p/zones/z/instanceGroups/n").
func zoneOfGroup(u string) string {
	parts := strings.Split(resourceKey(u), "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "zones" {
			return parts[i+1]
		}
	}
	return ""
}

func lbDetailGrid(d lbDetail) output.Grid {
	g := output.Grid{Headers: []string{"COMPONENT", "NAME", "DETAIL"}}
	add := func(kind, name, detail string) { g.Rows = append(g.Rows, []string{kind, name, detail}) }
	for _, r := range d.ForwardingRules {
		add(string(kindRule), r.Name, fmt.Sprintf("%s %s:%s %s -> %s", r.Protocol, r.IPAddress, r.Port, r.Scheme, dash(r.Target)))
	}
	for _, p := range d.Proxies {
		detail := ""
		switch {
		case p.URLMap != "":
			detail = "URL map " + p.URLMap
		case p.BackendService != "":
			detail = "backend service " + p.BackendService
		}
		if len(p.SSLCertificates) > 0 {
			detail += ", certs: " + strings.Join(p.SSLCertificates, ",")
		}
		add(p.Kind, p.Name, detail)
	}
	for _, m := range d.URLMaps {
		add(string(kindURLMap), m.Name, "default -> "+m.DefaultService)
	}
	for _, b := range d.BackendServices {
		add(string(kindBackendService), b.Name, fmt.Sprintf("%s, port-name %s, %s, health %s", b.Protocol, dash(b.PortName), b.Scheme, b.Health))
	}
	for _, h := range d.HealthChecks {
		add(string(kindHealthCheck), h.Name, fmt.Sprintf("%s :%s interval %ds timeout %ds", h.Type, h.Port, h.Interval, h.Timeout))
	}
	for _, ig := range d.InstanceGroups {
		var members []string
		for _, m := range ig.Members {
			members = append(members, m.Instance)
		}
		add(string(kindInstanceGroup), ig.Name, fmt.Sprintf("zone %s, named ports %s, members %s", ig.Zone, dash(strings.Join(ig.NamedPorts, ",")), dash(strings.Join(members, ","))))
	}
	return g
}

func lbGetCmd(rt *app.Runtime) *cobra.Command {
	var sf scopeFlags
	cmd := &cobra.Command{
		Use:   "get <name>",
		Short: "Show a load balancer with its whole chain of components",
		Long: `Show a load balancer: its forwarding rules, target proxies, URL map, backend
services (with the health of their instances), health checks and instance
groups with their named ports and members. <name> is the load balancer name
(the polyctl-lb label of its forwarding rules, else the URL map name, else
the forwarding rule name) or the name of one of its forwarding rules; the
inventory tells which account holds it (synced once when unknown), then
everything is read live. Without --region or --global a regional load
balancer wins over a global one of the same name. Several matches are exit
code 5 (pass --profile, --region or --global; a terminal lets you choose);
none is exit code 4. On a terminal, without <name> the load balancers of
the selected accounts are offered.`,
		Example: "  polyctl gcp compute load-balancer get lb-web-1 -o json",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			region, all, err := sf.resolve(false)
			if err != nil {
				return err
			}
			t, err := lbTargetArg(ctx, rt, args, region, all)
			if err != nil {
				return err
			}
			d := t.detail(ctx, rt)
			return rt.Render(d, func() output.Grid { return lbDetailGrid(d) })
		},
	}
	sf.register(cmd, "load balancer (to choose among load balancers of one name)")
	return cmd
}

// ---------------------------------------------------------------- delete

// lbDeletion is a component the delete of a load balancer removes, or
// keeps because something outside the load balancer uses it.
type lbDeletion struct {
	kind   lbKind
	name   string
	key    string
	usedBy []string
}

// deletions computes what deleting the load balancer removes: its
// forwarding rules, then the target proxies, URL maps and backend services
// that only its forwarding rules reach. Instance groups, health checks,
// firewall rules and addresses are never deleted (other load balancers may
// share them).
func (t *lbTarget) deletions() []lbDeletion {
	x := t.x
	gone := map[string]bool{}
	var out []lbDeletion
	for _, e := range t.entries {
		k := resourceKey(e.rule.SelfLink)
		gone[k] = true
		out = append(out, lbDeletion{kind: kindRule, name: e.rule.Name, key: k})
	}
	// Who refers to what, among everything of the project.
	refs := map[string][]string{} // component key -> keys of the components that use it
	add := func(user, used string) {
		if used != "" {
			refs[resourceKey(used)] = append(refs[resourceKey(used)], user)
		}
	}
	for _, fr := range x.rules {
		u := resourceKey(fr.SelfLink)
		add(u, fr.Target)
		add(u, fr.BackendService)
	}
	for k, p := range x.httpProxies {
		add(k, p.UrlMap)
	}
	for k, p := range x.httpsProxy {
		add(k, p.UrlMap)
	}
	for k, p := range x.tcpProxies {
		add(k, p.Service)
	}
	for k, m := range x.urlMaps {
		for _, s := range urlMapServices(m) {
			add(k, s)
		}
	}
	consider := func(kind lbKind, key string) {
		if key == "" || gone[key] {
			return
		}
		for _, d := range out {
			if d.key == key {
				return
			}
		}
		var others []string
		for _, u := range refs[key] {
			if !gone[u] {
				others = append(others, componentLabel(u))
			}
		}
		sort.Strings(others)
		d := lbDeletion{kind: kind, name: lastSegment(key), key: key, usedBy: dedupe(others)}
		if len(others) == 0 {
			gone[key] = true
		}
		out = append(out, d)
	}
	for _, e := range t.entries {
		consider(e.proxyKind, e.proxyKey)
	}
	for _, e := range t.entries {
		if e.urlMap != nil && gone[e.proxyKey] {
			consider(kindURLMap, resourceKey(e.urlMap.SelfLink))
		}
	}
	for _, e := range t.entries {
		for _, b := range e.backendKeys {
			consider(kindBackendService, b)
		}
	}
	return out
}

// componentLabel renders a component reference as kind/name.
func componentLabel(key string) string {
	parts := strings.Split(key, "/")
	if len(parts) < 2 {
		return key
	}
	kind := parts[len(parts)-2]
	switch kind {
	case "forwardingRules":
		kind = string(kindRule)
	case "targetHttpProxies":
		kind = string(kindHTTPProxy)
	case "targetHttpsProxies":
		kind = string(kindHTTPSProxy)
	case "targetTcpProxies":
		kind = string(kindTCPProxy)
	case "urlMaps":
		kind = string(kindURLMap)
	case "backendServices":
		kind = string(kindBackendService)
	}
	return kind + "/" + parts[len(parts)-1]
}

func lbDeleteCmd(rt *app.Runtime) *cobra.Command {
	var sf scopeFlags
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a load balancer: its forwarding rules, proxies, URL map and backend services (asks first)",
		Long: `Delete a load balancer (found like get finds it): its forwarding rules, then
the target proxies, URL map and backend services that only those forwarding
rules reach, in that order, waiting for each operation (--timeout, 10m). A
component something else still uses is kept and reported skipped. Instance
groups, health checks, firewall rules and static addresses are never deleted:
other load balancers may share them (delete them with their own commands).
An ephemeral IP goes with its forwarding rule.

The components are shown first, then a confirmation is asked (default no;
--yes skips it, and the non-interactive flow needs --yes). --dry-run reports
what would be deleted. On a terminal, without <name> the load balancers of
the selected accounts are offered.`,
		Example: "  polyctl gcp compute load-balancer delete lb-web-1 --yes",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if timeout <= 0 {
				return app.UsageErrf("--timeout must be a positive duration, got %s", timeout)
			}
			region, all, err := sf.resolve(false)
			if err != nil {
				return err
			}
			t, err := lbTargetArg(ctx, rt, args, region, all)
			if err != nil {
				return err
			}
			s := t.scope()
			s.timeout = timeout
			dels := t.deletions()
			rt.Infof("load balancer %s (%s, gcp/%s, project %s):", t.name, s.label(), t.profile, t.c.project)
			var plan platform.Plan
			for _, d := range dels {
				res := string(d.kind) + "/" + d.name
				if len(d.usedBy) > 0 {
					rt.Infof("  keep    %s (used by %s)", res, strings.Join(d.usedBy, ", "))
					plan.Add(platform.Step{Resource: res, Action: platform.Skipped, Desc: "used by " + strings.Join(d.usedBy, ", ")})
					continue
				}
				rt.Infof("  delete  %s", res)
				plan.Add(platform.Step{Resource: res, Action: platform.Deleted, Desc: s.label(),
					Apply: func(ctx context.Context) (platform.Change, error) {
						err := s.deleteComponent(ctx, d.kind, d.name)
						switch {
						case errors.Is(err, platform.ErrNotFound):
							return platform.Change{Action: platform.Skipped, Detail: "already deleted"}, nil
						case isReason(err, reasonInUse):
							return platform.Change{}, fmt.Errorf("%s is used by %s: delete that first", res, inUseByRef(err))
						}
						return platform.Change{}, err
					}})
			}
			rt.Infof("  kept: instance groups, health checks, firewall rules and static addresses")
			target := platform.Target{Platform: platform.GCP, Profile: t.profile, Project: t.c.project, Region: t.region}
			if !rt.DryRun() {
				ok, err := rt.Confirm(ctx, fmt.Sprintf("Delete load balancer %s (%s, project %s)?", t.name, s.label(), t.c.project), false)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("%w: cancelled; load balancer %s was not deleted", platform.ErrNothingToDo, t.name)
				}
			}
			rep, err := rt.RunPlan(ctx, target, &plan)
			if !rep.DryRun {
				if db, derr := rt.DB(); derr == nil {
					set := inventory.Set{Platform: platform.GCP, Profile: t.profile, Type: platform.ResLoadBalancer}
					for _, ch := range rep.Changes {
						if ch.Action != platform.Deleted || !strings.HasPrefix(ch.Resource, string(kindRule)+"/") {
							continue
						}
						for _, e := range t.entries {
							if string(kindRule)+"/"+e.rule.Name == ch.Resource {
								_ = db.Delete(ctx, set, platform.ResLoadBalancer, t.c.ruleOf(e.rule).inventoryID())
							}
						}
					}
				}
			}
			if rerr := rt.RenderReport(rep); rerr != nil && err == nil {
				err = rerr
			}
			return err
		},
	}
	sf.register(cmd, "load balancer (to choose among load balancers of one name)")
	cmd.Flags().DurationVar(&timeout, "timeout", app.DefaultWaitTimeout, "upper bound of the wait for each deletion (a Go duration such as 90s or 10m)")
	return cmd
}
