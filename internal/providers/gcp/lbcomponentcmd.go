package gcp

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// The components of load balancers on their own: backend services,
// forwarding rules and health checks (regional or global) and instance
// groups (zonal), for troubleshooting and clean-up. They are read live:
// list reads the profile's project; get and delete search every selected
// GCP account for the name.

// ---------------------------------------------------------------- listing

// component is one component found by name: its scope (region "" for a
// global one; zone for an instance group) and the object read.
type component struct {
	kind   lbKind
	name   string
	region string
	zone   string
	obj    any
}

func (c component) where() string {
	if c.kind == kindInstanceGroup {
		return "zone " + c.zone
	}
	return (certScope{region: c.region}).label()
}

// listComponents lists every component of kind in every scope of the
// project, and the scopes that could not be read.
func (c *client) listComponents(ctx context.Context, kind lbKind) ([]component, []string, error) {
	var out []component
	var unreachable []string
	p, cs := c.project, c.compute
	var err error
	switch kind {
	case kindBackendService:
		unreachable, err = aggregatedPages(ctx, cs.BackendServices.AggregatedList(p), func(l *compute.BackendServiceAggregatedList) (string, []string) {
			u := l.Unreachables
			for scope, s := range l.Items {
				if s.Warning != nil {
					u = append(u, warnedUnreachable(scope, s.Warning.Code)...)
				}
				for _, v := range s.BackendServices {
					out = append(out, component{kind: kind, name: v.Name, region: lastSegment(v.Region), obj: v})
				}
			}
			return l.NextPageToken, u
		})
	case kindHealthCheck:
		unreachable, err = aggregatedPages(ctx, cs.HealthChecks.AggregatedList(p), func(l *compute.HealthChecksAggregatedList) (string, []string) {
			u := l.Unreachables
			for scope, s := range l.Items {
				if s.Warning != nil {
					u = append(u, warnedUnreachable(scope, s.Warning.Code)...)
				}
				for _, v := range s.HealthChecks {
					out = append(out, component{kind: kind, name: v.Name, region: lastSegment(v.Region), obj: v})
				}
			}
			return l.NextPageToken, u
		})
	case kindRule:
		seen := map[string]bool{}
		unreachable, err = aggregatedPages(ctx, cs.ForwardingRules.AggregatedList(p), func(l *compute.ForwardingRuleAggregatedList) (string, []string) {
			u := l.Unreachables
			for scope, s := range l.Items {
				if s.Warning != nil {
					u = append(u, warnedUnreachable(scope, s.Warning.Code)...)
				}
				for _, v := range s.ForwardingRules {
					k := v.SelfLink
					if k == "" {
						k = v.Region + "/" + v.Name
					}
					if !seen[k] {
						seen[k] = true
						out = append(out, component{kind: kind, name: v.Name, region: lastSegment(v.Region), obj: v})
					}
				}
			}
			return l.NextPageToken, u
		})
	case kindInstanceGroup:
		unreachable, err = aggregatedPages(ctx, cs.InstanceGroups.AggregatedList(p), func(l *compute.InstanceGroupAggregatedList) (string, []string) {
			u := l.Unreachables
			for scope, s := range l.Items {
				if s.Warning != nil {
					u = append(u, warnedUnreachable(scope, s.Warning.Code)...)
				}
				for _, v := range s.InstanceGroups {
					out = append(out, component{kind: kind, name: v.Name, zone: lastSegment(v.Zone), obj: v})
				}
			}
			return l.NextPageToken, u
		})
	default:
		return nil, nil, fmt.Errorf("cannot list %s", kind)
	}
	if err != nil {
		return nil, nil, computeErr(err)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.name != b.name {
			return a.name < b.name
		}
		return a.region+a.zone < b.region+b.zone
	})
	sort.Strings(unreachable)
	return out, unreachable, nil
}

// componentQuery is the scope given on the command line: region / global
// (all: neither), or a zone for instance groups.
type componentQuery struct {
	region string
	all    bool
	zone   string
}

func (q componentQuery) fits(x component) bool {
	if x.kind == kindInstanceGroup {
		return q.zone == "" || x.zone == q.zone
	}
	return q.all || x.region == q.region
}

// located is a component found in one account.
type located struct {
	component
	profile string
	c       *client
}

// componentsOf lists the components of kind in every enabled project of
// every selected GCP account (in the project of --project) that fit q
// (those named name, when it is given), and the scopes searched.
func componentsOf(ctx context.Context, rt *app.Runtime, kind lbKind, name string, q componentQuery) ([]located, []string, error) {
	if rt.Flags.Offline {
		return nil, nil, fmt.Errorf("%w: %ss are read live", app.ErrOffline, kind)
	}
	if rt.Flags.Profile != "" {
		if _, err := gcpProfile(rt); err != nil {
			return nil, nil, err
		}
	}
	scopes, err := gcpScopes(ctx, rt)
	if err != nil {
		return nil, nil, err
	}
	var hits []located
	var searched []string
	for _, sc := range scopes {
		searched = append(searched, sc.String())
		c, err := openScope(ctx, rt, sc)
		if err != nil {
			return nil, nil, err
		}
		list, unreachable, err := c.listComponents(ctx, kind)
		if err != nil {
			if !c.pinned && isAPIDisabled(err) {
				c.noteOff(c.project, err)
				continue
			}
			return nil, nil, fmt.Errorf("%w (%s)", err, sc)
		}
		if len(unreachable) > 0 {
			rt.Infof("warning: %s: unreachable scopes: %s", sc, strings.Join(unreachable, ", "))
		}
		for _, x := range list {
			if (name == "" || x.name == name) && q.fits(x) {
				hits = append(hits, located{component: x, profile: sc.profile, c: c})
			}
		}
	}
	flushScopes(scopes)
	return hits, searched, nil
}

// locateComponent finds a component by name in every enabled project of
// every selected GCP account.
// Several matches, a regional and a global one of the same name included,
// are a pick in the interactive flow and ambiguous (exit code 5) otherwise;
// none is exit code 4.
func locateComponent(ctx context.Context, rt *app.Runtime, kind lbKind, name string, q componentQuery) (*located, error) {
	hits, searched, err := componentsOf(ctx, rt, kind, name, q)
	if err != nil {
		return nil, err
	}
	switch len(hits) {
	case 0:
		return nil, fmt.Errorf("%w: %s %q in %s", platform.ErrNotFound, kind, name, strings.Join(searched, ", "))
	case 1:
		return &hits[0], nil
	}
	cands := make([]cand, 0, len(hits))
	for _, h := range hits {
		cands = append(cands, cand{profile: h.profile, project: h.c.project, where: h.where()})
	}
	locFlag := regionFlags
	if kind == kindInstanceGroup {
		locFlag = "--zone <z>"
	}
	h, err := app.OneOf(rt, ambiguous(string(kind), name, cands, locFlag, ""), hits, func(h located) string {
		return prompt.Cells(h.name, h.where(), "project "+h.c.project, "gcp/"+h.profile)
	})
	if err != nil {
		return nil, err
	}
	return &h, nil
}

// componentArg finds the component of get and delete: <name> through
// locateComponent, or, without it in the interactive flow, a pick of the
// components of kind of the selected accounts that fit the scope flags
// (labelled like the rows of list; none is nothing to do).
func componentArg(ctx context.Context, rt *app.Runtime, spec componentSpec, args []string, q componentQuery) (*located, error) {
	if len(args) > 0 {
		return locateComponent(ctx, rt, spec.kind, args[0], q)
	}
	if !rt.Interactive() {
		return nil, app.UsageErrf("<name> is required")
	}
	hits, _, err := componentsOf(ctx, rt, spec.kind, "", q)
	if err != nil {
		return nil, err
	}
	h, err := app.PickOf(rt, app.Choice{Title: strings.ToUpper(string(spec.kind)[:1]) + string(spec.kind)[1:], Arg: "<name>", What: string(spec.kind)}, hits,
		func(h located) string {
			_, row := spec.row(h.component)
			return prompt.Cells(append(row, "gcp/"+h.profile)...)
		})
	if err != nil {
		return nil, err
	}
	return &h, nil
}

// ---------------------------------------------------------------- commands

// componentSpec describes the commands of one kind of component.
type componentSpec struct {
	kind   lbKind
	use    string
	short  string
	plural string
	// zonal components take --zone instead of --region / --global.
	zonal bool
	// usedBy names what a delete in use waits for ("the URL map or proxy").
	usedBy string
	// rows renders the list; detail renders get.
	headers []string
	row     func(component) (any, []string)
	detail  func(ctx context.Context, l *located) (any, output.Grid)
	example string
}

func newComponentCmd(rt *app.Runtime, spec componentSpec) *cobra.Command {
	cmd := &cobra.Command{Use: spec.use, Short: spec.short}
	cmd.AddCommand(componentListCmd(rt, spec), componentGetCmd(rt, spec), componentDeleteCmd(rt, spec))
	return cmd
}

// queryFlags registers the scope flags of a kind and returns the reader of
// the query.
func queryFlags(cmd *cobra.Command, spec componentSpec, what string) func() (componentQuery, error) {
	if spec.zonal {
		var zone string
		cmd.Flags().StringVar(&zone, "zone", "", "zone of the "+what)
		return func() (componentQuery, error) { return componentQuery{zone: strings.TrimSpace(zone), all: true}, nil }
	}
	var sf scopeFlags
	sf.register(cmd, what)
	return func() (componentQuery, error) {
		region, all, err := sf.resolve(false)
		return componentQuery{region: region, all: all}, err
	}
}

func componentListCmd(rt *app.Runtime, spec componentSpec) *cobra.Command {
	var query func() (componentQuery, error)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the " + spec.plural + " of the enabled projects",
		Long: "List the " + spec.plural + " of the enabled projects, read live in every scope (" + scopeHelp(spec) + `
narrows it). No match is exit code 0 with an empty list and a note.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			q, err := query()
			if err != nil {
				return err
			}
			c, profile, err := openGCP(ctx, rt)
			if err != nil {
				return err
			}
			// Every enabled project (--project: that one alone); the
			// project is the second column and a field of each row.
			type projectRows struct {
				project     string
				unreachable []string
				values      []any
				cells       [][]string
			}
			perProject, err := sweepProjects(ctx, c, func(ctx context.Context, c *client) ([]projectRows, error) {
				list, unreachable, err := c.listComponents(ctx, spec.kind)
				if err != nil {
					return nil, fmt.Errorf("%w (gcp/%s)", err, profile)
				}
				own := projectRows{project: c.project, unreachable: unreachable}
				for _, x := range list {
					if !q.fits(x) {
						continue
					}
					v, row := spec.row(x)
					own.values = append(own.values, withProject(v, c.project))
					own.cells = append(own.cells, append([]string{row[0], c.project}, row[1:]...))
				}
				return []projectRows{own}, nil
			})
			if err != nil {
				return err
			}
			values := []any{}
			var cells [][]string
			for _, p := range perProject {
				if len(p.unreachable) > 0 {
					rt.Infof("warning: project %s: unreachable scopes: %s", p.project, strings.Join(p.unreachable, ", "))
				}
				values = append(values, p.values...)
				cells = append(cells, p.cells...)
			}
			if len(values) == 0 {
				rt.Infof("note: no %s in %s (gcp/%s)", spec.plural, c.projectsLabel(ctx), profile)
			} else {
				rt.Infof("%d %s in %s via gcp/%s", len(values), spec.plural, c.projectsLabel(ctx), profile)
			}
			headers := append([]string{spec.headers[0], "PROJECT"}, spec.headers[1:]...)
			return rt.Render(values, func() output.Grid {
				return output.Grid{Headers: headers, Rows: cells, Empty: "no " + spec.plural}
			})
		},
	}
	query = queryFlags(cmd, spec, string(spec.kind)+" (default: every scope)")
	return cmd
}

func deleteHelp(spec componentSpec) string {
	h := "Delete a " + string(spec.kind) + " (found like get finds it). "
	if spec.usedBy != "" {
		h += "A " + string(spec.kind) + " that " + spec.usedBy + ` still uses cannot be
deleted: exit code 1, naming the user (delete it first; load-balancer delete
removes a whole load balancer in order). `
	} else {
		h += "An ephemeral IP goes with it; a static address stays reserved. "
	}
	return h + `The component is shown first, then a
confirmation is asked (default no; --yes skips it, and the non-interactive
flow needs --yes). The operation is waited for (--timeout, 10m). --dry-run
reports what would be deleted. On a terminal, without <name> the ` + spec.plural + `
of the selected accounts are offered, and several of one name are a pick.`
}

func scopeHelp(spec componentSpec) string {
	if spec.zonal {
		return "--zone"
	}
	return "--region or --global"
}

func componentGetCmd(rt *app.Runtime, spec componentSpec) *cobra.Command {
	var query func() (componentQuery, error)
	cmd := &cobra.Command{
		Use:   "get <name>",
		Short: "Show a " + string(spec.kind),
		Long: "Show a " + string(spec.kind) + `, read live. Every selected GCP account is searched for
the name (` + scopeHelp(spec) + ` narrows the search). Several matches are exit code 5,
naming the flags that choose (a terminal lets you choose), none is exit
code 4. On a terminal, without <name> the ` + spec.plural + ` of
the selected accounts are offered.`,
		Example: spec.example,
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			q, err := query()
			if err != nil {
				return err
			}
			l, err := componentArg(ctx, rt, spec, args, q)
			if err != nil {
				return err
			}
			v, g := spec.detail(ctx, l)
			g.Rows = append(g.Rows, []string{"project", l.c.project})
			return rt.Render(withProject(v, l.c.project), func() output.Grid { return g })
		},
	}
	query = queryFlags(cmd, spec, string(spec.kind))
	return cmd
}

func componentDeleteCmd(rt *app.Runtime, spec componentSpec) *cobra.Command {
	var query func() (componentQuery, error)
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a " + string(spec.kind) + " nothing uses (asks first)",
		Long:  deleteHelp(spec),
		Args:  app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			q, err := query()
			if err != nil {
				return err
			}
			if timeout <= 0 {
				return app.UsageErrf("--timeout must be a positive duration, got %s", timeout)
			}
			l, err := componentArg(ctx, rt, spec, args, q)
			if err != nil {
				return err
			}
			res := string(spec.kind) + "/" + l.name
			rt.Infof("%s (%s, gcp/%s, project %s)", res, l.where(), l.profile, l.c.project)
			if _, g := spec.detail(ctx, l); len(g.Rows) > 0 {
				for _, r := range g.Rows {
					rt.Infof("  %s", strings.Join(r, "  "))
				}
			}
			target := platform.Target{Platform: platform.GCP, Profile: l.profile, Project: l.c.project, Region: l.region, Zone: l.zone}
			change := platform.Change{Resource: res, Action: platform.Deleted, Detail: l.where()}
			if done, err := rt.WouldWrite(target, change); done || err != nil {
				return err
			}
			ok, err := rt.Confirm(ctx, fmt.Sprintf("Delete %s %s (%s, project %s)?", spec.kind, l.name, l.where(), l.c.project), false)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("%w: cancelled; %s %s was not deleted", platform.ErrNothingToDo, spec.kind, l.name)
			}
			if spec.kind == kindInstanceGroup {
				err = l.c.deleteInstanceGroup(ctx, l.zone, l.name, timeout)
			} else {
				err = (certScope{c: l.c, region: l.region, timeout: timeout}).deleteComponent(ctx, spec.kind, l.name)
			}
			if err != nil {
				if isReason(err, reasonInUse) {
					by := inUseByRef(err)
					return fmt.Errorf("%s is used by %s: delete %s first", res, by, by)
				}
				return err
			}
			if spec.kind == kindRule {
				if db, derr := rt.DB(); derr == nil {
					_ = db.Delete(ctx, inventorySetLB(l.profile), platform.ResLoadBalancer, l.c.ruleOf(l.obj.(*compute.ForwardingRule)).inventoryID())
				}
			}
			rt.Infof("deleted %s in project %s via gcp/%s", res, l.c.project, l.profile)
			return rt.RenderReport(platform.Report{Target: target, Changes: []platform.Change{change}})
		},
	}
	query = queryFlags(cmd, spec, string(spec.kind))
	cmd.Flags().DurationVar(&timeout, "timeout", app.DefaultWaitTimeout, "upper bound of the wait for the deletion (a Go duration such as 90s or 10m)")
	return cmd
}

// ---------------------------------------------------------------- kinds

func newBackendServiceCmd(rt *app.Runtime) *cobra.Command {
	return newComponentCmd(rt, componentSpec{kind: kindBackendService, use: "backend-service", plural: "backend services",
		short:   "Backend services of load balancers (regional and global)",
		usedBy:  "a URL map, a target proxy or a forwarding rule",
		headers: []string{"NAME", "SCOPE", "REGION", "PROTOCOL", "SCHEME", "PORT-NAME", "HEALTH-CHECKS", "BACKENDS"},
		example: "  polyctl gcp compute backend-service get bs-web-1 --region <region>",
		row: func(x component) (any, []string) {
			v := backendViewOf(x.obj.(*compute.BackendService))
			var groups []string
			for _, b := range v.Backends {
				groups = append(groups, b.Group)
			}
			return v, []string{v.Name, v.Scope, dash(v.Region), v.Protocol, v.Scheme, dash(v.PortName), dash(strings.Join(v.HealthChecks, ",")), dash(strings.Join(groups, ","))}
		},
		detail: func(ctx context.Context, l *located) (any, output.Grid) {
			bs := l.obj.(*compute.BackendService)
			v := backendViewOf(bs)
			v.withHealth(ctx, l.c, bs)
			kv := []string{"name", v.Name, "scope", v.Scope, "region", dash(v.Region), "protocol", v.Protocol, "scheme", v.Scheme,
				"port_name", dash(v.PortName), "health_checks", dash(strings.Join(v.HealthChecks, ",")), "health", v.Health}
			for _, b := range v.Backends {
				kv = append(kv, "backend "+b.Group, dash(strings.Join(b.Health, ",")))
			}
			return v, output.KV(kv...)
		},
	})
}

func newForwardingRuleCmd(rt *app.Runtime) *cobra.Command {
	return newComponentCmd(rt, componentSpec{kind: kindRule, use: "forwarding-rule", plural: "forwarding rules",
		short:   "Forwarding rules of load balancers (regional and global)",
		headers: []string{"NAME", "SCOPE", "REGION", "IP", "PORT", "PROTOCOL", "SCHEME", "TARGET"},
		example: "  polyctl gcp compute forwarding-rule get fr-web-1",
		row: func(x component) (any, []string) {
			v := ruleRowOf(x.obj.(*compute.ForwardingRule))
			target := v.Target
			if target == "" {
				target = v.Backend
			}
			return v, []string{v.Name, v.Scope, dash(v.Region), v.IPAddress, v.Port, v.IPProtocol, v.Scheme, dash(target)}
		},
		detail: func(_ context.Context, l *located) (any, output.Grid) {
			v := ruleRowOf(l.obj.(*compute.ForwardingRule))
			return v, output.KV("name", v.Name, "scope", v.Scope, "region", dash(v.Region), "ip_address", v.IPAddress, "port", v.Port,
				"ip_protocol", v.IPProtocol, "scheme", v.Scheme, "target", dash(v.Target), "backend_service", dash(v.Backend),
				"network", dash(v.Network), "network_tier", dash(v.NetworkTier), "load_balancer", dash(v.LoadBalancer))
		},
	})
}

func newHealthCheckCmd(rt *app.Runtime) *cobra.Command {
	return newComponentCmd(rt, componentSpec{kind: kindHealthCheck, use: "health-check", plural: "health checks",
		short:   "Health checks of load balancers (regional and global)",
		usedBy:  "a backend service",
		headers: []string{"NAME", "SCOPE", "REGION", "TYPE", "PORT", "INTERVAL", "TIMEOUT"},
		example: "  polyctl gcp compute health-check get check-80 --region <region>",
		row: func(x component) (any, []string) {
			v := healthCheckRowOf(x.obj.(*compute.HealthCheck))
			return v, []string{v.Name, v.Scope, dash(v.Region), v.Type, dash(v.Port), strconv.FormatInt(v.Interval, 10) + "s", strconv.FormatInt(v.Timeout, 10) + "s"}
		},
		detail: func(_ context.Context, l *located) (any, output.Grid) {
			v := healthCheckRowOf(l.obj.(*compute.HealthCheck))
			return v, output.KV("name", v.Name, "scope", v.Scope, "region", dash(v.Region), "type", v.Type, "port", dash(v.Port),
				"check_interval_sec", strconv.FormatInt(v.Interval, 10), "timeout_sec", strconv.FormatInt(v.Timeout, 10),
				"healthy_threshold", strconv.FormatInt(v.Healthy, 10), "unhealthy_threshold", strconv.FormatInt(v.Unhealty, 10))
		},
	})
}

func newInstanceGroupCmd(rt *app.Runtime) *cobra.Command {
	return newComponentCmd(rt, componentSpec{kind: kindInstanceGroup, use: "instance-group", plural: "instance groups", zonal: true,
		short:   "Unmanaged instance groups (zonal) behind load balancers",
		usedBy:  "a backend service",
		headers: []string{"NAME", "ZONE", "SIZE", "NAMED-PORTS", "NETWORK"},
		example: "  polyctl gcp compute instance-group get ig-web-1 --zone <zone>",
		row: func(x component) (any, []string) {
			v := groupRowOf(x.obj.(*compute.InstanceGroup))
			return v, []string{v.Name, v.Zone, strconv.FormatInt(v.Size, 10), dash(strings.Join(v.NamedPorts, ",")), dash(v.Network)}
		},
		detail: func(ctx context.Context, l *located) (any, output.Grid) {
			d := groupDetailOf(ctx, l.c, l.obj.(*compute.InstanceGroup))
			var members []string
			for _, m := range d.Members {
				members = append(members, m.Instance+" ("+dash(m.Status)+")")
			}
			return d, output.KV("name", d.Name, "zone", d.Zone, "size", strconv.FormatInt(d.Size, 10), "named_ports", dash(strings.Join(d.NamedPorts, ",")),
				"network", dash(d.Network), "members", dash(strings.Join(members, ", ")))
		},
	})
}

// withProject returns the row v (a struct) with its Project field set.
func withProject(v any, project string) any {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Struct {
		return v
	}
	cp := reflect.New(rv.Type()).Elem()
	cp.Set(rv)
	if f := cp.FieldByName("Project"); f.IsValid() && f.Kind() == reflect.String && f.CanSet() {
		f.SetString(project)
	}
	return cp.Interface()
}
