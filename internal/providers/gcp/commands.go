package gcp

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// Command returns the `polyctl gcp` command tree.
func Command(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gcp",
		Short: "Google Cloud native commands",
		Long: `Google Cloud commands that follow the platform's own model: Cloud DNS managed
zones hold multi-value record sets, Compute Engine instances live in zones.
Every command runs against the project stored in the active gcp profile
(pass --profile to pick another one).`,
	}
	cmd.AddCommand(newProjectCmd(rt), newDNSCmd(rt), newComputeCmd(rt))
	return cmd
}

// openClient opens the gcp profile and returns the concrete client.
func openClient(ctx context.Context, rt *app.Runtime) (*client, platform.Profile, error) {
	if rt.Flags.Offline {
		return nil, platform.Profile{}, app.ErrOffline
	}
	c, prof, err := rt.OpenFor(ctx, platform.GCP)
	if err != nil {
		return nil, prof, err
	}
	gc, ok := c.(*client)
	if !ok {
		return nil, prof, fmt.Errorf("unexpected client type %T for gcp", c)
	}
	return gc, prof, nil
}

// ---------------------------------------------------------------- project

func newProjectCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "project", Short: "Google Cloud projects"}
	cmd.AddCommand(newProjectListCmd(rt), newProjectCurrentCmd(rt))
	return cmd
}

type projectRow struct {
	ProjectID string `json:"project_id" yaml:"project_id"`
	Name      string `json:"name" yaml:"name"`
	Number    int64  `json:"project_number" yaml:"project_number"`
	State     string `json:"state" yaml:"state"`
}

func newProjectListCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the active projects visible to the profile's credentials",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, prof, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			projects, err := c.ListProjects(cmd.Context())
			if err != nil {
				return err
			}
			rows := make([]projectRow, 0, len(projects))
			for _, p := range projects {
				rows = append(rows, projectRow{ProjectID: p.ProjectId, Name: p.Name, Number: p.ProjectNumber, State: p.LifecycleState})
			}
			rt.Infof("%d project(s) via gcp/%s", len(rows), prof.Name)
			return rt.Render(rows, func() output.Grid {
				g := output.Grid{Headers: []string{"PROJECT_ID", "NAME", "NUMBER", "STATE"}, Empty: "no projects"}
				for _, r := range rows {
					marker := ""
					if r.ProjectID == c.project {
						marker = " *"
					}
					g.Rows = append(g.Rows, []string{r.ProjectID + marker, r.Name, fmt.Sprint(r.Number), r.State})
				}
				return g
			})
		},
	}
}

type currentProject struct {
	Profile string `json:"profile" yaml:"profile"`
	Project string `json:"project" yaml:"project"`
	Method  string `json:"method" yaml:"method"`
	Account string `json:"account,omitempty" yaml:"account,omitempty"`
}

func newProjectCurrentCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "current",
		Short: "Show the project the active gcp profile operates on",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := rt.ProfileFor(platform.GCP)
			if err != nil {
				return err
			}
			cfg, err := rt.Config()
			if err != nil {
				return err
			}
			p, err := cfg.Profile(name)
			if err != nil {
				return err
			}
			account := p.Metadata["email"]
			if account == "" {
				account = p.Metadata["client_email"]
			}
			cur := currentProject{Profile: name, Project: p.Metadata["project"], Method: p.Metadata["method"], Account: account}
			return rt.Render(cur, func() output.Grid {
				return output.KV("profile", cur.Profile, "project", cur.Project, "method", cur.Method, "account", cur.Account)
			})
		},
	}
}

// ---------------------------------------------------------------- dns

func newDNSCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "dns", Short: "Cloud DNS managed zones and record sets"}
	zone := &cobra.Command{Use: "zone", Short: "Managed zones"}
	zone.AddCommand(newZoneListCmd(rt), newZoneGetCmd(rt))
	record := &cobra.Command{Use: "record", Short: "Record sets of a managed zone"}
	record.AddCommand(newRecordListCmd(rt), newRecordUpsertCmd(rt), newRecordDeleteCmd(rt))
	cmd.AddCommand(zone, record)
	return cmd
}

// zoneRef is a resolved managed zone: its API name and DNS name.
type zoneRef struct {
	ID   string
	Name string
}

// cachedZones serves the zone list through the inventory (honouring
// --refresh / --offline / TTL).
func cachedZones(ctx context.Context, rt *app.Runtime, profile string) ([]platform.Zone, bool, error) {
	set := inventory.Set{Platform: platform.GCP, Profile: profile, Type: platform.ResZone}
	rows, cached, err := rt.EnsureSet(ctx, set, func(ctx context.Context) ([]platform.Resource, error) {
		c, _, err := openClient(ctx, rt)
		if err != nil {
			return nil, err
		}
		return c.Sync(ctx, platform.ResZone)
	})
	if err != nil {
		return nil, cached, err
	}
	zones := make([]platform.Zone, 0, len(rows))
	for _, r := range rows {
		var z platform.Zone
		if err := r.Decode(&z); err != nil {
			return nil, cached, fmt.Errorf("decode cached zone %s: %w", r.ID, err)
		}
		zones = append(zones, z)
	}
	return zones, cached, nil
}

// resolveZone accepts a managed zone name or a DNS name. The inventory is
// consulted first; online, an unknown managed zone name is fetched directly.
func resolveZone(ctx context.Context, rt *app.Runtime, profile, arg string) (*zoneRef, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return nil, fmt.Errorf("zone is required")
	}
	zones, _, err := cachedZones(ctx, rt, profile)
	if err != nil && !errors.Is(err, inventory.ErrNeverSynced) {
		return nil, err
	}
	dnsName := platform.NormalizeDomain(arg)
	for _, z := range zones {
		if z.ID == arg || z.Name == dnsName {
			return &zoneRef{ID: z.ID, Name: z.Name}, nil
		}
	}
	if rt.Flags.Offline || strings.Contains(arg, ".") {
		return nil, fmt.Errorf("%w: managed zone %q in gcp/%s (run with --refresh if it was created recently)", platform.ErrNotFound, arg, profile)
	}
	c, _, err := openClient(ctx, rt)
	if err != nil {
		return nil, err
	}
	z, err := c.GetZone(ctx, arg)
	if err != nil {
		return nil, err
	}
	return &zoneRef{ID: z.ID, Name: z.Name}, nil
}

type zoneResult struct {
	Profile string          `json:"profile" yaml:"profile"`
	Cached  bool            `json:"cached" yaml:"cached"`
	Zones   []platform.Zone `json:"zones" yaml:"zones"`
}

func zoneGrid(zones []platform.Zone) output.Grid {
	g := output.Grid{Headers: []string{"ZONE", "DNS_NAME", "VISIBILITY", "NAMESERVERS", "DESCRIPTION"}, Empty: "no managed zones"}
	for _, z := range zones {
		g.Rows = append(g.Rows, []string{z.ID, z.Name, z.Status, strings.Join(z.Nameservers, ","), output.Str(z.Extra["description"])})
	}
	return g
}

func newZoneListCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List managed zones of the project",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, err := rt.ProfileFor(platform.GCP)
			if err != nil {
				return err
			}
			zones, cached, err := cachedZones(cmd.Context(), rt, profile)
			if err != nil {
				return err
			}
			rt.Infof("%d managed zone(s) via gcp/%s%s", len(zones), profile, cacheNote(cached))
			return rt.Render(zoneResult{Profile: profile, Cached: cached, Zones: zones}, func() output.Grid { return zoneGrid(zones) })
		},
	}
}

func newZoneGetCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get <zone>",
		Short: "Show one managed zone (by managed zone name or DNS name)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, err := rt.ProfileFor(platform.GCP)
			if err != nil {
				return err
			}
			var z *platform.Zone
			cached := false
			if rt.Flags.Offline || !rt.Flags.Refresh {
				zones, fromCache, err := cachedZones(cmd.Context(), rt, profile)
				if err != nil && !errors.Is(err, inventory.ErrNeverSynced) {
					return err
				}
				cached = fromCache
				want := platform.NormalizeDomain(args[0])
				for i := range zones {
					if zones[i].ID == args[0] || zones[i].Name == want {
						z = &zones[i]
						break
					}
				}
			}
			if z == nil {
				if rt.Flags.Offline {
					return fmt.Errorf("%w: managed zone %q in gcp/%s", platform.ErrNotFound, args[0], profile)
				}
				ref, err := resolveZone(cmd.Context(), rt, profile, args[0])
				if err != nil {
					return err
				}
				c, _, err := openClient(cmd.Context(), rt)
				if err != nil {
					return err
				}
				if z, err = c.GetZone(cmd.Context(), ref.ID); err != nil {
					return err
				}
				cached = false
			}
			rt.Infof("zone %s via gcp/%s%s", z.ID, profile, cacheNote(cached))
			return rt.Render(z, func() output.Grid {
				return output.KV(
					"zone", z.ID,
					"dns_name", z.Name,
					"visibility", z.Status,
					"nameservers", strings.Join(z.Nameservers, ","),
					"description", output.Str(z.Extra["description"]),
					"id", output.Str(z.Extra["id"]),
					"dnssec", output.Str(z.Extra["dnssec"]),
					"created", output.Str(z.Extra["creation_time"]),
				)
			})
		},
	}
}

type recordResult struct {
	Profile string            `json:"profile" yaml:"profile"`
	Zone    zoneRef           `json:"zone" yaml:"zone"`
	Cached  bool              `json:"cached" yaml:"cached"`
	Records []platform.Record `json:"records" yaml:"records"`
}

func recordGrid(recs []platform.Record) output.Grid {
	g := output.Grid{Headers: []string{"NAME", "TYPE", "CONTENT", "TTL", "ID"}, Empty: "no records"}
	for _, r := range recs {
		content := r.Content
		if r.Priority != nil {
			content = fmt.Sprintf("%d %s", *r.Priority, r.Content)
		}
		g.Rows = append(g.Rows, []string{r.Name, r.Type, content, platform.TTLLabel(platform.GCP, r), r.ID})
	}
	return g
}

func sortRecords(recs []platform.Record) {
	sort.SliceStable(recs, func(i, j int) bool {
		if recs[i].Name != recs[j].Name {
			return recs[i].Name < recs[j].Name
		}
		if recs[i].Type != recs[j].Type {
			return recs[i].Type < recs[j].Type
		}
		return recs[i].Content < recs[j].Content
	})
}

// cachedRecords serves one zone's records through the inventory.
func cachedRecords(ctx context.Context, rt *app.Runtime, profile string, z *zoneRef) ([]platform.Record, bool, error) {
	set := inventory.Set{Platform: platform.GCP, Profile: profile, Type: platform.ResDNSRecord, Scope: z.ID}
	rows, cached, err := rt.EnsureSet(ctx, set, func(ctx context.Context) ([]platform.Resource, error) {
		c, _, err := openClient(ctx, rt)
		if err != nil {
			return nil, err
		}
		recs, err := c.ListRecords(ctx, z.ID)
		if err != nil {
			return nil, err
		}
		return app.RecordResources(z.ID, z.Name, recs), nil
	})
	if err != nil {
		return nil, cached, err
	}
	recs := make([]platform.Record, 0, len(rows))
	for _, r := range rows {
		var rec platform.Record
		if err := r.Decode(&rec); err != nil {
			return nil, cached, fmt.Errorf("decode cached record %s: %w", r.ID, err)
		}
		recs = append(recs, rec)
	}
	return recs, cached, nil
}

// refreshRecords re-reads a zone after a mutation so the inventory matches.
func refreshRecords(ctx context.Context, rt *app.Runtime, c *client, profile string, z *zoneRef) {
	recs, err := c.ListRecords(ctx, z.ID)
	if err != nil {
		rt.Verbosef("warning: refresh inventory for zone %s: %v", z.ID, err)
		return
	}
	db, err := rt.DB()
	if err != nil {
		return
	}
	cfg, _ := rt.Config()
	set := inventory.Set{Platform: platform.GCP, Profile: profile, Type: platform.ResDNSRecord, Scope: z.ID}
	if err := db.Replace(ctx, set, app.RecordResources(z.ID, z.Name, recs), cfg.TTLFor(platform.ResDNSRecord)); err != nil {
		rt.Verbosef("warning: update inventory for zone %s: %v", z.ID, err)
	}
}

func newRecordListCmd(rt *app.Runtime) *cobra.Command {
	var typ, name string
	cmd := &cobra.Command{
		Use:   "list <zone>",
		Short: "List record values of a managed zone (one row per value)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, err := rt.ProfileFor(platform.GCP)
			if err != nil {
				return err
			}
			z, err := resolveZone(cmd.Context(), rt, profile, args[0])
			if err != nil {
				return err
			}
			recs, cached, err := cachedRecords(cmd.Context(), rt, profile, z)
			if err != nil {
				return err
			}
			if name != "" {
				recs = app.MatchRecords(recs, platform.FQDN(name, z.Name), typ, "")
			} else if typ != "" {
				var f []platform.Record
				for _, r := range recs {
					if strings.EqualFold(r.Type, typ) {
						f = append(f, r)
					}
				}
				recs = f
			}
			sortRecords(recs)
			rt.Infof("zone %s (%s) via gcp/%s%s", z.ID, z.Name, profile, cacheNote(cached))
			return rt.Render(recordResult{Profile: profile, Zone: *z, Cached: cached, Records: recs}, func() output.Grid { return recordGrid(recs) })
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "filter by record type")
	cmd.Flags().StringVar(&name, "name", "", "filter by record name (relative, @ or FQDN)")
	return cmd
}

func newRecordUpsertCmd(rt *app.Runtime) *cobra.Command {
	var typ, name string
	var values []string
	var ttl, priority int
	cmd := &cobra.Command{
		Use:   "upsert <zone>",
		Short: "Create or replace a record set (--value may repeat; the set becomes exactly these values)",
		Long: `Create or replace the record set identified by --name and --type. Cloud DNS
stores all values of a name/type pair in one set; this command makes the set
equal to the given --value list (repeat --value for multi-value sets).

MX and SRV values take the priority from --priority, or as a leading number
inside the value ("10 mail.example.com"). Hostnames get the trailing dot
Cloud DNS expects; TXT values are quoted automatically.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if typ == "" || len(values) == 0 {
				return app.UsageErrf("--type and at least one --value are required")
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			profile, err := rt.ProfileFor(platform.GCP)
			if err != nil {
				return err
			}
			z, err := resolveZone(cmd.Context(), rt, profile, args[0])
			if err != nil {
				return err
			}
			typ = strings.ToUpper(typ)
			fqdn := platform.FQDN(name, z.Name)
			raw := make([]string, 0, len(values))
			for _, v := range values {
				rec := platform.Record{Name: fqdn, Type: typ, Content: v}
				if cmd.Flags().Changed("priority") {
					p := priority
					rec.Priority = &p
				}
				rd, err := rrdataFromRecord(rec)
				if err != nil {
					return err
				}
				raw = append(raw, rd)
			}
			c, _, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			if err := c.SetRRSet(cmd.Context(), z.ID, fqdn, typ, int64(ttl), raw); err != nil {
				return err
			}
			rs, err := c.getRRSet(cmd.Context(), z.ID, dnsName(fqdn), typ)
			if err != nil {
				return err
			}
			recs := recordsFromRRSet(z.ID, rs)
			refreshRecords(cmd.Context(), rt, c, profile, z)
			rt.Infof("set %s %s to %d value(s) in zone %s via gcp/%s", fqdn, typ, len(recs), z.ID, profile)
			return rt.Render(recordResult{Profile: profile, Zone: *z, Records: recs}, func() output.Grid { return recordGrid(recs) })
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "record type (A, AAAA, CNAME, TXT, MX, ...)")
	cmd.Flags().StringVar(&name, "name", "", "record name relative to the zone (www, @) or FQDN; default: the zone apex")
	cmd.Flags().StringArrayVar(&values, "value", nil, "record value (repeat for multiple values)")
	cmd.Flags().IntVar(&ttl, "ttl", 0, "TTL in seconds (0 = keep existing, or 300 for a new set)")
	cmd.Flags().IntVar(&priority, "priority", 0, "priority for MX/SRV records")
	return cmd
}

func newRecordDeleteCmd(rt *app.Runtime) *cobra.Command {
	var typ, name, value, id string
	var priority int
	cmd := &cobra.Command{
		Use:   "delete <zone>",
		Short: "Delete a record set (--name --type), one value of it (--value) or a record by --id",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id == "" && (typ == "" || name == "") {
				return app.UsageErrf("--name and --type (or --id) are required")
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			profile, err := rt.ProfileFor(platform.GCP)
			if err != nil {
				return err
			}
			z, err := resolveZone(cmd.Context(), rt, profile, args[0])
			if err != nil {
				return err
			}
			c, _, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			var what string
			switch {
			case id != "":
				if err := c.DeleteRecord(cmd.Context(), z.ID, id); err != nil {
					return err
				}
				what = id
			case value != "":
				rec := platform.Record{Name: platform.FQDN(name, z.Name), Type: typ, Content: value}
				if cmd.Flags().Changed("priority") {
					p := priority
					rec.Priority = &p
				}
				raw, err := rrdataFromRecord(rec)
				if err != nil {
					return err
				}
				rid := encodeRecordID(z.ID, typ, rec.Name, raw)
				if err := c.DeleteRecord(cmd.Context(), z.ID, rid); err != nil {
					return err
				}
				what = fmt.Sprintf("%s %s value %q", rec.Name, strings.ToUpper(typ), raw)
			default:
				fqdn := platform.FQDN(name, z.Name)
				if err := c.DeleteRRSet(cmd.Context(), z.ID, fqdn, typ); err != nil {
					return err
				}
				what = fmt.Sprintf("record set %s %s", fqdn, strings.ToUpper(typ))
			}
			refreshRecords(cmd.Context(), rt, c, profile, z)
			rt.Infof("deleted %s in zone %s via gcp/%s", what, z.ID, profile)
			return rt.Render(map[string]string{"deleted": what, "zone": z.ID, "profile": profile}, func() output.Grid { return output.Grid{} })
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "record type")
	cmd.Flags().StringVar(&name, "name", "", "record name relative to the zone (www, @) or FQDN; default: the zone apex")
	cmd.Flags().StringVar(&value, "value", "", "only remove this value from the set")
	cmd.Flags().IntVar(&priority, "priority", 0, "priority of the MX/SRV value given with --value")
	cmd.Flags().StringVar(&id, "id", "", "delete the record value with this id (zone|TYPE|name|value)")
	return cmd
}

// ---------------------------------------------------------------- compute

func newComputeCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "compute", Short: "Compute Engine instances"}
	cmd.AddCommand(newComputeListCmd(rt), newComputePowerCmd(rt, "start"), newComputePowerCmd(rt, "stop"))
	return cmd
}

type instanceResult struct {
	Profile   string     `json:"profile" yaml:"profile"`
	Cached    bool       `json:"cached" yaml:"cached"`
	Instances []Instance `json:"instances" yaml:"instances"`
}

// cachedInstances serves the instance list through the inventory.
func cachedInstances(ctx context.Context, rt *app.Runtime, profile string) ([]Instance, bool, error) {
	set := inventory.Set{Platform: platform.GCP, Profile: profile, Type: platform.ResInstance}
	rows, cached, err := rt.EnsureSet(ctx, set, func(ctx context.Context) ([]platform.Resource, error) {
		c, _, err := openClient(ctx, rt)
		if err != nil {
			return nil, err
		}
		return c.ListInstances(ctx)
	})
	if err != nil {
		return nil, cached, err
	}
	out := make([]Instance, 0, len(rows))
	for _, r := range rows {
		var in Instance
		if err := r.Decode(&in); err != nil {
			return nil, cached, fmt.Errorf("decode cached instance %s: %w", r.ID, err)
		}
		out = append(out, in)
	}
	return out, cached, nil
}

func newComputeListCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List Compute Engine instances across all zones",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, err := rt.ProfileFor(platform.GCP)
			if err != nil {
				return err
			}
			list, cached, err := cachedInstances(cmd.Context(), rt, profile)
			if err != nil {
				return err
			}
			sort.Slice(list, func(i, j int) bool {
				if list[i].Zone != list[j].Zone {
					return list[i].Zone < list[j].Zone
				}
				return list[i].Name < list[j].Name
			})
			rt.Infof("%d instance(s) via gcp/%s%s", len(list), profile, cacheNote(cached))
			return rt.Render(instanceResult{Profile: profile, Cached: cached, Instances: list}, func() output.Grid {
				g := output.Grid{Headers: []string{"NAME", "ZONE", "MACHINE_TYPE", "STATUS", "INTERNAL_IP", "EXTERNAL_IP", "ID"}, Empty: "no instances"}
				for _, in := range list {
					g.Rows = append(g.Rows, []string{in.Name, in.Zone, in.MachineType, in.Status, in.InternalIP, in.ExternalIP, in.ID})
				}
				return g
			})
		},
	}
}

func newComputePowerCmd(rt *app.Runtime, verb string) *cobra.Command {
	var zone string
	var wait bool
	cmd := &cobra.Command{
		Use:   verb + " <instance>",
		Short: strings.ToUpper(verb[:1]) + verb[1:] + " an instance",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			profile, err := rt.ProfileFor(platform.GCP)
			if err != nil {
				return err
			}
			instance := args[0]
			if zone == "" {
				// Fall back to the cached inventory to find the instance's zone.
				list, _, err := cachedInstances(cmd.Context(), rt, profile)
				if err != nil && !errors.Is(err, inventory.ErrNeverSynced) {
					return err
				}
				var zones []string
				zone, instance, zones = locateInstance(list, instance)
				switch {
				case zone != "":
				case len(zones) == 0:
					return fmt.Errorf("--zone is required (instance %q is not in the local inventory)", instance)
				default:
					return &app.AmbiguousError{What: "zone of instance " + instance, Candidates: zones}
				}
			}
			c, _, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			var res *OperationResult
			if verb == "start" {
				res, err = c.StartInstance(cmd.Context(), zone, instance, wait)
			} else {
				res, err = c.StopInstance(cmd.Context(), zone, instance, wait)
			}
			if err != nil {
				return err
			}
			rt.Infof("%s %s in %s: operation %s is %s via gcp/%s", verb, instance, zone, res.Operation, res.Status, profile)
			return rt.Render(res, func() output.Grid {
				return output.KV("instance", res.Instance, "zone", res.Zone, "operation", res.Operation, "type", res.Type, "status", res.Status)
			})
		},
	}
	cmd.Flags().StringVar(&zone, "zone", "", "Compute Engine zone of the instance (looked up in the inventory when omitted)")
	cmd.Flags().BoolVar(&wait, "wait", false, "wait until the operation completes")
	return cmd
}

// locateInstance resolves an instance argument (numeric id or name) against
// the cached inventory. An id is unique in a project and wins outright; a
// name may exist in several zones, in which case zone is empty and
// candidates lists every zone that has an instance of that name.
func locateInstance(list []Instance, arg string) (zone, name string, candidates []string) {
	for _, in := range list {
		if in.ID == arg {
			return in.Zone, in.Name, nil
		}
	}
	for _, in := range list {
		if in.Name == arg {
			candidates = append(candidates, in.Zone)
		}
	}
	if len(candidates) == 1 {
		return candidates[0], arg, nil
	}
	return "", arg, candidates
}

func cacheNote(cached bool) string {
	if cached {
		return " (local inventory)"
	}
	return ""
}
