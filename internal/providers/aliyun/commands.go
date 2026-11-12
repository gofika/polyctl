package aliyun

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// Command returns the `polyctl aliyun` command tree.
func Command(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "aliyun",
		Short: "Alibaba Cloud native commands",
		Long: `Alibaba Cloud native commands: STS identity, Alibaba Cloud DNS (alidns)
domains and records, the domain registrar and ECS instances. The profile is
chosen with --profile (or the current/only aliyun profile); listing commands
read the local inventory unless --refresh is given or the data has expired.`,
	}
	cmd.AddCommand(newSTSCmd(rt), newDNSCmd(rt), newDomainCmd(rt), newECSCmd(rt))
	return cmd
}

// openClient opens the aliyun client for the selected profile.
func openClient(rt *app.Runtime, ctx context.Context) (*client, platform.Profile, error) {
	c, p, err := rt.OpenFor(ctx, platform.Aliyun)
	if err != nil {
		return nil, p, err
	}
	ac, ok := c.(*client)
	if !ok {
		return nil, p, fmt.Errorf("profile %q did not open an Alibaba Cloud client", p.Name)
	}
	return ac, p, nil
}

// openNamed opens a specific profile (used inside EnsureSet fetch callbacks).
func openNamed(rt *app.Runtime, ctx context.Context, name string) (*client, error) {
	c, _, err := rt.Open(ctx, name, platform.Aliyun)
	if err != nil {
		return nil, err
	}
	ac, ok := c.(*client)
	if !ok {
		return nil, fmt.Errorf("profile %q did not open an Alibaba Cloud client", name)
	}
	return ac, nil
}

func cacheNote(cached bool) string {
	if cached {
		return " (local inventory)"
	}
	return ""
}

func mustPositive(flag string, v int) error {
	if v < 0 {
		return fmt.Errorf("--%s must not be negative", flag)
	}
	return nil
}

// ---- sts -------------------------------------------------------------------

func newSTSCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "sts", Short: "Security Token Service"}
	cmd.AddCommand(&cobra.Command{
		Use:   "whoami",
		Short: "Show the identity behind the profile's AccessKey (GetCallerIdentity)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, p, err := openClient(rt, cmd.Context())
			if err != nil {
				return err
			}
			id, err := c.Verify(cmd.Context())
			if err != nil {
				return err
			}
			rt.Infof("profile %s", p.Name)
			return rt.Render(id, func() output.Grid {
				pairs := []string{"ACCOUNT", id.Account, "ARN", id.User}
				keys := make([]string, 0, len(id.Extra))
				for k := range id.Extra {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					pairs = append(pairs, strings.ToUpper(k), id.Extra[k])
				}
				return output.KV(pairs...)
			})
		},
	})
	return cmd
}

// ---- dns -------------------------------------------------------------------

type zoneList struct {
	Profile string          `json:"profile" yaml:"profile"`
	Cached  bool            `json:"cached" yaml:"cached"`
	Zones   []platform.Zone `json:"zones" yaml:"zones"`
}

type recordList struct {
	Profile string            `json:"profile" yaml:"profile"`
	Zone    string            `json:"zone" yaml:"zone"`
	Cached  bool              `json:"cached" yaml:"cached"`
	Records []platform.Record `json:"records" yaml:"records"`
}

func newDNSCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "dns", Short: "Alibaba Cloud DNS (alidns) domains and records"}
	domain := &cobra.Command{Use: "domain", Short: "DNS domains hosted on alidns"}
	domain.AddCommand(newDNSDomainListCmd(rt))
	record := &cobra.Command{Use: "record", Short: "Records of an alidns domain"}
	record.AddCommand(newDNSRecordListCmd(rt), newDNSRecordAddCmd(rt), newDNSRecordUpdateCmd(rt), newDNSRecordDeleteCmd(rt))
	cmd.AddCommand(domain, record)
	return cmd
}

func newDNSDomainListCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List DNS domains (zones) hosted on alidns",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := rt.ProfileFor(platform.Aliyun)
			if err != nil {
				return err
			}
			set := inventory.Set{Platform: platform.Aliyun, Profile: name, Type: platform.ResZone}
			rows, cached, err := rt.EnsureSet(cmd.Context(), set, func(ctx context.Context) ([]platform.Resource, error) {
				c, err := openNamed(rt, ctx, name)
				if err != nil {
					return nil, err
				}
				zones, err := c.ListZones(ctx)
				if err != nil {
					return nil, err
				}
				return app.ZoneResources(zones), nil
			})
			if err != nil {
				return err
			}
			zones := make([]platform.Zone, 0, len(rows))
			for _, r := range rows {
				var z platform.Zone
				if err := r.Decode(&z); err != nil {
					return fmt.Errorf("decode cached zone %s: %w", r.ID, err)
				}
				zones = append(zones, z)
			}
			rt.Infof("%d domain(s) via aliyun/%s%s", len(zones), name, cacheNote(cached))
			return rt.Render(zoneList{Profile: name, Cached: cached, Zones: zones}, func() output.Grid {
				g := output.Grid{Headers: []string{"DOMAIN", "VERSION", "RECORDS", "NAMESERVERS"}, Empty: "no domains"}
				for _, z := range zones {
					g.Rows = append(g.Rows, []string{z.Name, z.Status, output.Str(z.Extra["record_count"]), strings.Join(z.Nameservers, ",")})
				}
				return g
			})
		},
	}
}

func recordGrid(recs []platform.Record) output.Grid {
	g := output.Grid{Headers: []string{"NAME", "TYPE", "CONTENT", "TTL", "LINE", "STATUS", "ID"}, Empty: "no records"}
	for _, r := range recs {
		content := r.Content
		if r.Priority != nil {
			content = fmt.Sprintf("%d %s", *r.Priority, r.Content)
		}
		g.Rows = append(g.Rows, []string{r.Name, r.Type, content, platform.TTLLabel(platform.Aliyun, r), output.Str(r.Extra["line"]), output.Str(r.Extra["status"]), r.ID})
	}
	return g
}

func newDNSRecordListCmd(rt *app.Runtime) *cobra.Command {
	var typ, name string
	cmd := &cobra.Command{
		Use:   "list <domain>",
		Short: "List the records of an alidns domain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			zone := platform.NormalizeDomain(args[0])
			prof, err := rt.ProfileFor(platform.Aliyun)
			if err != nil {
				return err
			}
			set := inventory.Set{Platform: platform.Aliyun, Profile: prof, Type: platform.ResDNSRecord, Scope: zone}
			rows, cached, err := rt.EnsureSet(cmd.Context(), set, func(ctx context.Context) ([]platform.Resource, error) {
				c, err := openNamed(rt, ctx, prof)
				if err != nil {
					return nil, err
				}
				recs, err := c.ListRecords(ctx, zone)
				if err != nil {
					return nil, err
				}
				return app.RecordResources(zone, zone, recs), nil
			})
			if err != nil {
				return err
			}
			recs := make([]platform.Record, 0, len(rows))
			for _, r := range rows {
				var rec platform.Record
				if err := r.Decode(&rec); err != nil {
					return fmt.Errorf("decode cached record %s: %w", r.ID, err)
				}
				recs = append(recs, rec)
			}
			if name != "" {
				recs = app.MatchRecords(recs, platform.FQDN(name, zone), typ, "")
			} else if typ != "" {
				var f []platform.Record
				for _, r := range recs {
					if strings.EqualFold(r.Type, typ) {
						f = append(f, r)
					}
				}
				recs = f
			}
			sort.SliceStable(recs, func(i, j int) bool {
				if recs[i].Name != recs[j].Name {
					return recs[i].Name < recs[j].Name
				}
				return recs[i].Type < recs[j].Type
			})
			rt.Infof("%d record(s) in %s via aliyun/%s%s", len(recs), zone, prof, cacheNote(cached))
			return rt.Render(recordList{Profile: prof, Zone: zone, Cached: cached, Records: recs}, func() output.Grid {
				return recordGrid(recs)
			})
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "filter by record type")
	cmd.Flags().StringVar(&name, "name", "", "filter by record name (relative, @ or FQDN)")
	return cmd
}

// upsertRecord mirrors a mutated record into the inventory.
func upsertRecord(rt *app.Runtime, ctx context.Context, prof, zone string, rec platform.Record) {
	db, err := rt.DB()
	if err != nil {
		return
	}
	cfg, _ := rt.Config()
	_ = db.Upsert(ctx, inventory.Set{Platform: platform.Aliyun, Profile: prof, Type: platform.ResDNSRecord},
		app.RecordResources(zone, zone, []platform.Record{rec})[0], cfg.TTLFor(platform.ResDNSRecord))
}

func newDNSRecordAddCmd(rt *app.Runtime) *cobra.Command {
	var typ, name, value, line string
	var ttl, priority int
	cmd := &cobra.Command{
		Use:   "add <domain>",
		Short: "Add a record to an alidns domain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if typ == "" || value == "" {
				return app.UsageErrf("--type and --value are required")
			}
			if err := mustPositive("ttl", ttl); err != nil {
				return err
			}
			zone := platform.NormalizeDomain(args[0])
			c, p, err := openClient(rt, cmd.Context())
			if err != nil {
				return err
			}
			rec := platform.Record{ZoneID: zone, Name: platform.FQDN(name, zone), Type: strings.ToUpper(typ), Content: value, TTL: ttl}
			if cmd.Flags().Changed("priority") {
				pr := priority
				rec.Priority = &pr
			}
			if line != "" {
				rec.Extra = map[string]any{"line": line}
			}
			out, err := c.CreateRecord(cmd.Context(), zone, rec)
			if err != nil {
				return err
			}
			upsertRecord(rt, cmd.Context(), p.Name, zone, *out)
			rt.Infof("created %s %s -> %s (id %s) via aliyun/%s", out.Name, out.Type, out.Content, out.ID, p.Name)
			return rt.Render(recordList{Profile: p.Name, Zone: zone, Records: []platform.Record{*out}}, func() output.Grid {
				return recordGrid([]platform.Record{*out})
			})
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "record type (A, AAAA, CNAME, TXT, MX, ...)")
	cmd.Flags().StringVar(&name, "name", "", "record name relative to the domain (www, @); default: the apex")
	cmd.Flags().StringVar(&value, "value", "", "record content")
	cmd.Flags().IntVar(&ttl, "ttl", 0, "TTL in seconds (0 = alidns default, 600)")
	cmd.Flags().IntVar(&priority, "priority", 0, "priority for MX records (1-50)")
	cmd.Flags().StringVar(&line, "line", "", "resolution line (default, telecom, unicom, mobile, oversea, ...)")
	return cmd
}

func newDNSRecordUpdateCmd(rt *app.Runtime) *cobra.Command {
	var id, typ, name, value, line string
	var ttl, priority int
	cmd := &cobra.Command{
		Use:   "update <domain>",
		Short: "Update the record with --id; unset fields keep their current value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id == "" {
				return app.UsageErrf("--id is required")
			}
			if err := mustPositive("ttl", ttl); err != nil {
				return err
			}
			zone := platform.NormalizeDomain(args[0])
			c, p, err := openClient(rt, cmd.Context())
			if err != nil {
				return err
			}
			existing, err := c.ListRecords(cmd.Context(), zone)
			if err != nil {
				return err
			}
			var cur *platform.Record
			for i := range existing {
				if existing[i].ID == id {
					cur = &existing[i]
					break
				}
			}
			if cur == nil {
				return fmt.Errorf("record %s in %s: %w", id, zone, platform.ErrNotFound)
			}
			rec := *cur
			if typ != "" {
				rec.Type = strings.ToUpper(typ)
			}
			if cmd.Flags().Changed("name") {
				rec.Name = platform.FQDN(name, zone)
			}
			if value != "" {
				rec.Content = value
			}
			if cmd.Flags().Changed("ttl") {
				rec.TTL = ttl
			}
			if cmd.Flags().Changed("priority") {
				pr := priority
				rec.Priority = &pr
			}
			if line != "" {
				if rec.Extra == nil {
					rec.Extra = map[string]any{}
				}
				rec.Extra["line"] = line
			}
			out, err := c.UpdateRecord(cmd.Context(), zone, rec)
			if err != nil {
				return err
			}
			upsertRecord(rt, cmd.Context(), p.Name, zone, *out)
			rt.Infof("updated %s %s -> %s (id %s) via aliyun/%s", out.Name, out.Type, out.Content, out.ID, p.Name)
			return rt.Render(recordList{Profile: p.Name, Zone: zone, Records: []platform.Record{*out}}, func() output.Grid {
				return recordGrid([]platform.Record{*out})
			})
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "record id (see 'aliyun dns record list')")
	cmd.Flags().StringVar(&typ, "type", "", "new record type")
	cmd.Flags().StringVar(&name, "name", "", "new record name relative to the domain (www, @)")
	cmd.Flags().StringVar(&value, "value", "", "new record content")
	cmd.Flags().IntVar(&ttl, "ttl", 0, "new TTL in seconds")
	cmd.Flags().IntVar(&priority, "priority", 0, "new priority for MX records")
	cmd.Flags().StringVar(&line, "line", "", "new resolution line")
	return cmd
}

func newDNSRecordDeleteCmd(rt *app.Runtime) *cobra.Command {
	var id string
	cmd := &cobra.Command{
		Use:   "delete <domain>",
		Short: "Delete the record with --id",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id == "" {
				return app.UsageErrf("--id is required")
			}
			zone := platform.NormalizeDomain(args[0])
			c, p, err := openClient(rt, cmd.Context())
			if err != nil {
				return err
			}
			if err := c.DeleteRecord(cmd.Context(), zone, id); err != nil {
				return err
			}
			if db, err := rt.DB(); err == nil {
				_ = db.Delete(cmd.Context(), inventory.Set{Platform: platform.Aliyun, Profile: p.Name}, platform.ResDNSRecord, id)
			}
			rt.Infof("deleted record %s from %s via aliyun/%s", id, zone, p.Name)
			return rt.Render(map[string]string{"profile": p.Name, "zone": zone, "deleted": id}, func() output.Grid { return output.Grid{} })
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "record id (see 'aliyun dns record list')")
	return cmd
}

// ---- domain (registrar) ----------------------------------------------------

type domainList struct {
	Profile string            `json:"profile" yaml:"profile"`
	Cached  bool              `json:"cached" yaml:"cached"`
	Domains []platform.Domain `json:"domains" yaml:"domains"`
}

func newDomainCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "domain", Short: "Registered domains (Alibaba Cloud domain registrar)"}
	ns := &cobra.Command{Use: "ns", Short: "Nameservers of a registered domain"}
	ns.AddCommand(newDomainNSGetCmd(rt), newDomainNSSetCmd(rt))
	cmd.AddCommand(newDomainListCmd(rt), newDomainGetCmd(rt), ns)
	return cmd
}

// nameserversResult is the output of `aliyun domain ns get`.
type nameserversResult struct {
	Profile     string   `json:"profile" yaml:"profile"`
	Cached      bool     `json:"cached" yaml:"cached"`
	Domain      string   `json:"domain" yaml:"domain"`
	Nameservers []string `json:"nameservers" yaml:"nameservers"`
}

func newDomainNSGetCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get <domain>",
		Short: "Show the nameservers of a registered domain (local inventory when fresh or --offline)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := rt.ProfileFor(platform.Aliyun)
			if err != nil {
				return err
			}
			d, cached, err := loadDomain(rt, cmd.Context(), prof, platform.NormalizeDomain(args[0]))
			if err != nil {
				return err
			}
			rt.Infof("domain %s via aliyun/%s%s", d.Name, prof, cacheNote(cached))
			res := nameserversResult{Profile: prof, Cached: cached, Domain: d.Name, Nameservers: d.Nameservers}
			return rt.Render(res, func() output.Grid {
				g := output.Grid{Headers: []string{"NAMESERVER"}, Empty: "no nameservers"}
				for _, n := range d.Nameservers {
					g.Rows = append(g.Rows, []string{n})
				}
				return g
			})
		},
	}
}

func newDomainListCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List domains registered with Alibaba Cloud",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := rt.ProfileFor(platform.Aliyun)
			if err != nil {
				return err
			}
			set := inventory.Set{Platform: platform.Aliyun, Profile: prof, Type: platform.ResDomain}
			rows, cached, err := rt.EnsureSet(cmd.Context(), set, func(ctx context.Context) ([]platform.Resource, error) {
				c, err := openNamed(rt, ctx, prof)
				if err != nil {
					return nil, err
				}
				domains, err := c.ListDomains(ctx)
				if err != nil {
					return nil, err
				}
				return app.DomainResources(domains), nil
			})
			if err != nil {
				return err
			}
			domains := make([]platform.Domain, 0, len(rows))
			for _, r := range rows {
				var d platform.Domain
				if err := r.Decode(&d); err != nil {
					return fmt.Errorf("decode cached domain %s: %w", r.ID, err)
				}
				domains = append(domains, d)
			}
			rt.Infof("%d domain(s) via aliyun/%s%s", len(domains), prof, cacheNote(cached))
			return rt.Render(domainList{Profile: prof, Cached: cached, Domains: domains}, func() output.Grid {
				g := output.Grid{Headers: []string{"DOMAIN", "STATUS", "EXPIRES", "NAMESERVERS"}, Empty: "no domains"}
				for _, d := range domains {
					g.Rows = append(g.Rows, []string{d.Name, d.Status, d.ExpiresAt, strings.Join(d.Nameservers, ",")})
				}
				return g
			})
		},
	}
}

func domainKV(d *platform.Domain) output.Grid {
	pairs := []string{"DOMAIN", d.Name, "STATUS", d.Status, "EXPIRES", d.ExpiresAt, "NAMESERVERS", strings.Join(d.Nameservers, ","),
		"LOCKED", output.Str(d.Locked), "PRIVACY", output.Str(d.Privacy)}
	keys := make([]string, 0, len(d.Extra))
	for k := range d.Extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		pairs = append(pairs, strings.ToUpper(k), output.Str(d.Extra[k]))
	}
	return output.KV(pairs...)
}

// domainDetail is the output of `aliyun domain get`: the domain plus where
// it came from.
type domainDetail struct {
	*platform.Domain `yaml:",inline"`
	Profile          string `json:"profile" yaml:"profile"`
	Cached           bool   `json:"cached" yaml:"cached"`
}

// loadDomain returns the registrar record of a domain from the local
// inventory when it is fresh (or --offline), otherwise from the registrar
// (mirroring it into the inventory).
func loadDomain(rt *app.Runtime, ctx context.Context, prof, name string) (*platform.Domain, bool, error) {
	set := inventory.Set{Platform: platform.Aliyun, Profile: prof, Type: platform.ResDomain}
	need, err := rt.NeedsRefresh(ctx, set)
	if err != nil {
		return nil, false, err
	}
	if need {
		c, err := openNamed(rt, ctx, prof)
		if err != nil {
			return nil, false, err
		}
		d, err := c.GetDomain(ctx, name)
		if err != nil {
			return nil, false, err
		}
		upsertDomain(rt, ctx, prof, d)
		return d, false, nil
	}
	db, err := rt.DB()
	if err != nil {
		return nil, false, err
	}
	r, err := db.Get(ctx, set, platform.ResDomain, name)
	if err != nil {
		return nil, false, fmt.Errorf("domain %s in the local inventory of aliyun/%s: %w", name, prof, err)
	}
	var d platform.Domain
	if err := r.Decode(&d); err != nil {
		return nil, false, fmt.Errorf("decode cached domain %s: %w", name, err)
	}
	return &d, true, nil
}

// upsertDomain mirrors a registrar record into the inventory.
func upsertDomain(rt *app.Runtime, ctx context.Context, prof string, d *platform.Domain) {
	db, err := rt.DB()
	if err != nil {
		return
	}
	cfg, _ := rt.Config()
	_ = db.Upsert(ctx, inventory.Set{Platform: platform.Aliyun, Profile: prof, Type: platform.ResDomain},
		app.DomainResources([]platform.Domain{*d})[0], cfg.TTLFor(platform.ResDomain))
}

func newDomainGetCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get <domain>",
		Short: "Show a registered domain (QueryDomainByDomainName, or the local inventory when fresh)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := rt.ProfileFor(platform.Aliyun)
			if err != nil {
				return err
			}
			d, cached, err := loadDomain(rt, cmd.Context(), prof, platform.NormalizeDomain(args[0]))
			if err != nil {
				return err
			}
			rt.Infof("domain %s via aliyun/%s%s", d.Name, prof, cacheNote(cached))
			return rt.Render(domainDetail{Domain: d, Profile: prof, Cached: cached}, func() output.Grid { return domainKV(d) })
		},
	}
}

func newDomainNSSetCmd(rt *app.Runtime) *cobra.Command {
	var ns []string
	cmd := &cobra.Command{
		Use:   "set <domain>",
		Short: "Replace the nameservers of a registered domain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(ns) == 0 {
				return app.UsageErrf("--ns is required")
			}
			c, p, err := openClient(rt, cmd.Context())
			if err != nil {
				return err
			}
			name := platform.NormalizeDomain(args[0])
			// SetNameservers waits for the registrar task; on ErrTaskPending
			// (or any failure) nothing is mirrored into the inventory.
			if err := c.SetNameservers(cmd.Context(), name, ns); err != nil {
				return err
			}
			rt.Infof("nameservers of %s updated via aliyun/%s", name, p.Name)
			d, err := c.GetDomain(cmd.Context(), name)
			if err != nil {
				return rt.Render(map[string]any{"profile": p.Name, "domain": name, "nameservers": ns}, func() output.Grid {
					return output.KV("DOMAIN", name, "NAMESERVERS", strings.Join(ns, ","))
				})
			}
			upsertDomain(rt, cmd.Context(), p.Name, d)
			return rt.Render(d, func() output.Grid { return domainKV(d) })
		},
	}
	cmd.Flags().StringSliceVar(&ns, "ns", nil, "nameservers, comma separated (ns1.example.com,ns2.example.com)")
	return cmd
}

// ---- ecs -------------------------------------------------------------------

type instanceList struct {
	Profile   string     `json:"profile" yaml:"profile"`
	Region    string     `json:"region,omitempty" yaml:"region,omitempty"`
	Cached    bool       `json:"cached" yaml:"cached"`
	Instances []Instance `json:"instances" yaml:"instances"`
}

func instanceGrid(list []Instance) output.Grid {
	g := output.Grid{Headers: []string{"ID", "NAME", "STATUS", "TYPE", "ZONE", "PRIVATE IP", "PUBLIC IP"}, Empty: "no instances"}
	for _, in := range list {
		g.Rows = append(g.Rows, []string{in.ID, in.Name, in.Status, in.Type, in.Zone, in.PrivateIP, in.PublicIP})
	}
	return g
}

func newECSCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "ecs", Short: "Elastic Compute Service instances"}
	cmd.AddCommand(newECSListCmd(rt), newECSStartCmd(rt), newECSStopCmd(rt))
	return cmd
}

func newECSListCmd(rt *app.Runtime) *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List ECS instances in the profile region (or --region)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := rt.ProfileFor(platform.Aliyun)
			if err != nil {
				return err
			}
			region, err := resolveRegion(rt, prof, region)
			if err != nil {
				return err
			}
			// The set is always scoped to a region: instances are stored with
			// their region as ParentID, and an unscoped read would return the
			// instances of every region listed before.
			set := inventory.Set{Platform: platform.Aliyun, Profile: prof, Type: platform.ResInstance, Scope: region}
			rows, cached, err := rt.EnsureSet(cmd.Context(), set, func(ctx context.Context) ([]platform.Resource, error) {
				c, err := openNamed(rt, ctx, prof)
				if err != nil {
					return nil, err
				}
				return c.ListInstances(ctx, region)
			})
			if err != nil {
				return err
			}
			list := make([]Instance, 0, len(rows))
			for _, r := range rows {
				var in Instance
				if err := r.Decode(&in); err != nil {
					return fmt.Errorf("decode cached instance %s: %w", r.ID, err)
				}
				list = append(list, in)
			}
			rt.Infof("%d instance(s) in %s via aliyun/%s%s", len(list), region, prof, cacheNote(cached))
			return rt.Render(instanceList{Profile: prof, Region: region, Cached: cached, Instances: list}, func() output.Grid {
				return instanceGrid(list)
			})
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

// resolveRegion returns the explicit region or the profile's region
// (metadata "region", else DefaultRegion), as the client would use.
func resolveRegion(rt *app.Runtime, prof, region string) (string, error) {
	if region != "" {
		return region, nil
	}
	cfg, err := rt.Config()
	if err != nil {
		return "", err
	}
	p, err := cfg.Account(prof, platform.Aliyun)
	if err != nil {
		return "", err
	}
	if r := strings.TrimSpace(p.Metadata[metaRegion]); r != "" {
		return r, nil
	}
	return DefaultRegion, nil
}

// refreshInstance re-reads an instance after start/stop and mirrors it into the inventory.
func refreshInstance(rt *app.Runtime, ctx context.Context, c *client, prof, region, id string) *Instance {
	in, err := c.describeInstance(ctx, region, id)
	if err != nil {
		return nil
	}
	if db, err := rt.DB(); err == nil {
		cfg, _ := rt.Config()
		_ = db.Upsert(ctx, inventory.Set{Platform: platform.Aliyun, Profile: prof, Type: platform.ResInstance}, instanceResource(*in), cfg.TTLFor(platform.ResInstance))
	}
	return in
}

func newECSStartCmd(rt *app.Runtime) *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:   "start <instance-id>",
		Short: "Start a stopped ECS instance",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, p, err := openClient(rt, cmd.Context())
			if err != nil {
				return err
			}
			if err := c.StartInstance(cmd.Context(), region, args[0]); err != nil {
				return err
			}
			rt.Infof("start requested for %s via aliyun/%s", args[0], p.Name)
			in := refreshInstance(rt, cmd.Context(), c, p.Name, region, args[0])
			if in == nil {
				return rt.Render(map[string]string{"profile": p.Name, "instance": args[0], "action": "start"}, func() output.Grid {
					return output.KV("INSTANCE", args[0], "ACTION", "start")
				})
			}
			return rt.Render(in, func() output.Grid { return instanceGrid([]Instance{*in}) })
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

func newECSStopCmd(rt *app.Runtime) *cobra.Command {
	var region string
	var force bool
	cmd := &cobra.Command{
		Use:   "stop <instance-id>",
		Short: "Stop a running ECS instance",
		Long: "Stop a running ECS instance. In the interactive flow the stop is confirmed\n" +
			"first (default no); --yes skips the question. In the non-interactive flow\n" +
			"(no terminal, --no-input or POLYCTL_NO_INPUT=1) nothing is asked: --yes is\n" +
			"required, and without it the command is a usage error (exit code 2).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			action := fmt.Sprintf("stop instance %s", args[0])
			// Before anything else: the non-interactive flow without --yes
			// is refused without needing credentials or the network.
			if err := rt.CanConfirm(action); err != nil {
				return err
			}
			c, p, err := openClient(rt, cmd.Context())
			if err != nil {
				return err
			}
			if !rt.Flags.Yes {
				ok, err := rt.Confirm(cmd.Context(), action, false)
				if err != nil {
					return err
				}
				if !ok {
					// Declining is not a failure: exit code 0.
					rt.Infof("nothing to do: instance %s was not stopped", args[0])
					return nil
				}
			}
			if err := c.StopInstance(cmd.Context(), region, args[0], force); err != nil {
				return err
			}
			rt.Infof("stop requested for %s via aliyun/%s", args[0], p.Name)
			in := refreshInstance(rt, cmd.Context(), c, p.Name, region, args[0])
			if in == nil {
				return rt.Render(map[string]string{"profile": p.Name, "instance": args[0], "action": "stop"}, func() output.Grid {
					return output.KV("INSTANCE", args[0], "ACTION", "stop")
				})
			}
			return rt.Render(in, func() output.Grid { return instanceGrid([]Instance{*in}) })
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	cmd.Flags().BoolVar(&force, "force", false, "force stop (like pulling the power)")
	return cmd
}
