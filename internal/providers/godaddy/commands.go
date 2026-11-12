package godaddy

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

// Command returns the `polyctl godaddy` command tree.
func Command(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "godaddy",
		Short: "GoDaddy native commands",
		Long: `Registrar and DNS operations on a GoDaddy account.

The profile is chosen with --profile, the current profile, or the only GoDaddy
profile. Listing commands read the local inventory unless --refresh is given or
the cached data has expired; mutations always talk to the API.`,
	}
	cmd.AddGroup(
		&cobra.Group{ID: "registrar", Title: "Registrar:"},
		&cobra.Group{ID: "dns", Title: "DNS:"},
	)
	domain := newDomainCmd(rt)
	domain.GroupID = "registrar"
	dns := newDNSCmd(rt)
	dns.GroupID = "dns"
	cmd.AddCommand(domain, dns)
	return cmd
}

// openClient opens the GoDaddy client for the resolved profile.
func openClient(ctx context.Context, rt *app.Runtime) (*client, platform.Profile, error) {
	c, p, err := rt.OpenFor(ctx, platform.GoDaddy)
	if err != nil {
		return nil, p, err
	}
	gc, ok := c.(*client)
	if !ok {
		return nil, p, fmt.Errorf("profile %q did not open a GoDaddy client", p.Name)
	}
	return gc, p, nil
}

// ---- domain ----

func newDomainCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "domain", Short: "Registered domains"}
	ns := &cobra.Command{Use: "ns", Short: "Nameservers of a domain"}
	ns.AddCommand(newDomainNSGetCmd(rt), newDomainNSSetCmd(rt))
	cmd.AddCommand(
		newDomainListCmd(rt),
		newDomainGetCmd(rt),
		ns,
		newDomainLockCmd(rt, true),
		newDomainLockCmd(rt, false),
		newDomainAutoRenewCmd(rt),
		newDomainAvailableCmd(rt),
	)
	return cmd
}

type domainResult struct {
	Profile string            `json:"profile" yaml:"profile"`
	Cached  bool              `json:"cached" yaml:"cached"`
	Domains []platform.Domain `json:"domains" yaml:"domains"`
}

func domainGrid(domains []platform.Domain) output.Grid {
	g := output.Grid{Headers: []string{"DOMAIN", "STATUS", "EXPIRES", "AUTORENEW", "LOCKED", "PRIVACY", "NAMESERVERS"}, Empty: "no domains"}
	for _, d := range domains {
		g.Rows = append(g.Rows, []string{d.Name, d.Status, shortDate(d.ExpiresAt), output.Str(d.AutoRenew), output.Str(d.Locked), output.Str(d.Privacy), strings.Join(d.Nameservers, ",")})
	}
	return g
}

func domainKV(d *platform.Domain) output.Grid {
	pairs := []string{
		"Domain", d.Name,
		"Status", d.Status,
		"Expires", d.ExpiresAt,
		"Auto-renew", output.Str(d.AutoRenew),
		"Locked", output.Str(d.Locked),
		"Privacy", output.Str(d.Privacy),
		"Nameservers", strings.Join(d.Nameservers, ", "),
	}
	keys := make([]string, 0, len(d.Extra))
	for k := range d.Extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		pairs = append(pairs, k, output.Str(d.Extra[k]))
	}
	return output.KV(pairs...)
}

func shortDate(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

func newDomainListCmd(rt *app.Runtime) *cobra.Command {
	var statuses []string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the domains of the account",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := rt.ProfileFor(platform.GoDaddy)
			if err != nil {
				return err
			}
			set := inventory.Set{Platform: platform.GoDaddy, Profile: name, Type: platform.ResDomain}
			rows, cached, err := rt.EnsureSet(cmd.Context(), set, func(ctx context.Context) ([]platform.Resource, error) {
				c, _, err := rt.Open(ctx, name, platform.GoDaddy)
				if err != nil {
					return nil, err
				}
				return c.Sync(ctx, platform.ResDomain)
			})
			if err != nil {
				return err
			}
			want := map[string]bool{}
			for _, s := range statuses {
				want[strings.ToUpper(strings.TrimSpace(s))] = true
			}
			domains := make([]platform.Domain, 0, len(rows))
			for _, r := range rows {
				var d platform.Domain
				if err := r.Decode(&d); err != nil {
					return fmt.Errorf("decode cached domain %s: %w", r.ID, err)
				}
				if len(want) > 0 && !want[strings.ToUpper(d.Status)] {
					continue
				}
				domains = append(domains, d)
			}
			sort.Slice(domains, func(i, j int) bool { return domains[i].Name < domains[j].Name })
			rt.Infof("%d domain(s) via godaddy/%s%s", len(domains), name, cacheNote(cached))
			return rt.Render(domainResult{Profile: name, Cached: cached, Domains: domains}, func() output.Grid { return domainGrid(domains) })
		},
	}
	cmd.Flags().StringSliceVar(&statuses, "status", nil, "only show domains with these statuses (e.g. ACTIVE,EXPIRED)")
	return cmd
}

func cacheNote(cached bool) string {
	if cached {
		return " (local inventory)"
	}
	return ""
}

// loadDomain returns one domain, from the inventory when it is fresh (or
// --offline) and from the API otherwise. The API result is cached.
func loadDomain(ctx context.Context, rt *app.Runtime, name string) (*platform.Domain, string, bool, error) {
	profile, err := rt.ProfileFor(platform.GoDaddy)
	if err != nil {
		return nil, "", false, err
	}
	name = platform.NormalizeDomain(name)
	set := inventory.Set{Platform: platform.GoDaddy, Profile: profile, Type: platform.ResDomain}
	need, err := rt.NeedsRefresh(ctx, set)
	if err != nil {
		return nil, profile, false, err
	}
	if !need {
		db, err := rt.DB()
		if err != nil {
			return nil, profile, false, err
		}
		r, err := db.Get(ctx, set, platform.ResDomain, name)
		if err == nil {
			var d platform.Domain
			if err := r.Decode(&d); err != nil {
				return nil, profile, false, err
			}
			return &d, profile, true, nil
		}
		if !errors.Is(err, platform.ErrNotFound) {
			return nil, profile, false, err
		}
		if rt.Flags.Offline {
			return nil, profile, false, fmt.Errorf("%w: domain %s is not in the local inventory", platform.ErrNotFound, name)
		}
	}
	c, _, err := rt.Open(ctx, profile, platform.GoDaddy)
	if err != nil {
		return nil, profile, false, err
	}
	d, err := c.(*client).GetDomain(ctx, name)
	if err != nil {
		return nil, profile, false, err
	}
	cacheDomain(ctx, rt, profile, d)
	return d, profile, false, nil
}

// cacheDomain upserts a domain into the inventory (best effort).
func cacheDomain(ctx context.Context, rt *app.Runtime, profile string, d *platform.Domain) {
	db, err := rt.DB()
	if err != nil {
		return
	}
	cfg, err := rt.Config()
	if err != nil {
		return
	}
	set := inventory.Set{Platform: platform.GoDaddy, Profile: profile, Type: platform.ResDomain}
	if err := db.Upsert(ctx, set, app.DomainResources([]platform.Domain{*d})[0], cfg.TTLFor(platform.ResDomain)); err != nil {
		rt.Verbosef("warning: cache domain %s: %v", d.Name, err)
	}
	zone := zoneFromDomain(*d)
	zset := inventory.Set{Platform: platform.GoDaddy, Profile: profile, Type: platform.ResZone}
	if err := db.Upsert(ctx, zset, app.ZoneResources([]platform.Zone{zone})[0], cfg.TTLFor(platform.ResZone)); err != nil {
		rt.Verbosef("warning: cache zone %s: %v", d.Name, err)
	}
}

// refreshDomain re-reads a domain after a mutation and caches it; on
// failure it returns a minimal domain so the command can still render.
func refreshDomain(ctx context.Context, rt *app.Runtime, c *client, profile, name string) *platform.Domain {
	d, err := c.GetDomain(ctx, name)
	if err != nil {
		rt.Verbosef("warning: re-read domain %s: %v", name, err)
		return &platform.Domain{Name: name}
	}
	cacheDomain(ctx, rt, profile, d)
	return d
}

func newDomainGetCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get <domain>",
		Short: "Show the details of a domain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, profile, cached, err := loadDomain(cmd.Context(), rt, args[0])
			if err != nil {
				return err
			}
			rt.Infof("domain %s via godaddy/%s%s", d.Name, profile, cacheNote(cached))
			return rt.Render(d, func() output.Grid { return domainKV(d) })
		},
	}
}

func nsGrid(ns []string) output.Grid {
	g := output.Grid{Headers: []string{"NAMESERVER"}, Empty: "no nameservers"}
	for _, n := range ns {
		g.Rows = append(g.Rows, []string{n})
	}
	return g
}

func newDomainNSGetCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get <domain>",
		Short: "Show the nameservers of a domain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, profile, cached, err := loadDomain(cmd.Context(), rt, args[0])
			if err != nil {
				return err
			}
			rt.Infof("domain %s via godaddy/%s%s", d.Name, profile, cacheNote(cached))
			return rt.Render(map[string]any{"domain": d.Name, "nameservers": d.Nameservers}, func() output.Grid { return nsGrid(d.Nameservers) })
		},
	}
}

func newDomainNSSetCmd(rt *app.Runtime) *cobra.Command {
	var ns []string
	cmd := &cobra.Command{
		Use:   "set <domain> --ns ns1.example.com,ns2.example.com",
		Short: "Replace the nameservers of a domain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(ns) == 0 {
				return app.UsageErrf("--ns is required")
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			c, p, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			name := platform.NormalizeDomain(args[0])
			if err := c.SetNameservers(cmd.Context(), name, ns); err != nil {
				return err
			}
			d := refreshDomain(cmd.Context(), rt, c, p.Name, name)
			if len(d.Nameservers) == 0 {
				d.Nameservers = ns
			}
			rt.Infof("nameservers of %s updated via godaddy/%s", name, p.Name)
			return rt.Render(map[string]any{"domain": d.Name, "nameservers": d.Nameservers}, func() output.Grid { return nsGrid(d.Nameservers) })
		},
	}
	cmd.Flags().StringSliceVar(&ns, "ns", nil, "comma-separated nameservers (at least two)")
	return cmd
}

func newDomainLockCmd(rt *app.Runtime, lock bool) *cobra.Command {
	use, short := "lock <domain>", "Enable the registrar transfer lock"
	if !lock {
		use, short = "unlock <domain>", "Disable the registrar transfer lock"
	}
	return &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			c, p, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			name := platform.NormalizeDomain(args[0])
			if err := c.SetLocked(cmd.Context(), name, lock); err != nil {
				return err
			}
			d := refreshDomain(cmd.Context(), rt, c, p.Name, name)
			if d.Locked == nil {
				d.Locked = &lock
			}
			rt.Infof("transfer lock of %s set to %v via godaddy/%s", name, lock, p.Name)
			return rt.Render(d, func() output.Grid { return domainKV(d) })
		},
	}
}

func newDomainAutoRenewCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:       "autorenew <domain> on|off",
		Short:     "Enable or disable automatic renewal",
		Args:      cobra.ExactArgs(2),
		ValidArgs: []string{"on", "off"},
		RunE: func(cmd *cobra.Command, args []string) error {
			var on bool
			switch strings.ToLower(args[1]) {
			case "on", "true", "yes":
				on = true
			case "off", "false", "no":
				on = false
			default:
				return fmt.Errorf("expected on or off, got %q", args[1])
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			c, p, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			name := platform.NormalizeDomain(args[0])
			if err := c.SetAutoRenew(cmd.Context(), name, on); err != nil {
				return err
			}
			d := refreshDomain(cmd.Context(), rt, c, p.Name, name)
			if d.AutoRenew == nil {
				d.AutoRenew = &on
			}
			rt.Infof("auto-renew of %s set to %v via godaddy/%s", name, on, p.Name)
			return rt.Render(d, func() output.Grid { return domainKV(d) })
		},
	}
}

func newDomainAvailableCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "available <name>...",
		Short: "Check whether domains are available for registration",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			c, _, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			var results []Availability
			for _, n := range args {
				a, err := c.CheckAvailable(cmd.Context(), n)
				if err != nil {
					return err
				}
				results = append(results, *a)
			}
			return rt.Render(results, func() output.Grid {
				g := output.Grid{Headers: []string{"DOMAIN", "AVAILABLE", "DEFINITIVE", "PRICE", "PERIOD"}}
				for _, a := range results {
					price := ""
					if a.Price > 0 {
						price = fmt.Sprintf("%.2f %s", float64(a.Price)/1e6, a.Currency)
					}
					period := ""
					if a.Period > 0 {
						period = fmt.Sprintf("%d year(s)", a.Period)
					}
					g.Rows = append(g.Rows, []string{a.Domain, fmt.Sprint(a.Available), fmt.Sprint(a.Definitive), price, period})
				}
				return g
			})
		},
	}
}

// ---- dns ----

func newDNSCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dns",
		Short: "DNS records of a GoDaddy-hosted zone",
		Long: `Manage the DNS records GoDaddy hosts for a domain.

GoDaddy addresses records by type + name rather than by id; polyctl shows a
synthesized id of the form TYPE|name|data that works with the generic
"polyctl dns" commands as well.`,
	}
	cmd.AddCommand(newDNSListCmd(rt), newDNSAddCmd(rt), newDNSReplaceCmd(rt), newDNSDeleteCmd(rt))
	return cmd
}

type dnsResult struct {
	Profile string            `json:"profile" yaml:"profile"`
	Zone    string            `json:"zone" yaml:"zone"`
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
		g.Rows = append(g.Rows, []string{r.Name, r.Type, content, platform.TTLLabel(platform.GoDaddy, r), r.ID})
	}
	return g
}

// refreshZoneCache re-reads the zone's records and replaces the cached
// scope so later reads see the mutation (best effort).
func refreshZoneCache(ctx context.Context, rt *app.Runtime, c *client, profile, zone string) {
	recs, err := c.ListRecords(ctx, zone)
	if err != nil {
		rt.Verbosef("warning: re-read records of %s: %v", zone, err)
		return
	}
	db, err := rt.DB()
	if err != nil {
		return
	}
	cfg, err := rt.Config()
	if err != nil {
		return
	}
	set := inventory.Set{Platform: platform.GoDaddy, Profile: profile, Type: platform.ResDNSRecord, Scope: zone}
	if err := db.Replace(ctx, set, app.RecordResources(zone, zone, recs), cfg.TTLFor(platform.ResDNSRecord)); err != nil {
		rt.Verbosef("warning: cache records of %s: %v", zone, err)
	}
}

func newDNSListCmd(rt *app.Runtime) *cobra.Command {
	var typ, name string
	cmd := &cobra.Command{
		Use:   "list <domain>",
		Short: "List the DNS records of a domain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, err := rt.ProfileFor(platform.GoDaddy)
			if err != nil {
				return err
			}
			zone := platform.NormalizeDomain(args[0])
			set := inventory.Set{Platform: platform.GoDaddy, Profile: profile, Type: platform.ResDNSRecord, Scope: zone}
			rows, cached, err := rt.EnsureSet(cmd.Context(), set, func(ctx context.Context) ([]platform.Resource, error) {
				c, _, err := rt.Open(ctx, profile, platform.GoDaddy)
				if err != nil {
					return nil, err
				}
				recs, err := c.(*client).ListRecords(ctx, zone)
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
				if recs[i].Type != recs[j].Type {
					return recs[i].Type < recs[j].Type
				}
				return recs[i].Content < recs[j].Content
			})
			rt.Infof("zone %s via godaddy/%s%s", zone, profile, cacheNote(cached))
			return rt.Render(dnsResult{Profile: profile, Zone: zone, Cached: cached, Records: recs}, func() output.Grid { return recordGrid(recs) })
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "filter by record type")
	cmd.Flags().StringVar(&name, "name", "", "filter by record name (relative, @ or FQDN)")
	return cmd
}

func buildRecord(cmd *cobra.Command, zone, typ, name, value string, ttl, priority int) platform.Record {
	rec := platform.Record{ZoneID: zone, Name: platform.FQDN(name, zone), Type: strings.ToUpper(typ), Content: value, TTL: ttl}
	if cmd.Flags().Changed("priority") {
		p := priority
		rec.Priority = &p
	}
	return rec
}

func newDNSAddCmd(rt *app.Runtime) *cobra.Command {
	var typ, name, value string
	var ttl, priority int
	cmd := &cobra.Command{
		Use:   "add <domain> --type A --name www --value 1.2.3.4",
		Short: "Add a DNS record (existing records of the same name and type are kept)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if typ == "" || value == "" {
				return app.UsageErrf("--type and --value are required")
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			c, p, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			zone := platform.NormalizeDomain(args[0])
			out, err := c.CreateRecord(cmd.Context(), zone, buildRecord(cmd, zone, typ, name, value, ttl, priority))
			if err != nil {
				return err
			}
			refreshZoneCache(cmd.Context(), rt, c, p.Name, zone)
			rt.Infof("added %s %s -> %s via godaddy/%s", out.Name, out.Type, out.Content, p.Name)
			return rt.Render(dnsResult{Profile: p.Name, Zone: zone, Records: []platform.Record{*out}}, func() output.Grid { return recordGrid([]platform.Record{*out}) })
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "record type (A, AAAA, CNAME, TXT, MX, ...)")
	cmd.Flags().StringVar(&name, "name", "@", "record name relative to the domain (www, @)")
	cmd.Flags().StringVar(&value, "value", "", "record content")
	cmd.Flags().IntVar(&ttl, "ttl", 0, "TTL in seconds (0 = GoDaddy default; minimum 600)")
	cmd.Flags().IntVar(&priority, "priority", 0, "priority for MX/SRV records")
	return cmd
}

func newDNSReplaceCmd(rt *app.Runtime) *cobra.Command {
	var typ, name string
	var values []string
	var ttl, priority int
	cmd := &cobra.Command{
		Use:   "replace <domain> --type A --name www --value 1.2.3.4 [--value 5.6.7.8]",
		Short: "Replace every record of a name and type with the given values",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if typ == "" || len(values) == 0 {
				return app.UsageErrf("--type and at least one --value are required")
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			c, p, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			zone := platform.NormalizeDomain(args[0])
			rel := platform.RelativeName(platform.FQDN(name, zone), zone)
			recs := make([]platform.Record, 0, len(values))
			for _, v := range values {
				recs = append(recs, buildRecord(cmd, zone, typ, rel, v, ttl, priority))
			}
			out, err := c.ReplaceRecords(cmd.Context(), zone, typ, rel, recs)
			if err != nil {
				return err
			}
			refreshZoneCache(cmd.Context(), rt, c, p.Name, zone)
			rt.Infof("replaced %s %s with %d record(s) via godaddy/%s", platform.FQDN(rel, zone), strings.ToUpper(typ), len(out), p.Name)
			return rt.Render(dnsResult{Profile: p.Name, Zone: zone, Records: out}, func() output.Grid { return recordGrid(out) })
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "record type (A, AAAA, CNAME, TXT, MX, ...)")
	cmd.Flags().StringVar(&name, "name", "@", "record name relative to the domain (www, @)")
	cmd.Flags().StringArrayVar(&values, "value", nil, "record content (repeat for several records)")
	cmd.Flags().IntVar(&ttl, "ttl", 0, "TTL in seconds (0 = GoDaddy default; minimum 600)")
	cmd.Flags().IntVar(&priority, "priority", 0, "priority for MX/SRV records")
	return cmd
}

func newDNSDeleteCmd(rt *app.Runtime) *cobra.Command {
	var typ, name, id string
	cmd := &cobra.Command{
		Use:   "delete <domain> --type A --name www",
		Short: "Delete every record of a name and type (or one record by --id)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id == "" && typ == "" {
				return app.UsageErrf("--type (with --name) or --id is required")
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			c, p, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			zone := platform.NormalizeDomain(args[0])
			if id != "" {
				t, n, d, err := DecodeRecordID(id)
				if err != nil {
					return err
				}
				if err := c.DeleteRecord(cmd.Context(), zone, id); err != nil {
					return err
				}
				refreshZoneCache(cmd.Context(), rt, c, p.Name, zone)
				rt.Infof("deleted %s %s %s via godaddy/%s", platform.FQDN(n, zone), t, d, p.Name)
				return rt.Render(map[string]any{"profile": p.Name, "zone": zone, "deleted": []string{id}}, func() output.Grid { return output.Grid{} })
			}
			rel := platform.RelativeName(platform.FQDN(name, zone), zone)
			if err := c.DeleteRecordSet(cmd.Context(), zone, typ, rel); err != nil {
				return err
			}
			refreshZoneCache(cmd.Context(), rt, c, p.Name, zone)
			rt.Infof("deleted all %s records of %s via godaddy/%s", strings.ToUpper(typ), platform.FQDN(rel, zone), p.Name)
			return rt.Render(map[string]any{"profile": p.Name, "zone": zone, "type": strings.ToUpper(typ), "name": platform.FQDN(rel, zone)}, func() output.Grid { return output.Grid{} })
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "record type")
	cmd.Flags().StringVar(&name, "name", "@", "record name relative to the domain (www, @)")
	cmd.Flags().StringVar(&id, "id", "", "delete the single record with this id (TYPE|name|data)")
	return cmd
}
