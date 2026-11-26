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
		&cobra.Group{ID: "account", Title: "Account:"},
		&cobra.Group{ID: "registrar", Title: "Registrar:"},
		&cobra.Group{ID: "dns", Title: "DNS:"},
	)
	domain := newDomainCmd(rt)
	domain.GroupID = "registrar"
	dns := newDNSCmd(rt)
	dns.GroupID = "dns"
	whoami := app.WhoamiCommand(rt, platform.GoDaddy, "GoDaddy has no identity endpoint: the credentials are verified by listing one\ndomain, and the login method and the environment are reported.")
	whoami.GroupID = "account"
	cmd.AddCommand(whoami, domain, dns)
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
		newDomainCheckCmd(rt),
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
	if zone.Status != zoneActive {
		// GoDaddy does not serve its DNS (any more): not a zone to route to.
		if err := db.Delete(ctx, zset, platform.ResZone, zone.ID); err != nil {
			rt.Verbosef("warning: forget zone %s: %v", d.Name, err)
		}
		return
	}
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
		Args:  app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := rt.DomainArg(cmd.Context(), args, platform.GoDaddy, platform.ResDomain, nil)
			if err != nil {
				return err
			}
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
		Args:  app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := rt.DomainArg(cmd.Context(), args, platform.GoDaddy, platform.ResDomain, nil)
			if err != nil {
				return err
			}
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
	cmd := &cobra.Command{
		Use:     "set <domain> <nameserver>...",
		Short:   "Replace the nameservers of a domain",
		Long:    "Replace the nameservers of <domain> with the ones given (GoDaddy wants at\nleast two).\n" + app.NameserverHelp,
		Example: "  polyctl godaddy domain ns set example.com ns1.example.net ns2.example.net",
		Args:    app.NameserverArgsOrInteractive(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := rt.DomainArg(cmd.Context(), args, platform.GoDaddy, platform.ResDomain, nil)
			if err != nil {
				return err
			}
			if len(args) < 2 {
				ns, err := rt.PickNameservers(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				args = append(args, ns...)
			}
			ns, err := app.Nameservers(args[1:])
			if err != nil {
				return err
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			c, p, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			name := platform.NormalizeDomain(args[0])
			if done, err := rt.WouldWrite(platform.Target{Platform: platform.GoDaddy, Profile: p.Name, Domain: name}, app.NameserverChange(name, ns)); done || err != nil {
				return err
			}
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
		Args:  app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			// lock offers the unlocked domains, unlock the locked ones.
			args, err := rt.DomainArg(cmd.Context(), args, platform.GoDaddy, platform.ResDomain, func(d platform.Domain) bool {
				return (d.Locked != nil && *d.Locked) != lock
			})
			if err != nil {
				return err
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			c, p, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			name := platform.NormalizeDomain(args[0])
			if done, err := rt.WouldWrite(platform.Target{Platform: platform.GoDaddy, Profile: p.Name, Domain: name}, app.ResourceChange("domain", name+"/lock", platform.Updated, fmt.Sprintf("locked=%v", lock))); done || err != nil {
				return err
			}
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
		Args:      app.ArgsOrInteractive(rt, 2, nil),
		ValidArgs: []string{"on", "off"},
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := rt.DomainArg(cmd.Context(), args, platform.GoDaddy, platform.ResDomain, nil)
			if err != nil {
				return err
			}
			if len(args) < 2 {
				var cur *bool
				if d, _, _, err := loadDomain(cmd.Context(), rt, args[0]); err == nil {
					cur = d.AutoRenew
				}
				v, err := rt.PickOnOff("Automatic renewal of "+args[0], cur)
				if err != nil {
					return err
				}
				args = append(args, v)
			}
			var on bool
			switch strings.ToLower(args[1]) {
			case "on", "true", "yes":
				on = true
			case "off", "false", "no":
				on = false
			default:
				return app.UsageErrf("expected on or off, got %q", args[1])
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			c, p, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			name := platform.NormalizeDomain(args[0])
			if done, err := rt.WouldWrite(platform.Target{Platform: platform.GoDaddy, Profile: p.Name, Domain: name}, app.ResourceChange("domain", name+"/autorenew", platform.Updated, fmt.Sprintf("autorenew=%v", on))); done || err != nil {
				return err
			}
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

func newDomainCheckCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "check <name>...",
		Short: "Check whether domains are available for registration",
		Args:  app.MinArgsOrInteractive(rt, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := rt.NamesArgs(args)
			if err != nil {
				return err
			}
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
synthesized id of the form zone|TYPE|name|value that works with the generic
"polyctl dns" commands as well.`,
	}
	cmd.AddCommand(newDNSListCmd(rt), newDNSAddCmd(rt), newDNSUpsertCmd(rt), newDNSDeleteCmd(rt))
	return cmd
}

type dnsResult struct {
	Profile string            `json:"profile" yaml:"profile"`
	Zone    string            `json:"zone" yaml:"zone"`
	Cached  bool              `json:"cached" yaml:"cached"`
	Records []platform.Record `json:"records" yaml:"records"`
}

func recordGrid(recs []platform.Record) output.Grid {
	g := output.Grid{Headers: []string{"NAME", "TYPE", "VALUE", "TTL", "ID"}, Empty: "no records"}
	for _, r := range recs {
		content := r.Value
		if r.Priority != nil {
			content = fmt.Sprintf("%d %s", *r.Priority, r.Value)
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
		Args:  app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := rt.DomainArg(cmd.Context(), args, platform.GoDaddy, platform.ResZone, nil)
			if err != nil {
				return err
			}
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
				return recs[i].Value < recs[j].Value
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
	rec := platform.Record{ZoneID: zone, Name: platform.FQDN(name, zone), Type: strings.ToUpper(typ), Value: value, TTL: ttl}
	if cmd.Flags().Changed("priority") {
		p := priority
		rec.Priority = &p
	}
	return rec
}

func newDNSAddCmd(rt *app.Runtime) *cobra.Command {
	var ttl, priority int
	cmd := &cobra.Command{
		Use:   "add <domain> <name> <type> <value>",
		Short: "Add a DNS record (existing records of the same name and type are kept)",
		Long: `Add one record to <domain>. Records that already have the same name and type
are kept.

` + recordArgsHelp + `

` + app.RecordAskHelp("domain"),
		Example: `  polyctl godaddy dns add example.com www A 203.0.113.10
  polyctl godaddy dns add example.com @ MX mail.example.com --priority 10
  polyctl godaddy dns add example.com @ TXT "v=spf1 include:_spf.example.net ~all"`,
		Args:              app.RecordArgsOrInteractive(rt, 1, 1),
		ValidArgsFunction: app.CompleteRecordArgs(app.CompleteDomainArg(rt, platform.GoDaddy), platform.GoDaddy),
		RunE: func(cmd *cobra.Command, args []string) error {
			// The record is positional (<name> <type> <value>) or, in the
			// former form, given with --name, --type and --value.
			in, err := rt.RecordInput(cmd, args, app.RecordForm{MinValues: 1, MaxValues: 1})
			if err != nil {
				return err
			}
			args, err = rt.DomainArg(cmd.Context(), args[:min(len(args), 1)], platform.GoDaddy, platform.ResZone, nil)
			if err != nil {
				// The record cannot be created without a zone.
				return app.RequiredPick(err, "<domain>")
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			c, p, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			zone := platform.NormalizeDomain(args[0])
			if err := rt.CompleteRecord(in, app.RecordPrompt{Platform: platform.GoDaddy, Zone: zone,
				Existing: func() ([]platform.Record, error) { return c.ListRecords(cmd.Context(), zone) }}); err != nil {
				return err
			}
			name, typ, value := in.Name, in.Type, in.Value()
			rec := buildRecord(cmd, zone, typ, name, value, ttl, priority)
			if done, err := rt.WouldWrite(platform.Target{Platform: platform.GoDaddy, Profile: p.Name, Domain: zone}, platform.Change{Resource: app.RecordResource(rec.Name, rec.Type), Action: platform.Created, Detail: rec.Value}); done || err != nil {
				return err
			}
			out, err := c.CreateRecord(cmd.Context(), zone, rec)
			if err != nil {
				return err
			}
			refreshZoneCache(cmd.Context(), rt, c, p.Name, zone)
			rt.Infof("added %s %s -> %s via godaddy/%s", out.Name, out.Type, out.Value, p.Name)
			return rt.Render(dnsResult{Profile: p.Name, Zone: zone, Records: []platform.Record{*out}}, func() output.Grid { return recordGrid([]platform.Record{*out}) })
		},
	}
	app.FormerRecordFlags(cmd, false)
	cmd.Flags().IntVar(&ttl, "ttl", 0, "TTL in seconds (0 = GoDaddy default; minimum 600)")
	cmd.Flags().IntVar(&priority, "priority", 0, "priority for MX/SRV records")
	app.HideFormerRecordFlags(cmd)
	return cmd
}

// recordArgsHelp is the paragraph of the record commands about their
// positional record.
const recordArgsHelp = `<name> is relative to the domain (www, a.b), @ for the apex, or a full name
inside the domain (www.example.com). <type> is case-insensitive. A value is
one argument: quote one that contains spaces. A value that starts with "-" goes
after "--".`

func newDNSUpsertCmd(rt *app.Runtime) *cobra.Command {
	var ttl, priority int
	cmd := &cobra.Command{
		Use:   "upsert <domain> <name> <type> <value>...",
		Short: "Create or replace the record set of a name and type with the given values",
		Long: `Set the records of <name> and <type> to exactly the values given: the record
set is created when it does not exist, and every record it holds is replaced
when it does. Every <value> is one record. To add a record and keep the
existing ones use ` + "`polyctl godaddy dns add`" + `.

` + recordArgsHelp + `

` + app.RecordAskHelp("domain") + "\n\n" + app.RecordSetAskHelp,
		Example: `  polyctl godaddy dns upsert example.com www A 203.0.113.10 203.0.113.11
  polyctl godaddy dns upsert example.com @ MX mail.example.com --priority 10 --ttl 3600`,
		Args:              app.RecordArgsOrInteractive(rt, 1, -1),
		ValidArgsFunction: app.CompleteRecordArgs(app.CompleteDomainArg(rt, platform.GoDaddy), platform.GoDaddy),
		RunE: func(cmd *cobra.Command, args []string) error {
			// The record set is positional (<name> <type> <value>...) or, in
			// the former form, given with --name, --type and --value.
			in, err := rt.RecordInput(cmd, args, app.RecordForm{MinValues: 1, MaxValues: -1})
			if err != nil {
				return err
			}
			args, err = rt.DomainArg(cmd.Context(), args[:min(len(args), 1)], platform.GoDaddy, platform.ResZone, nil)
			if err != nil {
				// The record cannot be created without a zone.
				return app.RequiredPick(err, "<domain>")
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			c, p, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			zone := platform.NormalizeDomain(args[0])
			if err := rt.CompleteRecord(in, app.RecordPrompt{Platform: platform.GoDaddy, Zone: zone, WholeSet: true,
				Existing: func() ([]platform.Record, error) { return c.ListRecords(cmd.Context(), zone) }}); err != nil {
				return err
			}
			name, typ, values := in.Name, in.Type, in.Values
			rel := platform.RelativeName(platform.FQDN(name, zone), zone)
			recs := make([]platform.Record, 0, len(values))
			for _, v := range values {
				recs = append(recs, buildRecord(cmd, zone, typ, rel, v, ttl, priority))
			}
			if done, err := rt.WouldWrite(platform.Target{Platform: platform.GoDaddy, Profile: p.Name, Domain: zone}, platform.Change{Resource: app.RecordResource(platform.FQDN(rel, zone), typ), Action: platform.Updated, Detail: "set to " + strings.Join(values, ",")}); done || err != nil {
				return err
			}
			out, err := c.ReplaceRecords(cmd.Context(), zone, typ, rel, recs)
			if err != nil {
				return err
			}
			refreshZoneCache(cmd.Context(), rt, c, p.Name, zone)
			rt.Infof("upserted %s %s with %d record(s) via godaddy/%s", platform.FQDN(rel, zone), strings.ToUpper(typ), len(out), p.Name)
			return rt.Render(dnsResult{Profile: p.Name, Zone: zone, Records: out}, func() output.Grid { return recordGrid(out) })
		},
	}
	app.FormerRecordFlags(cmd, true)
	cmd.Flags().IntVar(&ttl, "ttl", 0, "TTL in seconds (0 = GoDaddy default; minimum 600)")
	cmd.Flags().IntVar(&priority, "priority", 0, "priority for MX/SRV records")
	app.HideFormerRecordFlags(cmd)
	return cmd
}

// deleteForm is the form of dns delete: the record by name or --id, or with
// the former --name and --type.
var deleteForm = app.RecordTargetForm{FormerFlags: []string{"name", "type"}, FormerApex: true}

// deleteResult is the output of dns delete: the ids and the records
// deleted, and the name and the type when they are those of one record set
// (as the command printed them when it deleted a record set as a whole).
type deleteResult struct {
	Profile string            `json:"profile" yaml:"profile"`
	Zone    string            `json:"zone" yaml:"zone"`
	Type    string            `json:"type,omitempty" yaml:"type,omitempty"`
	Name    string            `json:"name,omitempty" yaml:"name,omitempty"`
	Deleted []string          `json:"deleted" yaml:"deleted"`
	Records []platform.Record `json:"records" yaml:"records"`
}

func newDNSDeleteCmd(rt *app.Runtime) *cobra.Command {
	var typ, name, id string
	cmd := &cobra.Command{
		Use:   "delete <domain> [<name> [<type> [<value>]]]",
		Short: "Delete the DNS records of a name (optionally of one type and value), or one record by --id",
		Long: `Delete the records of <name> in <domain>, or the one record with --id.
GoDaddy addresses records by name and type; the id is the synthesized
zone|TYPE|name|value that ` + "`polyctl godaddy dns list`" + ` shows.

` + deleteForm.Help("domain", "polyctl godaddy dns list") + `

` + app.RecordDeleteHelp + `

--dry-run reports what would be deleted and asks nothing.`,
		Example: `  polyctl godaddy dns delete example.com www
  polyctl godaddy dns delete example.com www A
  polyctl godaddy dns delete example.com www A 203.0.113.10
  polyctl godaddy dns delete example.com --id 'example.com|A|www|203.0.113.10'`,
		Args:              deleteForm.ArgsOrInteractive(rt),
		ValidArgsFunction: deleteForm.Complete(rt, app.CompleteDomainArg(rt, platform.GoDaddy), platform.GoDaddy),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := deleteForm.Parse(cmd, args)
			if err != nil {
				return err
			}
			args, err = rt.DomainArg(cmd.Context(), args[:min(len(args), 1)], platform.GoDaddy, platform.ResZone, nil)
			if err != nil {
				return err
			}
			domain := platform.NormalizeDomain(args[0])
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			c, p, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			existing, err := c.ListRecords(cmd.Context(), domain)
			if err != nil {
				return err
			}
			zone := platform.Zone{ID: domain, Name: domain}
			sel := target.Select(app.RecordSelect{Zone: domain, Records: existing, ID: id, IDMatches: c.RecordIDMatches, Verb: "Delete", Grid: recordGrid})
			sel.Offer, sel.Mark = app.DeletableRecords(c, zone)
			chosen, err := rt.SelectRecords(sel)
			if err != nil {
				return err
			}
			del := app.RecordsDelete{Target: platform.Target{Platform: platform.GoDaddy, Profile: p.Name, Domain: domain},
				Zone: zone, DNS: c, Records: chosen.Records, Grid: recordGrid, Exact: sel.Exact(chosen)}
			if done, err := rt.DeleteRecords(cmd.Context(), del); !done || err != nil {
				return err
			}
			refreshZoneCache(cmd.Context(), rt, c, p.Name, domain)
			res := deleteResult{Profile: p.Name, Zone: domain, Records: chosen.Records}
			for _, r := range chosen.Records {
				res.Deleted = append(res.Deleted, r.ID)
			}
			if !chosen.ByID && !chosen.Listed && chosen.Type() != "" {
				res.Type, res.Name = chosen.Type(), chosen.Records[0].Name
			}
			return rt.Render(res, func() output.Grid { return output.Grid{} })
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "record type")
	cmd.Flags().StringVar(&name, "name", "@", "record name relative to the domain (www, @)")
	cmd.Flags().StringVar(&id, "id", "", "delete the record with this id (zone|TYPE|name|value, as dns list shows it)")
	app.HideFormerRecordFlags(cmd)
	return cmd
}
