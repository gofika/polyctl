package namecom

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// Command returns the `polyctl namecom` command tree.
func Command(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "namecom",
		Short: "name.com native commands",
		Long: `Operate a name.com account directly: registered domains (nameservers, lock,
auto-renew, availability) and the DNS records name.com hosts for each domain.

The profile is chosen with --profile, the current profile, or the only name.com
profile configured. Listing commands serve the local inventory unless --refresh
is given or the cached data has expired; --offline never touches the network.`,
	}
	cmd.AddCommand(
		app.WhoamiCommand(rt, platform.NameCom, "On name.com this calls GET /v4/hello and reports the user name, the\nenvironment and the server time."),
		newDomainCmd(rt), newDNSCmd(rt))
	return cmd
}

// --- shared helpers ---------------------------------------------------------

// open resolves the name.com profile and opens an authenticated client.
func open(ctx context.Context, rt *app.Runtime) (*Client, platform.Profile, error) {
	if rt.Flags.Offline {
		return nil, platform.Profile{}, app.ErrOffline
	}
	c, p, err := rt.OpenFor(ctx, platform.NameCom)
	if err != nil {
		return nil, p, err
	}
	nc, ok := c.(*Client)
	if !ok {
		return nil, p, fmt.Errorf("profile %q did not open a name.com client", p.Name)
	}
	return nc, p, nil
}

// warnInventory reports a failed inventory write-through. The remote change
// has already succeeded at that point, so the command still succeeds, but
// the user must know the cache now lags behind name.com.
func warnInventory(rt *app.Runtime, err error) {
	if err != nil {
		rt.Infof("warning: could not update local inventory: %v (run `polyctl sync --platform namecom`)", err)
	}
}

// storeDomain upserts a domain into the inventory. The zone view is upserted
// only while name.com serves the domain's DNS; otherwise any stale zone row
// is deleted so neutral domain routing stops seeing name.com as an owner.
func storeDomain(ctx context.Context, rt *app.Runtime, profile string, d *platform.Domain) error {
	if d == nil {
		return nil
	}
	db, err := rt.DB()
	if err != nil {
		return err
	}
	cfg, err := rt.Config()
	if err != nil {
		return err
	}
	if err := db.Upsert(ctx, inventory.Set{Platform: platform.NameCom, Profile: profile, Type: platform.ResDomain},
		app.DomainResources([]platform.Domain{*d})[0], cfg.TTLFor(platform.ResDomain)); err != nil {
		return fmt.Errorf("domain %s: %w", d.Name, err)
	}
	z := zoneFromDomain(d.Name, d.Nameservers)
	zset := inventory.Set{Platform: platform.NameCom, Profile: profile, Type: platform.ResZone}
	if z.Status != zoneActive {
		if err := db.Delete(ctx, zset, platform.ResZone, z.ID); err != nil {
			return fmt.Errorf("zone %s: %w", z.ID, err)
		}
		return nil
	}
	if err := db.Upsert(ctx, zset, app.ZoneResources([]platform.Zone{z})[0], cfg.TTLFor(platform.ResZone)); err != nil {
		return fmt.Errorf("zone %s: %w", z.ID, err)
	}
	return nil
}

// storeRecord upserts a record into the inventory.
func storeRecord(ctx context.Context, rt *app.Runtime, profile, domain string, r *platform.Record) error {
	if r == nil {
		return nil
	}
	db, err := rt.DB()
	if err != nil {
		return err
	}
	cfg, err := rt.Config()
	if err != nil {
		return err
	}
	if err := db.Upsert(ctx, inventory.Set{Platform: platform.NameCom, Profile: profile, Type: platform.ResDNSRecord},
		app.RecordResources(domain, domain, []platform.Record{*r})[0], cfg.TTLFor(platform.ResDNSRecord)); err != nil {
		return fmt.Errorf("record %s: %w", r.ID, err)
	}
	return nil
}

// dropRecord removes a record from the inventory. id must be the canonical
// record id as stored by toRecord.
func dropRecord(ctx context.Context, rt *app.Runtime, profile, id string) error {
	db, err := rt.DB()
	if err != nil {
		return err
	}
	if err := db.Delete(ctx, inventory.Set{Platform: platform.NameCom, Profile: profile}, platform.ResDNSRecord, id); err != nil {
		return fmt.Errorf("record %s: %w", id, err)
	}
	return nil
}

// loadDomain returns a domain from the inventory or the API according to
// --refresh/--offline/TTL, caching a fresh fetch.
func loadDomain(ctx context.Context, rt *app.Runtime, profile, name string) (*platform.Domain, bool, error) {
	name = platform.NormalizeDomain(name)
	set := inventory.Set{Platform: platform.NameCom, Profile: profile, Type: platform.ResDomain}
	need, err := rt.NeedsRefresh(ctx, set)
	if err != nil {
		return nil, false, err
	}
	db, err := rt.DB()
	if err != nil {
		return nil, false, err
	}
	if !need {
		if r, err := db.Get(ctx, set, platform.ResDomain, name); err == nil {
			var d platform.Domain
			if err := r.Decode(&d); err == nil {
				return &d, true, nil
			}
		} else if rt.Flags.Offline {
			return nil, true, fmt.Errorf("%w: domain %q is not in the local inventory for name.com/%s", platform.ErrNotFound, name, profile)
		}
	}
	c, _, err := open(ctx, rt)
	if err != nil {
		return nil, false, err
	}
	d, err := c.GetDomain(ctx, name)
	if err != nil {
		return nil, false, err
	}
	warnInventory(rt, storeDomain(ctx, rt, profile, d))
	return d, false, nil
}

func cacheNote(cached bool) string {
	if cached {
		return " (local inventory)"
	}
	return ""
}

func domainGrid(domains []platform.Domain) output.Grid {
	g := output.Grid{Headers: []string{"DOMAIN", "EXPIRES", "AUTORENEW", "LOCKED", "PRIVACY", "NAMESERVERS"}, Empty: "no domains"}
	for _, d := range domains {
		g.Rows = append(g.Rows, []string{d.Name, d.ExpiresAt, output.Str(d.AutoRenew), output.Str(d.Locked), output.Str(d.Privacy), strings.Join(d.Nameservers, ",")})
	}
	return g
}

func domainKV(d *platform.Domain) output.Grid {
	pairs := []string{
		"DOMAIN", d.Name,
		"STATUS", d.Status,
		"EXPIRES", d.ExpiresAt,
		"AUTORENEW", output.Str(d.AutoRenew),
		"LOCKED", output.Str(d.Locked),
		"PRIVACY", output.Str(d.Privacy),
		"NAMESERVERS", strings.Join(d.Nameservers, ","),
	}
	if v, ok := d.Extra["createDate"]; ok {
		pairs = append(pairs, "CREATED", output.Str(v))
	}
	if v, ok := d.Extra["renewalPrice"]; ok {
		pairs = append(pairs, "RENEWAL PRICE", output.Str(v))
	}
	return output.KV(pairs...)
}

func recordGrid(recs []platform.Record) output.Grid {
	g := output.Grid{Headers: []string{"NAME", "TYPE", "VALUE", "TTL", "ID"}, Empty: "no records"}
	for _, r := range recs {
		content := r.Value
		if r.Priority != nil {
			content = fmt.Sprintf("%d %s", *r.Priority, r.Value)
		}
		g.Rows = append(g.Rows, []string{r.Name, r.Type, content, platform.TTLLabel(platform.NameCom, r), r.ID})
	}
	return g
}

// --- result types (json/yaml) ------------------------------------------------

type domainListResult struct {
	Profile string            `json:"profile" yaml:"profile"`
	Cached  bool              `json:"cached" yaml:"cached"`
	Domains []platform.Domain `json:"domains" yaml:"domains"`
}

type domainResult struct {
	Profile string           `json:"profile" yaml:"profile"`
	Cached  bool             `json:"cached" yaml:"cached"`
	Domain  *platform.Domain `json:"domain" yaml:"domain"`
}

type nameserversResult struct {
	Profile     string   `json:"profile" yaml:"profile"`
	Cached      bool     `json:"cached" yaml:"cached"`
	Domain      string   `json:"domain" yaml:"domain"`
	Nameservers []string `json:"nameservers" yaml:"nameservers"`
}

type availabilityResult struct {
	Profile string         `json:"profile" yaml:"profile"`
	Results []Availability `json:"results" yaml:"results"`
}

type recordsResult struct {
	Profile string            `json:"profile" yaml:"profile"`
	Cached  bool              `json:"cached" yaml:"cached"`
	Domain  string            `json:"domain" yaml:"domain"`
	Records []platform.Record `json:"records" yaml:"records"`
}

// --- domain -----------------------------------------------------------------

func newDomainCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "domain",
		Short: "Registered domains: list, details, nameservers, lock, auto-renew, availability",
	}
	ns := &cobra.Command{Use: "ns", Short: "Get or set the nameservers of a domain"}
	ns.AddCommand(newDomainNSGetCmd(rt), newDomainNSSetCmd(rt))
	cmd.AddCommand(
		newDomainListCmd(rt),
		newDomainGetCmd(rt),
		ns,
		newDomainLockCmd(rt, true),
		newDomainLockCmd(rt, false),
		newDomainAutorenewCmd(rt),
		newDomainCheckCmd(rt),
	)
	return cmd
}

func newDomainListCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the domains registered in the account",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, err := rt.ProfileFor(platform.NameCom)
			if err != nil {
				return err
			}
			set := inventory.Set{Platform: platform.NameCom, Profile: profile, Type: platform.ResDomain}
			rows, cached, err := rt.EnsureSet(cmd.Context(), set, func(ctx context.Context) ([]platform.Resource, error) {
				c, _, err := open(ctx, rt)
				if err != nil {
					return nil, err
				}
				return c.Sync(ctx, platform.ResDomain)
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
			sort.Slice(domains, func(i, j int) bool { return domains[i].Name < domains[j].Name })
			rt.Infof("%d domain(s) via namecom/%s%s", len(domains), profile, cacheNote(cached))
			return rt.Render(domainListResult{Profile: profile, Cached: cached, Domains: domains}, func() output.Grid {
				return domainGrid(domains)
			})
		},
	}
}

func newDomainGetCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get <domain>",
		Short: "Show the details of a registered domain",
		Args:  app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := rt.DomainArg(cmd.Context(), args, platform.NameCom, platform.ResDomain, nil)
			if err != nil {
				return err
			}
			profile, err := rt.ProfileFor(platform.NameCom)
			if err != nil {
				return err
			}
			d, cached, err := loadDomain(cmd.Context(), rt, profile, args[0])
			if err != nil {
				return err
			}
			rt.Infof("domain %s via namecom/%s%s", d.Name, profile, cacheNote(cached))
			return rt.Render(domainResult{Profile: profile, Cached: cached, Domain: d}, func() output.Grid { return domainKV(d) })
		},
	}
}

func newDomainNSGetCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get <domain>",
		Short: "Show the nameservers of a domain",
		Args:  app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := rt.DomainArg(cmd.Context(), args, platform.NameCom, platform.ResDomain, nil)
			if err != nil {
				return err
			}
			profile, err := rt.ProfileFor(platform.NameCom)
			if err != nil {
				return err
			}
			d, cached, err := loadDomain(cmd.Context(), rt, profile, args[0])
			if err != nil {
				return err
			}
			res := nameserversResult{Profile: profile, Cached: cached, Domain: d.Name, Nameservers: d.Nameservers}
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

func newDomainNSSetCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "set <domain> <nameserver>...",
		Short:   "Replace the nameservers of a domain",
		Long:    "Replace the nameservers of <domain> with the ones given.\n" + app.NameserverHelp,
		Example: "  polyctl namecom domain ns set example.com ns1.example.net ns2.example.net",
		Args:    app.NameserverArgsOrInteractive(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := rt.DomainArg(cmd.Context(), args, platform.NameCom, platform.ResDomain, nil)
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
			c, p, err := open(cmd.Context(), rt)
			if err != nil {
				return err
			}
			if done, err := rt.WouldWrite(platform.Target{Platform: platform.NameCom, Profile: p.Name, Domain: platform.NormalizeDomain(args[0])}, app.NameserverChange(args[0], ns)); done || err != nil {
				return err
			}
			d, err := c.SetNameserversDomain(cmd.Context(), args[0], ns)
			if err != nil {
				return err
			}
			warnInventory(rt, storeDomain(cmd.Context(), rt, p.Name, d))
			rt.Infof("nameservers of %s set to %s via namecom/%s", d.Name, strings.Join(d.Nameservers, ","), p.Name)
			res := nameserversResult{Profile: p.Name, Domain: d.Name, Nameservers: d.Nameservers}
			return rt.Render(res, func() output.Grid {
				g := output.Grid{Headers: []string{"NAMESERVER"}}
				for _, n := range d.Nameservers {
					g.Rows = append(g.Rows, []string{n})
				}
				return g
			})
		},
	}
	return cmd
}

func newDomainLockCmd(rt *app.Runtime, lock bool) *cobra.Command {
	use, short := "unlock <domain>", "Unlock a domain to allow transfers"
	if lock {
		use, short = "lock <domain>", "Lock a domain against transfers"
	}
	return &cobra.Command{
		Use:   use,
		Short: short,
		Args:  app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			// lock offers the unlocked domains, unlock the locked ones.
			args, err := rt.DomainArg(cmd.Context(), args, platform.NameCom, platform.ResDomain, func(d platform.Domain) bool {
				return (d.Locked != nil && *d.Locked) != lock
			})
			if err != nil {
				return err
			}
			c, p, err := open(cmd.Context(), rt)
			if err != nil {
				return err
			}
			if done, err := rt.WouldWrite(platform.Target{Platform: platform.NameCom, Profile: p.Name, Domain: platform.NormalizeDomain(args[0])}, app.ResourceChange("domain", platform.NormalizeDomain(args[0])+"/lock", platform.Updated, fmt.Sprintf("locked=%v", lock))); done || err != nil {
				return err
			}
			d, err := c.SetLock(cmd.Context(), args[0], lock)
			if err != nil {
				return err
			}
			warnInventory(rt, storeDomain(cmd.Context(), rt, p.Name, d))
			rt.Infof("%s is now locked=%s via namecom/%s", d.Name, output.Str(d.Locked), p.Name)
			return rt.Render(domainResult{Profile: p.Name, Domain: d}, func() output.Grid { return domainKV(d) })
		},
	}
}

func newDomainAutorenewCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:       "autorenew <domain> on|off",
		Short:     "Enable or disable automatic renewal of a domain",
		Args:      app.ArgsOrInteractive(rt, 2, nil),
		ValidArgs: []string{"on", "off"},
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := rt.DomainArg(cmd.Context(), args, platform.NameCom, platform.ResDomain, nil)
			if err != nil {
				return err
			}
			if len(args) < 2 {
				profile, err := rt.ProfileFor(platform.NameCom)
				if err != nil {
					return err
				}
				var cur *bool
				if d, _, err := loadDomain(cmd.Context(), rt, profile, args[0]); err == nil {
					cur = d.AutoRenew
				}
				v, err := rt.PickOnOff("Automatic renewal of "+args[0], cur)
				if err != nil {
					return err
				}
				args = append(args, v)
			}
			var enabled bool
			switch strings.ToLower(args[1]) {
			case "on", "enable", "true":
				enabled = true
			case "off", "disable", "false":
			default:
				return app.UsageErrf("expected on or off, got %q", args[1])
			}
			c, p, err := open(cmd.Context(), rt)
			if err != nil {
				return err
			}
			if done, err := rt.WouldWrite(platform.Target{Platform: platform.NameCom, Profile: p.Name, Domain: platform.NormalizeDomain(args[0])}, app.ResourceChange("domain", platform.NormalizeDomain(args[0])+"/autorenew", platform.Updated, fmt.Sprintf("autorenew=%v", enabled))); done || err != nil {
				return err
			}
			d, err := c.SetAutorenew(cmd.Context(), args[0], enabled)
			if err != nil {
				return err
			}
			warnInventory(rt, storeDomain(cmd.Context(), rt, p.Name, d))
			rt.Infof("%s autorenew=%s via namecom/%s", d.Name, output.Str(d.AutoRenew), p.Name)
			return rt.Render(domainResult{Profile: p.Name, Domain: d}, func() output.Grid { return domainKV(d) })
		},
	}
}

func newDomainCheckCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "check <name>...",
		Short: "Check availability and purchase price of domain names",
		Args:  app.MinArgsOrInteractive(rt, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := rt.NamesArgs(args)
			if err != nil {
				return err
			}
			c, p, err := open(cmd.Context(), rt)
			if err != nil {
				return err
			}
			results, err := c.CheckAvailability(cmd.Context(), args)
			if err != nil {
				return err
			}
			return rt.Render(availabilityResult{Profile: p.Name, Results: results}, func() output.Grid {
				g := output.Grid{Headers: []string{"DOMAIN", "PURCHASABLE", "PREMIUM", "PRICE", "RENEWAL", "TYPE"}, Empty: "no results"}
				for _, r := range results {
					price, renewal := "", ""
					if r.Purchasable {
						price = fmt.Sprintf("%.2f", r.PurchasePrice)
						renewal = fmt.Sprintf("%.2f", r.RenewalPrice)
					}
					g.Rows = append(g.Rows, []string{r.DomainName, fmt.Sprint(r.Purchasable), fmt.Sprint(r.Premium), price, renewal, r.PurchaseType})
				}
				return g
			})
		},
	}
}

// --- dns --------------------------------------------------------------------

func newDNSCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dns",
		Short: "DNS records hosted by name.com for a domain",
	}
	cmd.AddCommand(newDNSListCmd(rt), newDNSCreateCmd(rt), newDNSUpdateCmd(rt), newDNSDeleteCmd(rt))
	return cmd
}

func newDNSListCmd(rt *app.Runtime) *cobra.Command {
	var typ, name string
	cmd := &cobra.Command{
		Use:   "list <domain>",
		Short: "List the DNS records of a domain",
		Args:  app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := rt.DomainArg(cmd.Context(), args, platform.NameCom, platform.ResZone, nil)
			if err != nil {
				return err
			}
			domain := platform.NormalizeDomain(args[0])
			profile, err := rt.ProfileFor(platform.NameCom)
			if err != nil {
				return err
			}
			set := inventory.Set{Platform: platform.NameCom, Profile: profile, Type: platform.ResDNSRecord, Scope: domain}
			rows, cached, err := rt.EnsureSet(cmd.Context(), set, func(ctx context.Context) ([]platform.Resource, error) {
				c, _, err := open(ctx, rt)
				if err != nil {
					return nil, err
				}
				recs, err := c.ListRecords(ctx, domain)
				if err != nil {
					return nil, err
				}
				return app.RecordResources(domain, domain, recs), nil
			})
			if err != nil {
				return err
			}
			var recs []platform.Record
			for _, r := range rows {
				var rec platform.Record
				if err := r.Decode(&rec); err != nil {
					return fmt.Errorf("decode cached record %s: %w", r.ID, err)
				}
				recs = append(recs, rec)
			}
			if name != "" {
				recs = app.MatchRecords(recs, platform.FQDN(name, domain), typ, "")
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
			rt.Infof("zone %s via namecom/%s%s", domain, profile, cacheNote(cached))
			return rt.Render(recordsResult{Profile: profile, Cached: cached, Domain: domain, Records: recs}, func() output.Grid {
				return recordGrid(recs)
			})
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "filter by record type")
	cmd.Flags().StringVar(&name, "name", "", "filter by record name (relative, @ or FQDN)")
	return cmd
}

func newDNSCreateCmd(rt *app.Runtime) *cobra.Command {
	var typ, name, value string
	var ttl, priority int
	cmd := &cobra.Command{
		Use:   "create <domain> <name> <type> <value>",
		Short: "Create a DNS record",
		Long: `Create one record of <domain>. Records that already have the same name and
type are left alone.

<name> is relative to the domain (www, a.b), @ for the apex, or a full name
inside the domain (www.example.com). <type> is case-insensitive. The value is
one argument: quote one that contains spaces. A value that starts with "-" goes
after "--".`,
		Example: `  polyctl namecom dns create example.com www A 203.0.113.10
  polyctl namecom dns create example.com @ MX mail.example.com --priority 10
  polyctl namecom dns create example.com @ TXT "v=spf1 include:_spf.example.net ~all"`,
		Args:              app.RecordArgsOrInteractive(rt, 1, 1),
		ValidArgsFunction: app.CompleteRecordArgs(app.CompleteDomainArg(rt, platform.NameCom)),
		RunE: func(cmd *cobra.Command, args []string) error {
			// The record is positional (<name> <type> <value>) or, in the
			// former form, given with --name, --type and --value.
			if len(args) > 1 {
				rec, err := app.ParseRecordArgs(cmd, args[1:], 1, 1)
				if err != nil {
					return err
				}
				name, typ, value = rec.Name, rec.Type, rec.Value()
				args = args[:1]
			}
			if (typ == "" || value == "") && !rt.Interactive() {
				return app.UsageErrf("%s", app.RecordUsage(cmd, 1, 1))
			}
			args, err := rt.DomainArg(cmd.Context(), args, platform.NameCom, platform.ResZone, nil)
			if err != nil {
				// The record cannot be created without a zone.
				return app.RequiredPick(err, "<domain>")
			}
			if typ == "" {
				if typ, err = rt.PickRecordType(platform.NameCom); err != nil {
					return err
				}
			}
			if value == "" {
				if value, err = rt.AskRecordValue(strings.ToUpper(typ), ""); err != nil {
					return err
				}
			}
			domain := platform.NormalizeDomain(args[0])
			c, p, err := open(cmd.Context(), rt)
			if err != nil {
				return err
			}
			rec := platform.Record{ZoneID: domain, Name: platform.FQDN(name, domain), Type: strings.ToUpper(typ), Value: value, TTL: ttl}
			if cmd.Flags().Changed("priority") {
				pr := priority
				rec.Priority = &pr
			}
			if done, err := rt.WouldWrite(platform.Target{Platform: platform.NameCom, Profile: p.Name, Domain: domain}, platform.Change{Resource: app.RecordResource(rec.Name, rec.Type), Action: platform.Created, Detail: rec.Value}); done || err != nil {
				return err
			}
			out, err := c.CreateRecord(cmd.Context(), domain, rec)
			if err != nil {
				return err
			}
			warnInventory(rt, storeRecord(cmd.Context(), rt, p.Name, domain, out))
			rt.Infof("created %s %s -> %s (id %s) via namecom/%s", out.Name, out.Type, out.Value, out.ID, p.Name)
			return rt.Render(recordsResult{Profile: p.Name, Domain: domain, Records: []platform.Record{*out}}, func() output.Grid {
				return recordGrid([]platform.Record{*out})
			})
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "record type (A, AAAA, CNAME, TXT, MX, SRV, NS, ...)")
	cmd.Flags().StringVar(&name, "name", "", "record name relative to the domain (www, @); default: the apex")
	cmd.Flags().StringVar(&value, "value", "", "record value")
	cmd.Flags().IntVar(&ttl, "ttl", 0, "TTL in seconds (0 = name.com default, minimum 300)")
	cmd.Flags().IntVar(&priority, "priority", 0, "priority for MX/SRV records")
	// The former form of the record keeps working and is left out of the help.
	for _, n := range []string{"name", "type", "value"} {
		_ = cmd.Flags().MarkHidden(n)
	}
	return cmd
}

func newDNSUpdateCmd(rt *app.Runtime) *cobra.Command {
	var typ, name, value string
	var ttl, priority int
	cmd := &cobra.Command{
		Use:   "update <domain> <record-id>",
		Short: "Update one DNS record (fields that are not given keep their value)",
		Long: "Update the DNS record <record-id> of <domain>; the ids are shown by\n" +
			"`polyctl namecom dns list`. Only the fields given are changed.",
		Args: app.RecordIDArgsOrInteractive(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := rt.DomainArg(cmd.Context(), args, platform.NameCom, platform.ResZone, nil)
			if err != nil {
				return err
			}
			if len(args) < 2 {
				id, err := pickRecord(cmd.Context(), rt, args[0], "Update")
				if err != nil {
					return err
				}
				args = append(args, id)
			}
			id := args[1]
			domain := platform.NormalizeDomain(args[0])
			c, p, err := open(cmd.Context(), rt)
			if err != nil {
				return err
			}
			cur, err := c.GetRecord(cmd.Context(), domain, id)
			if err != nil {
				return err
			}
			rec := *cur
			if cmd.Flags().Changed("type") {
				rec.Type = strings.ToUpper(typ)
			}
			if cmd.Flags().Changed("name") {
				rec.Name = platform.FQDN(name, domain)
			}
			if cmd.Flags().Changed("value") {
				rec.Value = value
			}
			if cmd.Flags().Changed("ttl") {
				rec.TTL = ttl
			}
			if cmd.Flags().Changed("priority") {
				pr := priority
				rec.Priority = &pr
			}
			if done, err := rt.WouldWrite(platform.Target{Platform: platform.NameCom, Profile: p.Name, Domain: domain}, platform.Change{Resource: app.RecordResource(rec.Name, rec.Type), Action: platform.Updated, ID: id, Detail: cur.Value + " -> " + rec.Value}); done || err != nil {
				return err
			}
			out, err := c.UpdateRecord(cmd.Context(), domain, rec)
			if err != nil {
				return err
			}
			warnInventory(rt, storeRecord(cmd.Context(), rt, p.Name, domain, out))
			rt.Infof("updated %s %s -> %s (id %s) via namecom/%s", out.Name, out.Type, out.Value, out.ID, p.Name)
			return rt.Render(recordsResult{Profile: p.Name, Domain: domain, Records: []platform.Record{*out}}, func() output.Grid {
				return recordGrid([]platform.Record{*out})
			})
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "new record type")
	cmd.Flags().StringVar(&name, "name", "", "new record name relative to the domain (www, @)")
	cmd.Flags().StringVar(&value, "value", "", "new record value")
	cmd.Flags().IntVar(&ttl, "ttl", 0, "new TTL in seconds (minimum 300)")
	cmd.Flags().IntVar(&priority, "priority", 0, "new priority for MX/SRV records")
	return cmd
}

func newDNSDeleteCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <domain> <record-id>",
		Short: "Delete one DNS record (ids are shown by `polyctl namecom dns list`)",
		Args:  app.RecordIDArgsOrInteractive(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := rt.DomainArg(cmd.Context(), args, platform.NameCom, platform.ResZone, nil)
			if err != nil {
				return err
			}
			if len(args) < 2 {
				id, err := pickRecord(cmd.Context(), rt, args[0], "Delete")
				if err != nil {
					return err
				}
				args = append(args, id)
			}
			id := args[1]
			domain := platform.NormalizeDomain(args[0])
			// Canonicalise the id once so the inventory delete and the output
			// use the same form toRecord stores (e.g. " 123" / "0123" -> "123").
			n, err := parseRecordID(id)
			if err != nil {
				return err
			}
			id = strconv.FormatInt(n, 10)
			c, p, err := open(cmd.Context(), rt)
			if err != nil {
				return err
			}
			if done, err := rt.WouldWrite(platform.Target{Platform: platform.NameCom, Profile: p.Name, Domain: domain}, platform.Change{Resource: "record/" + id, Action: platform.Deleted, ID: id, Detail: "domain " + domain}); done || err != nil {
				return err
			}
			if err := c.DeleteRecord(cmd.Context(), domain, id); err != nil {
				return err
			}
			warnInventory(rt, dropRecord(cmd.Context(), rt, p.Name, id))
			rt.Infof("deleted record %s of %s via namecom/%s", id, domain, p.Name)
			return rt.Render(map[string]string{"profile": p.Name, "domain": domain, "deleted_id": id}, func() output.Grid { return output.Grid{} })
		},
	}
	return cmd
}

// pickRecord asks for one record of domain (the <record-id> of dns update
// and dns delete), read live.
func pickRecord(ctx context.Context, rt *app.Runtime, domain, verb string) (string, error) {
	c, _, err := open(ctx, rt)
	if err != nil {
		return "", err
	}
	recs, err := c.ListRecords(ctx, platform.NormalizeDomain(domain))
	if err != nil {
		return "", err
	}
	return rt.PickRecordID(verb+" which record of "+platform.NormalizeDomain(domain)+"?", recs, nil)
}
