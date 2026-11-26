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
	var ttl, priority int
	cmd := &cobra.Command{
		Use:   "create <domain> <name> <type> <value>",
		Short: "Create a DNS record",
		Long: `Create one record of <domain>. Records that already have the same name and
type are left alone.

` + app.RecordArgsHelp("domain") + `

` + app.RecordAskHelp("domain"),
		Example: `  polyctl namecom dns create example.com www A 203.0.113.10
  polyctl namecom dns create example.com @ MX mail.example.com --priority 10
  polyctl namecom dns create example.com @ TXT "v=spf1 include:_spf.example.net ~all"`,
		Args:              app.RecordArgsOrInteractive(rt, 1, 1),
		ValidArgsFunction: app.CompleteRecordArgs(app.CompleteDomainArg(rt, platform.NameCom), platform.NameCom),
		RunE: func(cmd *cobra.Command, args []string) error {
			// The record is positional (<name> <type> <value>) or, in the
			// former form, given with --name, --type and --value.
			in, err := rt.RecordInput(cmd, args, app.RecordForm{MinValues: 1, MaxValues: 1, Platform: platform.NameCom, Creates: true})
			if err != nil {
				return err
			}
			args, err = rt.DomainArg(cmd.Context(), args[:min(len(args), 1)], platform.NameCom, platform.ResZone, nil)
			if err != nil {
				// The record cannot be created without a zone.
				return app.RequiredPick(err, "<domain>")
			}
			domain := platform.NormalizeDomain(args[0])
			c, p, err := open(cmd.Context(), rt)
			if err != nil {
				return err
			}
			if err := rt.CompleteRecord(in, app.RecordPrompt{Platform: platform.NameCom, Zone: domain,
				Existing: func() ([]platform.Record, error) { return c.ListRecords(cmd.Context(), domain) }}); err != nil {
				return err
			}
			checked, err := in.Check(cmd, "")
			if err != nil {
				return err
			}
			v := checked[0]
			rec := platform.Record{ZoneID: domain, Name: platform.FQDN(in.Name, domain), Type: v.Type, Value: v.Value, Priority: v.Priority, TTL: ttl}
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
	app.FormerRecordFlags(cmd, false)
	cmd.Flags().IntVar(&ttl, "ttl", 0, "TTL in seconds (0 = name.com default, minimum 300)")
	cmd.Flags().IntVar(&priority, "priority", 0, "priority of an MX record (or in front of its value)")
	return cmd
}

// recordTargetForm is the form of update and delete: the record by name,
// --id, or the former <record-id> after the first argument.
var recordTargetForm = app.RecordTargetForm{FormerID: true}

// recordTargetHelp says how update and delete find their record.
var recordTargetHelp = recordTargetForm.Help("domain", "polyctl namecom dns list")

// recordIDMatches reports whether id names r: a name.com record id is a
// number, and "0123" is the record 123.
func recordIDMatches(id string, r platform.Record) bool {
	n, err := parseRecordID(id)
	return err == nil && strconv.FormatInt(n, 10) == r.ID
}

func newDNSUpdateCmd(rt *app.Runtime) *cobra.Command {
	var typ, name, value, id string
	var ttl, priority int
	changeFlags := []string{"value", "ttl", "priority", "name", "type"}
	cmd := &cobra.Command{
		Use:   "update <domain> [<name> [<type> [<value>]]]",
		Short: "Update one DNS record (fields that are not given keep their value)",
		Long: `Update one DNS record of <domain>: the record of <name>, or the one with --id.
Only the fields given with flags are changed; the positional <type> and
<value> say which record is meant, --type and --value what it becomes.

` + recordTargetHelp + `

` + app.RecordUpdateHelp,
		Example: `  polyctl namecom dns update example.com www --value 203.0.113.20
  polyctl namecom dns update example.com www A 203.0.113.10 --value 203.0.113.20
  polyctl namecom dns update example.com @ MX --priority 20
  polyctl namecom dns update example.com --id 12345 --ttl 600`,
		Args:              recordTargetForm.ArgsOrInteractive(rt),
		ValidArgsFunction: recordTargetForm.Complete(rt, app.CompleteDomainArg(rt, platform.NameCom), platform.NameCom),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := recordTargetForm.Parse(cmd, args)
			if err != nil {
				return err
			}
			changes, err := rt.RecordChanges(cmd, changeFlags...)
			if err != nil {
				return err
			}
			if err := app.CheckRecordChange(cmd, platform.NameCom, target.TypeOf()); err != nil {
				return err
			}
			args, err = rt.DomainArg(cmd.Context(), args, platform.NameCom, platform.ResZone, nil)
			if err != nil {
				return err
			}
			domain := platform.NormalizeDomain(args[0])
			c, p, err := open(cmd.Context(), rt)
			if err != nil {
				return err
			}
			existing, err := c.ListRecords(cmd.Context(), domain)
			if err != nil {
				return err
			}
			chosen, err := rt.SelectRecords(target.Select(app.RecordSelect{Zone: domain, Records: existing, ID: id, IDMatches: recordIDMatches, One: true, Verb: "Update", Grid: recordGrid}))
			if err != nil {
				return err
			}
			cur := chosen.Records[0]
			rec := cur
			if !changes {
				if rec.Value, err = rt.AskNewRecordValue(cur); err != nil {
					return err
				}
			}
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
			if err := app.CheckRecordUpdate(cmd, platform.NameCom, cur, &rec); err != nil {
				return err
			}
			if done, err := rt.WouldWrite(platform.Target{Platform: platform.NameCom, Profile: p.Name, Domain: domain}, platform.Change{Resource: app.RecordResource(rec.Name, rec.Type), Action: platform.Updated, ID: cur.ID, Detail: cur.Value + " -> " + rec.Value}); done || err != nil {
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
	cmd.Flags().StringVar(&id, "id", "", "update the record with this id")
	cmd.Flags().StringVar(&typ, "type", "", "new record type")
	cmd.Flags().StringVar(&name, "name", "", "new record name relative to the domain (www, @)")
	cmd.Flags().StringVar(&value, "value", "", "new record value")
	cmd.Flags().IntVar(&ttl, "ttl", 0, "new TTL in seconds (minimum 300)")
	cmd.Flags().IntVar(&priority, "priority", 0, "new priority of an MX record")
	return cmd
}

// deleteResult is the output of dns delete. DeletedID is the id of the
// record when one was deleted, as the command printed it when it took one
// record id.
type deleteResult struct {
	Profile   string            `json:"profile" yaml:"profile"`
	Domain    string            `json:"domain" yaml:"domain"`
	DeletedID string            `json:"deleted_id,omitempty" yaml:"deleted_id,omitempty"`
	Records   []platform.Record `json:"records" yaml:"records"`
}

func newDNSDeleteCmd(rt *app.Runtime) *cobra.Command {
	var id string
	cmd := &cobra.Command{
		Use:   "delete <domain> [<name> [<type> [<value>]]]",
		Short: "Delete the DNS records of a name (optionally of one type and value), or one record by --id",
		Long: `Delete the records of <name> in <domain>, or the one record with --id.

` + recordTargetHelp + `

` + app.RecordDeleteHelp + `

--dry-run reports what would be deleted and asks nothing.`,
		Example: `  polyctl namecom dns delete example.com www
  polyctl namecom dns delete example.com www A
  polyctl namecom dns delete example.com www A 203.0.113.10
  polyctl namecom dns delete example.com --id 12345`,
		Args:              recordTargetForm.ArgsOrInteractive(rt),
		ValidArgsFunction: recordTargetForm.Complete(rt, app.CompleteDomainArg(rt, platform.NameCom), platform.NameCom),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := recordTargetForm.Parse(cmd, args)
			if err != nil {
				return err
			}
			args, err = rt.DomainArg(cmd.Context(), args, platform.NameCom, platform.ResZone, nil)
			if err != nil {
				return err
			}
			domain := platform.NormalizeDomain(args[0])
			c, p, err := open(cmd.Context(), rt)
			if err != nil {
				return err
			}
			existing, err := c.ListRecords(cmd.Context(), domain)
			if err != nil {
				return err
			}
			zone := platform.Zone{ID: domain, Name: domain}
			sel := target.Select(app.RecordSelect{Zone: domain, Records: existing, ID: id, IDMatches: recordIDMatches, Verb: "Delete", Grid: recordGrid})
			sel.Offer, sel.Mark = app.DeletableRecords(c, zone)
			chosen, err := rt.SelectRecords(sel)
			if err != nil {
				return err
			}
			del := app.RecordsDelete{Target: platform.Target{Platform: platform.NameCom, Profile: p.Name, Domain: domain},
				Zone: zone, DNS: c, Records: chosen.Records, Grid: recordGrid, Exact: sel.Exact(chosen)}
			if done, err := rt.DeleteRecords(cmd.Context(), del); !done || err != nil {
				return err
			}
			res := deleteResult{Profile: p.Name, Domain: domain, Records: chosen.Records}
			if len(chosen.Records) == 1 {
				res.DeletedID = chosen.Records[0].ID
			}
			return rt.Render(res, func() output.Grid { return output.Grid{} })
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "delete the record with this id")
	return cmd
}
