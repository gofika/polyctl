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
	cmd.AddCommand(newDomainCmd(rt), newDNSCmd(rt), newHelloCmd(rt))
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
	g := output.Grid{Headers: []string{"NAME", "TYPE", "CONTENT", "TTL", "ID"}, Empty: "no records"}
	for _, r := range recs {
		content := r.Content
		if r.Priority != nil {
			content = fmt.Sprintf("%d %s", *r.Priority, r.Content)
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

type helloResult struct {
	Profile    string `json:"profile" yaml:"profile"`
	Env        string `json:"env" yaml:"env"`
	Username   string `json:"username" yaml:"username"`
	ServerName string `json:"server_name,omitempty" yaml:"server_name,omitempty"`
	ServerTime string `json:"server_time,omitempty" yaml:"server_time,omitempty"`
	Motd       string `json:"motd,omitempty" yaml:"motd,omitempty"`
}

// --- hello ------------------------------------------------------------------

func newHelloCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "hello",
		Short: "Call GET /v4/hello to verify credentials and show the server time",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, p, err := open(cmd.Context(), rt)
			if err != nil {
				return err
			}
			h, err := c.hello(cmd.Context())
			if err != nil {
				return err
			}
			res := helloResult{Profile: p.Name, Env: c.env, Username: h.Username, ServerName: h.ServerName, ServerTime: h.ServerTime, Motd: h.Motd}
			return rt.Render(res, func() output.Grid {
				return output.KV("PROFILE", res.Profile, "ENV", res.Env, "USERNAME", res.Username, "SERVER", res.ServerName, "SERVER TIME", res.ServerTime, "MOTD", res.Motd)
			})
		},
	}
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
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
	var ns []string
	cmd := &cobra.Command{
		Use:   "set <domain> --ns ns1.example.com,ns2.example.com",
		Short: "Replace the nameservers of a domain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(ns) == 0 {
				return app.UsageErrf("--ns is required")
			}
			c, p, err := open(cmd.Context(), rt)
			if err != nil {
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
	cmd.Flags().StringSliceVar(&ns, "ns", nil, "nameservers (comma separated or repeated)")
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
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, p, err := open(cmd.Context(), rt)
			if err != nil {
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
		Args:      cobra.ExactArgs(2),
		ValidArgs: []string{"on", "off"},
		RunE: func(cmd *cobra.Command, args []string) error {
			var enabled bool
			switch strings.ToLower(args[1]) {
			case "on", "enable", "true":
				enabled = true
			case "off", "disable", "false":
			default:
				return fmt.Errorf("expected on or off, got %q", args[1])
			}
			c, p, err := open(cmd.Context(), rt)
			if err != nil {
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
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
		Use:   "create <domain> --type A --name www --value 1.2.3.4",
		Short: "Create a DNS record",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if typ == "" || value == "" {
				return app.UsageErrf("--type and --value are required")
			}
			domain := platform.NormalizeDomain(args[0])
			c, p, err := open(cmd.Context(), rt)
			if err != nil {
				return err
			}
			rec := platform.Record{ZoneID: domain, Name: platform.FQDN(name, domain), Type: strings.ToUpper(typ), Content: value, TTL: ttl}
			if cmd.Flags().Changed("priority") {
				pr := priority
				rec.Priority = &pr
			}
			out, err := c.CreateRecord(cmd.Context(), domain, rec)
			if err != nil {
				return err
			}
			warnInventory(rt, storeRecord(cmd.Context(), rt, p.Name, domain, out))
			rt.Infof("created %s %s -> %s (id %s) via namecom/%s", out.Name, out.Type, out.Content, out.ID, p.Name)
			return rt.Render(recordsResult{Profile: p.Name, Domain: domain, Records: []platform.Record{*out}}, func() output.Grid {
				return recordGrid([]platform.Record{*out})
			})
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "record type (A, AAAA, CNAME, TXT, MX, SRV, NS, ...)")
	cmd.Flags().StringVar(&name, "name", "", "record name relative to the domain (www, @); default: the apex")
	cmd.Flags().StringVar(&value, "value", "", "record content")
	cmd.Flags().IntVar(&ttl, "ttl", 0, "TTL in seconds (0 = name.com default, minimum 300)")
	cmd.Flags().IntVar(&priority, "priority", 0, "priority for MX/SRV records")
	return cmd
}

func newDNSUpdateCmd(rt *app.Runtime) *cobra.Command {
	var id, typ, name, value string
	var ttl, priority int
	cmd := &cobra.Command{
		Use:   "update <domain> --id <record-id> [--type] [--name] [--value] [--ttl] [--priority]",
		Short: "Update an existing DNS record by id (unspecified fields are kept)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id == "" {
				return app.UsageErrf("--id is required")
			}
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
				rec.Content = value
			}
			if cmd.Flags().Changed("ttl") {
				rec.TTL = ttl
			}
			if cmd.Flags().Changed("priority") {
				pr := priority
				rec.Priority = &pr
			}
			out, err := c.UpdateRecord(cmd.Context(), domain, rec)
			if err != nil {
				return err
			}
			warnInventory(rt, storeRecord(cmd.Context(), rt, p.Name, domain, out))
			rt.Infof("updated %s %s -> %s (id %s) via namecom/%s", out.Name, out.Type, out.Content, out.ID, p.Name)
			return rt.Render(recordsResult{Profile: p.Name, Domain: domain, Records: []platform.Record{*out}}, func() output.Grid {
				return recordGrid([]platform.Record{*out})
			})
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "record id (see 'namecom dns list')")
	cmd.Flags().StringVar(&typ, "type", "", "new record type")
	cmd.Flags().StringVar(&name, "name", "", "new record name relative to the domain (www, @)")
	cmd.Flags().StringVar(&value, "value", "", "new record content")
	cmd.Flags().IntVar(&ttl, "ttl", 0, "new TTL in seconds (minimum 300)")
	cmd.Flags().IntVar(&priority, "priority", 0, "new priority for MX/SRV records")
	return cmd
}

func newDNSDeleteCmd(rt *app.Runtime) *cobra.Command {
	var id string
	cmd := &cobra.Command{
		Use:   "delete <domain> --id <record-id>",
		Short: "Delete a DNS record by id",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id == "" {
				return app.UsageErrf("--id is required")
			}
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
			if err := c.DeleteRecord(cmd.Context(), domain, id); err != nil {
				return err
			}
			warnInventory(rt, dropRecord(cmd.Context(), rt, p.Name, id))
			rt.Infof("deleted record %s of %s via namecom/%s", id, domain, p.Name)
			return rt.Render(map[string]string{"profile": p.Name, "domain": domain, "deleted_id": id}, func() output.Grid { return output.Grid{} })
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "record id (see 'namecom dns list')")
	return cmd
}
