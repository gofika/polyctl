package cloudflare

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

// Command returns the `polyctl cf` command tree.
func Command(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cf",
		Short: "Cloudflare native commands",
		Long: `Cloudflare-specific operations: zones, DNS records, cache purge, development
mode, SSL mode, accounts and token verification.

<zone> arguments accept a zone name (example.com) or a zone id. Names are
resolved through the local inventory first, then remotely.`,
	}
	cmd.AddCommand(newZoneCmd(rt), newDNSCmd(rt), newCacheCmd(rt), newDevModeCmd(rt), newSSLModeCmd(rt), newAccountCmd(rt), newTokenCmd(rt))
	return cmd
}

// --- shared helpers --------------------------------------------------------

// session is an opened Cloudflare client with its profile name.
type session struct {
	client  *Client
	profile string
}

func open(ctx context.Context, rt *app.Runtime) (*session, error) {
	c, p, err := rt.OpenFor(ctx, platform.Cloudflare)
	if err != nil {
		return nil, err
	}
	cc, ok := c.(*Client)
	if !ok {
		return nil, fmt.Errorf("unexpected client type %T", c)
	}
	return &session{client: cc, profile: p.Name}, nil
}

// zoneSet is the inventory set holding the zones of a profile.
func zoneSet(profile string) inventory.Set {
	return inventory.Set{Platform: platform.Cloudflare, Profile: profile, Type: platform.ResZone}
}

// recordSet is the inventory set holding the records of one zone.
func recordSet(profile, zoneID string) inventory.Set {
	return inventory.Set{Platform: platform.Cloudflare, Profile: profile, Type: platform.ResDNSRecord, Scope: zoneID}
}

// cachedZones returns the zones of the resolved profile honouring
// --refresh/--offline/TTL, and whether they came from the cache.
func cachedZones(ctx context.Context, rt *app.Runtime) ([]platform.Zone, string, bool, error) {
	profile, err := rt.ProfileFor(platform.Cloudflare)
	if err != nil {
		return nil, "", false, err
	}
	rows, cached, err := rt.EnsureSet(ctx, zoneSet(profile), func(ctx context.Context) ([]platform.Resource, error) {
		s, err := open(ctx, rt)
		if err != nil {
			return nil, err
		}
		zones, err := s.client.ListZones(ctx)
		if err != nil {
			return nil, err
		}
		return app.ZoneResources(zones), nil
	})
	if err != nil {
		return nil, profile, cached, err
	}
	zones := make([]platform.Zone, 0, len(rows))
	for _, r := range rows {
		var z platform.Zone
		if err := r.Decode(&z); err != nil {
			return nil, profile, cached, fmt.Errorf("decode cached zone %s: %w", r.ID, err)
		}
		zones = append(zones, z)
	}
	return zones, profile, cached, nil
}

// resolveZone finds a zone by name or id: inventory first, then remotely
// (unless --offline). A remote hit is stored in the inventory.
func resolveZone(ctx context.Context, rt *app.Runtime, arg string) (*platform.Zone, string, error) {
	zones, profile, _, err := cachedZones(ctx, rt)
	if err != nil {
		return nil, profile, err
	}
	if z := matchZone(zones, arg); z != nil {
		return z, profile, nil
	}
	if rt.Flags.Offline {
		return nil, profile, fmt.Errorf("%w: zone %q is not in the local inventory (profile %s)", platform.ErrNotFound, arg, profile)
	}
	s, err := open(ctx, rt)
	if err != nil {
		return nil, profile, err
	}
	z, err := s.client.GetZone(ctx, arg)
	if err != nil {
		return nil, profile, err
	}
	if db, err := rt.DB(); err == nil {
		cfg, _ := rt.Config()
		_ = db.Upsert(ctx, zoneSet(profile), app.ZoneResources([]platform.Zone{*z})[0], cfg.TTLFor(platform.ResZone))
	}
	return z, profile, nil
}

func matchZone(zones []platform.Zone, arg string) *platform.Zone {
	name := platform.NormalizeDomain(arg)
	for i := range zones {
		if zones[i].ID == arg || platform.NormalizeDomain(zones[i].Name) == name {
			return &zones[i]
		}
	}
	return nil
}

// mutationSession rejects --offline and opens the client.
func mutationSession(ctx context.Context, rt *app.Runtime) (*session, error) {
	if rt.Flags.Offline {
		return nil, app.ErrOffline
	}
	return open(ctx, rt)
}

func cacheNote(cached bool) string {
	if cached {
		return " (local inventory)"
	}
	return ""
}

func parseBool(flag, v string) (*bool, error) {
	switch v {
	case "":
		return nil, nil
	case "true", "false":
		b := v == "true"
		return &b, nil
	}
	return nil, fmt.Errorf("--%s must be true or false", flag)
}

// --- output shapes ---------------------------------------------------------

type zoneListResult struct {
	Profile string          `json:"profile" yaml:"profile"`
	Cached  bool            `json:"cached" yaml:"cached"`
	Zones   []platform.Zone `json:"zones" yaml:"zones"`
}

type zoneResult struct {
	Profile string         `json:"profile" yaml:"profile"`
	Zone    *platform.Zone `json:"zone" yaml:"zone"`
}

type recordsResult struct {
	Profile string            `json:"profile" yaml:"profile"`
	Zone    *platform.Zone    `json:"zone" yaml:"zone"`
	Cached  bool              `json:"cached" yaml:"cached"`
	Records []platform.Record `json:"records" yaml:"records"`
}

func zoneGrid(zones []platform.Zone) output.Grid {
	g := output.Grid{Headers: []string{"NAME", "STATUS", "PLAN", "NAMESERVERS", "ID"}, Empty: "no zones"}
	for _, z := range zones {
		g.Rows = append(g.Rows, []string{z.Name, z.Status, output.Str(z.Extra["plan"]), strings.Join(z.Nameservers, ","), z.ID})
	}
	return g
}

func zoneKV(z *platform.Zone) output.Grid {
	return output.KV(
		"name", z.Name,
		"id", z.ID,
		"status", z.Status,
		"plan", output.Str(z.Extra["plan"]),
		"paused", output.Str(z.Extra["paused"]),
		"account_id", output.Str(z.Extra["account_id"]),
		"account_name", output.Str(z.Extra["account_name"]),
		"nameservers", strings.Join(z.Nameservers, ","),
	)
}

func recordGrid(recs []platform.Record) output.Grid {
	g := output.Grid{Headers: []string{"NAME", "TYPE", "CONTENT", "TTL", "PROXIED", "ID"}, Empty: "no records"}
	for _, r := range recs {
		content := r.Content
		if r.Priority != nil {
			content = fmt.Sprintf("%d %s", *r.Priority, r.Content)
		}
		ttl := fmt.Sprint(r.TTL)
		if r.TTL == 1 {
			ttl = "auto"
		}
		g.Rows = append(g.Rows, []string{r.Name, r.Type, content, ttl, output.Str(r.Proxied), r.ID})
	}
	return g
}

func sortRecords(recs []platform.Record) {
	sort.SliceStable(recs, func(i, j int) bool {
		if recs[i].Name != recs[j].Name {
			return recs[i].Name < recs[j].Name
		}
		return recs[i].Type < recs[j].Type
	})
}

// --- zone ------------------------------------------------------------------

func newZoneCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "zone", Short: "Zones"}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List zones of the profile",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				zones, profile, cached, err := cachedZones(cmd.Context(), rt)
				if err != nil {
					return err
				}
				sort.SliceStable(zones, func(i, j int) bool { return zones[i].Name < zones[j].Name })
				rt.Infof("%d zone(s) via cloudflare/%s%s", len(zones), profile, cacheNote(cached))
				return rt.Render(zoneListResult{Profile: profile, Cached: cached, Zones: zones}, func() output.Grid { return zoneGrid(zones) })
			},
		},
		&cobra.Command{
			Use:               "get <zone>",
			Short:             "Show one zone",
			Args:              cobra.ExactArgs(1),
			ValidArgsFunction: completeZones(rt),
			RunE: func(cmd *cobra.Command, args []string) error {
				z, profile, err := resolveZone(cmd.Context(), rt, args[0])
				if err != nil {
					return err
				}
				return rt.Render(zoneResult{Profile: profile, Zone: z}, func() output.Grid { return zoneKV(z) })
			},
		},
	)
	return cmd
}

// completeZones completes zone names from the local inventory.
func completeZones(rt *app.Runtime) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) > 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		profile, err := rt.ProfileFor(platform.Cloudflare)
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		db, err := rt.DB()
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		rows, err := db.List(cmd.Context(), inventory.Query{Platform: platform.Cloudflare, Profile: profile, Type: platform.ResZone})
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		out := make([]string, 0, len(rows))
		for _, r := range rows {
			out = append(out, r.Name)
		}
		return out, cobra.ShellCompDirectiveNoFileComp
	}
}

// --- dns -------------------------------------------------------------------

func newDNSCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "dns", Short: "DNS records of a zone"}
	cmd.AddCommand(newDNSListCmd(rt), newDNSCreateCmd(rt), newDNSUpdateCmd(rt), newDNSDeleteCmd(rt))
	return cmd
}

// zoneRecords returns the records of a zone through the inventory.
func zoneRecords(ctx context.Context, rt *app.Runtime, profile string, z *platform.Zone) ([]platform.Record, bool, error) {
	rows, cached, err := rt.EnsureSet(ctx, recordSet(profile, z.ID), func(ctx context.Context) ([]platform.Resource, error) {
		s, err := open(ctx, rt)
		if err != nil {
			return nil, err
		}
		recs, err := s.client.ListRecords(ctx, z.ID)
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

func newDNSListCmd(rt *app.Runtime) *cobra.Command {
	var typ, name string
	cmd := &cobra.Command{
		Use:               "list <zone>",
		Short:             "List DNS records of a zone",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeZones(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			z, profile, err := resolveZone(cmd.Context(), rt, args[0])
			if err != nil {
				return err
			}
			recs, cached, err := zoneRecords(cmd.Context(), rt, profile, z)
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
			rt.Infof("zone %s via cloudflare/%s%s", z.Name, profile, cacheNote(cached))
			return rt.Render(recordsResult{Profile: profile, Zone: z, Cached: cached, Records: recs}, func() output.Grid { return recordGrid(recs) })
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "filter by record type")
	cmd.Flags().StringVar(&name, "name", "", "filter by record name (relative, @ or FQDN)")
	return cmd
}

// storeRecord mirrors a mutation into the inventory.
func storeRecord(ctx context.Context, rt *app.Runtime, profile string, z *platform.Zone, rec platform.Record) {
	db, err := rt.DB()
	if err != nil {
		return
	}
	cfg, _ := rt.Config()
	_ = db.Upsert(ctx, recordSet(profile, ""), app.RecordResources(z.ID, z.Name, []platform.Record{rec})[0], cfg.TTLFor(platform.ResDNSRecord))
}

func newDNSCreateCmd(rt *app.Runtime) *cobra.Command {
	var typ, name, value, proxied, comment string
	var ttl, priority int
	cmd := &cobra.Command{
		Use:               "create <zone>",
		Short:             "Create a DNS record",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeZones(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			if typ == "" || name == "" || value == "" {
				return app.UsageErrf("--type, --name and --value are required")
			}
			px, err := parseBool("proxied", proxied)
			if err != nil {
				return err
			}
			z, profile, err := resolveZone(cmd.Context(), rt, args[0])
			if err != nil {
				return err
			}
			s, err := mutationSession(cmd.Context(), rt)
			if err != nil {
				return err
			}
			rec := platform.Record{ZoneID: z.ID, Name: platform.FQDN(name, z.Name), Type: strings.ToUpper(typ), Content: value, TTL: ttl, Proxied: px}
			if cmd.Flags().Changed("priority") {
				p := priority
				rec.Priority = &p
			}
			if comment != "" {
				rec.Extra = map[string]any{"comment": comment}
			}
			out, err := s.client.CreateRecord(cmd.Context(), z.ID, rec)
			if err != nil {
				return err
			}
			storeRecord(cmd.Context(), rt, profile, z, *out)
			rt.Infof("created %s %s -> %s in zone %s via cloudflare/%s", out.Name, out.Type, out.Content, z.Name, profile)
			return rt.Render(recordsResult{Profile: profile, Zone: z, Records: []platform.Record{*out}}, func() output.Grid { return recordGrid([]platform.Record{*out}) })
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "record type (A, AAAA, CNAME, TXT, MX, ...)")
	cmd.Flags().StringVar(&name, "name", "", "record name relative to the zone (www, @) or FQDN")
	cmd.Flags().StringVar(&value, "value", "", "record content")
	cmd.Flags().IntVar(&ttl, "ttl", 0, "TTL in seconds (0 or 1 = automatic)")
	cmd.Flags().IntVar(&priority, "priority", 0, "priority for MX/SRV/URI records")
	cmd.Flags().StringVar(&proxied, "proxied", "", "proxy through Cloudflare: true or false")
	cmd.Flags().StringVar(&comment, "comment", "", "record comment")
	return cmd
}

func newDNSUpdateCmd(rt *app.Runtime) *cobra.Command {
	var id, typ, name, value, proxied, comment string
	var ttl, priority int
	cmd := &cobra.Command{
		Use:               "update <zone>",
		Short:             "Update the DNS record identified by --id (unset fields keep their value)",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeZones(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id == "" {
				return app.UsageErrf("--id is required")
			}
			px, err := parseBool("proxied", proxied)
			if err != nil {
				return err
			}
			z, profile, err := resolveZone(cmd.Context(), rt, args[0])
			if err != nil {
				return err
			}
			s, err := mutationSession(cmd.Context(), rt)
			if err != nil {
				return err
			}
			existing, err := s.client.ListRecords(cmd.Context(), z.ID)
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
				return fmt.Errorf("%w: record %s in zone %s", platform.ErrNotFound, id, z.Name)
			}
			rec := *cur
			rec.ZoneID = z.ID
			rec.Extra = make(map[string]any, len(cur.Extra))
			for k, v := range cur.Extra {
				rec.Extra[k] = v
			}
			if typ != "" {
				rec.Type = strings.ToUpper(typ)
			}
			if name != "" {
				rec.Name = platform.FQDN(name, z.Name)
			}
			if value != "" {
				rec.Content = value
				// The structured `data` of SRV/CAA/LOC/... records takes
				// precedence over `content` on write; drop the stale copy so
				// the new value is not silently ignored.
				delete(rec.Extra, "data")
			}
			if cmd.Flags().Changed("ttl") {
				rec.TTL = ttl
			}
			if cmd.Flags().Changed("priority") {
				p := priority
				rec.Priority = &p
			}
			if px != nil {
				rec.Proxied = px
			}
			if cmd.Flags().Changed("comment") {
				rec.Extra["comment"] = comment
			}
			out, err := s.client.UpdateRecord(cmd.Context(), z.ID, rec)
			if err != nil {
				return err
			}
			storeRecord(cmd.Context(), rt, profile, z, *out)
			rt.Infof("updated %s %s -> %s in zone %s via cloudflare/%s", out.Name, out.Type, out.Content, z.Name, profile)
			return rt.Render(recordsResult{Profile: profile, Zone: z, Records: []platform.Record{*out}}, func() output.Grid { return recordGrid([]platform.Record{*out}) })
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "record id (see `cf dns list`)")
	cmd.Flags().StringVar(&typ, "type", "", "new record type")
	cmd.Flags().StringVar(&name, "name", "", "new record name relative to the zone (www, @) or FQDN")
	cmd.Flags().StringVar(&value, "value", "", "new record content")
	cmd.Flags().IntVar(&ttl, "ttl", 0, "new TTL in seconds (0 or 1 = automatic)")
	cmd.Flags().IntVar(&priority, "priority", 0, "new priority for MX/SRV/URI records")
	cmd.Flags().StringVar(&proxied, "proxied", "", "proxy through Cloudflare: true or false")
	cmd.Flags().StringVar(&comment, "comment", "", "new record comment (empty string clears it)")
	return cmd
}

func newDNSDeleteCmd(rt *app.Runtime) *cobra.Command {
	var id string
	cmd := &cobra.Command{
		Use:               "delete <zone>",
		Short:             "Delete the DNS record identified by --id",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeZones(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id == "" {
				return app.UsageErrf("--id is required")
			}
			z, profile, err := resolveZone(cmd.Context(), rt, args[0])
			if err != nil {
				return err
			}
			s, err := mutationSession(cmd.Context(), rt)
			if err != nil {
				return err
			}
			if err := s.client.DeleteRecord(cmd.Context(), z.ID, id); err != nil {
				return err
			}
			if db, err := rt.DB(); err == nil {
				_ = db.Delete(cmd.Context(), recordSet(profile, ""), platform.ResDNSRecord, id)
			}
			rt.Infof("deleted record %s from zone %s via cloudflare/%s", id, z.Name, profile)
			return rt.Render(map[string]string{"profile": profile, "zone_id": z.ID, "zone": z.Name, "deleted": id}, func() output.Grid { return output.Grid{} })
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "record id (see `cf dns list`)")
	return cmd
}

// --- cache -----------------------------------------------------------------

type purgeOutput struct {
	Profile string       `json:"profile" yaml:"profile"`
	Zone    string       `json:"zone" yaml:"zone"`
	ZoneID  string       `json:"zone_id" yaml:"zone_id"`
	Request purgeRequest `json:"request" yaml:"request"`
	ID      string       `json:"id,omitempty" yaml:"id,omitempty"`
}

func newCacheCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "cache", Short: "Edge cache"}
	var everything bool
	var urls, hosts, tags, prefixes []string
	purge := &cobra.Command{
		Use:               "purge <zone>",
		Short:             "Purge cached content (--everything, or --url/--host/--tag/--prefix)",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeZones(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := purgeRequest{PurgeEverything: everything, Files: urls, Hosts: hosts, Tags: tags, Prefixes: prefixes}
			selective := len(urls)+len(hosts)+len(tags)+len(prefixes) > 0
			if everything == selective {
				return errors.New("pass exactly one of --everything or a selection (--url, --host, --tag, --prefix)")
			}
			z, profile, err := resolveZone(cmd.Context(), rt, args[0])
			if err != nil {
				return err
			}
			s, err := mutationSession(cmd.Context(), rt)
			if err != nil {
				return err
			}
			res, err := s.client.api.purgeCache(cmd.Context(), z.ID, req)
			if err != nil {
				return err
			}
			out := purgeOutput{Profile: profile, Zone: z.Name, ZoneID: z.ID, Request: req}
			if res != nil {
				out.ID = res.ID
			}
			what := "everything"
			if selective {
				what = fmt.Sprintf("%d url(s), %d host(s), %d tag(s), %d prefix(es)", len(urls), len(hosts), len(tags), len(prefixes))
			}
			rt.Infof("purged %s for zone %s via cloudflare/%s", what, z.Name, profile)
			return rt.Render(out, func() output.Grid {
				return output.KV("zone", z.Name, "purged", what, "id", out.ID)
			})
		},
	}
	purge.Flags().BoolVar(&everything, "everything", false, "purge the whole zone cache")
	purge.Flags().StringArrayVar(&urls, "url", nil, "purge this URL (repeatable)")
	purge.Flags().StringArrayVar(&hosts, "host", nil, "purge this hostname (repeatable, Enterprise)")
	purge.Flags().StringArrayVar(&tags, "tag", nil, "purge this cache tag (repeatable, Enterprise)")
	purge.Flags().StringArrayVar(&prefixes, "prefix", nil, "purge this URL prefix (repeatable, Enterprise)")
	cmd.AddCommand(purge)
	return cmd
}

// --- zone settings ---------------------------------------------------------

type settingOutput struct {
	Profile string       `json:"profile" yaml:"profile"`
	Zone    string       `json:"zone" yaml:"zone"`
	ZoneID  string       `json:"zone_id" yaml:"zone_id"`
	Setting *zoneSetting `json:"setting" yaml:"setting"`
}

func settingKV(zone string, s *zoneSetting) output.Grid {
	pairs := []string{"zone", zone, "setting", s.ID, "value", output.Str(s.Value), "editable", fmt.Sprint(s.Editable)}
	if s.TimeRemaining > 0 {
		pairs = append(pairs, "time_remaining", fmt.Sprintf("%ds", s.TimeRemaining))
	}
	if s.ModifiedOn != "" {
		pairs = append(pairs, "modified_on", s.ModifiedOn)
	}
	return output.KV(pairs...)
}

// settingCmd builds a "get or set a zone setting" command.
func settingCmd(rt *app.Runtime, use, short, setting string, allowed []string) *cobra.Command {
	return &cobra.Command{
		Use:               use,
		Short:             short,
		Args:              cobra.RangeArgs(1, 2),
		ValidArgsFunction: completeZones(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			var value string
			if len(args) == 2 {
				value = strings.ToLower(args[1])
				ok := false
				for _, a := range allowed {
					ok = ok || a == value
				}
				if !ok {
					return fmt.Errorf("value must be one of: %s", strings.Join(allowed, ", "))
				}
			}
			z, profile, err := resolveZone(cmd.Context(), rt, args[0])
			if err != nil {
				return err
			}
			var s *session
			var res *zoneSetting
			if value == "" {
				if rt.Flags.Offline {
					return app.ErrOffline
				}
				if s, err = open(cmd.Context(), rt); err != nil {
					return err
				}
				res, err = s.client.api.getSetting(cmd.Context(), z.ID, setting)
			} else {
				if s, err = mutationSession(cmd.Context(), rt); err != nil {
					return err
				}
				res, err = s.client.api.setSetting(cmd.Context(), z.ID, setting, value)
				if err == nil {
					rt.Infof("%s of zone %s set to %s via cloudflare/%s", setting, z.Name, output.Str(res.Value), profile)
				}
			}
			if err != nil {
				return err
			}
			return rt.Render(settingOutput{Profile: profile, Zone: z.Name, ZoneID: z.ID, Setting: res}, func() output.Grid { return settingKV(z.Name, res) })
		},
	}
}

func newDevModeCmd(rt *app.Runtime) *cobra.Command {
	return settingCmd(rt, "dev-mode <zone> [on|off]", "Show or set development mode (bypasses the cache for 3 hours)", "development_mode", []string{"on", "off"})
}

func newSSLModeCmd(rt *app.Runtime) *cobra.Command {
	return settingCmd(rt, "ssl-mode <zone> [off|flexible|full|strict]", "Show or set the SSL/TLS encryption mode", "ssl", []string{"off", "flexible", "full", "strict"})
}

// --- account / token -------------------------------------------------------

type accountListResult struct {
	Profile  string    `json:"profile" yaml:"profile"`
	Accounts []account `json:"accounts" yaml:"accounts"`
}

func newAccountCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "account", Short: "Accounts"}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List accounts visible to the token (needs Account:Read)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			s, err := open(cmd.Context(), rt)
			if err != nil {
				return err
			}
			accounts, err := s.client.api.listAccounts(cmd.Context())
			if err != nil {
				return err
			}
			pinned := s.client.profile.Meta(metaAccountID)
			return rt.Render(accountListResult{Profile: s.profile, Accounts: accounts}, func() output.Grid {
				g := output.Grid{Headers: []string{"NAME", "TYPE", "ID", "PINNED"}, Empty: "no accounts"}
				for _, a := range accounts {
					mark := ""
					if a.ID == pinned {
						mark = "*"
					}
					g.Rows = append(g.Rows, []string{a.Name, a.Type, a.ID, mark})
				}
				return g
			})
		},
	})
	return cmd
}

type tokenVerifyResult struct {
	Profile string     `json:"profile" yaml:"profile"`
	Token   *tokenInfo `json:"token" yaml:"token"`
}

func newTokenCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "token", Short: "API token"}
	cmd.AddCommand(&cobra.Command{
		Use:   "verify",
		Short: "Verify the profile's API token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			s, err := open(cmd.Context(), rt)
			if err != nil {
				return err
			}
			tok, err := s.client.api.verifyToken(cmd.Context())
			if err != nil {
				return err
			}
			if tok.Status != "active" {
				rt.Infof("warning: token status is %q", tok.Status)
			}
			return rt.Render(tokenVerifyResult{Profile: s.profile, Token: tok}, func() output.Grid {
				return output.KV("profile", s.profile, "token_id", tok.ID, "status", tok.Status, "expires_on", tok.ExpiresOn, "not_before", tok.NotBefore)
			})
		},
	})
	return cmd
}
