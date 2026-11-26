package cloudflare

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// Command returns the `polyctl cloudflare` command tree. The command is
// named after the platform id, like every other tree; `cf` is kept as an
// alias because the platform id itself accepts that short form.
func Command(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "cloudflare",
		Aliases: []string{"cf"},
		Short:   "Cloudflare native commands (alias: cf)",
		Long: `Cloudflare-specific operations: zones (create, ensure, delete, settings),
DNS records, cache purge, cache rules, redirect rules, development mode,
SSL mode, R2 custom domains, the accounts of the login and the identity check.

<zone> arguments accept a zone name (example.com) or a zone id. Names are
resolved through the local inventory first, then remotely.

One login works on every Cloudflare account its credentials see, unless an
account was disabled; one of them is the default account (see polyctl
cloudflare account). Lists and lookups cover every enabled account, and a new
zone goes to the default account. --account <id or name> on the zone, dns,
cache, redirect, dev-mode, ssl-mode and r2 commands names one account for the
call; a disabled account is read live then and nothing of it is cached.

The tree is also available under its short name: polyctl cf ...`,
	}
	cmd.AddCommand(
		app.WhoamiCommand(rt, platform.Cloudflare, "On Cloudflare this verifies the API token and reports its id, status and\nexpiry, with the default account of the login and the accounts that are\ndisabled for it, when there are any. For a login authorized in the browser it checks\nthe authorization with a request to the API and reports the granted scopes."),
		newR2Cmd(rt), newAccountCmd(rt))
	// The commands that work on zones take --account.
	for _, c := range []*cobra.Command{newZoneCmd(rt), newDNSCmd(rt), newCacheCmd(rt), newRedirectCmd(rt), newDevModeCmd(rt), newSSLModeCmd(rt)} {
		addAccountFlag(rt, c)
		cmd.AddCommand(c)
	}
	noteSameName(cmd)
	return cmd
}

// sameZoneHelp is the paragraph every command that looks a zone up by its
// name carries in its help: what happens when several accounts hold a zone
// of the name.
const sameZoneHelp = `

One Cloudflare login works on several accounts. A zone name that several of
the enabled accounts hold a zone of (an active zone in one, a pending one in
another) is asked on a terminal. In the non-interactive flow it is exit code
5: the error lists the zones with their accounts and names what chooses one:
--account <id or name>, the zone id, or --profile when the zones are of
different logins.`

// sameBucketHelp is the same paragraph for the commands that look an R2
// bucket up by its name.
const sameBucketHelp = `

One Cloudflare login works on several accounts, and the name of a bucket is
unique in its account only. A bucket name that several accounts hold is asked
on a terminal. In the non-interactive flow it is exit code 5: the error lists
the accounts and names what chooses one: --account <id or name>, or --profile
when the accounts are of different logins.`

// noteSameName appends sameZoneHelp or sameBucketHelp to the help of every
// command below c that finds an existing zone or bucket by the name it is
// given: the ones with a <zone> or <bucket> argument. zone create and zone
// ensure take a <domain> and say in their own help what they do with it.
func noteSameName(c *cobra.Command) {
	if !c.HasSubCommands() {
		note := ""
		switch {
		case strings.Contains(c.Use, "<zone>"):
			note = sameZoneHelp
		case strings.Contains(c.Use, "<bucket>"):
			note = sameBucketHelp
		}
		if note != "" {
			if c.Long == "" {
				c.Long = c.Short
			}
			c.Long += note
		}
	}
	for _, sub := range c.Commands() {
		noteSameName(sub)
	}
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

// cachedZones returns the zones of the resolved profile in the scope of
// the call (the enabled accounts, or the one of --account) honouring
// --refresh/--offline/TTL, and whether they came from the cache. The zones
// of a disabled account are read live and not stored.
func cachedZones(ctx context.Context, rt *app.Runtime) ([]platform.Zone, acctScope, bool, error) {
	profile, err := rt.ProfileFor(platform.Cloudflare)
	if err != nil {
		return nil, acctScope{}, false, err
	}
	sc, err := profileScope(ctx, rt, profile)
	if err != nil {
		return nil, acctScope{profile: profile}, false, err
	}
	if sc.live {
		s, err := open(ctx, rt)
		if err != nil {
			return nil, sc, false, err
		}
		zones, err := s.client.pin(sc.pin).ListZones(ctx)
		return zones, sc, false, err
	}
	rows, cached, err := rt.EnsureSet(ctx, zoneSet(profile), func(ctx context.Context) ([]platform.Resource, error) {
		s, err := open(ctx, rt)
		if err != nil {
			return nil, err
		}
		// One listing covers every enabled account.
		return s.client.Sync(ctx, platform.ResZone)
	})
	if err != nil {
		return nil, sc, cached, err
	}
	zones := make([]platform.Zone, 0, len(rows))
	for _, r := range rows {
		var z platform.Zone
		if err := r.Decode(&z); err != nil {
			return nil, sc, cached, fmt.Errorf("decode cached zone %s: %w", r.ID, err)
		}
		if !sc.keeps(rowAccount(r)) {
			continue
		}
		zones = append(zones, z)
	}
	return zones, sc, cached, nil
}

// resolveZone finds a zone by name or id in the scope of the call:
// inventory first, then remotely (unless --offline). A remote hit is stored
// in the inventory unless its account is disabled. A name that several
// accounts of the scope hold a zone of is a pick in the interactive flow
// and ambiguous (exit code 5) otherwise.
//
// An empty arg (the <zone> left out in the interactive flow) is asked for
// among the zones of the scope.
func resolveZone(ctx context.Context, rt *app.Runtime, arg string) (*platform.Zone, string, error) {
	zones, sc, _, err := cachedZones(ctx, rt)
	profile := sc.profile
	if err != nil {
		return nil, profile, err
	}
	if arg == "" {
		if arg, err = pickCachedZone(rt, zones, sc); err != nil {
			return nil, profile, err
		}
	}
	switch found := matchZones(zones, arg); len(found) {
	case 0:
	case 1:
		return &found[0], profile, nil
	default:
		cands := make([]zoneCand, 0, len(found))
		for _, z := range found {
			cands = append(cands, candOfZone(profile, z))
		}
		z, err := app.OneOf(rt, ambiguousZone(platform.NormalizeDomain(arg), cands, true), found, func(z platform.Zone) string { return candOfZone(profile, z).cells() })
		if err != nil {
			return nil, profile, err
		}
		return &z, profile, nil
	}
	if rt.Flags.Offline {
		return nil, profile, fmt.Errorf("%w: zone %q is not in the local inventory (profile %s)", platform.ErrNotFound, arg, profile)
	}
	s, err := open(ctx, rt)
	if err != nil {
		return nil, profile, err
	}
	az, err := findLiveZone(ctx, rt, s.client.api, sc, arg)
	if err != nil {
		return nil, profile, err
	}
	z := toZone(*az)
	if cacheable(rt, profile, az.Account.ID) {
		if db, err := rt.DB(); err == nil {
			cfg, _ := rt.Config()
			_ = db.Upsert(ctx, zoneSet(profile), zoneResources([]platform.Zone{z})[0], cfg.TTLFor(platform.ResZone))
		}
	}
	return &z, profile, nil
}

// matchZones returns the zone of the id arg, or the zones named arg.
func matchZones(zones []platform.Zone, arg string) []platform.Zone {
	name := platform.NormalizeDomain(arg)
	var named []platform.Zone
	for _, z := range zones {
		if z.ID == arg {
			return []platform.Zone{z}
		}
		if platform.NormalizeDomain(z.Name) == name {
			named = append(named, z)
		}
	}
	return named
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

// zoneGrid lists zones; those of several accounts are listed with the
// account of each.
func zoneGrid(zones []platform.Zone) output.Grid {
	several := severalAccounts(zones)
	g := output.Grid{Headers: []string{"NAME", "STATUS", "PLAN", "NAMESERVERS", "ID"}, Empty: "no zones"}
	if several {
		g.Headers = []string{"NAME", "ACCOUNT", "STATUS", "PLAN", "NAMESERVERS", "ID"}
	}
	for _, z := range zones {
		row := []string{z.Name}
		if several {
			row = append(row, nonEmpty(zoneAccountName(z), zoneAccount(z)))
		}
		g.Rows = append(g.Rows, append(row, z.Status, output.Str(z.Extra["plan"]), strings.Join(z.Nameservers, ","), z.ID))
	}
	return g
}

// severalAccounts reports whether zones are of more than one account.
func severalAccounts(zones []platform.Zone) bool {
	for _, z := range zones[min(1, len(zones)):] {
		if zoneAccount(z) != zoneAccount(zones[0]) {
			return true
		}
	}
	return false
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
	g := output.Grid{Headers: []string{"NAME", "TYPE", "VALUE", "TTL", "PROXIED", "ID"}, Empty: "no records"}
	for _, r := range recs {
		content := r.Value
		if r.Priority != nil {
			content = fmt.Sprintf("%d %s", *r.Priority, r.Value)
		}
		g.Rows = append(g.Rows, []string{r.Name, r.Type, content, platform.TTLLabel(platform.Cloudflare, r), output.Str(r.Proxied), r.ID})
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
	cmd := &cobra.Command{Use: "zone", Short: "Zones: list, get, create, ensure, delete and settings"}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List the zones of the profile, in every enabled account (or the one of --account)",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				zones, sc, cached, err := cachedZones(cmd.Context(), rt)
				if err != nil {
					return err
				}
				profile := sc.profile
				sort.SliceStable(zones, func(i, j int) bool { return zones[i].Name < zones[j].Name })
				rt.Infof("%d zone(s) via cloudflare/%s%s", len(zones), profile, cacheNote(cached))
				return rt.Render(zoneListResult{Profile: profile, Cached: cached, Zones: zones}, func() output.Grid { return zoneGrid(zones) })
			},
		},
		&cobra.Command{
			Use:               "get <zone>",
			Short:             "Show one zone",
			Args:              app.ArgsOrInteractive(rt, 1, nil),
			ValidArgsFunction: completeZones(rt),
			RunE: func(cmd *cobra.Command, args []string) error {
				z, profile, err := resolveZone(cmd.Context(), rt, app.Arg(args, 0))
				if err != nil {
					return err
				}
				return rt.Render(zoneResult{Profile: profile, Zone: z}, func() output.Grid { return zoneKV(z) })
			},
		},
		newZoneCreateCmd(rt), newZoneEnsureCmd(rt), newZoneDeleteCmd(rt), newZoneSettingCmd(rt),
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
		sc := localScope(cmd.Context(), rt, profile)
		out := make([]string, 0, len(rows))
		for _, r := range rows {
			if sc.keeps(rowAccount(r)) && !slices.Contains(out, r.Name) {
				out = append(out, r.Name)
			}
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

// zoneRecords returns the records of a zone through the inventory; those
// of a zone in a disabled account are read live and not stored.
func zoneRecords(ctx context.Context, rt *app.Runtime, profile string, z *platform.Zone) ([]platform.Record, bool, error) {
	if !cacheable(rt, profile, zoneAccount(*z)) {
		s, err := open(ctx, rt)
		if err != nil {
			return nil, false, err
		}
		recs, err := s.client.ListRecords(ctx, z.ID)
		return recs, false, err
	}
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
		Args:              app.ArgsOrInteractive(rt, 1, nil),
		ValidArgsFunction: completeZones(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			z, profile, err := resolveZone(cmd.Context(), rt, app.Arg(args, 0))
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

// storeRecord mirrors a mutation into the inventory, unless the zone is in
// a disabled account.
func storeRecord(ctx context.Context, rt *app.Runtime, profile string, z *platform.Zone, rec platform.Record) {
	if !cacheable(rt, profile, zoneAccount(*z)) {
		return
	}
	db, err := rt.DB()
	if err != nil {
		return
	}
	cfg, _ := rt.Config()
	_ = db.Upsert(ctx, recordSet(profile, ""), app.RecordResources(z.ID, z.Name, []platform.Record{rec})[0], cfg.TTLFor(platform.ResDNSRecord))
}

func newDNSCreateCmd(rt *app.Runtime) *cobra.Command {
	var comment string
	var ttl, priority int
	var proxied bool
	cmd := &cobra.Command{
		Use:   "create <zone> <name> <type> <value>",
		Short: "Create a DNS record",
		Long: `Create one record in <zone>. Records that already have the same name and
type are left alone.

<name> is relative to the zone (www, a.b), @ for the zone apex, or a full name
inside the zone (www.example.com). <type> is case-insensitive. The value is one
argument: quote one that contains spaces. A value that starts with "-" goes
after "--".

--proxied is a boolean: --proxied switches the proxy on, --proxied=false
switches it off, and without it Cloudflare's default applies.

` + app.RecordAskHelp("zone"),
		Example: `  polyctl cloudflare dns create example.com www A 203.0.113.10 --proxied
  polyctl cloudflare dns create example.com @ MX mail.example.com --priority 10
  polyctl cloudflare dns create example.com @ TXT "v=spf1 include:_spf.example.net ~all"`,
		Args:              app.ProxiedRecordArgs(app.RecordArgsOrInteractive(rt, 1, 1), 1),
		ValidArgsFunction: app.CompleteRecordArgs(completeZones(rt), platform.Cloudflare),
		RunE: func(cmd *cobra.Command, args []string) error {
			// The record is positional (<name> <type> <value>) or, in the
			// former form, given with --name, --type and --value. The
			// interactive flow asks for what is missing: the zone, the
			// name, the type and the value.
			in, err := rt.RecordInput(cmd, args, app.RecordForm{MinValues: 1, MaxValues: 1})
			if err != nil {
				return err
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			z, profile, err := resolveZone(cmd.Context(), rt, app.Arg(args, 0))
			if err != nil {
				// The record cannot be created without a zone.
				return app.RequiredPick(err, "<zone>")
			}
			s, err := mutationSession(cmd.Context(), rt)
			if err != nil {
				return err
			}
			if err := rt.CompleteRecord(in, app.RecordPrompt{Platform: platform.Cloudflare, Zone: z.Name,
				Existing: func() ([]platform.Record, error) { return s.client.ListRecords(cmd.Context(), z.ID) }}); err != nil {
				return err
			}
			name, typ, value := in.Name, in.Type, in.Value()
			rec := platform.Record{ZoneID: z.ID, Name: platform.FQDN(name, z.Name), Type: strings.ToUpper(typ), Value: value, TTL: ttl}
			if cmd.Flags().Changed("proxied") {
				px := proxied
				rec.Proxied = &px
			}
			if cmd.Flags().Changed("priority") {
				p := priority
				rec.Priority = &p
			}
			if comment != "" {
				rec.Extra = map[string]any{"comment": comment}
			}
			target := platform.Target{Platform: platform.Cloudflare, Profile: profile, Domain: z.Name}
			if done, err := rt.WouldWrite(target, platform.Change{Resource: app.RecordResource(rec.Name, rec.Type), Action: platform.Created, Detail: rec.Value}); done || err != nil {
				return err
			}
			out, err := s.client.CreateRecord(cmd.Context(), z.ID, rec)
			if err != nil {
				return err
			}
			storeRecord(cmd.Context(), rt, profile, z, *out)
			rt.Infof("created %s %s -> %s in zone %s via cloudflare/%s", out.Name, out.Type, out.Value, z.Name, profile)
			return rt.Render(recordsResult{Profile: profile, Zone: z, Records: []platform.Record{*out}}, func() output.Grid { return recordGrid([]platform.Record{*out}) })
		},
	}
	app.FormerRecordFlags(cmd, false)
	cmd.Flags().IntVar(&ttl, "ttl", 0, "TTL in seconds (0 or 1 = automatic)")
	cmd.Flags().IntVar(&priority, "priority", 0, "priority for MX/SRV/URI records")
	cmd.Flags().BoolVar(&proxied, "proxied", false, "proxy through Cloudflare: --proxied or --proxied=false (default: Cloudflare's default)")
	cmd.Flags().StringVar(&comment, "comment", "", "record comment")
	return cmd
}

// recordTargetForm is the form of update and delete: the record by name,
// --id, or the former <record-id> after the first argument.
var recordTargetForm = app.RecordTargetForm{FormerID: true}

// recordTargetHelp says how update and delete find their record.
var recordTargetHelp = recordTargetForm.Help("zone", "polyctl cloudflare dns list")

func newDNSUpdateCmd(rt *app.Runtime) *cobra.Command {
	var typ, name, value, comment, id string
	var ttl, priority int
	var proxied bool
	changeFlags := []string{"value", "ttl", "proxied", "priority", "comment", "name", "type"}
	cmd := &cobra.Command{
		Use:   "update <zone> [<name> [<type> [<value>]]]",
		Short: "Update one DNS record (fields that are not given keep their value)",
		Long: `Update one DNS record of <zone>: the record of <name>, or the one with --id.
Only the fields given with flags are changed; the positional <type> and
<value> say which record is meant, --type and --value what it becomes.

` + recordTargetHelp + `

` + app.RecordUpdateHelp + `

--proxied is a boolean: --proxied switches the proxy on, --proxied=false
switches it off, and without it the record keeps its current setting.`,
		Example: `  polyctl cloudflare dns update example.com www --value 203.0.113.20
  polyctl cloudflare dns update example.com www A --proxied=false
  polyctl cloudflare dns update example.com www A 203.0.113.10 --value 203.0.113.20
  polyctl cloudflare dns update example.com --id 372e67954025e0ba6aaa6d586b9e0b59 --ttl 300`,
		Args:              app.ProxiedTargetArgs(recordTargetForm.ArgsOrInteractive(rt)),
		ValidArgsFunction: recordTargetForm.Complete(rt, completeZones(rt), platform.Cloudflare),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := recordTargetForm.Parse(cmd, args)
			if err != nil {
				return err
			}
			changes, err := rt.RecordChanges(cmd, changeFlags...)
			if err != nil {
				return err
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			z, profile, err := resolveZone(cmd.Context(), rt, app.Arg(args, 0))
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
			chosen, err := rt.SelectRecords(target.Select(app.RecordSelect{Zone: z.Name, Records: existing, ID: id, One: true, Verb: "Update", Grid: recordGrid}))
			if err != nil {
				return err
			}
			cur := &chosen.Records[0]
			if !changes {
				if value, err = rt.AskNewRecordValue(*cur); err != nil {
					return err
				}
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
				rec.Value = value
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
			if cmd.Flags().Changed("proxied") {
				px := proxied
				rec.Proxied = &px
			}
			if cmd.Flags().Changed("comment") {
				rec.Extra["comment"] = comment
			}
			report := platform.Target{Platform: platform.Cloudflare, Profile: profile, Domain: z.Name}
			if done, err := rt.WouldWrite(report, platform.Change{Resource: app.RecordResource(rec.Name, rec.Type), Action: platform.Updated, ID: cur.ID, Detail: cur.Value + " -> " + rec.Value}); done || err != nil {
				return err
			}
			out, err := s.client.UpdateRecord(cmd.Context(), z.ID, rec)
			if err != nil {
				return err
			}
			storeRecord(cmd.Context(), rt, profile, z, *out)
			rt.Infof("updated %s %s -> %s in zone %s via cloudflare/%s", out.Name, out.Type, out.Value, z.Name, profile)
			return rt.Render(recordsResult{Profile: profile, Zone: z, Records: []platform.Record{*out}}, func() output.Grid { return recordGrid([]platform.Record{*out}) })
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "update the record with this id")
	cmd.Flags().StringVar(&typ, "type", "", "new record type")
	cmd.Flags().StringVar(&name, "name", "", "new record name relative to the zone (www, @) or FQDN")
	cmd.Flags().StringVar(&value, "value", "", "new record value")
	cmd.Flags().IntVar(&ttl, "ttl", 0, "new TTL in seconds (0 or 1 = automatic)")
	cmd.Flags().IntVar(&priority, "priority", 0, "new priority for MX/SRV/URI records")
	cmd.Flags().BoolVar(&proxied, "proxied", false, "proxy through Cloudflare: --proxied or --proxied=false (default: keep the current setting)")
	cmd.Flags().StringVar(&comment, "comment", "", "new record comment (empty string clears it)")
	return cmd
}

// deleteResult is the output of dns delete. Deleted is the id of the
// record when one was deleted, as the command printed it when it took one
// record id.
type deleteResult struct {
	Profile string            `json:"profile" yaml:"profile"`
	ZoneID  string            `json:"zone_id" yaml:"zone_id"`
	Zone    string            `json:"zone" yaml:"zone"`
	Deleted string            `json:"deleted,omitempty" yaml:"deleted,omitempty"`
	Records []platform.Record `json:"records" yaml:"records"`
}

func newDNSDeleteCmd(rt *app.Runtime) *cobra.Command {
	var id string
	cmd := &cobra.Command{
		Use:   "delete <zone> [<name> [<type> [<value>]]]",
		Short: "Delete the DNS records of a name (optionally of one type and value), or one record by --id",
		Long: `Delete the records of <name> in <zone>, or the one record with --id.

` + recordTargetHelp + `

` + app.RecordDeleteHelp + `

The CNAME of an R2 custom domain is removed by unbinding the domain from its
bucket. --dry-run reports what would be deleted and asks nothing.`,
		Example: `  polyctl cloudflare dns delete example.com www
  polyctl cloudflare dns delete example.com www A
  polyctl cloudflare dns delete example.com www A 203.0.113.10
  polyctl cloudflare dns delete example.com --id 372e67954025e0ba6aaa6d586b9e0b59`,
		Args:              recordTargetForm.ArgsOrInteractive(rt),
		ValidArgsFunction: recordTargetForm.Complete(rt, completeZones(rt), platform.Cloudflare),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := recordTargetForm.Parse(cmd, args)
			if err != nil {
				return err
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			z, profile, err := resolveZone(cmd.Context(), rt, app.Arg(args, 0))
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
			sel := target.Select(app.RecordSelect{Zone: z.Name, Records: existing, ID: id, Verb: "Delete", Grid: recordGrid})
			// A record owned by another service (the CNAME of an R2 custom
			// domain) is marked in a list and deleted by unbinding it there.
			sel.Offer, sel.Mark = app.DeletableRecords(s.client, *z)
			chosen, err := rt.SelectRecords(sel)
			if err != nil {
				return err
			}
			del := app.RecordsDelete{Target: platform.Target{Platform: platform.Cloudflare, Profile: profile, Domain: z.Name},
				Zone: *z, DNS: s.client, Records: chosen.Records, Grid: recordGrid, Exact: sel.Exact(chosen)}
			if done, err := rt.DeleteRecords(cmd.Context(), del); !done || err != nil {
				return err
			}
			res := deleteResult{Profile: profile, ZoneID: z.ID, Zone: z.Name, Records: chosen.Records}
			if len(chosen.Records) == 1 {
				res.Deleted = chosen.Records[0].ID
			}
			return rt.Render(res, func() output.Grid { return output.Grid{} })
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "delete the record with this id")
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
	cmd := &cobra.Command{Use: "cache", Short: "Edge cache: purge and cache rules"}
	var everything bool
	var urls, hosts, tags, prefixes []string
	purge := &cobra.Command{
		Use:               "purge <zone>",
		Short:             "Purge cached content (--everything, or --url/--host/--tag/--prefix)",
		Args:              app.ArgsOrInteractive(rt, 1, nil),
		ValidArgsFunction: completeZones(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			selective := len(urls)+len(hosts)+len(tags)+len(prefixes) > 0
			if everything && selective {
				return app.UsageErrf("pass exactly one of --everything or a selection (--url, --host, --tag, --prefix)")
			}
			if !everything && !selective {
				// The interactive flow asks what to purge.
				if !rt.Interactive() {
					return app.UsageErrf("pass exactly one of --everything or a selection (--url, --host, --tag, --prefix)")
				}
				var err error
				if everything, urls, hosts, tags, prefixes, err = askPurge(rt); err != nil {
					return err
				}
				selective = !everything
			}
			req := purgeRequest{PurgeEverything: everything, Files: urls, Hosts: hosts, Tags: tags, Prefixes: prefixes}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			z, profile, err := resolveZone(cmd.Context(), rt, app.Arg(args, 0))
			if err != nil {
				return err
			}
			s, err := mutationSession(cmd.Context(), rt)
			if err != nil {
				return err
			}
			what := "everything"
			if selective {
				what = fmt.Sprintf("%d url(s), %d host(s), %d tag(s), %d prefix(es)", len(urls), len(hosts), len(tags), len(prefixes))
			}
			target := platform.Target{Platform: platform.Cloudflare, Profile: profile, Domain: z.Name}
			if done, err := rt.WouldWrite(target, app.ResourceChange("cache", z.Name, platform.Updated, "purge "+what)); done || err != nil {
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
	cmd.AddCommand(purge, newRuleCmd(rt, cacheRules))
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
		Args:              app.RangeArgsOrInteractive(rt, 1, 2, nil),
		ValidArgsFunction: completeZones(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			var value string
			if len(args) == 2 {
				value = strings.ToLower(args[1])
				ok := false
				for _, a := range allowed {
					ok = ok || a == value
				}
				if !ok {
					return app.UsageErrf("value must be one of: %s", strings.Join(allowed, ", "))
				}
			}
			z, profile, err := resolveZone(cmd.Context(), rt, app.Arg(args, 0))
			if err != nil {
				return err
			}
			var s *session
			var res *zoneSetting
			if value == "" {
				if s, err = open(cmd.Context(), rt); err != nil {
					return err
				}
				res, err = s.client.api.getSetting(cmd.Context(), z.ID, setting)
			} else {
				target := platform.Target{Platform: platform.Cloudflare, Profile: profile, Domain: z.Name}
				if done, err := rt.WouldWrite(target, app.ResourceChange("zone", z.Name+"/"+setting, platform.Updated, value)); done || err != nil {
					return err
				}
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
