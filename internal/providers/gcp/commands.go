package gcp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// Command returns the `polyctl gcp` command tree.
func Command(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gcp",
		Short: "Google Cloud native commands",
		Long: `Google Cloud commands that follow the platform's own model: Cloud DNS managed
zones hold multi-value record sets, Compute Engine instances live in zones.
A gcp account works on every project its credentials see, unless one was
disabled ("polyctl gcp project enable" chooses which are enabled). Lists and lookups cover every
enabled project, a create goes to the default project, and --project on the
dns and compute commands names the project of one call (pass --profile to pick
another account).`,
	}
	dns, compute := newDNSCmd(rt), newComputeCmd(rt)
	noteSameName(dns)
	noteSameName(compute)
	cmd.AddCommand(
		app.WhoamiCommand(rt, platform.GCP, "On Google Cloud this reads the default project of the account (or, without\nthat permission, its Cloud DNS zones) and reports the default project, the\ndisabled projects, the signed-in account and the login method."),
		newProjectCmd(rt), dns, compute)
	return cmd
}

// sameNameHelp is the paragraph every command that looks a resource up by
// its name carries in its help: what happens when several projects hold
// the name.
const sameNameHelp = `

One gcp account works on several projects. A name that several of the
enabled projects hold (or several zones, regions or accounts) is asked on a
terminal. In the non-interactive flow it is exit code 5: the error lists the
candidates and names what chooses one, --project <id> among them.`

// looksUpByName reports whether a command of the dns or compute tree finds
// an existing resource by the name it is given: every command with a
// positional argument, but the ones that create what the argument names.
func looksUpByName(c *cobra.Command) bool {
	if c.HasSubCommands() || !strings.Contains(c.Use, "<") {
		return false
	}
	switch c.Name() {
	case "create":
		return false
	case "ensure":
		// firewall ensure [<name>] creates the rule; load-balancer ensure
		// <instance> looks the instance up.
		return strings.Contains(c.Use, "<instance>")
	}
	return true
}

// noteSameName appends sameNameHelp to the help of every command below c
// that looks a resource up by name.
func noteSameName(c *cobra.Command) {
	if looksUpByName(c) {
		if c.Long == "" {
			c.Long = c.Short
		}
		c.Long += sameNameHelp
	}
	for _, sub := range c.Commands() {
		noteSameName(sub)
	}
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
	if pin := pinnedProject(rt); pin != "" {
		gc = gc.pin(pin)
	}
	return gc, prof, nil
}

// ---------------------------------------------------------------- dns

func newDNSCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "dns", Short: "Cloud DNS managed zones and record sets"}
	zone := &cobra.Command{Use: "zone", Short: "Managed zones"}
	zone.AddCommand(newZoneListCmd(rt), newZoneGetCmd(rt))
	record := &cobra.Command{Use: "record", Short: "Record sets of a managed zone"}
	record.AddCommand(newRecordListCmd(rt), newRecordUpsertCmd(rt), newRecordDeleteCmd(rt))
	cmd.AddCommand(zone, record)
	addProjectFlag(rt, cmd)
	return cmd
}

// zoneRef is a resolved managed zone: its id ("<project>/<managed zone>"),
// its DNS name, and the two parts of the id.
type zoneRef struct {
	ID      string
	Name    string
	Project string
	Zone    string
}

func zoneRefOf(z platform.Zone) *zoneRef {
	project, zone := splitZoneID(z.ID)
	return &zoneRef{ID: z.ID, Name: z.Name, Project: project, Zone: zone}
}

// cachedZones serves the zone list through the inventory (honouring
// --refresh / --offline / TTL): the zones of every enabled project, or of
// the project of --project. A pinned project that is disabled is not in
// the inventory, and neither is one the syncs of the account do not
// cover or skipped because Cloud DNS is not enabled in it: when the
// inventory holds no zone of the pinned project its zones are read live
// and not stored, so that the answer of that project is kept.
func cachedZones(ctx context.Context, rt *app.Runtime, profile string) ([]platform.Zone, bool, error) {
	live := func() ([]platform.Zone, bool, error) {
		c, err := openProfile(ctx, rt, profile)
		if err != nil {
			return nil, false, err
		}
		zones, err := c.ListZones(ctx)
		return zones, false, err
	}
	if pinDisabled(rt, profile) {
		return live()
	}
	set := inventory.Set{Platform: platform.GCP, Profile: profile, Type: platform.ResZone}
	rows, cached, err := rt.EnsureSet(ctx, set, func(ctx context.Context) ([]platform.Resource, error) {
		c, err := openAccount(ctx, rt, profile)
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
		if project, _ := splitZoneID(z.ID); !keepProject(rt, profile, project) {
			continue
		}
		zones = append(zones, z)
	}
	if len(zones) == 0 && pinUnheld(rt) {
		return live()
	}
	return zones, cached, nil
}

// resolveZone finds the managed zone arg names: its id
// ("<project>/<managed zone>"), its managed zone name or its DNS name,
// among the zones of the enabled projects (of the project of --project).
// The inventory is consulted first; online, an unknown managed zone name
// is asked of each project.
//
// A managed zone name wins over a DNS name. A name that several zones
// answer to (the same managed zone name in two projects, a split-horizon
// pair of one DNS name) is ambiguous: the interactive flow asks which one,
// the non-interactive flow fails with exit code 5, naming --project or the
// zone ids.
func resolveZone(ctx context.Context, rt *app.Runtime, profile, arg string) (*zoneRef, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return nil, fmt.Errorf("zone is required")
	}
	// A zone id names its project: with --project it must be that one, so
	// that a call pinned to one project never works on a zone of another.
	if p, _ := splitZoneID(arg); p != "" {
		if pin := pinnedProject(rt); pin != "" && p != pin {
			return nil, app.UsageErrf("zone %q is of project %s, not of --project %s: drop --project or name a zone of that project", arg, p, pin)
		}
	}
	zones, _, err := cachedZones(ctx, rt, profile)
	if err != nil && !errors.Is(err, inventory.ErrNeverSynced) {
		return nil, err
	}
	if found := matchZones(zones, arg); len(found) > 0 {
		return chooseZone(rt, profile, arg, found)
	}
	full := strings.Contains(arg, "/")
	if rt.Flags.Offline || (strings.Contains(arg, ".") && !full) {
		return nil, fmt.Errorf("%w: managed zone %q in gcp/%s (run with --refresh if it was created recently)", platform.ErrNotFound, arg, profile)
	}
	c, err := openProfile(ctx, rt, profile)
	if err != nil {
		return nil, err
	}
	if full {
		z, err := c.GetZone(ctx, arg)
		if err != nil {
			return nil, err
		}
		return zoneRefOf(*z), nil
	}
	projects, err := c.sweep(ctx)
	if err != nil {
		return nil, err
	}
	// Every project is asked for a zone of that name; one without Cloud
	// DNS holds none.
	var first error
	var mu sync.Mutex
	found, err := sweepProjects(ctx, c, func(ctx context.Context, pc *client) ([]platform.Zone, error) {
		z, err := pc.GetZone(ctx, zoneID(pc.project, arg))
		switch {
		case err == nil:
			return []platform.Zone{*z}, nil
		case errors.Is(err, platform.ErrNotFound):
			mu.Lock()
			if first == nil {
				first = err
			}
			mu.Unlock()
			return nil, nil
		}
		return nil, err
	})
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		if len(projects) == 1 && first != nil {
			return nil, first
		}
		return nil, fmt.Errorf("%w: managed zone %q in the enabled projects of gcp/%s (%s)", platform.ErrNotFound, arg, profile, projectNames(projects))
	}
	return chooseZone(rt, profile, arg, found)
}

// matchZones returns the zones arg names: the one of that id, else those
// of that managed zone name, else those of that DNS name.
func matchZones(zones []platform.Zone, arg string) []platform.Zone {
	var byName, byDNS []platform.Zone
	dnsName := platform.NormalizeDomain(arg)
	for _, z := range zones {
		_, name := splitZoneID(z.ID)
		switch {
		case z.ID == arg:
			return []platform.Zone{z}
		case name == arg:
			byName = append(byName, z)
		case z.Name == dnsName:
			byDNS = append(byDNS, z)
		}
	}
	if len(byName) > 0 {
		return byName
	}
	return byDNS
}

// chooseZone settles the zones a name stands for: one is used, several
// are ambiguous.
func chooseZone(rt *app.Runtime, profile, arg string, found []platform.Zone) (*zoneRef, error) {
	if len(found) == 1 {
		return zoneRefOf(found[0]), nil
	}
	sort.Slice(found, func(i, j int) bool { return found[i].ID < found[j].ID })
	cands := make([]cand, 0, len(found))
	for _, z := range found {
		project, name := splitZoneID(z.ID)
		cands = append(cands, cand{profile: profile, project: project, id: "zone " + name, detail: prompt.Cells(z.Name, z.Status)})
	}
	z, err := app.OneOf(rt, ambiguous("managed zone", arg, cands, "", "the zone id <project>/<managed zone>"), found, func(z platform.Zone) string {
		return zoneLabel(z)
	})
	if err != nil {
		return nil, err
	}
	return zoneRefOf(z), nil
}

// zoneLabel: "example-zone  example.com  public  4 nameservers  project
// p1".
func zoneLabel(z platform.Zone) string {
	project, name := splitZoneID(z.ID)
	return prompt.Cells(name, z.Name, z.Status, fmt.Sprintf("%d nameservers", len(z.Nameservers)), "project "+project)
}

type zoneResult struct {
	Profile string          `json:"profile" yaml:"profile"`
	Cached  bool            `json:"cached" yaml:"cached"`
	Zones   []platform.Zone `json:"zones" yaml:"zones"`
}

func zoneGrid(zones []platform.Zone) output.Grid {
	g := output.Grid{Headers: []string{"ZONE", "PROJECT", "DNS_NAME", "VISIBILITY", "NAMESERVERS", "DESCRIPTION"}, Empty: "no managed zones"}
	for _, z := range zones {
		project, name := splitZoneID(z.ID)
		g.Rows = append(g.Rows, []string{name, project, z.Name, z.Status, strings.Join(z.Nameservers, ","), output.Str(z.Extra["description"])})
	}
	return g
}

func newZoneListCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the managed zones of the enabled projects",
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
		Short: "Show one managed zone (by zone id, managed zone name or DNS name)",
		Long: `Show one managed zone, given by its id (<project>/<managed zone>), its
managed zone name or its DNS name. A name several zones of the enabled
projects answer to is asked on a terminal and is exit code 5 otherwise;
--project or the zone id chooses. On a terminal, without <zone> the managed
zones of the profile are offered.`,
		Args: app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, err := rt.ProfileFor(platform.GCP)
			if err != nil {
				return err
			}
			if args, err = zoneArg(cmd.Context(), rt, args, profile, false); err != nil {
				return err
			}
			ref, err := resolveZone(cmd.Context(), rt, profile, args[0])
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
				for i := range zones {
					if zones[i].ID == ref.ID {
						z, cached = &zones[i], fromCache
						break
					}
				}
			}
			if z == nil {
				if rt.Flags.Offline {
					return fmt.Errorf("%w: managed zone %q in gcp/%s", platform.ErrNotFound, args[0], profile)
				}
				c, err := openProfile(cmd.Context(), rt, profile)
				if err != nil {
					return err
				}
				if z, err = c.GetZone(cmd.Context(), ref.ID); err != nil {
					return err
				}
			}
			rt.Infof("zone %s in project %s via gcp/%s%s", ref.Zone, ref.Project, profile, cacheNote(cached))
			return rt.Render(z, func() output.Grid {
				return output.KV(
					"zone", ref.Zone,
					"project", ref.Project,
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
	g := output.Grid{Headers: []string{"NAME", "TYPE", "VALUE", "TTL", "ID"}, Empty: "no records"}
	for _, r := range recs {
		content := r.Value
		if r.Priority != nil {
			content = fmt.Sprintf("%d %s", *r.Priority, r.Value)
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
		return recs[i].Value < recs[j].Value
	})
}

// cachedRecords serves one zone's records through the inventory. The
// records of a zone the inventory does not hold (a zone of a disabled
// project, or of one the syncs do not cover, named with --project) are
// read live and not stored.
func cachedRecords(ctx context.Context, rt *app.Runtime, profile string, z *zoneRef) ([]platform.Record, bool, error) {
	fetch := func(ctx context.Context) ([]platform.Resource, error) {
		recs, err := liveRecords(ctx, rt, profile, z)
		if err != nil {
			return nil, err
		}
		return app.RecordResources(z.ID, z.Name, recs), nil
	}
	if !zoneCached(ctx, rt, nil, profile, z) {
		if rt.Flags.Offline {
			return nil, false, app.ErrOffline
		}
		res, err := fetch(ctx)
		if err != nil {
			return nil, false, err
		}
		recs := make([]platform.Record, 0, len(res))
		for _, r := range res {
			recs = append(recs, r.Data.(platform.Record))
		}
		return recs, false, nil
	}
	set := inventory.Set{Platform: platform.GCP, Profile: profile, Type: platform.ResDNSRecord, Scope: z.ID}
	rows, cached, err := rt.EnsureSet(ctx, set, fetch)
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

// zoneCached reports whether the inventory holds the records of the zone:
// a zone of the default project, or of another project that is not
// disabled and that the syncs of the account cover. The zone row tells
// that without the network; only for a zone the inventory does not know
// yet is the account asked for its projects: c, its opened client, when
// the caller has one.
func zoneCached(ctx context.Context, rt *app.Runtime, c *client, profile string, z *zoneRef) bool {
	def, disabled, err := accountMeta(rt, profile)
	if err != nil || slices.Contains(disabled, z.Project) {
		return false
	}
	if z.Project == def {
		return true
	}
	if db, err := rt.DB(); err == nil {
		set := inventory.Set{Platform: platform.GCP, Profile: profile, Type: platform.ResZone}
		if r, err := db.Get(ctx, set, platform.ResZone, z.ID); err == nil && r != nil {
			return true
		}
	}
	if rt.Flags.Offline {
		return false
	}
	if c == nil {
		if c, err = openAccount(ctx, rt, profile); err != nil {
			return false
		}
	}
	ok, err := c.covers(ctx, z.Project)
	return err == nil && ok
}

// liveRecords reads the records of a zone from Cloud DNS, past the
// inventory: for a command that decides on them what to delete.
func liveRecords(ctx context.Context, rt *app.Runtime, profile string, z *zoneRef) ([]platform.Record, error) {
	c, err := openAccount(ctx, rt, profile)
	if err != nil {
		return nil, err
	}
	return c.ListRecords(ctx, z.ID)
}

// refreshRecords re-reads a zone after a mutation so the inventory matches.
func refreshRecords(ctx context.Context, rt *app.Runtime, c *client, profile string, z *zoneRef) {
	if !zoneCached(ctx, rt, c, profile, z) {
		return
	}
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
		Long: `List the record values of a managed zone, one row per value (--type and
--name filter). On a terminal, without <zone> the managed zones of the
profile are offered.`,
		Args: app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, err := rt.ProfileFor(platform.GCP)
			if err != nil {
				return err
			}
			if args, err = zoneArg(cmd.Context(), rt, args, profile, false); err != nil {
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
	var ttl, priority int
	cmd := &cobra.Command{
		Use:   "upsert <zone> <name> <type> <value>...",
		Short: "Create or replace a record set (the set becomes exactly the values given)",
		Long: `Create or replace the record set of <name> and <type>. Cloud DNS stores all
values of a name/type pair in one set; this command makes the set equal to
the values given, one argument each.

` + recordArgsHelp + `

MX and SRV values take the priority from --priority, or as a leading number
inside the value ("10 mail.example.com"). Hostnames get the trailing dot
Cloud DNS expects; TXT and SPF values are quoted automatically.

` + app.RecordAskHelp("zone") + "\n\n" + app.RecordSetAskHelp,
		Example: `  polyctl gcp dns record upsert example-zone www A 203.0.113.10 203.0.113.11
  polyctl gcp dns record upsert example-zone @ MX "10 mx1.example.net" "20 mx2.example.net" --ttl 300
  polyctl gcp dns record upsert example-zone @ TXT "v=spf1 include:_spf.example.net ~all"`,
		Args:              app.RecordArgsOrInteractive(rt, 1, -1),
		ValidArgsFunction: app.CompleteRecordArgs(app.CompleteDomainArg(rt, platform.GCP), platform.GCP),
		RunE: func(cmd *cobra.Command, args []string) error {
			// The record is positional (<name> <type> <value>...) or, in the
			// former form, given with --name, --type and --value.
			in, err := rt.RecordInput(cmd, args, app.RecordForm{MinValues: 1, MaxValues: -1})
			if err != nil {
				return err
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			profile, err := rt.ProfileFor(platform.GCP)
			if err != nil {
				return err
			}
			if args, err = zoneArg(cmd.Context(), rt, args[:min(len(args), 1)], profile, true); err != nil {
				return err
			}
			z, err := resolveZone(cmd.Context(), rt, profile, args[0])
			if err != nil {
				return err
			}
			if err := rt.CompleteRecord(in, app.RecordPrompt{Platform: platform.GCP, Zone: z.Name, WholeSet: true, ValueOf: recordValue,
				Existing: func() ([]platform.Record, error) {
					recs, _, err := cachedRecords(cmd.Context(), rt, profile, z)
					return recs, err
				}}); err != nil {
				return err
			}
			typ, values := in.Type, in.Values
			fqdn := platform.FQDN(in.Name, z.Name)
			raw := make([]string, 0, len(values))
			for _, v := range values {
				rec := platform.Record{Name: fqdn, Type: typ, Value: v}
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
			if done, err := rt.WouldWrite(platform.Target{Platform: platform.GCP, Profile: profile, Project: z.Project, Domain: z.Name}, platform.Change{Resource: app.RecordResource(fqdn, typ), Action: platform.Updated, Detail: "set to " + strings.Join(values, ",")}); done || err != nil {
				return err
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
	app.FormerRecordFlags(cmd, true)
	cmd.Flags().IntVar(&ttl, "ttl", 0, "TTL in seconds (0 = keep existing, or 300 for a new set)")
	cmd.Flags().IntVar(&priority, "priority", 0, "priority for MX/SRV records")
	return cmd
}

// recordArgsHelp is the paragraph of the record commands about their
// positional record.
var recordArgsHelp = app.RecordArgsHelp("zone")

// recordDeleteForm is the form of record delete: the record by name or
// --id, or with the former --name, --type and --value.
var recordDeleteForm = app.RecordTargetForm{FormerFlags: []string{"name", "type", "value"}}

func newRecordDeleteCmd(rt *app.Runtime) *cobra.Command {
	var id string
	var priority int
	cmd := &cobra.Command{
		Use:   "delete <zone> [<name> [<type> [<value>]]]",
		Short: "Delete the record set of a name (<name> [<type>]), one value of it (<value>) or a record by --id",
		Long: `Delete the record set of <name> and <type>, only one of its values (<value>),
or the record value given with --id. Cloud DNS addresses records by name and
type, so the id is an optional second way to pick one value here, not a
required argument.

` + recordArgsHelp + `

` + app.RecordSetDeleteHelp + `

On a terminal, a missing <zone> is picked from the managed zones of the
profile, and with only the zone the record sets of the zone are offered (the
apex SOA and NS sets left out), then, for a set of several values, the whole
set or one value.

Deleting a whole record set lists its values with their ids and, for several
values, says how to delete one of them only (<value> or --id), then asks one
yes/no question (default no; --yes skips it). The non-interactive flow asks
nothing: --yes is required (exit code 2 without it: for <name> <type> before
anything is read, for a name alone once it is known to mean one record set).
A name alone is looked up in the zone as it is, not in the inventory.
Declining changes nothing; a missing set is not found (exit code 4) before
the question. Removing one value (<value>, --id) asks nothing, like
dns delete of one record. --dry-run asks nothing.`,
		Example: `  polyctl gcp dns record delete example-zone _acme-challenge --yes
  polyctl gcp dns record delete example-zone _acme-challenge TXT --yes
  polyctl gcp dns record delete example-zone www A 203.0.113.11
  polyctl gcp dns record delete example-zone --id 'acme-prod/example-zone|A|www.example.com|203.0.113.11'`,
		Args:              recordDeleteForm.ArgsOrInteractive(rt),
		ValidArgsFunction: recordDeleteForm.Complete(rt, app.CompleteDomainArg(rt, platform.GCP), platform.GCP),
		RunE: func(cmd *cobra.Command, args []string) error {
			// The record is positional (<name> [<type> [<value>]]) or, in
			// the former form, given with --name, --type and --value.
			target, err := recordDeleteForm.Parse(cmd, args)
			if err != nil {
				return err
			}
			var name, typ, value string
			typeArg := "--type"
			if target != nil {
				name, typ, value, typeArg = target.Name, target.Type, target.Value(), target.TypeArg
			}
			args = args[:min(len(args), 1)]
			if id != "" && cmd.Flags().Changed("priority") {
				// The id names the value, with its priority.
				return app.UsageErrf("--id selects one record value; it cannot be combined with --priority")
			}
			// byName: the name alone says which record set, when it has one.
			// pick: without a name the record set is chosen from a list (the
			// non-interactive flow was refused when the arguments were read).
			byName := id == "" && name != "" && typ == ""
			pick := id == "" && name == ""
			// A whole record set that is named needs --yes where nothing can
			// be asked: refused before anything is read. A name alone is read
			// first: what it means (one set, several types, nothing) comes
			// before the confirmation.
			if !rt.Flags.DryRun && !pick && !byName && id == "" && value == "" {
				if err := rt.CanConfirm(fmt.Sprintf("delete the %s record set of %s", strings.ToUpper(typ), platform.FQDN(name, "<zone>"))); err != nil {
					return err
				}
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			profile, err := rt.ProfileFor(platform.GCP)
			if err != nil {
				return err
			}
			if args, err = zoneArg(cmd.Context(), rt, args, profile, false); err != nil {
				return err
			}
			z, err := resolveZone(cmd.Context(), rt, profile, args[0])
			if err != nil {
				return err
			}
			// onlyValue narrows the deletion to one value picked from a set.
			onlyValue := func(one *platform.Record) {
				if one == nil {
					return
				}
				value = one.Value
				if one.Priority != nil {
					priority = *one.Priority
					_ = cmd.Flags().Set("priority", strconv.Itoa(priority))
				}
			}
			if byName {
				// What the name means is decided on the zone as it is now,
				// not on the inventory: a cached list may miss a record set.
				recs, err := liveRecords(cmd.Context(), rt, profile, z)
				if err != nil {
					return err
				}
				// Record sets of several types: a list on a terminal (a
				// record set, then the whole set or one value), exit code 5
				// without one.
				chosen, err := rt.SelectRecords(app.RecordSelect{Zone: z.Name, Records: recs, Name: platform.FQDN(name, z.Name), Value: value, Verb: "Delete", TypeArg: typeArg,
					List: func(_ string, recs []platform.Record) ([]platform.Record, error) {
						set, one, err := pickRecordToDelete(rt, z, recs)
						if err != nil {
							return nil, err
						}
						typ = set.Type
						onlyValue(one)
						return recs, nil
					}})
				if err != nil {
					return err
				}
				if !chosen.Listed {
					typ = chosen.Type()
				}
			}
			if pick {
				recs, _, err := cachedRecords(cmd.Context(), rt, profile, z)
				if err != nil {
					return err
				}
				if typ != "" {
					var f []platform.Record
					for _, r := range recs {
						if strings.EqualFold(r.Type, typ) {
							f = append(f, r)
						}
					}
					recs = f
				}
				set, one, err := pickRecordToDelete(rt, z, recs)
				if err != nil {
					return err
				}
				name, typ = set.Name, set.Type
				onlyValue(one)
			}
			change := platform.Change{Resource: app.RecordResource(platform.FQDN(name, z.Name), typ), Action: platform.Deleted, Detail: "the whole record set"}
			switch {
			case id != "":
				change = platform.Change{Resource: "record/" + id, Action: platform.Deleted, ID: id}
			case value != "":
				change.Detail = value
			}
			if done, err := rt.WouldWrite(platform.Target{Platform: platform.GCP, Profile: profile, Project: z.Project, Domain: z.Name}, change); done || err != nil {
				return err
			}
			c, _, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			// A record id with a bare managed zone name (--id) is of the
			// project of the zone, not of the default project.
			c = c.inProject(z.Project)
			var what string
			switch {
			case id != "":
				if err := c.DeleteRecord(cmd.Context(), z.ID, id); err != nil {
					return err
				}
				what = id
			case value != "":
				rec := platform.Record{Name: platform.FQDN(name, z.Name), Type: typ, Value: value}
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
				if !rt.Flags.Yes {
					recs, err := c.RRSetRecords(cmd.Context(), z.ID, fqdn, typ)
					if err != nil {
						return err
					}
					if err := rt.ConfirmRecordDelete(cmd.Context(), app.RecordDelete{Records: recordGrid(recs), Exact: app.ExactRecordHint(typeArg, true, true),
						Question: fmt.Sprintf("Delete the %s record set of %s (%d value(s))?", strings.ToUpper(typ), fqdn, len(recs)),
						Refusal:  fmt.Sprintf("delete the %s record set of %s", strings.ToUpper(typ), fqdn)}); err != nil {
						return err
					}
				}
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
	cmd.Flags().String("type", "", "record type")
	cmd.Flags().String("name", "", "record name relative to the zone (www, @) or FQDN")
	cmd.Flags().String("value", "", "only remove this value from the set")
	cmd.Flags().IntVar(&priority, "priority", 0, "priority of the MX/SRV <value>, when the value does not start with one")
	cmd.Flags().StringVar(&id, "id", "", "delete the record value with this id (project/zone|TYPE|name|value)")
	app.HideFormerRecordFlags(cmd)
	return cmd
}

// ---------------------------------------------------------------- compute

func newComputeCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "compute", Short: "Compute Engine"}
	instance := &cobra.Command{Use: "instance", Short: "Compute Engine instances"}
	instance.AddCommand(newComputeListCmd(rt), computeGetCmd(rt), computeCreateCmd(rt), computeDeleteCmd(rt),
		computeResizeCmd(rt), computeRebootCmd(rt), computeUpdateCmd(rt),
		newComputePowerCmd(rt, "start"), newComputePowerCmd(rt, "stop"), computePasswordCmd(rt), computeSSHKeyCmd(rt))
	cmd.AddCommand(instance, newFirewallCmd(rt), newNetworkCmd(rt), newSubnetCmd(rt), newSSLCertificateCmd(rt), newLoadBalancerCmd(rt),
		newBackendServiceCmd(rt), newForwardingRuleCmd(rt), newHealthCheckCmd(rt), newInstanceGroupCmd(rt))
	addProjectFlag(rt, cmd)
	return cmd
}

type instanceResult struct {
	Profile   string     `json:"profile" yaml:"profile"`
	Cached    bool       `json:"cached" yaml:"cached"`
	Instances []Instance `json:"instances" yaml:"instances"`
}

// cachedInstances serves the instance list through the inventory: the
// instances of every enabled project, or of the project of --project
// (read live and not stored when it is disabled, or when the inventory
// holds no instance of it: the syncs do not cover it, or skipped it
// because the Compute Engine API is not enabled in it, and the command on
// that one project keeps its answer).
func cachedInstances(ctx context.Context, rt *app.Runtime, profile string) ([]Instance, bool, error) {
	decode := func(id string, d func(any) error) (Instance, error) {
		var in Instance
		if err := d(&in); err != nil {
			return in, fmt.Errorf("decode cached instance %s: %w", id, err)
		}
		return in, nil
	}
	live := func() ([]Instance, bool, error) {
		c, err := openProfile(ctx, rt, profile)
		if err != nil {
			return nil, false, err
		}
		res, err := c.syncInstances(ctx)
		if err != nil {
			// Unreachable zones leave the instances of the others.
			if platform.AsRegionSyncError(err) == nil {
				return nil, false, err
			}
			rt.Infof("warning: gcp/%s project %s: %v", profile, c.project, err)
		}
		out := make([]Instance, 0, len(res))
		for _, r := range res {
			out = append(out, r.Data.(Instance))
		}
		return out, false, nil
	}
	if pinDisabled(rt, profile) {
		return live()
	}
	set := inventory.Set{Platform: platform.GCP, Profile: profile, Type: platform.ResInstance}
	rows, cached, err := rt.EnsureSet(ctx, set, func(ctx context.Context) ([]platform.Resource, error) {
		c, err := openAccount(ctx, rt, profile)
		if err != nil {
			return nil, err
		}
		return c.ListInstances(ctx)
	})
	if err != nil {
		return nil, cached, err
	}
	def := defaultProject(rt, profile)
	out := make([]Instance, 0, len(rows))
	for _, r := range rows {
		in, err := decode(r.ID, r.Decode)
		if err != nil {
			return nil, cached, err
		}
		if !keepProject(rt, profile, in.Project) {
			continue
		}
		if in.Project == "" {
			in.Project = def
		}
		out = append(out, in)
	}
	if len(out) == 0 && pinUnheld(rt) {
		return live()
	}
	return out, cached, nil
}

func newComputeListCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the Compute Engine instances of the enabled projects across all zones",
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
				if list[i].Project != list[j].Project {
					return list[i].Project < list[j].Project
				}
				if list[i].Zone != list[j].Zone {
					return list[i].Zone < list[j].Zone
				}
				return list[i].Name < list[j].Name
			})
			rt.Infof("%d instance(s) via gcp/%s%s", len(list), profile, cacheNote(cached))
			return rt.Render(instanceResult{Profile: profile, Cached: cached, Instances: list}, func() output.Grid {
				g := output.Grid{Headers: []string{"NAME", "PROJECT", "ZONE", "MACHINE_TYPE", "STATUS", "INTERNAL_IP", "EXTERNAL_IP", "ID"}, Empty: "no instances"}
				for _, in := range list {
					g.Rows = append(g.Rows, []string{in.Name, in.Project, in.Zone, in.MachineType, in.Status, in.InternalIP, in.ExternalIP, in.ID})
				}
				return g
			})
		},
	}
}

func newComputePowerCmd(rt *app.Runtime, verb string) *cobra.Command {
	var zone string
	var wf app.WaitFlags
	want := statusRunning
	if verb == "stop" {
		want = statusTerminated
	}
	title := strings.ToUpper(verb[:1]) + verb[1:]
	long := title + ` a Compute Engine instance, found like get finds it (--zone narrows several
matches and finds an instance the inventory does not know yet). An instance
that is ` + want + ` already is unchanged (exit code 0). --wait waits for the
operation to finish (--timeout).`
	if verb == "stop" {
		long += `

A confirmation is asked first (default no; --yes skips it, and the
non-interactive flow needs --yes: exit code 2 without it). A declined
confirmation is exit code 0. A stopped instance loses its ephemeral external
IP.`
	}
	cmd := &cobra.Command{
		Use:   verb + " <name|id>",
		Short: title + " a Compute Engine instance",
		Long:  long,
		Args:  app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			wait, timeout, err := wf.Resolve(cmd)
			if err != nil {
				return err
			}
			what, keep := "stopped GCP instance", stoppedInstance
			if verb == "stop" {
				what, keep = "running GCP instance", statusIn(statusRunning)
			}
			if args, err = instanceArg(ctx, rt, args, zone, what, keep); err != nil {
				return err
			}
			// The non-interactive flow without --yes is refused before any
			// lookup; a dry run stops nothing and needs no confirmation.
			if verb == "stop" && !rt.DryRun() {
				if err := rt.CanConfirm("stop instance " + args[0]); err != nil {
					return err
				}
			}
			l, err := resolveInstance(ctx, rt, args[0], zone, false)
			if err != nil {
				return err
			}
			id := strconv.FormatUint(l.inst.Id, 10)
			cur := l.inst.Status
			if cur == want {
				return rt.RenderReport(platform.Report{Target: l.target(), DryRun: rt.DryRun(), Changes: []platform.Change{
					{Resource: l.resource(), Action: platform.Unchanged, ID: id, Detail: cur}}})
			}
			change := platform.Change{Resource: l.resource(), Action: platform.Updated, ID: id, Detail: verb}
			if done, err := rt.WouldWrite(l.target(), change); done || err != nil {
				return err
			}
			if verb == "stop" {
				ok, err := rt.Confirm(ctx, fmt.Sprintf("Stop instance %s (%s)? It is unavailable until it is started again.", l.label(), cur), false)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("%w: cancelled; instance %s was not stopped", platform.ErrNothingToDo, l.name())
				}
			}
			if !wait {
				timeout = 0 // no deadline: the call returns once the operation is requested
			}
			wctx, cancel, conv := deadline(ctx, timeout, l.resource(), "the "+verb+" operation to finish")
			defer cancel()
			var res *OperationResult
			if verb == "start" {
				res, err = l.c.StartInstance(wctx, l.zone, l.name(), wait)
			} else {
				res, err = l.c.StopInstance(wctx, l.zone, l.name(), wait)
			}
			if err = conv(err); err != nil {
				return err
			}
			rt.Infof("%s %s in %s: operation %s is %s via gcp/%s", verb, l.name(), l.zone, res.Operation, res.Status, l.profile)
			l.reread(ctx, rt)
			if wait {
				change.Detail += "; " + l.inst.Status
				if verb == "start" {
					internal, external := ips(l.inst)
					change.Attrs = map[string]string{"internal_ip": internal, "external_ip": external}
					rt.Infof("instance %s is %s: external ip %s, internal ip %s", l.name(), l.inst.Status, orNone(external), orNone(internal))
				}
			}
			return rt.RenderReport(platform.Report{Target: l.target(), Changes: []platform.Change{change}})
		},
	}
	cmd.Flags().StringVar(&zone, "zone", "", "zone of the instance; only an instance in this zone is used (default: from the inventory)")
	app.AddWaitFlags(cmd, &wf, false, app.DefaultWaitTimeout)
	return cmd
}

func cacheNote(cached bool) string {
	if cached {
		return " (local inventory)"
	}
	return ""
}
