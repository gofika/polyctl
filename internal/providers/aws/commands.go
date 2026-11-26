package aws

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// Command returns the `polyctl aws` command tree.
func Command(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "aws",
		Short: "Amazon Web Services native commands",
		Long: `Native Amazon Web Services commands: the identity check, Route 53 hosted
zones and records, Route 53 Domains registrations, EC2 instances, key pairs
and security groups, Elastic Load Balancing v2 load balancers, AWS
Certificate Manager certificates, and RDS database instances. The profile is chosen with --profile (or the current profile);
listing commands read the local inventory unless --refresh is given or the
cached data has expired.`,
	}
	cmd.AddCommand(
		app.WhoamiCommand(rt, platform.AWS, "On AWS this calls sts GetCallerIdentity and reports the account, the ARN, the\nuser id and the profile's region."),
		route53Cmd(rt), route53domainsCmd(rt), ec2Cmd(rt), elbv2Cmd(rt), acmCmd(rt), rdsCmd(rt))
	return cmd
}

// openClient opens the AWS client for the selected profile.
func openClient(ctx context.Context, rt *app.Runtime) (*client, platform.Profile, error) {
	c, prof, err := rt.OpenFor(ctx, platform.AWS)
	if err != nil {
		return nil, prof, err
	}
	ac, ok := c.(*client)
	if !ok {
		return nil, prof, fmt.Errorf("unexpected AWS client type %T", c)
	}
	return ac, prof, nil
}

// ------------------------------------------------------------ route53

// looksLikeZoneID reports whether s is a hosted zone id rather than a name.
func looksLikeZoneID(s string) bool {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, hostedZonePrefix) {
		return true
	}
	if strings.Contains(s, ".") || len(s) < 8 || !strings.HasPrefix(s, "Z") {
		return false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func matchZones(zones []platform.Zone, arg string) (exact *platform.Zone, byName []platform.Zone) {
	id, name := zoneID(arg), platform.NormalizeDomain(arg)
	for i := range zones {
		z := zones[i]
		if z.ID == id {
			return &z, nil
		}
		if z.Name == name {
			byName = append(byName, z)
		}
	}
	return nil, byName
}

func pickZone(rt *app.Runtime, zones []platform.Zone, arg string) (*platform.Zone, bool, error) {
	exact, byName := matchZones(zones, arg)
	switch {
	case exact != nil:
		return exact, true, nil
	case len(byName) == 1:
		return &byName[0], true, nil
	case len(byName) > 1:
		var ids []string
		for _, z := range byName {
			ids = append(ids, fmt.Sprintf("%s (%s)", z.ID, z.Status))
		}
		amb := &app.AmbiguousError{What: fmt.Sprintf("hosted zone %q", platform.NormalizeDomain(arg)), Candidates: ids, Hint: "pass the hosted zone id"}
		// The interactive flow asks which one (a public and a private
		// zone of one name, say).
		z, err := app.OneOf(rt, amb, byName, func(z platform.Zone) string {
			count := ""
			if n, ok := z.Extra["record_count"]; ok {
				count = fmt.Sprintf("%v records", n)
			}
			return prompt.Cells(z.Name, z.ID, z.Status, count)
		})
		if err != nil {
			return nil, true, err
		}
		return &z, true, nil
	}
	return nil, false, nil
}

// resolveZone turns a zone name or id into a zone, consulting the local
// inventory first and the platform when needed and allowed.
func resolveZone(ctx context.Context, rt *app.Runtime, arg string) (*platform.Zone, error) {
	profName, err := rt.ProfileFor(platform.AWS)
	if err != nil {
		return nil, err
	}
	db, err := rt.DB()
	if err != nil {
		return nil, err
	}
	set := inventory.Set{Platform: platform.AWS, Profile: profName, Type: platform.ResZone}
	rows, err := db.List(ctx, inventory.Query{Platform: set.Platform, Profile: set.Profile, Type: set.Type})
	if err != nil {
		return nil, err
	}
	var cached []platform.Zone
	for _, r := range rows {
		var z platform.Zone
		if err := r.Decode(&z); err == nil {
			cached = append(cached, z)
		}
	}
	if !rt.Flags.Refresh {
		if z, found, err := pickZone(rt, cached, arg); found {
			return z, err
		}
	}
	if rt.Flags.Offline {
		if looksLikeZoneID(arg) {
			return &platform.Zone{ID: zoneID(arg)}, nil
		}
		return nil, fmt.Errorf("%w: hosted zone %q is not in the local inventory (run `polyctl sync --platform aws` when online)", platform.ErrNotFound, arg)
	}
	c, prof, err := openClient(ctx, rt)
	if err != nil {
		return nil, err
	}
	zones, err := c.listZonesWithNameservers(ctx)
	if err != nil {
		return nil, err
	}
	cfg, _ := rt.Config()
	_ = db.Replace(ctx, inventory.Set{Platform: platform.AWS, Profile: prof.Name, Type: platform.ResZone}, zoneResources(zones), cfg.TTLFor(platform.ResZone))
	if z, found, err := pickZone(rt, zones, arg); found {
		return z, err
	}
	if looksLikeZoneID(arg) {
		return c.GetZone(ctx, arg)
	}
	return nil, fmt.Errorf("%w: hosted zone %q in profile %s", platform.ErrNotFound, arg, prof.Name)
}

type zoneResult struct {
	Profile string          `json:"profile" yaml:"profile"`
	Cached  bool            `json:"cached" yaml:"cached"`
	Zones   []platform.Zone `json:"zones" yaml:"zones"`
}

func zoneGrid(zones []platform.Zone) output.Grid {
	g := output.Grid{Headers: []string{"ID", "NAME", "STATUS", "RECORDS", "NAMESERVERS"}, Empty: "no hosted zones"}
	for _, z := range zones {
		g.Rows = append(g.Rows, []string{z.ID, z.Name, z.Status, output.Str(z.Extra["record_count"]), strings.Join(z.Nameservers, ",")})
	}
	return g
}

func zoneKV(z *platform.Zone) output.Grid {
	return output.KV("ID", z.ID, "NAME", z.Name, "STATUS", z.Status, "RECORDS", output.Str(z.Extra["record_count"]),
		"COMMENT", output.Str(z.Extra["comment"]), "NAMESERVERS", strings.Join(z.Nameservers, ","))
}

type recordResult struct {
	Profile string            `json:"profile" yaml:"profile"`
	Zone    *platform.Zone    `json:"zone" yaml:"zone"`
	Cached  bool              `json:"cached" yaml:"cached"`
	Records []platform.Record `json:"records" yaml:"records"`
}

func recordGrid(recs []platform.Record) output.Grid {
	g := output.Grid{Headers: []string{"NAME", "TYPE", "VALUE", "TTL", "SET", "ID"}, Empty: "no records"}
	for _, r := range recs {
		content := r.Value
		if r.Priority != nil {
			content = fmt.Sprintf("%d %s", *r.Priority, r.Value)
		}
		if extraBool(r.Extra, "alias") {
			content = "ALIAS " + content
		}
		g.Rows = append(g.Rows, []string{r.Name, r.Type, content, platform.TTLLabel(platform.AWS, r), extraString(r.Extra, "set_identifier"), r.ID})
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

func route53Cmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "route53", Short: "Route 53 hosted zones and records"}
	zone := &cobra.Command{Use: "zone", Short: "Hosted zones"}
	zone.AddCommand(zoneListCmd(rt), zoneGetCmd(rt))
	record := &cobra.Command{Use: "record", Short: "Record sets of a hosted zone (<zone> is a name or id)"}
	record.AddCommand(recordListCmd(rt), recordUpsertCmd(rt), recordDeleteCmd(rt))
	cmd.AddCommand(zone, record)
	return cmd
}

func zoneListCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List hosted zones",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			profName, err := rt.ProfileFor(platform.AWS)
			if err != nil {
				return err
			}
			set := inventory.Set{Platform: platform.AWS, Profile: profName, Type: platform.ResZone}
			rows, cached, err := rt.EnsureSet(cmd.Context(), set, func(ctx context.Context) ([]platform.Resource, error) {
				c, _, err := openClient(ctx, rt)
				if err != nil {
					return nil, err
				}
				zones, err := c.listZonesWithNameservers(ctx)
				if err != nil {
					return nil, err
				}
				return zoneResources(zones), nil
			})
			if err != nil {
				return err
			}
			res := zoneResult{Profile: profName, Cached: cached, Zones: make([]platform.Zone, 0, len(rows))}
			for _, r := range rows {
				var z platform.Zone
				if err := r.Decode(&z); err != nil {
					return fmt.Errorf("decode cached zone %s: %w", r.ID, err)
				}
				res.Zones = append(res.Zones, z)
			}
			if cached {
				rt.Infof("%d hosted zone(s) via aws/%s (local inventory)", len(res.Zones), profName)
			}
			return rt.Render(res, func() output.Grid { return zoneGrid(res.Zones) })
		},
	}
}

func zoneGetCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get <zone>",
		Short: "Show one hosted zone (by name or id)",
		Args:  app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := rt.DomainArg(cmd.Context(), args, platform.AWS, platform.ResZone, nil)
			if err != nil {
				return err
			}
			z, err := resolveZone(cmd.Context(), rt, args[0])
			if err != nil {
				return err
			}
			// resolveZone hands out an id-only stub offline for anything
			// that looks like a hosted zone id (record listings are cached
			// under that id); for `zone get` a stub means nothing is known.
			if rt.Flags.Offline && z.Name == "" {
				return fmt.Errorf("%w: hosted zone %q is not in the local inventory (run `polyctl sync --platform aws` when online)", platform.ErrNotFound, args[0])
			}
			if !rt.Flags.Offline {
				c, _, err := openClient(cmd.Context(), rt)
				if err != nil {
					return err
				}
				if z, err = c.GetZone(cmd.Context(), z.ID); err != nil {
					return err
				}
			}
			return rt.Render(z, func() output.Grid { return zoneKV(z) })
		},
	}
}

func recordListCmd(rt *app.Runtime) *cobra.Command {
	var typ, name string
	cmd := &cobra.Command{
		Use:   "list <zone>",
		Short: "List the records of a hosted zone (one row per value)",
		Args:  app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := rt.DomainArg(cmd.Context(), args, platform.AWS, platform.ResZone, nil)
			if err != nil {
				return err
			}
			z, err := resolveZone(cmd.Context(), rt, args[0])
			if err != nil {
				return err
			}
			profName, err := rt.ProfileFor(platform.AWS)
			if err != nil {
				return err
			}
			set := inventory.Set{Platform: platform.AWS, Profile: profName, Type: platform.ResDNSRecord, Scope: z.ID}
			rows, cached, err := rt.EnsureSet(cmd.Context(), set, func(ctx context.Context) ([]platform.Resource, error) {
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
				fqdn := platform.FQDN(name, z.Name)
				recs = app.MatchRecords(recs, fqdn, typ, "")
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
			if cached {
				rt.Infof("zone %s via aws/%s (local inventory)", z.Name, profName)
			}
			return rt.Render(recordResult{Profile: profName, Zone: z, Cached: cached, Records: recs}, func() output.Grid { return recordGrid(recs) })
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "filter by record type")
	cmd.Flags().StringVar(&name, "name", "", "filter by record name (relative, @ or FQDN)")
	return cmd
}

// zoneWithName makes sure the zone name is known (ids given with --offline
// may come without one).
func zoneWithName(ctx context.Context, rt *app.Runtime, c *client, z *platform.Zone) (*platform.Zone, error) {
	if z.Name != "" {
		return z, nil
	}
	return c.GetZone(ctx, z.ID)
}

// syncRecordRows replaces the inventory rows of (name, type) in a zone.
func syncRecordRows(ctx context.Context, rt *app.Runtime, prof string, z *platform.Zone, fqdn, typ string, recs []platform.Record) {
	db, err := rt.DB()
	if err != nil {
		return
	}
	cfg, _ := rt.Config()
	set := inventory.Set{Platform: platform.AWS, Profile: prof, Type: platform.ResDNSRecord}
	rows, _ := db.List(ctx, inventory.Query{Platform: set.Platform, Profile: set.Profile, Type: set.Type, ParentID: z.ID, Name: fqdn})
	for _, r := range rows {
		var rec platform.Record
		if r.Decode(&rec) == nil && strings.EqualFold(rec.Type, typ) {
			_ = db.Delete(ctx, set, platform.ResDNSRecord, r.ID)
		}
	}
	for _, res := range app.RecordResources(z.ID, z.Name, recs) {
		_ = db.Upsert(ctx, set, res, cfg.TTLFor(platform.ResDNSRecord))
	}
}

func recordUpsertCmd(rt *app.Runtime) *cobra.Command {
	var setID string
	var ttl, priority int
	cmd := &cobra.Command{
		Use:   "upsert <zone> <name> <type> <value>...",
		Short: "Create or replace a whole record set (name + type) with the given values",
		Long: `Create or replace the record set of <name> and <type>. Every <value> becomes
one value of the set; existing values that are not repeated are removed. MX
and SRV values take their priority from --priority, or as a leading number
inside the value ("10 mail.example.com").

` + recordArgsHelp + `

A routing-policy set (weighted, latency, failover, geolocation...) is
chosen with --set-identifier and keeps its policy; a set identifier that
does not exist is not found (exit code 4), since this command sets no
routing policy. Without it, a name and type that hold only routing-policy
sets are ambiguous (exit code 5).

` + app.RecordAskHelp("zone") + "\n\n" + app.RecordSetAskHelp,
		Example: `  polyctl aws route53 record upsert example.com www A 203.0.113.10 203.0.113.11
  polyctl aws route53 record upsert example.com @ MX "10 mx1.example.net" "20 mx2.example.net" --ttl 300
  polyctl aws route53 record upsert example.com www A 203.0.113.12 --set-identifier eu`,
		Args:              app.RecordArgsOrInteractive(rt, 1, -1),
		ValidArgsFunction: app.CompleteRecordArgs(app.CompleteDomainArg(rt, platform.AWS), platform.AWS),
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
			// A record is created in the zone: an empty list is a usage
			// error naming <zone>.
			args, err = rt.DomainArg(cmd.Context(), args[:min(len(args), 1)], platform.AWS, platform.ResZone, nil)
			if err != nil {
				return app.RequiredPick(err, "<zone>")
			}
			z, err := resolveZone(cmd.Context(), rt, args[0])
			if err != nil {
				return err
			}
			c, prof, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			if z, err = zoneWithName(cmd.Context(), rt, c, z); err != nil {
				return err
			}
			if err := rt.CompleteRecord(in, app.RecordPrompt{Platform: platform.AWS, Zone: z.Name, WholeSet: true,
				Existing: func() ([]platform.Record, error) { return c.ListRecords(cmd.Context(), z.ID) },
				// The value of the set being replaced, not of another
				// routing-policy set of the name and type.
				Current: func(r platform.Record) bool { return extraString(r.Extra, "set_identifier") == setID }}); err != nil {
				return err
			}
			typ, values := in.Type, in.Values
			fqdn := platform.FQDN(in.Name, z.Name)
			if cmd.Flags().Changed("priority") && hasPriority(typ) {
				// Prepend --priority to values that do not carry one already.
				for i, v := range values {
					if p, _ := splitPriority(typ, v); p == nil {
						values[i] = fmt.Sprintf("%d %s", priority, strings.TrimSpace(v))
					}
				}
			}
			if done, err := rt.WouldWrite(platform.Target{Platform: platform.AWS, Profile: prof.Name, Domain: z.Name}, platform.Change{Resource: app.RecordResource(fqdn, typ), Action: platform.Updated, Detail: "set to " + strings.Join(values, ",")}); done || err != nil {
				return err
			}
			recs, err := c.ReplaceSet(cmd.Context(), z.ID, fqdn, typ, setID, values, ttl)
			if err != nil {
				return err
			}
			syncRecordRows(cmd.Context(), rt, prof.Name, z, fqdn, typ, recs)
			rt.Infof("upserted %s %s (%d value(s)) in zone %s via aws/%s", fqdn, strings.ToUpper(typ), len(values), z.Name, prof.Name)
			return rt.Render(recordResult{Profile: prof.Name, Zone: z, Records: recs}, func() output.Grid { return recordGrid(recs) })
		},
	}
	app.FormerRecordFlags(cmd, true)
	cmd.Flags().IntVar(&ttl, "ttl", 0, "TTL in seconds (0 = keep existing, or 300 for a new set)")
	cmd.Flags().IntVar(&priority, "priority", 0, "priority for MX/SRV values that do not start with one")
	cmd.Flags().StringVar(&setID, "set-identifier", "", "set identifier of a routing-policy record set (weighted, latency, failover...)")
	app.HideFormerRecordFlags(cmd)
	return cmd
}

// recordArgsHelp is the paragraph of the record commands about their
// positional record.
const recordArgsHelp = `<name> is relative to the zone (www, a.b), @ for the zone apex, or a full name
inside the zone (www.example.com). <type> is case-insensitive. A value is one
argument: quote one that contains spaces. A value that starts with "-" goes
after "--".`

func recordDeleteCmd(rt *app.Runtime) *cobra.Command {
	var typ, name, setID string
	cmd := &cobra.Command{
		Use:   "delete <zone> <name> [<type>]",
		Short: "Delete the record set of a name (optionally of one type)",
		Long: `Delete the record set of <name> and <type>, with every value in it. <name> is
relative to the zone (www, a.b), @ for the zone apex, or a full name inside
the zone (www.example.com). <type> is case-insensitive.

<type> is needed only to tell record sets apart: a name with one record set
needs none. A name with record sets of several types is not deleted as a
whole: on a terminal its record sets are offered to pick one, and the
non-interactive flow names the types and exits with code 5, also with --yes.
The SOA and NS sets of the zone apex are never meant by the name alone.

A routing-policy set (weighted, latency, failover, geolocation...) is
chosen with --set-identifier; without it, a name and type that hold only
routing-policy sets are ambiguous (exit code 5) and the identifiers are
listed. Beside a name alone, --set-identifier says which set is meant: only
the sets with that identifier count, and only those are offered.

The values to delete are listed, then one yes/no question is asked (default
no; --yes skips it). The non-interactive flow asks nothing: --yes is required
(exit code 2 without it: for <name> <type> before anything is read, for a
name alone once it is known to mean one record set). Declining changes
nothing. A missing set is not found (exit code 4) before the question.
--dry-run reports what would be deleted and asks nothing.`,
		Example:           "  polyctl aws route53 record delete example.com _acme-challenge\n  polyctl aws route53 record delete example.com _acme-challenge TXT\n  polyctl aws route53 record delete example.com www A --set-identifier eu --yes",
		Args:              app.RecordSelectorArgsOrInteractive(rt, 0),
		ValidArgsFunction: app.CompleteRecordArgs(app.CompleteDomainArg(rt, platform.AWS), platform.AWS),
		RunE: func(cmd *cobra.Command, args []string) error {
			// The record set is positional (<name> [<type>]) or, in the
			// former form, given with --name and --type.
			typeArg, named := "--type", cmd.Flags().Changed("name")
			if len(args) > 1 {
				rec, err := app.ParseRecordSelector(cmd, args[1:], 0)
				if err != nil {
					return err
				}
				name, typ, typeArg, named = rec.Name, rec.Type, "<type>", true
				args = args[:1]
			}
			if typ == "" && !named && !rt.Interactive() {
				return app.UsageErrf("%s", app.RecordSelectorUsage(cmd, 0))
			}
			// A record set that is named needs --yes where nothing can be
			// asked: refused before anything is read. A name alone is read
			// first: what it means (one set, several types, nothing) comes
			// before the confirmation.
			if !rt.Flags.DryRun && typ != "" {
				if err := rt.CanConfirm(fmt.Sprintf("delete the %s record set of %s", strings.ToUpper(typ), nameOrApex(name))); err != nil {
					return err
				}
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			args, err := rt.DomainArg(cmd.Context(), args, platform.AWS, platform.ResZone, nil)
			if err != nil {
				return err
			}
			z, err := resolveZone(cmd.Context(), rt, args[0])
			if err != nil {
				return err
			}
			c, prof, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			if z, err = zoneWithName(cmd.Context(), rt, c, z); err != nil {
				return err
			}
			fqdn := platform.FQDN(name, z.Name)
			if typ == "" {
				recs, err := c.ListRecords(cmd.Context(), z.ID)
				if err != nil {
					return err
				}
				// --set-identifier says which sets are meant: only those
				// count for the name, and only those are offered in a list.
				if setID != "" {
					recs = recordsOfSetID(recs, setID)
				}
				// pick: the record set is chosen from a list, of the zone
				// or of the name.
				pick := !named
				if named {
					// The name alone: its one record set, or, with several,
					// a list on a terminal and exit code 5 without one.
					chosen, err := rt.SelectRecords(app.RecordSelect{Zone: z.Name, Records: recs, Name: fqdn, Verb: "Delete", TypeArg: typeArg,
						List: func(_ string, recs []platform.Record) (out []platform.Record, err error) {
							fqdn, typ, setID, err = pickRecordSet(rt, z, recs)
							return recs, err
						}})
					if err != nil {
						return err
					}
					recs = chosen.Records
					switch sets := recordSetKeys(recs); {
					case chosen.Listed:
					case len(sets) == 1:
						typ, setID = sets[0].typ, sets[0].setID
					case !rt.Interactive():
						// One type in several routed sets: LookupSet lists
						// the identifiers (exit code 5).
						typ = chosen.Type()
					default:
						// One type in several routed sets: one is picked.
						pick = true
					}
				}
				if pick {
					if fqdn, typ, setID, err = pickRecordSet(rt, z, recs); err != nil {
						return err
					}
				}
			}
			rs, err := c.LookupSet(cmd.Context(), z.ID, fqdn, typ, setID)
			if err != nil {
				return err
			}
			detail := "the whole record set"
			if setID != "" {
				detail += " (set identifier " + setID + ")"
			}
			if done, err := rt.WouldWrite(platform.Target{Platform: platform.AWS, Profile: prof.Name, Domain: z.Name}, platform.Change{Resource: app.RecordResource(fqdn, typ), Action: platform.Deleted, Detail: detail}); done || err != nil {
				return err
			}
			// A record set is one object here: there is no way to delete one
			// of its values only, so the confirmation names none.
			cur := recordsFromSet(zoneID(z.ID), *rs)
			if err := rt.ConfirmRecordDelete(cmd.Context(), app.RecordDelete{Records: recordGrid(cur),
				Question: fmt.Sprintf("Delete the %s record set of %s (%d value(s))?", strings.ToUpper(typ), platform.NormalizeDomain(fqdn), len(cur)),
				Refusal:  fmt.Sprintf("delete the %s record set of %s", strings.ToUpper(typ), platform.NormalizeDomain(fqdn))}); err != nil {
				return err
			}
			recs, err := c.DeleteSet(cmd.Context(), z.ID, fqdn, typ, setID)
			if err != nil {
				return err
			}
			syncRecordRows(cmd.Context(), rt, prof.Name, z, fqdn, typ, nil)
			rt.Infof("deleted %s %s (%d value(s)) from zone %s via aws/%s", fqdn, strings.ToUpper(typ), len(recs), z.Name, prof.Name)
			return rt.Render(recordResult{Profile: prof.Name, Zone: z, Records: recs}, func() output.Grid { return recordGrid(recs) })
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "record type")
	cmd.Flags().StringVar(&name, "name", "", "record name relative to the zone (www, @); default: the zone apex")
	cmd.Flags().StringVar(&setID, "set-identifier", "", "set identifier of a routing-policy record set (weighted, latency, failover...)")
	app.HideFormerRecordFlags(cmd)
	return cmd
}

// recordSetKey tells the record sets of one name apart: the type and, for
// a routing-policy set, the set identifier.
type recordSetKey struct{ typ, setID string }

// recordSetKeys are the record sets recs (the records of one name) are in.
func recordSetKeys(recs []platform.Record) []recordSetKey {
	var keys []recordSetKey
	seen := map[recordSetKey]bool{}
	for _, r := range recs {
		k := recordSetKey{strings.ToUpper(r.Type), extraString(r.Extra, "set_identifier")}
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	return keys
}

// recordsOfSetID are the records of recs in a routing-policy set with the
// set identifier id.
func recordsOfSetID(recs []platform.Record, id string) []platform.Record {
	var out []platform.Record
	for _, r := range recs {
		if extraString(r.Extra, "set_identifier") == id {
			out = append(out, r)
		}
	}
	return out
}

// nameOrApex names --name for a message: the zone apex when it is empty.
func nameOrApex(name string) string {
	if name == "" || name == "@" {
		return "the zone apex"
	}
	return name
}

// ----------------------------------------------------- route53domains

type domainResult struct {
	Profile string            `json:"profile" yaml:"profile"`
	Cached  bool              `json:"cached" yaml:"cached"`
	Domains []platform.Domain `json:"domains" yaml:"domains"`
}

func domainGrid(domains []platform.Domain) output.Grid {
	g := output.Grid{Headers: []string{"NAME", "EXPIRES", "AUTO_RENEW", "LOCKED", "PRIVACY", "NAMESERVERS"}, Empty: "no registered domains"}
	for _, d := range domains {
		g.Rows = append(g.Rows, []string{d.Name, d.ExpiresAt, output.Str(d.AutoRenew), output.Str(d.Locked), output.Str(d.Privacy), strings.Join(d.Nameservers, ",")})
	}
	return g
}

func domainKV(d *platform.Domain) output.Grid {
	return output.KV("NAME", d.Name, "STATUS", d.Status, "EXPIRES", d.ExpiresAt, "AUTO_RENEW", output.Str(d.AutoRenew),
		"LOCKED", output.Str(d.Locked), "PRIVACY", output.Str(d.Privacy), "NAMESERVERS", strings.Join(d.Nameservers, ","),
		"REGISTRAR", output.Str(d.Extra["registrar_name"]), "CREATED", output.Str(d.Extra["created_at"]))
}

func route53domainsCmd(rt *app.Runtime) *cobra.Command {
	// route53domains is this tree's registrar group, like `domain` in the
	// namecom, godaddy and aliyun trees: list, get and ns get|set sit
	// directly below it.
	cmd := &cobra.Command{Use: "route53domains", Short: "Route 53 Domains: registered domains and their nameservers"}
	ns := &cobra.Command{Use: "ns", Short: "Nameservers of a registered domain"}
	ns.AddCommand(nsGetCmd(rt), nsSetCmd(rt))
	cmd.AddCommand(domainListCmd(rt), domainGetCmd(rt), ns)
	return cmd
}

// nameserversResult is the output of `aws route53domains ns get`.
type nameserversResult struct {
	Profile     string   `json:"profile" yaml:"profile"`
	Cached      bool     `json:"cached" yaml:"cached"`
	Domain      string   `json:"domain" yaml:"domain"`
	Nameservers []string `json:"nameservers" yaml:"nameservers"`
}

func nsGetCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get <domain>",
		Short: "Show the nameservers of a registered domain (local inventory with --offline)",
		Args:  app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := rt.DomainArg(cmd.Context(), args, platform.AWS, platform.ResDomain, nil)
			if err != nil {
				return err
			}
			profName, err := rt.ProfileFor(platform.AWS)
			if err != nil {
				return err
			}
			var d *platform.Domain
			cached := rt.Flags.Offline
			if cached {
				if d, err = cachedDomain(cmd.Context(), rt, profName, args[0]); err != nil {
					return err
				}
			} else {
				c, _, err := openClient(cmd.Context(), rt)
				if err != nil {
					return err
				}
				if d, err = c.GetDomain(cmd.Context(), args[0]); err != nil {
					return err
				}
				storeDomain(cmd.Context(), rt, profName, d)
			}
			res := nameserversResult{Profile: profName, Cached: cached, Domain: d.Name, Nameservers: d.Nameservers}
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

func domainListCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List registered domains",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			profName, err := rt.ProfileFor(platform.AWS)
			if err != nil {
				return err
			}
			set := inventory.Set{Platform: platform.AWS, Profile: profName, Type: platform.ResDomain}
			rows, cached, err := rt.EnsureSet(cmd.Context(), set, func(ctx context.Context) ([]platform.Resource, error) {
				c, _, err := openClient(ctx, rt)
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
			res := domainResult{Profile: profName, Cached: cached, Domains: make([]platform.Domain, 0, len(rows))}
			for _, r := range rows {
				var d platform.Domain
				if err := r.Decode(&d); err != nil {
					return fmt.Errorf("decode cached domain %s: %w", r.ID, err)
				}
				res.Domains = append(res.Domains, d)
			}
			if cached {
				rt.Infof("%d registered domain(s) via aws/%s (local inventory)", len(res.Domains), profName)
			}
			return rt.Render(res, func() output.Grid { return domainGrid(res.Domains) })
		},
	}
}

func cachedDomain(ctx context.Context, rt *app.Runtime, profName, name string) (*platform.Domain, error) {
	db, err := rt.DB()
	if err != nil {
		return nil, err
	}
	r, err := db.Get(ctx, inventory.Set{Platform: platform.AWS, Profile: profName}, platform.ResDomain, platform.NormalizeDomain(name))
	if err != nil {
		return nil, fmt.Errorf("%w: domain %q is not in the local inventory", platform.ErrNotFound, name)
	}
	var d platform.Domain
	if err := r.Decode(&d); err != nil {
		return nil, err
	}
	return &d, nil
}

func storeDomain(ctx context.Context, rt *app.Runtime, profName string, d *platform.Domain) {
	if db, err := rt.DB(); err == nil {
		cfg, _ := rt.Config()
		_ = db.Upsert(ctx, inventory.Set{Platform: platform.AWS, Profile: profName, Type: platform.ResDomain},
			app.DomainResources([]platform.Domain{*d})[0], cfg.TTLFor(platform.ResDomain))
	}
}

func domainGetCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get <domain>",
		Short: "Show one registered domain",
		Args:  app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := rt.DomainArg(cmd.Context(), args, platform.AWS, platform.ResDomain, nil)
			if err != nil {
				return err
			}
			profName, err := rt.ProfileFor(platform.AWS)
			if err != nil {
				return err
			}
			var d *platform.Domain
			if rt.Flags.Offline {
				if d, err = cachedDomain(cmd.Context(), rt, profName, args[0]); err != nil {
					return err
				}
			} else {
				c, _, err := openClient(cmd.Context(), rt)
				if err != nil {
					return err
				}
				if d, err = c.GetDomain(cmd.Context(), args[0]); err != nil {
					return err
				}
				storeDomain(cmd.Context(), rt, profName, d)
			}
			return rt.Render(d, func() output.Grid { return domainKV(d) })
		},
	}
}

func nsSetCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "set <domain> <nameserver>...",
		Short:   "Replace the nameservers of a registered domain",
		Long:    "Replace the nameservers of <domain> with the ones given.\n" + app.NameserverHelp,
		Example: "  polyctl aws route53domains ns set example.com ns1.example.net ns2.example.net",
		Args:    app.NameserverArgsOrInteractive(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := rt.DomainArg(cmd.Context(), args, platform.AWS, platform.ResDomain, nil)
			if err != nil {
				return err
			}
			if len(args) < 2 {
				more, err := rt.PickNameservers(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				args = append(args, more...)
			}
			ns, err := app.Nameservers(args[1:])
			if err != nil {
				return err
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			c, prof, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			name := platform.NormalizeDomain(args[0])
			if done, err := rt.WouldWrite(platform.Target{Platform: platform.AWS, Profile: prof.Name, Domain: name}, app.NameserverChange(name, ns)); done || err != nil {
				return err
			}
			if err := c.SetNameservers(cmd.Context(), name, ns); err != nil {
				return err
			}
			rt.Infof("nameservers of %s set to %s via aws/%s", name, strings.Join(ns, ","), prof.Name)
			d, err := c.GetDomain(cmd.Context(), name)
			if err != nil {
				rt.Infof("note: could not re-read the domain: %v", err)
				d = &platform.Domain{Name: name, Nameservers: ns}
			} else {
				storeDomain(cmd.Context(), rt, prof.Name, d)
			}
			return rt.Render(d, func() output.Grid { return domainKV(d) })
		},
	}
	return cmd
}

// ---------------------------------------------------------------- ec2

type instanceResult struct {
	Profile   string         `json:"profile" yaml:"profile"`
	Region    string         `json:"region" yaml:"region"`
	Cached    bool           `json:"cached" yaml:"cached"`
	Instances []instanceInfo `json:"instances" yaml:"instances"`
}

func instanceGrid(instances []instanceInfo) output.Grid {
	g := output.Grid{Headers: []string{"ID", "NAME", "STATE", "TYPE", "AZ", "PRIVATE_IP", "PUBLIC_IP"}, Empty: "no instances"}
	for _, i := range instances {
		g.Rows = append(g.Rows, []string{i.ID, i.Name, i.State, i.Type, i.AZ, i.PrivateIP, i.PublicIP})
	}
	return g
}

func ec2Cmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "ec2", Short: "Elastic Compute Cloud"}
	instance := &cobra.Command{
		Use:   "instance",
		Short: "EC2 instances",
		Long: `EC2 instances. get, delete, reboot and resize find the instance by its Name
tag or its id in every selected AWS account, the way domains are routed:
the inventory tells which account holds it (synced once when it does not
know), and the account is asked live, so that a terminated instance of the
same name is never picked. Several live instances of one name are ambiguous
(exit code 5). --region looks in another region of the profile's account.
password shows the Windows login create --os windows stored; ssh-key lists,
adds and removes the SSH keys of a Linux instance over SSH.`,
	}
	instance.AddCommand(ec2ListCmd(rt), ec2GetCmd(rt), ec2CreateCmd(rt), ec2DeleteCmd(rt), ec2RebootCmd(rt), ec2ResizeCmd(rt),
		ec2StateCmd(rt, "start"), ec2StateCmd(rt, "stop"), ec2PasswordCmd(rt), ec2SSHKeyCmd(rt))
	cmd.AddCommand(instance, keyPairCmd(rt), securityGroupCmd(rt), volumeCmd(rt), snapshotCmd(rt))
	return cmd
}

func ec2ListCmd(rt *app.Runtime) *cobra.Command {
	var region string
	var filters instanceFilters
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List EC2 instances (the profile's default region is cached locally)",
		Long: `List the EC2 instances of the profile's region, every state included; the
list is cached in the local inventory. --region lists another region, and
the filters ask AWS directly, bypassing the inventory: --state and --type
take one or more comma-separated values (repeatable), --name matches the
Name tags that contain the value (a value holding * or ? is used as the
EC2 wildcard pattern it is). Several filters must all match.`,
		Example: "  polyctl aws ec2 instance list --state running --type c6a.large,c6a.xlarge --name web -o json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, s := range filters.States {
				if !slices.Contains(instanceStates, s) {
					return app.UsageErrf("--state %q: expected one of %s", s, strings.Join(instanceStates, ", "))
				}
			}
			profName, err := rt.ProfileFor(platform.AWS)
			if err != nil {
				return err
			}
			res := instanceResult{Profile: profName, Region: region}
			if region != "" || !filters.empty() {
				if rt.Flags.Offline {
					return app.ErrOffline
				}
				c, _, err := openClient(cmd.Context(), rt)
				if err != nil {
					return err
				}
				res.Region = c.regionOr(region)
				if res.Instances, err = c.listInstancesFiltered(cmd.Context(), res.Region, filters); err != nil {
					return err
				}
				if len(res.Instances) == 0 {
					rt.Infof("no matching instances in %s via aws/%s", res.Region, profName)
				}
				return rt.Render(res, func() output.Grid { return instanceGrid(res.Instances) })
			}
			set := inventory.Set{Platform: platform.AWS, Profile: profName, Type: platform.ResInstance}
			rows, cached, err := rt.EnsureSet(cmd.Context(), set, func(ctx context.Context) ([]platform.Resource, error) {
				c, _, err := openClient(ctx, rt)
				if err != nil {
					return nil, err
				}
				res.Region = c.region
				return c.Sync(ctx, platform.ResInstance)
			})
			if err != nil {
				return err
			}
			res.Cached = cached
			if res.Region == "" {
				res.Region = profileRegion(rt, profName)
			}
			// The inventory holds the instances of every enabled region;
			// the list shows those of the profile's region.
			for _, r := range rows {
				var i instanceInfo
				if err := r.Decode(&i); err != nil {
					return fmt.Errorf("decode cached instance %s: %w", r.ID, err)
				}
				if res.Region == "" {
					res.Region = i.Region
				}
				if i.Region != "" && i.Region != res.Region {
					continue
				}
				res.Instances = append(res.Instances, i)
			}
			if cached {
				rt.Infof("%d instance(s) via aws/%s (local inventory)", len(res.Instances), profName)
			}
			return rt.Render(res, func() output.Grid { return instanceGrid(res.Instances) })
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "list another region (bypasses the local inventory)")
	cmd.Flags().StringSliceVar(&filters.States, "state", nil, "only instances in these states ("+strings.Join(instanceStates, ", ")+"; comma-separated)")
	cmd.Flags().StringSliceVar(&filters.Types, "type", nil, "only instances of these types (comma-separated)")
	cmd.Flags().StringVar(&filters.Name, "name", "", "only instances whose Name tag contains this value (* and ? make it a pattern)")
	return cmd
}

func ec2StateCmd(rt *app.Runtime, action string) *cobra.Command {
	var region string
	var force bool
	var wf app.WaitFlags
	want := stateRunning
	if action == "stop" {
		want = stateStopped
	}
	title := strings.ToUpper(action[:1]) + action[1:]
	long := title + ` an EC2 instance, found like get finds it. An instance that is ` + want + `
already is unchanged (exit code 0). --wait waits (5 second polls, at most
--timeout) until the instance is ` + want + `; after a start the new addresses
are printed.`
	if action == "stop" {
		long += `

A confirmation is asked first (default no; --yes skips it, and the
non-interactive flow needs --yes: exit code 2 without it). A declined
confirmation is exit code 0. --force stops the instance without a clean
shutdown of the operating system. A pending instance cannot be stopped
yet: the command first waits (at most --timeout) until it is running.`
	}
	cmd := &cobra.Command{
		Use:   action + " <name|id>",
		Short: title + " an EC2 instance",
		Long:  long,
		Args:  app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			wait, timeout, err := wf.Resolve(cmd)
			if err != nil {
				return err
			}
			what, keep := "stopped AWS instance", statesIn(stateStopped)
			if action == "stop" {
				what, keep = "running AWS instance", statesIn(stateRunning, statePending)
			}
			if args, err = instanceArg(ctx, rt, args, region, what, keep); err != nil {
				return err
			}
			// The non-interactive flow without --yes is refused before any
			// lookup; a dry run stops nothing and needs no confirmation.
			if action == "stop" && !rt.DryRun() {
				if err := rt.CanConfirm("stop instance " + args[0]); err != nil {
					return err
				}
			}
			l, err := resolveInstance(ctx, rt, args[0], region, false)
			if err != nil {
				return err
			}
			target := l.target()
			label := instanceLabel(l.inst)
			cur := instanceState(l.inst)
			if cur == want {
				return rt.RenderReport(platform.Report{Target: target, DryRun: rt.DryRun(), Changes: []platform.Change{
					{Resource: l.resource(), Action: platform.Unchanged, ID: l.id(), Detail: cur}}})
			}
			change := platform.Change{Resource: l.resource(), Action: platform.Updated, ID: l.id(), Detail: action}
			if force {
				change.Detail = "stop (forced)"
			}
			if done, err := rt.WouldWrite(target, change); done || err != nil {
				return err
			}
			if action == "stop" {
				ok, cerr := rt.Confirm(ctx, fmt.Sprintf("Stop instance %s (%s)? It is unavailable until it is started again.", label, cur), false)
				if cerr != nil {
					return cerr
				}
				if !ok {
					return fmt.Errorf("%w: cancelled; instance %s was not stopped", platform.ErrNothingToDo, label)
				}
				if cur == statePending {
					// StopInstances refuses an instance that never ran:
					// wait (at most --timeout) until it is running.
					rt.Infof("instance %s is pending; waiting until it is running before it is stopped", label)
					if _, werr := l.c.waitInstanceState(ctx, l.region, l.id(), l.name(), stateRunning, timeout); werr != nil {
						return fmt.Errorf("instance %s was not stopped: %w", label, werr)
					}
				}
				err = l.c.stopInstanceChecked(ctx, l.region, l.id(), force)
			} else {
				err = l.c.startInstanceChecked(ctx, l.region, l.id())
			}
			if err != nil {
				return err
			}
			rt.Infof("%s of %s requested via aws/%s (was %s)", action, label, l.profile, cur)
			if wait {
				in, err := l.c.waitInstanceState(ctx, l.region, l.id(), l.name(), want, timeout)
				if err != nil {
					return fmt.Errorf("%s of %s was requested: %w", action, label, err)
				}
				l.inst = in
				if want == stateRunning {
					pub := awssdk.ToString(in.PublicIpAddress)
					change.Detail += "; running, public ip " + orNone(pub)
					change.Attrs = map[string]string{"public_ip": pub, "private_ip": awssdk.ToString(in.PrivateIpAddress)}
					rt.Infof("instance %s is running: public ip %s, private ip %s", label, orNone(pub), orNone(awssdk.ToString(in.PrivateIpAddress)))
				} else {
					change.Detail += "; stopped"
					rt.Infof("instance %s is stopped", label)
				}
				storeInstance(ctx, rt, l.profile, l.c, l.region, in)
			} else {
				l.reread(ctx, rt)
			}
			return rt.RenderReport(platform.Report{Target: target, Changes: []platform.Change{change}})
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region of the instance (default: look it up in the inventory of every account)")
	if action == "stop" {
		cmd.Flags().BoolVar(&force, "force", false, "force the instance to stop without a clean shutdown")
	}
	app.AddWaitFlags(cmd, &wf, false, defaultInstanceTimeout)
	return cmd
}

// pickRecordSet asks for the record set record delete deletes, from the
// sets of the zone (one option per name, type and set identifier, with its
// values and TTL; those of name only when it is given; the apex NS and SOA,
// which the zone cannot do without, left out). It returns the name, type
// and set identifier. None is nothing to do.
func pickRecordSet(rt *app.Runtime, z *platform.Zone, recs []platform.Record) (string, string, string, error) {
	apex := platform.NormalizeDomain(z.Name)
	type set struct {
		name, typ, setID string
		values           []string
		ttl              int
	}
	var sets []*set
	byKey := map[string]*set{}
	for _, r := range recs {
		n := platform.NormalizeDomain(r.Name)
		if n == apex && (r.Type == "NS" || r.Type == "SOA") {
			continue
		}
		setID := extraString(r.Extra, "set_identifier")
		key := n + "|" + r.Type + "|" + setID
		s := byKey[key]
		if s == nil {
			s = &set{name: r.Name, typ: r.Type, setID: setID, ttl: r.TTL}
			byKey[key] = s
			sets = append(sets, s)
		}
		s.values = append(s.values, r.Value)
	}
	var opts []prompt.Option
	for _, s := range sets {
		opts = append(opts, prompt.Option{Label: recordSetLabel(s.name, s.typ, s.setID, s.values, s.ttl), Value: s.name + "\x00" + s.typ + "\x00" + s.setID})
	}
	v, err := rt.Choose(app.Choice{Title: "Record set to delete from " + z.Name, Options: opts, Arg: "--type",
		Empty: app.NothingToDof("zone %s has no record set to delete", z.Name)})
	if err != nil {
		return "", "", "", err
	}
	parts := strings.SplitN(v, "\x00", 3)
	for len(parts) < 3 {
		parts = append(parts, "")
	}
	return platform.FQDN(parts[0], z.Name), parts[1], parts[2], nil
}

// recordSetLabel: "www.example.com  A  set us  198.51.100.2, 198.51.100.3
// ttl 60", the values of the set as one cell. The set identifier is all that
// tells the routed sets of one name and type apart, so it comes before the
// values: they can be longer than the terminal is wide, and a label is cut
// at its end.
func recordSetLabel(name, typ, setID string, values []string, ttl int) string {
	id, t := "", ""
	if setID != "" {
		id = "set " + setID
	}
	if ttl > 0 {
		t = fmt.Sprintf("ttl %d", ttl)
	}
	return prompt.Cells(name, typ, id, strings.Join(values, ", "), t)
}
