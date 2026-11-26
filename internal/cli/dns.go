package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

func newDNSCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dns",
		Short: "Platform-neutral DNS record management (auto-routed by domain)",
		Long: `Manage DNS records of any zone regardless of where it is hosted. The owning
account (profile and platform) is looked up in the local domain index; pass
--profile and/or --platform to narrow the search, --refresh to re-fetch from
the platform, --offline to never touch the network.`,
	}
	addRouteFlags(rt, cmd)
	cmd.AddCommand(newDNSListCmd(rt), newDNSSetCmd(rt), newDNSAddCmd(rt), newDNSEnsureCmd(rt), newDNSDeleteCmd(rt))
	return cmd
}

// dnsResult wraps records with the routing information for json/yaml output.
type dnsResult struct {
	Target  *app.Target       `json:"target" yaml:"target"`
	Cached  bool              `json:"cached" yaml:"cached"`
	Records []platform.Record `json:"records" yaml:"records"`
}

// dnsName reads the --name flag in the zone of t as dns ensure does: "@"
// is the apex, a name ending with a dot is absolute, other names are
// relative to the zone. A name outside the zone is a usage error.
func dnsName(t *app.Target, name string) (string, error) {
	return dnsNameOf(t, name, "--name")
}

// dnsNameOf is dnsName for a name given as arg: the --name flag, or the
// <name> of a positional record.
func dnsNameOf(t *app.Target, name, arg string) (string, error) {
	fqdn, err := platform.ZoneName(t.Domain, name)
	if err != nil {
		return "", usageErr("%s: %v", arg, err)
	}
	return fqdn, nil
}

// recordHelp is the paragraph of the record commands about their positional
// record.
var recordHelp = app.RecordArgsHelp("zone")

// recordGrid renders records of platform p; Cloudflare gets a PROXIED column.
func recordGrid(recs []platform.Record, p platform.ID) output.Grid {
	showProxied := p == platform.Cloudflare
	headers := []string{"NAME", "TYPE", "VALUE", "TTL"}
	if showProxied {
		headers = append(headers, "PROXIED")
	}
	headers = append(headers, "ID")
	g := output.Grid{Headers: headers, Empty: "no records"}
	for _, r := range recs {
		value := r.Value
		if r.Priority != nil {
			value = fmt.Sprintf("%d %s", *r.Priority, r.Value)
		}
		row := []string{r.Name, r.Type, value, platform.TTLLabel(p, r)}
		if showProxied {
			row = append(row, output.Str(r.Proxied))
		}
		row = append(row, r.ID)
		g.Rows = append(g.Rows, row)
	}
	return g
}

func newDNSListCmd(rt *app.Runtime) *cobra.Command {
	var typ, name string
	cmd := &cobra.Command{
		Use:               "list <domain>",
		Short:             "List DNS records of the zone that serves <domain>",
		Args:              app.ArgsOrInteractive(rt, 1, nil),
		ValidArgsFunction: completeDomains(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := domainArgs(cmd, rt, args, app.DomainPick{Title: "Zone", Kinds: zoneKinds})
			if err != nil {
				return err
			}
			t, err := rt.ResolveDomain(cmd.Context(), args[0], platform.ResZone)
			if err != nil {
				return err
			}
			recs, cached, err := rt.ZoneRecords(cmd.Context(), t)
			if err != nil {
				return err
			}
			if name != "" {
				fqdn, err := dnsName(t, name)
				if err != nil {
					return err
				}
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
			sort.SliceStable(recs, func(i, j int) bool {
				if recs[i].Name != recs[j].Name {
					return recs[i].Name < recs[j].Name
				}
				return recs[i].Type < recs[j].Type
			})
			rt.Infof("zone %s via %s/%s%s", t.Domain, t.Platform, t.Profile, cacheNote(cached))
			return rt.Render(dnsResult{Target: t, Cached: cached, Records: recs}, func() output.Grid {
				return recordGrid(recs, t.Platform)
			})
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "filter by record type")
	cmd.Flags().StringVar(&name, "name", "", "filter by record name (relative, @ or FQDN)")
	return cmd
}

func cacheNote(cached bool) string {
	if cached {
		return " (local inventory)"
	}
	return ""
}

// newDNSSetCmd is `dns set`: create the record, or update the one that has
// the same name and type.
func newDNSSetCmd(rt *app.Runtime) *cobra.Command {
	return newDNSWriteCmd(rt, false, &cobra.Command{
		Use:   "set <domain> <name> <type> <value>",
		Short: "Create or update a DNS record (matched by name + type)",
		Long: `Create or update a record in the zone serving <domain>.

` + recordHelp + `

If exactly one record with the same name and type exists it is updated;
if none exists it is created. If several exist the command fails: use
` + "`polyctl dns add`" + ` to create one more record of that name and type, or
` + "`polyctl dns delete`" + ` to remove the ones that should go.

` + app.RecordAskHelp("zone") + `

The value of the record that is updated is proposed.

--proxied (Cloudflare) is a boolean: --proxied switches the proxy on,
--proxied=false switches it off, and without it an updated record keeps its
current setting.`,
		Example: `  polyctl dns set example.com www A 203.0.113.10
  polyctl dns set example.com @ MX mail.example.com --priority 10
  polyctl dns set example.com www CNAME target.example.net --ttl 300`,
	})
}

// newDNSAddCmd is `dns add`: always create one more record.
func newDNSAddCmd(rt *app.Runtime) *cobra.Command {
	return newDNSWriteCmd(rt, true, &cobra.Command{
		Use:   "add <domain> <name> <type> <value>",
		Short: "Add a DNS record, keeping the existing ones of that name + type",
		Long: `Create one more record in the zone serving <domain>. Records that already
have the same name and type are left alone, which is how round-robin A
records or several TXT or MX records are built up. To change an existing
record use ` + "`polyctl dns set`" + `.

` + recordHelp + `

` + app.RecordAskHelp("zone") + `

--proxied (Cloudflare) is a boolean: --proxied switches the proxy on,
--proxied=false switches it off, and without it the platform default applies.`,
		Example: `  polyctl dns add example.com www A 203.0.113.11
  polyctl dns add example.com @ TXT "v=spf1 include:_spf.example.net ~all"`,
	})
}

// newDNSWriteCmd completes cmd as a record-writing command. With add it
// always creates a record; without, it updates the one record that has the
// same name and type and creates it when there is none.
func newDNSWriteCmd(rt *app.Runtime, add bool, cmd *cobra.Command) *cobra.Command {
	var ttl, priority int
	var proxied bool
	cmd.Args = app.ProxiedRecordArgs(app.RecordArgsOrInteractive(rt, 1, 1), 1)
	cmd.ValidArgsFunction = app.CompleteRecordArgs(completeDomains(rt), "")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		// The record is positional (<name> <type> <value>) or, in the
		// former form, given with --name, --type and --value. The
		// interactive flow asks for what is missing: the zone, then the
		// name, the type and the value.
		in, err := rt.RecordInput(cmd, args, app.RecordForm{MinValues: 1, MaxValues: 1})
		if err != nil {
			return err
		}
		args, err = domainArgs(cmd, rt, args[:min(len(args), 1)], app.DomainPick{Title: "Zone", Kinds: zoneKinds, Required: true})
		if err != nil {
			return err
		}
		t, err := rt.ResolveDomain(cmd.Context(), args[0], platform.ResZone)
		if err != nil {
			return err
		}
		if rt.Flags.Offline {
			return app.ErrOffline
		}
		// A <domain> below its zone names the record (the former form
		// `dns set www.example.com --type A --value ...`). The zone itself
		// names none: the interactive flow asks, and the former form
		// without --name keeps writing to the apex.
		fqdn := platform.NormalizeDomain(args[0])
		if in.Name != "" {
			if fqdn, err = dnsNameOf(t, in.Name, in.NameArg); err != nil {
				return err
			}
		} else if fqdn != platform.NormalizeDomain(t.Domain) {
			in.Name = fqdn
		}
		dns, err := rt.OpenDNS(cmd.Context(), t)
		if err != nil {
			return err
		}
		existing, err := dns.ListRecords(cmd.Context(), t.ResourceID)
		if err != nil {
			return err
		}
		asked := in.Name == ""
		if err := rt.CompleteRecord(in, app.RecordPrompt{Platform: t.Platform, Zone: t.Domain, Replaces: !add,
			Existing: func() ([]platform.Record, error) { return existing, nil }}); err != nil {
			return err
		}
		if asked && in.Name != "" {
			if fqdn, err = dnsNameOf(t, in.Name, in.NameArg); err != nil {
				return err
			}
		}
		typ, value := in.Type, in.Value()
		matches := app.MatchRecords(existing, fqdn, typ, "")
		rec := platform.Record{ZoneID: t.ResourceID, Name: fqdn, Type: typ, Value: value, TTL: ttl}
		if cmd.Flags().Changed("priority") {
			p := priority
			rec.Priority = &p
		}
		if cmd.Flags().Changed("proxied") {
			b := proxied
			rec.Proxied = &b
		}
		create := add || len(matches) == 0
		if !create && len(matches) > 1 {
			return fmt.Errorf("%d records named %s %s exist; use `polyctl dns add` to create another, or `polyctl dns delete` first", len(matches), fqdn, typ)
		}
		change := platform.Change{Resource: app.RecordResource(fqdn, typ), Action: platform.Created, Detail: value}
		if !create {
			change.Action, change.ID = platform.Updated, matches[0].ID
			change.Detail = matches[0].Value + " -> " + value
		}
		if done, err := rt.WouldWrite(t.ReportTarget(), change); done || err != nil {
			return err
		}
		var out *platform.Record
		oldID := ""
		if create {
			out, err = dns.CreateRecord(cmd.Context(), t.ResourceID, rec)
		} else {
			rec.ID = matches[0].ID
			oldID = rec.ID
			if rec.TTL == 0 {
				rec.TTL = matches[0].TTL
			}
			if rec.Priority == nil {
				rec.Priority = matches[0].Priority
			}
			if rec.Proxied == nil {
				rec.Proxied = matches[0].Proxied
			}
			rec.Extra = matches[0].Extra
			out, err = dns.UpdateRecord(cmd.Context(), t.ResourceID, rec)
		}
		if err != nil {
			return err
		}
		// Keep the local inventory in sync with the mutation. Platforms
		// whose record ids encode the value (Route 53, Cloud DNS,
		// GoDaddy) hand back a new id after an update, so the row under
		// the old id must go or the cache lists both.
		if db, err := rt.DB(); err == nil {
			cfg, _ := rt.Config()
			set := inventory.Set{Platform: t.Platform, Profile: t.Profile, Type: platform.ResDNSRecord}
			if oldID != "" && out.ID != oldID {
				if err := db.Delete(cmd.Context(), set, platform.ResDNSRecord, oldID); err != nil {
					rt.Verbosef("inventory: %v", err)
				}
			}
			if err := db.Upsert(cmd.Context(), set, app.RecordResources(t.ResourceID, t.Domain, []platform.Record{*out})[0], cfg.TTLFor(platform.ResDNSRecord)); err != nil {
				rt.Verbosef("inventory: %v", err)
			}
		}
		rt.Infof("%s %s %s -> %s via %s/%s", map[bool]string{true: "created", false: "updated"}[rec.ID == ""], out.Name, out.Type, out.Value, t.Platform, t.Profile)
		return rt.Render(dnsResult{Target: t, Records: []platform.Record{*out}}, func() output.Grid {
			return recordGrid([]platform.Record{*out}, t.Platform)
		})
	}
	ttlHelp := "TTL in seconds (0 = platform default / keep existing)"
	if add {
		ttlHelp = "TTL in seconds (0 = platform default)"
	}
	app.FormerRecordFlags(cmd, false)
	cmd.Flags().IntVar(&ttl, "ttl", 0, ttlHelp)
	cmd.Flags().IntVar(&priority, "priority", 0, "priority for MX/SRV records")
	proxiedHelp := "Cloudflare proxy status: --proxied or --proxied=false (default: keep the current value; the platform default for a new record)"
	if add {
		proxiedHelp = "Cloudflare proxy status: --proxied or --proxied=false (default: the platform default)"
	}
	cmd.Flags().BoolVar(&proxied, "proxied", false, proxiedHelp)
	return cmd
}

// dnsDeleteForm is the form of dns delete: the record by name or --id, with
// the former --name, --type and --value, or --all in place of a record.
var dnsDeleteForm = app.RecordTargetForm{FormerFlags: []string{"name", "type", "value"}, FormerApex: true, Instead: []string{"all"}}

func newDNSDeleteCmd(rt *app.Runtime) *cobra.Command {
	var types []string
	var name, value, id string
	var all, keepBound bool
	cmd := &cobra.Command{
		Use:   "delete <domain> [<name> [<type> [<value>]]]",
		Short: "Delete the DNS records of a name (optionally of one type and value), or all of them with --all",
		Long: "Delete the records of <name> in the zone serving <domain>, or the one record\n" +
			"with --id.\n" +
			"\n" + dnsDeleteForm.Help("zone", "polyctl dns list") + "\n" +
			"\n" + app.RecordDeleteHelp + "\n" +
			"\n" +
			"With --all, every record of the zone is deleted (it cannot be combined with\n" +
			"a positional record or --id); --type then limits the deletion to the given types\n" +
			"across the whole zone (repeatable or comma-separated). The SOA and the NS\n" +
			"records of the zone apex are never deleted; delegations (NS records of names\n" +
			"below the apex) are. A record owned by another service of the platform (the\n" +
			"CNAME of an R2 custom domain on Cloudflare) is unbound there, which removes\n" +
			"it; --keep-bound leaves such records alone. The interactive flow shows a\n" +
			"summary and asks first (default no); the non-interactive flow needs --yes.\n" +
			"A record that cannot be deleted does not stop the others: it is reported as\n" +
			"failed and the command exits with code 1 at the end. The zone is read live:\n" +
			"--offline is refused (exit code 6).",
		Example: `  polyctl dns delete example.com www
  polyctl dns delete example.com www A
  polyctl dns delete example.com www A 203.0.113.10
  polyctl dns delete example.com @ TXT "v=spf1 -all" --yes
  polyctl dns delete example.com --id 372e67954025e0ba6aaa6d586b9e0b59
  polyctl dns delete example.com --all --type TXT --dry-run`,
		Args:              dnsDeleteForm.ArgsOrInteractive(rt),
		ValidArgsFunction: dnsDeleteForm.Complete(rt, completeDomains(rt), ""),
		RunE: func(cmd *cobra.Command, args []string) error {
			// The record is positional (<name> [<type> [<value>]]) or, in
			// the former form, given with --name, --type and --value.
			target, err := dnsDeleteForm.Parse(cmd, args)
			if err != nil {
				return err
			}
			args, err = domainArgs(cmd, rt, args[:min(len(args), 1)], app.DomainPick{Title: "Zone", Kinds: zoneKinds})
			if err != nil {
				return err
			}
			if all {
				if name != "" || value != "" || id != "" {
					return usageErr("--all deletes every record of the zone; it cannot be combined with --name, --value or --id")
				}
				return runDNSDeleteAll(cmd.Context(), rt, args[0], types, keepBound)
			}
			if keepBound {
				return usageErr("--keep-bound only applies with --all")
			}
			t, err := rt.ResolveDomain(cmd.Context(), args[0], platform.ResZone)
			if err != nil {
				return err
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			// A name outside the zone is refused before the zone is read.
			if target != nil && target.Name != "" {
				nameArg := "<name>"
				if target.TypeArg == "--type" {
					nameArg = "--name"
					if !cmd.Flags().Changed("name") {
						// The former --type without --name: the records of
						// <domain> itself.
						target.Name = platform.NormalizeDomain(args[0])
					}
				}
				if _, err := dnsNameOf(t, target.Name, nameArg); err != nil {
					return err
				}
			}
			dns, err := rt.OpenDNS(cmd.Context(), t)
			if err != nil {
				return err
			}
			existing, err := dns.ListRecords(cmd.Context(), t.ResourceID)
			if err != nil {
				return err
			}
			zone := platform.Zone{ID: t.ResourceID, Name: t.Domain}
			// Without a name the interactive flow lists the records of the
			// zone to tick (of --value when only that is given). A name
			// selects its records; without a type that is every record of
			// the name when they have one type.
			sel := target.Select(app.RecordSelect{Zone: t.Domain, Records: existing, ID: id, Verb: "Delete"})
			if matcher, ok := dns.(platform.RecordIDMatcher); ok {
				sel.IDMatches = matcher.RecordIDMatches
			}
			sel.Offer, sel.Mark = app.DeletableRecords(dns, zone)
			chosen, err := rt.SelectRecords(sel)
			if err != nil {
				return err
			}
			matches := chosen.Records
			del := app.RecordsDelete{Target: t.ReportTarget(), Zone: zone, DNS: dns, Records: matches, Exact: sel.Exact(chosen),
				Grid: func(recs []platform.Record) output.Grid { return recordGrid(recs, t.Platform) }}
			if done, err := rt.DeleteRecords(cmd.Context(), del); !done || err != nil {
				return err
			}
			return rt.Render(dnsResult{Target: t, Records: matches}, func() output.Grid { return output.Grid{} })
		},
	}
	cmd.Flags().StringArrayVar(&types, "type", nil, "with --all, the types to delete across the zone (repeatable or comma-separated; default: every type)")
	cmd.Flags().StringVar(&name, "name", "", "former form of <name>; default: <domain> itself")
	cmd.Flags().StringVar(&value, "value", "", "former form of <value>")
	// --type stays in the help: --all reads it.
	app.HideFormerRecordFlags(cmd, "name", "value")
	cmd.Flags().StringVar(&id, "id", "", "delete the record with this platform id")
	cmd.Flags().BoolVar(&all, "all", false, "delete every record of the zone (except its SOA and apex NS records)")
	cmd.Flags().BoolVar(&keepBound, "keep-bound", false, "with --all, leave records owned by another service (R2 custom domains) alone instead of unbinding them")
	return cmd
}

// runDNSDeleteAll is `dns delete <domain> --all`: empty the zone, or
// remove every record of the given types from it.
func runDNSDeleteAll(ctx context.Context, rt *app.Runtime, domain string, rawTypes []string, keepBound bool) error {
	types, err := platform.ParseRecordTypes(rawTypes)
	if err != nil {
		return usageErr("%v", strings.TrimPrefix(err.Error(), platform.ErrInvalidInput.Error()+": "))
	}
	dryRun := rt.DryRun()
	// Refused before anything is read: the non-interactive flow cannot
	// confirm, and this is no command to run unconfirmed.
	if !dryRun && !rt.Flags.Yes && !rt.Interactive() {
		return usageErr("dns delete --all needs --yes in the non-interactive flow (nothing was deleted)")
	}
	if rt.Flags.Offline {
		return fmt.Errorf("%w: dns delete --all reads the zone live", app.ErrOffline)
	}
	t, err := rt.ResolveDomain(ctx, domain, platform.ResZone)
	if err != nil {
		return err
	}
	dns, err := rt.OpenDNS(ctx, t)
	if err != nil {
		return err
	}
	recs, err := dns.ListRecords(ctx, t.ResourceID)
	if err != nil {
		return err
	}
	plan := platform.PlanDNSDeleteAll(platform.DNSDeleteAll{
		Platform:  t.Platform,
		Zone:      platform.Zone{ID: t.ResourceID, Name: t.Domain},
		Records:   recs,
		Types:     types,
		KeepBound: keepBound,
		DNS:       dns,
		Removed: func(ctx context.Context, id string) {
			forgetRecord(ctx, rt, t, id)
		},
	})
	rt.Infof("zone %s via %s/%s", t.Domain, t.Platform, t.Profile)
	n := plan.Deletes()
	if n == 0 {
		if noID := countDisposition(plan.Items, platform.DispNoID); noID > 0 {
			rt.Infof("nothing can be deleted: %d record(s) have no id", noID)
		} else {
			rt.Infof("no records to clean up")
		}
	} else if !dryRun && !rt.Flags.Yes {
		printDeleteAllSummary(rt, t, plan.Items, n)
		ok, err := rt.Confirm(ctx, fmt.Sprintf("delete %d records in zone %s", n, t.Domain), false)
		if err != nil {
			return err
		}
		if !ok {
			return app.NoRecordDeleted("")
		}
	}
	changes, runErr := plan.Run(ctx, dryRun)
	sum := platform.Summarize(changes)
	rep := platform.Report{Target: t.ReportTarget(), DryRun: dryRun, Changes: changes, Summary: &sum}
	if err := rt.RenderReport(rep); err != nil && runErr == nil {
		runErr = err
	}
	prefix := ""
	if dryRun {
		prefix = "dry run: would have "
	}
	if n > 0 || sum.Failed > 0 {
		rt.Infof("%sdeleted %d, kept %d, failed %d", prefix, sum.Deleted, sum.Skipped, sum.Failed)
	}
	var partial *platform.PartialError
	if runErr != nil && !errors.As(runErr, &partial) {
		return runErr
	}
	if dryRun {
		return nil
	}
	return platform.FailedChanges(changes)
}

// countDisposition counts the items of the given disposition.
func countDisposition(items []platform.DeleteAllItem, d platform.Disposition) int {
	n := 0
	for _, it := range items {
		if it.Disposition == d {
			n++
		}
	}
	return n
}

// printDeleteAllSummary shows on stderr what dns delete --all is about to
// do, before its confirmation.
func printDeleteAllSummary(rt *app.Runtime, t *app.Target, items []platform.DeleteAllItem, n int) {
	pick := func(d ...platform.Disposition) []platform.DeleteAllItem {
		var out []platform.DeleteAllItem
		for _, it := range items {
			for _, x := range d {
				if it.Disposition == x {
					out = append(out, it)
				}
			}
		}
		return out
	}
	deleting := pick(platform.DispNormal, platform.DispBound)
	rt.Infof("about to delete %d DNS records of %s (%s/%s); this cannot be undone:", n, t.Domain, t.Platform, t.Profile)
	rt.Infof("  %s", platform.TypeCounts(deleting, func(typ string) string {
		bound := 0
		for _, it := range deleting {
			if it.Disposition == platform.DispBound && strings.EqualFold(it.Record.Type, typ) {
				bound++
			}
		}
		if bound == 0 {
			return ""
		}
		return fmt.Sprintf("%d of them unbound from their owner first, which removes them", bound)
	}))
	if sys := pick(platform.DispSystem); len(sys) > 0 {
		rt.Infof("kept (system records): %s", platform.TypeCounts(sys, nil))
	}
	if kept := pick(platform.DispKept); len(kept) > 0 {
		rt.Infof("kept (--keep-bound): %s", platform.TypeCounts(kept, nil))
	}
	if noID := pick(platform.DispNoID); len(noID) > 0 {
		rt.Infof("cannot be deleted (no id): %s", platform.TypeCounts(noID, nil))
	}
}

// newDNSEnsureCmd is `dns ensure`: converge a set of records of one zone.
func newDNSEnsureCmd(rt *app.Runtime) *cobra.Command {
	var records []string
	var file, ttl string
	var priority int
	var prune, proxied bool
	cmd := &cobra.Command{
		Use:   "ensure <domain> [<name> <type> <value>...]",
		Short: "Converge a set of DNS records: create the missing, update the differing",
		Long: `Bring a set of records of the zone serving <domain> to the desired state in one
run. Each record is matched on name + type: one that is already as desired is
reported unchanged and not written, one that differs is updated in place
(keeping its id), and a missing one is created. Records that are not named are
never touched, so the command can be repeated safely.

One record, or the set of one name and type, is written as arguments:

  polyctl dns ensure example.com www A 203.0.113.10
  polyctl dns ensure example.com @ MX "10 mx1.example.com" "20 mx2.example.com"

` + recordHelp + `

Several values are the set of that name and type. --ttl (seconds, or auto),
--priority and --proxied apply to the positional record only.

More records come from --record (repeatable) and/or --file, which combine
with the positional record:

  --record name:type:value[:ttl[:proxied]]

name is read as <name> is. The TTL (seconds, or auto) and proxied
(true or false, Cloudflare only) are optional; left out, an existing record
keeps what it has and a new one gets the platform default. auto is the
automatic TTL on Cloudflare and the same as leaving the TTL out elsewhere. A value that itself
ends in ":<number>", or an IPv6 address that could also be read with a TTL,
cannot be written inline: use a records file. An MX record's priority goes in
front of its value ("10 mail.example.com"), an SRV value is
"<priority> <weight> <port> <target>".

  records:
    - name: www
      type: A
      value: 203.0.113.10
      ttl: 300          # optional
      proxied: true     # optional
    - name: "@"
      type: MX
      value: mail.example.com
      priority: 10      # MX only

Several records with the same name and type form a set: each value that is
missing is created and nothing is updated (several MX or TXT values). One
record against several existing ones of that name and type is fine when one of
them is as desired, or has the desired value (its TTL or proxied setting is
then updated); otherwise the command stops before writing anything (exit code
5), unless --prune-duplicates is given: it keeps one record (updating the
oldest when none has the desired value) and deletes the others, after the
creates and updates. proxied=true on a platform other than Cloudflare reports the record as
skipped. The zone is always read live: --offline is refused (exit code 6).

` + app.RecordAskHelp("zone") + `

Without a record, --record and --file one record is asked for in that way,
and values are asked until one is left empty. With --record or --file and no
positional record nothing is asked.`,
		Example: `  polyctl dns ensure example.com @ A 192.0.2.10
  polyctl dns ensure example.com www CNAME target.example.net --ttl 300
  polyctl dns ensure example.com @ TXT "v=spf1 -all" "google-site-verification=abc"
  polyctl dns ensure example.com -r www:A:203.0.113.10:300 -r '@:MX:10 mail.example.com'
  polyctl dns ensure example.com -f records.yaml --dry-run`,
		Args:              app.ProxiedRecordArgs(app.RecordArgsOrInteractive(rt, 1, -1), -1),
		ValidArgsFunction: app.CompleteRecordArgs(completeDomains(rt), ""),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			var specs []platform.RecordSpec
			// The positional record; --record and --file are the other
			// ways to name records. With none of the three the interactive
			// flow asks for one record, and so it does for the rest of a
			// positional record that stops early.
			in, err := rt.RecordInput(cmd, args, app.RecordForm{MinValues: 1, MaxValues: -1, Optional: true})
			if err != nil {
				return err
			}
			ask := in.Given() || (len(records) == 0 && file == "")
			if !ask {
				for _, f := range []string{"ttl", "priority", "proxied"} {
					if cmd.Flags().Changed(f) {
						return usageErr("--%s applies to a positional record: %s", f, in.Usage())
					}
				}
			} else if !in.Given() && !rt.Interactive() {
				return usageErr("a record, --record or --file is required: %s", in.Usage())
			}
			args, err = domainArgs(cmd, rt, args[:min(len(args), 1)], app.DomainPick{Title: "Zone", Kinds: zoneKinds, Required: true})
			if err != nil {
				return err
			}
			for _, r := range records {
				s, err := platform.ParseRecordSpec(r)
				if err != nil {
					return err
				}
				specs = append(specs, s)
			}
			if file != "" {
				f, err := os.Open(file)
				if err != nil {
					return usageErr("records file: %v", err)
				}
				fs, err := platform.ParseRecordFile(f)
				_ = f.Close()
				if err != nil {
					return err
				}
				specs = append(specs, fs...)
			}
			if rt.Flags.Offline {
				return fmt.Errorf("%w: dns ensure reads the zone live", app.ErrOffline)
			}
			t, err := rt.ResolveDomain(ctx, args[0], platform.ResZone)
			if err != nil {
				return err
			}
			// The zone is read once: for the questions, when there are
			// any, and for the plan.
			var dns platform.DNSService
			var existing []platform.Record
			read := false
			zoneRecords := func() ([]platform.Record, error) {
				if read {
					return existing, nil
				}
				if dns, err = rt.OpenDNS(ctx, t); err != nil {
					return nil, err
				}
				if existing, err = dns.ListRecords(ctx, t.ResourceID); err != nil {
					return nil, err
				}
				read = true
				return existing, nil
			}
			if ask {
				if err := rt.CompleteRecord(in, app.RecordPrompt{Platform: t.Platform, Zone: t.Domain, Replaces: true, Existing: zoneRecords}); err != nil {
					return err
				}
				pos, err := positionalSpecs(cmd, in, ttl, priority, proxied)
				if err != nil {
					return err
				}
				specs = append(pos, specs...)
			}
			desired, err := platform.NormalizeRecordSpecs(t.Domain, t.Platform, specs, platform.WritableRecordTypes(t.Platform), rt.Infof)
			if err != nil {
				return err
			}
			if len(desired) == 0 {
				rt.Infof("note: the records file lists no records")
			}
			if _, err := zoneRecords(); err != nil {
				return err
			}
			plan, err := platform.PlanDNSEnsure(platform.DNSEnsure{
				Platform:        t.Platform,
				ZoneID:          t.ResourceID,
				Existing:        existing,
				Desired:         desired,
				PruneDuplicates: prune,
				DNS:             dns,
				Written: func(ctx context.Context, oldID string, r platform.Record) {
					rememberRecord(ctx, rt, t, oldID, r)
				},
				Removed: func(ctx context.Context, id string) {
					forgetRecord(ctx, rt, t, id)
				},
			})
			if err != nil {
				return err
			}
			rt.Infof("zone %s via %s/%s", t.Domain, t.Platform, t.Profile)
			return rt.Ensure(ctx, "dns.ensure", t.ReportTarget(), plan)
		},
	}
	cmd.Flags().StringArrayVarP(&records, "record", "r", nil, "desired record name:type:value[:ttl[:proxied]] (repeatable)")
	cmd.Flags().StringVarP(&file, "file", "f", "", "YAML file of desired records (see the help text); combines with --record")
	cmd.Flags().BoolVar(&prune, "prune-duplicates", false, "when a name + type has several records, keep one and delete the others")
	cmd.Flags().StringVar(&ttl, "ttl", "", "TTL of the positional record in seconds, or auto (default: keep the existing one; the platform default for a new record)")
	cmd.Flags().IntVar(&priority, "priority", 0, "priority of the positional record (MX)")
	cmd.Flags().BoolVar(&proxied, "proxied", false, "Cloudflare proxy status of the positional record: --proxied or --proxied=false (default: keep the current value; the platform default for a new record)")
	return cmd
}

// positionalSpecs turns the positional record of dns ensure into record
// specs, one per value, each with the --ttl, --priority and --proxied given.
func positionalSpecs(cmd *cobra.Command, rec *app.RecordInput, ttl string, priority int, proxied bool) ([]platform.RecordSpec, error) {
	base := platform.RecordSpec{Name: rec.Name, Type: rec.Type}
	if cmd.Flags().Changed("ttl") {
		switch t := strings.ToLower(strings.TrimSpace(ttl)); t {
		case "auto":
			base.TTLAuto = true
		default:
			n, err := strconv.Atoi(t)
			if err != nil || n < 0 {
				return nil, usageErr("--ttl %q is not a number of seconds or auto", ttl)
			}
			base.TTL = &n
		}
	}
	if cmd.Flags().Changed("priority") {
		p := priority
		base.Priority = &p
	}
	if cmd.Flags().Changed("proxied") {
		b := proxied
		base.Proxied = &b
	}
	specs := make([]platform.RecordSpec, 0, len(rec.Values))
	for _, v := range rec.Values {
		s := base
		s.Value = v
		specs = append(specs, s)
	}
	return specs, nil
}

// rememberRecord upserts a written record into the inventory. Platforms
// whose record ids encode the value (Route 53, Cloud DNS, GoDaddy) hand
// back a new id after an update, so the row under the old id goes.
func rememberRecord(ctx context.Context, rt *app.Runtime, t *app.Target, oldID string, r platform.Record) {
	db, err := rt.DB()
	if err != nil {
		return
	}
	cfg, err := rt.Config()
	if err != nil {
		return
	}
	set := inventory.Set{Platform: t.Platform, Profile: t.Profile, Type: platform.ResDNSRecord}
	if oldID != "" && r.ID != oldID {
		if err := db.Delete(ctx, set, platform.ResDNSRecord, oldID); err != nil {
			rt.Verbosef("inventory: %v", err)
		}
	}
	if err := db.Upsert(ctx, set, app.RecordResources(t.ResourceID, t.Domain, []platform.Record{r})[0], cfg.TTLFor(platform.ResDNSRecord)); err != nil {
		rt.Verbosef("inventory: %v", err)
	}
}

// forgetRecord removes a deleted record from the inventory.
func forgetRecord(ctx context.Context, rt *app.Runtime, t *app.Target, id string) {
	if db, err := rt.DB(); err == nil {
		if err := db.Delete(ctx, inventory.Set{Platform: t.Platform, Profile: t.Profile}, platform.ResDNSRecord, id); err != nil {
			rt.Verbosef("inventory: %v", err)
		}
	}
}
