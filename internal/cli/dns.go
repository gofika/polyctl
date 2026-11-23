package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
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
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeDomains(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := rt.ResolveDomain(cmd.Context(), args[0], platform.ResZone)
			if err != nil {
				return err
			}
			recs, cached, err := rt.ZoneRecords(cmd.Context(), t)
			if err != nil {
				return err
			}
			if name != "" {
				recs = app.MatchRecords(recs, platform.FQDN(name, t.Domain), typ, "")
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
		Use:   "set <domain>",
		Short: "Create or update a DNS record (matched by name + type)",
		Long: `Create or update a record in the zone serving <domain>.

If exactly one record with the same name and type exists it is updated;
if none exists it is created. If several exist the command fails: use
` + "`polyctl dns add`" + ` to create one more record of that name and type, or
` + "`polyctl dns delete`" + ` to remove the ones that should go.

--proxied (Cloudflare) is a boolean: --proxied switches the proxy on,
--proxied=false switches it off, and without it an updated record keeps its
current setting.`,
	})
}

// newDNSAddCmd is `dns add`: always create one more record.
func newDNSAddCmd(rt *app.Runtime) *cobra.Command {
	return newDNSWriteCmd(rt, true, &cobra.Command{
		Use:   "add <domain>",
		Short: "Add a DNS record, keeping the existing ones of that name + type",
		Long: `Create one more record in the zone serving <domain>. Records that already
have the same name and type are left alone, which is how round-robin A
records or several TXT or MX records are built up. To change an existing
record use ` + "`polyctl dns set`" + `.

--proxied (Cloudflare) is a boolean: --proxied switches the proxy on,
--proxied=false switches it off, and without it the platform default applies.`,
	})
}

// newDNSWriteCmd completes cmd as a record-writing command. With add it
// always creates a record; without, it updates the one record that has the
// same name and type and creates it when there is none.
func newDNSWriteCmd(rt *app.Runtime, add bool, cmd *cobra.Command) *cobra.Command {
	var typ, name, value string
	var ttl, priority int
	var proxied bool
	cmd.Args = app.ProxiedArgs(cobra.ExactArgs(1))
	cmd.ValidArgsFunction = completeDomains(rt)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if typ == "" || value == "" {
			return usageErr("--type and --value are required")
		}
		typ = strings.ToUpper(typ)
		t, err := rt.ResolveDomain(cmd.Context(), args[0], platform.ResZone)
		if err != nil {
			return err
		}
		if rt.Flags.Offline {
			return app.ErrOffline
		}
		fqdn := platform.FQDN(name, t.Domain)
		if name == "" {
			fqdn = platform.NormalizeDomain(args[0])
		}
		dns, err := rt.OpenDNS(cmd.Context(), t)
		if err != nil {
			return err
		}
		existing, err := dns.ListRecords(cmd.Context(), t.ResourceID)
		if err != nil {
			return err
		}
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
	cmd.Flags().StringVar(&typ, "type", "", "record type (A, AAAA, CNAME, TXT, MX, ...)")
	cmd.Flags().StringVar(&name, "name", "", "record name relative to the zone (www, @); default: <domain> itself")
	cmd.Flags().StringVar(&value, "value", "", "record value")
	cmd.Flags().IntVar(&ttl, "ttl", 0, ttlHelp)
	cmd.Flags().IntVar(&priority, "priority", 0, "priority for MX/SRV records")
	proxiedHelp := "Cloudflare proxy status: --proxied or --proxied=false (default: keep the current value; the platform default for a new record)"
	if add {
		proxiedHelp = "Cloudflare proxy status: --proxied or --proxied=false (default: the platform default)"
	}
	cmd.Flags().BoolVar(&proxied, "proxied", false, proxiedHelp)
	return cmd
}

func newDNSDeleteCmd(rt *app.Runtime) *cobra.Command {
	var types []string
	var name, value, id string
	var all, keepBound bool
	cmd := &cobra.Command{
		Use:   "delete <domain>",
		Short: "Delete DNS records matching --name/--type (and optionally --value), or all of them with --all",
		Long: "Delete DNS records matching --name/--type (and optionally --value), or the\n" +
			"one record with --id. A single match is deleted at once. Several matches are\n" +
			"listed on stderr and, in the interactive flow, confirmed first (default no);\n" +
			"--yes skips the question. In the non-interactive flow (no terminal,\n" +
			"--non-interactive or POLYCTL_NON_INTERACTIVE=1) nothing is asked and stdin is\n" +
			"not read: --yes is required to delete several records, and without it the\n" +
			"command is a usage error (exit code 2) and nothing is deleted.\n" +
			"\n" +
			"With --all, every record of the zone is deleted (it cannot be combined with\n" +
			"--name, --value or --id); --type then limits the deletion to the given types\n" +
			"across the whole zone (repeatable or comma-separated). The SOA and the NS\n" +
			"records of the zone apex are never deleted; delegations (NS records of names\n" +
			"below the apex) are. A record owned by another service of the platform (the\n" +
			"CNAME of an R2 custom domain on Cloudflare) is unbound there, which removes\n" +
			"it; --keep-bound leaves such records alone. The interactive flow shows a\n" +
			"summary and asks first (default no); the non-interactive flow needs --yes.\n" +
			"A record that cannot be deleted does not stop the others: it is reported as\n" +
			"failed and the command exits with code 1 at the end. The zone is read live:\n" +
			"--offline is refused (exit code 6).",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeDomains(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			if all {
				if name != "" || value != "" || id != "" {
					return usageErr("--all deletes every record of the zone; it cannot be combined with --name, --value or --id")
				}
				return runDNSDeleteAll(cmd.Context(), rt, args[0], types, keepBound)
			}
			if keepBound {
				return usageErr("--keep-bound only applies with --all")
			}
			if len(types) > 1 || (len(types) == 1 && strings.Contains(types[0], ",")) {
				return usageErr("--type takes one record type without --all")
			}
			typ := ""
			if len(types) == 1 {
				typ = types[0]
			}
			if id == "" && typ == "" {
				return usageErr("--type (with --name), --id or --all is required")
			}
			t, err := rt.ResolveDomain(cmd.Context(), args[0], platform.ResZone)
			if err != nil {
				return err
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			dns, err := rt.OpenDNS(cmd.Context(), t)
			if err != nil {
				return err
			}
			existing, err := dns.ListRecords(cmd.Context(), t.ResourceID)
			if err != nil {
				return err
			}
			var matches []platform.Record
			if id != "" {
				for _, r := range existing {
					if r.ID == id {
						matches = append(matches, r)
					}
				}
			} else {
				fqdn := platform.FQDN(name, t.Domain)
				if name == "" {
					fqdn = platform.NormalizeDomain(args[0])
				}
				matches = app.MatchRecords(existing, fqdn, typ, value)
			}
			if len(matches) == 0 {
				return fmt.Errorf("%w: no matching record in zone %s", platform.ErrNotFound, t.Domain)
			}
			// Records owned by another service of the platform (the CNAME of
			// an R2 custom domain) are deleted by unbinding them there.
			zone := platform.Zone{ID: t.ResourceID, Name: t.Domain}
			unbinder, _ := dns.(platform.RecordUnbinder)
			owners := make([]string, len(matches))
			var bound []string
			var changes []platform.Change
			for i, r := range matches {
				detail := r.Value
				if unbinder != nil {
					if owner, ok := unbinder.Match(zone, r); ok {
						owners[i] = owner
						bound = append(bound, owner)
						detail += " (unbound from " + owner + ", which removes the record)"
					}
				}
				changes = append(changes, platform.Change{Resource: app.RecordResource(r.Name, r.Type), Action: platform.Deleted, ID: r.ID, Detail: detail})
			}
			// A dry run neither asks nor needs --yes: nothing is deleted.
			if done, err := rt.WouldWrite(t.ReportTarget(), changes...); done || err != nil {
				return err
			}
			if len(matches) > 1 && !rt.Flags.Yes {
				// Shown in both flows, so the caller sees what is affected:
				// before the question, or with the refusal that asks for --yes.
				_ = output.RenderGrid(rt.Stderr, recordGrid(matches, t.Platform))
				question := fmt.Sprintf("delete %d records in zone %s", len(matches), t.Domain)
				if len(bound) > 0 {
					question += fmt.Sprintf(" (%d of them by unbinding them from %s)", len(bound), strings.Join(bound, ", "))
				}
				ok, err := rt.Confirm(cmd.Context(), question, false)
				if err != nil {
					return err
				}
				if !ok {
					return nothingToDo("no record was deleted")
				}
			}
			db, _ := rt.DB()
			// A record that cannot be unbound is left in place (it cannot be
			// deleted through the DNS API either); the other records are
			// still deleted and the command fails at the end.
			var unbound []error
			for i, r := range matches {
				if owners[i] != "" {
					rt.Infof("%s %s belongs to %s: unbinding it there removes the record", r.Name, r.Type, owners[i])
					handled, err := unbinder.Unbind(cmd.Context(), zone, r)
					if err == nil && !handled {
						err = fmt.Errorf("%s could not be unbound", owners[i])
					}
					if err != nil {
						err = fmt.Errorf("delete %s %s (%s): %w", r.Name, r.Type, r.ID, err)
						if len(matches) > 1 {
							rt.Infof("failed: %v", err)
						}
						unbound = append(unbound, err)
						continue
					}
				} else if err := dns.DeleteRecord(cmd.Context(), t.ResourceID, r.ID); err != nil {
					return fmt.Errorf("delete %s %s (%s): %w", r.Name, r.Type, r.ID, err)
				}
				if db != nil {
					_ = db.Delete(cmd.Context(), inventory.Set{Platform: t.Platform, Profile: t.Profile}, platform.ResDNSRecord, r.ID)
				}
				rt.Infof("deleted %s %s %s via %s/%s", r.Name, r.Type, r.Value, t.Platform, t.Profile)
			}
			if len(unbound) > 0 {
				if len(matches) == 1 {
					return unbound[0]
				}
				return &platform.PartialError{Failed: len(unbound), Total: len(matches), First: unbound[0]}
			}
			return rt.Render(dnsResult{Target: t, Records: matches}, func() output.Grid { return output.Grid{} })
		},
	}
	cmd.Flags().StringArrayVar(&types, "type", nil, "record type; with --all, the types to delete across the zone (repeatable or comma-separated; default: every type)")
	cmd.Flags().StringVar(&name, "name", "", "record name relative to the zone (www, @); default: <domain> itself")
	cmd.Flags().StringVar(&value, "value", "", "only delete records with this value")
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
		rt.Infof("no records to clean up")
	} else if !dryRun && !rt.Flags.Yes {
		printDeleteAllSummary(rt, t, plan.Items, n)
		ok, err := rt.Confirm(ctx, fmt.Sprintf("delete %d records in zone %s", n, t.Domain), false)
		if err != nil {
			return err
		}
		if !ok {
			return nothingToDo("cancelled, no record was deleted")
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
	var file string
	var prune bool
	cmd := &cobra.Command{
		Use:   "ensure <domain>",
		Short: "Converge a set of DNS records: create the missing, update the differing",
		Long: `Bring a set of records of the zone serving <domain> to the desired state in one
run. Each record is matched on name + type: one that is already as desired is
reported unchanged and not written, one that differs is updated in place
(keeping its id), and a missing one is created. Records that are not named are
never touched, so the command can be repeated safely.

Records come from --record (repeatable) and/or --file:

  --record name:type:value[:ttl[:proxied]]

name is relative to the zone (www, @ for the apex, a.b) or a name in the zone
(www.example.com, www.example.com.). The TTL (seconds, or auto) and proxied
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
them is as desired; otherwise the command stops before writing anything (exit
code 5), unless --prune-duplicates is given: it keeps one record (updating the
oldest when none is as desired) and deletes the others, after the creates and
updates. proxied=true on a platform other than Cloudflare reports the record as
skipped. The zone is always read live: --offline is refused (exit code 6).`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeDomains(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if len(records) == 0 && file == "" {
				return usageErr("at least one --record or --file is required")
			}
			var specs []platform.RecordSpec
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
			desired, err := platform.NormalizeRecordSpecs(t.Domain, t.Platform, specs, platform.WritableRecordTypes(t.Platform), rt.Infof)
			if err != nil {
				return err
			}
			if len(desired) == 0 {
				rt.Infof("note: the records file lists no records")
			}
			dns, err := rt.OpenDNS(ctx, t)
			if err != nil {
				return err
			}
			existing, err := dns.ListRecords(ctx, t.ResourceID)
			if err != nil {
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
	return cmd
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
