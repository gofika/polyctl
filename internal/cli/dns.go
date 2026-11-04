package cli

import (
	"fmt"
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
platform and profile are looked up in the local domain index; pass --profile to
override, --refresh to re-fetch from the platform, --offline to never touch the
network.`,
	}
	cmd.AddCommand(newDNSListCmd(rt), newDNSUpdateCmd(rt), newDNSDeleteCmd(rt))
	return cmd
}

// dnsResult wraps records with the routing information for json/yaml output.
type dnsResult struct {
	Target  *app.Target       `json:"target" yaml:"target"`
	Cached  bool              `json:"cached" yaml:"cached"`
	Records []platform.Record `json:"records" yaml:"records"`
}

func recordGrid(recs []platform.Record, showProxied bool) output.Grid {
	headers := []string{"NAME", "TYPE", "CONTENT", "TTL"}
	if showProxied {
		headers = append(headers, "PROXIED")
	}
	headers = append(headers, "ID")
	g := output.Grid{Headers: headers, Empty: "no records"}
	for _, r := range recs {
		content := r.Content
		if r.Priority != nil {
			content = fmt.Sprintf("%d %s", *r.Priority, r.Content)
		}
		row := []string{r.Name, r.Type, content, fmt.Sprint(r.TTL)}
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
				return recordGrid(recs, t.Platform == platform.Cloudflare)
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

func newDNSUpdateCmd(rt *app.Runtime) *cobra.Command {
	var typ, name, value string
	var ttl, priority int
	var proxied string
	var create bool
	cmd := &cobra.Command{
		Use:   "update <domain>",
		Short: "Create or update a DNS record (upsert by name + type)",
		Long: `Create or update a record in the zone serving <domain>.

If exactly one record with the same name and type exists it is updated;
if none exists it is created; if several exist the command fails unless
--add is given, which always creates an additional record.`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeDomains(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
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
			rec := platform.Record{ZoneID: t.ResourceID, Name: fqdn, Type: typ, Content: value, TTL: ttl}
			if cmd.Flags().Changed("priority") {
				p := priority
				rec.Priority = &p
			}
			switch proxied {
			case "":
			case "true", "false":
				b := proxied == "true"
				rec.Proxied = &b
			default:
				return usageErr("--proxied must be true or false")
			}
			var out *platform.Record
			switch {
			case create || len(matches) == 0:
				out, err = dns.CreateRecord(cmd.Context(), t.ResourceID, rec)
			case len(matches) == 1:
				rec.ID = matches[0].ID
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
			default:
				return fmt.Errorf("%d records named %s %s exist; use --add to create another, or `polyctl dns delete` first", len(matches), fqdn, typ)
			}
			if err != nil {
				return err
			}
			// Keep the local inventory in sync with the mutation.
			if db, err := rt.DB(); err == nil {
				cfg, _ := rt.Config()
				_ = db.Upsert(cmd.Context(), inventory.Set{Platform: t.Platform, Profile: t.Profile, Type: platform.ResDNSRecord},
					app.RecordResources(t.ResourceID, t.Domain, []platform.Record{*out})[0], cfg.TTLFor(platform.ResDNSRecord))
			}
			rt.Infof("%s %s %s -> %s via %s/%s", map[bool]string{true: "created", false: "updated"}[rec.ID == ""], out.Name, out.Type, out.Content, t.Platform, t.Profile)
			return rt.Render(dnsResult{Target: t, Records: []platform.Record{*out}}, func() output.Grid {
				return recordGrid([]platform.Record{*out}, t.Platform == platform.Cloudflare)
			})
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "record type (A, AAAA, CNAME, TXT, MX, ...)")
	cmd.Flags().StringVar(&name, "name", "", "record name relative to the zone (www, @); default: <domain> itself")
	cmd.Flags().StringVar(&value, "value", "", "record content")
	cmd.Flags().IntVar(&ttl, "ttl", 0, "TTL in seconds (0 = platform default / keep existing)")
	cmd.Flags().IntVar(&priority, "priority", 0, "priority for MX/SRV records")
	cmd.Flags().StringVar(&proxied, "proxied", "", "Cloudflare proxy status: true or false")
	cmd.Flags().BoolVar(&create, "add", false, "always create a new record instead of updating an existing one")
	return cmd
}

func newDNSDeleteCmd(rt *app.Runtime) *cobra.Command {
	var typ, name, value, id string
	cmd := &cobra.Command{
		Use:               "delete <domain>",
		Short:             "Delete DNS records matching --name/--type (and optionally --value)",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeDomains(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id == "" && typ == "" {
				return usageErr("--type (with --name) or --id is required")
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
			if len(matches) > 1 && !rt.Flags.Yes {
				_ = output.RenderGrid(rt.Stderr, recordGrid(matches, false))
				ok, err := rt.Prompt().Confirm(fmt.Sprintf("delete %d records", len(matches)), false)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("aborted")
				}
			}
			db, _ := rt.DB()
			for _, r := range matches {
				if err := dns.DeleteRecord(cmd.Context(), t.ResourceID, r.ID); err != nil {
					return fmt.Errorf("delete %s %s (%s): %w", r.Name, r.Type, r.ID, err)
				}
				if db != nil {
					_ = db.Delete(cmd.Context(), inventory.Set{Platform: t.Platform, Profile: t.Profile}, platform.ResDNSRecord, r.ID)
				}
				rt.Infof("deleted %s %s %s via %s/%s", r.Name, r.Type, r.Content, t.Platform, t.Profile)
			}
			return rt.Render(dnsResult{Target: t, Records: matches}, func() output.Grid { return output.Grid{} })
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "record type")
	cmd.Flags().StringVar(&name, "name", "", "record name relative to the zone (www, @); default: <domain> itself")
	cmd.Flags().StringVar(&value, "value", "", "only delete records with this content")
	cmd.Flags().StringVar(&id, "id", "", "delete the record with this platform id")
	return cmd
}
