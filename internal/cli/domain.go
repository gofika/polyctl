package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

func newDomainCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "domain",
		Short: "Platform-neutral domain management (auto-routed by domain)",
	}
	addRouteFlags(rt, cmd)
	ns := &cobra.Command{Use: "ns", Short: "Manage nameservers at the registrar"}
	ns.AddCommand(newDomainNSSetCmd(rt), newDomainNSGetCmd(rt))
	cmd.AddCommand(newDomainInfoCmd(rt), ns, newDomainWhichCmd(rt), newDomainIndexCmd(rt), newDomainListCmd(rt))
	return cmd
}

type domainInfo struct {
	Domain    string           `json:"domain" yaml:"domain"`
	Registrar *app.Target      `json:"registrar,omitempty" yaml:"registrar,omitempty"`
	Details   *platform.Domain `json:"details,omitempty" yaml:"details,omitempty"`
	Zone      *app.Target      `json:"zone,omitempty" yaml:"zone,omitempty"`
	ZoneInfo  *platform.Zone   `json:"zone_info,omitempty" yaml:"zone_info,omitempty"`
	Cached    bool             `json:"cached" yaml:"cached"`
}

// loadDomain returns the registrar view of a domain from cache or remote.
func loadDomain(cmd *cobra.Command, rt *app.Runtime, t *app.Target) (*platform.Domain, bool, error) {
	set := inventory.Set{Platform: t.Platform, Profile: t.Profile, Type: platform.ResDomain}
	need, err := rt.NeedsRefresh(cmd.Context(), set)
	if err != nil {
		return nil, false, err
	}
	if need {
		reg, err := rt.OpenRegistrar(cmd.Context(), t)
		if err != nil {
			return nil, false, err
		}
		d, err := reg.GetDomain(cmd.Context(), t.Domain)
		if err != nil {
			return nil, false, err
		}
		if db, err := rt.DB(); err == nil {
			cfg, _ := rt.Config()
			_ = db.Upsert(cmd.Context(), set, app.DomainResources([]platform.Domain{*d})[0], cfg.TTLFor(platform.ResDomain))
		}
		return d, false, nil
	}
	db, err := rt.DB()
	if err != nil {
		return nil, false, err
	}
	r, err := db.Get(cmd.Context(), set, platform.ResDomain, t.ResourceID)
	if err != nil {
		return nil, false, err
	}
	var d platform.Domain
	if err := r.Decode(&d); err != nil {
		return nil, false, err
	}
	return &d, true, nil
}

func newDomainInfoCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:               "info <domain>",
		Short:             "Show registrar details and the DNS zone of a domain",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeDomains(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			info := domainInfo{Domain: platform.NormalizeDomain(args[0]), Cached: true}
			if rt.Flags.Profile != "" || rt.Flags.Platform != "" {
				// A selection that names no account is reported as such
				// and not as a domain missing from the index.
				names, err := rt.DomainAccounts()
				if err != nil {
					return err
				}
				if len(names) == 0 {
					return fmt.Errorf("%w: no domain-capable account matches --profile / --platform", platform.ErrNotFound)
				}
			}
			var errs []error
			if t, err := rt.ResolveDomain(cmd.Context(), args[0], platform.ResDomain); err == nil {
				info.Registrar = t
				d, cached, err := loadDomain(cmd, rt, t)
				if err != nil {
					errs = append(errs, fmt.Errorf("registrar: %w", err))
				} else {
					info.Details = d
					info.Cached = info.Cached && cached
				}
			} else {
				errs = append(errs, fmt.Errorf("registrar: %w", err))
			}
			if t, err := rt.ResolveDomain(cmd.Context(), args[0], platform.ResZone); err == nil {
				info.Zone = t
				if db, err := rt.DB(); err == nil {
					if r, err := db.Get(cmd.Context(), inventory.Set{Platform: t.Platform, Profile: t.Profile}, platform.ResZone, t.ResourceID); err == nil {
						var z platform.Zone
						if r.Decode(&z) == nil {
							info.ZoneInfo = &z
						}
					}
				}
			} else {
				errs = append(errs, fmt.Errorf("zone: %w", err))
			}
			if info.Registrar == nil && info.Zone == nil {
				// Keep the original error chain so ambiguity, missing
				// authorization and offline misses keep their exit codes;
				// only a plain double miss collapses into one message.
				allUnknown := true
				for _, e := range errs {
					if !errors.Is(e, app.ErrDomainUnknown) {
						allUnknown = false
					}
				}
				if allUnknown {
					for _, e := range errs {
						rt.Verbosef("%v", e)
					}
					return fmt.Errorf("%w: %q is neither a registered domain nor a DNS zone in any profile; run `polyctl domain index` when online", app.ErrDomainUnknown, info.Domain)
				}
				return errors.Join(errs...)
			}
			for _, e := range errs {
				rt.Infof("note: %s", e.Error())
			}
			return rt.Render(info, func() output.Grid {
				pairs := []string{"DOMAIN", info.Domain}
				if info.Registrar != nil {
					pairs = append(pairs, "REGISTRAR", fmt.Sprintf("%s/%s", info.Registrar.Platform, info.Registrar.Profile))
				}
				if d := info.Details; d != nil {
					pairs = append(pairs,
						"STATUS", d.Status,
						"EXPIRES", d.ExpiresAt,
						"AUTO-RENEW", output.Str(d.AutoRenew),
						"LOCKED", output.Str(d.Locked),
						"PRIVACY", output.Str(d.Privacy),
						"NAMESERVERS", strings.Join(d.Nameservers, " "))
				}
				if info.Zone != nil {
					pairs = append(pairs, "DNS ZONE", fmt.Sprintf("%s via %s/%s (id %s)", info.Zone.Domain, info.Zone.Platform, info.Zone.Profile, info.Zone.ResourceID))
					if z := info.ZoneInfo; z != nil && len(z.Nameservers) > 0 {
						pairs = append(pairs, "ZONE NS", strings.Join(z.Nameservers, " "))
					}
				}
				if info.Cached {
					pairs = append(pairs, "SOURCE", "local inventory (use --refresh to re-fetch)")
				}
				return output.KV(pairs...)
			})
		},
	}
}

func newDomainNSGetCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:               "get <domain>",
		Short:             "Show the nameservers set at the registrar",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeDomains(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := rt.ResolveDomain(cmd.Context(), args[0], platform.ResDomain)
			if err != nil {
				return err
			}
			d, cached, err := loadDomain(cmd, rt, t)
			if err != nil {
				return err
			}
			rt.Infof("%s via %s/%s%s", d.Name, t.Platform, t.Profile, cacheNote(cached))
			return rt.Render(map[string]any{"domain": d.Name, "nameservers": d.Nameservers, "target": t}, func() output.Grid {
				g := output.Grid{Headers: []string{"NAMESERVER"}, Empty: "no nameservers"}
				for _, ns := range d.Nameservers {
					g.Rows = append(g.Rows, []string{ns})
				}
				return g
			})
		},
	}
}

func newDomainNSSetCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:               "set <domain> <nameserver>...",
		Short:             "Set the nameservers at the registrar",
		Long:              "Replace the nameservers of <domain> at its registrar with the ones given.\n" + app.NameserverHelp,
		Example:           "  polyctl domain ns set example.com ns1.example.net ns2.example.net",
		Args:              app.NameserverArgs,
		ValidArgsFunction: completeDomains(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			ns, err := app.Nameservers(args[1:])
			if err != nil {
				return err
			}
			t, err := rt.ResolveDomain(cmd.Context(), args[0], platform.ResDomain)
			if err != nil {
				return err
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			reg, err := rt.OpenRegistrar(cmd.Context(), t)
			if err != nil {
				return err
			}
			if err := reg.SetNameservers(cmd.Context(), t.Domain, ns); err != nil {
				return err
			}
			d, err := reg.GetDomain(cmd.Context(), t.Domain)
			if err == nil {
				if db, err := rt.DB(); err == nil {
					cfg, _ := rt.Config()
					_ = db.Upsert(cmd.Context(), inventory.Set{Platform: t.Platform, Profile: t.Profile, Type: platform.ResDomain}, app.DomainResources([]platform.Domain{*d})[0], cfg.TTLFor(platform.ResDomain))
				}
			} else {
				d = &platform.Domain{Name: t.Domain, Nameservers: ns}
			}
			rt.Infof("nameservers of %s updated via %s/%s", t.Domain, t.Platform, t.Profile)
			return rt.Render(map[string]any{"domain": d.Name, "nameservers": d.Nameservers, "target": t}, func() output.Grid {
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

func newDomainWhichCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "which <domain>",
		Short: "Show which accounts own a domain (registrar and DNS zone)",
		Long: "Show every account that owns a domain, as a registrar or as a DNS zone.\n" +
			"--profile and --platform narrow the list to the owners in that profile and\n" +
			"on that platform, as on domain list; without them every owner is shown.",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeDomains(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validates --profile and --platform, so that a mistyped one
			// is an error and not an empty list.
			if _, err := rt.Accounts(); err != nil {
				return err
			}
			only, err := rt.RoutePlatform()
			if err != nil {
				return err
			}
			filtered := rt.Flags.Profile != "" || only != ""
			db, err := rt.DB()
			if err != nil {
				return err
			}
			cands := platform.Candidates(args[0])
			if len(cands) == 0 {
				return usageErr("invalid domain %q", args[0])
			}
			lookup := func() ([]inventory.IndexEntry, error) {
				entries, err := db.LookupDomain(cmd.Context(), cands, "")
				if err != nil || !filtered {
					return entries, err
				}
				var f []inventory.IndexEntry
				for _, e := range entries {
					if (rt.Flags.Profile == "" || e.Profile == rt.Flags.Profile) && (only == "" || e.Platform == only) {
						f = append(f, e)
					}
				}
				return f, nil
			}
			entries, err := lookup()
			if err != nil {
				return err
			}
			if len(entries) == 0 && !rt.Flags.Offline {
				// Trigger auto-indexing through the resolver, then re-read.
				_, _ = rt.ResolveDomain(cmd.Context(), args[0], platform.ResZone)
				_, _ = rt.ResolveDomain(cmd.Context(), args[0], platform.ResDomain)
				if entries, err = lookup(); err != nil {
					return err
				}
			}
			if len(entries) == 0 {
				if filtered {
					return fmt.Errorf("%w: %q has no owner matching --profile / --platform", app.ErrDomainUnknown, args[0])
				}
				return fmt.Errorf("%w: %q", app.ErrDomainUnknown, args[0])
			}
			return rt.Render(entries, func() output.Grid {
				g := output.Grid{Headers: []string{"DOMAIN", "KIND", "PLATFORM", "PROFILE", "RESOURCE ID", "INDEXED"}}
				for _, e := range entries {
					g.Rows = append(g.Rows, []string{e.Domain, string(e.Type), string(e.Platform), e.Profile, e.ResourceID, e.UpdatedAt.Format("2006-01-02 15:04")})
				}
				return g
			})
		},
	}
}

func newDomainIndexCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "index",
		Short: "Scan every domain-capable account and rebuild the domain index",
		Long: "Fetch zones and registered domains from every domain-capable account (or\n" +
			"those selected with --profile / --platform) and rebuild the domain index.\n" +
			"When there is no such account nothing is indexed, which is not an error.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			names, err := rt.DomainAccounts()
			if err != nil {
				return err
			}
			if len(names) == 0 {
				// Nothing to index is not a failure; the empty result is
				// still printed, so `-o json` gives a list to parse.
				if err := renderSyncReports(rt, []app.SyncReport{}, nil); err != nil {
					return err
				}
				if rt.Flags.Profile != "" || rt.Flags.Platform != "" {
					return nothingToDo("no domain-capable account matches --profile / --platform")
				}
				return nothingToDo("no domain-capable accounts configured (run `polyctl auth login <platform>`)")
			}
			var reports []app.SyncReport
			var firstErr error
			for _, n := range names {
				reps, err := rt.SyncAccount(cmd.Context(), n, []platform.ResourceType{platform.ResZone, platform.ResDomain})
				reports = append(reports, reps...)
				if err != nil {
					rt.Infof("warning: %s: %v", n.Label(), err)
					if firstErr == nil {
						firstErr = err
					}
				}
			}
			return renderSyncReports(rt, reports, firstErr)
		},
	}
}

func newDomainListCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List every indexed domain and zone across all accounts",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			only, err := rt.RoutePlatform()
			if err != nil {
				return err
			}
			db, err := rt.DB()
			if err != nil {
				return err
			}
			filtered := rt.Flags.Profile != "" || only != ""
			if filtered || rt.Flags.Refresh {
				// Validates --profile; a selection that names no account
				// simply lists nothing.
				names, err := rt.DomainAccounts()
				if err != nil {
					return err
				}
				if rt.Flags.Refresh {
					for _, n := range names {
						if _, err := rt.SyncAccount(cmd.Context(), n, []platform.ResourceType{platform.ResZone, platform.ResDomain}); err != nil {
							rt.Infof("warning: %s: %v", n.Label(), err)
						}
					}
				}
			}
			entries, err := db.IndexEntries(cmd.Context())
			if err != nil {
				return err
			}
			empty := "index is empty; run `polyctl domain index`"
			if filtered {
				empty = "no indexed domain or zone matches --profile / --platform; run `polyctl domain index`"
				var f []inventory.IndexEntry
				for _, e := range entries {
					if (rt.Flags.Profile == "" || e.Profile == rt.Flags.Profile) && (only == "" || e.Platform == only) {
						f = append(f, e)
					}
				}
				entries = f
			}
			return rt.Render(entries, func() output.Grid {
				g := output.Grid{Headers: []string{"DOMAIN", "KIND", "PLATFORM", "PROFILE", "RESOURCE ID"}, Empty: empty}
				for _, e := range entries {
					g.Rows = append(g.Rows, []string{e.Domain, string(e.Type), string(e.Platform), e.Profile, e.ResourceID})
				}
				return g
			})
		},
	}
}
