package cli

import (
	"errors"
	"fmt"
	"strings"
	"time"

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
	ns := &cobra.Command{Use: "ns", Short: "Manage nameservers at the registrar and check the delegation"}
	ns.AddCommand(newDomainNSSetCmd(rt), newDomainNSGetCmd(rt), newDomainNSCheckCmd(rt))
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
		Args:              app.ArgsOrInteractive(rt, 1, nil),
		ValidArgsFunction: completeDomains(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := domainArgs(cmd, rt, args, app.DomainPick{})
			if err != nil {
				return err
			}
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
		Args:              app.ArgsOrInteractive(rt, 1, nil),
		ValidArgsFunction: completeDomains(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := domainArgs(cmd, rt, args, app.DomainPick{Title: "Registered domain", Kinds: domainKinds})
			if err != nil {
				return err
			}
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
		Args:              app.NameserverArgsOrInteractive(rt),
		ValidArgsFunction: completeDomains(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := domainArgs(cmd, rt, args, app.DomainPick{Title: "Registered domain", Kinds: domainKinds})
			if err != nil {
				return err
			}
			var ns []string
			if len(args) < 2 {
				ns, err = rt.PickNameservers(cmd.Context(), args[0])
			} else {
				ns, err = app.Nameservers(args[1:])
			}
			if err != nil {
				return err
			}
			t, err := rt.ResolveDomain(cmd.Context(), args[0], platform.ResDomain)
			if err != nil {
				return err
			}
			if done, err := rt.WouldWrite(t.ReportTarget(), app.NameserverChange(t.Domain, ns)); done || err != nil {
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
		Args:              app.ArgsOrInteractive(rt, 1, nil),
		ValidArgsFunction: completeDomains(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validates --profile and --platform, so that a mistyped one
			// is an error and not an empty list.
			if _, err := rt.Accounts(); err != nil {
				return err
			}
			args, err := domainArgs(cmd, rt, args, app.DomainPick{})
			if err != nil {
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
				if err == nil {
					entries, err = rt.ConfiguredEntries(entries)
				}
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
			var indexErrs []error
			if len(entries) == 0 && !rt.Flags.Offline {
				// Index as routing would (never built, or --refresh), then
				// re-read. Resolving an owner is not needed, so nothing is
				// asked even when several accounts hold the domain.
				for _, kind := range []platform.ResourceType{platform.ResZone, platform.ResDomain} {
					if err := rt.IndexForLookup(cmd.Context(), kind); err != nil {
						if cerr := cmd.Context().Err(); cerr != nil {
							return cerr
						}
						indexErrs = append(indexErrs, err)
					}
				}
				if entries, err = lookup(); err != nil {
					return err
				}
			}
			if len(entries) == 0 && len(indexErrs) > 0 {
				// No account of a kind could be asked: not "unknown".
				return errors.Join(indexErrs...)
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
			// refreshErr is set when --refresh could not sync an account:
			// the list is still printed (the index as it stands), and the
			// exit code says the refresh failed.
			var refreshErrs []error
			var refreshErr error
			if filtered || rt.Flags.Refresh {
				// Validates --profile; a selection that names no account
				// simply lists nothing.
				names, err := rt.DomainAccounts()
				if err != nil {
					return err
				}
				if rt.Flags.Refresh {
					for _, n := range names {
						if err := app.SyncError(rt.SyncAccount(cmd.Context(), n, []platform.ResourceType{platform.ResZone, platform.ResDomain})); err != nil {
							rt.Infof("warning: %s: %v", n.Label(), err)
							refreshErrs = append(refreshErrs, fmt.Errorf("%s: %w", n.Label(), err))
						}
					}
					if len(refreshErrs) > 0 {
						// As domain index: any account that failed fails
						// the run.
						refreshErr = app.IndexFailure(cmd.Context(), "domains and zones", refreshErrs, len(names))
					}
				}
			}
			entries, err := db.IndexEntries(cmd.Context())
			if err != nil {
				return err
			}
			if entries, err = rt.ConfiguredEntries(entries); err != nil {
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
			if err := rt.Render(entries, func() output.Grid {
				g := output.Grid{Headers: []string{"DOMAIN", "KIND", "PLATFORM", "PROFILE", "RESOURCE ID"}, Empty: empty}
				for _, e := range entries {
					g.Rows = append(g.Rows, []string{e.Domain, string(e.Type), string(e.Platform), e.Profile, e.ResourceID})
				}
				return g
			}); err != nil {
				return err
			}
			return refreshErr
		},
	}
}

func newDomainNSCheckCmd(rt *app.Runtime) *cobra.Command {
	var (
		resolvers           []string
		timeout             time.Duration
		noRegistrar, noZone bool
	)
	cmd := &cobra.Command{
		Use:   "check <domain>",
		Short: "Compare the nameservers at the registrar, in the hosted zone and as resolvers see them",
		Long: "Compare three sets of nameservers of a domain: the ones set at its registrar, the\n" +
			"ones its hosted DNS zone was assigned (every zone of the domain in every\n" +
			"selected account is listed), and the ones public resolvers return now. A name\n" +
			"below a registered domain is checked as that registered domain. The status is\n" +
			"ok, partial, mismatch, no-zone, no-live or unknown; it is a report, so the exit\n" +
			"code is 0 whatever the status (read status from -o json in scripts). The\n" +
			"exception: when every requested side (registrar, zone, live lookup) failed,\n" +
			"the report is still printed and the exit code is 1, or 3 when a side failed\n" +
			"for credentials or permissions.",
		Example: "  polyctl domain ns check example.com\n" +
			"  polyctl domain ns check www.example.com -o json\n" +
			"  polyctl domain ns check example.com --resolver 223.5.5.5,114.114.114.114\n" +
			"  polyctl domain ns check example.com --no-registrar",
		Args:              app.ArgsOrInteractive(rt, 1, nil),
		ValidArgsFunction: completeDomains(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := rt.Config()
			if err != nil {
				return err
			}
			args, err = domainArgs(cmd, rt, args, app.DomainPick{})
			if err != nil {
				return err
			}
			list := cfg.NSResolvers()
			if cmd.Flags().Changed("resolver") {
				list = resolvers
			}
			var addrs []string
			for _, r := range list {
				a, err := platform.ParseResolver(r)
				if err != nil {
					return usageErr("--resolver: %v", err)
				}
				addrs = append(addrs, a)
			}
			if len(addrs) == 0 {
				return usageErr("--resolver: at least one resolver is required")
			}
			t := cfg.NSTimeout()
			if cmd.Flags().Changed("timeout") {
				if timeout <= 0 {
					return usageErr("--timeout must be positive, got %s", timeout)
				}
				t = timeout
			}
			res, err := rt.NSCheck(cmd.Context(), app.NSCheckOptions{
				Domain: args[0], Resolvers: addrs, Timeout: t,
				NoRegistrar: noRegistrar, NoZone: noZone,
			})
			if err != nil {
				return err
			}
			if err := rt.Render(res, func() output.Grid { return nsCheckGrid(res) }); err != nil {
				return err
			}
			return res.Failed
		},
	}
	cmd.Flags().StringSliceVar(&resolvers, "resolver", nil, "recursive resolvers to ask, in order: IP or IP:port, comma-separated or repeated (default 1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4, or dns.resolvers)")
	cmd.Flags().DurationVar(&timeout, "timeout", platform.DefaultNSTimeout, "timeout of one DNS query (or dns.timeout)")
	cmd.Flags().BoolVar(&noRegistrar, "no-registrar", false, "skip the registrar side")
	cmd.Flags().BoolVar(&noZone, "no-zone", false, "skip the hosted zone side")
	return cmd
}

// nsCheckGrid renders an NS check as a key-value block.
func nsCheckGrid(r *app.NSCheckResult) output.Grid {
	nsList := func(ns []string) string {
		if len(ns) == 0 {
			return "(none)"
		}
		return strings.Join(ns, ", ")
	}
	side := func(v app.NSView, notes ...string) string {
		if v.Skipped {
			return v.Reason
		}
		if !v.Available {
			s := "unavailable"
			if v.Account() != "" {
				s += " [" + v.Account() + "]"
			}
			if v.Reason != "" {
				s += ": " + v.Reason
			}
			return s
		}
		if v.Account() != "" {
			notes = append([]string{v.Account()}, notes...)
		}
		s := nsList(v.NS)
		if len(notes) > 0 {
			s += "  [" + strings.Join(notes, ", ") + "]"
		}
		return s
	}
	status := strings.ToUpper(r.Status)
	var diffs []string
	for _, d := range []struct {
		eq   *bool
		name string
	}{{r.Match.RegistrarVsZone, "registrar != zone"}, {r.Match.LiveVsZone, "live != zone"}, {r.Match.RegistrarVsLive, "registrar != live"}} {
		if d.eq != nil && !*d.eq {
			diffs = append(diffs, d.name)
		}
	}
	if len(diffs) > 0 {
		status += "  (" + strings.Join(diffs, ", ") + ")"
	}
	pairs := []string{"DOMAIN", r.Domain}
	if r.CheckedDomain != r.Domain {
		pairs = append(pairs, "CHECKED DOMAIN", r.CheckedDomain+" (registered domain of "+r.Domain+")")
	}
	pairs = append(pairs, "STATUS", status, "REGISTRAR NS", side(r.Registrar))
	switch {
	case r.Zone.Skipped:
		pairs = append(pairs, "ZONE NS", r.Zone.Reason)
	case len(r.Zones) == 0:
		pairs = append(pairs, "ZONE NS", side(r.Zone))
	default:
		for _, z := range r.Zones {
			var notes []string
			if z.Status != "" {
				notes = append(notes, "zone status="+z.Status)
			}
			if len(r.Zones) > 1 && z.LiveMatch != "" {
				notes = append(notes, "live match="+z.LiveMatch)
			}
			if z.MirrorsRegistrar {
				notes = append(notes, "mirrors the registration")
			}
			pairs = append(pairs, "ZONE NS", side(z, notes...))
		}
	}
	var liveNotes []string
	if r.Live.Resolver != "" {
		liveNotes = append(liveNotes, r.Live.Resolver)
	}
	live := side(r.Live, liveNotes...)
	if r.Live.Available && len(r.Live.NS) == 0 {
		live = "(none)  [" + strings.Join(append(liveNotes, r.Live.Result), ", ") + "]"
	}
	guess := r.ProviderGuess
	if len(r.Providers) > 0 {
		guess += " (" + strings.Join(r.Providers, ", ") + ")"
	}
	pairs = append(pairs, "LIVE NS", live, "PROVIDER GUESS", guess, "CONCLUSION", r.Message)
	return output.KV(pairs...)
}
