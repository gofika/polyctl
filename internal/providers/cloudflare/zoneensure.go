package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// presetOptimized is the one preset of `zone ensure --preset`.
const presetOptimized = "optimized"

// presetItem is one setting of a preset: the value it converges to, and
// whether polyctl writes it on Enterprise zones only.
type presetItem struct {
	id         string
	want       string
	enterprise bool
}

// optimizedPreset is `--preset optimized`, in the order it is applied: the
// HTTPS settings come before the SSL mode, which is switched last. The
// Enterprise-only items are polyctl's policy, not a limit of the API: the
// API accepts ipv6=off and Argo on other plans too, and Argo is billed
// there.
func optimizedPreset(ssl string) []presetItem {
	return []presetItem{
		{id: "0rtt", want: "on"},
		{id: "early_hints", want: "on"},
		{id: "rum", want: "on"},
		{id: "response_buffering", want: "on", enterprise: true},
		{id: "ipv6", want: "off", enterprise: true},
		{id: settingArgo, want: "on", enterprise: true},
		{id: "always_use_https", want: "on"},
		{id: "automatic_https_rewrites", want: "on"},
		{id: "ssl", want: ssl},
	}
}

// zoneEnsure is one run of zone create / ensure.
type zoneEnsure struct {
	rt      *app.Runtime
	c       *Client
	profile string
	// account is where a new zone goes: the account of --account, else the
	// default account of the login. An existing zone found in another
	// selected account moves it there.
	account string
	// only: the account was named for this call; the zone is looked for in
	// it alone, not in every selected account.
	only   bool
	domain string
	create bool // zone create: an existing zone is an error
	// foundation: try to switch Foundation DNS on for a new zone (and, when
	// foundationSet, converge an existing zone to it).
	foundation    bool
	foundationSet bool
	items         []presetItem

	z       *apiZone
	created bool // the zone was created by this run
	nsMoved bool // its nameservers changed (Foundation DNS switched on)
	wrote   bool
}

func (e *zoneEnsure) resource(sub string) string {
	if sub == "" {
		return "zone/" + e.domain
	}
	return "zone/" + e.domain + "/" + sub
}

func (e *zoneEnsure) report(changes []platform.Change) zoneReport {
	rep := zoneReport{
		Target:  zoneReportTarget{Platform: platform.Cloudflare, Profile: e.profile, AccountID: e.account},
		DryRun:  e.rt.DryRun(),
		Changes: changes,
	}
	if e.z != nil {
		rep.Zone = viewZone(e.z)
	} else {
		rep.Zone = &zoneView{ID: platform.Pending, Name: e.domain}
	}
	return rep
}

// find looks for the zone: in the named account alone, else in every
// selected account of the login, since a domain may have a zone in more
// than one account and a second one must not be made next to the first.
func (e *zoneEnsure) find(ctx context.Context) ([]apiZone, error) {
	if e.only {
		return e.c.api.findZonesNamed(ctx, e.domain, e.account)
	}
	return e.c.api.zonesNamed(ctx, e.domain)
}

// several reports whether the run looked in more than one account.
func (e *zoneEnsure) several() bool { return !e.only && len(e.c.api.scopeIDs()) > 1 }

// run observes the zone, then creates it when it is missing (with
// Foundation DNS) and converges the settings, printing the report.
func (e *zoneEnsure) run(ctx context.Context, event string) error {
	zs, err := e.find(ctx)
	if err != nil {
		return err
	}
	switch {
	case len(zs) > 1 && e.create:
		held := make([]string, 0, len(zs))
		for _, z := range zs {
			held = append(held, fmt.Sprintf("%s in account %s", z.ID, accountLabel(z.Account.ID, z.Account.Name)))
		}
		return fmt.Errorf("zone %s already exists in %d accounts of profile %s (%s); use 'polyctl cloudflare zone ensure' with --account", e.domain, len(zs), e.profile, strings.Join(held, ", "))
	case len(zs) > 1:
		z, err := pickAmbiguousZone(e.rt, e.profile, e.domain, zs)
		if err != nil {
			return err
		}
		zs = []apiZone{*z}
	}
	if len(zs) > 0 {
		e.z = &zs[0]
		if acc := e.z.Account.ID; acc != "" {
			// The zone is reused where it is.
			e.account = acc
		}
		dropZoneNamed(ctx, e.rt, e.profile, e.domain, e.account, e.z.ID)
		storeZone(ctx, e.rt, e.profile, *e.z)
		if e.create {
			if e.several() {
				return fmt.Errorf("zone %s already exists in account %s of profile %s (id=%s); use 'polyctl cloudflare zone ensure'", e.domain, e.account, e.profile, e.z.ID)
			}
			return fmt.Errorf("zone %s already exists in profile %s (id=%s); use 'polyctl cloudflare zone ensure'", e.domain, e.profile, e.z.ID)
		}
	} else {
		// The inventory may remember a zone of that name that is gone,
		// in the accounts that were looked in.
		account := ""
		if e.only {
			account = e.account
		}
		dropZoneNamed(ctx, e.rt, e.profile, e.domain, account, "")
	}

	var plan platform.Plan
	plan.Add(e.zoneSteps()...)
	changes, err := plan.Run(ctx, e.rt.DryRun())
	if err == nil && len(e.items) > 0 {
		var more []platform.Change
		more, err = e.settings(ctx)
		changes = append(changes, more...)
	}
	if e.wrote && !e.rt.DryRun() && e.z != nil {
		// Refresh the zone after the writes: its nameservers and status
		// are what the user acts on.
		if z, gerr := e.c.api.getZone(ctx, e.z.ID); gerr == nil {
			e.z = z
			storeZone(ctx, e.rt, e.profile, *z)
		}
	}
	rep := e.report(changes)
	showNS := e.z != nil && (e.created || e.nsMoved || e.z.Status == "pending")
	if e.z != nil && e.z.Status == "pending" && !e.created {
		e.rt.Infof("zone %s is pending: its nameservers have not been switched at the registrar yet", e.domain)
	}
	if rerr := renderZoneReport(e.rt, rep, showNS); rerr != nil && err == nil {
		err = rerr
	}
	if err != nil && !rep.DryRun && !errors.Is(err, app.ErrUsage) {
		e.rt.NotifyFailure(ctx, app.Failure{Event: event + ".failed", Platform: string(platform.Cloudflare), Profile: e.profile,
			Domain: e.domain, Error: err.Error(), Changes: changes})
	}
	return err
}

// zoneSteps are the steps of the zone itself and of its Foundation DNS.
func (e *zoneEnsure) zoneSteps() []platform.Step {
	if e.z != nil {
		steps := []platform.Step{{Resource: e.resource(""), Action: platform.Unchanged, ID: e.z.ID,
			Desc: fmt.Sprintf("id=%s status=%s", e.z.ID, e.z.Status)}}
		if e.foundationSet && e.foundation {
			steps = append(steps, e.foundationExisting())
		}
		return steps
	}
	steps := []platform.Step{{
		Resource: e.resource(""),
		Action:   platform.Created,
		Desc:     fmt.Sprintf("account=%s type=full", e.account),
		Apply:    e.createZone,
	}}
	if e.foundation {
		steps = append(steps, platform.Step{
			Resource: e.resource("foundation-dns"),
			Action:   platform.Created,
			Desc:     "enable",
			Apply:    e.foundationNew,
		})
	}
	return steps
}

func (e *zoneEnsure) createZone(ctx context.Context) (platform.Change, error) {
	z, err := e.c.api.createZone(ctx, e.domain, e.account)
	if ae := apiError(err); ae != nil && ae.HasCode(codeZoneExists) {
		if !e.create {
			// Created by someone else since it was looked up: use it.
			if zs, ferr := e.c.api.findZonesNamed(ctx, e.domain, e.account); ferr == nil && len(zs) > 0 {
				e.z = &zs[0]
				storeZone(ctx, e.rt, e.profile, *e.z)
				return platform.Change{Action: platform.Unchanged, ID: e.z.ID, Detail: fmt.Sprintf("id=%s status=%s (created meanwhile)", e.z.ID, e.z.Status)}, nil
			}
		}
		return platform.Change{}, fmt.Errorf("zone %s already exists, in this account or in another one the login does not select (Cloudflare holds an active domain in one account only): pass --account or --profile to target the account that holds it: %w", e.domain, err)
	}
	if err != nil {
		return platform.Change{}, err
	}
	e.z, e.created, e.wrote = z, true, true
	storeZone(ctx, e.rt, e.profile, *z)
	if !cacheable(e.rt, e.profile, e.account) {
		e.rt.Infof("note: account %s is not selected, so the new zone is not in the inventory (polyctl cloudflare account add %s)", e.account, e.account)
	}
	return platform.Change{ID: z.ID, Detail: fmt.Sprintf("id=%s status=%s", z.ID, z.Status)}, nil
}

// foundationNew switches Foundation DNS on for the zone just created. An
// account that cannot use it keeps the default nameservers: that is
// reported as skipped, not a failure.
func (e *zoneEnsure) foundationNew(ctx context.Context) (platform.Change, error) {
	if !e.created {
		return platform.Change{Action: platform.Skipped, Detail: "the zone existed already"}, nil
	}
	if on, _ := e.z.Meta["foundation_dns"].(bool); on || usesFoundationDNS(e.z.NameServers) {
		// The account switches it on for new zones by itself.
		return platform.Change{Action: platform.Unchanged, Detail: "enabled"}, nil
	}
	return e.enableFoundation(ctx)
}

// foundationExisting converges an existing zone to Foundation DNS on (only
// when --foundation-dns was given).
func (e *zoneEnsure) foundationExisting() platform.Step {
	return platform.Step{
		Resource: e.resource("foundation-dns"),
		Action:   platform.Updated,
		Desc:     "false -> true",
		Check: func(ctx context.Context) (platform.Change, bool, error) {
			s, err := e.c.api.getFoundationDNS(ctx, e.z.ID)
			if foundationUnsupported(err) {
				return platform.Change{Action: platform.Skipped, Detail: "account does not support foundation dns: " + err.Error()}, true, nil
			}
			if err != nil {
				return platform.Change{}, false, err
			}
			if on, _ := s.Value.(bool); on {
				return platform.Change{Detail: "enabled"}, true, nil
			}
			return platform.Change{}, false, nil
		},
		Apply: e.enableFoundation,
	}
}

func (e *zoneEnsure) enableFoundation(ctx context.Context) (platform.Change, error) {
	_, err := e.c.api.setFoundationDNS(ctx, e.z.ID, true)
	if foundationUnsupported(err) {
		msg := err.Error()
		if ae := apiError(err); ae != nil && len(ae.Errors) > 0 {
			msg = ae.Errors[0].Message
		}
		return platform.Change{Action: platform.Skipped, Detail: "account does not support foundation dns: " + msg}, nil
	}
	if err != nil {
		return platform.Change{}, err
	}
	e.wrote = true
	before := e.z.NameServers
	// The nameservers change at once: read them again, they are the ones
	// to set at the registrar.
	if z, gerr := e.c.api.getZone(ctx, e.z.ID); gerr == nil {
		e.z = z
		storeZone(ctx, e.rt, e.profile, *z)
	}
	e.nsMoved = strings.Join(before, ",") != strings.Join(e.z.NameServers, ",")
	return platform.Change{Detail: "enabled"}, nil
}

// settings converges the settings of the preset (or --ssl alone).
func (e *zoneEnsure) settings(ctx context.Context) ([]platform.Change, error) {
	var plan platform.Plan
	if e.z == nil {
		// A dry run of a zone that does not exist: nothing can be read.
		for _, it := range e.items {
			if it.enterprise {
				plan.Add(platform.Step{Resource: e.resource("setting/" + it.id), Action: platform.Skipped, Desc: "enterprise only (plan unknown until created)"})
				continue
			}
			plan.Add(platform.Step{Resource: e.resource("setting/" + it.id), Action: platform.Updated, Desc: platform.Pending + " -> " + it.want})
		}
		return plan.Run(ctx, e.rt.DryRun())
	}
	steps, err := e.settingSteps(ctx)
	if err != nil {
		return nil, err
	}
	plan.Add(steps...)
	return plan.Run(ctx, e.rt.DryRun())
}

// settingSteps observes the current values (one request for most settings;
// rum and Argo have to be read one by one) and returns a step per item.
func (e *zoneEnsure) settingSteps(ctx context.Context) ([]platform.Step, error) {
	zoneID, plan := e.z.ID, e.z.Plan.LegacyID
	enterprise := plan == planEnterprise
	listed, err := e.c.api.listSettings(ctx, zoneID)
	if err != nil {
		return nil, err
	}
	current := map[string]*zoneSetting{}
	for i := range listed {
		current[listed[i].ID] = &listed[i]
	}
	var steps []platform.Step
	for _, it := range e.items {
		it := it
		res := e.resource("setting/" + it.id)
		if it.enterprise && !enterprise {
			if plan == "" {
				plan = "unknown"
			}
			steps = append(steps, platform.Step{Resource: res, Action: platform.Skipped, Desc: fmt.Sprintf("enterprise only (plan=%s)", plan)})
			continue
		}
		cur := current[it.id]
		if cur == nil {
			// Not in the bulk listing (rum, Argo): read it alone.
			cur, err = e.c.api.readSetting(ctx, zoneID, it.id)
			if errors.Is(err, platform.ErrNotFound) {
				steps = append(steps, platform.Step{Resource: res, Action: platform.Skipped, Desc: "not available on this zone"})
				continue
			}
			if err != nil {
				return nil, err
			}
		}
		have := settingText(cur.Value)
		switch {
		case have == it.want:
			steps = append(steps, platform.Step{Resource: res, Action: platform.Unchanged, Desc: have})
		case !cur.Editable:
			steps = append(steps, platform.Step{Resource: res, Action: platform.Skipped, Desc: "not editable on this plan"})
		default:
			detail := have + " -> " + it.want
			attrs := map[string]string{"from": have, "to": it.want}
			steps = append(steps, platform.Step{Resource: res, Action: platform.Updated, Desc: detail, Attrs: attrs,
				Apply: func(ctx context.Context) (platform.Change, error) {
					_, err := e.c.api.writeSetting(ctx, zoneID, it.id, it.want, plan)
					if errors.Is(err, platform.ErrNotSupported) {
						return platform.Change{Action: platform.Skipped, Detail: fmt.Sprintf("not supported on plan %s", plan)}, nil
					}
					if err != nil {
						return platform.Change{}, err
					}
					e.wrote = true
					return platform.Change{}, nil
				}})
		}
	}
	return steps, nil
}

// --- commands ------------------------------------------------------------------

func newZoneCreateCmd(rt *app.Runtime) *cobra.Command {
	var foundation bool
	cmd := &cobra.Command{
		Use:   "create <domain>",
		Short: "Add a zone to the account of --account, else the default account of the login (fails when it exists; see ensure)",
		Long: `Add the zone <domain> (a registered domain such as example.com) to a
Cloudflare account of the profile: --account, else the default account of
the login. A new zone is "pending" until its nameservers, printed below the
report, are set at the registrar; polyctl does not wait for it to become
active.

Foundation DNS is switched on for the new zone (--foundation-dns=false skips
it); an account that cannot use it keeps the default nameservers and the
step is reported as skipped.

A zone of that name that exists already is an error (exit code 1): use
` + "`zone ensure`" + `, which reuses it. Without --account it is looked for in
every selected account of the login, and the error names the account that
holds it; with --account in that account alone. Cloudflare holds an active
domain in one account only, so a zone it refuses because another account,
one the login does not select, holds the domain is an error as well.`,
		Example: "  polyctl cloudflare zone create example.com --profile acme\n  polyctl cloudflare zone create example.com --account acme-eu",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			arg, err := newZoneDomain(cmd.Context(), rt, args)
			if err != nil {
				return err
			}
			domain, err := zoneDomainArg(arg)
			if err != nil {
				return err
			}
			s, account, only, err := openAccount(cmd.Context(), rt)
			if err != nil {
				return err
			}
			e := &zoneEnsure{rt: rt, c: s.client, profile: s.profile, account: account, only: only, domain: domain, create: true, foundation: foundation}
			return e.run(cmd.Context(), "cloudflare.zone.create")
		},
	}
	cmd.Flags().BoolVar(&foundation, "foundation-dns", true, "switch Foundation DNS on for the new zone (--foundation-dns=false skips it)")
	return cmd
}

func newZoneEnsureCmd(rt *app.Runtime) *cobra.Command {
	var foundation bool
	var preset, ssl string
	cmd := &cobra.Command{
		Use:   "ensure <domain>",
		Short: "Create the zone when it is missing and converge its settings (--preset optimized, --ssl)",
		Long: `Make sure the zone <domain> exists in a Cloudflare account of the profile
(created as ` + "`zone create`" + ` does, with Foundation DNS, when it is missing; reused
when it exists) and, with --preset or --ssl, converge its settings: each
setting is read first and written only when it differs. Running it again
changes nothing.

Without --account the zone is looked for in every selected account of the
login: it is reused in the account that holds it (the report names that
account), two accounts holding one are a pick on a terminal and ambiguous
(exit code 5) otherwise, and a missing zone is created in the default
account. With --account only that account is looked in and created in.

--preset optimized sets, in this order: 0rtt on, early_hints on, rum on,
response_buffering on, ipv6 off and Argo Smart Routing on (these three on
Enterprise zones only, reported as skipped on other plans: Argo is billed
there), always_use_https on, automatic_https_rewrites on, and last the SSL
mode: --ssl (flexible or strict), else defaults.cloudflare.ssl, else strict.
Note that strict replaces flexible on a zone that has it: pass --ssl
flexible for an origin without HTTPS. --ssl without --preset sets the SSL
mode only. A setting the plan cannot change is reported as skipped.

--foundation-dns applies to a new zone (on by default); for an existing
zone Foundation DNS is left alone unless --foundation-dns is given, which
switches it on (--foundation-dns=false never switches it off).

A new zone is "pending" until its nameservers, printed below the report, are
set at the registrar; ensure does not wait for it.`,
		Example: `  polyctl cloudflare zone ensure example.com --preset optimized --ssl flexible
  polyctl cloudflare zone ensure example.com --preset optimized --dry-run -o json`,
		Args: app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			arg, err := newZoneDomain(cmd.Context(), rt, args)
			if err != nil {
				return err
			}
			domain, err := zoneDomainArg(arg)
			if err != nil {
				return err
			}
			preset = strings.ToLower(strings.TrimSpace(preset))
			if preset != "" && preset != presetOptimized {
				return app.UsageErrf("--preset takes %q, got %q", presetOptimized, preset)
			}
			ssl = strings.ToLower(strings.TrimSpace(ssl))
			if cmd.Flags().Changed("ssl") && ssl != "flexible" && ssl != "strict" {
				return app.UsageErrf("--ssl takes flexible or strict, got %q (use `polyctl cloudflare ssl-mode` for off and full)", ssl)
			}
			s, account, only, err := openAccount(cmd.Context(), rt)
			if err != nil {
				return err
			}
			var items []presetItem
			switch {
			case preset == presetOptimized:
				mode, err := rt.Setting(s.profile, platform.Cloudflare, "ssl", ssl)
				if err != nil {
					return err
				}
				items = optimizedPreset(mode)
			case ssl != "":
				items = []presetItem{{id: "ssl", want: ssl}}
			}
			e := &zoneEnsure{rt: rt, c: s.client, profile: s.profile, account: account, only: only, domain: domain,
				foundation: foundation, foundationSet: cmd.Flags().Changed("foundation-dns"), items: items}
			return e.run(cmd.Context(), "cloudflare.zone.ensure")
		},
	}
	cmd.Flags().StringVar(&preset, "preset", "", "converge the settings of a preset: optimized")
	cmd.Flags().StringVar(&ssl, "ssl", "", "SSL mode: flexible or strict (with --preset default: defaults.cloudflare.ssl, else strict)")
	cmd.Flags().BoolVar(&foundation, "foundation-dns", true, "switch Foundation DNS on for a new zone; given explicitly, also for an existing one (--foundation-dns=false skips it)")
	return cmd
}
