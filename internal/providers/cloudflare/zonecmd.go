package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// This file holds what the zone lifecycle commands (create, ensure,
// delete, setting) share: the zone a command works on, read live, and its
// mirror in the inventory.

// zoneScope is a zone read live from the account that holds it.
type zoneScope struct {
	c       *Client
	profile string
	z       *apiZone
}

func (s *zoneScope) name() string { return platform.NormalizeDomain(s.z.Name) }

func (s *zoneScope) plan() string { return s.z.Plan.LegacyID }

func (s *zoneScope) target() platform.Target {
	return platform.Target{Platform: platform.Cloudflare, Profile: s.profile, Domain: s.name()}
}

// storeZone mirrors a zone read from the API into the inventory, unless
// its account is outside the selection of the login. A failure is only
// reported: the platform is the source of truth.
func storeZone(ctx context.Context, rt *app.Runtime, profile string, z apiZone) {
	if !cacheable(rt, profile, z.Account.ID) {
		return
	}
	db, err := rt.DB()
	if err != nil {
		rt.Verbosef("inventory: %v", err)
		return
	}
	cfg, err := rt.Config()
	if err != nil {
		return
	}
	if err := db.Upsert(ctx, zoneSet(profile), zoneResources([]platform.Zone{toZone(z)})[0], cfg.TTLFor(platform.ResZone)); err != nil {
		rt.Infof("warning: could not update the local inventory: %v", err)
	}
}

// dropZone removes a zone and its DNS records from the inventory. A failure
// is only reported (the zone is gone on the platform either way).
func dropZone(ctx context.Context, rt *app.Runtime, profile, zoneID string) {
	db, err := rt.DB()
	if err != nil {
		rt.Verbosef("inventory: %v", err)
		return
	}
	warn := func(err error) {
		if err != nil {
			rt.Infof("warning: could not update the local inventory: %v", err)
		}
	}
	recs, err := db.List(ctx, inventory.Query{Platform: platform.Cloudflare, Profile: profile, Type: platform.ResDNSRecord, ParentID: zoneID})
	warn(err)
	for _, r := range recs {
		warn(db.Delete(ctx, recordSet(profile, zoneID), platform.ResDNSRecord, r.ID))
	}
	warn(db.Delete(ctx, zoneSet(profile), platform.ResZone, zoneID))
}

// dropZoneNamed removes the zones named name (and their records) of an
// account of a profile from the inventory: rows left behind by a zone that
// is gone. The zone of the same name another account holds is not touched;
// an empty account means every account of the profile.
func dropZoneNamed(ctx context.Context, rt *app.Runtime, profile, name, account, keepID string) {
	db, err := rt.DB()
	if err != nil {
		return
	}
	rows, err := db.List(ctx, inventory.Query{Platform: platform.Cloudflare, Profile: profile, Type: platform.ResZone, Name: name})
	if err != nil {
		return
	}
	for _, r := range rows {
		if ra := rowAccount(r); account != "" && ra != "" && ra != account {
			continue
		}
		if r.ID != keepID {
			dropZone(ctx, rt, profile, r.ID)
		}
	}
}

// zoneRef normalizes a <zone> argument: a name is lower-cased without its
// trailing dot, an id is kept as it is.
func zoneRef(arg string) string {
	ref := strings.TrimSpace(arg)
	if strings.Contains(ref, ".") {
		return platform.NormalizeDomain(ref)
	}
	return ref
}

// resolveLiveZone finds the zone <zone> names among the Cloudflare logins
// (restricted by --profile) and their selected accounts (or the account of
// --account) through the inventory, synced once when it does not know the
// zone, and reads it live: a zone the inventory remembers but the platform
// no longer has is removed from the inventory and looked up again by name,
// and is not found (exit code 4) when that finds nothing. A name several
// accounts hold a zone of is a pick in the interactive flow and ambiguous
// (exit code 5) otherwise.
func resolveLiveZone(ctx context.Context, rt *app.Runtime, arg string) (*zoneScope, error) {
	ref := zoneRef(arg)
	c, res, err := routeZone(ctx, rt, ref)
	if err != nil {
		return nil, err
	}
	z, err := c.api.getZone(ctx, res.ID)
	if zoneGone(err) {
		dropZone(ctx, rt, res.Profile, res.ID)
		name := res.Name
		if !strings.Contains(name, ".") {
			return nil, fmt.Errorf("%w: zone %s no longer exists (removed from the local inventory)", platform.ErrNotFound, ref)
		}
		zs, ferr := c.api.zonesNamed(ctx, name)
		if ferr != nil {
			return nil, ferr
		}
		switch len(zs) {
		case 0:
			return nil, fmt.Errorf("%w: zone %s (it no longer exists in cloudflare/%s; removed from the local inventory)", platform.ErrNotFound, name, res.Profile)
		case 1:
			z, err = &zs[0], nil
		default:
			// The accounts the login works on hold several zones of the
			// name.
			if z, err = pickAmbiguousZone(rt, res.Profile, name, zs, true); err != nil {
				return nil, err
			}
		}
	}
	if err != nil {
		return nil, err
	}
	if acc := z.Account.ID; !c.api.covers(acc) {
		// The row was of an account the login works on; the zone is not.
		dropZone(ctx, rt, res.Profile, res.ID)
		return nil, unselectedZoneErr(z.Name, z.ID, acc)
	}
	storeZone(ctx, rt, res.Profile, *z)
	return &zoneScope{c: c, profile: res.Profile, z: z}, nil
}

// routeZone finds the zone ref (a normalized name or an id) among the
// Cloudflare logins (restricted by --profile) and the accounts they select
// (or the account of --account) through the inventory, synced once when it
// does not know the zone, and opens the client of the login that holds it.
// The zone is not read: the inventory row is all the caller gets. A name
// several accounts hold a zone of is a pick in the interactive flow and
// ambiguous (exit code 5) otherwise.
//
// The account of --account that no login selects is not in the inventory:
// its zone is looked up on the platform, through the profile every
// Cloudflare command would use.
func routeZone(ctx context.Context, rt *app.Runtime, ref string) (*Client, inventory.Resource, error) {
	if rt.Flags.Offline {
		return nil, inventory.Resource{}, app.ErrOffline
	}
	scopes, err := routeScopes(ctx, rt)
	if err != nil {
		return nil, inventory.Resource{}, err
	}
	if len(scopes) == 1 && scopes[0].live {
		return routeLiveZone(ctx, rt, scopes[0], ref)
	}
	by := map[string]acctScope{}
	for _, s := range scopes {
		by[s.profile] = s
	}
	keep := func(r inventory.Resource) bool {
		s, ok := by[r.Profile]
		return ok && s.keeps(rowAccount(r))
	}
	if ref == "" {
		// The <zone> left out in the interactive flow: asked for among
		// the zones of the selected accounts.
		if ref, err = pickLiveZone(ctx, rt, by, keep); err != nil {
			return nil, inventory.Resource{}, err
		}
	}
	cand := func(r inventory.Resource) zoneCand { return candOfZone(r.Profile, rowZone(r)) }
	// A name is looked up in zone sets that are not due: after the
	// selection changed, an account that was added may hold a zone of it too.
	lookup := app.ResourceLookup{Platform: platform.Cloudflare, Kind: platform.ResZone, Ref: ref, Keep: keep, SyncDue: strings.Contains(ref, "."),
		Candidate: func(r inventory.Resource) string { return cand(r).String() },
		Option:    func(r inventory.Resource) string { return cand(r).cells() },
		Hint: func(found []inventory.Resource) string {
			cands := make([]zoneCand, 0, len(found))
			for _, r := range found {
				cands = append(cands, cand(r))
			}
			return zoneHint(cands, true)
		}}
	res, err := rt.ResolveResourceWith(ctx, lookup)
	if errors.Is(err, platform.ErrNotFound) && !rt.Flags.Refresh {
		// The inventory is fresh but does not know the zone (it may have
		// been added since): sync once before giving up.
		rt.Flags.Refresh = true
		res, err = rt.ResolveResourceWith(ctx, lookup)
		rt.Flags.Refresh = false
	}
	if errors.Is(err, platform.ErrNotFound) && !strings.Contains(ref, ".") {
		// A zone id with the --account of another account: say so.
		for _, s := range scopes {
			if s.pin == "" {
				continue
			}
			if c, oerr := openProfile(ctx, rt, s.profile); oerr == nil {
				if _, zerr := findLiveZone(ctx, rt, c.api, s, ref); errors.Is(zerr, app.ErrUsage) {
					return nil, inventory.Resource{}, zerr
				}
			}
			break
		}
	}
	if err != nil {
		return nil, inventory.Resource{}, err
	}
	c, err := openProfile(ctx, rt, res.Profile)
	if err != nil {
		return nil, inventory.Resource{}, err
	}
	if pin := by[res.Profile].pin; pin != "" {
		c = c.pin(pin)
	}
	return c, res, nil
}

// routeLiveZone is routeZone for the account of --account that no login
// selects: the zone is looked up on the platform, and asked for among the
// zones read from it when ref is empty.
func routeLiveZone(ctx context.Context, rt *app.Runtime, sc acctScope, ref string) (*Client, inventory.Resource, error) {
	c, err := openProfile(ctx, rt, sc.profile)
	if err != nil {
		return nil, inventory.Resource{}, err
	}
	c = c.pin(sc.pin)
	if ref == "" {
		if !rt.Interactive() {
			return nil, inventory.Resource{}, app.UsageErrf("<zone> is required")
		}
		zones, err := c.ListZones(ctx)
		if err != nil {
			return nil, inventory.Resource{}, err
		}
		if ref, err = pickCachedZone(rt, zones, sc); err != nil {
			return nil, inventory.Resource{}, err
		}
	}
	z, err := findLiveZone(ctx, rt, c.api, sc, ref)
	if err != nil {
		return nil, inventory.Resource{}, err
	}
	return c, inventory.Resource{Platform: platform.Cloudflare, Profile: sc.profile, Type: platform.ResZone,
		ID: z.ID, Name: platform.NormalizeDomain(z.Name), ParentID: z.Account.ID}, nil
}

// openProfile opens the Cloudflare client of a profile.
func openProfile(ctx context.Context, rt *app.Runtime, profile string) (*Client, error) {
	cl, _, err := rt.Open(ctx, profile, platform.Cloudflare)
	if err != nil {
		return nil, err
	}
	c, ok := cl.(*Client)
	if !ok {
		return nil, fmt.Errorf("unexpected client type %T", cl)
	}
	return c, nil
}

// gone turns the answer "this zone does not exist" to a request about the
// zone of s into a not-found error, removing the zone from the inventory.
func (s *zoneScope) gone(ctx context.Context, rt *app.Runtime, err error) error {
	if !zoneGone(err) {
		return err
	}
	dropZone(ctx, rt, s.profile, s.z.ID)
	return fmt.Errorf("%w: zone %s (id %s) no longer exists (removed from the local inventory): %v", platform.ErrNotFound, s.name(), s.z.ID, err)
}

// openAccount opens the Cloudflare account a new zone goes to: the profile
// is chosen as for every Cloudflare command, and the account is the one of
// --account, else the default account of the login. only says the account
// was named for this call, so an existing zone is looked for in it alone.
//
// A login without an account (its credentials could not list accounts when
// it was made) needs --account while they still cannot (the error of the
// listing otherwise). When they can by now, the only account they see is
// used; several are asked for in the interactive flow and a usage error
// otherwise.
func openAccount(ctx context.Context, rt *app.Runtime) (s *session, account string, only bool, err error) {
	if rt.Flags.Offline {
		return nil, "", false, app.ErrOffline
	}
	if s, err = open(ctx, rt); err != nil {
		return nil, "", false, err
	}
	if ref := pinnedAccount(rt); ref != "" {
		id, err := resolveAccountRef(ctx, rt, s.profile, ref)
		if err != nil {
			return nil, "", false, err
		}
		return s, id, true, nil
	}
	if id := s.client.api.accountID; id != "" {
		return s, id, false, nil
	}
	accounts, err := s.client.api.listAccounts(ctx)
	if err != nil {
		return nil, "", false, fmt.Errorf("profile %s has no selected account and its accounts cannot be listed (pass --account <id>): %w", s.profile, err)
	}
	switch len(accounts) {
	case 0:
		return nil, "", false, fmt.Errorf("%w: the credentials of profile %s see no account", platform.ErrUnauthorized, s.profile)
	case 1:
		return s, accounts[0].ID, true, nil
	}
	if !rt.Interactive() {
		return nil, "", false, app.UsageErrf("the credentials of profile %s see %d accounts (%s): pass --account <id or name>, or select the accounts of the login with \"polyctl cloudflare account use <id>\"",
			s.profile, len(accounts), accountNames(accounts))
	}
	// The interactive flow asks, for this run only.
	var opts []prompt.Option
	for _, a := range accounts {
		opts = append(opts, prompt.Option{Label: prompt.Cells(a.Name, a.ID), Value: a.ID})
	}
	id, err := rt.Choose(app.Choice{Title: "Cloudflare account of the new zone", Options: opts, Arg: "--account"})
	if err != nil {
		return nil, "", false, err
	}
	rt.Infof("note: to skip this question pass --account %s, or make it the default account: polyctl cloudflare account use %s", id, id)
	return s, id, true, nil
}

// --- output ------------------------------------------------------------------

// zoneView is the zone part of the report of zone create / ensure.
type zoneView struct {
	ID                  string   `json:"id" yaml:"id"`
	Name                string   `json:"name" yaml:"name"`
	Status              string   `json:"status" yaml:"status"`
	Plan                string   `json:"plan" yaml:"plan"`
	NameServers         []string `json:"name_servers" yaml:"name_servers"`
	OriginalNameServers []string `json:"original_name_servers" yaml:"original_name_servers"`
}

func viewZone(z *apiZone) *zoneView {
	return &zoneView{ID: z.ID, Name: platform.NormalizeDomain(z.Name), Status: z.Status, Plan: z.Plan.LegacyID,
		NameServers: z.NameServers, OriginalNameServers: z.OriginalNameServers}
}

// zoneReportTarget is the target of a zone report: the account the zone is
// in.
type zoneReportTarget struct {
	Platform  platform.ID `json:"platform" yaml:"platform"`
	Profile   string      `json:"profile" yaml:"profile"`
	AccountID string      `json:"account_id,omitempty" yaml:"account_id,omitempty"`
}

// zoneReport is the json / yaml shape of zone create / ensure.
type zoneReport struct {
	Target  zoneReportTarget  `json:"target" yaml:"target"`
	DryRun  bool              `json:"dry_run" yaml:"dry_run"`
	Zone    *zoneView         `json:"zone" yaml:"zone"`
	Changes []platform.Change `json:"changes" yaml:"changes"`
}

// renderZoneReport prints the change report, and in the table form the
// nameservers to set at the registrar below it when showNS is set.
func renderZoneReport(rt *app.Runtime, rep zoneReport, showNS bool) error {
	if rep.Changes == nil {
		rep.Changes = []platform.Change{}
	}
	if err := rt.Render(rep, func() output.Grid { return app.ChangeGrid(rep.Changes) }); err != nil {
		return err
	}
	if !showNS || rep.Zone == nil || len(rep.Zone.NameServers) == 0 {
		return nil
	}
	if rt.Format() == output.Table {
		var b strings.Builder
		b.WriteString("\nNameservers (set these at your registrar):\n")
		for _, ns := range rep.Zone.NameServers {
			b.WriteString("  " + ns + "\n")
		}
		if _, err := fmt.Fprint(rt.Stdout, output.Clean(b.String())); err != nil {
			return err
		}
	}
	rt.Infof("set them at the registrar with: polyctl domain ns set %s %s", rep.Zone.Name, strings.Join(rep.Zone.NameServers, " "))
	return nil
}

// usesFoundationDNS reports whether a zone is served by Foundation DNS
// nameservers.
func usesFoundationDNS(nameservers []string) bool {
	for _, ns := range nameservers {
		if strings.Contains(strings.ToLower(ns), "foundationdns") {
			return true
		}
	}
	return false
}
