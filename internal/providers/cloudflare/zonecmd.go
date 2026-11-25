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

// storeZone mirrors a zone read from the API into the inventory. A failure
// is only reported: the platform is the source of truth.
func storeZone(ctx context.Context, rt *app.Runtime, profile string, z apiZone) {
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

// dropZoneNamed removes the zones named name (and their records) of a
// profile from the inventory: rows left behind by a zone that is gone.
func dropZoneNamed(ctx context.Context, rt *app.Runtime, profile, name string, keepID string) {
	db, err := rt.DB()
	if err != nil {
		return
	}
	rows, err := db.List(ctx, inventory.Query{Platform: platform.Cloudflare, Profile: profile, Type: platform.ResZone, Name: name})
	if err != nil {
		return
	}
	for _, r := range rows {
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

// resolveLiveZone finds the zone <zone> names among the Cloudflare accounts
// (restricted by --profile) through the inventory, synced once when it does
// not know the zone, and reads it live: a zone the inventory remembers but
// the platform no longer has is removed from the inventory and looked up
// again by name, and is not found (exit code 4) when that finds nothing. A
// name held by several accounts is ambiguous (exit code 5).
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
		zs, ferr := c.api.findZonesNamed(ctx, name, c.api.accountID)
		if ferr != nil {
			return nil, ferr
		}
		if len(zs) == 0 {
			return nil, fmt.Errorf("%w: zone %s (it no longer exists in cloudflare/%s; removed from the local inventory)", platform.ErrNotFound, name, res.Profile)
		}
		if len(zs) > 1 {
			// The profile is not pinned to an account and the name is
			// held by several of the accounts its credentials see.
			return nil, fmt.Errorf("%w: zone %s is held by %d accounts of cloudflare/%s; pin the account with `polyctl auth login cloudflare --profile %s --set account_id=<id>`",
				platform.ErrAmbiguous, name, len(zs), res.Profile, res.Profile)
		}
		z, err = &zs[0], nil
	}
	if err != nil {
		return nil, err
	}
	storeZone(ctx, rt, res.Profile, *z)
	return &zoneScope{c: c, profile: res.Profile, z: z}, nil
}

// routeZone finds the zone ref (a normalized name or an id) among the
// Cloudflare accounts (restricted by --profile) through the inventory,
// synced once when it does not know the zone, and opens the client of the
// account that holds it. The zone is not read: the inventory row is all the
// caller gets. A name held by several accounts is ambiguous (exit code 5).
func routeZone(ctx context.Context, rt *app.Runtime, ref string) (*Client, inventory.Resource, error) {
	if rt.Flags.Offline {
		return nil, inventory.Resource{}, app.ErrOffline
	}
	if ref == "" {
		// The <zone> left out in the interactive flow: asked for among
		// the zones of the selected accounts.
		var err error
		if ref, err = pickLiveZone(ctx, rt); err != nil {
			return nil, inventory.Resource{}, err
		}
	}
	res, err := rt.ResolveResource(ctx, platform.Cloudflare, platform.ResZone, ref)
	if errors.Is(err, platform.ErrNotFound) && !rt.Flags.Refresh {
		// The inventory is fresh but does not know the zone (it may have
		// been added since): sync once before giving up.
		rt.Flags.Refresh = true
		res, err = rt.ResolveResource(ctx, platform.Cloudflare, platform.ResZone, ref)
		rt.Flags.Refresh = false
	}
	if err != nil {
		return nil, inventory.Resource{}, err
	}
	cl, _, err := rt.Open(ctx, res.Profile, platform.Cloudflare)
	if err != nil {
		return nil, inventory.Resource{}, err
	}
	c, ok := cl.(*Client)
	if !ok {
		return nil, inventory.Resource{}, fmt.Errorf("unexpected client type %T", cl)
	}
	return c, res, nil
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
// is chosen as for every Cloudflare command, and the account is the one the
// profile is pinned to, or the only one its credentials see.
func openAccount(ctx context.Context, rt *app.Runtime) (*session, string, error) {
	if rt.Flags.Offline {
		return nil, "", app.ErrOffline
	}
	s, err := open(ctx, rt)
	if err != nil {
		return nil, "", err
	}
	if id := s.client.api.accountID; id != "" {
		return s, id, nil
	}
	accounts, err := s.client.api.listAccounts(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("profile %s has no pinned account and its accounts cannot be listed: %w", s.profile, err)
	}
	switch len(accounts) {
	case 0:
		return nil, "", fmt.Errorf("%w: the credentials of profile %s see no account", platform.ErrUnauthorized, s.profile)
	case 1:
		return s, accounts[0].ID, nil
	}
	if !rt.Interactive() {
		return nil, "", app.UsageErrf("the credentials of profile %s see %d accounts (%s); pin one with `polyctl auth login cloudflare --profile %s --set account_id=<id>`",
			s.profile, len(accounts), accountNames(accounts), s.profile)
	}
	// The interactive flow asks, for this run only.
	var opts []prompt.Option
	for _, a := range accounts {
		opts = append(opts, prompt.Option{Label: fmt.Sprintf("%s  %s", a.Name, a.ID), Value: a.ID})
	}
	id, err := rt.Choose(app.Choice{Title: "Cloudflare account of the new zone", Options: opts, Arg: "--set account_id"})
	if err != nil {
		return nil, "", err
	}
	rt.Infof("note: to skip this question, pin the account with `polyctl auth login cloudflare --profile %s --set account_id=%s`", s.profile, id)
	return s, id, nil
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
