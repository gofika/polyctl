package app

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// Target is the resolved owner of a domain for a given kind of operation.
type Target struct {
	Platform platform.ID           `json:"platform" yaml:"platform"`
	Profile  string                `json:"profile" yaml:"profile"`
	Type     platform.ResourceType `json:"resource_type" yaml:"resource_type"`
	// ResourceID is the zone id (for zones) or the domain name (for domains).
	ResourceID string `json:"resource_id" yaml:"resource_id"`
	// Domain is the matched zone / registered domain name.
	Domain string `json:"domain" yaml:"domain"`
}

// String renders "platform/profile (zone example.com)".
func (t Target) String() string {
	return fmt.Sprintf("%s/%s (%s %s)", t.Platform, t.Profile, t.Type, t.Domain)
}

// ErrDomainUnknown is returned when no profile owns the domain.
var ErrDomainUnknown = errors.New("domain not found in local index")

// ResolveDomain finds which profile owns domain for the requested resource
// kind (ResZone for DNS operations, ResDomain for registrar operations).
//
// Precedence: --profile and --platform restrict the search; otherwise the
// longest matching domain in the index wins. Index rows of accounts that are
// no longer in the config (kept by `auth logout --keep-inventory`, or left by
// a hand edit) take no part. If several accounts (or several resources of
// one account) own the same best match, an AmbiguousError is returned.
// With --refresh the candidate accounts are indexed before the lookup, once
// per run and kind. Without it, the candidate accounts whose set of kind
// was marked due (see IndexDue) are indexed before the lookup, once per run;
// after that a miss indexes the candidates only when none of them has ever
// been indexed, and the lookup is retried. A set that merely ran past its
// TTL is not indexed again by a lookup.
func (rt *Runtime) ResolveDomain(ctx context.Context, domain string, kind platform.ResourceType) (*Target, error) {
	domain = platform.NormalizeDomain(domain)
	cands := platform.Candidates(domain)
	if len(cands) == 0 {
		return nil, fmt.Errorf("invalid domain %q", domain)
	}
	db, err := rt.DB()
	if err != nil {
		return nil, err
	}
	only, err := rt.RoutePlatform()
	if err != nil {
		return nil, err
	}
	// The accounts able to hold kind, restricted to --profile / --platform.
	// This reads the config only, so it works offline too; an unknown
	// --profile fails here.
	profiles, err := rt.indexCandidates(ctx, kind)
	if err != nil {
		return nil, err
	}
	selected := map[config.AccountRef]bool{}
	for _, p := range profiles {
		selected[p] = true
	}
	lookup := func() (*Target, error) {
		entries, err := db.LookupDomain(ctx, cands, kind)
		if err != nil {
			return nil, err
		}
		var filtered []inventory.IndexEntry
		for _, e := range entries {
			if selected[config.AccountRef{Profile: e.Profile, Platform: e.Platform}] {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
		if len(entries) == 0 {
			return nil, nil
		}
		best := entries[0].Domain
		var owners []inventory.IndexEntry
		seen := map[string]bool{}
		for _, e := range entries {
			if e.Domain != best {
				break
			}
			// Two resources of the same profile (e.g. two Route 53 hosted
			// zones with one name) are as ambiguous as two profiles.
			k := string(e.Platform) + "/" + e.Profile + "/" + e.ResourceID
			if !seen[k] {
				seen[k] = true
				owners = append(owners, e)
			}
		}
		if len(owners) > 1 {
			var names, labels []string
			profiles, platforms := map[string]bool{}, map[platform.ID]bool{}
			for _, o := range owners {
				names = append(names, fmt.Sprintf("%s/%s (%s %s)", o.Platform, o.Profile, o.Type, o.ResourceID))
				labels = append(labels, prompt.Cells(string(o.Platform)+"/"+o.Profile, string(o.Type), o.Domain, "id "+o.ResourceID))
				profiles[o.Profile], platforms[o.Platform] = true, true
			}
			// Name only the flags that actually narrow the candidates down.
			var hint string
			switch {
			case len(profiles) > 1 && len(platforms) > 1:
				hint = "pass --profile <name> and/or --platform <platform> to choose"
			case len(platforms) > 1:
				hint = "pass --platform <platform> to choose"
			case len(profiles) > 1:
				hint = "pass --profile <name> to choose"
			default:
				hint = "the account holds several resources with this name; use the platform's own command with the resource id"
				// The platform may know what tells them apart (the
				// projects of one Google Cloud account).
				if prov, err := platform.Get(owners[0].Platform); err == nil {
					if h, ok := prov.(platform.OwnerHinter); ok {
						ids := make([]string, 0, len(owners))
						for _, o := range owners {
							ids = append(ids, o.ResourceID)
						}
						if v := h.OwnerHint(kind, ids); v != "" {
							hint = v
						}
					}
					// And what each of them is, beyond its id (the account
					// of a Cloudflare zone).
					// The options show those facts in cells of their own,
					// and only when every owner has them: a list mixing
					// them with the default cells would put different
					// facts in one column.
					if d, ok := prov.(platform.OwnerDescriber); ok {
						cd, _ := prov.(platform.OwnerCellDescriber)
						described := make([]string, len(owners))
						complete := true
						for i, o := range owners {
							row, err := db.Get(ctx, inventory.Set{Platform: o.Platform, Profile: o.Profile, Type: o.Type}, o.Type, o.ResourceID)
							if err != nil {
								complete = false
								continue
							}
							v := d.DescribeOwner(o.Type, row.ID, row.ParentID, row.Data)
							if v == "" {
								complete = false
								continue
							}
							names[i] = fmt.Sprintf("%s/%s %s", o.Platform, o.Profile, v)
							described[i] = prompt.Cells(string(o.Platform)+"/"+o.Profile, v)
							if cd != nil {
								if cells := cd.OwnerCells(o.Type, row.ID, row.ParentID, row.Data); len(cells) > 0 {
									described[i] = prompt.Cells(append([]string{string(o.Platform) + "/" + o.Profile}, cells...)...)
								}
							}
						}
						if complete {
							labels = described
						}
					}
				}
			}
			amb := &AmbiguousError{What: fmt.Sprintf("owner of %s %q", kind, best), Candidates: names, Hint: hint}
			// The interactive flow asks which owner; the non-interactive
			// flow keeps the error (exit code 5).
			idx := make([]int, len(owners))
			for i := range idx {
				idx[i] = i
			}
			i, err := OneOf(rt, amb, idx, func(i int) string { return labels[i] })
			if err != nil {
				return nil, err
			}
			owners = owners[i : i+1]
		}
		o := owners[0]
		return &Target{Platform: o.Platform, Profile: o.Profile, Type: o.Type, ResourceID: o.ResourceID, Domain: o.Domain}, nil
	}

	notFound := func() error {
		where := "any configured account"
		if rt.Flags.Profile != "" || only != "" {
			where = "the accounts selected by --profile / --platform"
		}
		return fmt.Errorf("%w: %q is not a %s in %s", ErrDomainUnknown, domain, kind, where)
	}
	// --refresh re-indexes before the lookup, so that a zone moved to
	// another account or deleted is not served from the old row.
	refreshed := rt.routeRefreshed[kind]
	var indexErr error
	if rt.Flags.Refresh && len(profiles) > 0 {
		indexErr = rt.refreshIndex(ctx, kind, profiles)
		refreshed = true
	}
	// A set marked due may miss what its account covers since then, or
	// hold only one of two zones of a name: it is indexed before the
	// lookup, so that neither a miss nor a hit is served from it.
	dueErr, err := rt.indexDue(ctx, kind, profiles)
	if err != nil {
		return nil, err
	}
	t, err := lookup()
	if err != nil || t != nil {
		return t, err
	}
	// Check the selection before blaming the index: a --profile /
	// --platform pair that names no account is not something indexing can
	// fix.
	if len(profiles) == 0 && (rt.Flags.Profile != "" || only != "") {
		return nil, fmt.Errorf("%w: %q, and no account selected by --profile / --platform is able to manage %ss", ErrDomainUnknown, domain, kind)
	}
	if rt.Flags.Offline {
		return nil, fmt.Errorf("%w: %q (%s); run `polyctl domain index` when online", ErrDomainUnknown, domain, kind)
	}
	if len(profiles) == 0 {
		return nil, fmt.Errorf("%w: %q, and no account is able to manage %ss (run `polyctl auth login`)", ErrDomainUnknown, domain, kind)
	}
	if refreshed {
		if indexErr != nil {
			// Not "unknown": no account could be asked.
			return nil, indexErr
		}
		return nil, notFound()
	}
	if dueErr != nil {
		// Not "unknown" either: no account marked due could be asked.
		return nil, dueErr
	}
	// Without --refresh, index automatically only when the index has never
	// been built for any of the candidate profiles. Once at least one
	// profile is indexed, a miss no longer triggers a network scan: a
	// profile whose sync keeps failing never gets a state, and re-indexing
	// everything on every miss would hammer the platforms.
	var unindexed []string
	for _, p := range profiles {
		st, err := db.GetState(ctx, inventory.Set{Platform: p.Platform, Profile: p.Profile, Type: kind})
		if err != nil {
			return nil, err
		}
		if st == nil {
			unindexed = append(unindexed, p.Label())
		}
	}
	needIndex := false
	switch {
	case len(unindexed) == len(profiles):
		needIndex = true
	case len(unindexed) > 0:
		return nil, fmt.Errorf("%w: %q (%s); account(s) %s not indexed yet, run `polyctl domain index` or retry with --refresh", ErrDomainUnknown, domain, kind, strings.Join(unindexed, ", "))
	}
	if !needIndex {
		return nil, fmt.Errorf("%w: %q (%s); run `polyctl domain index` or retry with --refresh", ErrDomainUnknown, domain, kind)
	}
	indexErr = rt.indexKind(ctx, kind, profiles)
	t, err = lookup()
	if err != nil {
		return nil, err
	}
	if t == nil {
		if indexErr != nil {
			return nil, indexErr
		}
		return nil, notFound()
	}
	return t, nil
}

// refreshIndex indexes kind in profiles for --refresh, once per run: a
// later call returns the outcome of the first.
func (rt *Runtime) refreshIndex(ctx context.Context, kind platform.ResourceType, profiles []config.AccountRef) error {
	if rt.routeRefreshed[kind] {
		return rt.routeRefreshErr[kind]
	}
	err := rt.indexKind(ctx, kind, profiles)
	if rt.routeRefreshed == nil {
		rt.routeRefreshed = map[platform.ResourceType]bool{}
		rt.routeRefreshErr = map[platform.ResourceType]error{}
	}
	rt.routeRefreshed[kind], rt.routeRefreshErr[kind] = true, err
	return err
}

// ForcedDue reports whether a set was marked due by the program and did
// not just run past its TTL: the data migration of an upgrade, a login that
// changed what the account covers, and the enable / disable / use commands
// of a platform set its expiry to the zero Unix time (inventory.DB.Expire),
// which no sync writes anew (a sync writes its own time plus the TTL, or
// its own time for a set that kept old rows; a set that was marked due and
// kept old rows, because some of its regions, projects or accounts failed,
// keeps the mark).
func ForcedDue(st *inventory.State) bool {
	return st != nil && st.ExpiresAt.Unix() == 0
}

// dueKey names one account and kind in Runtime.dueIndexed.
type dueKey struct {
	ref  config.AccountRef
	kind platform.ResourceType
}

// IndexDue indexes kind in the accounts selected by --profile / --platform
// whose set of kind was marked due (ForcedDue), each at most once per run.
// It does nothing with --offline. With --refresh it indexes every candidate
// instead, once per run as routing does before its lookup, so that a caller
// that reads the index itself does not serve a set marked due because of
// the flag. A failing account is a warning and stays marked
// for the next run; the error returned says that every account marked due
// that was tried in this run failed (the other candidates were not asked).
func (rt *Runtime) IndexDue(ctx context.Context, kind platform.ResourceType) error {
	profiles, err := rt.indexCandidates(ctx, kind)
	if err != nil {
		return err
	}
	if rt.Flags.Refresh {
		if rt.Flags.Offline || len(profiles) == 0 {
			return nil
		}
		return rt.refreshIndex(ctx, kind, profiles)
	}
	dueErr, err := rt.indexDue(ctx, kind, profiles)
	if err != nil {
		return err
	}
	return dueErr
}

// indexDue is IndexDue for the given candidates, for a caller that
// indexes them all itself with --refresh (nothing is done then). Its first
// error is the
// one of every account failing (the lookup may still be answered by
// another account), its second one stops the lookup.
func (rt *Runtime) indexDue(ctx context.Context, kind platform.ResourceType, profiles []config.AccountRef) (error, error) {
	if rt.Flags.Offline || rt.Flags.Refresh || len(profiles) == 0 {
		return nil, nil
	}
	db, err := rt.DB()
	if err != nil {
		return nil, err
	}
	var due []config.AccountRef
	for _, p := range profiles {
		if _, done := rt.dueIndexed[dueKey{p, kind}]; done {
			continue
		}
		st, err := db.GetState(ctx, inventory.Set{Platform: p.Platform, Profile: p.Profile, Type: kind})
		if err != nil {
			return nil, err
		}
		if ForcedDue(st) {
			due = append(due, p)
		}
	}
	if len(due) > 0 {
		rt.Infof("indexing %s in %d account(s) whose cached inventory was marked due...", kind, len(due))
		if rt.dueIndexed == nil {
			rt.dueIndexed = map[dueKey]error{}
		}
		for _, p := range due {
			err := SyncError(rt.SyncAccount(ctx, p, []platform.ResourceType{kind}))
			if err != nil {
				rt.Infof("warning: index %s: %v", p.Label(), err)
				err = fmt.Errorf("%s: %w", p.Label(), err)
			}
			rt.dueIndexed[dueKey{p, kind}] = err
		}
	}
	// The outcome of this run, so that a later lookup reports what the
	// first one did.
	tried, errs := rt.dueOutcome(kind, profiles)
	if tried == 0 || len(errs) < tried {
		return nil, nil
	}
	return indexFailure(ctx, string(kind)+"s", "the account(s) whose cached inventory was marked due", errs), nil
}

// dueOutcome returns how many of profiles indexDue tried in this run for
// kind, and the errors of the ones that failed.
func (rt *Runtime) dueOutcome(kind platform.ResourceType, profiles []config.AccountRef) (tried int, errs []error) {
	for _, p := range profiles {
		err, done := rt.dueIndexed[dueKey{p, kind}]
		if !done {
			continue
		}
		tried++
		if err != nil {
			errs = append(errs, err)
		}
	}
	return tried, errs
}

// indexKind syncs kind in each of profiles. A failing account is a
// warning while another one succeeds; when every one fails the error says
// so (see IndexFailure), because a lookup that finds nothing then means
// "could not ask", not "unknown domain".
func (rt *Runtime) indexKind(ctx context.Context, kind platform.ResourceType, profiles []config.AccountRef) error {
	rt.Infof("indexing %s across %d account(s)...", kind, len(profiles))
	var errs []error
	for _, p := range profiles {
		if err := SyncError(rt.SyncAccount(ctx, p, []platform.ResourceType{kind})); err != nil {
			rt.Infof("warning: index %s: %v", p.Label(), err)
			errs = append(errs, fmt.Errorf("%s: %w", p.Label(), err))
		}
	}
	if len(profiles) == 0 || len(errs) < len(profiles) {
		return nil
	}
	return IndexFailure(ctx, string(kind)+"s", errs, len(profiles))
}

// SyncError is the error of a SyncAccount: its own, or else the first
// error of its reports (a type that failed does not stop the others, so
// SyncAccount itself does not return it).
func SyncError(reports []SyncReport, err error) error {
	if err != nil {
		return err
	}
	for _, r := range reports {
		if r.Err != nil {
			return r.Err
		}
		if r.Error != "" {
			return errors.New(r.Error)
		}
	}
	return nil
}

// IndexFailure is the error of an indexing in which errs failed out of
// total accounts: exit code 3 when every failure is a credential or
// permission one, 1 otherwise (the causes differ; the messages list them).
// A cancelled context is returned as is.
func IndexFailure(ctx context.Context, what string, errs []error, total int) error {
	which := "any account"
	if len(errs) < total {
		which = fmt.Sprintf("%d of %d account(s)", len(errs), total)
	}
	return indexFailure(ctx, what, which, errs)
}

// indexFailure is IndexFailure with the accounts that failed named by
// which.
func indexFailure(ctx context.Context, what, which string, errs []error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	auth := true
	msgs := make([]string, len(errs))
	for i, e := range errs {
		msgs[i] = e.Error()
		if !errors.Is(e, platform.ErrUnauthorized) && !errors.Is(e, platform.ErrForbidden) {
			auth = false
		}
	}
	if auth {
		return fmt.Errorf("could not index the %s of %s: %w", what, which, errors.Join(errs...))
	}
	return fmt.Errorf("could not index the %s of %s: %s", what, which, strings.Join(msgs, "; "))
}

// IndexForLookup indexes kind for the lookup of a domain the index does
// not hold, as ResolveDomain would, but without resolving an owner (so it
// never asks which one): with --refresh once per run, otherwise only when
// no candidate account of kind was ever indexed. The accounts whose set
// was marked due are a matter of IndexDue, which the caller runs before its
// lookup. The error is that of indexKind: every account failed.
func (rt *Runtime) IndexForLookup(ctx context.Context, kind platform.ResourceType) error {
	profiles, err := rt.indexCandidates(ctx, kind)
	if err != nil || len(profiles) == 0 || rt.Flags.Offline {
		return err
	}
	if rt.Flags.Refresh {
		return rt.refreshIndex(ctx, kind, profiles)
	}
	db, err := rt.DB()
	if err != nil {
		return err
	}
	for _, p := range profiles {
		st, err := db.GetState(ctx, inventory.Set{Platform: p.Platform, Profile: p.Profile, Type: kind})
		if err != nil {
			return err
		}
		if st != nil {
			return nil
		}
	}
	return rt.indexKind(ctx, kind, profiles)
}

// ConfiguredEntries keeps the index entries of accounts that are still in
// the config. Rows of an account that was logged out with --keep-inventory,
// or removed from the config by hand, stay in the index but take no part in
// routing, so pickers, domain which, domain list and completion leave them
// out as well.
func (rt *Runtime) ConfiguredEntries(entries []inventory.IndexEntry) ([]inventory.IndexEntry, error) {
	cfg, err := rt.Config()
	if err != nil {
		return nil, err
	}
	known := map[config.AccountRef]bool{}
	for _, ref := range cfg.Accounts("") {
		known[ref] = true
	}
	var out []inventory.IndexEntry
	for _, e := range entries {
		if known[config.AccountRef{Profile: e.Profile, Platform: e.Platform}] {
			out = append(out, e)
		}
	}
	return out, nil
}

// indexCandidates returns the accounts able to hold kind, restricted to
// --profile and --platform when they are set.
func (rt *Runtime) indexCandidates(ctx context.Context, kind platform.ResourceType) ([]config.AccountRef, error) {
	return rt.AccountsFor(kind)
}

// OpenDNS opens the DNS client that owns t.
func (rt *Runtime) OpenDNS(ctx context.Context, t *Target) (platform.DNSService, error) {
	c, _, err := rt.Open(ctx, t.Profile, t.Platform)
	if err != nil {
		return nil, err
	}
	dns, ok := c.(platform.DNSService)
	if !ok {
		return nil, fmt.Errorf("%s: DNS %w", t.Platform, platform.ErrNotSupported)
	}
	return dns, nil
}

// OpenRegistrar opens the registrar client that owns t.
func (rt *Runtime) OpenRegistrar(ctx context.Context, t *Target) (platform.RegistrarService, error) {
	c, _, err := rt.Open(ctx, t.Profile, t.Platform)
	if err != nil {
		return nil, err
	}
	reg, ok := c.(platform.RegistrarService)
	if !ok {
		return nil, fmt.Errorf("%s: registrar %w", t.Platform, platform.ErrNotSupported)
	}
	return reg, nil
}

// ZoneRecords returns the records of a zone, from cache or remote per flags.
func (rt *Runtime) ZoneRecords(ctx context.Context, t *Target) ([]platform.Record, bool, error) {
	set := inventory.Set{Platform: t.Platform, Profile: t.Profile, Type: platform.ResDNSRecord, Scope: t.ResourceID}
	rows, cached, err := rt.EnsureSet(ctx, set, func(ctx context.Context) ([]platform.Resource, error) {
		dns, err := rt.OpenDNS(ctx, t)
		if err != nil {
			return nil, err
		}
		recs, err := dns.ListRecords(ctx, t.ResourceID)
		if err != nil {
			return nil, err
		}
		return RecordResources(t.ResourceID, t.Domain, recs), nil
	})
	if err != nil {
		return nil, cached, err
	}
	out := make([]platform.Record, 0, len(rows))
	for _, r := range rows {
		var rec platform.Record
		if err := r.Decode(&rec); err != nil {
			return nil, cached, fmt.Errorf("decode cached record %s: %w", r.ID, err)
		}
		out = append(out, rec)
	}
	return out, cached, nil
}

// RecordResources converts records to inventory resources.
func RecordResources(zoneID, zoneName string, recs []platform.Record) []platform.Resource {
	out := make([]platform.Resource, 0, len(recs))
	for _, r := range recs {
		r.ZoneID = zoneID
		r.Name = platform.NormalizeDomain(r.Name)
		out = append(out, platform.Resource{Type: platform.ResDNSRecord, ID: r.ID, Name: r.Name, ParentID: zoneID, Domain: zoneName, Data: r})
	}
	return out
}

// ZoneResources converts zones to inventory resources.
func ZoneResources(zones []platform.Zone) []platform.Resource {
	out := make([]platform.Resource, 0, len(zones))
	for _, z := range zones {
		z.Name = platform.NormalizeDomain(z.Name)
		out = append(out, platform.Resource{Type: platform.ResZone, ID: z.ID, Name: z.Name, Domain: z.Name, Data: z})
	}
	return out
}

// DomainResources converts registered domains to inventory resources.
func DomainResources(domains []platform.Domain) []platform.Resource {
	out := make([]platform.Resource, 0, len(domains))
	for _, d := range domains {
		d.Name = platform.NormalizeDomain(d.Name)
		out = append(out, platform.Resource{Type: platform.ResDomain, ID: d.Name, Name: d.Name, Domain: d.Name, Data: d})
	}
	return out
}

// MatchRecords filters records by FQDN name, type and (optionally) value;
// the value is compared as platform.RecordValueMatches does.
func MatchRecords(recs []platform.Record, fqdn, typ, value string) []platform.Record {
	fqdn = platform.NormalizeDomain(fqdn)
	typ = strings.ToUpper(typ)
	var out []platform.Record
	for _, r := range recs {
		if platform.NormalizeDomain(r.Name) != fqdn {
			continue
		}
		if typ != "" && strings.ToUpper(r.Type) != typ {
			continue
		}
		if value != "" && !platform.RecordValueMatches(r, value) {
			continue
		}
		out = append(out, r)
	}
	return out
}
