package app

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
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
// longest matching domain in the index wins. If several accounts (or several
// resources of one account) own the same best match, an AmbiguousError is
// returned. When nothing is found and --refresh was given (or none of the
// candidate profiles has ever been indexed), the relevant profiles are
// indexed first and the lookup retried.
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
	lookup := func() (*Target, error) {
		entries, err := db.LookupDomain(ctx, cands, kind)
		if err != nil {
			return nil, err
		}
		if rt.Flags.Profile != "" || only != "" {
			var filtered []inventory.IndexEntry
			for _, e := range entries {
				if (rt.Flags.Profile == "" || e.Profile == rt.Flags.Profile) && (only == "" || e.Platform == only) {
					filtered = append(filtered, e)
				}
			}
			entries = filtered
		}
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
			var names []string
			profiles, platforms := map[string]bool{}, map[platform.ID]bool{}
			for _, o := range owners {
				names = append(names, fmt.Sprintf("%s/%s (%s %s)", o.Platform, o.Profile, o.Type, o.ResourceID))
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
			}
			return nil, &AmbiguousError{What: fmt.Sprintf("owner of %s %q", kind, best), Candidates: names, Hint: hint}
		}
		o := owners[0]
		return &Target{Platform: o.Platform, Profile: o.Profile, Type: o.Type, ResourceID: o.ResourceID, Domain: o.Domain}, nil
	}

	t, err := lookup()
	if err != nil || t != nil {
		return t, err
	}
	// Check the selection before blaming the index: an unknown --profile, or
	// a --profile / --platform pair that names no account, is not something
	// indexing can fix. This reads the config only, so it works offline too.
	profiles, err := rt.indexCandidates(ctx, kind)
	if err != nil {
		return nil, err
	}
	if len(profiles) == 0 && (rt.Flags.Profile != "" || only != "") {
		return nil, fmt.Errorf("%w: %q, and no account selected by --profile / --platform is able to manage %ss", ErrDomainUnknown, domain, kind)
	}
	if rt.Flags.Offline {
		return nil, fmt.Errorf("%w: %q (%s); run `polyctl domain index` when online", ErrDomainUnknown, domain, kind)
	}
	// Decide whether to (re)index automatically: always when --refresh, or
	// when the index has never been built for any of the candidate profiles.
	// Once at least one profile is indexed, a miss no longer triggers a
	// network scan: a profile whose sync keeps failing never gets a state,
	// and re-indexing everything on every miss would hammer the platforms.
	if len(profiles) == 0 {
		return nil, fmt.Errorf("%w: %q, and no account is able to manage %ss (run `polyctl auth login`)", ErrDomainUnknown, domain, kind)
	}
	needIndex := rt.Flags.Refresh
	if !needIndex {
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
		switch {
		case len(unindexed) == len(profiles):
			needIndex = true
		case len(unindexed) > 0:
			return nil, fmt.Errorf("%w: %q (%s); account(s) %s not indexed yet, run `polyctl domain index` or retry with --refresh", ErrDomainUnknown, domain, kind, strings.Join(unindexed, ", "))
		}
	}
	if !needIndex {
		return nil, fmt.Errorf("%w: %q (%s); run `polyctl domain index` or retry with --refresh", ErrDomainUnknown, domain, kind)
	}
	rt.Infof("indexing %s across %d account(s)...", kind, len(profiles))
	for _, p := range profiles {
		if _, err := rt.SyncAccount(ctx, p, []platform.ResourceType{kind}); err != nil {
			rt.Infof("warning: index %s: %v", p.Label(), err)
		}
	}
	t, err = lookup()
	if err != nil {
		return nil, err
	}
	if t == nil {
		where := "any configured account"
		if rt.Flags.Profile != "" || only != "" {
			where = "the accounts selected by --profile / --platform"
		}
		return nil, fmt.Errorf("%w: %q is not a %s in %s", ErrDomainUnknown, domain, kind, where)
	}
	return t, nil
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

// MatchRecords filters records by FQDN name, type and (optionally) content.
func MatchRecords(recs []platform.Record, fqdn, typ, content string) []platform.Record {
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
		if content != "" && r.Content != content {
			continue
		}
		out = append(out, r)
	}
	return out
}
