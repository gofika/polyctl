package app

import (
	"context"
	"errors"
	"fmt"
	"strings"

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
// Precedence: --profile restricts the search to that profile; otherwise the
// longest matching domain in the index wins. If several profiles own the same
// best match, an AmbiguousError is returned. When nothing is found and
// --refresh was given (or the index is empty), the relevant profiles are
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
	lookup := func() (*Target, error) {
		entries, err := db.LookupDomain(ctx, cands, kind)
		if err != nil {
			return nil, err
		}
		if rt.Flags.Profile != "" {
			var filtered []inventory.IndexEntry
			for _, e := range entries {
				if e.Profile == rt.Flags.Profile {
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
			k := string(e.Platform) + "/" + e.Profile
			if !seen[k] {
				seen[k] = true
				owners = append(owners, e)
			}
		}
		if len(owners) > 1 {
			var names []string
			for _, o := range owners {
				names = append(names, fmt.Sprintf("%s (%s)", o.Profile, o.Platform))
			}
			return nil, &AmbiguousError{What: fmt.Sprintf("owner of %s %q", kind, best), Candidates: names}
		}
		o := owners[0]
		return &Target{Platform: o.Platform, Profile: o.Profile, Type: o.Type, ResourceID: o.ResourceID, Domain: o.Domain}, nil
	}

	t, err := lookup()
	if err != nil || t != nil {
		return t, err
	}
	if rt.Flags.Offline {
		return nil, fmt.Errorf("%w: %q (%s); run `polyctl domain index` when online", ErrDomainUnknown, domain, kind)
	}
	// Decide whether to (re)index automatically: always when --refresh, or
	// when the index has never been built for the candidate profiles.
	profiles, err := rt.indexCandidates(ctx, kind)
	if err != nil {
		return nil, err
	}
	if len(profiles) == 0 {
		return nil, fmt.Errorf("%w: %q, and no profile is able to manage %ss (run `polyctl auth login`)", ErrDomainUnknown, domain, kind)
	}
	needIndex := rt.Flags.Refresh
	if !needIndex {
		for _, p := range profiles {
			st, err := db.GetState(ctx, inventory.Set{Platform: p.Platform, Profile: p.Name, Type: kind})
			if err != nil {
				return nil, err
			}
			if st == nil {
				needIndex = true
				break
			}
		}
	}
	if !needIndex {
		return nil, fmt.Errorf("%w: %q (%s); run `polyctl domain index` or retry with --refresh", ErrDomainUnknown, domain, kind)
	}
	rt.Infof("indexing %s across %d profile(s)...", kind, len(profiles))
	for _, p := range profiles {
		if _, err := rt.SyncProfile(ctx, p.Name, []platform.ResourceType{kind}); err != nil {
			rt.Infof("warning: index %s/%s: %v", p.Platform, p.Name, err)
		}
	}
	t, err = lookup()
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, fmt.Errorf("%w: %q is not a %s in any configured profile", ErrDomainUnknown, domain, kind)
	}
	return t, nil
}

func (rt *Runtime) indexCandidates(ctx context.Context, kind platform.ResourceType) ([]platform.Profile, error) {
	cfg, err := rt.Config()
	if err != nil {
		return nil, err
	}
	names := cfg.ProfileNames()
	if rt.Flags.Profile != "" {
		names = []string{rt.Flags.Profile}
	}
	var out []platform.Profile
	for _, n := range names {
		p, ok := cfg.Profiles[n]
		if !ok {
			return nil, fmt.Errorf("profile %q not found", n)
		}
		prov, err := platform.Get(p.Platform)
		if err != nil || !platform.Supports(prov, kind) {
			continue
		}
		out = append(out, platform.Profile{Name: n, Platform: p.Platform, Metadata: p.Metadata})
	}
	return out, nil
}

// OpenTarget opens the client that owns t and asserts the service type.
func (rt *Runtime) OpenDNS(ctx context.Context, t *Target) (platform.DNSService, error) {
	c, _, err := rt.Open(ctx, t.Profile)
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
	c, _, err := rt.Open(ctx, t.Profile)
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
