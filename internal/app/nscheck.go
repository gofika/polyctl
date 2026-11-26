package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

// Statuses of an NS check (NSCheckResult.Status).
const (
	NSStatusOK       = "ok"
	NSStatusPartial  = "partial"
	NSStatusMismatch = "mismatch"
	NSStatusNoZone   = "no-zone"
	NSStatusNoLive   = "no-live"
	NSStatusUnknown  = "unknown"
)

// How a zone's nameservers compare with the live ones (NSView.LiveMatch).
const (
	NSLiveEqual   = "equal"
	NSLivePartial = "partial"
	NSLiveNone    = "none"
)

// NSCheckOptions configures Runtime.NSCheck.
type NSCheckOptions struct {
	// Domain is the name the user gave.
	Domain string
	// Resolvers are host:port addresses (see platform.ParseResolver).
	Resolvers []string
	// Timeout is the timeout of one DNS query.
	Timeout time.Duration
	// NoRegistrar and NoZone skip a side.
	NoRegistrar, NoZone bool
}

// NSView is one side of an NS check: the registrar, a hosted zone or the
// live resolution. NS is always a list (empty when the side has none).
type NSView struct {
	Platform platform.ID `json:"platform,omitempty" yaml:"platform,omitempty"`
	Profile  string      `json:"profile,omitempty" yaml:"profile,omitempty"`
	ZoneID   string      `json:"zone_id,omitempty" yaml:"zone_id,omitempty"`
	NS       []string    `json:"ns" yaml:"ns"`
	// Status is the zone status the platform reports (Cloudflare active /
	// pending, ...).
	Status string `json:"status,omitempty" yaml:"status,omitempty"`
	// Resolver is the resolver whose answer was used (live side).
	Resolver string `json:"resolver,omitempty" yaml:"resolver,omitempty"`
	// Result is the outcome of the live query (OK, NXDOMAIN, NODATA,
	// SERVFAIL, TIMEOUT, UNAVAILABLE, ...).
	Result string `json:"result,omitempty" yaml:"result,omitempty"`
	// LiveMatch says how a zone's nameservers compare with the live ones:
	// equal, partial or none (zones only, when the live side has NS).
	LiveMatch string `json:"live_match,omitempty" yaml:"live_match,omitempty"`
	// MirrorsRegistrar marks a zone that the registrar account lists for
	// the registration itself (its nameservers are the registration's):
	// it is considered only when no other zone exists.
	MirrorsRegistrar bool   `json:"mirrors_registrar,omitempty" yaml:"mirrors_registrar,omitempty"`
	Available        bool   `json:"available" yaml:"available"`
	Skipped          bool   `json:"skipped,omitempty" yaml:"skipped,omitempty"`
	Reason           string `json:"reason,omitempty" yaml:"reason,omitempty"`

	err error
}

// Account returns "platform/profile", or "".
func (v NSView) Account() string {
	if v.Platform == "" {
		return ""
	}
	return string(v.Platform) + "/" + v.Profile
}

// NSMatch holds the pairwise comparisons; null when a side is missing.
type NSMatch struct {
	RegistrarVsZone *bool `json:"registrar_vs_zone" yaml:"registrar_vs_zone"`
	LiveVsZone      *bool `json:"live_vs_zone" yaml:"live_vs_zone"`
	RegistrarVsLive *bool `json:"registrar_vs_live" yaml:"registrar_vs_live"`
}

// NSCheckResult is the report of `domain ns check`.
type NSCheckResult struct {
	Domain        string `json:"domain" yaml:"domain"`
	CheckedDomain string `json:"checked_domain" yaml:"checked_domain"`
	Registrar     NSView `json:"registrar" yaml:"registrar"`
	// Zone is the hosted zone the comparison uses: the candidate whose
	// nameservers match the live ones best.
	Zone NSView `json:"zone" yaml:"zone"`
	// Zones lists every hosted zone of the domain that was found.
	Zones         []NSView `json:"zones" yaml:"zones"`
	Live          NSView   `json:"live" yaml:"live"`
	ProviderGuess string   `json:"provider_guess" yaml:"provider_guess"`
	// Providers lists the DNS hosts when ProviderGuess is "mixed".
	Providers []string `json:"providers,omitempty" yaml:"providers,omitempty"`
	Match     NSMatch  `json:"match" yaml:"match"`
	Status    string   `json:"status" yaml:"status"`
	Message   string   `json:"message" yaml:"message"`

	// Failed is set when every side that was asked failed: the command
	// then exits with the general error code after printing the report.
	Failed error `json:"-" yaml:"-"`
}

// ErrNSCheckFailed is wrapped by NSCheckResult.Failed.
var ErrNSCheckFailed = errors.New("every side of the NS check failed")

// NSCheck compares the nameservers of the registered domain of
// opts.Domain at its registrar, in the hosted zones that hold it, and as
// public resolvers see them now. The live lookup runs concurrently with
// the account lookups; a failing side is reported and does not stop the
// others. It returns an error only for what makes the check meaningless:
// a selection (--profile / --platform) that names no usable account, an
// authentication failure of the selected accounts, or a domain the
// selected platform does not hold.
func (rt *Runtime) NSCheck(ctx context.Context, opts NSCheckOptions) (*NSCheckResult, error) {
	checked, err := platform.RegisteredDomain(opts.Domain)
	if err != nil {
		return nil, UsageErrf("invalid domain: %v", err)
	}
	if opts.NoRegistrar && opts.NoZone {
		return nil, UsageErrf("--no-registrar and --no-zone cannot both be given: at least one side has to be compared with the live nameservers")
	}
	if rt.Flags.Offline {
		return nil, fmt.Errorf("%w: domain ns check queries public resolvers and the platforms live", ErrOffline)
	}
	only, err := rt.RoutePlatform()
	if err != nil {
		return nil, err
	}
	// Validates --profile before anything is asked.
	if _, err := rt.Accounts(); err != nil {
		return nil, err
	}
	if only != "" {
		prov, err := platform.Get(only)
		if err != nil {
			return nil, err
		}
		if (opts.NoZone || !platform.Supports(prov, platform.ResZone)) && (opts.NoRegistrar || !platform.Supports(prov, platform.ResDomain)) {
			return nil, fmt.Errorf("%s: reading the nameservers of the requested side %w", only, platform.ErrNotSupported)
		}
	}

	res := &NSCheckResult{Domain: platform.NormalizeDomain(opts.Domain), CheckedDomain: checked, Zones: []NSView{}}
	if res.CheckedDomain != res.Domain {
		rt.Infof("checking the registered domain %s of %s", checked, res.Domain)
	}

	liveCh := make(chan platform.LiveNSResult, 1)
	go func() { liveCh <- platform.LiveNS(ctx, checked, opts.Resolvers, opts.Timeout) }()

	var authErrs []error
	if opts.NoRegistrar {
		res.Registrar = NSView{NS: []string{}, Skipped: true, Reason: "skipped (--no-registrar)"}
	} else {
		res.Registrar = rt.nsRegistrar(ctx, checked)
		if res.Registrar.err != nil && errors.Is(res.Registrar.err, platform.ErrUnauthorized) {
			authErrs = append(authErrs, res.Registrar.err)
		}
	}
	var zoneErrs []error
	if opts.NoZone {
		res.Zone = NSView{NS: []string{}, Skipped: true, Reason: "skipped (--no-zone)"}
	} else {
		res.Zones, zoneErrs = rt.nsZones(ctx, checked)
		for _, e := range zoneErrs {
			if errors.Is(e, platform.ErrUnauthorized) {
				authErrs = append(authErrs, e)
			}
		}
	}
	live := <-liveCh
	res.Live = liveView(checked, live)

	zoneFound := false
	for _, z := range res.Zones {
		if z.Available {
			zoneFound = true
		}
	}
	selected := rt.Flags.Profile != "" || only != ""
	if selected && len(authErrs) > 0 && !res.Registrar.Available && !zoneFound {
		return nil, authErrs[0]
	}
	if only != "" && len(zoneErrs) == 0 && res.Registrar.err == nil && !res.Registrar.Available && !zoneFound {
		return nil, fmt.Errorf("%w: %s is neither registered nor hosted in the accounts on %s", platform.ErrNotFound, checked, only)
	}

	res.evaluate(opts.NoZone, zoneErrs)

	regFailed := opts.NoRegistrar || res.Registrar.err != nil
	zoneFailed := opts.NoZone || (len(zoneErrs) > 0 && !zoneFound)
	if !res.Live.Available && regFailed && zoneFailed && !(opts.NoRegistrar && opts.NoZone) {
		var errs []error
		if res.Registrar.err != nil {
			errs = append(errs, fmt.Errorf("registrar: %w", res.Registrar.err))
		}
		for _, e := range zoneErrs {
			errs = append(errs, fmt.Errorf("zone: %w", e))
		}
		errs = append(errs, fmt.Errorf("live: %s", res.Live.Reason))
		res.Failed = fmt.Errorf("%w: %w", ErrNSCheckFailed, errors.Join(errs...))
	}
	return res, nil
}

// liveView turns a live lookup into the live side of the report.
func liveView(domain string, r platform.LiveNSResult) NSView {
	v := NSView{NS: []string{}, Resolver: hostOf(r.Resolver), Result: r.Kind, Available: r.Available()}
	switch r.Kind {
	case platform.NSOK:
		v.NS = r.Nameservers
	case platform.NSNXDomain:
		v.Reason = "NXDOMAIN: the domain does not exist (or has expired)"
	case platform.NSNoData:
		v.Reason = "NODATA: the name has no NS records"
		if r.ZoneApex != "" && r.ZoneApex != domain {
			v.Reason += fmt.Sprintf("; %s is not a zone apex, check its registered domain %s", domain, r.ZoneApex)
		}
	case platform.NSServFail:
		v.Reason = "SERVFAIL: the resolvers cannot resolve the domain, usually a broken delegation or DNSSEC; check the DS record at the registrar"
	case platform.NSTimeout:
		v.Reason = "resolution timed out: no resolver answered"
	case platform.NSUnavailable:
		v.Reason = "resolvers unavailable"
		if r.Err != nil {
			v.Reason += ": " + r.Err.Error()
		}
	default:
		v.Reason = fmt.Sprintf("the resolvers answered %s", r.Kind)
	}
	return v
}

// hostOf strips the default port from a resolver address for display.
func hostOf(addr string) string {
	if h, ok := strings.CutSuffix(addr, ":53"); ok {
		return strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	}
	return addr
}

// nsAccountEntries returns the index entries of kind for exactly domain in
// the accounts the selection allows. The sets marked due are synced before
// the lookup, as routing does (IndexDue): one of them may hold a second
// zone of the domain. When there are no entries, or with --refresh, the
// accounts whose set is missing or expired (all of them with --refresh)
// are synced first. Sync failures are returned: an account that could not
// be listed may hold the domain.
func (rt *Runtime) nsAccountEntries(ctx context.Context, domain string, kind platform.ResourceType) ([]inventory.IndexEntry, []error, error) {
	accounts, err := rt.AccountsFor(kind)
	if err != nil {
		return nil, nil, err
	}
	if len(accounts) == 0 {
		return nil, nil, nil
	}
	db, err := rt.DB()
	if err != nil {
		return nil, nil, err
	}
	allowed := map[string]bool{}
	for _, a := range accounts {
		allowed[string(a.Platform)+"/"+a.Profile] = true
	}
	lookup := func() ([]inventory.IndexEntry, error) {
		entries, err := db.LookupDomain(ctx, []string{domain}, kind)
		if err != nil {
			return nil, err
		}
		var out []inventory.IndexEntry
		seen := map[string]bool{}
		for _, e := range entries {
			k := string(e.Platform) + "/" + e.Profile
			if e.Domain != domain || !allowed[k] || seen[k+"/"+e.ResourceID] {
				continue
			}
			seen[k+"/"+e.ResourceID] = true
			out = append(out, e)
		}
		return out, nil
	}
	if _, err := rt.indexDue(ctx, kind, accounts); err != nil {
		return nil, nil, err
	}
	_, dueErrs := rt.dueOutcome(kind, accounts)
	entries, err := lookup()
	if err != nil {
		return nil, nil, err
	}
	if len(entries) > 0 && !rt.Flags.Refresh {
		return entries, dueErrs, nil
	}
	var stale []config.AccountRef
	for _, a := range accounts {
		// An account marked due was tried above, once per run.
		if _, done := rt.dueIndexed[dueKey{a, kind}]; done {
			continue
		}
		st, err := db.GetState(ctx, inventory.Set{Platform: a.Platform, Profile: a.Profile, Type: kind})
		if err != nil {
			return nil, nil, err
		}
		if rt.Flags.Refresh || !st.Fresh(time.Now()) {
			stale = append(stale, a)
		}
	}
	syncErrs := dueErrs
	if len(stale) > 0 {
		rt.Infof("indexing %s across %d account(s)...", kind, len(stale))
	}
	for _, a := range stale {
		reps, err := rt.SyncAccount(ctx, a, []platform.ResourceType{kind})
		if err == nil {
			for _, r := range reps {
				if r.Err != nil {
					err = r.Err
					break
				}
			}
		}
		if err != nil {
			rt.Verbosef("index %s: %v", a.Label(), err)
			syncErrs = append(syncErrs, fmt.Errorf("%s: %w", a.Label(), err))
		}
	}
	if entries, err = lookup(); err != nil {
		return nil, nil, err
	}
	return entries, syncErrs, nil
}

// nsRegistrar reads the nameservers of domain at the registrar account
// that holds it. A domain no registrar account holds is not an error.
func (rt *Runtime) nsRegistrar(ctx context.Context, domain string) NSView {
	v := NSView{NS: []string{}}
	entries, syncErrs, err := rt.nsAccountEntries(ctx, domain, platform.ResDomain)
	if err != nil {
		v.err, v.Reason = err, err.Error()
		return v
	}
	var errs []error
	for _, e := range entries {
		t := &Target{Platform: e.Platform, Profile: e.Profile, Type: e.Type, ResourceID: e.ResourceID, Domain: e.Domain}
		reg, err := rt.OpenRegistrar(ctx, t)
		var d *platform.Domain
		if err == nil {
			d, err = reg.GetDomain(ctx, domain)
		}
		if errors.Is(err, platform.ErrNotFound) {
			rt.Verbosef("registrar %s/%s no longer holds %s", e.Platform, e.Profile, domain)
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s/%s: %w", e.Platform, e.Profile, err))
			continue
		}
		return NSView{Platform: e.Platform, Profile: e.Profile, NS: platform.NormalizeNS(d.Nameservers), Available: true}
	}
	errs = append(errs, syncErrs...)
	if len(errs) > 0 {
		v.err = errors.Join(errs...)
		v.Reason = "registrar could not be read: " + errMessages(errs)
		return v
	}
	v.Reason = "the domain is not in a registrar account polyctl is logged in to"
	return v
}

// nsZones reads every hosted zone of domain in the selected accounts.
// Private zones (Route 53, Cloud DNS) and zones a registrar keeps but does
// not serve are left out.
func (rt *Runtime) nsZones(ctx context.Context, domain string) ([]NSView, []error) {
	out := []NSView{}
	entries, syncErrs, err := rt.nsAccountEntries(ctx, domain, platform.ResZone)
	if err != nil {
		return out, []error{err}
	}
	var errs []error
	for _, e := range entries {
		t := &Target{Platform: e.Platform, Profile: e.Profile, Type: e.Type, ResourceID: e.ResourceID, Domain: e.Domain}
		v := NSView{Platform: e.Platform, Profile: e.Profile, ZoneID: e.ResourceID, NS: []string{}}
		z, err := rt.nsZone(ctx, t)
		if errors.Is(err, platform.ErrNotFound) {
			rt.Verbosef("zone %s on %s/%s no longer exists", e.ResourceID, e.Platform, e.Profile)
			continue
		}
		if err != nil {
			err = fmt.Errorf("%s/%s: %w", e.Platform, e.Profile, err)
			errs = append(errs, err)
			v.err, v.Reason = err, err.Error()
			out = append(out, v)
			continue
		}
		if z.Status == "private" || z.Status == "inactive" {
			continue
		}
		v.NS, v.Status, v.Available = platform.NormalizeNS(z.Nameservers), z.Status, true
		out = append(out, v)
	}
	return out, append(errs, syncErrs...)
}

// nsZone reads one zone live: with GetZone when the client has it, else
// from the zone list.
func (rt *Runtime) nsZone(ctx context.Context, t *Target) (*platform.Zone, error) {
	dns, err := rt.OpenDNS(ctx, t)
	if err != nil {
		return nil, err
	}
	if g, ok := dns.(platform.ZoneGetter); ok {
		return g.GetZone(ctx, t.ResourceID)
	}
	zones, err := dns.ListZones(ctx)
	if err != nil {
		return nil, err
	}
	for _, z := range zones {
		if z.ID == t.ResourceID {
			return &z, nil
		}
	}
	return nil, fmt.Errorf("%w: zone %s", platform.ErrNotFound, t.ResourceID)
}

func errMessages(errs []error) string {
	msgs := make([]string, 0, len(errs))
	for _, e := range errs {
		msgs = append(msgs, e.Error())
	}
	return strings.Join(msgs, "; ")
}

func boolp(b bool) *bool { return &b }

// evaluate picks the zone the comparison uses, fills the comparisons, the
// status, the provider guess and the message.
func (r *NSCheckResult) evaluate(noZone bool, zoneErrs []error) {
	reg, live := r.Registrar, r.Live
	liveHasNS := live.Available && len(live.NS) > 0
	for i := range r.Zones {
		z := &r.Zones[i]
		if !z.Available {
			continue
		}
		z.MirrorsRegistrar = reg.Available && z.Platform == reg.Platform && z.Profile == reg.Profile && platform.SameNS(z.NS, reg.NS)
		if liveHasNS {
			switch {
			case platform.SameNS(z.NS, live.NS):
				z.LiveMatch = NSLiveEqual
			case platform.OverlapNS(z.NS, live.NS):
				z.LiveMatch = NSLivePartial
			default:
				z.LiveMatch = NSLiveNone
			}
		}
	}
	if !noZone {
		r.Zone = bestZone(r.Zones)
		if !r.Zone.Available && r.Zone.Reason == "" {
			if len(zoneErrs) > 0 {
				r.Zone.Reason = "zones could not be read: " + errMessages(zoneErrs)
			} else {
				r.Zone.Reason = "no hosted zone for the domain in the accounts polyctl is logged in to"
			}
		}
	}
	zone := r.Zone
	if reg.Available && zone.Available {
		r.Match.RegistrarVsZone = boolp(platform.SameNS(reg.NS, zone.NS))
	}
	if live.Available && zone.Available {
		r.Match.LiveVsZone = boolp(platform.SameNS(live.NS, zone.NS))
	}
	if reg.Available && live.Available {
		r.Match.RegistrarVsLive = boolp(platform.SameNS(reg.NS, live.NS))
	}

	guessFrom := live.NS
	if len(guessFrom) == 0 {
		guessFrom = zone.NS
	}
	r.ProviderGuess, r.Providers = platform.GuessProvider(guessFrom)

	switch {
	case noZone:
		r.Status = NSStatusUnknown
		r.Message = "the hosted zone was not checked (--no-zone): only the facts of each side are shown"
	case !zone.Available && len(zoneErrs) == 0:
		r.Status = NSStatusNoZone
		r.Message = fmt.Sprintf("%s has no hosted zone in the accounts polyctl is logged in to", r.CheckedDomain)
	case !zone.Available:
		r.Status = NSStatusUnknown
		r.Message = "the hosted zone could not be read: " + zone.Reason
	case !live.Available:
		r.Status = NSStatusUnknown
		r.Message = "the live nameservers could not be resolved: " + live.Reason
	case !liveHasNS:
		r.Status = NSStatusNoLive
		r.Message = live.Reason
	case platform.SameNS(live.NS, zone.NS) && (!reg.Available || platform.SameNS(reg.NS, zone.NS)):
		r.Status = NSStatusOK
		r.Message = "the delegation points to the hosted zone"
	case platform.SameNS(live.NS, zone.NS):
		r.Status = NSStatusPartial
		r.Message = "resolvers return the hosted zone's nameservers, but the registrar lists others; the registrar data or the change may still be in progress"
	case platform.OverlapNS(live.NS, zone.NS):
		r.Status = NSStatusPartial
		r.Message = "the delegation partly points to the hosted zone: a migration in progress, or some nameservers were not updated"
	default:
		r.Status = NSStatusMismatch
		switch {
		case reg.Available && platform.SameNS(reg.NS, live.NS):
			r.Message = "the delegation does not point to the hosted nameservers yet; set the nameservers at the registrar to the zone's (polyctl domain ns set)"
		case reg.Available && platform.SameNS(reg.NS, zone.NS):
			r.Message = "the registrar already lists the zone's nameservers but resolvers still return others, probably cached (TTLs are often 1-48 hours); check again later"
		case reg.Available:
			r.Message = "the registrar's nameservers match neither the zone nor the live answer; set the nameservers at the registrar to the zone's (polyctl domain ns set)"
		default:
			r.Message = "the delegation does not point to the hosted nameservers; set the nameservers at the registrar to the zone's"
		}
	}
	if zone.Available && zone.Status == "pending" && r.Status != NSStatusOK {
		r.Message += "; the platform reports the zone as pending"
	}
}

// bestZone returns the zone the comparison uses: among the zones that were
// read, those that do not just mirror the registration come first; then the
// one whose nameservers equal the live ones, then one that overlaps them,
// then the first. Without a readable zone it returns an unavailable view.
func bestZone(zones []NSView) NSView {
	rank := func(z NSView) int {
		r := 0
		switch z.LiveMatch {
		case NSLiveEqual:
			r = 3
		case NSLivePartial:
			r = 2
		}
		if !z.MirrorsRegistrar {
			r += 10
		}
		return r
	}
	var cands []NSView
	for _, z := range zones {
		if z.Available {
			cands = append(cands, z)
		}
	}
	if len(cands) == 0 {
		return NSView{NS: []string{}}
	}
	// MaxFunc returns the first of equally ranked zones.
	return slices.MaxFunc(cands, func(a, b NSView) int { return rank(a) - rank(b) })
}
