package app_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

var ctx = context.Background()

// harness is a Runtime bound to a temporary config dir with three profiles,
// each holding one account: a and b on the (fake) name.com platform, c on the
// (fake) GoDaddy platform. Tests that need a profile with several accounts
// add it through mutate.
type harness struct {
	t              *testing.T
	rt             *app.Runtime
	dir            string
	stdout, stderr *bytes.Buffer
}

func newHarness(t *testing.T, flags app.Flags, mutate func(*config.Config)) *harness {
	t.Helper()
	registerFakes()
	resetFakes()
	dir := t.TempDir()
	t.Setenv(config.EnvConfigDir, dir)
	t.Setenv("POLYCTL_CREDENTIAL_STORE", "file")
	t.Setenv("POLYCTL_INVENTORY_DB", "")
	t.Setenv("POLYCTL_OUTPUT", "")

	cfgPath := filepath.Join(dir, "config.yaml")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.CredentialStore = "file"
	cfg.Profiles = map[string]*config.Profile{
		"a": profileOn(platform.NameCom),
		"b": profileOn(platform.NameCom),
		"c": profileOn(platform.GoDaddy),
	}
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	store := creds.NewFile(dir)
	for _, ref := range cfg.Accounts("") {
		if err := store.Set(creds.Key(ref.Profile, string(ref.Platform)), map[string]string{"token": secretOf(ref.Profile, ref.Platform)}); err != nil {
			t.Fatal(err)
		}
	}

	flags.ConfigDir = filepath.Dir(cfgPath)
	h := &harness{t: t, dir: dir, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	h.rt = app.New(flags, strings.NewReader(""), h.stdout, h.stderr)
	if err := h.rt.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { _ = h.rt.Close() })
	return h
}

func (h *harness) db() *inventory.DB {
	h.t.Helper()
	db, err := h.rt.DB()
	if err != nil {
		h.t.Fatal(err)
	}
	return db
}

// profileOn builds a profile holding one empty account per given platform.
func profileOn(ids ...platform.ID) *config.Profile {
	p := &config.Profile{Platforms: map[platform.ID]*config.Account{}}
	for _, id := range ids {
		p.Platforms[id] = &config.Account{}
	}
	return p
}

// secretOf is the token the harness stores for an account.
func secretOf(profile string, id platform.ID) string {
	return "secret-" + profile + "-" + string(id)
}

func ref(profile string, id platform.ID) config.AccountRef {
	return config.AccountRef{Profile: profile, Platform: id}
}

// platformOf returns the platform of a profile that holds exactly one
// account; tests on multi-account profiles name the platform explicitly.
func (h *harness) platformOf(profile string) platform.ID {
	h.t.Helper()
	cfg, _ := h.rt.Config()
	p, ok := cfg.Profiles[profile]
	if !ok {
		h.t.Fatalf("profile %q not in config", profile)
	}
	ids := p.PlatformIDs()
	if len(ids) != 1 {
		h.t.Fatalf("profile %q has %d accounts, want exactly one", profile, len(ids))
	}
	return ids[0]
}

// client returns the fake client of a single-account profile.
func (h *harness) client(profile string) *fakeClient {
	h.t.Helper()
	return clientFor(profile, h.platformOf(profile))
}

// seedZones writes a zone set for a single-account profile straight into
// the inventory, which also marks the zone index of that account as built.
func (h *harness) seedZones(profile string, zones ...platform.Zone) {
	h.t.Helper()
	h.seedZonesFor(ref(profile, h.platformOf(profile)), zones...)
}

// seedZonesFor does the same for one account of any profile.
func (h *harness) seedZonesFor(r config.AccountRef, zones ...platform.Zone) {
	h.t.Helper()
	s := inventory.Set{Platform: r.Platform, Profile: r.Profile, Type: platform.ResZone}
	if err := h.db().Replace(ctx, s, app.ZoneResources(zones), time.Hour); err != nil {
		h.t.Fatal(err)
	}
}

func zone(id, name string) platform.Zone { return platform.Zone{ID: id, Name: name} }

func (h *harness) seedStandard() {
	h.seedZones("a", zone("z-example", "example.com"), zone("z-shared-a", "shared.com"))
	h.seedZones("b", zone("z-other", "other.com"), zone("z-shared-b", "shared.com"), zone("z-sub", "sub.example.com"))
	h.seedZones("c")
}

func TestResolveDomainLongestMatch(t *testing.T) {
	h := newHarness(t, app.Flags{}, nil)
	h.seedStandard()

	cases := []struct {
		domain, profile, zone, id string
	}{
		{"www.example.com", "a", "example.com", "z-example"},
		{"example.com", "a", "example.com", "z-example"},
		{"Example.COM.", "a", "example.com", "z-example"},
		{"deep.sub.example.com", "b", "sub.example.com", "z-sub"},
		{"sub.example.com", "b", "sub.example.com", "z-sub"},
		{"mail.other.com", "b", "other.com", "z-other"},
	}
	for _, c := range cases {
		tgt, err := h.rt.ResolveDomain(ctx, c.domain, platform.ResZone)
		if err != nil {
			t.Errorf("ResolveDomain(%q): %v", c.domain, err)
			continue
		}
		if tgt.Profile != c.profile || tgt.Domain != c.zone || tgt.ResourceID != c.id || tgt.Type != platform.ResZone || tgt.Platform != h.platformOf(c.profile) {
			t.Errorf("ResolveDomain(%q) = %+v, want profile %s zone %s id %s", c.domain, tgt, c.profile, c.zone, c.id)
		}
	}
	// Nothing was fetched: every answer came from the index.
	for _, p := range []string{"a", "b", "c"} {
		if n := h.client(p).count("Sync"); n != 0 {
			t.Errorf("profile %s synced %d times, want 0", p, n)
		}
	}
	if tgt, _ := h.rt.ResolveDomain(ctx, "www.example.com", platform.ResZone); tgt != nil && !strings.Contains(tgt.String(), "namecom/a (zone example.com)") {
		t.Errorf("Target.String() = %q", tgt.String())
	}
}

func TestResolveDomainAmbiguous(t *testing.T) {
	h := newHarness(t, app.Flags{}, nil)
	h.seedStandard()

	_, err := h.rt.ResolveDomain(ctx, "www.shared.com", platform.ResZone)
	var amb *app.AmbiguousError
	if !errors.As(err, &amb) {
		t.Fatalf("ResolveDomain(shared.com) = %v, want *app.AmbiguousError", err)
	}
	if len(amb.Candidates) != 2 || amb.Candidates[0] != "namecom/a (zone z-shared-a)" || amb.Candidates[1] != "namecom/b (zone z-shared-b)" {
		t.Errorf("candidates = %v", amb.Candidates)
	}
	// Both candidates are on one platform: only --profile tells them apart.
	if !strings.Contains(err.Error(), "pass --profile <name> to choose") || strings.Contains(err.Error(), "--platform") {
		t.Errorf("error should hint at --profile only: %v", err)
	}
	// A profile that owns the best match plus another that only owns a
	// shorter match is not ambiguous: the longest match wins.
	h.seedZones("c", zone("z-wild", "sub.example.com"))
	if _, err := h.rt.ResolveDomain(ctx, "x.sub.example.com", platform.ResZone); !errors.As(err, &amb) {
		t.Errorf("same zone in b and c must be ambiguous: %v", err)
	} else if amb.Hint != "pass --profile <name> and/or --platform <platform> to choose" {
		// b and c differ in both profile and platform: either flag works.
		t.Errorf("hint = %q", amb.Hint)
	}
	if tgt, err := h.rt.ResolveDomain(ctx, "www.example.com", platform.ResZone); err != nil || tgt.Profile != "a" {
		t.Errorf("example.com is only owned by a: %+v, %v", tgt, err)
	}
}

func TestResolveDomainProfileFlagBreaksTie(t *testing.T) {
	h := newHarness(t, app.Flags{Profile: "b"}, nil)
	h.seedStandard()

	tgt, err := h.rt.ResolveDomain(ctx, "www.shared.com", platform.ResZone)
	if err != nil {
		t.Fatalf("ResolveDomain with --profile b: %v", err)
	}
	if tgt.Profile != "b" || tgt.ResourceID != "z-shared-b" {
		t.Errorf("target = %+v, want profile b", tgt)
	}
	// --profile restricts the search: a domain owned only by another
	// profile is not found, and nothing is re-indexed since b's index exists.
	_, err = h.rt.ResolveDomain(ctx, "www.example.com", platform.ResZone)
	if !errors.Is(err, app.ErrDomainUnknown) {
		t.Fatalf("ResolveDomain(example.com) with --profile b = %v, want ErrDomainUnknown", err)
	}
	if n := h.client("b").count("Sync"); n != 0 {
		t.Errorf("profile b was re-synced %d times although its index exists", n)
	}
	if n := h.client("a").count("Sync"); n != 0 {
		t.Errorf("profile a must not be touched when --profile b is given: %d syncs", n)
	}
}

func TestResolveDomainOfflineUnknown(t *testing.T) {
	h := newHarness(t, app.Flags{Offline: true}, nil)
	_, err := h.rt.ResolveDomain(ctx, "www.example.com", platform.ResZone)
	if !errors.Is(err, app.ErrDomainUnknown) {
		t.Fatalf("offline unknown = %v, want ErrDomainUnknown", err)
	}
	if !strings.Contains(err.Error(), "domain index") {
		t.Errorf("error should tell the user to build the index: %v", err)
	}
	for _, p := range []string{"a", "b", "c"} {
		if n := h.client(p).count("Sync"); n != 0 {
			t.Errorf("offline must never sync (profile %s: %d)", p, n)
		}
	}
	// A seeded index still works offline.
	h.seedZones("a", zone("z1", "example.com"))
	if tgt, err := h.rt.ResolveDomain(ctx, "www.example.com", platform.ResZone); err != nil || tgt.Profile != "a" {
		t.Errorf("offline with index = %+v, %v", tgt, err)
	}
}

// Offline, a selection that names no account must be reported as such, the
// way it is online, and not as a gap in the index that indexing would fix.
func TestResolveDomainOfflineChecksTheSelection(t *testing.T) {
	seeded := func(flags app.Flags) *harness {
		flags.Offline = true
		h := newHarness(t, flags, nil)
		h.seedZones("a", zone("z1", "example.com"))
		return h
	}
	_, err := seeded(app.Flags{Profile: "nope"}).rt.ResolveDomain(ctx, "www.example.com", platform.ResZone)
	if !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), `profile "nope" not found`) {
		t.Errorf("unknown --profile offline = %v, want the profile reported as not found", err)
	}
	// Profile a has a name.com account only.
	_, err = seeded(app.Flags{Profile: "a", Platform: "godaddy"}).rt.ResolveDomain(ctx, "www.example.com", platform.ResZone)
	if !errors.Is(err, app.ErrDomainUnknown) || !strings.Contains(err.Error(), "no account selected by --profile / --platform") || strings.Contains(err.Error(), "domain index") {
		t.Errorf("--profile / --platform without an account offline = %v", err)
	}
	// A valid selection that simply misses still points at the index.
	_, err = seeded(app.Flags{Profile: "b"}).rt.ResolveDomain(ctx, "www.example.com", platform.ResZone)
	if !errors.Is(err, app.ErrDomainUnknown) || !strings.Contains(err.Error(), "run `polyctl domain index` when online") {
		t.Errorf("valid selection, miss offline = %v", err)
	}
	// And one that hits resolves.
	if tgt, err := seeded(app.Flags{Profile: "a", Platform: "namecom"}).rt.ResolveDomain(ctx, "www.example.com", platform.ResZone); err != nil || tgt.Profile != "a" {
		t.Errorf("valid selection, hit offline = %+v, %v", tgt, err)
	}
}

func TestResolveDomainAutoIndexesWhenIndexMissing(t *testing.T) {
	h := newHarness(t, app.Flags{}, nil)
	h.client("a").zones = []platform.Zone{zone("z1", "example.com")}

	tgt, err := h.rt.ResolveDomain(ctx, "www.example.com", platform.ResZone)
	if err != nil {
		t.Fatalf("ResolveDomain: %v", err)
	}
	if tgt.Profile != "a" || tgt.ResourceID != "z1" || tgt.Domain != "example.com" {
		t.Errorf("target = %+v", tgt)
	}
	for _, p := range []string{"a", "b", "c"} {
		if n := h.client(p).count("Sync:zone"); n != 1 {
			t.Errorf("profile %s zone sync count = %d, want 1", p, n)
		}
		if n := h.client(p).count("Sync:domain"); n != 0 {
			t.Errorf("profile %s synced domains although only zones were needed", p)
		}
	}
	if !strings.Contains(h.stderr.String(), "indexing zone across 3 account(s)") {
		t.Errorf("stderr = %q", h.stderr.String())
	}
	st, err := h.db().GetState(ctx, inventory.Set{Platform: platform.NameCom, Profile: "a", Type: platform.ResZone})
	if err != nil || !st.Fresh(time.Now()) {
		t.Errorf("index state after auto-index = %+v, %v", st, err)
	}

	// Once every profile is indexed, an unknown domain fails without
	// touching the network again (no --refresh).
	_, err = h.rt.ResolveDomain(ctx, "nope.org", platform.ResZone)
	if !errors.Is(err, app.ErrDomainUnknown) {
		t.Fatalf("unknown after index = %v, want ErrDomainUnknown", err)
	}
	if !strings.Contains(err.Error(), "--refresh") {
		t.Errorf("error should suggest --refresh: %v", err)
	}
	for _, p := range []string{"a", "b", "c"} {
		if n := h.client(p).count("Sync:zone"); n != 1 {
			t.Errorf("profile %s re-synced without --refresh (count %d)", p, n)
		}
	}
	// Registrar lookups use their own index and trigger their own sync.
	h.client("c").domains = []platform.Domain{{Name: "example.com", Nameservers: []string{"ns1.example.net"}}}
	reg, err := h.rt.ResolveDomain(ctx, "example.com", platform.ResDomain)
	if err != nil || reg.Profile != "c" || reg.Type != platform.ResDomain || reg.ResourceID != "example.com" {
		t.Errorf("registrar target = %+v, %v", reg, err)
	}
	if n := h.client("c").count("Sync:domain"); n != 1 {
		t.Errorf("profile c domain sync count = %d", n)
	}
}

func TestResolveDomainRefreshReindexes(t *testing.T) {
	h := newHarness(t, app.Flags{Refresh: true}, nil)
	h.seedStandard()
	h.client("a").zones = []platform.Zone{zone("z-new", "brandnew.io")}
	h.client("b").zones = []platform.Zone{zone("z-other", "other.com"), zone("z-shared-b", "shared.com"), zone("z-sub", "sub.example.com")}

	tgt, err := h.rt.ResolveDomain(ctx, "www.brandnew.io", platform.ResZone)
	if err != nil {
		t.Fatalf("ResolveDomain with --refresh: %v", err)
	}
	if tgt.Profile != "a" || tgt.ResourceID != "z-new" {
		t.Errorf("target = %+v", tgt)
	}
	if n := h.client("a").count("Sync:zone"); n != 1 {
		t.Errorf("profile a sync count = %d, want 1", n)
	}
	// The refresh replaced a's zones, so its old zone is gone from the index.
	if entries, _ := h.db().LookupDomain(ctx, []string{"example.com"}, platform.ResZone); len(entries) != 0 {
		t.Errorf("stale zone survived the refresh: %+v", entries)
	}
	// Index hits are still served without a sync even with --refresh.
	if _, err := h.rt.ResolveDomain(ctx, "www.other.com", platform.ResZone); err != nil {
		t.Errorf("ResolveDomain(other.com): %v", err)
	}
	if n := h.client("b").count("Sync:zone"); n != 1 {
		t.Errorf("profile b sync count = %d, want 1 (only the first miss indexes)", n)
	}
}

func TestResolveDomainInvalid(t *testing.T) {
	h := newHarness(t, app.Flags{Offline: true}, nil)
	for _, in := range []string{"", "com", "."} {
		if _, err := h.rt.ResolveDomain(ctx, in, platform.ResZone); err == nil || !strings.Contains(err.Error(), "invalid domain") {
			t.Errorf("ResolveDomain(%q) = %v, want invalid domain error", in, err)
		}
	}
}

func TestResolveDomainNoCapableProfile(t *testing.T) {
	h := newHarness(t, app.Flags{}, func(c *config.Config) {
		c.Profiles = map[string]*config.Profile{"cf": profileOn(platform.Cloudflare)}
	})
	// Cloudflare is not registered in this test binary, so no profile can
	// manage zones.
	_, err := h.rt.ResolveDomain(ctx, "example.com", platform.ResZone)
	if !errors.Is(err, app.ErrDomainUnknown) || !strings.Contains(err.Error(), "no account is able to manage zones (run `polyctl auth login`)") {
		t.Fatalf("err = %v", err)
	}
}

func TestEnsureSetCacheRefreshOffline(t *testing.T) {
	h := newHarness(t, app.Flags{}, nil)
	s := inventory.Set{Platform: platform.NameCom, Profile: "a", Type: platform.ResZone}
	fetches := 0
	fetch := func(ctx context.Context) ([]platform.Resource, error) {
		fetches++
		return app.ZoneResources([]platform.Zone{zone("z1", "example.com")}), nil
	}

	rows, cached, err := h.rt.EnsureSet(ctx, s, fetch)
	if err != nil {
		t.Fatalf("first EnsureSet: %v", err)
	}
	if cached || fetches != 1 || len(rows) != 1 || rows[0].ID != "z1" {
		t.Errorf("first call: cached=%v fetches=%d rows=%+v", cached, fetches, rows)
	}

	rows, cached, err = h.rt.EnsureSet(ctx, s, fetch)
	if err != nil {
		t.Fatalf("second EnsureSet: %v", err)
	}
	if !cached || fetches != 1 || len(rows) != 1 {
		t.Errorf("second call must be served from cache: cached=%v fetches=%d rows=%d", cached, fetches, len(rows))
	}

	// --refresh forces a fetch even when fresh.
	h.rt.Flags.Refresh = true
	_, cached, err = h.rt.EnsureSet(ctx, s, fetch)
	if err != nil || cached || fetches != 2 {
		t.Errorf("--refresh: cached=%v fetches=%d err=%v", cached, fetches, err)
	}
	h.rt.Flags.Refresh = false

	// --offline serves the cache and never fetches.
	h.rt.Flags.Offline = true
	rows, cached, err = h.rt.EnsureSet(ctx, s, fetch)
	if err != nil || !cached || fetches != 2 || len(rows) != 1 {
		t.Errorf("--offline cached: cached=%v fetches=%d rows=%d err=%v", cached, fetches, len(rows), err)
	}
	// --offline with nothing cached is an error, not a fetch.
	never := inventory.Set{Platform: platform.NameCom, Profile: "b", Type: platform.ResZone}
	_, _, err = h.rt.EnsureSet(ctx, never, fetch)
	if !errors.Is(err, inventory.ErrNeverSynced) {
		t.Errorf("--offline never synced = %v, want ErrNeverSynced", err)
	}
	if fetches != 2 {
		t.Errorf("--offline must not fetch (fetches=%d)", fetches)
	}
	h.rt.Flags.Offline = false

	// Fetch errors propagate and leave the cache untouched.
	boom := errors.New("boom")
	h.rt.Flags.Refresh = true
	_, _, err = h.rt.EnsureSet(ctx, s, func(context.Context) ([]platform.Resource, error) { return nil, boom })
	if !errors.Is(err, boom) {
		t.Errorf("fetch error = %v, want boom", err)
	}
	h.rt.Flags.Refresh = false
	if rows, cached, err := h.rt.EnsureSet(ctx, s, fetch); err != nil || !cached || len(rows) != 1 {
		t.Errorf("cache after failed fetch: rows=%d cached=%v err=%v", len(rows), cached, err)
	}
}

func TestEnsureSetExpiredRefetches(t *testing.T) {
	h := newHarness(t, app.Flags{}, func(c *config.Config) {
		c.TTL = map[string]config.Duration{string(platform.ResZone): 0}
	})
	s := inventory.Set{Platform: platform.NameCom, Profile: "a", Type: platform.ResZone}
	fetches := 0
	fetch := func(ctx context.Context) ([]platform.Resource, error) {
		fetches++
		return nil, nil
	}
	for i := 1; i <= 2; i++ {
		if _, cached, err := h.rt.EnsureSet(ctx, s, fetch); err != nil || cached || fetches != i {
			t.Errorf("call %d with zero TTL: cached=%v fetches=%d err=%v", i, cached, fetches, err)
		}
	}
	// Another type keeps its default TTL and is cached.
	d := inventory.Set{Platform: platform.NameCom, Profile: "a", Type: platform.ResDomain}
	h.rt.EnsureSet(ctx, d, fetch)
	if _, cached, err := h.rt.EnsureSet(ctx, d, fetch); err != nil || !cached || fetches != 3 {
		t.Errorf("domain set must be cached: cached=%v fetches=%d err=%v", cached, fetches, err)
	}
}

func TestNeedsRefresh(t *testing.T) {
	h := newHarness(t, app.Flags{}, nil)
	s := inventory.Set{Platform: platform.NameCom, Profile: "a", Type: platform.ResZone}
	if need, err := h.rt.NeedsRefresh(ctx, s); err != nil || !need {
		t.Errorf("never synced: need=%v err=%v", need, err)
	}
	h.seedZones("a")
	if need, err := h.rt.NeedsRefresh(ctx, s); err != nil || need {
		t.Errorf("fresh: need=%v err=%v", need, err)
	}
	h.rt.Flags.Refresh = true
	if need, _ := h.rt.NeedsRefresh(ctx, s); !need {
		t.Error("--refresh must force a refresh")
	}
	h.rt.Flags.Refresh = false
	h.rt.Flags.Offline = true
	if need, _ := h.rt.NeedsRefresh(ctx, inventory.Set{Platform: platform.NameCom, Profile: "b", Type: platform.ResZone}); need {
		t.Error("--offline must never refresh")
	}
}

func TestProfileForPrecedence(t *testing.T) {
	// No current profile: a sole profile is picked, two are ambiguous.
	h := newHarness(t, app.Flags{}, nil)
	if got, err := h.rt.ProfileFor(platform.GoDaddy); err != nil || got != "c" {
		t.Errorf("sole profile: %q, %v", got, err)
	}
	_, err := h.rt.ProfileFor(platform.NameCom)
	var amb *app.AmbiguousError
	if !errors.As(err, &amb) || len(amb.Candidates) != 2 || amb.Candidates[0] != "a" || amb.Candidates[1] != "b" {
		t.Errorf("two profiles: %v (candidates %v)", err, amb)
	}
	if _, err := h.rt.ProfileFor(platform.Cloudflare); !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("no profile on platform = %v, want ErrUnauthorized", err)
	}

	// --profile wins, but must exist and have an account on the platform.
	h.rt.Flags.Profile = "b"
	if got, err := h.rt.ProfileFor(platform.NameCom); err != nil || got != "b" {
		t.Errorf("--profile b: %q, %v", got, err)
	}
	if _, err := h.rt.ProfileFor(platform.GoDaddy); !errors.Is(err, platform.ErrUnauthorized) ||
		!strings.Contains(err.Error(), `profile "b" has no godaddy account`) ||
		!strings.Contains(err.Error(), "auth login godaddy --profile b") {
		t.Errorf("--profile lacking the platform = %v, want ErrUnauthorized with a login hint", err)
	}
	h.rt.Flags.Profile = "zzz"
	if _, err := h.rt.ProfileFor(platform.NameCom); !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), `profile "zzz" not found`) {
		t.Errorf("--profile unknown = %v", err)
	} else if errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("unknown --profile must not read as a missing login: %v", err)
	}

	// current_profile breaks the tie only on its own platform.
	h2 := newHarness(t, app.Flags{}, func(c *config.Config) { c.CurrentProfile = "a" })
	if got, err := h2.rt.ProfileFor(platform.NameCom); err != nil || got != "a" {
		t.Errorf("current_profile: %q, %v", got, err)
	}
	if got, err := h2.rt.ProfileFor(platform.GoDaddy); err != nil || got != "c" {
		t.Errorf("current_profile on another platform must not interfere: %q, %v", got, err)
	}
	h2.rt.Flags.Profile = "b"
	if got, err := h2.rt.ProfileFor(platform.NameCom); err != nil || got != "b" {
		t.Errorf("--profile must beat current_profile: %q, %v", got, err)
	}

	// A current_profile that no longer exists is ignored.
	h3 := newHarness(t, app.Flags{}, func(c *config.Config) { c.CurrentProfile = "gone" })
	if got, err := h3.rt.ProfileFor(platform.GoDaddy); err != nil || got != "c" {
		t.Errorf("dangling current_profile: %q, %v", got, err)
	}
}

func TestOpenAndLoadProfile(t *testing.T) {
	h := newHarness(t, app.Flags{}, nil)
	c, p, err := h.rt.Open(ctx, "a", platform.NameCom)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if p.Name != "a" || p.Platform != platform.NameCom || p.Secret["token"] != secretOf("a", platform.NameCom) {
		t.Errorf("profile = %+v", p)
	}
	if _, ok := c.(platform.DNSService); !ok {
		t.Error("fake client should expose DNSService")
	}
	if h.client("a").count("Open") != 1 {
		t.Error("provider Open not called")
	}
	if c2, p2, err := h.rt.OpenFor(ctx, platform.GoDaddy); err != nil || p2.Name != "c" || c2 == nil {
		t.Errorf("OpenFor(godaddy) = %+v, %v", p2, err)
	}

	// Missing credentials map to ErrUnauthorized with a login hint.
	if err := creds.NewFile(h.dir).Delete(creds.Key("b", string(platform.NameCom))); err != nil {
		t.Fatal(err)
	}
	_, err = h.rt.LoadProfile("b", platform.NameCom)
	if !errors.Is(err, platform.ErrUnauthorized) || !strings.Contains(err.Error(), "auth login namecom --profile b") {
		t.Errorf("LoadProfile without creds = %v", err)
	}
	if _, err := h.rt.LoadProfile("nobody", platform.NameCom); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("LoadProfile(nobody) = %v", err)
	}
	// An existing profile without an account on the platform.
	if _, err := h.rt.LoadProfile("a", platform.GoDaddy); err == nil || !strings.Contains(err.Error(), `profile "a" has no godaddy account`) {
		t.Errorf("LoadProfile on a platform the profile lacks = %v", err)
	}
	if _, _, err := h.rt.Open(ctx, "a", platform.GoDaddy); err == nil {
		t.Error("Open on a platform the profile lacks must fail")
	}
	if n := clientFor("a", platform.GoDaddy).count("Open"); n != 0 {
		t.Errorf("provider Open reached for a missing account (%d calls)", n)
	}

	// --offline refuses to open anything.
	h.rt.Flags.Offline = true
	if _, _, err := h.rt.Open(ctx, "a", platform.NameCom); !errors.Is(err, app.ErrOffline) {
		t.Errorf("Open offline = %v, want ErrOffline", err)
	}
}

func TestOpenDNSAndRegistrarNotSupported(t *testing.T) {
	h := newHarness(t, app.Flags{}, nil)
	h.client("c").noDNS = true
	tgt := &app.Target{Platform: platform.GoDaddy, Profile: "c", Type: platform.ResZone, ResourceID: "z", Domain: "x.com"}
	if _, err := h.rt.OpenDNS(ctx, tgt); !errors.Is(err, platform.ErrNotSupported) {
		t.Errorf("OpenDNS on plain client = %v, want ErrNotSupported", err)
	}
	if _, err := h.rt.OpenRegistrar(ctx, tgt); !errors.Is(err, platform.ErrNotSupported) {
		t.Errorf("OpenRegistrar on plain client = %v, want ErrNotSupported", err)
	}
	ok := &app.Target{Platform: platform.NameCom, Profile: "a", Type: platform.ResZone, ResourceID: "z", Domain: "x.com"}
	if _, err := h.rt.OpenDNS(ctx, ok); err != nil {
		t.Errorf("OpenDNS: %v", err)
	}
	if _, err := h.rt.OpenRegistrar(ctx, ok); err != nil {
		t.Errorf("OpenRegistrar: %v", err)
	}
}

func TestZoneRecordsCachesPerZone(t *testing.T) {
	h := newHarness(t, app.Flags{}, nil)
	h.seedZones("a", zone("z1", "example.com"), zone("z2", "other.com"))
	fc := h.client("a")
	fc.zones = []platform.Zone{zone("z1", "example.com"), zone("z2", "other.com")}
	fc.records["z1"] = []platform.Record{{ID: "r1", Name: "WWW.example.com.", Type: "A", Value: "1.2.3.4", TTL: 300}}
	fc.records["z2"] = []platform.Record{{ID: "r2", Name: "other.com", Type: "MX", Value: "mx.other.com", TTL: 300}}

	tgt, err := h.rt.ResolveDomain(ctx, "www.example.com", platform.ResZone)
	if err != nil {
		t.Fatal(err)
	}
	recs, cached, err := h.rt.ZoneRecords(ctx, tgt)
	if err != nil {
		t.Fatalf("ZoneRecords: %v", err)
	}
	if cached || len(recs) != 1 || recs[0].Name != "www.example.com" || recs[0].ZoneID != "z1" {
		t.Errorf("first ZoneRecords = %+v cached=%v", recs, cached)
	}
	if fc.count("ListRecords:z1") != 1 || fc.count("ListRecords:z2") != 0 {
		t.Errorf("calls = %v", fc.calls)
	}
	recs, cached, err = h.rt.ZoneRecords(ctx, tgt)
	if err != nil || !cached || len(recs) != 1 {
		t.Errorf("second ZoneRecords = %+v cached=%v err=%v", recs, cached, err)
	}
	if fc.count("ListRecords:z1") != 1 {
		t.Error("cached zone was fetched again")
	}
	// The other zone has its own scope and is fetched separately.
	tgt2, _ := h.rt.ResolveDomain(ctx, "other.com", platform.ResZone)
	if recs, cached, err := h.rt.ZoneRecords(ctx, tgt2); err != nil || cached || len(recs) != 1 || recs[0].Type != "MX" {
		t.Errorf("other zone = %+v cached=%v err=%v", recs, cached, err)
	}
	// Records are stored under the zone domain but never indexed.
	if rows, _ := h.db().List(ctx, inventory.Query{Type: platform.ResDNSRecord, Domain: "example.com"}); len(rows) != 1 || rows[0].ParentID != "z1" {
		t.Errorf("stored records = %+v", rows)
	}
	if entries, _ := h.db().IndexEntries(ctx); len(entries) != 2 {
		t.Errorf("index must only hold the two zones: %+v", entries)
	}
}

func TestSyncAccount(t *testing.T) {
	h := newHarness(t, app.Flags{}, nil)
	fc := h.client("a")
	fc.zones = []platform.Zone{zone("z1", "example.com")}
	fc.records["z1"] = []platform.Record{{ID: "r1", Name: "example.com", Type: "A", Value: "1.1.1.1"}}
	fc.domains = []platform.Domain{{Name: "example.com"}}

	reports, err := h.rt.SyncAccount(ctx, ref("a", platform.NameCom), nil)
	if err != nil {
		t.Fatalf("SyncAccount: %v", err)
	}
	if len(reports) != 3 {
		t.Fatalf("reports = %+v", reports)
	}
	counts := map[platform.ResourceType]int{}
	for _, r := range reports {
		if r.Error != "" || r.Profile != "a" || r.Platform != platform.NameCom {
			t.Errorf("report %+v", r)
		}
		counts[r.Type] = r.Count
	}
	if counts[platform.ResZone] != 1 || counts[platform.ResDNSRecord] != 1 || counts[platform.ResDomain] != 1 {
		t.Errorf("counts = %v", counts)
	}
	stats, _ := h.db().Stats(ctx)
	if len(stats) != 3 {
		t.Errorf("stats = %+v", stats)
	}
	// Unsupported types are skipped silently.
	reports, err = h.rt.SyncAccount(ctx, ref("a", platform.NameCom), []platform.ResourceType{platform.ResInstance})
	if err != nil || len(reports) != 0 {
		t.Errorf("unsupported type: %+v, %v", reports, err)
	}
	// An unauthorized error aborts the account and is reported.
	fc.syncErr = platform.ErrUnauthorized
	reports, err = h.rt.SyncAccount(ctx, ref("a", platform.NameCom), nil)
	if !errors.Is(err, platform.ErrUnauthorized) || len(reports) != 1 || reports[0].Error == "" {
		t.Errorf("unauthorized sync: %+v, %v", reports, err)
	}
	// The previous inventory contents survive a failed sync.
	if rows, _ := h.db().List(ctx, inventory.Query{Profile: "a", Type: platform.ResZone}); len(rows) != 1 {
		t.Errorf("failed sync wiped the cache: %+v", rows)
	}
}

func TestMatchRecords(t *testing.T) {
	recs := []platform.Record{
		{ID: "1", Name: "www.example.com", Type: "A", Value: "1.1.1.1"},
		{ID: "2", Name: "WWW.example.com", Type: "AAAA", Value: "::1"},
		{ID: "3", Name: "www.example.com", Type: "a", Value: "2.2.2.2"},
		{ID: "4", Name: "example.com", Type: "A", Value: "1.1.1.1"},
	}
	ids := func(rs []platform.Record) string {
		var out []string
		for _, r := range rs {
			out = append(out, r.ID)
		}
		return strings.Join(out, ",")
	}
	if got := ids(app.MatchRecords(recs, "www.example.com", "", "")); got != "1,2,3" {
		t.Errorf("by name = %s", got)
	}
	if got := ids(app.MatchRecords(recs, "WWW.EXAMPLE.COM.", "a", "")); got != "1,3" {
		t.Errorf("by name+type (case-insensitive) = %s", got)
	}
	if got := ids(app.MatchRecords(recs, "www.example.com", "A", "2.2.2.2")); got != "3" {
		t.Errorf("by content = %s", got)
	}
	if got := ids(app.MatchRecords(recs, "nope.example.com", "", "")); got != "" {
		t.Errorf("no match = %s", got)
	}
}

func TestResourceConverters(t *testing.T) {
	zr := app.ZoneResources([]platform.Zone{{ID: "z", Name: "Example.COM."}})
	if len(zr) != 1 || zr[0].Type != platform.ResZone || zr[0].ID != "z" || zr[0].Name != "example.com" || zr[0].Domain != "example.com" {
		t.Errorf("ZoneResources = %+v", zr)
	}
	rr := app.RecordResources("z", "example.com", []platform.Record{{ID: "r", Name: "WWW.Example.com", Type: "A"}})
	if len(rr) != 1 || rr[0].Type != platform.ResDNSRecord || rr[0].ParentID != "z" || rr[0].Domain != "example.com" || rr[0].Name != "www.example.com" {
		t.Errorf("RecordResources = %+v", rr)
	}
	if rec, ok := rr[0].Data.(platform.Record); !ok || rec.ZoneID != "z" || rec.Name != "www.example.com" {
		t.Errorf("record data = %+v", rr[0].Data)
	}
	dr := app.DomainResources([]platform.Domain{{Name: "Example.com"}})
	if len(dr) != 1 || dr[0].Type != platform.ResDomain || dr[0].ID != "example.com" || dr[0].Domain != "example.com" {
		t.Errorf("DomainResources = %+v", dr)
	}
}

func TestInitRejectsRefreshWithOffline(t *testing.T) {
	registerFakes()
	dir := t.TempDir()
	rt := app.New(app.Flags{ConfigDir: dir, Refresh: true, Offline: true}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err := rt.Init(); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("Init = %v", err)
	}
	rt = app.New(app.Flags{ConfigDir: dir, Output: "xml"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err := rt.Init(); err == nil || !strings.Contains(err.Error(), "unknown output format") {
		t.Fatalf("Init with bad output = %v", err)
	}
}

func TestResolveDomainDoesNotReindexWhenSomeProfilesAreIndexed(t *testing.T) {
	h := newHarness(t, app.Flags{}, nil)
	h.seedZones("a", zone("z1", "example.com"))
	// b and c have no zone state (e.g. their sync keeps failing); a miss
	// must not scan every profile again, but name the unindexed ones.
	_, err := h.rt.ResolveDomain(ctx, "nope.org", platform.ResZone)
	if !errors.Is(err, app.ErrDomainUnknown) {
		t.Fatalf("err = %v, want ErrDomainUnknown", err)
	}
	if !strings.Contains(err.Error(), "account(s) namecom/b, godaddy/c not indexed yet") || !strings.Contains(err.Error(), "--refresh") {
		t.Errorf("error should name the unindexed accounts and suggest --refresh: %v", err)
	}
	for _, p := range []string{"a", "b", "c"} {
		if n := h.client(p).count("Sync"); n != 0 {
			t.Errorf("profile %s synced %d times, want none", p, n)
		}
	}
	if strings.Contains(h.stderr.String(), "indexing") {
		t.Errorf("stderr = %q", h.stderr.String())
	}
}

func TestResolveDomainProfileFlagWrongPlatform(t *testing.T) {
	h := newHarness(t, app.Flags{Profile: "a"}, func(c *config.Config) {
		c.Profiles["a"] = profileOn(platform.Cloudflare) // not registered here: manages nothing
	})
	_, err := h.rt.ResolveDomain(ctx, "example.com", platform.ResDomain)
	if !errors.Is(err, app.ErrDomainUnknown) || !strings.Contains(err.Error(), "no account selected by --profile / --platform is able to manage domains") || strings.Contains(err.Error(), "auth login") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveDomainSameProfileDuplicateZonesAmbiguous(t *testing.T) {
	h := newHarness(t, app.Flags{}, nil)
	h.seedZones("a", zone("z-dup-1", "dup.com"), zone("z-dup-2", "dup.com"))
	_, err := h.rt.ResolveDomain(ctx, "www.dup.com", platform.ResZone)
	var amb *app.AmbiguousError
	if !errors.As(err, &amb) {
		t.Fatalf("two zones of one profile must be ambiguous, got %v", err)
	}
	if len(amb.Candidates) != 2 || amb.Candidates[0] != "namecom/a (zone z-dup-1)" || amb.Candidates[1] != "namecom/a (zone z-dup-2)" {
		t.Errorf("candidates = %v", amb.Candidates)
	}
	// Neither flag can tell two zones of one account apart.
	if strings.Contains(amb.Hint, "--profile") || strings.Contains(amb.Hint, "--platform") || !strings.Contains(amb.Hint, "resource id") {
		t.Errorf("hint = %q", amb.Hint)
	}
	h.rt.Flags.Profile, h.rt.Flags.Platform = "a", "namecom"
	if _, err := h.rt.ResolveDomain(ctx, "www.dup.com", platform.ResZone); !errors.As(err, &amb) {
		t.Errorf("--profile and --platform cannot pick between two zones of one account: %v", err)
	}
}
