package app_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/dnstest"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// markDue marks every cached set of a single-account profile as due, as an
// upgrade, a login that changes what the account covers, and the enable /
// disable / use commands of a platform do.
func (h *harness) markDue(profile string) {
	h.t.Helper()
	if err := h.db().Expire(ctx, h.platformOf(profile), profile); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) zoneState(profile string) *inventory.State {
	h.t.Helper()
	st, err := h.db().GetState(ctx, inventory.Set{Platform: h.platformOf(profile), Profile: profile, Type: platform.ResZone})
	if err != nil {
		h.t.Fatal(err)
	}
	return st
}

// A set marked due is indexed before the lookup, without --refresh: the
// zone its account covers since then is routed, and only that account is
// asked, once per run.
func TestResolveDomainIndexesSetsMarkedDue(t *testing.T) {
	h := newHarness(t, app.Flags{}, nil)
	h.seedStandard()
	if !app.ForcedDue(&inventory.State{ExpiresAt: time.Unix(0, 0)}) || app.ForcedDue(h.zoneState("a")) || app.ForcedDue(nil) {
		t.Fatal("ForcedDue: only the zero Unix time is a set marked due")
	}
	h.markDue("a")
	if !app.ForcedDue(h.zoneState("a")) {
		t.Fatalf("state after Expire = %+v", h.zoneState("a"))
	}
	h.client("a").zones = []platform.Zone{zone("z-example", "example.com"), zone("z-new", "newlycovered.io")}

	tgt, err := h.rt.ResolveDomain(ctx, "www.newlycovered.io", platform.ResZone)
	if err != nil || tgt.Profile != "a" || tgt.ResourceID != "z-new" {
		t.Fatalf("target = %+v, %v (%s)", tgt, err, h.stderr.String())
	}
	if !strings.Contains(h.stderr.String(), "indexing zone in 1 account(s) whose cached inventory was marked due") {
		t.Errorf("stderr = %q", h.stderr.String())
	}
	if st := h.zoneState("a"); !st.Fresh(time.Now()) {
		t.Errorf("state after the indexing = %+v", st)
	}
	// Later lookups of the run, hits and misses, ask nobody again.
	if _, err := h.rt.ResolveDomain(ctx, "nope.org", platform.ResZone); !errors.Is(err, app.ErrDomainUnknown) {
		t.Errorf("miss = %v", err)
	}
	if _, err := h.rt.ResolveDomain(ctx, "newlycovered.io", platform.ResZone); err != nil {
		t.Errorf("second hit = %v", err)
	}
	if n := h.client("a").count("Sync:zone"); n != 1 {
		t.Errorf("profile a zone sync count = %d, want 1", n)
	}
	for _, p := range []string{"b", "c"} {
		if n := h.client(p).count("Sync"); n != 0 {
			t.Errorf("profile %s, whose set was not marked due, synced %d times", p, n)
		}
	}
	if n := h.client("a").count("Sync:domain"); n != 0 {
		t.Errorf("a zone lookup synced domains")
	}
}

// The indexing happens before the lookup, not only on a miss: a zone name
// held twice is reported as ambiguous and not routed to the account that
// was indexed earlier.
func TestResolveDomainSetMarkedDueRevealsASecondOwner(t *testing.T) {
	h := newHarness(t, app.Flags{}, nil)
	h.seedZones("a", zone("z1", "example.com"))
	h.seedZones("b", zone("z9", "other.org"))
	h.seedZones("c")
	h.markDue("b")
	h.client("b").zones = []platform.Zone{zone("z9", "other.org"), zone("z2", "example.com")}

	_, err := h.rt.ResolveDomain(ctx, "example.com", platform.ResZone)
	var amb *app.AmbiguousError
	if !errors.As(err, &amb) || len(amb.Candidates) != 2 {
		t.Fatalf("err = %v, want two owners", err)
	}
	if n := h.client("a").count("Sync"); n != 0 {
		t.Errorf("profile a synced %d times", n)
	}
}

// A set that ran past its TTL is not a set marked due: a miss does not
// sweep the accounts.
func TestResolveDomainTTLExpiredSetIsNotIndexed(t *testing.T) {
	h := newHarness(t, app.Flags{}, nil)
	for _, p := range []string{"a", "b", "c"} {
		s := inventory.Set{Platform: h.platformOf(p), Profile: p, Type: platform.ResZone}
		if err := h.db().Replace(ctx, s, app.ZoneResources([]platform.Zone{zone("z-"+p, p+".example")}), -time.Hour); err != nil {
			t.Fatal(err)
		}
		if st := h.zoneState(p); st.Fresh(time.Now()) || app.ForcedDue(st) {
			t.Fatalf("state of %s = %+v, want expired by its TTL", p, st)
		}
		h.client(p).zones = []platform.Zone{zone("z-new", "newlycovered.io")}
	}
	if _, err := h.rt.ResolveDomain(ctx, "newlycovered.io", platform.ResZone); !errors.Is(err, app.ErrDomainUnknown) || !strings.Contains(err.Error(), "--refresh") {
		t.Fatalf("miss = %v", err)
	}
	if tgt, err := h.rt.ResolveDomain(ctx, "a.example", platform.ResZone); err != nil || tgt.Profile != "a" {
		t.Errorf("hit = %+v, %v", tgt, err)
	}
	for _, p := range []string{"a", "b", "c"} {
		if n := h.client(p).count(""); n != 0 {
			t.Errorf("profile %s was reached: %v", p, h.client(p).calls)
		}
	}
	if strings.Contains(h.stderr.String(), "indexing") {
		t.Errorf("stderr = %q", h.stderr.String())
	}
}

// --offline makes no request for a set marked due: its rows are served,
// and a miss keeps the offline message.
func TestResolveDomainOfflineLeavesSetsMarkedDue(t *testing.T) {
	h := newHarness(t, app.Flags{Offline: true}, nil)
	h.seedStandard()
	h.markDue("a")
	h.client("a").zones = []platform.Zone{zone("z-new", "newlycovered.io")}

	_, err := h.rt.ResolveDomain(ctx, "newlycovered.io", platform.ResZone)
	if !errors.Is(err, app.ErrDomainUnknown) || !strings.Contains(err.Error(), "run `polyctl domain index` when online") {
		t.Fatalf("offline miss = %v", err)
	}
	if tgt, err := h.rt.ResolveDomain(ctx, "www.example.com", platform.ResZone); err != nil || tgt.Profile != "a" {
		t.Errorf("offline hit = %+v, %v", tgt, err)
	}
	if err := h.rt.IndexDue(ctx, platform.ResZone); err != nil {
		t.Errorf("IndexDue offline = %v", err)
	}
	for _, p := range []string{"a", "b", "c"} {
		if n := h.client(p).count(""); n != 0 {
			t.Errorf("profile %s was reached offline: %v", p, h.client(p).calls)
		}
	}
	if !app.ForcedDue(h.zoneState("a")) {
		t.Errorf("the set is no longer marked due: %+v", h.zoneState("a"))
	}
}

// --profile restricts the indexing like the lookup: a set marked due of an
// account that is not selected is left alone.
func TestResolveDomainSetMarkedDueRespectsTheSelection(t *testing.T) {
	h := newHarness(t, app.Flags{Profile: "b"}, nil)
	h.seedStandard()
	h.markDue("a")
	h.markDue("b")
	if _, err := h.rt.ResolveDomain(ctx, "nope.org", platform.ResZone); !errors.Is(err, app.ErrDomainUnknown) {
		t.Fatalf("miss = %v", err)
	}
	if a, b := h.client("a").count("Sync"), h.client("b").count("Sync:zone"); a != 0 || b != 1 {
		t.Errorf("sync counts: a %d (want 0), b %d (want 1)", a, b)
	}
}

// An account whose set was marked due and that fails to sync is a warning
// while the lookup is answered, by the rows it kept or by another account;
// it is tried once per run. When nothing answers, the failure is reported
// and not "unknown domain".
func TestResolveDomainSetMarkedDueFailingAccount(t *testing.T) {
	h := newHarness(t, app.Flags{}, nil)
	h.seedStandard()
	h.markDue("a")
	h.client("a").syncErr = errors.New("dial tcp: connection refused")

	if tgt, err := h.rt.ResolveDomain(ctx, "www.example.com", platform.ResZone); err != nil || tgt.Profile != "a" {
		t.Fatalf("hit in the rows kept = %+v, %v", tgt, err)
	}
	if !strings.Contains(h.stderr.String(), "warning: index namecom/a") {
		t.Errorf("stderr = %q", h.stderr.String())
	}
	_, err := h.rt.ResolveDomain(ctx, "nope.org", platform.ResZone)
	if err == nil || errors.Is(err, app.ErrDomainUnknown) || !strings.Contains(err.Error(), "could not index the zones") {
		t.Errorf("miss = %v, want the indexing failure", err)
	}
	if n := h.client("a").count("Sync:zone"); n != 1 {
		t.Errorf("profile a zone sync count = %d, want 1", n)
	}
	if !app.ForcedDue(h.zoneState("a")) {
		t.Errorf("a failed sync cleared the mark: %+v", h.zoneState("a"))
	}
}

// When one of two accounts marked due fails, the other one's answer
// stands and a miss is a plain "unknown domain".
func TestResolveDomainSetMarkedDuePartialFailure(t *testing.T) {
	h := newHarness(t, app.Flags{}, nil)
	h.seedStandard()
	h.markDue("a")
	h.markDue("b")
	h.client("a").syncErr = errors.New("dial tcp: connection refused")
	h.client("b").zones = []platform.Zone{zone("z-new", "newlycovered.io")}

	if tgt, err := h.rt.ResolveDomain(ctx, "newlycovered.io", platform.ResZone); err != nil || tgt.Profile != "b" {
		t.Fatalf("target = %+v, %v", tgt, err)
	}
	if _, err := h.rt.ResolveDomain(ctx, "nope.org", platform.ResZone); !errors.Is(err, app.ErrDomainUnknown) {
		t.Errorf("miss = %v, want ErrDomainUnknown", err)
	}
}

// --refresh indexes every candidate once; the sets marked due are not
// indexed a second time for it, also when the account marked due fails
// (its set is then still marked when the lookup runs).
func TestResolveDomainRefreshCoversSetsMarkedDue(t *testing.T) {
	h := newHarness(t, app.Flags{Refresh: true}, nil)
	h.seedStandard()
	h.markDue("a")
	h.client("a").syncErr = errors.New("dial tcp: connection refused")
	if _, err := h.rt.ResolveDomain(ctx, "nope.org", platform.ResZone); !errors.Is(err, app.ErrDomainUnknown) {
		t.Fatalf("miss = %v", err)
	}
	if !app.ForcedDue(h.zoneState("a")) {
		t.Fatalf("state = %+v, want still marked due", h.zoneState("a"))
	}
	if _, err := h.rt.ResolveDomain(ctx, "nope.org", platform.ResZone); !errors.Is(err, app.ErrDomainUnknown) {
		t.Fatalf("second miss = %v", err)
	}
	for _, p := range []string{"a", "b", "c"} {
		if n := h.client(p).count("Sync:zone"); n != 1 {
			t.Errorf("profile %s zone sync count = %d, want 1", p, n)
		}
	}
}

// IndexDue alone, as domain which and the domain picker call it before
// they read the index: with --refresh every candidate is indexed, once per
// run, so that the flag does not leave a set marked due unread; the
// lookups that follow ask nobody again.
func TestIndexDueWithRefreshIndexesEveryCandidateOnce(t *testing.T) {
	h := newHarness(t, app.Flags{Refresh: true}, nil)
	h.seedStandard()
	h.markDue("a")
	h.client("a").zones = []platform.Zone{zone("z-example", "example.com"), zone("z-new", "newlycovered.io")}
	for i := 0; i < 2; i++ {
		if err := h.rt.IndexDue(ctx, platform.ResZone); err != nil {
			t.Fatalf("IndexDue = %v", err)
		}
	}
	for _, p := range []string{"a", "b", "c"} {
		if n := h.client(p).count("Sync:zone"); n != 1 {
			t.Fatalf("after IndexDue: profile %s zone sync count = %d, want 1", p, n)
		}
	}
	if err := h.rt.IndexForLookup(ctx, platform.ResZone); err != nil {
		t.Fatalf("IndexForLookup = %v", err)
	}
	if tgt, err := h.rt.ResolveDomain(ctx, "newlycovered.io", platform.ResZone); err != nil || tgt.Profile != "a" {
		t.Fatalf("target = %+v, %v", tgt, err)
	}
	for _, p := range []string{"a", "b", "c"} {
		if n := h.client(p).count("Sync:zone"); n != 1 {
			t.Errorf("profile %s zone sync count = %d, want 1", p, n)
		}
		if n := h.client(p).count("Sync:domain"); n != 0 {
			t.Errorf("profile %s synced domains for a zone lookup", p)
		}
	}
}

// An account marked due of which one project (or one account of a token)
// fails stores what the others returned and stays marked: the part that
// failed may be the one the mark was set for, so the next run asks again
// and routes what it covers. The failure names the accounts marked due,
// not the candidates that were not asked.
func TestResolveDomainSetMarkedDueFailingInPartStaysMarked(t *testing.T) {
	h := newHarness(t, app.Flags{}, nil)
	h.seedStandard()
	h.markDue("a")
	h.client("a").zones = []platform.Zone{zone("z-example", "example.com"), zone("z-shared-a", "shared.com"), zone("z-seen", "seen.io")}
	h.client("a").syncErr = &platform.RegionSyncError{Noun: "project", Failures: []platform.RegionError{{Region: "proj-new", Tree: true, Err: errors.New("503")}}}

	// What the projects that worked returned is stored and routed.
	if tgt, err := h.rt.ResolveDomain(ctx, "seen.io", platform.ResZone); err != nil || tgt.ResourceID != "z-seen" {
		t.Fatalf("zone of a project that worked = %+v, %v", tgt, err)
	}
	if !strings.Contains(h.stderr.String(), "warning: index namecom/a: 1 project(s) failed") {
		t.Errorf("stderr = %q", h.stderr.String())
	}
	_, err := h.rt.ResolveDomain(ctx, "newlycovered.io", platform.ResZone)
	if err == nil || errors.Is(err, app.ErrDomainUnknown) {
		t.Fatalf("miss = %v, want the indexing failure", err)
	}
	if msg := err.Error(); !strings.Contains(msg, "could not index the zones of the account(s) whose cached inventory was marked due: namecom/a: 1 project(s) failed") || strings.Contains(msg, "any account") {
		t.Errorf("miss = %v", err)
	}
	if st := h.zoneState("a"); !app.ForcedDue(st) {
		t.Fatalf("a sync that failed in part cleared the mark: %+v", st)
	}
	if n := h.client("a").count("Sync:zone"); n != 1 {
		t.Errorf("profile a zone sync count = %d, want 1 in this run", n)
	}

	// The next run: the project answers again.
	h2 := newHarnessIn(t, h.dir, app.Flags{})
	h.client("a").syncErr = nil
	h.client("a").zones = append(h.client("a").zones, zone("z-new", "newlycovered.io"))
	if tgt, err := h2.rt.ResolveDomain(ctx, "newlycovered.io", platform.ResZone); err != nil || tgt.Profile != "a" || tgt.ResourceID != "z-new" {
		t.Fatalf("next run = %+v, %v (%s)", tgt, err, h2.stderr.String())
	}
	if st := h2.zoneState("a"); app.ForcedDue(st) || !st.Fresh(time.Now()) {
		t.Errorf("state after the sync that read everything = %+v", st)
	}
	if n := h.client("a").count("Sync:zone"); n != 2 {
		t.Errorf("profile a zone sync count = %d, want 2", n)
	}
}

// A registrar operation routes by the registered domains: their set, when
// marked due, is the one indexed, and the zones are left alone.
func TestResolveDomainIndexesRegisteredDomainsMarkedDue(t *testing.T) {
	h := newHarness(t, app.Flags{}, nil)
	h.seedStandard()
	for _, p := range []string{"a", "b", "c"} {
		s := inventory.Set{Platform: h.platformOf(p), Profile: p, Type: platform.ResDomain}
		if err := h.db().Replace(ctx, s, app.DomainResources([]platform.Domain{{Name: p + "-registered.com"}}), time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	h.markDue("b")
	h.client("b").domains = []platform.Domain{{Name: "b-registered.com"}, {Name: "newlyheld.io"}}

	tgt, err := h.rt.ResolveDomain(ctx, "newlyheld.io", platform.ResDomain)
	if err != nil || tgt.Profile != "b" || tgt.Type != platform.ResDomain {
		t.Fatalf("target = %+v, %v (%s)", tgt, err, h.stderr.String())
	}
	if !strings.Contains(h.stderr.String(), "indexing domain in 1 account(s) whose cached inventory was marked due") {
		t.Errorf("stderr = %q", h.stderr.String())
	}
	if d, z := h.client("b").count("Sync:domain"), h.client("b").count("Sync:zone"); d != 1 || z != 0 {
		t.Errorf("profile b sync counts: domain %d (want 1), zone %d (want 0)", d, z)
	}
	if !app.ForcedDue(h.zoneState("b")) {
		t.Errorf("the zone set, which no lookup needed, lost its mark: %+v", h.zoneState("b"))
	}
	for _, p := range []string{"a", "c"} {
		if n := h.client(p).count("Sync"); n != 0 {
			t.Errorf("profile %s synced %d times", p, n)
		}
	}
}

// --platform restricts the indexing like the lookup.
func TestResolveDomainSetMarkedDueRespectsThePlatform(t *testing.T) {
	h := newHarness(t, app.Flags{Platform: string(platform.GoDaddy)}, nil)
	h.seedStandard()
	h.markDue("a")
	h.markDue("c")
	h.client("c").zones = []platform.Zone{zone("z-new", "newlycovered.io")}
	if tgt, err := h.rt.ResolveDomain(ctx, "newlycovered.io", platform.ResZone); err != nil || tgt.Profile != "c" {
		t.Fatalf("target = %+v, %v", tgt, err)
	}
	if a, c := h.client("a").count("Sync"), h.client("c").count("Sync:zone"); a != 0 || c != 1 {
		t.Errorf("sync counts: a %d (want 0), c %d (want 1)", a, c)
	}
	if !app.ForcedDue(h.zoneState("a")) {
		t.Errorf("the set of an account that is not selected lost its mark")
	}
}

// domain ns check reads the index itself: a hit is not served from a set
// marked due either, so the second zone of the name that its account
// covers since then is listed. The account is asked once per run.
func TestNSCheckIndexesSetsMarkedDue(t *testing.T) {
	h := newHarness(t, app.Flags{}, nil)
	ns := []string{"ns1.dns.example.net", "ns2.dns.example.net"}
	za := platform.Zone{ID: "z1", Name: "example.com", Nameservers: ns}
	zb := platform.Zone{ID: "z2", Name: "example.com", Nameservers: []string{"ns1.other.example.org"}}
	h.seedZones("a", za)
	h.seedZones("b", zone("z9", "other.org"))
	h.seedZones("c")
	h.client("a").zones = []platform.Zone{za}
	h.markDue("b")
	h.client("b").zones = []platform.Zone{zone("z9", "other.org"), zb}
	srv := dnstest.Start(t, map[string]dnstest.Answer{"example.com": {NS: ns}})

	opts := app.NSCheckOptions{Domain: "example.com", Resolvers: []string{srv.Addr}, Timeout: time.Second, NoRegistrar: true}
	res, err := h.rt.NSCheck(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Zones) != 2 || res.Zone.ZoneID != "z1" {
		t.Fatalf("zones = %+v, compared %+v; want z1 and z2, z1 compared", res.Zones, res.Zone)
	}
	if _, err := h.rt.NSCheck(ctx, opts); err != nil {
		t.Fatal(err)
	}
	if a, b := h.client("a").count("Sync"), h.client("b").count("Sync:zone"); a != 0 || b != 1 {
		t.Errorf("sync counts: a %d (want 0), b %d (want 1)", a, b)
	}
}

// An account marked due that fails is a warning while ns check finds the
// zone elsewhere; when it finds none, the failure is reported, and the
// account is not asked a second time in the run.
func TestNSCheckSetMarkedDueFailingAccount(t *testing.T) {
	h := newHarness(t, app.Flags{}, nil)
	ns := []string{"ns1.dns.example.net", "ns2.dns.example.net"}
	za := platform.Zone{ID: "z1", Name: "example.com", Nameservers: ns}
	h.seedZones("a", za)
	h.seedZones("b", zone("z9", "other.org"))
	h.seedZones("c")
	h.client("a").zones = []platform.Zone{za}
	h.markDue("b")
	h.client("b").syncErr = errors.New("dial tcp: connection refused")
	srv := dnstest.Start(t, map[string]dnstest.Answer{"example.com": {NS: ns}, "missing.org": {NS: ns}})

	res, err := h.rt.NSCheck(ctx, app.NSCheckOptions{Domain: "example.com", Resolvers: []string{srv.Addr}, Timeout: time.Second, NoRegistrar: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Zones) != 1 || res.Status != app.NSStatusOK || !strings.Contains(h.stderr.String(), "warning: index namecom/b") {
		t.Errorf("result = %+v, stderr = %q; want the zone of a and a warning for b", res, h.stderr.String())
	}
	// Nothing found, and b could not be asked: not "no hosted zone".
	res, err = h.rt.NSCheck(ctx, app.NSCheckOptions{Domain: "missing.org", Resolvers: []string{srv.Addr}, Timeout: time.Second, NoRegistrar: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != app.NSStatusUnknown || !strings.Contains(res.Message, "namecom/b") {
		t.Errorf("miss = %+v, want the failure of b", res)
	}
	if n := h.client("b").count("Sync:zone"); n != 1 {
		t.Errorf("profile b zone sync count = %d, want 1", n)
	}
}

// The domain picker indexes the sets marked due before it lists the
// index, so that a zone an account covers since then is offered.
func TestPickDomainIndexesSetsMarkedDue(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h := newHarness(t, app.Flags{}, nil)
	h.seedStandard()
	h.markDue("a")
	h.client("a").zones = []platform.Zone{zone("z-example", "example.com"), zone("z-new", "newlycovered.io")}
	p := prompttest.New(t, "newlycovered.io")
	h.rt.Picker = p
	d, err := h.rt.PickDomain(ctx, app.DomainPick{Arg: "<domain>", Kinds: []platform.ResourceType{platform.ResZone}})
	if err != nil || d != "newlycovered.io" {
		t.Fatalf("PickDomain = %q, %v", d, err)
	}
	p.Done()
	if a, b := h.client("a").count("Sync:zone"), h.client("b").count("Sync"); a != 1 || b != 0 {
		t.Errorf("sync counts: a %d (want 1), b %d (want 0)", a, b)
	}
}
