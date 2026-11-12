package app_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// withProj adds a profile "proj" holding an account on both fake platforms
// next to the single-account profiles a, b and c of the harness.
func withProj(c *config.Config) {
	c.Profiles["proj"] = profileOn(platform.NameCom, platform.GoDaddy)
}

func refs(rs []config.AccountRef) string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.String()
	}
	return strings.Join(out, ",")
}

func TestProfileForWithMultiPlatformProfile(t *testing.T) {
	// proj is one more candidate on both platforms.
	h := newHarness(t, app.Flags{}, withProj)
	var amb *app.AmbiguousError
	if _, err := h.rt.ProfileFor(platform.NameCom); !errors.As(err, &amb) || strings.Join(amb.Candidates, ",") != "a,b,proj" {
		t.Errorf("namecom without a choice = %v", err)
	}
	if _, err := h.rt.ProfileFor(platform.GoDaddy); !errors.As(err, &amb) || strings.Join(amb.Candidates, ",") != "c,proj" {
		t.Errorf("godaddy without a choice = %v", err)
	}

	// --profile proj serves both platforms.
	h.rt.Flags.Profile = "proj"
	for _, id := range []platform.ID{platform.NameCom, platform.GoDaddy} {
		if got, err := h.rt.ProfileFor(id); err != nil || got != "proj" {
			t.Errorf("--profile proj for %s: %q, %v", id, got, err)
		}
	}
	if _, err := h.rt.ProfileFor(platform.Cloudflare); !errors.Is(err, platform.ErrUnauthorized) || !strings.Contains(err.Error(), "auth login cloudflare --profile proj") {
		t.Errorf("--profile proj for a platform it lacks = %v", err)
	}

	// So does current_profile, and it does not leak to platforms it lacks.
	h2 := newHarness(t, app.Flags{}, func(c *config.Config) {
		withProj(c)
		c.CurrentProfile = "proj"
	})
	for _, id := range []platform.ID{platform.NameCom, platform.GoDaddy} {
		if got, err := h2.rt.ProfileFor(id); err != nil || got != "proj" {
			t.Errorf("current_profile proj for %s: %q, %v", id, got, err)
		}
	}
	if _, err := h2.rt.ProfileFor(platform.Cloudflare); !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("current_profile without the platform = %v, want ErrUnauthorized", err)
	}
	h2.rt.Flags.Profile = "c"
	if got, err := h2.rt.ProfileFor(platform.GoDaddy); err != nil || got != "c" {
		t.Errorf("--profile must beat current_profile: %q, %v", got, err)
	}
	if _, err := h2.rt.ProfileFor(platform.NameCom); !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("--profile c lacks namecom and must not fall back to current_profile: %v", err)
	}

	// A sole multi-platform profile is picked without any hint.
	h3 := newHarness(t, app.Flags{}, func(c *config.Config) {
		c.Profiles = map[string]*config.Profile{"proj": profileOn(platform.NameCom, platform.GoDaddy)}
	})
	for _, id := range []platform.ID{platform.NameCom, platform.GoDaddy} {
		if got, err := h3.rt.ProfileFor(id); err != nil || got != "proj" {
			t.Errorf("sole profile for %s: %q, %v", id, got, err)
		}
	}
}

func TestOpenPerPlatformInOneProfile(t *testing.T) {
	h := newHarness(t, app.Flags{}, withProj)
	nc, gd := clientFor("proj", platform.NameCom), clientFor("proj", platform.GoDaddy)
	if nc == gd {
		t.Fatal("the two accounts of one profile must not share a fake client")
	}

	for _, id := range []platform.ID{platform.NameCom, platform.GoDaddy} {
		c, p, err := h.rt.Open(ctx, "proj", id)
		if err != nil {
			t.Fatalf("Open(proj, %s): %v", id, err)
		}
		if p.Name != "proj" || p.Platform != id || p.Secret["token"] != secretOf("proj", id) {
			t.Errorf("Open(proj, %s) profile = %+v", id, p)
		}
		ident, err := c.Verify(ctx)
		if err != nil || ident.Account != "fake-account-"+string(id) {
			t.Errorf("Open(proj, %s) returned the client of another platform: %+v, %v", id, ident, err)
		}
	}
	if nc.count("Open") != 1 || gd.count("Open") != 1 || nc.count("Verify") != 1 || gd.count("Verify") != 1 {
		t.Errorf("calls: namecom %v, godaddy %v", nc.calls, gd.calls)
	}

	// OpenFor resolves the profile per platform.
	h.rt.Flags.Profile = "proj"
	if _, p, err := h.rt.OpenFor(ctx, platform.GoDaddy); err != nil || p.Name != "proj" || p.Platform != platform.GoDaddy {
		t.Errorf("OpenFor(godaddy) = %+v, %v", p, err)
	}
	if gd.count("Open") != 2 || nc.count("Open") != 1 {
		t.Errorf("OpenFor(godaddy) opened the wrong account: namecom %v, godaddy %v", nc.calls, gd.calls)
	}

	// A refreshed secret is written back under the account key only.
	p, err := h.rt.LoadProfile("proj", platform.GoDaddy)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.UpdateSecret(map[string]string{"token": "rotated"}); err != nil {
		t.Fatal(err)
	}
	store := creds.NewFile(h.dir)
	if s, err := store.Get(creds.Key("proj", "godaddy")); err != nil || s["token"] != "rotated" {
		t.Errorf("godaddy secret after UpdateSecret = %v, %v", s, err)
	}
	if s, err := store.Get(creds.Key("proj", "namecom")); err != nil || s["token"] != secretOf("proj", platform.NameCom) {
		t.Errorf("UpdateSecret touched the sibling account: %v, %v", s, err)
	}
	if _, err := store.Get("proj"); !errors.Is(err, creds.ErrNotFound) {
		t.Errorf("nothing may be stored under the bare profile name: %v", err)
	}
}

func TestSyncAccountInMultiPlatformProfile(t *testing.T) {
	h := newHarness(t, app.Flags{}, withProj)
	nc, gd := clientFor("proj", platform.NameCom), clientFor("proj", platform.GoDaddy)
	nc.zones = []platform.Zone{zone("z-nc", "example.com")}
	gd.zones = []platform.Zone{zone("z-gd-1", "other.com"), zone("z-gd-2", "third.com")}
	gd.domains = []platform.Domain{{Name: "example.com"}}

	reports, err := h.rt.SyncAccount(ctx, ref("proj", platform.GoDaddy), nil)
	if err != nil {
		t.Fatalf("SyncAccount(proj/godaddy): %v", err)
	}
	counts := map[platform.ResourceType]int{}
	for _, r := range reports {
		if r.Error != "" || r.Profile != "proj" || r.Platform != platform.GoDaddy {
			t.Errorf("report %+v", r)
		}
		counts[r.Type] = r.Count
	}
	if len(reports) != 3 || counts[platform.ResZone] != 2 || counts[platform.ResDomain] != 1 {
		t.Errorf("reports = %+v", reports)
	}
	if n := nc.count(""); n != 0 {
		t.Errorf("syncing proj/godaddy reached proj/namecom: %v", nc.calls)
	}
	// Only the godaddy sets of the profile exist in the inventory.
	if st, err := h.db().GetState(ctx, inventory.Set{Platform: platform.GoDaddy, Profile: "proj", Type: platform.ResZone}); err != nil || st == nil {
		t.Errorf("godaddy zone state = %+v, %v", st, err)
	}
	if st, err := h.db().GetState(ctx, inventory.Set{Platform: platform.NameCom, Profile: "proj", Type: platform.ResZone}); err != nil || st != nil {
		t.Errorf("namecom zone state must not exist yet: %+v, %v", st, err)
	}

	// Syncing the sibling account adds to the profile instead of replacing it.
	if _, err := h.rt.SyncAccount(ctx, ref("proj", platform.NameCom), []platform.ResourceType{platform.ResZone}); err != nil {
		t.Fatalf("SyncAccount(proj/namecom): %v", err)
	}
	rows, err := h.db().List(ctx, inventory.Query{Profile: "proj", Type: platform.ResZone})
	if err != nil || len(rows) != 3 {
		t.Errorf("zones of proj = %+v, %v", rows, err)
	}
	if nc.count("Sync:zone") != 1 || nc.count("Sync:domain") != 0 || gd.count("Sync:zone") != 1 {
		t.Errorf("calls: namecom %v, godaddy %v", nc.calls, gd.calls)
	}

	// An account the profile does not have cannot be synced.
	if _, err := h.rt.SyncAccount(ctx, ref("a", platform.GoDaddy), nil); err == nil {
		t.Error("SyncAccount on a missing account must fail")
	}
}

func TestResolveDomainRoutesInsideOneProfile(t *testing.T) {
	h := newHarness(t, app.Flags{}, withProj)
	h.seedStandard()
	h.seedZonesFor(ref("proj", platform.NameCom), zone("z-nc", "proj-dns.com"))
	h.seedZonesFor(ref("proj", platform.GoDaddy), zone("z-gd", "proj-shop.com"), zone("z-gd-sub", "eu.proj-dns.com"))
	nc, gd := clientFor("proj", platform.NameCom), clientFor("proj", platform.GoDaddy)
	nc.records["z-nc"] = []platform.Record{{ID: "r1", Name: "www.proj-dns.com", Type: "A", Content: "1.1.1.1"}}
	gd.records["z-gd"] = []platform.Record{{ID: "r2", Name: "www.proj-shop.com", Type: "A", Content: "2.2.2.2"}}

	cases := []struct {
		domain string
		id     platform.ID
		zoneID string
	}{
		{"www.proj-dns.com", platform.NameCom, "z-nc"},
		{"www.proj-shop.com", platform.GoDaddy, "z-gd"},
		// The longest match wins across the accounts of one profile too.
		{"api.eu.proj-dns.com", platform.GoDaddy, "z-gd-sub"},
	}
	for _, c := range cases {
		tgt, err := h.rt.ResolveDomain(ctx, c.domain, platform.ResZone)
		if err != nil {
			t.Errorf("ResolveDomain(%q): %v", c.domain, err)
			continue
		}
		if tgt.Profile != "proj" || tgt.Platform != c.id || tgt.ResourceID != c.zoneID {
			t.Errorf("ResolveDomain(%q) = %+v, want proj/%s zone %s", c.domain, tgt, c.id, c.zoneID)
		}
	}

	// The target opens the client of its own platform.
	tgt, err := h.rt.ResolveDomain(ctx, "www.proj-shop.com", platform.ResZone)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tgt.String(), "godaddy/proj (zone proj-shop.com)") {
		t.Errorf("Target.String() = %q", tgt.String())
	}
	recs, _, err := h.rt.ZoneRecords(ctx, tgt)
	if err != nil || len(recs) != 1 || recs[0].ID != "r2" {
		t.Errorf("ZoneRecords(proj/godaddy) = %+v, %v", recs, err)
	}
	if gd.count("ListRecords:z-gd") != 1 || nc.count("") != 0 {
		t.Errorf("calls: namecom %v, godaddy %v", nc.calls, gd.calls)
	}
	dns, err := h.rt.OpenDNS(ctx, &app.Target{Platform: platform.NameCom, Profile: "proj", Type: platform.ResZone, ResourceID: "z-nc", Domain: "proj-dns.com"})
	if err != nil {
		t.Fatalf("OpenDNS(proj/namecom): %v", err)
	}
	if got, err := dns.ListRecords(ctx, "z-nc"); err != nil || len(got) != 1 || got[0].ID != "r1" {
		t.Errorf("records through proj/namecom = %+v, %v", got, err)
	}

	// One zone name in both accounts of the profile is ambiguous, and the
	// candidates tell the two platforms apart.
	h.seedZonesFor(ref("proj", platform.NameCom), zone("z-nc", "proj-dns.com"), zone("z-both-nc", "both.com"))
	h.seedZonesFor(ref("proj", platform.GoDaddy), zone("z-gd", "proj-shop.com"), zone("z-both-gd", "both.com"))
	_, err = h.rt.ResolveDomain(ctx, "www.both.com", platform.ResZone)
	var amb *app.AmbiguousError
	if !errors.As(err, &amb) || len(amb.Candidates) != 2 {
		t.Fatalf("same zone in both accounts of proj = %v, want *app.AmbiguousError", err)
	}
	joined := strings.Join(amb.Candidates, " | ")
	if !strings.Contains(joined, "godaddy/proj (zone z-both-gd)") || !strings.Contains(joined, "namecom/proj (zone z-both-nc)") {
		t.Errorf("candidates = %v", amb.Candidates)
	}
	// Both candidates are in one profile: only --platform tells them apart.
	if !strings.Contains(amb.Hint, "--platform <platform>") || strings.Contains(amb.Hint, "--profile") || !strings.Contains(err.Error(), amb.Hint) {
		t.Errorf("hint = %q (error %v)", amb.Hint, err)
	}
}

func TestResolveDomainProfileFlagWithSeveralAccounts(t *testing.T) {
	h := newHarness(t, app.Flags{Profile: "proj"}, withProj)
	h.seedStandard()
	nc, gd := clientFor("proj", platform.NameCom), clientFor("proj", platform.GoDaddy)
	nc.zones = []platform.Zone{zone("z-nc", "shared.com")}
	gd.zones = []platform.Zone{zone("z-gd", "proj-shop.com")}

	// Neither account of proj is indexed yet: both are indexed, nobody else.
	tgt, err := h.rt.ResolveDomain(ctx, "www.proj-shop.com", platform.ResZone)
	if err != nil {
		t.Fatalf("ResolveDomain with --profile proj: %v", err)
	}
	if tgt.Profile != "proj" || tgt.Platform != platform.GoDaddy || tgt.ResourceID != "z-gd" {
		t.Errorf("target = %+v", tgt)
	}
	if !strings.Contains(h.stderr.String(), "indexing zone across 2 account(s)") {
		t.Errorf("stderr = %q", h.stderr.String())
	}
	if nc.count("Sync:zone") != 1 || gd.count("Sync:zone") != 1 {
		t.Errorf("calls: namecom %v, godaddy %v", nc.calls, gd.calls)
	}
	for _, p := range []string{"a", "b", "c"} {
		if n := h.client(p).count(""); n != 0 {
			t.Errorf("profile %s was reached although --profile proj was given: %v", p, h.client(p).calls)
		}
	}

	// shared.com is also owned by a and b; --profile proj picks proj's zone.
	tgt, err = h.rt.ResolveDomain(ctx, "www.shared.com", platform.ResZone)
	if err != nil || tgt.Profile != "proj" || tgt.Platform != platform.NameCom || tgt.ResourceID != "z-nc" {
		t.Errorf("shared.com with --profile proj = %+v, %v", tgt, err)
	}
	// A domain of another profile stays out of reach, without a re-index.
	if _, err := h.rt.ResolveDomain(ctx, "www.example.com", platform.ResZone); !errors.Is(err, app.ErrDomainUnknown) {
		t.Errorf("example.com with --profile proj = %v, want ErrDomainUnknown", err)
	}
	if nc.count("Sync:zone") != 1 || gd.count("Sync:zone") != 1 {
		t.Errorf("an indexed profile was re-synced on a miss: namecom %v, godaddy %v", nc.calls, gd.calls)
	}

	// With one account indexed and one not, the miss names the account.
	h2 := newHarness(t, app.Flags{Profile: "proj"}, withProj)
	h2.seedZonesFor(ref("proj", platform.NameCom), zone("z-nc", "proj-dns.com"))
	_, err = h2.rt.ResolveDomain(ctx, "nope.org", platform.ResZone)
	if !errors.Is(err, app.ErrDomainUnknown) || !strings.Contains(err.Error(), "account(s) godaddy/proj not indexed yet") {
		t.Errorf("partly indexed profile = %v", err)
	}

	// An unknown --profile is reported as such.
	h3 := newHarness(t, app.Flags{Profile: "zzz"}, withProj)
	if _, err := h3.rt.ResolveDomain(ctx, "example.com", platform.ResZone); err == nil || !strings.Contains(err.Error(), `profile "zzz" not found`) {
		t.Errorf("unknown --profile = %v", err)
	}
}

func TestAccounts(t *testing.T) {
	mutate := func(c *config.Config) {
		// cloudflare and aws are not registered in this test binary, so their
		// accounts are listed but cannot hold any resource type.
		c.Profiles["proj"] = profileOn(platform.NameCom, platform.GoDaddy, platform.Cloudflare)
		c.Profiles["aws"] = profileOn(platform.AWS)
		c.Profiles["empty"] = profileOn()
	}
	h := newHarness(t, app.Flags{}, mutate)

	all, err := h.rt.Accounts()
	if err != nil {
		t.Fatal(err)
	}
	// Sorted by profile, then platform.
	if got := refs(all); got != "a/namecom,aws/aws,b/namecom,c/godaddy,proj/cloudflare,proj/godaddy,proj/namecom" {
		t.Errorf("Accounts = %s", got)
	}
	dom, err := h.rt.DomainAccounts()
	if err != nil {
		t.Fatal(err)
	}
	if got := refs(dom); got != "a/namecom,b/namecom,c/godaddy,proj/godaddy,proj/namecom" {
		t.Errorf("DomainAccounts = %s", got)
	}
	zones, err := h.rt.AccountsFor(platform.ResZone)
	if err != nil || refs(zones) != refs(dom) {
		t.Errorf("AccountsFor(zone) = %s, %v", refs(zones), err)
	}
	// An account supporting several of the kinds is listed once.
	if got, err := h.rt.AccountsFor(platform.ResZone, platform.ResDNSRecord, platform.ResDomain); err != nil || refs(got) != refs(dom) {
		t.Errorf("AccountsFor(zone, dns_record, domain) = %s, %v", refs(got), err)
	}
	if got, err := h.rt.AccountsFor(platform.ResInstance); err != nil || len(got) != 0 {
		t.Errorf("AccountsFor(instance) = %s, %v", refs(got), err)
	}
	if got, err := h.rt.AccountsFor(); err != nil || len(got) != 0 {
		t.Errorf("AccountsFor() = %s, %v", refs(got), err)
	}

	// --profile restricts all three to the accounts of that profile.
	h.rt.Flags.Profile = "proj"
	if got, err := h.rt.Accounts(); err != nil || refs(got) != "proj/cloudflare,proj/godaddy,proj/namecom" {
		t.Errorf("Accounts with --profile proj = %s, %v", refs(got), err)
	}
	if got, err := h.rt.DomainAccounts(); err != nil || refs(got) != "proj/godaddy,proj/namecom" {
		t.Errorf("DomainAccounts with --profile proj = %s, %v", refs(got), err)
	}
	if got, err := h.rt.AccountsFor(platform.ResDomain); err != nil || refs(got) != "proj/godaddy,proj/namecom" {
		t.Errorf("AccountsFor(domain) with --profile proj = %s, %v", refs(got), err)
	}
	h.rt.Flags.Profile = "c"
	if got, err := h.rt.DomainAccounts(); err != nil || refs(got) != "c/godaddy" {
		t.Errorf("DomainAccounts with --profile c = %s, %v", refs(got), err)
	}
	// A profile whose only account cannot hold domains, or with no account.
	h.rt.Flags.Profile = "aws"
	if got, err := h.rt.Accounts(); err != nil || refs(got) != "aws/aws" {
		t.Errorf("Accounts with --profile aws = %s, %v", refs(got), err)
	}
	if got, err := h.rt.DomainAccounts(); err != nil || len(got) != 0 {
		t.Errorf("DomainAccounts with --profile aws = %s, %v", refs(got), err)
	}
	h.rt.Flags.Profile = "empty"
	if got, err := h.rt.Accounts(); err != nil || len(got) != 0 {
		t.Errorf("Accounts with --profile empty = %s, %v", refs(got), err)
	}
	// An unknown profile is an error for all three.
	h.rt.Flags.Profile = "zzz"
	if _, err := h.rt.Accounts(); !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), `profile "zzz" not found`) {
		t.Errorf("Accounts with unknown --profile = %v", err)
	}
	if _, err := h.rt.AccountsFor(platform.ResZone); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("AccountsFor with unknown --profile = %v", err)
	}
	if _, err := h.rt.DomainAccounts(); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("DomainAccounts with unknown --profile = %v", err)
	}
}

// legacyConfig is a config file in the one-platform-per-profile layout, next
// to one profile already in the current layout.
const legacyConfig = `current_profile: old
credential_store: file
profiles:
  old:
    platform: namecom
    metadata:
      account: acme
    credential_backend: file
    created_at: 2026-01-02T03:04:05Z
    updated_at: 2026-02-03T04:05:06Z
  shop:
    platform: godaddy
  new:
    platforms:
      godaddy:
        metadata:
          account: fresh
`

// legacyRuntime writes legacyConfig and the given secrets into a temporary
// config dir and returns a Runtime on it that uses the file store.
func legacyRuntime(t *testing.T, flags app.Flags, secrets map[string]string) (*app.Runtime, string, *bytes.Buffer) {
	t.Helper()
	registerFakes()
	resetFakes()
	dir := t.TempDir()
	t.Setenv(config.EnvConfigDir, dir)
	t.Setenv("POLYCTL_CREDENTIAL_STORE", "file")
	t.Setenv("POLYCTL_INVENTORY_DB", "")
	t.Setenv("POLYCTL_OUTPUT", "")
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(legacyConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	store := creds.NewFile(dir)
	for key, token := range secrets {
		if err := store.Set(key, map[string]string{"token": token}); err != nil {
			t.Fatal(err)
		}
	}
	flags.ConfigPath = cfgPath
	stderr := &bytes.Buffer{}
	rt := app.New(flags, strings.NewReader(""), &bytes.Buffer{}, stderr)
	if err := rt.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })
	return rt, dir, stderr
}

func TestLegacySecretMigration(t *testing.T) {
	rt, dir, _ := legacyRuntime(t, app.Flags{}, map[string]string{
		"old":         "legacy-old",
		"shop":        "legacy-shop",
		"new/godaddy": "current-new",
	})
	cfgPath := filepath.Join(dir, "config.yaml")

	// Loading alone converts the layout in memory and marks the accounts.
	cfg, err := rt.Config()
	if err != nil {
		t.Fatal(err)
	}
	if got := refs(cfg.Accounts("")); got != "new/godaddy,old/namecom,shop/godaddy" {
		t.Fatalf("accounts after load = %s", got)
	}
	for _, r := range cfg.Accounts("") {
		a, _ := cfg.Account(r.Profile, r.Platform)
		if want := r.Profile != "new"; a.LegacySecret != want {
			t.Errorf("%s LegacySecret = %v, want %v", r, a.LegacySecret, want)
		}
	}
	if raw, _ := os.ReadFile(cfgPath); string(raw) != legacyConfig {
		t.Error("loading the config must not rewrite it")
	}

	// The first use of the credential store moves the secrets.
	if _, err := rt.Creds(); err != nil {
		t.Fatalf("Creds: %v", err)
	}
	store := creds.NewFile(dir)
	for key, want := range map[string]string{"old/namecom": "legacy-old", "shop/godaddy": "legacy-shop", "new/godaddy": "current-new"} {
		if s, err := store.Get(key); err != nil || s["token"] != want {
			t.Errorf("secret %q = %v, %v, want token %s", key, s, err, want)
		}
	}
	for _, key := range []string{"old", "shop", "new"} {
		if _, err := store.Get(key); !errors.Is(err, creds.ErrNotFound) {
			t.Errorf("legacy key %q survived the migration: %v", key, err)
		}
	}
	for _, r := range cfg.Accounts("") {
		if a, _ := cfg.Account(r.Profile, r.Platform); a.LegacySecret {
			t.Errorf("%s is still marked legacy", r)
		}
	}

	// The config file was rewritten in the current layout, keeping the rest.
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "legacy_secret") || strings.Contains(string(raw), "platform: ") || strings.Count(string(raw), "platforms:") != 3 {
		t.Errorf("config file after migration:\n%s", raw)
	}
	disk, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("reload migrated config: %v", err)
	}
	if disk.CurrentProfile != "old" || disk.CredentialStore != "file" || refs(disk.Accounts("")) != "new/godaddy,old/namecom,shop/godaddy" {
		t.Errorf("reloaded config = %+v (%s)", disk, refs(disk.Accounts("")))
	}
	old, err := disk.Account("old", platform.NameCom)
	if err != nil {
		t.Fatal(err)
	}
	if old.LegacySecret || old.Metadata["account"] != "acme" || old.CredentialBackend != "file" ||
		!old.CreatedAt.Equal(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)) || !old.UpdatedAt.Equal(time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)) {
		t.Errorf("old/namecom after migration = %+v", old)
	}
	if shop, err := disk.Account("shop", platform.GoDaddy); err != nil || shop.LegacySecret || shop.CredentialBackend != "file" {
		t.Errorf("shop/godaddy after migration = %+v, %v", shop, err)
	}
	if fresh, err := disk.Account("new", platform.GoDaddy); err != nil || fresh.Metadata["account"] != "fresh" {
		t.Errorf("new/godaddy after migration = %+v, %v", fresh, err)
	}

	// The migrated accounts are usable, and a refreshed secret goes to the
	// new key.
	p, err := rt.LoadProfile("old", platform.NameCom)
	if err != nil || p.Secret["token"] != "legacy-old" || p.Metadata["account"] != "acme" || p.Platform != platform.NameCom {
		t.Fatalf("LoadProfile(old, namecom) = %+v, %v", p, err)
	}
	if err := p.UpdateSecret(map[string]string{"token": "rotated"}); err != nil {
		t.Fatal(err)
	}
	if s, _ := store.Get("old/namecom"); s["token"] != "rotated" {
		t.Errorf("UpdateSecret wrote %v under old/namecom", s)
	}
	if _, err := store.Get("old"); !errors.Is(err, creds.ErrNotFound) {
		t.Errorf("UpdateSecret recreated the legacy key: %v", err)
	}
	if got, err := rt.ProfileFor(platform.NameCom); err != nil || got != "old" {
		t.Errorf("ProfileFor(namecom) = %q, %v", got, err)
	}

	// A second run on the migrated files is a no-op.
	before, _ := os.ReadFile(cfgPath)
	rt2 := app.New(app.Flags{ConfigPath: cfgPath}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err := rt2.Init(); err != nil {
		t.Fatal(err)
	}
	if p, err := rt2.LoadProfile("shop", platform.GoDaddy); err != nil || p.Secret["token"] != "legacy-shop" {
		t.Errorf("second run LoadProfile(shop, godaddy) = %+v, %v", p, err)
	}
	if after, _ := os.ReadFile(cfgPath); !bytes.Equal(before, after) {
		t.Errorf("second run rewrote the config:\n%s", after)
	}
}

func TestLegacySecretMigrationThroughOpen(t *testing.T) {
	// No explicit Creds() call: opening a legacy profile migrates it.
	rt, dir, _ := legacyRuntime(t, app.Flags{}, map[string]string{"old": "legacy-old"})
	c, p, err := rt.Open(ctx, "old", platform.NameCom)
	if err != nil || c == nil {
		t.Fatalf("Open(old, namecom): %v", err)
	}
	if p.Secret["token"] != "legacy-old" || clientFor("old", platform.NameCom).count("Open") != 1 {
		t.Errorf("profile = %+v", p)
	}
	store := creds.NewFile(dir)
	if s, err := store.Get("old/namecom"); err != nil || s["token"] != "legacy-old" {
		t.Errorf("secret under the new key = %v, %v", s, err)
	}
	if _, err := store.Get("old"); !errors.Is(err, creds.ErrNotFound) {
		t.Errorf("legacy key survived: %v", err)
	}

	// shop has no secret under either key. That does not prove there is
	// nothing to move (the secret may sit in a backend this run cannot reach),
	// so shop keeps its mark; using it asks for a login on the right platform.
	_, err = rt.LoadProfile("shop", platform.GoDaddy)
	if !errors.Is(err, platform.ErrUnauthorized) || !strings.Contains(err.Error(), "auth login godaddy --profile shop") {
		t.Errorf("LoadProfile(shop, godaddy) without a secret = %v", err)
	}
	disk, err := config.Load(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range disk.Accounts("") {
		a, _ := disk.Account(r.Profile, r.Platform)
		if want := r.Profile == "shop"; a.LegacySecret != want {
			t.Errorf("%s LegacySecret on disk = %v, want %v", r, a.LegacySecret, want)
		}
	}
	// A legacy profile holds only the platform it was created for.
	if _, err := rt.LoadProfile("old", platform.GoDaddy); err == nil || !strings.Contains(err.Error(), `profile "old" has no godaddy account`) {
		t.Errorf("LoadProfile(old, godaddy) = %v", err)
	}
}

func TestLegacySecretFallbackWhenMigrationFails(t *testing.T) {
	rt, dir, stderr := legacyRuntime(t, app.Flags{Verbose: true}, map[string]string{"old": "legacy-old"})
	cfgPath := filepath.Join(dir, "config.yaml")
	// A lock file that cannot be opened (a directory is in its place) lets
	// the store read but not write, on every operating system, so the secret
	// cannot be moved.
	lock := filepath.Join(dir, "credentials.lock")
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(lock, 0o700); err != nil {
		t.Fatal(err)
	}

	p, err := rt.LoadProfile("old", platform.NameCom)
	if err != nil || p.Secret["token"] != "legacy-old" {
		t.Fatalf("LoadProfile must fall back to the legacy key: %+v, %v", p, err)
	}
	if !strings.Contains(stderr.String(), "migrate credentials: lock ") {
		t.Errorf("verbose output = %q", stderr.String())
	}
	cfg, _ := rt.Config()
	if a, _ := cfg.Account("old", platform.NameCom); !a.LegacySecret {
		t.Error("an account whose secret was not moved must keep its legacy mark")
	}
	if raw, _ := os.ReadFile(cfgPath); string(raw) != legacyConfig {
		t.Errorf("config must be left alone when the migration failed:\n%s", raw)
	}
	if s, err := creds.NewFile(dir).Get("old"); err != nil || s["token"] != "legacy-old" {
		t.Errorf("legacy secret = %v, %v", s, err)
	}

	// Once the store can be written again the next run finishes the job.
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	rt2 := app.New(app.Flags{ConfigPath: cfgPath}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err := rt2.Init(); err != nil {
		t.Fatal(err)
	}
	if p, err := rt2.LoadProfile("old", platform.NameCom); err != nil || p.Secret["token"] != "legacy-old" {
		t.Errorf("LoadProfile after the retry = %+v, %v", p, err)
	}
	if s, err := creds.NewFile(dir).Get("old/namecom"); err != nil || s["token"] != "legacy-old" {
		t.Errorf("secret under the new key after the retry = %v, %v", s, err)
	}
	if _, err := creds.NewFile(dir).Get("old"); !errors.Is(err, creds.ErrNotFound) {
		t.Errorf("legacy key after the retry: %v", err)
	}
}

func TestLegacySecretMigrationKeepsNewerSecret(t *testing.T) {
	// The new key already holds a secret (an interrupted migration, or a token
	// refreshed since): the legacy copy must not overwrite it.
	rt, dir, _ := legacyRuntime(t, app.Flags{}, map[string]string{"old": "stale", "old/namecom": "refreshed"})
	p, err := rt.LoadProfile("old", platform.NameCom)
	if err != nil || p.Secret["token"] != "refreshed" {
		t.Fatalf("LoadProfile(old, namecom) = %+v, %v", p, err)
	}
	store := creds.NewFile(dir)
	if s, err := store.Get("old/namecom"); err != nil || s["token"] != "refreshed" {
		t.Errorf("secret under the new key = %v, %v", s, err)
	}
	if _, err := store.Get("old"); !errors.Is(err, creds.ErrNotFound) {
		t.Errorf("stale legacy copy survived: %v", err)
	}
	disk, err := config.Load(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := disk.Account("old", platform.NameCom); a.LegacySecret {
		t.Error("old/namecom is still marked legacy on disk")
	}
}

func TestLegacySecretMarkWhenNoSecretIsFound(t *testing.T) {
	// No secret at all. old/namecom names the file backend, which is in
	// use and holds nothing: its mark goes. shop/godaddy does not say where
	// its secret was stored, which may be a keyring this run does not use:
	// its mark stays and every later run looks again.
	rt, dir, stderr := legacyRuntime(t, app.Flags{Verbose: true}, nil)
	cfgPath := filepath.Join(dir, "config.yaml")
	if _, err := rt.Creds(); err != nil {
		t.Fatal(err)
	}
	cfg, _ := rt.Config()
	for _, r := range cfg.Accounts("") {
		a, _ := cfg.Account(r.Profile, r.Platform)
		if want := r.Profile == "shop"; a.LegacySecret != want {
			t.Errorf("%s LegacySecret = %v, want %v", r, a.LegacySecret, want)
		}
	}
	disk, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := disk.Account("old", platform.NameCom); a.LegacySecret {
		t.Error("old/namecom is still marked legacy on disk")
	}
	if a, _ := disk.Account("shop", platform.GoDaddy); !a.LegacySecret {
		t.Error("shop/godaddy lost its mark on disk")
	}
	if strings.Contains(stderr.String(), "migrate credentials") {
		t.Errorf("a secret that is simply absent is not worth a log line: %q", stderr.String())
	}
	if _, err := rt.LoadProfile("old", platform.NameCom); !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("LoadProfile without any secret = %v, want ErrUnauthorized", err)
	}

	// The secret shows up under the bare name later: the next run moves it.
	if err := creds.NewFile(dir).Set("shop", map[string]string{"token": "late"}); err != nil {
		t.Fatal(err)
	}
	rt2 := app.New(app.Flags{ConfigPath: cfgPath}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err := rt2.Init(); err != nil {
		t.Fatal(err)
	}
	if p, err := rt2.LoadProfile("shop", platform.GoDaddy); err != nil || p.Secret["token"] != "late" {
		t.Fatalf("LoadProfile on the next run = %+v, %v", p, err)
	}
	if disk, err = config.Load(cfgPath); err != nil {
		t.Fatal(err)
	}
	if a, _ := disk.Account("shop", platform.GoDaddy); a.LegacySecret {
		t.Error("shop/godaddy must lose its mark once its secret was moved")
	}
}

// terminalStub stands in for a terminal: a Runtime with it is in the
// interactive flow. It counts the arrow-key prompts it is asked to show.
type terminalStub struct{ asked int }

func (p *terminalStub) Select(string, []prompt.Option, string) (string, error) {
	p.asked++
	return "", prompt.ErrAborted
}

func (p *terminalStub) MultiSelect(string, []prompt.Option) ([]string, error) {
	p.asked++
	return nil, prompt.ErrAborted
}

func (p *terminalStub) Confirm(string, bool) (bool, error) {
	p.asked++
	return false, prompt.ErrAborted
}

func (p *terminalStub) Input(string, string, func(string) error) (string, error) {
	p.asked++
	return "", prompt.ErrAborted
}

// unreadStdin counts the reads of a stdin that must not be read.
type unreadStdin struct{ reads int }

func (r *unreadStdin) Read([]byte) (int, error) {
	r.reads++
	return 0, io.EOF
}

// Confirm treats a question that was left as a no.
func TestConfirmLeftIsNo(t *testing.T) {
	t.Setenv(app.EnvNoInput, "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt := app.New(app.Flags{}, strings.NewReader("y\n"), &bytes.Buffer{}, &bytes.Buffer{})
	rt.Picker = &terminalStub{}
	if ok, err := rt.Confirm(ctx, "delete", true); ok || err != nil {
		t.Errorf("Confirm on an interrupted command = %v, %v; want false, nil", ok, err)
	}
	if ok, err := rt.Confirm(context.Background(), "delete", false); !ok || err != nil {
		t.Errorf("Confirm with y typed = %v, %v; want true, nil", ok, err)
	}
}

// The flow is decided in one place: a terminal on stdin and stderr (here the
// injected picker), unless --no-input or POLYCTL_NO_INPUT forces it off.
func TestInteractiveDecision(t *testing.T) {
	for _, tc := range []struct {
		name     string
		terminal bool
		flag     bool
		env      string
		want     bool
		initErr  bool
	}{
		{name: "terminal", terminal: true, want: true},
		{name: "no terminal"},
		{name: "terminal, --no-input", terminal: true, flag: true},
		{name: "no terminal, --no-input", flag: true},
		{name: "terminal, env 1", terminal: true, env: "1"},
		{name: "terminal, env true", terminal: true, env: "true"},
		{name: "terminal, env YES", terminal: true, env: "YES"},
		{name: "terminal, env padded", terminal: true, env: " 1 "},
		{name: "terminal, env 0", terminal: true, env: "0", want: true},
		{name: "terminal, env false", terminal: true, env: "False", want: true},
		{name: "terminal, env no", terminal: true, env: "no", want: true},
		{name: "terminal, env empty", terminal: true, env: "", want: true},
		{name: "terminal, env invalid", terminal: true, env: "maybe", initErr: true},
		{name: "no terminal, env invalid", env: "2", initErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv(config.EnvConfigDir, dir)
			t.Setenv(app.EnvNoInput, tc.env)
			stdin, stub := &unreadStdin{}, &terminalStub{}
			var stderr bytes.Buffer
			rt := app.New(app.Flags{NoInput: tc.flag}, stdin, &bytes.Buffer{}, &stderr)
			if tc.terminal {
				rt.Picker = stub
			}
			// The decision is available before Init: cobra validates the
			// arguments first.
			if got := rt.Interactive(); got != tc.want {
				t.Errorf("Interactive() = %v, want %v", got, tc.want)
			}
			err := rt.Init()
			if (err != nil) != tc.initErr {
				t.Fatalf("Init = %v, want an error: %v", err, tc.initErr)
			}
			if tc.initErr && (!strings.Contains(err.Error(), app.EnvNoInput) || !strings.Contains(err.Error(), tc.env)) {
				t.Errorf("Init error does not name the variable and its value: %v", err)
			}
			if got := rt.Prompt().Interactive(); got != tc.want {
				t.Errorf("Prompt().Interactive() = %v, want %v", got, tc.want)
			}
			in := rt.LoginInput("p", nil, nil)
			if in.Interactive != tc.want || in.NoBrowser != !tc.want || in.MayOpenBrowser() != tc.want || in.Prompt != rt.Prompt() {
				t.Errorf("LoginInput: Interactive %v, NoBrowser %v, MayOpenBrowser %v; want %v, %v, %v and the shared prompt", in.Interactive, in.NoBrowser, in.MayOpenBrowser(), tc.want, !tc.want, tc.want)
			}
			if tc.want {
				if rt.Pick() != prompt.Picker(stub) {
					t.Error("Pick must return the injected picker in the interactive flow")
				}
				return
			}
			// Non-interactive: every question is refused without touching
			// the picker or either stream.
			pk := rt.Pick()
			_, e1 := pk.Select("Platform", []prompt.Option{{Label: "a", Value: "a"}}, "")
			_, e2 := pk.MultiSelect("Remove", nil)
			_, e3 := pk.Confirm("Sure", true)
			_, e4 := pk.Input("Name", "x", nil)
			for i, e := range []error{e1, e2, e3, e4} {
				if !errors.Is(e, app.ErrUsage) {
					t.Errorf("picker question %d = %v, want a usage error", i, e)
				}
			}
			if !strings.Contains(e1.Error(), "Platform") {
				t.Errorf("the refusal does not name the question: %v", e1)
			}
			p := rt.Prompt()
			if _, err := p.Required("x"); !errors.Is(err, prompt.ErrNotInteractive) {
				t.Errorf("line prompt = %v, want ErrNotInteractive", err)
			}
			ok, err := rt.Confirm(context.Background(), "delete 2 records", true)
			if ok || !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "confirmation required: pass --yes to proceed (would delete 2 records)") {
				t.Errorf("Confirm = %v, %v; want the usage error naming --yes", ok, err)
			}
			if err := rt.CanConfirm("delete 2 records"); !errors.Is(err, app.ErrUsage) {
				t.Errorf("CanConfirm = %v, want a usage error", err)
			}
			if stub.asked != 0 || stdin.reads != 0 || stderr.Len() != 0 {
				t.Errorf("picker asked %d time(s), stdin read %d time(s), stderr %q; want nothing", stub.asked, stdin.reads, stderr.String())
			}
			// --yes answers the confirmation in the non-interactive flow too.
			rt.Flags.Yes = true
			if ok, err := rt.Confirm(context.Background(), "delete 2 records", false); !ok || err != nil {
				t.Errorf("Confirm with --yes = %v, %v", ok, err)
			}
			if err := rt.CanConfirm("x"); err != nil || stdin.reads != 0 {
				t.Errorf("CanConfirm with --yes = %v (stdin read %d time(s))", err, stdin.reads)
			}
		})
	}
}

// --yes skips the question in the interactive flow as well.
func TestConfirmYesAsksNothing(t *testing.T) {
	t.Setenv(app.EnvNoInput, "")
	stdin := &unreadStdin{}
	var stderr bytes.Buffer
	rt := app.New(app.Flags{Yes: true}, stdin, &bytes.Buffer{}, &stderr)
	rt.Picker = &terminalStub{}
	if ok, err := rt.Confirm(context.Background(), "delete", false); !ok || err != nil || stdin.reads != 0 || stderr.Len() != 0 {
		t.Errorf("Confirm with --yes = %v, %v (stdin read %d time(s), stderr %q)", ok, err, stdin.reads, stderr.String())
	}
}

// `--set key=-` values: one line each from one shared reader, silently, in
// the non-interactive flow; a prompt in the interactive one.
func TestStdinValue(t *testing.T) {
	t.Setenv(app.EnvNoInput, "")
	ctx := context.Background()
	var stderr bytes.Buffer
	rt := app.New(app.Flags{}, strings.NewReader("first\nsecond\n"), &bytes.Buffer{}, &stderr)
	for _, want := range []string{"first", "second"} {
		if v, err := rt.StdinValue(ctx, "key", true); err != nil || v != want {
			t.Errorf("StdinValue = %q, %v; want %q", v, err, want)
		}
	}
	// The same reader serves the login flow afterwards: nothing is left.
	if _, err := rt.LoginInput("p", nil, nil).IO(ctx).ReadValue(); !errors.Is(err, prompt.ErrNoValue) {
		t.Errorf("read after both lines = %v, want ErrNoValue", err)
	}
	_, err := rt.StdinValue(ctx, "token", true)
	if !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--set token=-") {
		t.Errorf("StdinValue on an empty stdin = %v, want a usage error naming the key", err)
	}
	if stderr.Len() != 0 {
		t.Errorf("the non-interactive flow printed %q", stderr.String())
	}

	// Interactive: asked for, with the key as the label.
	stderr.Reset()
	rt = app.New(app.Flags{}, strings.NewReader("typed\n"), &bytes.Buffer{}, &stderr)
	rt.Picker = &terminalStub{}
	if v, err := rt.StdinValue(ctx, "token", true); err != nil || v != "typed" || !strings.Contains(stderr.String(), "token: ") {
		t.Errorf("interactive StdinValue = %q, %v (stderr %q)", v, err, stderr.String())
	}
}

func TestRoutePlatformFlag(t *testing.T) {
	h := newHarness(t, app.Flags{}, withProj)
	if id, err := h.rt.RoutePlatform(); err != nil || id != "" {
		t.Errorf("RoutePlatform without the flag = %q, %v", id, err)
	}
	for in, want := range map[string]platform.ID{"godaddy": platform.GoDaddy, "gd": platform.GoDaddy, "name.com": platform.NameCom} {
		h.rt.Flags.Platform = in
		if id, err := h.rt.RoutePlatform(); err != nil || id != want {
			t.Errorf("RoutePlatform(%q) = %q, %v", in, id, err)
		}
	}

	// --platform restricts the account listings, alone and with --profile.
	h.rt.Flags.Platform = "gd"
	if got, err := h.rt.Accounts(); err != nil || refs(got) != "c/godaddy,proj/godaddy" {
		t.Errorf("Accounts with --platform gd = %s, %v", refs(got), err)
	}
	if got, err := h.rt.DomainAccounts(); err != nil || refs(got) != "c/godaddy,proj/godaddy" {
		t.Errorf("DomainAccounts with --platform gd = %s, %v", refs(got), err)
	}
	h.rt.Flags.Profile = "proj"
	if got, err := h.rt.AccountsFor(platform.ResZone); err != nil || refs(got) != "proj/godaddy" {
		t.Errorf("AccountsFor(zone) with --profile proj --platform gd = %s, %v", refs(got), err)
	}
	h.rt.Flags.Profile = "a"
	if got, err := h.rt.Accounts(); err != nil || len(got) != 0 {
		t.Errorf("Accounts with --profile a --platform gd = %s, %v", refs(got), err)
	}
	h.rt.Flags.Profile = ""
	h.rt.Flags.Platform = "cloudflare"
	if got, err := h.rt.Accounts(); err != nil || len(got) != 0 {
		t.Errorf("Accounts on a platform nobody has = %s, %v", refs(got), err)
	}

	// An unknown platform is a usage error everywhere the flag is read.
	h.rt.Flags.Platform = "nosuch"
	if _, err := h.rt.RoutePlatform(); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), `unknown platform "nosuch"`) {
		t.Errorf("RoutePlatform(nosuch) = %v", err)
	}
	if _, err := h.rt.Accounts(); !errors.Is(err, app.ErrUsage) {
		t.Errorf("Accounts with --platform nosuch = %v", err)
	}
	if _, err := h.rt.DomainAccounts(); !errors.Is(err, app.ErrUsage) {
		t.Errorf("DomainAccounts with --platform nosuch = %v", err)
	}
	if _, err := h.rt.ResolveDomain(ctx, "example.com", platform.ResZone); !errors.Is(err, app.ErrUsage) {
		t.Errorf("ResolveDomain with --platform nosuch = %v", err)
	}
	for _, p := range []string{"a", "b", "c"} {
		if n := h.client(p).count(""); n != 0 {
			t.Errorf("profile %s was reached despite the invalid flag: %v", p, h.client(p).calls)
		}
	}
}

func TestResolveDomainPlatformFlagPicksAccountInsideProfile(t *testing.T) {
	seed := func(h *harness) {
		h.seedStandard()
		h.seedZonesFor(ref("proj", platform.NameCom), zone("z-both-nc", "both.com"))
		h.seedZonesFor(ref("proj", platform.GoDaddy), zone("z-both-gd", "both.com"))
	}

	// Without a flag the two accounts of proj are ambiguous (see
	// TestResolveDomainRoutesInsideOneProfile); --platform picks one.
	for flag, want := range map[string]struct {
		id   platform.ID
		zone string
	}{
		"godaddy": {platform.GoDaddy, "z-both-gd"},
		"gd":      {platform.GoDaddy, "z-both-gd"},
		"namecom": {platform.NameCom, "z-both-nc"},
	} {
		h := newHarness(t, app.Flags{Platform: flag}, withProj)
		seed(h)
		tgt, err := h.rt.ResolveDomain(ctx, "www.both.com", platform.ResZone)
		if err != nil {
			t.Errorf("--platform %s: %v", flag, err)
			continue
		}
		if tgt.Profile != "proj" || tgt.Platform != want.id || tgt.ResourceID != want.zone || tgt.Domain != "both.com" {
			t.Errorf("--platform %s: target = %+v", flag, tgt)
		}
		// The target opens the account of that platform only.
		if _, err := h.rt.OpenDNS(ctx, tgt); err != nil {
			t.Errorf("--platform %s: OpenDNS: %v", flag, err)
		}
		other := platform.NameCom
		if want.id == platform.NameCom {
			other = platform.GoDaddy
		}
		if clientFor("proj", want.id).count("Open") != 1 || clientFor("proj", other).count("") != 0 {
			t.Errorf("--platform %s opened the wrong account", flag)
		}
	}

	// Both flags together work as well.
	h := newHarness(t, app.Flags{Profile: "proj", Platform: "namecom"}, withProj)
	seed(h)
	if tgt, err := h.rt.ResolveDomain(ctx, "both.com", platform.ResZone); err != nil || tgt.Platform != platform.NameCom || tgt.ResourceID != "z-both-nc" {
		t.Errorf("--profile proj --platform namecom = %+v, %v", tgt, err)
	}

	// --platform alone does not help when two profiles hold the zone on that
	// platform: the hint then names --profile only.
	h = newHarness(t, app.Flags{Platform: "godaddy"}, withProj)
	seed(h)
	h.seedZones("c", zone("z-both-c", "both.com"))
	_, err := h.rt.ResolveDomain(ctx, "both.com", platform.ResZone)
	var amb *app.AmbiguousError
	if !errors.As(err, &amb) || strings.Join(amb.Candidates, " | ") != "godaddy/c (zone z-both-c) | godaddy/proj (zone z-both-gd)" {
		t.Fatalf("--platform godaddy with two godaddy owners = %v", err)
	}
	if amb.Hint != "pass --profile <name> to choose" {
		t.Errorf("hint = %q", amb.Hint)
	}
	// Without any flag the three owners differ in both ways.
	h.rt.Flags.Platform = ""
	if _, err := h.rt.ResolveDomain(ctx, "both.com", platform.ResZone); !errors.As(err, &amb) || len(amb.Candidates) != 3 ||
		amb.Hint != "pass --profile <name> and/or --platform <platform> to choose" {
		t.Errorf("three owners = %v", err)
	}

	// --platform restricts the search like --profile does: a zone held on
	// another platform is out of reach, and nothing is re-indexed.
	h.rt.Flags.Platform = "godaddy"
	if _, err := h.rt.ResolveDomain(ctx, "www.example.com", platform.ResZone); !errors.Is(err, app.ErrDomainUnknown) {
		t.Errorf("namecom zone with --platform godaddy = %v, want ErrDomainUnknown", err)
	}
	for _, r := range []config.AccountRef{ref("a", platform.NameCom), ref("b", platform.NameCom), ref("c", platform.GoDaddy), ref("proj", platform.NameCom), ref("proj", platform.GoDaddy)} {
		if n := clientFor(r.Profile, r.Platform).count("Sync"); n != 0 {
			t.Errorf("%s was synced %d times", r, n)
		}
	}
}

func TestResolveDomainPlatformFlagLimitsIndexing(t *testing.T) {
	// Nothing is indexed: a miss indexes the accounts of the platform only.
	h := newHarness(t, app.Flags{Platform: "godaddy"}, withProj)
	clientFor("proj", platform.GoDaddy).zones = []platform.Zone{zone("z-gd", "proj-shop.com")}
	clientFor("proj", platform.NameCom).zones = []platform.Zone{zone("z-nc", "proj-shop.com")}
	tgt, err := h.rt.ResolveDomain(ctx, "www.proj-shop.com", platform.ResZone)
	if err != nil || tgt.Profile != "proj" || tgt.Platform != platform.GoDaddy || tgt.ResourceID != "z-gd" {
		t.Fatalf("target = %+v, %v", tgt, err)
	}
	if !strings.Contains(h.stderr.String(), "indexing zone across 2 account(s)") {
		t.Errorf("stderr = %q", h.stderr.String())
	}
	if clientFor("c", platform.GoDaddy).count("Sync:zone") != 1 || clientFor("proj", platform.GoDaddy).count("Sync:zone") != 1 {
		t.Error("the godaddy accounts must be indexed")
	}
	for _, r := range []config.AccountRef{ref("a", platform.NameCom), ref("b", platform.NameCom), ref("proj", platform.NameCom)} {
		if n := clientFor(r.Profile, r.Platform).count(""); n != 0 {
			t.Errorf("%s was reached although --platform godaddy was given", r)
		}
	}
	// After indexing, a miss says the domain is in none of the accounts.
	h2 := newHarness(t, app.Flags{Platform: "godaddy"}, withProj)
	if _, err := h2.rt.ResolveDomain(ctx, "nope.org", platform.ResZone); !errors.Is(err, app.ErrDomainUnknown) || !strings.Contains(err.Error(), "is not a zone in the accounts selected by --profile / --platform") {
		t.Errorf("miss after indexing = %v", err)
	}

	// A platform no selected account is on: nothing to search, no login hint.
	h3 := newHarness(t, app.Flags{Platform: "cloudflare"}, withProj)
	_, err = h3.rt.ResolveDomain(ctx, "example.com", platform.ResZone)
	if !errors.Is(err, app.ErrDomainUnknown) || !strings.Contains(err.Error(), "no account selected by --profile / --platform is able to manage zones") || strings.Contains(err.Error(), "auth login") {
		t.Errorf("--platform cloudflare = %v", err)
	}
	h3.rt.Flags.Profile, h3.rt.Flags.Platform = "a", "godaddy"
	if _, err := h3.rt.ResolveDomain(ctx, "example.com", platform.ResZone); !errors.Is(err, app.ErrDomainUnknown) || !strings.Contains(err.Error(), "no account selected by --profile / --platform") {
		t.Errorf("--profile a --platform godaddy = %v", err)
	}
}

// Several polyctl processes started together after an upgrade all find the
// same secrets to move. Each Runtime stands for one process here: they share
// the files but nothing in memory.
func TestLegacySecretMigrationInParallel(t *testing.T) {
	const accounts, processes = 40, 4
	dir := t.TempDir()
	t.Setenv(config.EnvConfigDir, dir)
	t.Setenv("POLYCTL_CREDENTIAL_STORE", "file")
	t.Setenv("POLYCTL_OUTPUT", "")
	var body strings.Builder
	body.WriteString("credential_store: file\nprofiles:\n")
	seed := creds.NewFile(dir)
	for i := 0; i < accounts; i++ {
		name := fmt.Sprintf("p%d", i)
		fmt.Fprintf(&body, "  %s:\n    platform: namecom\n    credential_backend: file\n", name)
		if err := seed.Set(name, map[string]string{"token": name}); err != nil {
			t.Fatal(err)
		}
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(body.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	var rts []*app.Runtime
	for i := 0; i < processes; i++ {
		rt := app.New(app.Flags{ConfigPath: cfgPath}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
		if err := rt.Init(); err != nil {
			t.Fatal(err)
		}
		rts = append(rts, rt)
	}
	var wg sync.WaitGroup
	for _, rt := range rts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := rt.Creds(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()

	for i := 0; i < accounts; i++ {
		name := fmt.Sprintf("p%d", i)
		if s, err := seed.Get(creds.Key(name, "namecom")); err != nil || s["token"] != name {
			t.Errorf("secret of %s under the new key = %v, %v", name, s, err)
		}
		if _, err := seed.Get(name); !errors.Is(err, creds.ErrNotFound) {
			t.Errorf("bare key %s survived: %v", name, err)
		}
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "legacy_secret") || strings.Contains(string(raw), "platform: ") || strings.Count(string(raw), "platforms:") != accounts {
		t.Errorf("config after the parallel migration:\n%s", raw)
	}
	// Every process sees its accounts as migrated, whoever did the work.
	for i, rt := range rts {
		cfg, _ := rt.Config()
		for _, r := range cfg.Accounts("") {
			if a, _ := cfg.Account(r.Profile, r.Platform); a.LegacySecret {
				t.Errorf("process %d: %s is still marked legacy", i, r)
			}
		}
	}
}

// A process that only reads must not write its older copy of the config back
// when another process finished the migration and changed the file since.
func TestLegacySecretMigrationKeepsLaterConfigChanges(t *testing.T) {
	rt, dir, _ := legacyRuntime(t, app.Flags{}, map[string]string{"old": "legacy-old", "shop": "legacy-shop"})
	cfgPath := filepath.Join(dir, "config.yaml")

	// Another process migrates and then adds an account.
	other := app.New(app.Flags{ConfigPath: cfgPath}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err := other.Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := other.Creds(); err != nil {
		t.Fatal(err)
	}
	ocfg, _ := other.Config()
	ocfg.Profiles["added"] = profileOn(platform.GoDaddy)
	ocfg.CurrentProfile = "added"
	if err := ocfg.Save(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(cfgPath)

	// rt loaded the config before all that and opens the store only now.
	if _, err := rt.Creds(); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(cfgPath); !bytes.Equal(before, after) {
		t.Errorf("the config was rewritten from an older copy:\n%s", after)
	}
	cfg, _ := rt.Config()
	for _, name := range []string{"old", "shop"} {
		if a := cfg.Profiles[name].Platforms[cfg.Profiles[name].PlatformIDs()[0]]; a.LegacySecret {
			t.Errorf("%s is still marked legacy in memory", name)
		}
	}

	// A migration that does have work keeps the other changes too.
	rt2, dir2, _ := legacyRuntime(t, app.Flags{}, map[string]string{"old": "legacy-old"})
	cfgPath2 := filepath.Join(dir2, "config.yaml")
	disk, err := config.Load(cfgPath2)
	if err != nil {
		t.Fatal(err)
	}
	disk.Profiles["added"] = profileOn(platform.GoDaddy)
	if err := disk.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := rt2.Creds(); err != nil {
		t.Fatal(err)
	}
	disk, err = config.Load(cfgPath2)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := disk.Profiles["added"]; !ok {
		t.Error("the migration dropped a profile added by another process")
	}
	if a, _ := disk.Account("old", platform.NameCom); a == nil || a.LegacySecret {
		t.Errorf("old/namecom on disk = %+v, want it migrated", a)
	}
}

// A refreshed token is written to the primary backend and its copy in the
// other one removed; the config must follow, or commands that check whether
// the recorded backend is within reach look in the wrong place.
func TestUpdateSecretRecordsTheBackend(t *testing.T) {
	keyring.MockInit()
	registerFakes()
	resetFakes()
	dir := t.TempDir()
	t.Setenv(config.EnvConfigDir, dir)
	t.Setenv("POLYCTL_CREDENTIAL_STORE", "auto")
	t.Setenv("POLYCTL_OUTPUT", "")
	cfgPath := filepath.Join(dir, "config.yaml")
	body := "profiles:\n  p:\n    platforms:\n      namecom:\n        credential_backend: file\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	file := creds.NewFile(dir)
	if err := file.Set("p/namecom", map[string]string{"token": "old"}); err != nil {
		t.Fatal(err)
	}
	rt := app.New(app.Flags{ConfigPath: cfgPath}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err := rt.Init(); err != nil {
		t.Fatal(err)
	}
	p, err := rt.LoadProfile("p", platform.NameCom)
	if err != nil || p.Secret["token"] != "old" {
		t.Fatalf("LoadProfile = %+v, %v", p, err)
	}
	if raw, _ := os.ReadFile(cfgPath); string(raw) != body {
		t.Errorf("reading a secret must not rewrite the config:\n%s", raw)
	}
	if err := p.UpdateSecret(map[string]string{"token": "refreshed"}); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Get("p/namecom"); !errors.Is(err, creds.ErrNotFound) {
		t.Errorf("the file copy survived: %v", err)
	}
	if s, err := (creds.Keyring{}).Get("p/namecom"); err != nil || s["token"] != "refreshed" {
		t.Errorf("keyring = %v, %v", s, err)
	}
	disk, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := disk.Account("p", platform.NameCom); a == nil || a.CredentialBackend != "keyring" {
		t.Errorf("account on disk = %+v, want credential_backend keyring", a)
	}
}

func TestReloadConfig(t *testing.T) {
	rt := newHarness(t, app.Flags{}, nil).rt
	cfg, err := rt.Config()
	if err != nil {
		t.Fatal(err)
	}
	// Another process adds an account and switches the current profile.
	other, err := config.Load(cfg.Path())
	if err != nil {
		t.Fatal(err)
	}
	other.Profiles["added"] = profileOn(platform.GoDaddy)
	other.CurrentProfile = "added"
	if err := other.Save(); err != nil {
		t.Fatal(err)
	}
	fresh, err := rt.ReloadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := rt.Config(); again != fresh || fresh == cfg {
		t.Error("ReloadConfig must replace the copy Config returns")
	}
	if _, ok := fresh.Profiles["added"]; !ok || fresh.CurrentProfile != "added" {
		t.Errorf("reloaded config = %+v", fresh)
	}
	// A change saved from the reloaded copy keeps what the other process did.
	delete(fresh.Profiles, "a")
	if err := fresh.Save(); err != nil {
		t.Fatal(err)
	}
	disk, err := config.Load(cfg.Path())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := disk.Profiles["added"]; !ok || disk.CurrentProfile != "added" {
		t.Errorf("config on disk = %+v", disk)
	}

	// An unreadable file leaves the earlier copy in use.
	if err := os.WriteFile(cfg.Path(), []byte("profiles: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.ReloadConfig(); err == nil {
		t.Fatal("ReloadConfig of a malformed file must fail")
	}
	if kept, err := rt.Config(); err != nil || kept != fresh {
		t.Errorf("Config after a failed reload = %p, %v; want the earlier copy", kept, err)
	}
}
