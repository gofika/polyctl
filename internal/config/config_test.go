package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/platform"
)

func TestLoadMissingFileIsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Profiles == nil || len(cfg.Profiles) != 0 {
		t.Fatalf("Profiles = %v, want empty non-nil map", cfg.Profiles)
	}
	if cfg.Path() != path {
		t.Fatalf("Path() = %q, want %q", cfg.Path(), path)
	}
	if cfg.CurrentProfile != "" || cfg.Output != "" || cfg.TTL != nil {
		t.Fatalf("unexpected non-zero fields in empty config: %+v", cfg)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "config.yaml")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	cfg.CurrentProfile = "work"
	cfg.CredentialStore = "file"
	cfg.Output = "json"
	cfg.Profiles["work"] = &config.Profile{Platforms: map[platform.ID]*config.Account{
		platform.Cloudflare: {
			Metadata:          map[string]string{"account": "acc-1", "email": "me@example.com"},
			CredentialBackend: "file",
			CreatedAt:         created,
			UpdatedAt:         created,
		},
		platform.NameCom: {
			Metadata:          map[string]string{"username": "me"},
			CredentialBackend: "keyring",
			CreatedAt:         created,
			UpdatedAt:         updated,
		},
	}}
	cfg.Profiles["reg"] = &config.Profile{Platforms: map[platform.ID]*config.Account{
		platform.NameCom: {},
	}}
	cfg.TTL = map[string]config.Duration{
		string(platform.ResDNSRecord): config.Duration(90 * time.Minute),
		"default":                     config.Duration(2 * time.Hour),
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "1h30m0s") {
		t.Errorf("TTL not marshalled as a duration string:\n%s", raw)
	}
	if strings.Contains(string(raw), "secret") {
		t.Errorf("config must not contain secrets or a legacy_secret mark:\n%s", raw)
	}
	for _, want := range []string{"\n    work:\n        platforms:\n", "\n            cloudflare:\n", "\n            namecom:\n"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("saved config lacks %q:\n%s", want, raw)
		}
	}
	if strings.Contains(string(raw), "platform:") {
		t.Errorf("saved config uses the legacy platform key:\n%s", raw)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("config mode = %o, want 0600", fi.Mode().Perm())
		}
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "config.yaml" {
		t.Errorf("temporary file left behind: %v", entries)
	}

	got, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.CurrentProfile != "work" || got.CredentialStore != "file" || got.Output != "json" {
		t.Errorf("scalar fields not round-tripped: %+v", got)
	}
	work := got.Profiles["work"]
	if work == nil || len(work.Platforms) != 2 {
		t.Fatalf("profile work = %+v, want two platforms", work)
	}
	cf := work.Platforms[platform.Cloudflare]
	if cf == nil || cf.CredentialBackend != "file" || cf.LegacySecret {
		t.Fatalf("work/cloudflare = %+v", cf)
	}
	if !reflect.DeepEqual(cf.Metadata, map[string]string{"account": "acc-1", "email": "me@example.com"}) {
		t.Errorf("work/cloudflare metadata = %v", cf.Metadata)
	}
	if !cf.CreatedAt.Equal(created) || !cf.UpdatedAt.Equal(created) {
		t.Errorf("work/cloudflare timestamps = %v / %v, want %v", cf.CreatedAt, cf.UpdatedAt, created)
	}
	nc := work.Platforms[platform.NameCom]
	if nc == nil || nc.CredentialBackend != "keyring" || nc.LegacySecret {
		t.Fatalf("work/namecom = %+v", nc)
	}
	if !reflect.DeepEqual(nc.Metadata, map[string]string{"username": "me"}) {
		t.Errorf("work/namecom metadata = %v", nc.Metadata)
	}
	if !nc.CreatedAt.Equal(created) || !nc.UpdatedAt.Equal(updated) {
		t.Errorf("work/namecom timestamps = %v / %v", nc.CreatedAt, nc.UpdatedAt)
	}
	reg := got.Profiles["reg"]
	if reg == nil || len(reg.Platforms) != 1 || reg.Platforms[platform.NameCom] == nil {
		t.Fatalf("profile reg = %+v", reg)
	}
	if a := reg.Platforms[platform.NameCom]; a.Metadata != nil || a.CredentialBackend != "" || !a.CreatedAt.IsZero() {
		t.Errorf("reg/namecom = %+v, want a zero account", a)
	}
	if d := got.TTLFor(platform.ResDNSRecord); d != 90*time.Minute {
		t.Errorf("TTLFor(dns_record) = %v, want 90m", d)
	}
	if d := got.TTLFor(platform.ResZone); d != 2*time.Hour {
		t.Errorf("TTLFor(zone) = %v, want the configured default 2h", d)
	}
}

// writeConfig writes a config file into a temp dir and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const legacyConfig = `current_profile: cf
profiles:
    cf:
        platform: cloudflare
        metadata:
            account: acc-1
        credential_backend: keyring
        created_at: 2026-01-02T03:04:05Z
        updated_at: 2026-02-03T04:05:06Z
    reg:
        platform: name.com
`

func TestLoadLegacyLayout(t *testing.T) {
	path := writeConfig(t, legacyConfig)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CurrentProfile != "cf" {
		t.Errorf("CurrentProfile = %q", cfg.CurrentProfile)
	}
	if got := cfg.Accounts(""); !reflect.DeepEqual(got, []config.AccountRef{
		{Profile: "cf", Platform: platform.Cloudflare},
		{Profile: "reg", Platform: platform.NameCom},
	}) {
		t.Fatalf("Accounts = %v", got)
	}
	a, err := cfg.Account("cf", platform.Cloudflare)
	if err != nil {
		t.Fatal(err)
	}
	if !a.LegacySecret {
		t.Error("converted account must be marked LegacySecret")
	}
	if a.CredentialBackend != "keyring" || !reflect.DeepEqual(a.Metadata, map[string]string{"account": "acc-1"}) {
		t.Errorf("cf/cloudflare = %+v", a)
	}
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	if !a.CreatedAt.Equal(created) || !a.UpdatedAt.Equal(updated) {
		t.Errorf("timestamps = %v / %v", a.CreatedAt, a.UpdatedAt)
	}
	// A platform alias in the legacy key is normalised to its ID.
	reg, err := cfg.Account("reg", platform.NameCom)
	if err != nil {
		t.Fatal(err)
	}
	if !reg.LegacySecret || reg.Metadata != nil {
		t.Errorf("reg/namecom = %+v", reg)
	}

	// Saving rewrites the file in the current layout and keeps the mark.
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := string(raw)
	if strings.Contains(out, "platform:") {
		t.Errorf("saved config still uses the legacy platform key:\n%s", out)
	}
	if !strings.Contains(out, "\n    cf:\n        platforms:\n            cloudflare:\n") {
		t.Errorf("saved config is not in the platforms layout:\n%s", out)
	}
	if n := strings.Count(out, "legacy_secret: true"); n != 2 {
		t.Errorf("legacy_secret: true appears %d times, want 2:\n%s", n, out)
	}

	again, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !reflect.DeepEqual(again.Profiles, cfg.Profiles) {
		t.Errorf("profiles changed across save and reload:\n got %+v\nwant %+v", again.Profiles, cfg.Profiles)
	}

	// Once the mark is cleared it is no longer written.
	for _, ref := range again.Accounts("") {
		again.Profiles[ref.Profile].Platforms[ref.Platform].LegacySecret = false
	}
	if err := again.Save(); err != nil {
		t.Fatal(err)
	}
	if raw, _ = os.ReadFile(path); strings.Contains(string(raw), "legacy_secret") {
		t.Errorf("cleared mark still written:\n%s", raw)
	}
}

func TestLoadCurrentLayoutIsNotLegacy(t *testing.T) {
	cfg, err := config.Load(writeConfig(t, `profiles:
    acme:
        platforms:
            cf:
                metadata:
                    account: acc-1
            aws:
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	p := cfg.Profiles["acme"]
	if got := p.PlatformIDs(); !reflect.DeepEqual(got, []platform.ID{platform.AWS, platform.Cloudflare}) {
		t.Fatalf("PlatformIDs = %v", got)
	}
	if a := p.Platforms[platform.Cloudflare]; a.LegacySecret || a.Metadata["account"] != "acc-1" {
		t.Errorf("acme/cloudflare = %+v", a)
	}
	// An account with nothing under it is an empty account, not nil.
	if a := p.Platforms[platform.AWS]; a == nil || a.LegacySecret {
		t.Errorf("acme/aws = %+v, want an empty account", a)
	}
}

func TestLoadRejectsUnknownPlatform(t *testing.T) {
	cases := map[string]string{
		"legacy":  "profiles:\n  p:\n    platform: nosuch\n",
		"current": "profiles:\n  p:\n    platforms:\n      cloudflare: {}\n      nosuch: {}\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := config.Load(writeConfig(t, body))
			if err == nil || !strings.Contains(err.Error(), `unknown platform "nosuch"`) {
				t.Fatalf("Load = %v, want unknown platform error", err)
			}
		})
	}
}

func TestLoadRejectsPlatformConfiguredTwice(t *testing.T) {
	// "cf" is an alias of "cloudflare": both name the same account.
	_, err := config.Load(writeConfig(t, "profiles:\n  p:\n    platforms:\n      cloudflare: {}\n      cf: {}\n"))
	if err == nil || !strings.Contains(err.Error(), "configured twice") {
		t.Fatalf("Load = %v, want configured twice error", err)
	}
}

func TestLoadRejectsLegacyAndCurrentKeysTogether(t *testing.T) {
	// A profile is either in the legacy layout or in the current one; a file
	// with both keys would silently lose one of the two accounts.
	cases := map[string]string{
		"different platforms": "profiles:\n  p:\n    platform: cloudflare\n    platforms:\n      godaddy: {}\n",
		"same platform":       "profiles:\n  p:\n    platform: cloudflare\n    platforms:\n      cloudflare: {}\n",
		"empty platforms":     "profiles:\n  p:\n    platform: cloudflare\n    platforms: {}\n",
		"second profile":      "profiles:\n  ok:\n    platforms:\n      aws: {}\n  p:\n    platforms:\n      godaddy: {}\n    platform: cf\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, body)
			cfg, err := config.Load(path)
			if err == nil {
				t.Fatalf("Load = %+v, want an error", cfg.Profiles["p"])
			}
			for _, want := range []string{"parse " + path, "both platform (legacy layout) and platforms are set", "keep only platforms"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error lacks %q: %v", want, err)
				}
			}
			if raw, _ := os.ReadFile(path); string(raw) != body {
				t.Error("a rejected config must be left untouched")
			}
		})
	}
	// Each key alone still loads.
	for _, body := range []string{"profiles:\n  p:\n    platform: cloudflare\n", "profiles:\n  p:\n    platforms:\n      cloudflare: {}\n"} {
		cfg, err := config.Load(writeConfig(t, body))
		if err != nil || len(cfg.Profiles["p"].Platforms) != 1 || cfg.Profiles["p"].Platforms[platform.Cloudflare] == nil {
			t.Errorf("Load(%q) = %v", body, err)
		}
	}
}

// A hand-edited profile that mixes the two layouts in a way that cannot be
// converted must not load with a part of it silently dropped.
func TestLoadRejectsHalfLegacyProfiles(t *testing.T) {
	cases := map[string]struct{ body, want string }{
		"null platform with metadata":  {"profiles:\n  p:\n    platform:\n    metadata:\n      email: me@example.com\n", "platform (legacy layout) is empty"},
		"null platform alone":          {"profiles:\n  p:\n    platform:\n", "platform (legacy layout) is empty"},
		"empty platform":               {"profiles:\n  p:\n    platform: \"\"\n", "platform (legacy layout) is empty"},
		"null platform and platforms":  {"profiles:\n  p:\n    platform:\n    platforms:\n      godaddy: {}\n", "both platform (legacy layout) and platforms are set"},
		"platform and null platforms":  {"profiles:\n  p:\n    platform: cloudflare\n    platforms:\n", "both platform (legacy layout) and platforms are set"},
		"both null":                    {"profiles:\n  p:\n    platform:\n    platforms:\n", "both platform (legacy layout) and platforms are set"},
		"metadata without platform":    {"profiles:\n  p:\n    metadata:\n      email: me@example.com\n", "metadata is set on the profile itself"},
		"metadata next to platforms":   {"profiles:\n  p:\n    metadata:\n      email: me@example.com\n    platforms:\n      aws: {}\n", "metadata is set on the profile itself"},
		"backend without platform":     {"profiles:\n  p:\n    credential_backend: keyring\n", "credential_backend is set on the profile itself"},
		"timestamps next to platforms": {"profiles:\n  p:\n    platforms:\n      aws: {}\n    updated_at: 2026-01-02T03:04:05Z\n", "updated_at is set on the profile itself"},
		// Keys that arrive through a merge key count like written ones.
		"merged platform and platforms": {"base: &b\n  platform: aws\nprofiles:\n  p:\n    <<: *b\n    platforms: {}\n", "both platform (legacy layout) and platforms are set"},
		"merged platforms and platform": {"base: &b\n  platforms:\n    aws: {}\nprofiles:\n  p:\n    <<: *b\n    platform: godaddy\n", "both platform (legacy layout) and platforms are set"},
		"merge list with platform":      {"one: &one\n  platform: aws\ntwo: &two\n  platforms: {}\nprofiles:\n  p:\n    <<: [*two, *one]\n", "both platform (legacy layout) and platforms are set"},
		"inline merged metadata":        {"profiles:\n  p:\n    <<: {metadata: {email: me@example.com}}\n    platforms:\n      aws: {}\n", "metadata is set on the profile itself"},
		"aliased profile with both":     {"base: &b\n  platform: aws\n  platforms: {}\nprofiles:\n  p: *b\n", "both platform (legacy layout) and platforms are set"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, tc.body)
			cfg, err := config.Load(path)
			if err == nil {
				t.Fatalf("Load = %+v, want an error", cfg.Profiles["p"])
			}
			for _, want := range []string{"parse " + path, tc.want} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error lacks %q: %v", want, err)
				}
			}
			if raw, _ := os.ReadFile(path); string(raw) != tc.body {
				t.Error("a rejected config must be left untouched")
			}
		})
	}
}

func TestLoadEmptyProfileMapping(t *testing.T) {
	bodies := map[string]string{
		"null":            "profiles:\n  empty:\n",
		"empty mapping":   "profiles:\n  empty: {}\n",
		"null platforms":  "profiles:\n  empty:\n    platforms:\n",
		"empty platforms": "profiles:\n  empty:\n    platforms: {}\n",
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, body)
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			p, err := cfg.Profile("empty")
			if err != nil {
				t.Fatal(err)
			}
			if p == nil || p.Platforms == nil || len(p.Platforms) != 0 {
				t.Fatalf("profile = %+v, want an empty non-nil platform map", p)
			}
			if ids := p.PlatformIDs(); len(ids) != 0 {
				t.Errorf("PlatformIDs = %v", ids)
			}
			if refs := cfg.Accounts(""); len(refs) != 0 {
				t.Errorf("Accounts = %v", refs)
			}
			if _, err := cfg.Account("empty", platform.AWS); err == nil {
				t.Error("Account on an empty profile must fail")
			}
			// The profile survives a save and reload.
			if err := cfg.Save(); err != nil {
				t.Fatal(err)
			}
			again, err := config.Load(path)
			if err != nil {
				t.Fatalf("reload: %v", err)
			}
			if p := again.Profiles["empty"]; p == nil || len(p.Platforms) != 0 {
				t.Errorf("reloaded profile = %+v", p)
			}
		})
	}
}

func TestLoadNullProfilesKey(t *testing.T) {
	cfg, err := config.Load(writeConfig(t, "current_profile: x\nprofiles:\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Profiles == nil || len(cfg.Profiles) != 0 {
		t.Fatalf("Profiles = %v, want empty non-nil map", cfg.Profiles)
	}
}

func TestLoadRejectsInvalidDuration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("ttl:\n  zone: soon\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(path); err == nil || !strings.Contains(err.Error(), "invalid duration") {
		t.Fatalf("Load = %v, want invalid duration error", err)
	}
}

func TestLoadRejectsMalformedYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("profiles: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(path); err == nil {
		t.Fatal("Load accepted malformed YAML")
	}
}

func TestTTLForDefaults(t *testing.T) {
	cfg := &config.Config{}
	cases := map[platform.ResourceType]time.Duration{
		platform.ResDNSRecord:      time.Hour,
		platform.ResZone:           24 * time.Hour,
		platform.ResDomain:         24 * time.Hour,
		platform.ResInstance:       15 * time.Minute,
		platform.ResourceType("x"): 24 * time.Hour,
	}
	for rt, want := range cases {
		if got := cfg.TTLFor(rt); got != want {
			t.Errorf("TTLFor(%q) = %v, want %v", rt, got, want)
		}
	}
}

func TestTTLForOverrides(t *testing.T) {
	cfg := &config.Config{TTL: map[string]config.Duration{
		string(platform.ResInstance): config.Duration(time.Minute),
	}}
	if got := cfg.TTLFor(platform.ResInstance); got != time.Minute {
		t.Errorf("type override: got %v, want 1m", got)
	}
	if got := cfg.TTLFor(platform.ResZone); got != 24*time.Hour {
		t.Errorf("unconfigured type must use built-in default: got %v", got)
	}

	cfg.TTL["default"] = config.Duration(5 * time.Minute)
	if got := cfg.TTLFor(platform.ResZone); got != 5*time.Minute {
		t.Errorf("configured default must beat built-in default: got %v", got)
	}
	if got := cfg.TTLFor(platform.ResourceType("unknown")); got != 5*time.Minute {
		t.Errorf("configured default must apply to unknown types: got %v", got)
	}
	if got := cfg.TTLFor(platform.ResInstance); got != time.Minute {
		t.Errorf("type override must beat configured default: got %v", got)
	}
	// A zero TTL is a valid override meaning "always stale".
	cfg.TTL[string(platform.ResZone)] = 0
	if got := cfg.TTLFor(platform.ResZone); got != 0 {
		t.Errorf("zero override: got %v, want 0", got)
	}
}

// accounts builds a profile holding an empty account on each platform.
func accounts(ids ...platform.ID) *config.Profile {
	p := &config.Profile{Platforms: map[platform.ID]*config.Account{}}
	for _, id := range ids {
		p.Platforms[id] = &config.Account{}
	}
	return p
}

func TestProfilesForAndNames(t *testing.T) {
	cfg := &config.Config{Profiles: map[string]*config.Profile{
		"zeta":  accounts(platform.NameCom, platform.Cloudflare),
		"alpha": accounts(platform.NameCom),
		"cf":    accounts(platform.Cloudflare),
		"none":  {},
	}}
	if got := cfg.ProfileNames(); !reflect.DeepEqual(got, []string{"alpha", "cf", "none", "zeta"}) {
		t.Errorf("ProfileNames = %v", got)
	}
	if got := cfg.ProfilesFor(platform.NameCom); !reflect.DeepEqual(got, []string{"alpha", "zeta"}) {
		t.Errorf("ProfilesFor(namecom) = %v", got)
	}
	if got := cfg.ProfilesFor(platform.Cloudflare); !reflect.DeepEqual(got, []string{"cf", "zeta"}) {
		t.Errorf("ProfilesFor(cloudflare) = %v", got)
	}
	if got := cfg.ProfilesFor(platform.AWS); len(got) != 0 {
		t.Errorf("ProfilesFor(aws) = %v, want none", got)
	}
	if _, err := cfg.Profile("alpha"); err != nil {
		t.Errorf("Profile(alpha): %v", err)
	}
	if _, err := cfg.Profile("missing"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("Profile(missing) = %v, want not found error", err)
	}
}

func TestAccountLookup(t *testing.T) {
	want := &config.Account{Metadata: map[string]string{"account": "acc-1"}}
	cfg := &config.Config{Profiles: map[string]*config.Profile{
		"acme": {Platforms: map[platform.ID]*config.Account{
			platform.Cloudflare: want,
			platform.AWS:        {},
		}},
	}}
	got, err := cfg.Account("acme", platform.Cloudflare)
	if err != nil {
		t.Fatalf("Account: %v", err)
	}
	if got != want {
		t.Errorf("Account returned %p, want the stored account %p", got, want)
	}
	_, err = cfg.Account("acme", platform.GoDaddy)
	if err == nil {
		t.Fatal("Account on a platform the profile lacks must fail")
	}
	for _, part := range []string{`profile "acme"`, "no godaddy account", "auth login godaddy --profile acme"} {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("error %q lacks %q", err, part)
		}
	}
	if _, err := cfg.Account("missing", platform.Cloudflare); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("Account(missing) = %v, want not found error", err)
	}
}

func TestAccountsAndPlatformIDsOrdering(t *testing.T) {
	cfg := &config.Config{Profiles: map[string]*config.Profile{
		"zeta":  accounts(platform.NameCom, platform.AWS, platform.Cloudflare),
		"alpha": accounts(platform.GoDaddy, platform.GCP, platform.Aliyun),
		"none":  {},
	}}
	if got := cfg.Profiles["zeta"].PlatformIDs(); !reflect.DeepEqual(got,
		[]platform.ID{platform.AWS, platform.Cloudflare, platform.NameCom}) {
		t.Errorf("PlatformIDs(zeta) = %v", got)
	}
	if got := cfg.Profiles["none"].PlatformIDs(); len(got) != 0 {
		t.Errorf("PlatformIDs(none) = %v", got)
	}
	all := []config.AccountRef{
		{Profile: "alpha", Platform: platform.Aliyun},
		{Profile: "alpha", Platform: platform.GCP},
		{Profile: "alpha", Platform: platform.GoDaddy},
		{Profile: "zeta", Platform: platform.AWS},
		{Profile: "zeta", Platform: platform.Cloudflare},
		{Profile: "zeta", Platform: platform.NameCom},
	}
	// Map iteration is random: repeat to catch an unsorted result.
	for i := 0; i < 20; i++ {
		if got := cfg.Accounts(""); !reflect.DeepEqual(got, all) {
			t.Fatalf("Accounts(\"\") = %v, want %v", got, all)
		}
	}
	if got := cfg.Accounts("zeta"); !reflect.DeepEqual(got, all[3:]) {
		t.Errorf("Accounts(zeta) = %v", got)
	}
	if got := cfg.Accounts("none"); len(got) != 0 {
		t.Errorf("Accounts(none) = %v", got)
	}
	if got := cfg.Accounts("missing"); len(got) != 0 {
		t.Errorf("Accounts(missing) = %v", got)
	}
	if got := all[4].String(); got != "zeta/cloudflare" {
		t.Errorf("AccountRef.String() = %q", got)
	}
}

func TestDefaultProfileName(t *testing.T) {
	if config.DefaultProfile != "default" {
		t.Errorf("DefaultProfile = %q", config.DefaultProfile)
	}
}

func TestDirHonoursEnvOverride(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfg")
	t.Setenv(config.EnvConfigDir, dir)
	got, err := config.Dir()
	if err != nil {
		t.Fatal(err)
	}
	if got != dir {
		t.Fatalf("Dir() = %q, want %q", got, dir)
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("Dir() did not create %q: %v", dir, err)
	}
	p, err := config.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if p != filepath.Join(dir, "config.yaml") {
		t.Fatalf("DefaultPath() = %q", p)
	}
}

// Save must not write a copy of the config over changes made to the file
// after that copy was loaded.
func TestSaveRefusesToOverwriteLaterChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	first, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	// Another process creates the file while this copy still thinks there
	// is none.
	other, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	other.Profiles["theirs"] = &config.Profile{Platforms: map[platform.ID]*config.Account{platform.AWS: {}}}
	if err := other.Save(); err != nil {
		t.Fatal(err)
	}
	first.CurrentProfile = "mine"
	// Unchanged says so before anything is attempted.
	if err := other.Unchanged(); err != nil {
		t.Errorf("Unchanged on the copy that was saved last = %v", err)
	}
	if err := first.Unchanged(); !errors.Is(err, config.ErrChanged) || !strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "nothing was saved") {
		t.Errorf("Unchanged over a file created meanwhile = %v, want ErrChanged naming the file", err)
	}
	if err := first.Save(); !errors.Is(err, config.ErrChanged) || !strings.Contains(err.Error(), path) {
		t.Fatalf("Save over a file created meanwhile = %v, want ErrChanged naming the file", err)
	}

	// The same once the file exists: a copy loaded before a later write.
	stale, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	other.CurrentProfile = "theirs"
	if err := other.Save(); err != nil {
		t.Fatalf("a copy may be saved again and again: %v", err)
	}
	want, _ := os.ReadFile(path)
	stale.Profiles["mine"] = &config.Profile{Platforms: map[platform.ID]*config.Account{}}
	if err := stale.Save(); !errors.Is(err, config.ErrChanged) {
		t.Fatalf("Save of a stale copy = %v, want ErrChanged", err)
	}
	if got, _ := os.ReadFile(path); string(got) != string(want) {
		t.Errorf("a refused save changed the file:\n%s", got)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("a refused save left files behind: %v", entries)
	}

	// A fresh load can be saved, and a file removed meanwhile counts as a
	// change too.
	fresh, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.Save(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := fresh.Save(); !errors.Is(err, config.ErrChanged) {
		t.Errorf("Save after the file was removed = %v, want ErrChanged", err)
	}
}

func TestLegacySecretBackend(t *testing.T) {
	a := &config.Account{CredentialBackend: "keyring", LegacySecret: true}
	if got := a.LegacySecretBackend(); got != "keyring" {
		t.Errorf("LegacySecretBackend = %q, want the credential backend", got)
	}
	// The secret is stored again elsewhere: the old entry stays on record.
	a.SetCredentialBackend("file")
	a.SetCredentialBackend("file")
	if a.CredentialBackend != "file" || a.LegacyBackend != "keyring" || a.LegacySecretBackend() != "keyring" {
		t.Errorf("after storing in the file: %+v", a)
	}
	a.ClearLegacySecret()
	if a.LegacySecret || a.LegacyBackend != "" || a.CredentialBackend != "file" {
		t.Errorf("after clearing the mark: %+v", a)
	}
	// Without the mark there is nothing to remember.
	b := &config.Account{CredentialBackend: "file"}
	b.SetCredentialBackend("keyring")
	if b.LegacyBackend != "" || b.CredentialBackend != "keyring" {
		t.Errorf("unmarked account: %+v", b)
	}
	// The record survives a save.
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Profiles["p"] = &config.Profile{Platforms: map[platform.ID]*config.Account{
		platform.AWS: {CredentialBackend: "file", LegacySecret: true, LegacyBackend: "keyring"},
	}}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	again, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := again.Account("p", platform.AWS); got == nil || got.LegacySecretBackend() != "keyring" || got.CredentialBackend != "file" || !got.LegacySecret {
		t.Errorf("reloaded account = %+v", got)
	}
}

// A legacy profile whose keys all come from a merge key is converted like
// one that has them written out.
func TestLoadLegacyProfileThroughMergeKey(t *testing.T) {
	path := writeConfig(t, "base: &b\n  platform: aws\n  credential_backend: file\nprofiles:\n  p:\n    <<: *b\n")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	a, err := cfg.Account("p", platform.AWS)
	if err != nil {
		t.Fatal(err)
	}
	if !a.LegacySecret || a.CredentialBackend != "file" {
		t.Errorf("account = %+v, want the merged legacy account", a)
	}
}
