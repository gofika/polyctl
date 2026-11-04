package config_test

import (
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
	cfg.CurrentProfile = "work"
	cfg.CredentialStore = "file"
	cfg.Output = "json"
	cfg.Profiles["work"] = &config.Profile{
		Platform:          platform.Cloudflare,
		Metadata:          map[string]string{"account": "acc-1", "email": "me@example.com"},
		CredentialBackend: "file",
		CreatedAt:         created,
		UpdatedAt:         created,
	}
	cfg.Profiles["reg"] = &config.Profile{Platform: platform.NameCom}
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
		t.Errorf("config must not contain secrets:\n%s", raw)
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
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temporary file left behind: %v", err)
	}

	got, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.CurrentProfile != "work" || got.CredentialStore != "file" || got.Output != "json" {
		t.Errorf("scalar fields not round-tripped: %+v", got)
	}
	work := got.Profiles["work"]
	if work == nil || work.Platform != platform.Cloudflare || work.CredentialBackend != "file" {
		t.Fatalf("profile work = %+v", work)
	}
	if !reflect.DeepEqual(work.Metadata, map[string]string{"account": "acc-1", "email": "me@example.com"}) {
		t.Errorf("metadata = %v", work.Metadata)
	}
	if !work.CreatedAt.Equal(created) || !work.UpdatedAt.Equal(created) {
		t.Errorf("timestamps = %v / %v, want %v", work.CreatedAt, work.UpdatedAt, created)
	}
	if got.Profiles["reg"] == nil || got.Profiles["reg"].Platform != platform.NameCom {
		t.Errorf("profile reg = %+v", got.Profiles["reg"])
	}
	if d := got.TTLFor(platform.ResDNSRecord); d != 90*time.Minute {
		t.Errorf("TTLFor(dns_record) = %v, want 90m", d)
	}
	if d := got.TTLFor(platform.ResZone); d != 2*time.Hour {
		t.Errorf("TTLFor(zone) = %v, want the configured default 2h", d)
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

func TestProfilesForAndNames(t *testing.T) {
	cfg := &config.Config{Profiles: map[string]*config.Profile{
		"zeta":  {Platform: platform.NameCom},
		"alpha": {Platform: platform.NameCom},
		"cf":    {Platform: platform.Cloudflare},
	}}
	if got := cfg.ProfileNames(); !reflect.DeepEqual(got, []string{"alpha", "cf", "zeta"}) {
		t.Errorf("ProfileNames = %v", got)
	}
	if got := cfg.ProfilesFor(platform.NameCom); !reflect.DeepEqual(got, []string{"alpha", "zeta"}) {
		t.Errorf("ProfilesFor(namecom) = %v", got)
	}
	if got := cfg.ProfilesFor(platform.Cloudflare); !reflect.DeepEqual(got, []string{"cf"}) {
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
